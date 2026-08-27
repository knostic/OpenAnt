"""Smoke tests for utilities/autopatcher/tools/run_traced.py -- the
in-process tracing wrapper around core.patch.run_patch_cve()/run_patch().

This wrapper is run directly (``python3.12
utilities/autopatcher/tools/run_traced.py ...``), not imported via ``python
-m`` or a dotted package path, so it's loaded here directly from its file
path rather than imported by dotted name -- same reason
test_stage_replay.py loads run_stage.py (same directory) the same way.
These tests are hermetic: LLM_PROVIDER=mock, fetch_cve mocked at its source
module (mirrors tests/patch/test_run_patch_cve.py), no network, no real
repo beyond tmp_path.

Covers the checklist from the task:
  1. --help lists both budget flags.
  2. An invalid --context-budget-policy is rejected.
  3. --max-context-budget-windows must be positive (0 / negative / non-int).
  4. Parsed values reach the real production ContextBudgetController.
  5. Default behavior (neither flag given) matches openant/cli.py's cmd_patch.
  6. The trace hooks still produce a prompt/raw-response trace, hermetically.
  7. No budget logic is duplicated in the wrapper (structural check).
  8. context_selection_*.json debug artifacts are included in the manifest.
  9. A failing run_patch()/run_patch_cve() call still leaves checkpoints.jsonl
     and a failed run_manifest.json behind, and the failure still propagates.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from unittest import mock

import pytest

SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "utilities" / "autopatcher" / "tools" / "run_traced.py"
)

FIXTURE_CVE = {
    "id": "CVE-2021-12345",
    "descriptions": [
        {"lang": "en", "value": "A SQL injection vulnerability exists in the authenticate() function."}
    ],
    "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
}


@pytest.fixture(scope="module")
def run_traced():
    """Load utilities/autopatcher/tools/run_traced.py as a module, once per test module."""
    assert SCRIPT_PATH.exists(), f"expected wrapper at {SCRIPT_PATH}"
    spec = importlib.util.spec_from_file_location("run_traced", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mock_fetch_cve_at_source(cve=FIXTURE_CVE):
    # core.patch.run_patch_cve imports fetch_cve locally from its home
    # module -- same patch target test_run_patch_cve.py uses.
    return mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve)


def _make_git_repo(tmp_path: Path, name: str = "repo") -> Path:
    """Init a minimal git repo with one committed file -- used by the
    replay-provenance tests below, which need a real, resolvable HEAD SHA
    (a plain mkdir()'d directory, as most tests in this file use, has
    none)."""
    repo = tmp_path / name
    repo.mkdir()
    (repo / "README.md").write_text("placeholder\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)
    return repo


class TestHelpAndValidation:
    def test_help_lists_both_budget_flags(self, run_traced, capsys):
        parser = run_traced.build_parser()
        help_text = parser.format_help()
        assert "--context-budget-policy" in help_text
        assert "{ask,always,never}" in help_text
        assert "--max-context-budget-windows" in help_text
        assert "MAX_CONTEXT_BUDGET_WINDOWS" in help_text

    def test_invalid_policy_rejected(self, run_traced):
        parser = run_traced.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--cve", "X", "--repo-root", "/tmp", "--context-budget-policy", "bogus"])

    @pytest.mark.parametrize("bad_value", ["0", "-1", "-100", "abc", "1.5"])
    def test_max_windows_must_be_positive_integer(self, run_traced, bad_value):
        parser = run_traced.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["--cve", "X", "--repo-root", "/tmp", "--max-context-budget-windows", bad_value]
            )

    @pytest.mark.parametrize("good_value", ["1", "10", "9999"])
    def test_max_windows_accepts_positive_integers(self, run_traced, good_value):
        parser = run_traced.build_parser()
        args = parser.parse_args(
            ["--cve", "X", "--repo-root", "/tmp", "--max-context-budget-windows", good_value]
        )
        assert args.max_context_budget_windows == int(good_value)


class TestBudgetWiring:
    def test_parsed_values_reach_production_controller(self, run_traced):
        parser = run_traced.build_parser()
        args = parser.parse_args(
            ["--cve", "X", "--repo-root", "/tmp",
             "--context-budget-policy", "always",
             "--max-context-budget-windows", "10"]
        )
        controller = run_traced.resolve_budget_controller(args)
        assert isinstance(controller, run_traced.ContextBudgetController)
        assert controller.policy == "always"
        assert controller.max_windows == 10

    def test_default_policy_matches_cli_when_omitted_interactive(self, run_traced, monkeypatch):
        monkeypatch.setattr(run_traced.sys.stdin, "isatty", lambda: True)
        parser = run_traced.build_parser()
        args = parser.parse_args(["--cve", "X", "--repo-root", "/tmp"])
        controller = run_traced.resolve_budget_controller(args)
        assert controller.policy == "ask"
        assert controller.max_windows == run_traced.DEFAULT_MAX_CONTEXT_BUDGET_WINDOWS

    def test_default_policy_matches_cli_when_omitted_non_interactive(self, run_traced, monkeypatch):
        monkeypatch.setattr(run_traced.sys.stdin, "isatty", lambda: False)
        parser = run_traced.build_parser()
        args = parser.parse_args(["--cve", "X", "--repo-root", "/tmp"])
        controller = run_traced.resolve_budget_controller(args)
        assert controller.policy == "never"
        assert controller.max_windows == 10


class TestNoDuplicatedBudgetLogic:
    def test_wrapper_does_not_redefine_controller_or_policy_tuple(self):
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        assert "class ContextBudgetController" not in source
        assert 'CONTEXT_BUDGET_POLICIES = (' not in source
        assert "def request_extension" not in source  # policy-decision method lives only in production
        assert "input(" not in source  # wrapper must never block on stdin itself

    def test_wrapper_imports_production_symbols(self):
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        assert "from utilities.autopatcher.context_budget import" in source
        assert "from openant.cli import _positive_int" in source


class TestTraceHooksHermetic:
    """Mocked, no-cost CVE run: verifies the trace hooks still produce a
    prompt/raw-response trace, and that the two production artifacts
    (vulnerability.md / trust-report.md) are still written unchanged."""

    def test_traced_run_produces_prompt_and_response_files(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        argv = [
            "--cve", "CVE-2021-12345",
            "--repo-root", str(repo_root),
            "--output", str(output_dir),
        ]

        with _mock_fetch_cve_at_source():
            exit_code = run_traced.main(argv)

        assert exit_code == 0

        trace_dir = output_dir / "trace"
        assert trace_dir.is_dir()

        prompt_files = sorted(trace_dir.glob("*.prompt.txt"))
        response_files = sorted(trace_dir.glob("*.response.txt"))
        assert prompt_files, "expected at least one traced prompt file"
        assert len(prompt_files) == len(response_files)
        assert any(f.name.endswith("_patch_generation.prompt.txt") for f in prompt_files)
        for f in prompt_files + response_files:
            assert f.stat().st_size > 0

        checkpoints_path = trace_dir / "checkpoints.jsonl"
        assert checkpoints_path.is_file()
        checkpoint_lines = [json.loads(line) for line in checkpoints_path.read_text().splitlines()]
        assert checkpoint_lines, "expected at least one checkpoint entry"
        # Ordering: seq must be strictly increasing (stage/checkpoint ordering trace).
        seqs = [c["seq"] for c in checkpoint_lines]
        assert seqs == sorted(seqs)
        assert seqs == list(range(1, len(seqs) + 1))

        manifest_path = trace_dir / "run_manifest.json"
        assert manifest_path.is_file()
        manifest = json.loads(manifest_path.read_text())
        assert manifest["input_type"] == "cve"
        assert manifest["input_id"] == "CVE-2021-12345"
        assert manifest["llm_call_count"] == len(checkpoint_lines)

        # The existing production artifacts are untouched/still produced.
        assert Path(manifest["vulnerability_path"]).is_file()
        assert Path(manifest["trust_report_path"]).is_file()

    def test_call_llm_is_restored_after_run(self, run_traced, tmp_path, monkeypatch):
        import utilities.autopatcher.llm_client as llm_client_module

        original = llm_client_module.call_llm
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(tmp_path / "out")]
        with _mock_fetch_cve_at_source():
            run_traced.main(argv)

        assert llm_client_module.call_llm is original

    def test_successful_manifest_has_explicit_success_status(self, run_traced, tmp_path, monkeypatch):
        """Successful-run manifest behavior is unchanged except for the
        added explicit `status` field."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            exit_code = run_traced.main(argv)

        assert exit_code == 0
        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["status"] == "success"
        assert manifest["input_type"] == "cve"


class TestDebugArtifactManifest:
    """Covers requirement 1: context_selection_*.json artifacts must be
    included in autopatcher_debug_artifacts alongside the pre-existing
    edit_readiness_/relocation_telemetry_/post_patch_recovery_ prefixes,
    via the existing _DEBUG_ARTIFACT_PREFIXES/_new_debug_artifacts
    mechanism -- no new parsing of those files' contents."""

    def test_context_selection_prefix_is_registered(self, run_traced):
        assert "context_selection_" in run_traced._DEBUG_ARTIFACT_PREFIXES
        # Alongside, not instead of, the pre-existing prefixes.
        assert "edit_readiness_" in run_traced._DEBUG_ARTIFACT_PREFIXES
        assert "relocation_telemetry_" in run_traced._DEBUG_ARTIFACT_PREFIXES
        assert "post_patch_recovery_" in run_traced._DEBUG_ARTIFACT_PREFIXES

    def test_context_selection_artifact_is_included_when_produced(self, run_traced, tmp_path):
        """Direct check of the exact function the wrapper's manifest is
        built from (_new_debug_artifacts) -- a context_selection_*.json
        file written during the run (mtime >= `since`) must be picked up
        exactly like the other three prefixes, and a stale one (mtime <
        `since`, i.e. from a previous run) must not."""
        debug_dir = tmp_path / "reports" / "debug"
        debug_dir.mkdir(parents=True)

        stale = debug_dir / "context_selection_stale.json"
        stale.write_text("{}", encoding="utf-8")
        os.utime(stale, (1_000_000, 1_000_000))  # long before `since`

        since = 2_000_000.0
        fresh = debug_dir / "context_selection_fresh.json"
        fresh.write_text("{}", encoding="utf-8")
        os.utime(fresh, (2_000_500, 2_000_500))  # after `since`

        found = run_traced._new_debug_artifacts(debug_dir, since)
        assert str(fresh) in found
        assert str(stale) not in found


class TestFailedRunManifest:
    """Covers requirement 2: a run_patch_cve()/run_patch() failure must
    still leave checkpoints.jsonl and a failed run_manifest.json behind,
    and the failure itself must still propagate unchanged."""

    def test_failing_pipeline_run_still_writes_checkpoints_and_failed_manifest(
        self, run_traced, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        import utilities.autopatcher.pipeline as pipeline_module

        def _boom(**kwargs):
            raise RuntimeError("simulated pipeline failure")

        monkeypatch.setattr(pipeline_module, "run", _boom)

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            with pytest.raises(RuntimeError, match="simulated pipeline failure"):
                run_traced.main(argv)

        trace_dir = output_dir / "trace"
        checkpoints_path = trace_dir / "checkpoints.jsonl"
        manifest_path = trace_dir / "run_manifest.json"
        assert checkpoints_path.is_file()
        assert manifest_path.is_file()

        manifest = json.loads(manifest_path.read_text())
        assert manifest["status"] == "failed"
        assert manifest["error_type"] == "RuntimeError"
        assert "simulated pipeline failure" in manifest["error_message"]
        assert manifest["context_budget_policy"] in ("ask", "always", "never")
        assert isinstance(manifest["max_context_budget_windows"], int)
        assert manifest["checkpoints_file"] == checkpoints_path.name
        assert isinstance(manifest["llm_call_count"], int)
        assert isinstance(manifest["autopatcher_debug_artifacts"], list)

    def test_failure_still_propagates_and_is_not_swallowed(self, run_traced, tmp_path, monkeypatch):
        """The wrapper has no top-level try/except around main() itself
        (unchanged): an uncaught exception here is exactly what makes
        `sys.exit(main())` never complete normally, so the process exit
        code stays non-zero -- main() must raise, never quietly return 0
        or a falsy/success-shaped value."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        import utilities.autopatcher.pipeline as pipeline_module
        monkeypatch.setattr(
            pipeline_module, "run",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
        )

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(tmp_path / "out")]
        with _mock_fetch_cve_at_source():
            with pytest.raises(RuntimeError):
                run_traced.main(argv)

    def test_call_llm_is_restored_after_a_failed_run(self, run_traced, tmp_path, monkeypatch):
        """The env-var restore in `finally` must still run on failure --
        unaffected by this change, checked here to guard against a
        regression while touching the surrounding try/finally."""
        import utilities.autopatcher.llm_client as llm_client_module

        original = llm_client_module.call_llm
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        import utilities.autopatcher.pipeline as pipeline_module
        monkeypatch.setattr(pipeline_module, "run", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(tmp_path / "out")]
        with _mock_fetch_cve_at_source():
            with pytest.raises(RuntimeError):
                run_traced.main(argv)

        assert llm_client_module.call_llm is original


class TestCompareExistingTestsFlag:
    """Covers requirements 1-3: the parser accepts --compare-existing-tests,
    defaults to False, and store_true flips it to True."""

    def test_parser_accepts_compare_existing_tests(self, run_traced):
        parser = run_traced.build_parser()
        args = parser.parse_args(["--cve", "X", "--repo-root", "/tmp", "--compare-existing-tests"])
        assert hasattr(args, "compare_existing_tests")

    def test_default_is_false(self, run_traced):
        parser = run_traced.build_parser()
        args = parser.parse_args(["--cve", "X", "--repo-root", "/tmp"])
        assert args.compare_existing_tests is False

    def test_flag_present_makes_it_true(self, run_traced):
        parser = run_traced.build_parser()
        args = parser.parse_args(["--cve", "X", "--repo-root", "/tmp", "--compare-existing-tests"])
        assert args.compare_existing_tests is True

    def test_help_lists_compare_existing_tests_flag(self, run_traced):
        parser = run_traced.build_parser()
        help_text = parser.format_help()
        assert "--compare-existing-tests" in help_text


class TestCompareExistingTestsForwarding:
    """Covers requirements 4-6: compare_existing_tests is forwarded to both
    run_patch_cve (CVE mode) and run_patch (finding mode), and the False
    default is forwarded (not silently dropped) exactly as explicitly."""

    def test_cve_mode_forwards_true_to_run_patch_cve(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        fake_result = mock.MagicMock(
            input_type="cve", input_id="CVE-2021-12345",
            vulnerability_path=str(tmp_path / "v.md"), trust_report_path=str(tmp_path / "t.md"),
        )
        with mock.patch("core.patch.run_patch_cve", return_value=fake_result) as m_run:
            argv = [
                "--cve", "CVE-2021-12345", "--repo-root", str(repo_root),
                "--output", str(output_dir), "--compare-existing-tests",
            ]
            exit_code = run_traced.main(argv)

        assert exit_code == 0
        m_run.assert_called_once()
        assert m_run.call_args.kwargs["compare_existing_tests"] is True

    def test_finding_mode_forwards_true_to_run_patch(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"
        pipeline_output = tmp_path / "pipeline_output.json"
        pipeline_output.write_text("{}", encoding="utf-8")

        fake_result = mock.MagicMock(
            input_type="finding", input_id="F-001",
            vulnerability_path=str(tmp_path / "v.md"), trust_report_path=str(tmp_path / "t.md"),
        )
        with mock.patch("core.patch.run_patch", return_value=fake_result) as m_run:
            argv = [
                str(pipeline_output), "--finding-id", "F-001", "--repo-root", str(repo_root),
                "--output", str(output_dir), "--compare-existing-tests",
            ]
            exit_code = run_traced.main(argv)

        assert exit_code == 0
        m_run.assert_called_once()
        assert m_run.call_args.kwargs["compare_existing_tests"] is True

    def test_default_false_is_forwarded_to_run_patch_cve(self, run_traced, tmp_path, monkeypatch):
        """Omitting the flag must forward an explicit False, not merely
        omit the kwarg -- run_traced must behave exactly like the
        production CLI path (which also always passes it explicitly)."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        fake_result = mock.MagicMock(
            input_type="cve", input_id="CVE-2021-12345",
            vulnerability_path=str(tmp_path / "v.md"), trust_report_path=str(tmp_path / "t.md"),
        )
        with mock.patch("core.patch.run_patch_cve", return_value=fake_result) as m_run:
            argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(tmp_path / "out")]
            run_traced.main(argv)

        assert m_run.call_args.kwargs["compare_existing_tests"] is False

    def test_default_false_is_forwarded_to_run_patch(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        pipeline_output = tmp_path / "pipeline_output.json"
        pipeline_output.write_text("{}", encoding="utf-8")

        fake_result = mock.MagicMock(
            input_type="finding", input_id="F-001",
            vulnerability_path=str(tmp_path / "v.md"), trust_report_path=str(tmp_path / "t.md"),
        )
        with mock.patch("core.patch.run_patch", return_value=fake_result) as m_run:
            argv = [
                str(pipeline_output), "--finding-id", "F-001", "--repo-root", str(repo_root),
                "--output", str(tmp_path / "out"),
            ]
            run_traced.main(argv)

        assert m_run.call_args.kwargs["compare_existing_tests"] is False


class TestCompareExistingTestsManifest:
    """Covers requirements 7-8: both success and failure manifests record
    compare_existing_tests, additively -- no other manifest field removed or
    renamed."""

    def test_success_manifest_records_true(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        from utilities.autopatcher.test_execution_models import ExecutorPreflightResult

        argv = [
            "--cve", "CVE-2021-12345", "--repo-root", str(repo_root),
            "--output", str(output_dir), "--compare-existing-tests",
        ]
        # The early whole-run gate (core.patch._require_test_comparison_environment)
        # now runs for --compare-existing-tests regardless of whether Docker is
        # actually available on the machine running this test suite --
        # mock it ready so this test still exercises what it's actually
        # about (the manifest's additive field), not this sandbox's Docker
        # state.
        with _mock_fetch_cve_at_source(), \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=ExecutorPreflightResult(ready=True, status="OK", reason=None),
             ):
            run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["compare_existing_tests"] is True
        # Pre-existing fields are still present, unaffected by the addition.
        assert manifest["status"] == "success"
        assert manifest["input_type"] == "cve"

    def test_success_manifest_records_false_by_default(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["compare_existing_tests"] is False

    def test_failure_manifest_records_true(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        from utilities.autopatcher.test_execution_models import ExecutorPreflightResult

        import utilities.autopatcher.pipeline as pipeline_module
        monkeypatch.setattr(
            pipeline_module, "run",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("simulated failure")),
        )

        argv = [
            "--cve", "CVE-2021-12345", "--repo-root", str(repo_root),
            "--output", str(output_dir), "--compare-existing-tests",
        ]
        # Early gate mocked ready so THIS test's own injected failure
        # (pipeline.run raising) is what's actually exercised, independent
        # of this sandbox's real Docker availability.
        with _mock_fetch_cve_at_source(), \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=ExecutorPreflightResult(ready=True, status="OK", reason=None),
             ):
            with pytest.raises(RuntimeError):
                run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["compare_existing_tests"] is True
        # Pre-existing failure-manifest fields are still present, unaffected.
        assert manifest["status"] == "failed"
        assert manifest["error_type"] == "RuntimeError"

    def test_failure_manifest_records_false_by_default(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        import utilities.autopatcher.pipeline as pipeline_module
        monkeypatch.setattr(
            pipeline_module, "run",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("simulated failure")),
        )

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            with pytest.raises(RuntimeError):
                run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["compare_existing_tests"] is False


class TestCompareExistingTestsDoesNotAffectBudgetFlags:
    """Covers requirement 9: pre-existing --context-budget-policy /
    --max-context-budget-windows propagation is unaffected by the new
    flag being present alongside them."""

    def test_budget_flags_still_propagate_alongside_compare_existing_tests(self, run_traced):
        parser = run_traced.build_parser()
        args = parser.parse_args([
            "--cve", "X", "--repo-root", "/tmp",
            "--context-budget-policy", "always",
            "--max-context-budget-windows", "10",
            "--compare-existing-tests",
        ])
        controller = run_traced.resolve_budget_controller(args)
        assert controller.policy == "always"
        assert controller.max_windows == 10
        assert args.compare_existing_tests is True

    def test_budget_flags_unaffected_when_compare_existing_tests_omitted(self, run_traced):
        parser = run_traced.build_parser()
        args = parser.parse_args([
            "--cve", "X", "--repo-root", "/tmp",
            "--context-budget-policy", "always",
            "--max-context-budget-windows", "10",
        ])
        controller = run_traced.resolve_budget_controller(args)
        assert controller.policy == "always"
        assert controller.max_windows == 10
        assert args.compare_existing_tests is False


class TestCompareExistingTestsPreflightTracing:
    """Environment-preflight failure must be visible in a traced run as
    the ABSENCE of trace files for stages that never ran -- no new
    tracing framework needed, the existing LLMCallTracer already proves
    this for free once a stage's LLM call is never reached."""

    def test_early_whole_run_gate_produces_zero_llm_trace_files(self, run_traced, tmp_path, monkeypatch, capsys):
        """The EARLY gate (core.patch._require_test_comparison_environment,
        called before pipeline.run() -- and therefore before repository
        parsing, remediation planning, and patch generation, not just
        before Test Plan Discovery) firing must leave NO trace files at
        all: zero prompt/response files for ANY stage (patch_generation,
        remediation_planning, test_plan_discovery, ...), zero checkpoint
        lines. Unlike an UNEXPECTED failure, this expected prerequisite
        failure must NOT propagate as an exception/traceback -- main()
        catches it, prints a concise message, and returns a non-zero
        exit code (see TestCompareExistingTestsExpectedPrerequisiteFailure
        below for the dedicated UX tests)."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        from utilities.autopatcher.test_execution_models import ExecutorPreflightResult

        argv = [
            "--cve", "CVE-2021-12345", "--repo-root", str(repo_root),
            "--output", str(output_dir), "--compare-existing-tests",
        ]
        with _mock_fetch_cve_at_source(), \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=ExecutorPreflightResult(
                     ready=False, status="CLI_MISSING",
                     reason="docker is not installed (the `docker` command was not found on PATH).",
                 ),
             ):
            exit_code = run_traced.main(argv)

        assert exit_code == 2
        captured = capsys.readouterr()
        assert "Traceback" not in captured.err

        trace_dir = output_dir / "trace"
        assert list(trace_dir.glob("*.prompt.txt")) == []
        assert list(trace_dir.glob("*.response.txt")) == []

        checkpoints_path = trace_dir / "checkpoints.jsonl"
        assert checkpoints_path.is_file()
        assert checkpoints_path.read_text() == ""  # zero LLM calls of any kind

        manifest = json.loads((trace_dir / "run_manifest.json").read_text())
        assert manifest["status"] == "failed"
        assert manifest["error_type"] == "TestComparisonEnvironmentError"
        assert manifest["compare_existing_tests"] is True
        assert manifest["llm_call_count"] == 0

    def test_failed_preflight_produces_no_test_plan_discovery_trace(self, run_traced, tmp_path, monkeypatch):
        """Exercises the INNER, defense-in-depth preflight inside
        evaluate_existing_test_comparison() specifically -- the EARLY
        whole-run gate is mocked ready (as if Docker was fine at command
        entry) so this test isolates the case where the environment
        changed, or the inner check is reached some other way; unlike
        the early gate, the inner one degrades to NOT_VERIFIED and lets
        the rest of the pipeline's OTHER LLM stages proceed normally."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        import utilities.autopatcher.existing_test_regression as etr_module
        from utilities.autopatcher.test_execution_models import ExecutorPreflightResult

        unready = mock.MagicMock()
        unready.preflight.return_value = ExecutorPreflightResult(
            ready=False, status="DAEMON_UNREACHABLE",
            reason="the Docker daemon is not reachable (...). Start Docker and rerun with --compare-existing-tests.",
        )

        argv = [
            "--cve", "CVE-2021-12345", "--repo-root", str(repo_root),
            "--output", str(output_dir), "--compare-existing-tests",
        ]
        with _mock_fetch_cve_at_source(), \
             mock.patch.object(
                 etr_module, "preflight_test_comparison_environment",
                 return_value=ExecutorPreflightResult(ready=True, status="OK", reason=None),
             ), \
             mock.patch.object(etr_module, "select_executor", return_value=unready):
            exit_code = run_traced.main(argv)

        assert exit_code == 0
        trace_dir = output_dir / "trace"
        prompt_files = sorted(trace_dir.glob("*.prompt.txt"))
        assert prompt_files, "expected the run's other LLM stages to still be traced normally"
        assert not any("test_plan_discovery" in f.name for f in prompt_files)

        checkpoints = [
            json.loads(line) for line in (trace_dir / "checkpoints.jsonl").read_text().splitlines()
        ]
        assert not any(c["stage"] == "test_plan_discovery" for c in checkpoints)

        manifest = json.loads((trace_dir / "run_manifest.json").read_text())
        assert manifest["compare_existing_tests"] is True


class TestCompareExistingTestsExpectedPrerequisiteFailureUX:
    """Dedicated UX tests for core.patch.TestComparisonEnvironmentError
    handling in run_traced.py's main() -- the ONE exception type this
    wrapper catches without re-raising."""

    def _run_with_unready_docker(self, run_traced, tmp_path, monkeypatch, status="CLI_MISSING", reason=None):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        # Unique subdirectory per call so this helper is safe to call more
        # than once against the same tmp_path (e.g. one call per status
        # in a table-driven test).
        call_id = uuid.uuid4().hex[:8]
        repo_root = tmp_path / f"repo-{call_id}"
        repo_root.mkdir()
        output_dir = tmp_path / f"out-{call_id}"

        from utilities.autopatcher.test_execution_models import ExecutorPreflightResult

        reason = reason or "docker is not installed (the `docker` command was not found on PATH)."
        argv = [
            "--cve", "CVE-2021-12345", "--repo-root", str(repo_root),
            "--output", str(output_dir), "--compare-existing-tests",
        ]
        with _mock_fetch_cve_at_source(), \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=ExecutorPreflightResult(ready=False, status=status, reason=reason),
             ):
            exit_code = run_traced.main(argv)
        return exit_code, output_dir

    def test_no_exception_escapes_main(self, run_traced, tmp_path, monkeypatch):
        # main() returning normally (not raising) IS the assertion here --
        # pytest would report an error if main() raised instead.
        exit_code, _ = self._run_with_unready_docker(run_traced, tmp_path, monkeypatch)
        assert isinstance(exit_code, int)

    def test_non_zero_exit_code(self, run_traced, tmp_path, monkeypatch):
        exit_code, _ = self._run_with_unready_docker(run_traced, tmp_path, monkeypatch)
        assert exit_code != 0
        assert exit_code == 2

    def test_no_traceback_text_printed(self, run_traced, tmp_path, monkeypatch, capsys):
        self._run_with_unready_docker(run_traced, tmp_path, monkeypatch)
        captured = capsys.readouterr()
        assert "Traceback (most recent call last)" not in captured.err
        assert "Traceback (most recent call last)" not in captured.out

    def test_concise_actionable_message_printed(self, run_traced, tmp_path, monkeypatch, capsys):
        self._run_with_unready_docker(run_traced, tmp_path, monkeypatch)
        captured = capsys.readouterr()
        assert "Existing Test Comparison cannot start." in captured.err
        assert "docker" in captured.err.lower()
        assert len(captured.err) < 1000  # concise, not a dump

    def test_no_duplicate_call_to_action_wording(self, run_traced, tmp_path, monkeypatch, capsys):
        """Regression test for the exact bug from the real run: the
        printed message must never contain the actionable next step
        twice (e.g. 'Start Docker and rerun ... Start Docker and
        rerun ...')."""
        self._run_with_unready_docker(
            run_traced, tmp_path, monkeypatch, status="DAEMON_UNREACHABLE",
            reason=(
                "the Docker daemon is not reachable (Cannot connect to the Docker daemon). "
                "Start Docker and rerun with --compare-existing-tests."
            ),
        )
        captured = capsys.readouterr()
        assert captured.err.lower().count("start docker and rerun") == 1

    def test_failure_manifest_still_records_the_prerequisite_failure(self, run_traced, tmp_path, monkeypatch):
        exit_code, output_dir = self._run_with_unready_docker(
            run_traced, tmp_path, monkeypatch, status="DAEMON_UNREACHABLE", reason="the Docker daemon is not reachable.",
        )
        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["status"] == "failed"
        assert manifest["error_type"] == "TestComparisonEnvironmentError"
        assert "not reachable" in manifest["error_message"]
        assert manifest["llm_call_count"] == 0

    def test_distinguishes_cli_missing_vs_daemon_unavailable_vs_timeout(self, run_traced, tmp_path, monkeypatch, capsys):
        cases = [
            ("CLI_MISSING", "docker is not installed (the `docker` command was not found on PATH)."),
            ("DAEMON_UNREACHABLE", "the Docker daemon is not reachable (Cannot connect to the Docker daemon)."),
            ("TIMEOUT", "the Docker readiness check (`docker info`) timed out after 5s."),
        ]
        seen_messages = set()
        for status, reason in cases:
            self._run_with_unready_docker(run_traced, tmp_path, monkeypatch, status=status, reason=reason)
            seen_messages.add(capsys.readouterr().err)
        assert len(seen_messages) == 3  # each status produces distinguishable wording

    def test_unexpected_runtime_error_still_propagates_with_existing_behavior(
        self, run_traced, tmp_path, monkeypatch,
    ):
        """A real bug (anything other than TestComparisonEnvironmentError)
        must NOT be swallowed -- run_traced.py's existing, unchanged
        developer-oriented behavior (propagate, no catch) still applies."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        import utilities.autopatcher.pipeline as pipeline_module
        monkeypatch.setattr(
            pipeline_module, "run",
            lambda **kwargs: (_ for _ in ()).throw(RuntimeError("a real, unrelated bug")),
        )

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(tmp_path / "out")]
        with _mock_fetch_cve_at_source():
            with pytest.raises(RuntimeError, match="a real, unrelated bug"):
                run_traced.main(argv)


class TestReplayProvenanceManifest:
    """New traces must be replay-capable by design: run_manifest.json must
    carry structured (not prose-only) schema_version, target_repository
    (with a FULL git SHA), openant, and llm provenance -- additive to
    every pre-existing flat field, on both the success and failure
    manifest shapes. See utilities/autopatcher/stage_replay.py and
    utilities/autopatcher/tools/run_stage.py, the consumers of these new
    fields."""

    def test_success_manifest_has_schema_version(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = _make_git_repo(tmp_path)
        output_dir = tmp_path / "out"

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["schema_version"] == 3

    def test_success_manifest_has_full_target_repo_sha(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = _make_git_repo(tmp_path)
        expected_sha = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root, capture_output=True, text=True, check=True,
        ).stdout.strip()
        assert len(expected_sha) == 40  # sanity: a real full SHA, not a short one
        output_dir = tmp_path / "out"

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["target_repository"]["repo_root"] == str(repo_root)
        assert manifest["target_repository"]["repo_commit"] == expected_sha

    def test_success_manifest_has_source_openant_commit(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = _make_git_repo(tmp_path)
        output_dir = tmp_path / "out"

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        patcher_commit = manifest["openant"]["patcher_commit"]
        # This checkout may or may not itself be a git repo depending on
        # how the test environment is set up -- assert shape, not a
        # specific value, so this test doesn't depend on that.
        assert patcher_commit is None or (isinstance(patcher_commit, str) and len(patcher_commit) == 40)

    def test_success_manifest_has_llm_provider_and_model(self, run_traced, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = _make_git_repo(tmp_path)
        output_dir = tmp_path / "out"

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["llm"]["provider"] == "mock"
        assert manifest["llm"]["model"] == "mock"

    def test_success_manifest_has_relevant_pipeline_options(self, run_traced, tmp_path, monkeypatch):
        """The pre-existing flat fields ARE the "pipeline_options" this
        feature needs -- no new nested duplicate of them was added."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = _make_git_repo(tmp_path)
        output_dir = tmp_path / "out"

        argv = [
            "--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir),
            "--context-budget-policy", "always", "--max-context-budget-windows", "7",
        ]
        with _mock_fetch_cve_at_source():
            run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["context_budget_policy"] == "always"
        assert manifest["max_context_budget_windows"] == 7
        assert manifest["compare_existing_tests"] is False

    def test_pre_existing_flat_fields_are_unchanged(self, run_traced, tmp_path, monkeypatch):
        """The new structured fields are additive -- every field an
        existing consumer already reads is still present, unrenamed,
        unremoved."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = _make_git_repo(tmp_path)
        output_dir = tmp_path / "out"

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        for key in (
            "status", "input_type", "input_id", "repo_root", "output_dir",
            "context_budget_policy", "max_context_budget_windows", "compare_existing_tests",
            "vulnerability_path", "trust_report_path", "llm_call_count",
            "checkpoints_file", "autopatcher_debug_artifacts",
        ):
            assert key in manifest, f"pre-existing flat field {key!r} missing from manifest"

    def test_failure_manifest_also_has_structured_provenance(self, run_traced, tmp_path, monkeypatch):
        """Provenance is recorded even for a failed run -- a source trace
        of a run that failed downstream of test_plan_discovery (or never
        attempted it) can still be a valid replay source, as long as the
        target repository was recorded before the failure."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = _make_git_repo(tmp_path)
        output_dir = tmp_path / "out"

        import utilities.autopatcher.pipeline as pipeline_module
        monkeypatch.setattr(pipeline_module, "run", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            with pytest.raises(RuntimeError):
                run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["schema_version"] == 3
        assert manifest["target_repository"]["repo_root"] == str(repo_root)
        assert len(manifest["target_repository"]["repo_commit"]) == 40
        assert "openant" in manifest
        assert "llm" in manifest

    def test_repo_commit_is_null_when_repo_root_not_given(self, run_traced, tmp_path, monkeypatch):
        """Finding-mode with no --repo-root: target_repository.repo_commit
        must be null (never a fabricated or misleading value), and this
        must not crash manifest writing."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        pipeline_output = tmp_path / "pipeline_output.json"
        pipeline_output.write_text("{}", encoding="utf-8")
        output_dir = tmp_path / "out"

        fake_result = mock.MagicMock(
            input_type="finding", input_id="F-001",
            vulnerability_path=str(tmp_path / "v.md"), trust_report_path=str(tmp_path / "t.md"),
        )
        with mock.patch("core.patch.run_patch", return_value=fake_result):
            argv = [str(pipeline_output), "--finding-id", "F-001", "--output", str(output_dir)]
            run_traced.main(argv)

        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["target_repository"]["repo_root"] is None
        assert manifest["target_repository"]["repo_commit"] is None

    def test_replay_does_not_depend_on_trust_report_parsing(self, run_traced, tmp_path, monkeypatch):
        """A NEW trace's replay-relevant provenance must be fully present
        in run_manifest.json even if the Trust Report were deleted --
        proving replay does not need to fall back to parsing it. See
        stage_replay.resolve_source_provenance's structured-first
        priority and TestNewTraceReplayIgnoresTrustReport in
        test_stage_replay.py for the end-to-end version of this proof."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = _make_git_repo(tmp_path)
        output_dir = tmp_path / "out"

        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source():
            run_traced.main(argv)

        trust_report_path = Path(
            json.loads((output_dir / "trace" / "run_manifest.json").read_text())["trust_report_path"]
        )
        assert trust_report_path.is_file()
        trust_report_path.unlink()  # gone -- provenance must not need it

        from utilities.autopatcher.stage_replay import load_source_manifest, resolve_source_provenance

        manifest = load_source_manifest(output_dir / "trace")
        provenance = resolve_source_provenance(output_dir / "trace", manifest)
        assert provenance.source == "structured_manifest"
        assert provenance.repo_root == str(repo_root)
