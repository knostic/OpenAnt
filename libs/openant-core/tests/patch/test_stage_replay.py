"""Tests for single-stage Auto Patcher replay (Phase 1): the
test_plan_discovery replay path in utilities/autopatcher/stage_replay.py
and utilities/autopatcher/tools/run_stage.py.

Hermetic throughout: LLM_PROVIDER=mock (tests/patch/conftest.py's autouse
fixture), no network, no real LLM provider credential, no real repo beyond
tmp_path git fixtures created here. Source traces are hand-constructed
(a run_manifest.json, optionally a trust-report.md) rather than produced
via a full run_traced.py invocation -- run_traced.py's OWN manifest-writing
behavior is covered separately in test_run_traced_wrapper.py's
TestReplayProvenanceManifest; this file tests stage_replay.py's consumption
of that shape, independent of how it was produced.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from utilities.autopatcher import stage_replay
from utilities.autopatcher.stage_replay import (
    SUPPORTED_STAGES,
    StageReplayError,
    load_source_manifest,
    replay_test_plan_discovery,
    resolve_source_provenance,
    resolve_source_trace_dir,
    validate_target_repository,
)

_TOOLS_DIR = (
    Path(__file__).resolve().parent.parent.parent / "utilities" / "autopatcher" / "tools"
)
RUN_STAGE_SCRIPT = _TOOLS_DIR / "run_stage.py"
RUN_TRACED_SCRIPT = _TOOLS_DIR / "run_traced.py"


@pytest.fixture(scope="module")
def run_stage():
    """Load utilities/autopatcher/tools/run_stage.py as a module -- run
    directly (``python3.12 utilities/autopatcher/tools/run_stage.py``),
    not via ``python -m`` or a dotted import, same reason
    test_run_traced_wrapper.py loads run_traced.py this way."""
    assert RUN_STAGE_SCRIPT.exists(), f"expected script at {RUN_STAGE_SCRIPT}"
    spec = importlib.util.spec_from_file_location("run_stage", RUN_STAGE_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def run_traced():
    assert RUN_TRACED_SCRIPT.exists(), f"expected script at {RUN_TRACED_SCRIPT}"
    spec = importlib.util.spec_from_file_location("run_traced", RUN_TRACED_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)


def _make_target_repo(tmp_path: Path, name: str = "target-repo", *, with_evidence: bool = True) -> Path:
    """A real git repo with one commit. With evidence, a bare pyproject.toml
    at the root -- the exact fixture shape tests/patch/test_test_plan_discovery.py
    already uses, so gather_test_plan_evidence's citable_identifiers is
    the single-element {"pyproject.toml"}."""
    repo = tmp_path / name
    repo.mkdir()
    if with_evidence:
        (repo / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    else:
        (repo / ".gitkeep").write_text("", encoding="utf-8")
    _git("init", cwd=repo)
    _git("config", "user.email", "t@t.com", cwd=repo)
    _git("config", "user.name", "T", cwd=repo)
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "init", cwd=repo)
    return repo


def _head_sha(repo: Path, *, short: bool = False) -> str:
    fmt = "%h" if short else "%H"
    result = subprocess.run(
        ["git", "log", "-1", f"--format={fmt}"], cwd=repo, capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def _make_dirty(repo: Path) -> None:
    (repo / "untracked.txt").write_text("uncommitted\n", encoding="utf-8")


def _write_structured_source_trace(
    trace_dir: Path,
    *,
    repo_root: Path,
    repo_commit: "str | None" = None,
    patcher_commit: "str | None" = "1234567890abcdef1234567890abcdef12345678",
    llm_provider: "str | None" = "anthropic",
    llm_model: "str | None" = "claude-source-x",
    schema_version: "int | None" = 1,
    input_type: str = "cve",
    input_id: str = "CVE-2021-99999",
    trust_report_path: "str | None" = None,
) -> Path:
    """Hand-build a NEW-shape (schema_version-bearing) source trace
    directory -- exactly the shape run_traced.py's _replay_provenance now
    produces, built directly here so these tests exercise stage_replay.py
    in isolation from run_traced.py's own (separately tested) writer."""
    trace_dir.mkdir(parents=True, exist_ok=True)
    if repo_commit is None:
        repo_commit = _head_sha(repo_root)
    manifest = {
        "status": "success",
        "input_type": input_type,
        "input_id": input_id,
        "repo_root": str(repo_root),
        "output_dir": str(trace_dir.parent),
        "context_budget_policy": "never",
        "max_context_budget_windows": 10,
        "compare_existing_tests": False,
        "vulnerability_path": None,
        "trust_report_path": trust_report_path,
        "llm_call_count": 8,
        "checkpoints_file": "checkpoints.jsonl",
        "autopatcher_debug_artifacts": [],
    }
    if schema_version is not None:
        manifest["schema_version"] = schema_version
        manifest["target_repository"] = {"repo_root": str(repo_root), "repo_commit": repo_commit}
        manifest["openant"] = {"patcher_commit": patcher_commit}
        manifest["llm"] = {"provider": llm_provider, "model": llm_model}
    (trace_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return trace_dir


def _write_legacy_trust_report(path: Path, *, repo_commit: str, patcher_commit: str = "abc1234",
                                llm_provider: str = "anthropic", llm_model: str = "claude-legacy-x",
                                extra_repo_commit_row: bool = False) -> None:
    rows = f"| Repo commit | {repo_commit} |\n"
    if extra_repo_commit_row:
        rows += f"| Repo commit | {repo_commit}-duplicate |\n"
    rows += f"| Auto-patcher | {patcher_commit} |\n| LLM provider | {llm_provider} |\n| LLM model | {llm_model} |\n"
    text = (
        "# Trust Report\n\nSome report body.\n\n---\n\n## Run Metadata\n\n"
        "| Field | Value |\n|---|---|\n"
        "| Generated | 2026-01-01 00:00:00 UTC |\n"
        "| Input | x |\n"
        f"{rows}"
        "| LLM mode | LIVE |\n"
    )
    path.write_text(text, encoding="utf-8")


def _write_legacy_source_trace(
    trace_dir: Path, *, repo_root: Path, trust_report_path: Path, repo_commit_short: "str | None" = None,
) -> Path:
    """A trace with NO schema_version at all -- the shape every trace
    produced before this feature existed."""
    trace_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "status": "success",
        "input_type": "cve",
        "input_id": "CVE-2020-11111",
        "repo_root": str(repo_root),
        "trust_report_path": str(trust_report_path),
        "llm_call_count": 8,
        "checkpoints_file": "checkpoints.jsonl",
        "autopatcher_debug_artifacts": [],
    }
    (trace_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return trace_dir


def _accepted_response_json(evidence=("pyproject.toml",)) -> str:
    return json.dumps({
        "setup_commands": [["python", "-m", "pip", "install", "-e", "."]],
        "test_command": ["python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"],
        "result_strategy": "junit",
        "result_output_path": "/tmp/openant-result.xml",
        "runtime_family": "python",
        "runtime_version_hint": "3.11",
        "evidence": list(evidence),
        "reasoning_summary": "pyproject.toml declares pytest.",
        "confidence": "high",
    })


def _install_fake_call_llm(monkeypatch, response):
    """Replace utilities.autopatcher.llm_client.call_llm with a stub
    returning (or raising) `response`. Records every call for assertions.
    Used instead of LLM_PROVIDER=mock's built-in _mock_response() router,
    which routes test_plan_discovery's system prompt (its first line
    contains "OpenAnt's Auto Patcher") to the PATCH mock (a diff block,
    not JSON) -- this stub gives tests exact control over the JSON
    payload instead."""
    import utilities.autopatcher.llm_client as llm_client_module

    calls = []

    def fake(prompt, model=None, stage="unknown"):
        calls.append({"prompt": prompt, "model": model, "stage": stage})
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(llm_client_module, "call_llm", fake)
    return calls


# ---------------------------------------------------------------------------
# Part 3 -- source trace path resolution (deterministic, non-fuzzy)
# ---------------------------------------------------------------------------


class TestSourceTraceResolution:
    def test_accepts_run_root_directly(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        run_root = tmp_path / "run"
        _write_structured_source_trace(run_root, repo_root=repo)
        assert resolve_source_trace_dir(run_root) == run_root

    def test_accepts_trace_subdirectory_directly(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        run_root = tmp_path / "run"
        trace_subdir = run_root / "trace"
        _write_structured_source_trace(trace_subdir, repo_root=repo)
        # Both the run root AND the trace/ subdirectory itself must resolve.
        assert resolve_source_trace_dir(run_root) == trace_subdir
        assert resolve_source_trace_dir(trace_subdir) == trace_subdir

    def test_missing_manifest_fails_before_llm(self, tmp_path):
        empty_dir = tmp_path / "nothing-here"
        empty_dir.mkdir()
        with pytest.raises(StageReplayError, match="no run_manifest.json found"):
            resolve_source_trace_dir(empty_dir)

    def test_does_not_recursively_search(self, tmp_path):
        """A manifest three levels deep must NOT be found -- resolution is
        exact-name only (run root or run root/trace), never fuzzy/recursive."""
        repo = _make_target_repo(tmp_path)
        run_root = tmp_path / "run"
        deeply_nested = run_root / "a" / "b" / "trace"
        _write_structured_source_trace(deeply_nested, repo_root=repo)
        with pytest.raises(StageReplayError, match="no run_manifest.json found"):
            resolve_source_trace_dir(run_root)


# ---------------------------------------------------------------------------
# Schema validation + structured-vs-legacy provenance priority
# ---------------------------------------------------------------------------


class TestSchemaAndProvenancePriority:
    def test_unsupported_future_schema_fails_before_llm(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo, schema_version=999)
        manifest = load_source_manifest(trace_dir)
        with pytest.raises(StageReplayError, match="schema_version=999"):
            resolve_source_provenance(trace_dir, manifest)

    def test_structured_manifest_used_when_schema_version_present(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(
            tmp_path / "run", repo_root=repo, llm_provider="openai", llm_model="gpt-x",
        )
        manifest = load_source_manifest(trace_dir)
        provenance = resolve_source_provenance(trace_dir, manifest)
        assert provenance.source == "structured_manifest"
        assert provenance.repo_commit_is_short is False
        assert provenance.llm_provider == "openai"
        assert provenance.llm_model == "gpt-x"

    def test_structured_manifest_never_touches_trust_report(self, tmp_path):
        """Proves requirement: for NEW traces, replay must not depend on
        trust-report parsing -- point trust_report_path at a file that
        doesn't exist at all, and confirm resolution still succeeds."""
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(
            tmp_path / "run", repo_root=repo, trust_report_path="/nonexistent/does-not-exist.md",
        )
        manifest = load_source_manifest(trace_dir)
        provenance = resolve_source_provenance(trace_dir, manifest)
        assert provenance.source == "structured_manifest"

    def test_structured_manifest_missing_repo_commit_fails_closed(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        manifest = load_source_manifest(trace_dir)
        manifest["target_repository"]["repo_commit"] = None
        with pytest.raises(StageReplayError, match="repo_commit=null"):
            resolve_source_provenance(trace_dir, manifest)


class TestLegacyCompatibility:
    def test_legacy_trace_falls_back_to_run_metadata_table(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        short_sha = _head_sha(repo, short=True)
        trust_report = tmp_path / "trust-report.md"
        _write_legacy_trust_report(trust_report, repo_commit=short_sha)
        trace_dir = _write_legacy_source_trace(tmp_path / "run", repo_root=repo, trust_report_path=trust_report)

        manifest = load_source_manifest(trace_dir)
        provenance = resolve_source_provenance(trace_dir, manifest)
        assert provenance.source == "legacy_trust_report_fallback"
        assert provenance.repo_commit == short_sha
        assert provenance.repo_commit_is_short is True

    def test_legacy_trace_with_no_run_metadata_section_fails_closed(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        trust_report = tmp_path / "trust-report.md"
        trust_report.write_text("# Trust Report\n\nNo metadata section here.\n", encoding="utf-8")
        trace_dir = _write_legacy_source_trace(tmp_path / "run", repo_root=repo, trust_report_path=trust_report)

        manifest = load_source_manifest(trace_dir)
        with pytest.raises(StageReplayError, match="Run Metadata"):
            resolve_source_provenance(trace_dir, manifest)

    def test_legacy_trace_ambiguous_repo_commit_row_fails_closed(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        short_sha = _head_sha(repo, short=True)
        trust_report = tmp_path / "trust-report.md"
        _write_legacy_trust_report(trust_report, repo_commit=short_sha, extra_repo_commit_row=True)
        trace_dir = _write_legacy_source_trace(tmp_path / "run", repo_root=repo, trust_report_path=trust_report)

        manifest = load_source_manifest(trace_dir)
        with pytest.raises(StageReplayError, match="Repo commit"):
            resolve_source_provenance(trace_dir, manifest)

    def test_legacy_trace_unknown_repo_commit_fails_closed(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        trust_report = tmp_path / "trust-report.md"
        _write_legacy_trust_report(trust_report, repo_commit="unknown")
        trace_dir = _write_legacy_source_trace(tmp_path / "run", repo_root=repo, trust_report_path=trust_report)

        manifest = load_source_manifest(trace_dir)
        with pytest.raises(StageReplayError, match="Repo commit"):
            resolve_source_provenance(trace_dir, manifest)

    def test_legacy_trace_without_trust_report_fails_closed(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_legacy_source_trace(
            tmp_path / "run", repo_root=repo, trust_report_path=tmp_path / "missing.md",
        )
        manifest = load_source_manifest(trace_dir)
        with pytest.raises(StageReplayError, match="trust_report_path"):
            resolve_source_provenance(trace_dir, manifest)

    def test_legacy_trace_without_repo_root_fails_closed(self, tmp_path):
        trace_dir = tmp_path / "run"
        trace_dir.mkdir()
        manifest = {"status": "success", "trust_report_path": None}
        (trace_dir / "run_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        with pytest.raises(StageReplayError, match="repo_root"):
            resolve_source_provenance(trace_dir, manifest)


# ---------------------------------------------------------------------------
# Part 4 -- target-repository identity + clean-state safety gate
# ---------------------------------------------------------------------------


class TestTargetRepositoryIdentity:
    def _provenance(self, tmp_path, repo):
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        manifest = load_source_manifest(trace_dir)
        return resolve_source_provenance(trace_dir, manifest)

    def test_matching_clean_repo_passes(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        provenance = self._provenance(tmp_path, repo)
        resolved = validate_target_repository(None, provenance, stage="test_plan_discovery")
        assert resolved == repo

    def test_wrong_sha_fails_before_llm(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        provenance = self._provenance(tmp_path, repo)
        # Advance the repo to a second commit -- HEAD no longer matches.
        (repo / "new_file.txt").write_text("x\n", encoding="utf-8")
        _git("add", "-A", cwd=repo)
        _git("commit", "-m", "second", cwd=repo)

        with pytest.raises(StageReplayError, match="HEAD does not match source trace"):
            validate_target_repository(None, provenance, stage="test_plan_discovery")

    def test_dirty_repo_fails_before_llm(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        provenance = self._provenance(tmp_path, repo)
        _make_dirty(repo)

        with pytest.raises(StageReplayError, match="uncommitted changes"):
            validate_target_repository(None, provenance, stage="test_plan_discovery")

    def test_missing_repo_fails_before_llm(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        provenance = self._provenance(tmp_path, repo)
        import shutil

        shutil.rmtree(repo)

        with pytest.raises(StageReplayError, match="does not exist"):
            validate_target_repository(None, provenance, stage="test_plan_discovery")

    def test_non_git_directory_fails(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        provenance = self._provenance(tmp_path, repo)
        import shutil

        shutil.rmtree(repo / ".git")

        with pytest.raises(StageReplayError, match="not a git repository"):
            validate_target_repository(None, provenance, stage="test_plan_discovery")

    def test_repo_root_override_is_validated_the_same_way(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        # with_evidence=False -> different tree content, so this is
        # guaranteed a different commit SHA regardless of commit timestamp
        # granularity (two otherwise-identical trees committed within the
        # same second would otherwise hash identically).
        other_repo = _make_target_repo(tmp_path, name="other-repo", with_evidence=False)
        provenance = self._provenance(tmp_path, repo)

        with pytest.raises(StageReplayError, match="HEAD does not match source trace"):
            validate_target_repository(str(other_repo), provenance, stage="test_plan_discovery")

    def test_never_mutates_target_repository(self, tmp_path):
        """Purely observational: a wrong-SHA rejection must not have run
        git checkout/reset/clean against the target repo."""
        repo = _make_target_repo(tmp_path)
        provenance = self._provenance(tmp_path, repo)
        (repo / "new_file.txt").write_text("x\n", encoding="utf-8")
        _git("add", "-A", cwd=repo)
        _git("commit", "-m", "second", cwd=repo)
        sha_before = _head_sha(repo)

        with pytest.raises(StageReplayError):
            validate_target_repository(None, provenance, stage="test_plan_discovery")

        assert _head_sha(repo) == sha_before


# ---------------------------------------------------------------------------
# Output-directory safety (Part 9) -- never overlaps the source trace
# ---------------------------------------------------------------------------


class TestOutputDirectorySafety:
    def test_output_equal_to_source_trace_rejected(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        with pytest.raises(StageReplayError, match="same path"):
            replay_test_plan_discovery(source_trace=trace_dir, output_dir=trace_dir)

    def test_output_nested_inside_source_trace_rejected(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        with pytest.raises(StageReplayError, match="nested inside"):
            replay_test_plan_discovery(source_trace=trace_dir, output_dir=trace_dir / "nested-output")

    def test_source_trace_nested_inside_output_rejected(self, tmp_path):
        repo = _make_target_repo(tmp_path)
        run_root = tmp_path / "run"
        trace_dir = _write_structured_source_trace(run_root / "trace", repo_root=repo)
        with pytest.raises(StageReplayError, match="contains"):
            replay_test_plan_discovery(source_trace=trace_dir, output_dir=run_root)


# ---------------------------------------------------------------------------
# Stage dispatch (run_stage.py CLI) -- unsupported stage fails before any work
# ---------------------------------------------------------------------------


class TestStageDispatch:
    def test_unsupported_stage_fails_before_llm(self, run_stage, tmp_path, capsys):
        """"challenger" IS a canonical stage (utilities.autopatcher.
        stage_registry) but has no run_fn wired up yet in this batch --
        registered-but-not-replayable, not unknown."""
        exit_code = run_stage.main([
            "--source-run", str(tmp_path / "nonexistent"),
            "--stage", "challenger",
            "--output", str(tmp_path / "out"),
        ])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "challenger" in captured.err
        assert "not replayable yet" in captured.err
        assert "test_analysis_and_plan" in captured.err  # currently the only replayable stage
        assert not (tmp_path / "out").exists()  # zero work performed

    def test_unknown_stage_fails_before_llm(self, run_stage, tmp_path, capsys):
        """A stage name that isn't even in the canonical registry gets a
        DIFFERENT, more specific message than a registered-but-not-yet-
        replayable one."""
        exit_code = run_stage.main([
            "--source-run", str(tmp_path / "nonexistent"),
            "--stage", "not_a_real_stage",
            "--output", str(tmp_path / "out"),
        ])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert "Unknown stage" in captured.err
        assert "not_a_real_stage" in captured.err
        assert "test_analysis_and_plan" in captured.err  # canonical stage list is shown
        assert not (tmp_path / "out").exists()

    def test_only_test_plan_discovery_is_supported_in_phase_1(self):
        """stage_replay.SUPPORTED_STAGES is Phase 1's own, now-superseded
        dispatch set -- kept unchanged for backward compatibility of any
        direct caller of replay_test_plan_discovery(). The CLI's actual
        canonical stage list now comes from stage_registry.py (see
        TestCanonicalRegistryMigration below), not from this constant."""
        assert SUPPORTED_STAGES == frozenset({"test_plan_discovery"})


class TestCanonicalRegistryMigration:
    """Batch A: run_stage.py's --stage now comes from the 13-stage
    canonical registry, not the Phase-1 one-entry dispatch table."""

    def test_test_plan_discovery_is_no_longer_a_valid_cli_stage(self, run_stage, tmp_path, capsys):
        exit_code = run_stage.main([
            "--source-run", str(tmp_path / "nonexistent"),
            "--stage", "test_plan_discovery",
            "--output", str(tmp_path / "out"),
        ])
        assert exit_code == 2
        assert "Unknown stage" in capsys.readouterr().err

    def test_source_trace_flag_still_accepted_as_alias(self, run_stage, tmp_path, monkeypatch):
        """--source-trace remains a working alias for --source-run."""
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        exit_code = run_stage.main([
            "--source-trace", str(trace_dir), "--stage", "test_analysis_and_plan", "--output", str(output_dir),
        ])
        assert exit_code == 0


# ---------------------------------------------------------------------------
# End-to-end replay: accepted plan, rejected plan, LLM call guarantees,
# current-implementation proof, pipeline.run() never invoked.
# ---------------------------------------------------------------------------


class TestAcceptedPlanReplay:
    def test_accepted_plan_writes_parsed_result_json(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        calls = _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        assert result.outcome == "accepted"
        parsed = json.loads((output_dir / "parsed_result.json").read_text())
        assert parsed["test_command"] == ["python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"]
        assert parsed["result_strategy"] == "junit"
        assert parsed["confidence"] == "high"
        assert parsed["evidence"] == ["pyproject.toml"]
        assert len(calls) == 1

    def test_accepted_plan_also_writes_prompt_and_response(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        prompt_files = sorted(output_dir.glob("*test_plan_discovery.prompt.txt"))
        response_files = sorted(output_dir.glob("*test_plan_discovery.response.txt"))
        assert len(prompt_files) == 1
        assert len(response_files) == 1
        assert "pyproject.toml" in prompt_files[0].read_text()  # real, current-repo evidence


class TestRejectedPlanReplay:
    def test_rejected_plan_writes_rejection_reason_json(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, "not json at all")
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        assert result.outcome == "rejected"
        reason = json.loads((output_dir / "rejection_reason.json").read_text())["reason"]
        assert "not valid JSON" in reason
        assert not (output_dir / "parsed_result.json").exists()

    def test_rejected_plan_still_records_prompt_and_response(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, "not json at all")
        output_dir = tmp_path / "replay-out"

        replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        response_files = list(output_dir.glob("*test_plan_discovery.response.txt"))
        assert len(response_files) == 1
        assert response_files[0].read_text() == "not json at all"

    def test_rejected_plan_counts_as_successful_replay_exit_0(self, run_stage, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, "not json at all")
        output_dir = tmp_path / "replay-out"

        exit_code = run_stage.main([
            "--source-run", str(trace_dir), "--stage", "test_analysis_and_plan", "--output", str(output_dir),
        ])
        assert exit_code == 0


class TestCurrentImplementationInvoked:
    def test_current_discover_test_plan_is_the_one_called(self, tmp_path, monkeypatch):
        """Proves CURRENT code runs -- a change to the production
        implementation is immediately visible in the replay output."""
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)

        sentinel_calls = []

        def _fake_discover(repo_root, llm, *, rejection_reason=None):
            sentinel_calls.append((repo_root, llm))
            if rejection_reason is not None:
                rejection_reason.append("sentinel: replaced implementation ran")
            return None

        monkeypatch.setattr(stage_replay, "discover_test_plan", _fake_discover)
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        assert len(sentinel_calls) == 1
        reason = json.loads((output_dir / "rejection_reason.json").read_text())["reason"]
        assert reason == "sentinel: replaced implementation ran"
        assert result.outcome == "rejected"

    def test_historical_prompt_response_files_never_read(self, tmp_path, monkeypatch):
        """A stale prompt/response file already sitting in the SOURCE
        trace (as if from the original full run) must have zero effect on
        replay -- the historical text is never resent to any LLM, and is
        never read at all by the replay path."""
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        stale_prompt = trace_dir / "003_test_plan_discovery.prompt.txt"
        stale_response = trace_dir / "003_test_plan_discovery.response.txt"
        stale_prompt.write_text("HISTORICAL PROMPT -- must never be resent", encoding="utf-8")
        stale_response.write_text("HISTORICAL RESPONSE -- must never be reused", encoding="utf-8")

        calls = _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        assert len(calls) == 1
        assert "HISTORICAL PROMPT" not in calls[0]["prompt"]
        # The stale files in the SOURCE trace are untouched, not read into
        # the new prompt.
        assert stale_prompt.read_text() == "HISTORICAL PROMPT -- must never be resent"

    def test_pipeline_run_never_invoked(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())

        import utilities.autopatcher.pipeline as pipeline_module

        def _boom(**kwargs):
            raise AssertionError("pipeline.run() must never be invoked by single-stage replay")

        monkeypatch.setattr(pipeline_module, "run", _boom)
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)
        assert result.outcome == "accepted"  # would have raised AssertionError otherwise

    def test_stage_replay_module_does_not_import_pipeline(self):
        """Structural guarantee, on top of the runtime check above: the
        replay module's own source never imports pipeline.py or any other
        stage module -- a single-stage replay cannot call a function it
        never imported."""
        source = Path(stage_replay.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "from .pipeline import", "from . import pipeline", "import utilities.autopatcher.pipeline",
            "from .remediation_planner import", "from .patch_generator import",
            "from .patch_challenger import", "from .finding_calibration import",
            "from .patch_reviewer import", "from .confidence_scorer import",
        ):
            assert forbidden not in source, f"stage_replay.py must not import via {forbidden!r}"


class TestLLMCallGuarantee:
    """The core token/LLM-call guarantee: a test_plan_discovery replay
    makes exactly one LLM call, tagged stage=test_plan_discovery, and no
    other Auto Patcher stage function is ever invoked."""

    def test_exactly_one_call_stage_test_plan_discovery(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        calls = _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        assert len(calls) == 1
        assert calls[0]["stage"] == "test_plan_discovery"

    def test_no_other_autopatcher_stage_function_is_invoked(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())

        def _boom(name):
            def _inner(*args, **kwargs):
                raise AssertionError(f"{name} must never be invoked by a test_plan_discovery replay")
            return _inner

        import utilities.autopatcher.confidence_scorer as confidence_scorer_module
        import utilities.autopatcher.finding_calibration as finding_calibration_module
        import utilities.autopatcher.patch_challenger as patch_challenger_module
        import utilities.autopatcher.patch_generator as patch_generator_module
        import utilities.autopatcher.patch_reviewer as patch_reviewer_module
        import utilities.autopatcher.remediation_planner as remediation_planner_module

        monkeypatch.setattr(remediation_planner_module, "generate_remediation_plan", _boom("generate_remediation_plan"))
        monkeypatch.setattr(remediation_planner_module, "generate_remediation_strategy", _boom("generate_remediation_strategy"))
        monkeypatch.setattr(patch_generator_module, "generate_patch_raw", _boom("generate_patch_raw"))
        monkeypatch.setattr(patch_generator_module, "generate_patch", _boom("generate_patch"))
        monkeypatch.setattr(patch_challenger_module, "challenge_patch", _boom("challenge_patch"))
        monkeypatch.setattr(finding_calibration_module, "calibrate_findings", _boom("calibrate_findings"))
        monkeypatch.setattr(patch_reviewer_module, "review_patch", _boom("review_patch"))
        monkeypatch.setattr(confidence_scorer_module, "score_confidence", _boom("score_confidence"))

        output_dir = tmp_path / "replay-out"
        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)
        assert result.outcome == "accepted"  # any _boom() firing would have raised instead

    def test_zero_llm_calls_when_no_repository_evidence(self, tmp_path, monkeypatch):
        """discover_test_plan itself makes ZERO LLM calls when there is no
        repository evidence to reason from -- a legitimate, current-
        implementation "rejected" outcome, not an error, and not a case
        where the one-call guarantee is violated (it's an upper bound)."""
        repo = _make_target_repo(tmp_path, with_evidence=False)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        calls = _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        assert len(calls) == 0
        assert result.outcome == "rejected"
        reason = json.loads((output_dir / "rejection_reason.json").read_text())["reason"]
        assert "no repository evidence" in reason


# ---------------------------------------------------------------------------
# OpenAnt / LLM provenance: source vs. replay, recorded but never compared
# ---------------------------------------------------------------------------


class TestOpenAntProvenance:
    def test_dirty_openant_checkout_does_not_block_replay(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        # is_worktree_clean is used for BOTH the target-repo gate (Part 4,
        # must stay real/clean here) and the OpenAnt informational dirty
        # check (Part 5, this test's actual subject) -- only fake the
        # latter, by path, so the target-repo gate still passes for real.
        monkeypatch.setattr(stage_replay, "is_worktree_clean", lambda path: Path(path) == repo)
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        assert result.outcome == "accepted"
        assert result.manifest["openant"]["replay_openant_dirty"] is True

    def test_source_and_replay_openant_commit_may_differ(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(
            tmp_path / "run", repo_root=repo, patcher_commit="1111111111111111111111111111111111111a",
        )
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        # collect_full_commit_sha is used for BOTH the target-repo identity
        # check (Part 4, must stay real here) and the OpenAnt provenance
        # commit (Part 5, this test's actual subject) -- only fake the
        # latter, by path, so the target-repo gate still passes for real.
        real_collect = stage_replay.collect_full_commit_sha

        def _fake_collect(path):
            return real_collect(path) if Path(path) == repo else "2222222222222222222222222222222222222b"

        monkeypatch.setattr(stage_replay, "collect_full_commit_sha", _fake_collect)
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        openant = result.manifest["openant"]
        assert openant["source_patcher_commit"] == "1111111111111111111111111111111111111a"
        assert openant["replay_patcher_commit"] == "2222222222222222222222222222222222222b"
        assert openant["source_patcher_commit"] != openant["replay_patcher_commit"]


class TestLLMProvenance:
    def test_source_and_replay_llm_provider_may_differ(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(
            tmp_path / "run", repo_root=repo, llm_provider="anthropic", llm_model="claude-source-x",
        )
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        # Simulate the replay actually resolving to a different provider,
        # without any real credential/network resolution.
        monkeypatch.setattr(stage_replay, "ensure_provider_configured", lambda: None)
        import utilities.autopatcher.llm_client as llm_client_module

        monkeypatch.setattr(llm_client_module, "_cached_provider", "openai")
        monkeypatch.setattr(llm_client_module, "_cached_model", {"openai": "gpt-replay-y"})
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        llm = result.manifest["llm"]
        assert llm["source_provider"] == "anthropic"
        assert llm["source_model"] == "claude-source-x"
        assert llm["replay_provider"] == "openai"
        assert llm["replay_model"] == "gpt-replay-y"

    def test_both_source_and_replay_llm_provenance_recorded_by_default(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(
            tmp_path / "run", repo_root=repo, llm_provider="anthropic", llm_model="claude-source-x",
        )
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        llm = result.manifest["llm"]
        assert llm["source_provider"] == "anthropic"
        assert llm["replay_provider"] == "mock"  # this test's real, hermetic resolution
        assert llm["replay_model"] == "mock"

    def test_llm_config_unresolvable_fails_before_stage_execution(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        calls = _install_fake_call_llm(monkeypatch, _accepted_response_json())

        def _boom():
            raise RuntimeError("no usable LLM configuration")

        monkeypatch.setattr(stage_replay, "ensure_provider_configured", _boom)
        output_dir = tmp_path / "replay-out"

        with pytest.raises(RuntimeError, match="no usable LLM configuration"):
            replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        assert len(calls) == 0
        assert not output_dir.exists()  # nothing written for an infra-level failure


class TestReplayManifestProvenance:
    def test_replay_manifest_records_source_run_identity(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(
            tmp_path / "run", repo_root=repo, input_type="cve", input_id="CVE-2021-99999",
        )
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        result = replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        on_disk = json.loads((output_dir / "replay_manifest.json").read_text())
        assert on_disk == result.manifest
        assert on_disk["stage"] == "test_plan_discovery"
        assert on_disk["source_run"] == {"input_type": "cve", "input_id": "CVE-2021-99999"}
        assert on_disk["target_repository"]["repo_commit"] == _head_sha(repo)
        assert on_disk["llm_call_count"] == 1
        assert isinstance(on_disk["duration_seconds"], (int, float))


# ---------------------------------------------------------------------------
# Part 9 / immutability: replay output isolated, source trace never mutated
# ---------------------------------------------------------------------------


class TestSourceTraceImmutability:
    def test_replay_output_separate_from_source_trace(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        replay_test_plan_discovery(source_trace=trace_dir, output_dir=output_dir)

        assert output_dir != trace_dir
        assert list(trace_dir.iterdir()) == [trace_dir / "run_manifest.json"]  # unchanged, nothing added

    def test_source_trace_byte_for_byte_unchanged(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        # A couple of extra "historical" files, as a real run_traced.py
        # trace would have -- prove ALL of them, not just run_manifest.json,
        # survive untouched.
        (trace_dir / "checkpoints.jsonl").write_text('{"seq": 1}\n', encoding="utf-8")
        (trace_dir / "001_remediation_planning.prompt.txt").write_text("hello", encoding="utf-8")

        before = {
            p: (p.read_bytes(), p.stat().st_mtime_ns) for p in sorted(trace_dir.rglob("*")) if p.is_file()
        }

        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        replay_test_plan_discovery(source_trace=trace_dir, output_dir=tmp_path / "replay-out")

        after = {
            p: (p.read_bytes(), p.stat().st_mtime_ns) for p in sorted(trace_dir.rglob("*")) if p.is_file()
        }
        assert before == after

    def test_rejected_replay_also_leaves_source_trace_unchanged(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        before = (trace_dir / "run_manifest.json").read_bytes()

        _install_fake_call_llm(monkeypatch, "not json at all")
        replay_test_plan_discovery(source_trace=trace_dir, output_dir=tmp_path / "replay-out")

        assert (trace_dir / "run_manifest.json").read_bytes() == before


# ---------------------------------------------------------------------------
# run_stage.py CLI, end to end
# ---------------------------------------------------------------------------


class TestRunStageCLI:
    def test_cli_success_prints_json_with_outcome(self, run_stage, tmp_path, monkeypatch, capsys):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        exit_code = run_stage.main([
            "--source-run", str(trace_dir), "--stage", "test_analysis_and_plan", "--output", str(output_dir),
        ])

        assert exit_code == 0
        printed = json.loads(capsys.readouterr().out)
        assert printed["stage"] == "test_analysis_and_plan"
        assert printed["outcome"] == "accepted"
        assert printed["output_dir"] == str(output_dir)

    def test_cli_infrastructure_failure_returns_2_before_any_llm_call(self, run_stage, tmp_path, monkeypatch, capsys):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        calls = _install_fake_call_llm(monkeypatch, _accepted_response_json())
        (repo / "new_file.txt").write_text("x\n", encoding="utf-8")
        _git("add", "-A", cwd=repo)
        _git("commit", "-m", "second", cwd=repo)  # HEAD no longer matches the trace
        output_dir = tmp_path / "replay-out"

        exit_code = run_stage.main([
            "--source-run", str(trace_dir), "--stage", "test_analysis_and_plan", "--output", str(output_dir),
        ])

        assert exit_code == 2
        assert "HEAD does not match" in capsys.readouterr().err
        assert len(calls) == 0

    def test_cli_repo_root_override_flag(self, run_stage, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        trace_dir = _write_structured_source_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        exit_code = run_stage.main([
            "--source-run", str(trace_dir), "--stage", "test_analysis_and_plan",
            "--output", str(output_dir), "--repo-root", str(repo),
        ])
        assert exit_code == 0


# ---------------------------------------------------------------------------
# True end-to-end: a REAL run_traced.py trace consumed by REAL run_stage.py
# -- proves the producer and consumer actually agree on the schema, not
# just that stage_replay.py agrees with this file's own hand-built
# fixtures (see the module docstring).
# ---------------------------------------------------------------------------


class TestEndToEndRealRunTracedThenRunStage:
    FIXTURE_CVE = {
        "id": "CVE-2021-77777",
        "descriptions": [{"lang": "en", "value": "A test vulnerability."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
    }

    def test_real_trace_is_replayable_by_real_run_stage(self, run_traced, run_stage, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo = _make_target_repo(tmp_path)
        trace_output_dir = tmp_path / "full-run-out"

        with mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=self.FIXTURE_CVE):
            exit_code = run_traced.main([
                "--cve", "CVE-2021-77777", "--repo-root", str(repo), "--output", str(trace_output_dir),
            ])
        assert exit_code == 0

        source_trace = trace_output_dir / "trace"
        manifest = json.loads((source_trace / "run_manifest.json").read_text())
        assert manifest["schema_version"] == 3  # sanity: this really is a NEW trace

        # Now replay test_analysis_and_plan from that REAL trace (Batch A:
        # its transitional implementation exercises exactly the same
        # discover_test_plan call Phase 1's test_plan_discovery replay
        # did), with a controlled response so this assertion is about
        # wiring, not LLM content.
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        replay_output_dir = tmp_path / "replay-out"

        exit_code = run_stage.main([
            "--source-run", str(source_trace), "--stage", "test_analysis_and_plan",
            "--output", str(replay_output_dir),
        ])

        assert exit_code == 0
        replay_manifest = json.loads((replay_output_dir / "run_manifest.json").read_text())
        assert replay_manifest["kind"] == "replay"
        assert "replaces_stage" not in replay_manifest
        assert "stages" not in replay_manifest
        matching = [e for e in replay_manifest["executions"] if e["canonical_stage"] == "test_analysis_and_plan"]
        assert len(matching) == 1
        execution = matching[0]
        assert execution["invocation_kind"] == "replay"
        assert execution["outcome"] == "accepted"
        assert execution["transitional"] is True
        assert replay_manifest["target_repository"]["repo_commit"] == _head_sha(repo)


# ---------------------------------------------------------------------------
# Repository placement: the tracing/replay tooling is tracked Auto Patcher
# development capability living at utilities/autopatcher/tools/, not
# gitignored scratch tooling under scripts/local/. These tests guard
# against the move regressing (files reappearing at the old location) or
# only half-completing (new location missing/not runnable).
# ---------------------------------------------------------------------------


class TestToolingRepositoryPlacement:
    OLD_SCRIPTS_LOCAL = Path(__file__).resolve().parent.parent.parent / "scripts" / "local"

    def test_new_tools_directory_is_a_normal_importable_package(self):
        """utilities/autopatcher/tools/ is a real package (has __init__.py),
        consistent with every other directory under utilities/ -- not a
        bare directory of loose scripts."""
        assert (_TOOLS_DIR / "__init__.py").is_file()

    def test_run_traced_and_run_stage_live_under_tools(self):
        assert RUN_TRACED_SCRIPT == _TOOLS_DIR / "run_traced.py"
        assert RUN_STAGE_SCRIPT == _TOOLS_DIR / "run_stage.py"
        assert RUN_TRACED_SCRIPT.is_file()
        assert RUN_STAGE_SCRIPT.is_file()

    def test_documentation_lives_alongside_the_tools(self):
        doc = _TOOLS_DIR / "TRACING_AND_DEBUGGING.md"
        assert doc.is_file()
        assert "utilities/autopatcher/tools/run_traced.py" in doc.read_text(encoding="utf-8")

    def test_old_scripts_local_copies_no_longer_exist(self):
        """No duplicate ACTIVE copy of either tool remains at the old,
        gitignored location -- a stale copy there would silently diverge
        from the tracked one and could be run by mistake."""
        assert not (self.OLD_SCRIPTS_LOCAL / "run_traced.py").exists()
        assert not (self.OLD_SCRIPTS_LOCAL / "run_stage.py").exists()
        assert not (self.OLD_SCRIPTS_LOCAL / "TRACING_AND_DEBUGGING.md").exists()

    def test_reusable_replay_logic_is_normally_importable(self):
        """stage_replay.py and llm_call_tracing.py are ordinary importable
        Auto Patcher modules (not tied to the tools/ location at all) --
        this is what lets run_stage.py stay a thin CLI wrapper."""
        import importlib

        stage_replay_module = importlib.import_module("utilities.autopatcher.stage_replay")
        tracing_module = importlib.import_module("utilities.autopatcher.llm_call_tracing")
        assert hasattr(stage_replay_module, "replay_test_plan_discovery")
        assert hasattr(tracing_module, "LLMCallCapture")

    def test_run_traced_and_stage_replay_share_the_same_capture_class(self):
        """Proof the tracing-capture duplication was actually reduced:
        tools/run_traced.py's LLMCallTracer and stage_replay.py both build
        on the exact same LLMCallCapture class, not two independent
        copies."""
        import utilities.autopatcher.llm_call_tracing as tracing_module

        run_traced_source = RUN_TRACED_SCRIPT.read_text(encoding="utf-8")
        stage_replay_source = Path(stage_replay.__file__).read_text(encoding="utf-8")
        assert "from utilities.autopatcher.llm_call_tracing import LLMCallCapture" in run_traced_source
        assert "from .llm_call_tracing import LLMCallCapture" in stage_replay_source
        # Neither file redefines its own monkeypatch-call_llm mechanics.
        assert "def _traced_call_llm" not in stage_replay_source
        assert tracing_module.LLMCallCapture.__module__ == "utilities.autopatcher.llm_call_tracing"
