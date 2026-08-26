"""Tests for the early, whole-run-aborting test-comparison-environment gate:

    core.patch.TestComparisonEnvironmentError
    core.patch._require_test_comparison_environment
    core.patch._run_engine_and_write_artifacts (calls the above first)

This is the fix for the real observed problem: with --compare-existing-tests
requested and Docker unavailable, the Auto Patcher pipeline (repository
parsing, Repository Understanding, remediation planning, patch
generation -- all of it) must never start, and no Anthropic LLM call may
ever be made, no matter which entry point (openant patch / run_traced.py)
is used -- both converge on _run_engine_and_write_artifacts, the single
shared boundary this gate lives on.

Hermetic throughout: fetch_cve mocked, pipeline.run mocked, no network, no
Docker, no repo beyond tmp_path.
"""

from __future__ import annotations

from unittest import mock

import pytest

import core.patch as core_patch
from core.patch import TestComparisonEnvironmentError, run_patch, run_patch_cve
from utilities.autopatcher.test_execution_models import ExecutorPreflightResult

FIXTURE_CVE = {
    "id": "CVE-2021-12345",
    "descriptions": [{"lang": "en", "value": "A SQL injection vulnerability exists."}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
}


def _mock_fetch_cve_at_source(cve=FIXTURE_CVE):
    return mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve)


def _preflight(ready: bool, status: str = "OK", reason=None) -> ExecutorPreflightResult:
    return ExecutorPreflightResult(ready=ready, status=status, reason=reason)


def _write_pipeline_output(tmp_path, findings):
    import json
    path = tmp_path / "pipeline_output.json"
    path.write_text(json.dumps({"findings": findings}), encoding="utf-8")
    return str(path)


FIXTURE_FINDING = {
    "id": "F-001", "name": "SQL Injection", "cwe_id": 89,
    "stage2_verdict": "confirmed",
    "location": {"file": "app.py", "function": "handler"},
}


# ---------------------------------------------------------------------------
# Unit tests: _require_test_comparison_environment / TestComparisonEnvironmentError
# ---------------------------------------------------------------------------

class TestRequireTestComparisonEnvironment:
    def test_flag_off_is_a_pure_noop(self):
        with mock.patch(
            "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment"
        ) as m_preflight:
            core_patch._require_test_comparison_environment(False)
        m_preflight.assert_not_called()

    def test_flag_on_and_ready_does_not_raise(self):
        with mock.patch(
            "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
            return_value=_preflight(ready=True, status="OK"),
        ):
            core_patch._require_test_comparison_environment(True)  # must not raise

    def test_cli_missing_raises_with_exact_actionable_message(self):
        with mock.patch(
            "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
            return_value=_preflight(ready=False, status="CLI_MISSING", reason="docker is not installed."),
        ):
            with pytest.raises(TestComparisonEnvironmentError) as exc_info:
                core_patch._require_test_comparison_environment(True)
        message = str(exc_info.value)
        assert message == (
            "--compare-existing-tests requires Docker, but the `docker` command was not found. "
            "Install/start Docker and rerun."
        )

    def test_daemon_unreachable_raises_with_daemon_specific_message(self):
        with mock.patch(
            "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
            return_value=_preflight(
                ready=False, status="DAEMON_UNREACHABLE",
                reason=(
                    "the Docker daemon is not reachable (Cannot connect to the Docker daemon). "
                    "Start Docker and rerun with --compare-existing-tests."
                ),
            ),
        ):
            with pytest.raises(TestComparisonEnvironmentError) as exc_info:
                core_patch._require_test_comparison_environment(True)
        message = str(exc_info.value)
        assert "requires Docker" in message
        assert "Cannot connect to the Docker daemon" in message  # bounded technical detail preserved
        assert message.lower().count("start docker") == 1  # no duplicate call-to-action

    def test_message_never_repeats_the_call_to_action(self):
        """Regression test for the exact bug observed in the real run:
        docker_preflight's own reason already ends with its own
        actionable next step -- composing a second one here must never
        produce 'Start Docker and rerun ... Start Docker and rerun ...'."""
        with mock.patch(
            "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
            return_value=_preflight(
                ready=False, status="DAEMON_UNREACHABLE",
                reason=(
                    "the Docker daemon is not reachable (boom). "
                    "Start Docker and rerun with --compare-existing-tests."
                ),
            ),
        ):
            with pytest.raises(TestComparisonEnvironmentError) as exc_info:
                core_patch._require_test_comparison_environment(True)
        message = str(exc_info.value)
        assert message.lower().count("start docker and rerun") == 1

    def test_timeout_raises_before_pipeline_with_bounded_message(self):
        with mock.patch(
            "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
            return_value=_preflight(
                ready=False, status="TIMEOUT",
                reason="the Docker readiness check (`docker info`) timed out after 5s.",
            ),
        ):
            with pytest.raises(TestComparisonEnvironmentError) as exc_info:
                core_patch._require_test_comparison_environment(True)
        assert len(str(exc_info.value)) < 500
        assert "timed out" in str(exc_info.value)

    def test_never_dumps_a_raw_result_object_no_traceback_style_text(self):
        with mock.patch(
            "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
            return_value=_preflight(ready=False, status="ERROR", reason="unexpected: boom"),
        ):
            with pytest.raises(TestComparisonEnvironmentError) as exc_info:
                core_patch._require_test_comparison_environment(True)
        message = str(exc_info.value)
        assert "Traceback" not in message
        assert "ExecutorPreflightResult" not in message


# ---------------------------------------------------------------------------
# Ordering invariant, at the highest useful shared boundary: run_patch_cve
# ---------------------------------------------------------------------------

class TestOrderingInvariantCveMode:
    def test_docker_unready_aborts_before_fetch_cve_before_pipeline_run_before_any_llm_call(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        import utilities.autopatcher.pipeline as pipeline_module
        import utilities.autopatcher.llm_client as llm_client_module

        with _mock_fetch_cve_at_source() as m_fetch_cve, \
             mock.patch.object(pipeline_module, "run") as m_pipeline_run, \
             mock.patch.object(llm_client_module, "call_llm") as m_call_llm, \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=_preflight(ready=False, status="CLI_MISSING", reason="docker is not installed."),
             ):
            with pytest.raises(TestComparisonEnvironmentError):
                run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path), compare_existing_tests=True)

        m_fetch_cve.assert_not_called()  # the key correction: NVD fetch never happens either
        m_pipeline_run.assert_not_called()
        m_call_llm.assert_not_called()

    def test_preflight_runs_strictly_before_fetch_cve_call_order(self, tmp_path, monkeypatch):
        """Direct call-order proof (not just "fetch_cve wasn't called"):
        even on the READY path, preflight must be invoked before
        fetch_cve, never interleaved or reversed."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        call_order = []

        def _preflight_side_effect():
            call_order.append("preflight")
            return _preflight(ready=True, status="OK")

        def _fetch_side_effect(cve_id):
            call_order.append("fetch_cve")
            return FIXTURE_CVE

        import utilities.autopatcher.pipeline as pipeline_module

        with mock.patch(
                 "utilities.autopatcher.cve_fetcher.fetch_cve", side_effect=_fetch_side_effect,
             ), \
             mock.patch.object(pipeline_module, "run", return_value="# Trust Report\n"), \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 side_effect=_preflight_side_effect,
             ):
            run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path), compare_existing_tests=True)

        assert call_order == ["preflight", "fetch_cve"]

    def test_docker_unready_produces_no_trust_report_or_vulnerability_artifact(self, tmp_path, monkeypatch):
        """No patch run/report at all -- the requested command never
        started, it did not run and produce a 'Not Verified' report."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source() as m_fetch_cve, \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=_preflight(ready=False, status="DAEMON_UNREACHABLE", reason="not reachable."),
             ):
            with pytest.raises(TestComparisonEnvironmentError):
                run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path), compare_existing_tests=True)

        m_fetch_cve.assert_not_called()
        assert not (tmp_path / "patch").exists()

    def test_docker_ready_proceeds_to_pipeline_exactly_as_before(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        import utilities.autopatcher.pipeline as pipeline_module

        with _mock_fetch_cve_at_source() as m_fetch_cve, \
             mock.patch.object(pipeline_module, "run", return_value="# Trust Report\n") as m_pipeline_run, \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=_preflight(ready=True, status="OK"),
             ):
            result = run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path), compare_existing_tests=True)

        m_fetch_cve.assert_called_once()  # normal flow: fetch happens AFTER preflight passes
        m_pipeline_run.assert_called_once()
        assert m_pipeline_run.call_args.kwargs["compare_existing_tests"] is True
        assert result.trust_report_path

    def test_only_one_outer_preflight_call_on_a_successful_run(self, tmp_path, monkeypatch):
        """Avoid three preflights: on a successful path this outer,
        whole-run gate must fire exactly once. The SEPARATE inner
        defense-in-depth preflight inside evaluate_existing_test_
        regression is not reached at all here since pipeline.run is
        mocked wholesale -- see test_existing_test_regression.py for
        that layer's own coverage."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        import utilities.autopatcher.pipeline as pipeline_module

        with _mock_fetch_cve_at_source(), \
             mock.patch.object(pipeline_module, "run", return_value="# Trust Report\n"), \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=_preflight(ready=True, status="OK"),
             ) as m_preflight:
            run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path), compare_existing_tests=True)

        m_preflight.assert_called_once()

    def test_flag_absent_never_calls_the_new_preflight_at_all(self, tmp_path, monkeypatch):
        """--compare-existing-tests not requested -> zero NEW Docker preflight
        at command entry -- existing behavior completely unchanged."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        import utilities.autopatcher.pipeline as pipeline_module

        with _mock_fetch_cve_at_source(), \
             mock.patch.object(pipeline_module, "run", return_value="# Trust Report\n"), \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment"
             ) as m_preflight:
            run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path))  # compare_existing_tests defaults False

        m_preflight.assert_not_called()


# ---------------------------------------------------------------------------
# Ordering invariant, Finding mode: run_patch
# ---------------------------------------------------------------------------

class TestOrderingInvariantFindingMode:
    def test_docker_unready_aborts_before_pipeline_run_and_before_any_llm_call(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        pipeline_output = _write_pipeline_output(tmp_path, [FIXTURE_FINDING])

        import utilities.autopatcher.pipeline as pipeline_module
        import utilities.autopatcher.llm_client as llm_client_module

        with mock.patch.object(pipeline_module, "run") as m_pipeline_run, \
             mock.patch.object(llm_client_module, "call_llm") as m_call_llm, \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=_preflight(ready=False, status="CLI_MISSING", reason="docker is not installed."),
             ):
            with pytest.raises(TestComparisonEnvironmentError):
                run_patch(
                    pipeline_output_path=pipeline_output, finding_id="F-001",
                    output_dir=str(tmp_path), repo_root=str(repo_root), compare_existing_tests=True,
                )

        m_pipeline_run.assert_not_called()
        m_call_llm.assert_not_called()

    def test_docker_ready_proceeds_to_pipeline_exactly_as_before(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        pipeline_output = _write_pipeline_output(tmp_path, [FIXTURE_FINDING])

        import utilities.autopatcher.pipeline as pipeline_module

        with mock.patch.object(pipeline_module, "run", return_value="# Trust Report\n") as m_pipeline_run, \
             mock.patch(
                 "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
                 return_value=_preflight(ready=True, status="OK"),
             ):
            result = run_patch(
                pipeline_output_path=pipeline_output, finding_id="F-001",
                output_dir=str(tmp_path), repo_root=str(repo_root), compare_existing_tests=True,
            )

        m_pipeline_run.assert_called_once()
        assert result.trust_report_path

    def test_docker_unready_aborts_before_pipeline_output_is_even_read(self, tmp_path, monkeypatch):
        """As early as practical: pipeline_output_path is never opened at
        all when the test-comparison-environment gate fails -- a NONEXISTENT
        path is passed here specifically so that, if the gate did NOT
        run first, the failure would instead be a FileNotFoundError, not
        TestComparisonEnvironmentError."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        nonexistent_pipeline_output = str(tmp_path / "does-not-exist.json")

        with mock.patch(
            "utilities.autopatcher.existing_test_regression.preflight_test_comparison_environment",
            return_value=_preflight(ready=False, status="CLI_MISSING", reason="docker is not installed."),
        ):
            with pytest.raises(TestComparisonEnvironmentError):
                run_patch(
                    pipeline_output_path=nonexistent_pipeline_output, finding_id="F-001",
                    output_dir=str(tmp_path), repo_root=str(repo_root), compare_existing_tests=True,
                )
