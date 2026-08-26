"""Pipeline wiring tests for Existing Test Comparison
(--compare-existing-tests).

Docker/pytest execution itself is never exercised here --
utilities.autopatcher.pipeline.evaluate_existing_test_comparison is always
mocked. These tests cover the wiring contract: opt-in gating, running only
after the FINAL candidate patch has settled (post-repair), the
PipelineResult field, the report section, the Trust Signal, and that the
feature flag being off changes nothing else about the run.
"""

from __future__ import annotations

from unittest import mock

import pytest


_CLEAN_DIFF = """\
```diff
--- a/src/app/util.py
+++ b/src/app/util.py
@@ -1,2 +1,3 @@
 def util():
+    pass
     pass
```"""

_REPAIR_DIFF = """\
```diff
--- a/src/app/util.py
+++ b/src/app/util.py
@@ -1,2 +1,3 @@
 def util():
+    # repaired
     pass
```"""

_APPLICABILITY_CLEAN = {
    "applicable": True, "skipped": False, "stderr": "",
    "exit_code": 0, "skipped_reason": None, "error": None,
}

_CHALLENGER_WITH_DEFECT = {
    "still_vulnerable": False,
    "edge_cases": ["An attacker can bypass this check via crafted input"],
    "potential_issues": [],
    "summary": "The patch has a confirmed bypass.",
}

_CHALLENGER_CLEAN = {
    "still_vulnerable": False,
    "edge_cases": [],
    "potential_issues": [],
    "summary": "No issues found.",
}


def _calibrate_all_observed(vulnerability_text, patch, findings, llm, code_context=""):
    return [{"original": f, "group": "observed", "reworded": f} for f in findings]


def _run_pipeline(
    tmp_path, *, compare_existing_tests, repo_root=None,
    patches_gen=(_CLEAN_DIFF,), patches_chall=(_CHALLENGER_CLEAN,),
    etr_return_value=None, etr_side_effect=None,
):
    """Run pipeline.run() with everything mocked except the wiring under
    test. Returns (PipelineResult, report, mock_evaluate)."""
    captured = {}
    import utilities.autopatcher.pipeline as _pipeline_mod
    orig_build = _pipeline_mod._build_report

    def _capture(r):
        captured["result"] = r
        return orig_build(r)

    with (
        mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
        mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=patches_gen[0]),
        mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen[1:]),
        mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                   return_value=_APPLICABILITY_CLEAN),
        mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
        mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=patches_chall),
        mock.patch("utilities.autopatcher.pipeline.calibrate_findings", side_effect=_calibrate_all_observed),
        mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
        mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
        mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        mock.patch("utilities.autopatcher.pipeline._build_report", side_effect=_capture),
        mock.patch(
            "utilities.autopatcher.pipeline.evaluate_existing_test_comparison",
            return_value=etr_return_value, side_effect=etr_side_effect,
        ) as mock_evaluate,
    ):
        mock_llm_cls.return_value = mock.MagicMock()
        from utilities.autopatcher.pipeline import run
        report = run(
            "test vuln", api_key="",
            repo_root=repo_root if repo_root is not None else str(tmp_path),
            compare_existing_tests=compare_existing_tests,
        )

    return captured["result"], report, mock_evaluate


class TestFeatureFlagOff:
    def test_evaluate_never_called(self, tmp_path):
        result, report, mock_evaluate = _run_pipeline(tmp_path, compare_existing_tests=False)
        mock_evaluate.assert_not_called()

    def test_field_stays_none(self, tmp_path):
        result, report, _ = _run_pipeline(tmp_path, compare_existing_tests=False)
        assert result.existing_test_comparison is None

    def test_report_shows_not_requested(self, tmp_path):
        _, report, _ = _run_pipeline(tmp_path, compare_existing_tests=False)
        assert "## Existing Test Comparison" in report
        assert "Not requested" in report

    def test_existing_test_comparison_section_deterministic_across_repeated_runs(self, tmp_path):
        """With the flag off, this feature's own section/signal must be
        byte-identical across repeated runs (no nondeterminism introduced
        by this feature) -- checked in isolation from unrelated sections,
        since a MagicMock-based Impact Surface mock elsewhere in this
        pipeline already embeds a nondeterministic object id irrespective
        of this feature."""
        import re

        def _section(report: str) -> str:
            m = re.search(r"## Existing Test Comparison\n.*?(?=\n## |\Z)", report, re.DOTALL)
            return m.group(0) if m else ""

        _, report_a, _ = _run_pipeline(tmp_path, compare_existing_tests=False)
        _, report_b, _ = _run_pipeline(tmp_path, compare_existing_tests=False)
        assert _section(report_a) == _section(report_b)
        assert _section(report_a) != ""


class TestFeatureFlagOn:
    def test_not_verified_when_no_repo_root(self, tmp_path):
        result, report, mock_evaluate = _run_pipeline(tmp_path, compare_existing_tests=True, repo_root="")
        mock_evaluate.assert_not_called()
        assert result.existing_test_comparison is not None
        assert result.existing_test_comparison.status == "NOT_VERIFIED"
        assert "no repository root" in result.existing_test_comparison.reason

    def test_evaluate_called_once_when_applicable(self, tmp_path):
        from utilities.autopatcher.existing_test_regression import ExistingTestComparisonResult
        fake_result = ExistingTestComparisonResult(
            status="PASS", command=("python", "-m", "pytest"), baseline=None, patched=None,
            reason="No failures in either the baseline or the patched run.",
        )
        result, report, mock_evaluate = _run_pipeline(
            tmp_path, compare_existing_tests=True, etr_return_value=fake_result,
        )
        mock_evaluate.assert_called_once()
        assert result.existing_test_comparison is fake_result

    def test_uses_final_patch_after_repair_not_pre_repair_candidate(self, tmp_path):
        """The repair loop replaces `patch` with the repaired diff;
        evaluate_existing_test_comparison must be called with THAT final
        patch, never the original pre-repair candidate."""
        from utilities.autopatcher.existing_test_regression import ExistingTestComparisonResult
        fake_result = ExistingTestComparisonResult(
            status="PASS", command=("python", "-m", "pytest"), baseline=None, patched=None, reason="ok",
        )
        result, report, mock_evaluate = _run_pipeline(
            tmp_path, compare_existing_tests=True,
            patches_gen=(_CLEAN_DIFF, _REPAIR_DIFF),
            patches_chall=(_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN),
            etr_return_value=fake_result,
        )
        assert result.repair_succeeded is True
        mock_evaluate.assert_called_once()
        called_repo_root, called_patch = mock_evaluate.call_args[0]
        assert "repaired" in called_patch
        assert called_patch == result.patch

    def test_exception_inside_evaluate_degrades_to_test_execution_error(self, tmp_path):
        result, report, mock_evaluate = _run_pipeline(
            tmp_path, compare_existing_tests=True, etr_side_effect=RuntimeError("docker exploded"),
        )
        assert result.existing_test_comparison is not None
        assert result.existing_test_comparison.status == "TEST_EXECUTION_ERROR"
        assert "docker exploded" in result.existing_test_comparison.reason

    def test_report_and_signal_present(self, tmp_path):
        from utilities.autopatcher.existing_test_regression import ExistingTestComparisonResult
        fake_result = ExistingTestComparisonResult(
            status="NEW_FAILURES_DETECTED", command=("python", "-m", "pytest"),
            baseline=None, patched=None, newly_failing_tests=["tests.test_x::test_y"],
            reason="1 test(s) newly failing after the patch.",
        )
        result, report, _ = _run_pipeline(tmp_path, compare_existing_tests=True, etr_return_value=fake_result)
        assert "## Existing Test Comparison" in report
        assert "1 new failure after the candidate patch" in report
        assert "tests.test_x::test_y" in report
        assert "Were there new test failures after the patch?" in report


class TestRecommendationPolicyUnaffected:
    def test_recommendation_identical_regardless_of_test_comparison_status(self, tmp_path):
        """Confirms, at the full-pipeline level (not just the unit-level
        neutrality test in test_trust_package.py), that the final
        Recommendation decision line is unchanged by this signal."""
        from utilities.autopatcher.existing_test_regression import ExistingTestComparisonResult
        import re

        def _decision(report: str) -> str:
            m = re.search(r"^## [^\n]*\n", report, re.MULTILINE)
            return m.group(0) if m else ""

        _, report_off, _ = _run_pipeline(tmp_path, compare_existing_tests=False)
        decisions = {_decision(report_off)}

        for status in ("PASS", "NEW_FAILURES_DETECTED", "PRE_EXISTING_FAILURES_ONLY", "TEST_EXECUTION_ERROR"):
            fake_result = ExistingTestComparisonResult(
                status=status, command=("python", "-m", "pytest"), baseline=None, patched=None, reason="r",
            )
            _, report_on, _ = _run_pipeline(tmp_path, compare_existing_tests=True, etr_return_value=fake_result)
            decisions.add(_decision(report_on))

        assert len(decisions) == 1, f"Decision line changed across test-comparison statuses: {decisions}"

    def test_recommendation_unaffected_by_an_environment_preflight_failure(self, tmp_path):
        """Same guarantee, specifically for the new environment-preflight
        NOT_VERIFIED shape (e.g. "test comparison did not start: the
        Docker daemon is not reachable...") -- a preflight failure must be
        exactly as inert to Recommendation Policy as every other Existing
        Test Comparison outcome."""
        from utilities.autopatcher.existing_test_regression import ExistingTestComparisonResult
        import re

        def _decision(report: str) -> str:
            m = re.search(r"^## [^\n]*\n", report, re.MULTILINE)
            return m.group(0) if m else ""

        _, report_off, _ = _run_pipeline(tmp_path, compare_existing_tests=False)

        preflight_result = ExistingTestComparisonResult(
            status="NOT_VERIFIED", command=None, baseline=None, patched=None,
            reason=(
                "test comparison did not start: the Docker daemon is not reachable "
                "(Cannot connect to the Docker daemon). Start Docker and rerun with --compare-existing-tests."
            ),
        )
        _, report_on, _ = _run_pipeline(tmp_path, compare_existing_tests=True, etr_return_value=preflight_result)

        assert _decision(report_off) == _decision(report_on)
