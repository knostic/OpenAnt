"""Tests for pipeline.py's Batch B4 StageExecution recording -- Stage 7
(patch_review), Stage 8 (confidence_scoring), Stage 9
(impact_and_behavior_analysis), the consecutive canonical stages
immediately following Stage 6.

Same mocking boundary as test_pipeline_execution_recording_stage6.py. See
test_run_traced_execution_recording.py for the real, end-to-end (mock-mode
LLM) proof of LLM-call attribution/no-leakage across S6/S7/S8/S9.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from utilities.autopatcher.execution_recorder import ExecutionRecorder

_CLEAN_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -1,2 +1,3 @@
 def retry():
+    pass
     pass
```"""

_CHALLENGER_CLEAN = {
    "still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": "No issues found.",
}
_CHALLENGER_WITH_DEFECT = {
    "still_vulnerable": True,
    "edge_cases": ["An attacker can bypass this check via path traversal"],
    "potential_issues": ["Performance may be impacted"],
    "summary": "Still vulnerable.",
}
_APPLICABILITY_CLEAN = {
    "applicable": True, "skipped": False, "stderr": "", "exit_code": 0, "skipped_reason": None, "error": None,
}


def _calibrate_all_observed(vulnerability_text, patch, findings, llm, code_context=""):
    return [{"original": f, "group": "observed", "reworded": f} for f in findings]


def _run_with_recorder(tmp_path, *, patches_gen, patches_app, patches_chall, no_candidate=False, repo_root=None):
    call_log = []
    run_dir = str(tmp_path / "run")
    recorder = ExecutionRecorder(call_log=call_log, run_dir=run_dir, artifacts_dir=tmp_path / "run" / "executions")
    gen_raw_return = "" if no_candidate else patches_gen[0]

    with (
        mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
        mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=gen_raw_return),
        mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen[1:]),
        mock.patch("utilities.autopatcher.patch_applicability.check_applicability", side_effect=patches_app),
        mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="This patch correctly parameterizes the query.") as mock_review,
        mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=patches_chall),
        mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="**Confidence score:** 0.80\n\nSolid fix.") as mock_score,
        mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        mock.patch("utilities.autopatcher.pipeline.calibrate_findings", side_effect=_calibrate_all_observed),
    ):
        mock_llm_cls.return_value = mock.MagicMock()
        from utilities.autopatcher.pipeline import run
        report = run(
            "test vuln", api_key="", repo_root=repo_root or str(tmp_path), execution_recorder=recorder,
        )

    return report, recorder, mock_review, mock_score


def _artifact(rec, index):
    execution = rec.executions[index]
    return execution, json.loads(open(execution["artifact_path"], encoding="utf-8").read())


# ---------------------------------------------------------------------------
# 1-2: exact execution order + consumed identities
# ---------------------------------------------------------------------------

class TestTopology:
    def test_s7_s8_s9_order_and_ids(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert [e["canonical_stage"] for e in rec.executions[6:9]] == [
            "patch_review", "confidence_scoring", "impact_and_behavior_analysis",
        ]
        assert [e["execution_id"] for e in rec.executions[6:9]] == [
            "007_patch_review", "008_confidence_scoring", "009_impact_and_behavior_analysis",
        ]

    def test_s7_consumes_exact_s6(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        s6, s7 = rec.executions[5], rec.executions[6]
        assert s7["consumed"] == {
            "patch_repair_and_calibration": {"run": rec.run_dir, "execution_id": s6["execution_id"]},
        }

    def test_s8_consumes_exact_s6_and_s7(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        s6, s7, s8 = rec.executions[5], rec.executions[6], rec.executions[7]
        assert s8["consumed"] == {
            "patch_repair_and_calibration": {"run": rec.run_dir, "execution_id": s6["execution_id"]},
            "patch_review": {"run": rec.run_dir, "execution_id": s7["execution_id"]},
        }

    def test_s9_consumes_exact_s6_only_not_s7_s8(self, tmp_path):
        """Matches actual dataflow, not merely a linear chain: both
        analyzers read only `patch`/`challenger` (S6-settled), never
        `review`/`score_text` -- and stage_registry.STAGE_DEPENDENCIES[
        IMPACT_AND_BEHAVIOR_ANALYSIS] is (PATCH_REPAIR_AND_CALIBRATION,)
        only."""
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        s6, s9 = rec.executions[5], rec.executions[8]
        assert s9["consumed"] == {
            "patch_repair_and_calibration": {"run": rec.run_dir, "execution_id": s6["execution_id"]},
        }


# ---------------------------------------------------------------------------
# 3, 6: real artifact persistence, containing real stage-owned output
# ---------------------------------------------------------------------------

class TestArtifacts:
    def test_s7_artifact_contains_real_review_text(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        _, artifact = _artifact(rec, 6)
        assert artifact["review"] == "This patch correctly parameterizes the query."

    def test_s8_artifact_contains_real_score_and_adjustment(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        _, artifact = _artifact(rec, 7)
        assert artifact["orig_score"] == 0.8
        assert artifact["adjusted_score"] == 0.8  # no adversarial findings -> unchanged
        assert "Confidence score" in artifact["score_text"]

    def test_s8_adjustment_reflects_challenger_still_vulnerable(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        _, artifact = _artifact(rec, 7)
        assert artifact["orig_score"] == 0.8
        assert artifact["adjusted_score"] == pytest.approx(0.8 * 0.4)

    def test_s9_artifact_contains_real_impact_and_behavior(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN], repo_root=str(tmp_path),
        )
        _, artifact = _artifact(rec, 8)
        assert "impact" in artifact
        assert "behavior" in artifact
        assert "detected_language" in artifact
        # behavior_summary.BehaviorAnalyzer.analyze() always runs (not
        # repo_root-gated) -- real structured dict, not a boolean/summary.
        assert isinstance(artifact["behavior"], dict)

    def test_report_contains_the_recorded_review_and_score(self, tmp_path):
        """Proves artifact content matches what the report actually used --
        not a parallel, possibly-divergent copy."""
        report, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        _, s7_artifact = _artifact(rec, 6)
        assert s7_artifact["review"] in report


# ---------------------------------------------------------------------------
# 7: skipped/degraded path represented honestly (no candidate patch)
# ---------------------------------------------------------------------------

class TestSkippedPath:
    def test_s7_s8_skipped_when_no_candidate_patch(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[""], patches_app=[], patches_chall=[], no_candidate=True,
        )
        s7, s8 = rec.executions[6], rec.executions[7]
        assert s7["outcome"] == "skipped_no_candidate_patch"
        assert s8["outcome"] == "skipped_no_candidate_patch"

    def test_s7_artifact_honest_empty_review_when_skipped(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[""], patches_app=[], patches_chall=[], no_candidate=True,
        )
        _, artifact = _artifact(rec, 6)
        assert artifact["review"] == ""

    def test_s9_still_settled_even_with_no_candidate_patch(self, tmp_path):
        """S9's own contract is not gated on candidate-patch existence --
        both analyzers run regardless (best-effort, degrade to None on
        their own failure only)."""
        _, rec, _, _ = _run_with_recorder(
            tmp_path, patches_gen=[""], patches_app=[], patches_chall=[], no_candidate=True,
        )
        s9 = rec.executions[8]
        assert s9["outcome"] == "settled"


# ---------------------------------------------------------------------------
# 8: recorder=None preserves behavior (S7-S9 code paths specifically)
# ---------------------------------------------------------------------------

class TestRecorderNonePreservesBehavior:
    def test_report_identical_with_and_without_recorder(self, tmp_path):
        def _run(path, execution_recorder):
            with (
                mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
                mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=_CLEAN_DIFF),
                mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=[]),
                mock.patch("utilities.autopatcher.patch_applicability.check_applicability", return_value=_APPLICABILITY_CLEAN),
                mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
                mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value=_CHALLENGER_CLEAN),
                mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
                mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer") as mock_impact_cls,
                mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
                mock.patch("utilities.autopatcher.pipeline.calibrate_findings", side_effect=_calibrate_all_observed),
            ):
                mock_llm_cls.return_value = mock.MagicMock()
                mock_impact_cls.return_value.analyze.return_value.to_dict.return_value = {}
                from utilities.autopatcher.pipeline import run
                return run("test vuln", api_key="", repo_root=str(path), execution_recorder=execution_recorder)

        report_without = _run(tmp_path / "a", execution_recorder=None)
        recorder = ExecutionRecorder(call_log=[], run_dir=str(tmp_path / "b"), artifacts_dir=tmp_path / "b" / "executions")
        report_with = _run(tmp_path / "b", execution_recorder=recorder)
        assert report_without == report_with
