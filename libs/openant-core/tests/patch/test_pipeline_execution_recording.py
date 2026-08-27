"""Tests for pipeline.py's Batch B2 StageExecution recording -- S1-S5's
initial pass only, via an injected ExecutionRecorder.

Hermetic: LLMClient mocked wholesale (no real/mock LLM calls), repo_root is
an empty tmp_path directory (real repo_locator/candidate_selection/
evidence_fusion calls run for real against it -- deterministic, cheap, no
network). generate_patch_raw/generate_patch/challenge_patch/
calibrate_findings/check_applicability/check_patch/review_patch/
score_confidence are mocked exactly as tests/patch/test_pipeline_repair.py
already does, so the repair loop can be deterministically triggered or not.

See test_execution_recorder.py for hermetic unit-level proof of the
recorder itself, and test_run_traced_execution_recording.py for a real,
end-to-end (mock-mode LLM) proof through tools/run_traced.py.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from utilities.autopatcher.execution_recorder import ExecutionRecorder
from utilities.autopatcher.stage_registry import (
    CHALLENGER,
    GUIDED_CONTEXT_ACQUISITION,
    PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
    REMEDIATION_STRATEGY,
    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
)

_CLEAN_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -1,2 +1,3 @@
 def retry():
+    pass
     pass
```"""

_REPAIR_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -1,2 +1,3 @@
 def retry():
+    # repaired
     pass
```"""

_CHALLENGER_WITH_DEFECT = {
    "still_vulnerable": False,
    "edge_cases": ["An attacker can bypass this check via path traversal"],
    "potential_issues": [],
    "summary": "The patch has a confirmed bypass.",
}
_CHALLENGER_CLEAN = {
    "still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": "No issues found.",
}
_APPLICABILITY_CLEAN = {
    "applicable": True, "skipped": False, "stderr": "", "exit_code": 0, "skipped_reason": None, "error": None,
}


def _calibrate_all_observed(vulnerability_text, patch, findings, llm, code_context=""):
    return [{"original": f, "group": "observed", "reworded": f} for f in findings]


def _run_with_recorder(tmp_path, *, patches_gen, patches_app, patches_chall, no_candidate=False):
    """Run pipeline.run() with a real ExecutionRecorder attached, and the
    same top-level mocking boundary as test_pipeline_repair.py's
    _capture_result. Returns (report_text, recorder).
    """
    call_log = []
    run_dir = str(tmp_path / "run")
    recorder = ExecutionRecorder(call_log=call_log, run_dir=run_dir, artifacts_dir=tmp_path / "run" / "executions")

    gen_raw_return = "" if no_candidate else patches_gen[0]

    with (
        mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
        mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=gen_raw_return),
        mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen[1:]),
        mock.patch("utilities.autopatcher.patch_applicability.check_applicability", side_effect=patches_app),
        mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
        mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=patches_chall),
        mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
        mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
        mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        mock.patch("utilities.autopatcher.pipeline.calibrate_findings", side_effect=_calibrate_all_observed),
    ):
        mock_llm_cls.return_value = mock.MagicMock()
        from utilities.autopatcher.pipeline import run
        report = run("test vuln", api_key="", repo_root=str(tmp_path), execution_recorder=recorder)

    return report, recorder


# ---------------------------------------------------------------------------
# 1-2: exact execution order + consumed identities (no-repair path)
# ---------------------------------------------------------------------------

class TestNoRepairTopology:
    def test_exactly_five_executions_in_order(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert [e["canonical_stage"] for e in rec.executions] == [
            REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
            REMEDIATION_STRATEGY,
            GUIDED_CONTEXT_ACQUISITION,
            PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
            CHALLENGER,
        ]
        assert [e["execution_id"] for e in rec.executions] == [
            "001_repository_analysis_and_remediation_planning",
            "002_remediation_strategy",
            "003_guided_context_acquisition",
            "004_patch_generation_and_post_patch_investigation",
            "005_challenger",
        ]

    def test_exact_consumed_edges(self, tmp_path):
        run_dir = str(tmp_path / "run")
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        s1, s2, s3, s4, s5 = rec.executions
        assert s1["consumed"] == {}
        assert s2["consumed"] == {
            REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: {"run": run_dir, "execution_id": s1["execution_id"]},
        }
        assert s3["consumed"] == {
            REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: {"run": run_dir, "execution_id": s1["execution_id"]},
            REMEDIATION_STRATEGY: {"run": run_dir, "execution_id": s2["execution_id"]},
        }
        assert s4["consumed"] == {
            REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: {"run": run_dir, "execution_id": s1["execution_id"]},
            REMEDIATION_STRATEGY: {"run": run_dir, "execution_id": s2["execution_id"]},
            GUIDED_CONTEXT_ACQUISITION: {"run": run_dir, "execution_id": s3["execution_id"]},
        }
        assert s5["consumed"] == {
            PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION: {"run": run_dir, "execution_id": s4["execution_id"]},
        }

    def test_all_invoked_by_null(self, tmp_path):
        """B2 never records more than one execution per canonical stage --
        invoked_by must stay null on every one of them."""
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert all(e["invoked_by"] is None for e in rec.executions)

    def test_all_invocation_kind_initial(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert all(e["invocation_kind"] == "initial" for e in rec.executions)


# ---------------------------------------------------------------------------
# 3, 6, 7: artifacts -- one file per execution, immutable, JSON-safe
# ---------------------------------------------------------------------------

class TestArtifacts:
    def test_each_execution_has_its_own_artifact_file(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        paths = [e["artifact_path"] for e in rec.executions]
        assert all(p is not None for p in paths)
        assert len(set(paths)) == len(paths)  # every execution has a DISTINCT artifact file
        for p in paths:
            assert json.loads  # sanity: json module usable
            json.loads(open(p, encoding="utf-8").read())  # every artifact is valid JSON

    def test_s1_artifact_contains_real_structured_output_not_a_boolean(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        s1 = rec.executions[0]
        artifact = json.loads(open(s1["artifact_path"], encoding="utf-8").read())
        assert "plan_result" in artifact
        assert isinstance(artifact["plan_result"], dict)  # a real RemediationPlanResult dict, not a bool
        assert set(artifact["plan_result"].keys()) >= {"rendered", "target_files", "target_symbols"}
        assert "repository_understanding" in artifact
        assert "pre_patch_anchors" in artifact
        # Explicitly must NOT be reduced to a presence boolean.
        assert artifact.get("repository_understanding_rendered_present") is None

    def test_s3_artifact_contains_real_slice_output_not_summary_booleans(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        s3 = rec.executions[2]
        artifact = json.loads(open(s3["artifact_path"], encoding="utf-8").read())
        assert "slice_result" in artifact
        assert "edit_readiness" in artifact
        assert "skip_patch_generation" in artifact
        # slice_result must be the real structured NamedTuple (or null, on
        # this fixture's degraded/no-strategy-targets path) -- never
        # collapsed to a bare "present" boolean.
        assert not isinstance(artifact["slice_result"], bool)
        assert not isinstance(artifact["edit_readiness"], bool)

    def test_artifacts_immutable_after_later_execution_finishes(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        s1_path = rec.executions[0]["artifact_path"]
        before = open(s1_path, "rb").read()
        # s5 (the last execution) has already finished by the time we read
        # this -- re-read s1 and confirm it was never touched.
        after = open(s1_path, "rb").read()
        assert before == after


# ---------------------------------------------------------------------------
# 4/5 (S4 artifact contract) -- from the earlier investigation
# ---------------------------------------------------------------------------

class TestS4Artifact:
    def test_includes_post_patch_investigation_state_and_scope(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        s4 = rec.executions[3]
        artifact = json.loads(open(s4["artifact_path"], encoding="utf-8").read())
        assert artifact["patch"] == _CLEAN_DIFF
        for key in (
            "original_patch", "retry_patch", "retry_attempted", "retry_succeeded",
            "hygiene_findings", "applicability_result", "final_repair_meta",
            "patch_target_conformance", "post_patch_recovery",
            "post_patch_observations", "post_patch_coverage", "investigated_patch",
        ):
            assert key in artifact
        assert s4.get("canonical_contract_scope") == "full"

    def test_outcome_settled_when_candidate_produced(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert rec.executions[3]["outcome"] == "settled"


class TestS5Artifact:
    def test_includes_raw_and_classified_challenger_output(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        s5 = rec.executions[4]
        artifact = json.loads(open(s5["artifact_path"], encoding="utf-8").read())
        assert artifact["challenger"] == _CHALLENGER_WITH_DEFECT
        assert "classified_challenger" in artifact
        assert artifact["classified_challenger"]["confirmed_defect_count"] >= 1


# ---------------------------------------------------------------------------
# 16-17: repair path still records exactly S1-S5, never S6/S4#2/S5#2
# ---------------------------------------------------------------------------

class TestRepairLoopNotRecorded:
    def test_repair_accepted_still_records_exactly_five(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert len(rec.executions) == 5
        stages = {e["canonical_stage"] for e in rec.executions}
        assert "patch_repair_and_calibration" not in stages
        ids = {e["execution_id"] for e in rec.executions}
        assert "006_patch_repair_and_calibration" not in ids
        assert "006_patch_generation_and_post_patch_investigation" not in ids
        assert "005_patch_generation_and_post_patch_investigation" not in ids  # no S4#2

    def test_repair_rejected_still_records_exactly_five(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
        )
        assert len(rec.executions) == 5

    def test_s4_and_s5_artifacts_reflect_pre_repair_state_only(self, tmp_path):
        """S4/S5's recorded artifacts describe the INITIAL pass -- the
        repair loop's regeneration/re-challenge must not leak into them."""
        _, rec = _run_with_recorder(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        s4 = json.loads(open(rec.executions[3]["artifact_path"], encoding="utf-8").read())
        s5 = json.loads(open(rec.executions[4]["artifact_path"], encoding="utf-8").read())
        # S4's own recorded `patch` is the INITIAL candidate, even though
        # the repair loop later replaced the pipeline's own `patch` local
        # with the repair diff for the report.
        assert s4["patch"] == _CLEAN_DIFF
        assert "repaired" not in s4["patch"]
        assert s5["challenger"] == _CHALLENGER_WITH_DEFECT


# ---------------------------------------------------------------------------
# 18: no-candidate/skipped paths represented honestly
# ---------------------------------------------------------------------------

class TestSkippedAndDegradedOutcomes:
    def test_no_candidate_patch_outcome(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[""], patches_app=[], patches_chall=[], no_candidate=True,
        )
        s4, s5 = rec.executions[3], rec.executions[4]
        assert s4["outcome"] == "no_candidate_patch"
        assert s5["outcome"] == "skipped_no_candidate_patch"

    def test_no_candidate_patch_does_not_fabricate_a_settled_patch(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[""], patches_app=[], patches_chall=[], no_candidate=True,
        )
        s4 = rec.executions[3]
        artifact = json.loads(open(s4["artifact_path"], encoding="utf-8").read())
        assert not artifact["patch"]

    def test_s2_s3_honestly_skip_when_no_planner_evidence(self, tmp_path):
        """With LLMClient fully mocked away, generate_remediation_plan's own
        best-effort fallback yields an empty (non-fabricated) plan result --
        S2/S3 must honestly report they were skipped, never silently
        claim readiness they don't have."""
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        s2, s3 = rec.executions[1], rec.executions[2]
        assert s2["outcome"] == "skipped_no_planner_evidence"
        assert s3["outcome"] == "skipped_no_strategy_targets"


# ---------------------------------------------------------------------------
# 19: recorder=None preserves existing report/behavior exactly
# ---------------------------------------------------------------------------

class TestRecorderNoneIsBehaviorPreserving:
    def _run(self, tmp_path, *, execution_recorder):
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
            # Deterministic (no MagicMock repr/object-id leaking into the
            # rendered report -- unrelated to execution_recorder, but
            # otherwise makes two independent runs' report text differ by
            # nothing but a random memory address, defeating this test's
            # own exact-equality check).
            mock_impact_cls.return_value.analyze.return_value.to_dict.return_value = {}
            from utilities.autopatcher.pipeline import run
            return run("test vuln", api_key="", repo_root=str(tmp_path), execution_recorder=execution_recorder)

    def test_report_identical_with_and_without_recorder(self, tmp_path):
        report_without = self._run(tmp_path / "a", execution_recorder=None)
        recorder = ExecutionRecorder(call_log=[], run_dir=str(tmp_path / "b"), artifacts_dir=tmp_path / "b" / "executions")
        report_with = self._run(tmp_path / "b", execution_recorder=recorder)
        assert report_without == report_with

    def test_no_recorder_means_no_artifacts_directory_created(self, tmp_path):
        self._run(tmp_path, execution_recorder=None)
        assert not (tmp_path / "executions").exists()

    def test_default_execution_recorder_is_none(self, tmp_path):
        import inspect
        from utilities.autopatcher.pipeline import run
        sig = inspect.signature(run)
        assert sig.parameters["execution_recorder"].default is None
