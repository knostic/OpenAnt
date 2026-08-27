"""Tests for pipeline.py's Batch B3 Stage-6 StageExecution recording
(patch_repair_and_calibration) -- extends Batch B2's S1-S5 recording with a
real, fully-settled S6 execution.

Same mocking boundary as test_pipeline_execution_recording.py (LLMClient
mocked wholesale, generate_patch_raw/generate_patch/challenge_patch/
calibrate_findings/check_applicability/check_patch mocked). See
test_run_traced_execution_recording.py for the real, end-to-end (mock-mode
LLM) proof that S6's fallback-calibration LLM call is genuinely captured
and correctly attributed.
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
_CHALLENGER_RISK_ONLY = {
    "still_vulnerable": False,
    "edge_cases": ["This might behave unexpectedly under concurrent access"],
    "potential_issues": [],
    "summary": "Unverified risk only.",
}
_APPLICABILITY_CLEAN = {
    "applicable": True, "skipped": False, "stderr": "", "exit_code": 0, "skipped_reason": None, "error": None,
}


def _calibrate_all_observed(vulnerability_text, patch, findings, llm, code_context=""):
    return [{"original": f, "group": "observed", "reworded": f} for f in findings]


def _run_with_recorder(tmp_path, *, patches_gen, patches_app, patches_chall, calibration_side_effect=None):
    call_log = []
    run_dir = str(tmp_path / "run")
    recorder = ExecutionRecorder(call_log=call_log, run_dir=run_dir, artifacts_dir=tmp_path / "run" / "executions")

    with (
        mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
        mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=patches_gen[0]),
        mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen[1:]),
        mock.patch("utilities.autopatcher.patch_applicability.check_applicability", side_effect=patches_app),
        mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
        mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=patches_chall),
        mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
        mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer") as mock_impact_cls,
        mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=calibration_side_effect or _calibrate_all_observed,
        ),
    ):
        mock_llm_cls.return_value = mock.MagicMock()
        mock_impact_cls.return_value.analyze.return_value.to_dict.return_value = {}
        from utilities.autopatcher.pipeline import run
        report = run("test vuln", api_key="", repo_root=str(tmp_path), execution_recorder=recorder)

    return report, recorder


def _s6(rec):
    s6 = rec.executions[5]
    artifact = json.loads(open(s6["artifact_path"], encoding="utf-8").read())
    return s6, artifact


# ---------------------------------------------------------------------------
# A. NO REPAIR
# ---------------------------------------------------------------------------

class TestNoRepair:
    def test_exactly_nine_executions_and_s6_consumes_exact_s4_s5(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert len(rec.executions) == 9
        s4, s5, s6 = rec.executions[3], rec.executions[4], rec.executions[5]
        assert s6["canonical_stage"] == "patch_repair_and_calibration"
        assert s6["consumed"] == {
            "patch_generation_and_post_patch_investigation": {"run": rec.run_dir, "execution_id": s4["execution_id"]},
            "challenger": {"run": rec.run_dir, "execution_id": s5["execution_id"]},
        }

    def test_authoritative_candidate_is_original(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        _, artifact = _s6(rec)
        assert artifact["authoritative_candidate"]["source"] == "original"
        assert artifact["authoritative_candidate"]["patch"] == _CLEAN_DIFF

    def test_authoritative_candidate_does_not_repeat_s4_s5_execution_identities(self, tmp_path):
        """authoritative_candidate must never repeat S4#1/S5#1 as if they
        identified the selected candidate -- that provenance lives only in
        StageExecution.consumed."""
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        _, artifact = _s6(rec)
        assert "patch_generation_and_post_patch_investigation" not in artifact["authoritative_candidate"]
        assert "challenger" not in artifact["authoritative_candidate"]
        assert set(artifact["authoritative_candidate"].keys()) == {
            "source", "patch", "applicability_result", "hygiene_findings",
        }

    def test_no_repair_metadata_fabricated(self, tmp_path):
        _, rec = _run_with_recorder(
            tmp_path, patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        _, artifact = _s6(rec)
        assert artifact["repair_attempted"] is False
        assert artifact["repair_regeneration"] is None
        assert artifact["repair_rechallenge"] is None
        assert artifact["repair_outcome"] == "not_triggered_no_defects"


# ---------------------------------------------------------------------------
# B. REPAIR ACCEPTED
# ---------------------------------------------------------------------------

class TestRepairAccepted:
    def _run(self, tmp_path):
        return _run_with_recorder(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )

    def test_still_exactly_nine_canonical_executions(self, tmp_path):
        _, rec = self._run(tmp_path)
        assert len(rec.executions) == 9
        assert [e["canonical_stage"] for e in rec.executions][5] == "patch_repair_and_calibration"

    def test_repair_internal_activity_visible_in_artifact(self, tmp_path):
        _, rec = self._run(tmp_path)
        _, artifact = _s6(rec)
        assert artifact["repair_attempted"] is True
        assert artifact["repair_regeneration"]["patch"] == _REPAIR_DIFF
        assert artifact["repair_rechallenge"]["challenger"] == _CHALLENGER_CLEAN
        assert artifact["repair_outcome"] == "attempted_applicable_accepted"

    def test_authoritative_candidate_is_repaired(self, tmp_path):
        _, rec = self._run(tmp_path)
        _, artifact = _s6(rec)
        assert artifact["authoritative_candidate"]["source"] == "internal_repair"
        assert artifact["authoritative_candidate"]["patch"] == _REPAIR_DIFF
        # Must NOT imply S4#1/S5#1 identify/produced the repaired candidate
        # -- no execution identity exists for it; see the no-repair case's
        # equivalent test for the full key-set assertion.
        assert "patch_generation_and_post_patch_investigation" not in artifact["authoritative_candidate"]
        assert "challenger" not in artifact["authoritative_candidate"]

    def test_consumed_still_points_at_original_s4_s5_not_fabricated(self, tmp_path):
        """Even though the AUTHORITATIVE candidate is the repair, `consumed`
        stays the exact original canonical S4#1/S5#1 identities -- never
        overloaded to point at a non-canonical repair candidate."""
        _, rec = self._run(tmp_path)
        s4, s5, s6 = rec.executions[3], rec.executions[4], rec.executions[5]
        assert s6["consumed"] == {
            "patch_generation_and_post_patch_investigation": {"run": rec.run_dir, "execution_id": s4["execution_id"]},
            "challenger": {"run": rec.run_dir, "execution_id": s5["execution_id"]},
        }


# ---------------------------------------------------------------------------
# C. REPAIR REJECTED
# ---------------------------------------------------------------------------

class TestRepairRejected:
    def _run(self, tmp_path):
        return _run_with_recorder(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            # repair challenger still has a confirmed defect -> rejected
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
        )

    def test_repair_truthfully_recorded_as_evaluated_and_rejected(self, tmp_path):
        _, rec = self._run(tmp_path)
        _, artifact = _s6(rec)
        assert artifact["repair_attempted"] is True
        assert artifact["repair_regeneration"]["patch"] == _REPAIR_DIFF
        assert artifact["repair_rechallenge"]["challenger"] == _CHALLENGER_WITH_DEFECT
        assert artifact["repair_outcome"] == "attempted_applicable_rejected"

    def test_authoritative_candidate_remains_original(self, tmp_path):
        _, rec = self._run(tmp_path)
        _, artifact = _s6(rec)
        assert artifact["authoritative_candidate"]["source"] == "original"
        assert artifact["authoritative_candidate"]["patch"] == _CLEAN_DIFF

    def test_provenance_not_rewritten_to_pretend_original_was_evaluated_repair(self, tmp_path):
        """The rejected repair candidate's real, distinct content
        (_REPAIR_DIFF) must remain visible in repair_regeneration -- never
        silently replaced by/merged with the original candidate's text."""
        _, rec = self._run(tmp_path)
        s4, s5, s6 = rec.executions[3], rec.executions[4], rec.executions[5]
        _, artifact = _s6(rec)
        # consumed still references the ORIGINAL S4#1/S5#1 (what was
        # canonically evaluated), not some rewritten identity.
        assert s6["consumed"] == {
            "patch_generation_and_post_patch_investigation": {"run": rec.run_dir, "execution_id": s4["execution_id"]},
            "challenger": {"run": rec.run_dir, "execution_id": s5["execution_id"]},
        }
        # The rejected candidate's own real content is preserved, distinct
        # from the authoritative (original) patch.
        assert artifact["repair_regeneration"]["patch"] != artifact["authoritative_candidate"]["patch"]
        assert artifact["repair_regeneration"]["patch"] == _REPAIR_DIFF


# ---------------------------------------------------------------------------
# E. BEHAVIOR PRESERVATION -- report unchanged, recorder present or absent,
# across representative no-repair/accepted/rejected fixtures.
# ---------------------------------------------------------------------------

class TestBehaviorPreservation:
    def _run_plain(self, tmp_path, *, patches_gen, patches_app, patches_chall, execution_recorder):
        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=patches_gen[0]),
            mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen[1:]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability", side_effect=patches_app),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=patches_chall),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer") as mock_impact_cls,
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.pipeline.calibrate_findings", side_effect=_calibrate_all_observed),
        ):
            mock_llm_cls.return_value = mock.MagicMock()
            mock_impact_cls.return_value.analyze.return_value.to_dict.return_value = {}
            from utilities.autopatcher.pipeline import run
            return run(
                "test vuln", api_key="", repo_root=str(tmp_path), execution_recorder=execution_recorder,
            )

    @pytest.mark.parametrize("scenario", ["no_repair", "accepted", "rejected"])
    def test_report_identical_with_and_without_recorder(self, tmp_path, scenario):
        if scenario == "no_repair":
            kwargs = dict(patches_gen=[_CLEAN_DIFF], patches_app=[_APPLICABILITY_CLEAN], patches_chall=[_CHALLENGER_CLEAN])
        elif scenario == "accepted":
            kwargs = dict(
                patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
                patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
                patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
            )
        else:
            kwargs = dict(
                patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
                patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
                patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
            )

        report_without = self._run_plain(tmp_path / "a", execution_recorder=None, **kwargs)
        recorder = ExecutionRecorder(call_log=[], run_dir=str(tmp_path / "b"), artifacts_dir=tmp_path / "b" / "executions")
        report_with = self._run_plain(tmp_path / "b", execution_recorder=recorder, **kwargs)
        assert report_without == report_with
