"""Tests for pipeline.py's Batch B5 StageExecution recording -- Stage 10
(test_analysis_and_plan) and Stage 11 (existing_test_comparison), now
recorded as separate, truthful executions after the discovery/comparison
extraction in existing_test_regression.py.

Docker/pytest execution itself is never exercised here (same hermetic
approach as test_pipeline_existing_test_regression.py) --
discover_test_plan (the real LLM-calling function) and
evaluate_existing_test_comparison_with_plan's Docker-touching internals are
mocked; a synthetic "test_plan_discovery"-tagged call is appended to the
recorder's own call_log to prove attribution end-to-end without needing a
real Docker daemon or LLM.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from utilities.autopatcher.execution_recorder import ExecutionRecorder
from utilities.autopatcher.existing_test_amendment import AmendmentOutcome, AmendmentRerunOutcome
from utilities.autopatcher.existing_test_regression import ExistingTestComparisonResult
from utilities.autopatcher.test_execution_models import TestExecutionPlan


def _fixed_pass_amendment_outcome(repo_root, patch, plan, security_invariant=None, executor=None, llm=None):
    """Fixed PASS result, wrapped as an AmendmentRerunOutcome with no
    amendment attempted -- used wherever a test just needs S11 to settle
    cleanly and isn't exercising the amendment mechanism itself."""
    return AmendmentRerunOutcome(
        result=ExistingTestComparisonResult(
            status="PASS", command=plan.test_command, baseline=None, patched=None, reason="ok",
        ),
        patch=patch, accepted=False,
        amendment=AmendmentOutcome(status="not_attempted", reason="test fixture: amendment not exercised"),
    )

_CLEAN_DIFF = """\
```diff
--- a/src/app/util.py
+++ b/src/app/util.py
@@ -1,2 +1,3 @@
 def util():
+    pass
     pass
```"""

_CHALLENGER_CLEAN = {
    "still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": "No issues found.",
}
_APPLICABILITY_CLEAN = {
    "applicable": True, "skipped": False, "stderr": "", "exit_code": 0, "skipped_reason": None, "error": None,
}


def _calibrate_all_observed(vulnerability_text, patch, findings, llm, code_context=""):
    return [{"original": f, "group": "observed", "reworded": f} for f in findings]


_PLAN = TestExecutionPlan(
    setup_commands=(("pip", "install", "-e", "."),), test_command=("python", "-m", "pytest"),
    result_strategy="exit_code", result_output_path=None,
    runtime_family="python", runtime_version_hint="3.11",
    evidence=("requirements.txt",), reasoning_summary="pytest project", confidence="high",
)


def _run_with_recorder(
    tmp_path, *, compare_existing_tests=True, call_log_side_effect=None,
    discover_return=None, comparison_return=None, comparison_side_effect=None,
):
    """Run pipeline.run() with a real ExecutionRecorder attached.
    discover_test_plan_for_comparison and evaluate_existing_test_comparison_
    with_amendment are mocked at the pipeline.py boundary (same as
    test_pipeline_existing_test_regression.py); call_log_side_effect, if
    given, additionally appends a synthetic LLM-call record to the
    recorder's own call_log (proving real attribution mechanics).

    `comparison_return`/`comparison_side_effect` describe the underlying
    S11 ExistingTestComparisonResult (or an exception) exactly as before
    the Existing Test Amendment feature -- wrapped into an
    AmendmentRerunOutcome with accepted=False/amendment.status=
    "not_attempted" below (this file exercises S10/S11 EXECUTION RECORDING,
    not the amendment mechanism itself -- see test_existing_test_amendment.py
    for that).
    """
    call_log = []
    run_dir = str(tmp_path / "run")
    recorder = ExecutionRecorder(call_log=call_log, run_dir=run_dir, artifacts_dir=tmp_path / "run" / "executions")

    def _discover(repo_root, patch, llm):
        if call_log_side_effect:
            call_log_side_effect(call_log)
        if discover_return is not None:
            return discover_return
        return (_PLAN, None, mock.MagicMock())

    def _amendment_call(repo_root, patch, plan, security_invariant=None, executor=None, llm=None):
        from utilities.autopatcher.existing_test_amendment import AmendmentOutcome, AmendmentRerunOutcome
        if comparison_side_effect is not None:
            if isinstance(comparison_side_effect, BaseException):
                raise comparison_side_effect
            return comparison_side_effect(
                repo_root, patch, plan, security_invariant=security_invariant, executor=executor, llm=llm,
            )
        result = comparison_return or ExistingTestComparisonResult(
            status="PASS", command=_PLAN.test_command, baseline=None, patched=None, reason="ok",
        )
        return AmendmentRerunOutcome(
            result=result, patch=patch, accepted=False,
            amendment=AmendmentOutcome(status="not_attempted", reason="test fixture: amendment not exercised"),
        )

    with (
        mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
        mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=_CLEAN_DIFF),
        mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=[]),
        mock.patch("utilities.autopatcher.patch_applicability.check_applicability", return_value=_APPLICABILITY_CLEAN),
        mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
        mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value=_CHALLENGER_CLEAN),
        mock.patch("utilities.autopatcher.pipeline.calibrate_findings", side_effect=_calibrate_all_observed),
        mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
        mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer") as mock_impact_cls,
        mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        mock.patch("utilities.autopatcher.pipeline.discover_test_plan_for_comparison", side_effect=_discover) as mock_discover,
        mock.patch(
            "utilities.autopatcher.pipeline.evaluate_existing_test_comparison_with_amendment",
            side_effect=_amendment_call,
        ) as mock_compare,
    ):
        mock_llm_cls.return_value = mock.MagicMock()
        mock_impact_cls.return_value.analyze.return_value.to_dict.return_value = {}
        from utilities.autopatcher.pipeline import run
        report = run(
            "test vuln", api_key="", repo_root=str(tmp_path),
            execution_recorder=recorder, compare_existing_tests=compare_existing_tests,
        )

    return report, recorder, mock_discover, mock_compare


def _s10_s11(rec):
    """S10/S11 run BEFORE S7/S8/S9 in ACTUAL code order (Existing Test
    Comparison's block precedes Patch Review/Confidence Scoring/Impact
    Analysis in pipeline.run()) -- so their real execution_ids are 007/008,
    not 010/011. sequence/execution_id reflect real execution order, not
    canonical stage number (unchanged design principle since Batch B2)."""
    by_stage = {e["canonical_stage"]: e for e in rec.executions}
    return by_stage["test_analysis_and_plan"], by_stage["existing_test_comparison"]


# ---------------------------------------------------------------------------
# 2-4: exactly-once discovery, S11 consumes the provided plan, never re-discovers
# ---------------------------------------------------------------------------

class TestNoDoubleDiscovery:
    def test_discovery_called_exactly_once(self, tmp_path):
        _, rec, mock_discover, mock_compare = _run_with_recorder(tmp_path)
        mock_discover.assert_called_once()

    def test_s11_receives_the_s10_plan_not_a_rediscovered_one(self, tmp_path):
        _, rec, mock_discover, mock_compare = _run_with_recorder(tmp_path)
        mock_compare.assert_called_once()
        _repo_root, _patch, called_plan = mock_compare.call_args[0]
        assert called_plan is _PLAN

    def test_evaluate_existing_test_comparison_with_plan_never_calls_discover_test_plan(self):
        """Structural proof: S11's own comparison function has no code
        path capable of invoking discovery a second time -- checked via
        the compiled function's own referenced names (co_names), not
        source text (which would false-positive on this function's own
        docstring mentioning discover_test_plan by name)."""
        from utilities.autopatcher import existing_test_regression as etr
        assert "discover_test_plan" not in etr.evaluate_existing_test_comparison_with_plan.__code__.co_names


# ---------------------------------------------------------------------------
# 10-11: exact canonical consumed identities
# ---------------------------------------------------------------------------

class TestConsumedIdentities:
    def test_s10_consumes_exact_s6_only(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(tmp_path)
        s6 = rec.executions[5]
        s10, _ = _s10_s11(rec)
        assert s10["canonical_stage"] == "test_analysis_and_plan"
        assert s10["consumed"] == {
            "patch_repair_and_calibration": {"run": rec.run_dir, "execution_id": s6["execution_id"]},
        }

    def test_s11_consumes_exact_s6_and_s10(self, tmp_path):
        """Also consumes S2 as of the Existing Test Amendment feature --
        the amendment step reads S2's own security_invariant field (see
        stage_registry.STAGE_DEPENDENCIES[EXISTING_TEST_COMPARISON])."""
        _, rec, _, _ = _run_with_recorder(tmp_path)
        s2 = rec.executions[1]
        s6 = rec.executions[5]
        s10, s11 = _s10_s11(rec)
        assert s2["canonical_stage"] == "remediation_strategy"
        assert s11["canonical_stage"] == "existing_test_comparison"
        assert s11["consumed"] == {
            "patch_repair_and_calibration": {"run": rec.run_dir, "execution_id": s6["execution_id"]},
            "test_analysis_and_plan": {"run": rec.run_dir, "execution_id": s10["execution_id"]},
            "remediation_strategy": {"run": rec.run_dir, "execution_id": s2["execution_id"]},
        }


# ---------------------------------------------------------------------------
# 8-9: LLM-call attribution -- S10's discovery call belongs to S10 only,
# never leaks into S11 (proven via a synthetic call_log append, since a
# real Docker+LLM E2E run isn't hermetically reproducible here).
# ---------------------------------------------------------------------------

class TestLLMAttribution:
    def _append_discovery_call(self, call_log):
        call_log.append({
            "seq": len(call_log) + 1, "stage": "test_plan_discovery",
            "started_at": "t", "finished_at": "t",
            "prompt_chars": 1, "response_chars": 1,
            "prompt_file": "x.prompt.txt", "response_file": "x.response.txt",
        })

    def test_discovery_call_attributed_to_s10_only(self, tmp_path):
        _, rec, _, _ = _run_with_recorder(tmp_path, call_log_side_effect=self._append_discovery_call)
        s10, s11 = _s10_s11(rec)
        assert [c["stage"] for c in s10["llm_calls"]] == ["test_plan_discovery"]
        assert s11["llm_calls"] == []

    def test_s10_llm_calls_within_registry_owned_tags(self, tmp_path):
        from utilities.autopatcher.stage_registry import STAGE_OWNED_LLM_TAGS, TEST_ANALYSIS_AND_PLAN

        _, rec, _, _ = _run_with_recorder(tmp_path, call_log_side_effect=self._append_discovery_call)
        s10, _ = _s10_s11(rec)
        for call in s10["llm_calls"]:
            assert call["stage"] in STAGE_OWNED_LLM_TAGS[TEST_ANALYSIS_AND_PLAN]


# ---------------------------------------------------------------------------
# 7: disabled path makes no new LLM calls / no executions recorded
# ---------------------------------------------------------------------------

class TestDisabledPath:
    def test_compare_existing_tests_false_records_no_s10_s11(self, tmp_path):
        _, rec, mock_discover, mock_compare = _run_with_recorder(tmp_path, compare_existing_tests=False)
        mock_discover.assert_not_called()
        mock_compare.assert_not_called()
        assert len(rec.executions) == 9
        assert "test_analysis_and_plan" not in [e["canonical_stage"] for e in rec.executions]
        assert "existing_test_comparison" not in [e["canonical_stage"] for e in rec.executions]


# ---------------------------------------------------------------------------
# Skip path: discovery yields no plan -- S11 is honestly recorded as
# skipped, no fabricated comparison.
# ---------------------------------------------------------------------------

class TestNoPlanDiscovered:
    def test_s10_rejected_s11_skipped_no_plan(self, tmp_path):
        early_result = ExistingTestComparisonResult(
            status="NOT_VERIFIED", command=None, baseline=None, patched=None,
            reason="no reliable test execution plan could be discovered for this repository",
        )
        _, rec, mock_discover, mock_compare = _run_with_recorder(
            tmp_path, discover_return=(None, early_result, None),
        )
        mock_compare.assert_not_called()
        s10, s11 = _s10_s11(rec)
        assert s10["outcome"] == "rejected"
        assert s11["outcome"] == "skipped_no_plan"
        artifact10 = json.loads(open(s10["artifact_path"], encoding="utf-8").read())
        assert artifact10["reason"] == early_result.reason


# ---------------------------------------------------------------------------
# 12: production S10 artifact shares the transitional replay's canonical
# contract for the accepted case.
# ---------------------------------------------------------------------------

class TestProductionReplayContractParity:
    def test_accepted_plan_artifact_matches_replay_shape(self, tmp_path):
        """Production's accepted-plan artifact must be the same
        dataclasses.asdict(plan)-equivalent shape replay_engine.py's
        _run_test_analysis_and_plan already writes to test_execution_plan.json."""
        import dataclasses
        _, rec, _, _ = _run_with_recorder(tmp_path)
        s10, _ = _s10_s11(rec)
        artifact = json.loads(open(s10["artifact_path"], encoding="utf-8").read())
        # Round-trip the reference through JSON too (tuples -> lists) --
        # both production's and replay's own artifacts undergo the exact
        # same JSON conversion; comparing structural/JSON shape, not
        # native-Python tuple-vs-list identity.
        assert artifact == json.loads(json.dumps(dataclasses.asdict(_PLAN)))

    def test_accepted_outcome_uses_same_vocabulary_as_replay(self, tmp_path):
        """Both production and the transitional replay use "accepted"/
        "rejected" -- not two different outcome vocabularies."""
        _, rec, _, _ = _run_with_recorder(tmp_path)
        s10, _ = _s10_s11(rec)
        assert s10["outcome"] == "accepted"


# ---------------------------------------------------------------------------
# 14: recorder=None preserves behavior
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
                mock.patch(
                    "utilities.autopatcher.pipeline.discover_test_plan_for_comparison",
                    return_value=(_PLAN, None, mock.MagicMock()),
                ),
                mock.patch(
                    "utilities.autopatcher.pipeline.evaluate_existing_test_comparison_with_amendment",
                    side_effect=_fixed_pass_amendment_outcome,
                ),
            ):
                mock_llm_cls.return_value = mock.MagicMock()
                mock_impact_cls.return_value.analyze.return_value.to_dict.return_value = {}
                from utilities.autopatcher.pipeline import run
                return run(
                    "test vuln", api_key="", repo_root=str(path),
                    execution_recorder=execution_recorder, compare_existing_tests=True,
                )

        report_without = _run(tmp_path / "a", execution_recorder=None)
        recorder = ExecutionRecorder(call_log=[], run_dir=str(tmp_path / "b"), artifacts_dir=tmp_path / "b" / "executions")
        report_with = _run(tmp_path / "b", execution_recorder=recorder)
        assert report_without == report_with
