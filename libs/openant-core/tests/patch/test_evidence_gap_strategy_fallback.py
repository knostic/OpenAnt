"""Tests for the Evidence-Gap Strategy Fallback
(pipeline._evidence_gap_fallback_trigger, pipeline._run_evidence_gap_strategy_fallback,
and their wiring into pipeline.run()'s Final Strategy (S2) stage).

Addresses a real, demonstrated deadlock: Final Strategy correctly refuses
to name a target because the pre-Strategy candidate context it was given
was too small/mistruncated to decide from (never because it looked and
found nothing) -- and, unrecovered, guided context acquisition (S3) can
never run to fetch more, because S3 itself is gated on Final Strategy
already having named a target. TestUrllib3TraceReplayRegression below
replays the exact shape of a real captured urllib3/CVE-2023-43804 run's
Final Strategy #1 response.

Authority boundary under test throughout: Planner's target_files/
target_symbols must be used ONLY as retrieval seeds for deterministic,
no-LLM-call source acquisition -- never promoted into (or used to
construct) a RemediationStrategyResult/FinalTargetSliceResult/
IntendedEdit/EditReadinessResult. Only a second, genuine
generate_remediation_strategy() call's own result may become
authoritative for anything downstream.

Two layers, matching how this codebase already tests similar bounded
orchestration (see test_planner_claim_verifier_orchestration.py):
- Direct unit tests of `_evidence_gap_fallback_trigger` and
  `_run_evidence_gap_strategy_fallback` -- fast, isolated.
- Full `pipeline.run()` tests -- prove the WIRING, not just the
  orchestration functions in isolation.
"""

from __future__ import annotations

from unittest import mock

import pytest

from utilities.autopatcher import pipeline as pipeline_mod
from utilities.autopatcher.pipeline import (
    _evidence_gap_fallback_trigger, _run_evidence_gap_strategy_fallback,
)
from utilities.autopatcher.remediation_planner import RemediationPlanResult, RemediationStrategyResult

_VULN_TEXT = "# Test vulnerability\n\nSome description of a vulnerability for testing.\n"


def _strategy(
    *, evaluated=True, target_files=(), target_symbols=(), insufficient_evidence=(), required_edits=(),
):
    return RemediationStrategyResult(
        rendered="", target_files=list(target_files), target_symbols=list(target_symbols),
        warnings=[], extended_mechanism=None, required_edits=list(required_edits),
        security_invariant=None, insufficient_evidence=list(insufficient_evidence), evaluated=evaluated,
    )


def _plan(target_files=("a.py",), target_symbols=("A",)):
    return RemediationPlanResult(
        rendered="## Target Discovery Plan\n", target_files=list(target_files), target_symbols=list(target_symbols),
        narrower_alternative_decision=None, narrower_alternative_considered=None,
    )


# ---------------------------------------------------------------------------
# _evidence_gap_fallback_trigger -- pure, structural, no prose inspection
# ---------------------------------------------------------------------------

class TestEvidenceGapFallbackTrigger:
    def test_fires_on_evaluated_empty_targets_nonempty_insufficient_evidence(self):
        strategy = _strategy(evaluated=True, target_files=[], target_symbols=[], insufficient_evidence=["gap"])
        assert _evidence_gap_fallback_trigger(strategy) is True

    def test_does_not_fire_when_insufficient_evidence_empty(self):
        """Genuine 'no viable target' decision -- must never trigger."""
        strategy = _strategy(evaluated=True, target_files=[], target_symbols=[], insufficient_evidence=[])
        assert _evidence_gap_fallback_trigger(strategy) is False

    def test_does_not_fire_when_target_files_present(self):
        strategy = _strategy(evaluated=True, target_files=["a.py"], insufficient_evidence=["gap"])
        assert _evidence_gap_fallback_trigger(strategy) is False

    def test_does_not_fire_when_target_symbols_present(self):
        strategy = _strategy(evaluated=True, target_symbols=["A"], insufficient_evidence=["gap"])
        assert _evidence_gap_fallback_trigger(strategy) is False

    def test_does_not_fire_when_not_evaluated(self):
        strategy = _strategy(evaluated=False, target_files=[], target_symbols=[], insufficient_evidence=["gap"])
        assert _evidence_gap_fallback_trigger(strategy) is False

    def test_does_not_fire_on_none(self):
        assert _evidence_gap_fallback_trigger(None) is False


# ---------------------------------------------------------------------------
# _run_evidence_gap_strategy_fallback -- direct unit tests. Mocks
# build_planner_evidence/generate_remediation_strategy at their SOURCE
# module -- both are local (function-body) imports inside the function
# under test, so mocking pipeline.<name> would not intercept them; mocking
# the source module's attribute does, since the local import re-fetches it
# at call time (same pattern as test_planner_claim_verifier_orchestration.py).
# ---------------------------------------------------------------------------

def _evidence_result(rendered, labels=()):
    """A PlannerEvidenceResult stand-in for mocking
    remediation_planner.build_planner_evidence_with_budget -- the ONE
    shared function both Strategy #1's own construction and the
    evidence-gap fallback now call (see EVIDENCE-01 and the unified
    Planner-evidence context-expansion design). `labels` is the
    structural source-coverage signature (`excerpt_plan.included_labels`)
    -- what "new evidence acquired" is decided from, never rendered text."""
    from utilities.autopatcher.remediation_planner import PlannerEvidenceResult, _SourceExcerptPlan
    return PlannerEvidenceResult(
        rendered=rendered,
        excerpt_plan=_SourceExcerptPlan(
            blocks=(rendered,) if rendered else (),
            included_labels=frozenset(labels),
            symbol_omitted=(), fallback_omitted=(), read_failed=(),
            budget=4_000, omitted_sizes={},
        ),
    )


_EMPTY_BASELINE = _evidence_result("", [])


def _run_fallback(**overrides):
    kwargs = dict(
        plan_result=_plan(), repo_root="/tmp/repo", vulnerability_text=_VULN_TEXT,
        investigation_context=None,
        budget_controller=None, llm=mock.MagicMock(),
        repo_grounding_ctx="", repository_understanding_ctx="", discovery_plan_ctx="",
        baseline_planner_evidence_result=_EMPTY_BASELINE,
    )
    kwargs.update(overrides)
    return _run_evidence_gap_strategy_fallback(**kwargs)


class TestRunEvidenceGapStrategyFallback:
    """Mocks remediation_planner.build_planner_evidence_with_budget --
    the ONE shared function both Strategy #1's own construction and this
    fallback now call -- at its SOURCE module (a local, function-body
    import inside the function under test, so mocking pipeline.<name>
    would not intercept it; mocking the source module's attribute does,
    since the local import re-fetches it at call time -- same pattern as
    test_planner_claim_verifier_orchestration.py)."""

    def test_no_planner_targets_skips_without_calling_anything(self):
        with (
            mock.patch("utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget") as spy_evidence,
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy") as spy_strategy,
        ):
            result = _run_fallback(
                plan_result=RemediationPlanResult(rendered="", target_files=[], target_symbols=[]),
            )
        spy_evidence.assert_not_called()
        spy_strategy.assert_not_called()
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "no_planner_targets_to_seed_from"

    def test_no_repo_root_skips_without_calling_anything(self):
        with (
            mock.patch("utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget") as spy_evidence,
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy") as spy_strategy,
        ):
            result = _run_fallback(repo_root=None)
        spy_evidence.assert_not_called()
        spy_strategy.assert_not_called()
        assert result["rerun_performed"] is False

    def test_identical_coverage_skips_rerun_deterministically(self):
        """Structural source coverage unchanged relative to what Strategy
        #1's own construction already saw (baseline_planner_evidence_result)
        -- must not trigger a pointless second Strategy call. This is the
        exact, sole mechanism 'new evidence actually acquired' is decided
        by (see EVIDENCE-01: comparing RENDERED TEXT was the bug)."""
        baseline = _evidence_result("thin evidence", ["a.py:A"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("thin evidence", ["a.py:A"]),
            ) as spy_evidence,
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy") as spy_strategy,
        ):
            result = _run_fallback(baseline_planner_evidence_result=baseline)
        spy_evidence.assert_called_once()
        spy_strategy.assert_not_called()
        assert result["evidence_acquired"] is False
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "no_new_evidence"

    def test_empty_new_evidence_skips_rerun(self):
        """Coverage genuinely changed relative to the baseline, but the
        full rendered evidence build still came back empty -- a defensive
        path distinct from 'coverage never changed' above."""
        baseline = _evidence_result("thin evidence", ["a.py:A"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("", []),
            ) as spy_evidence,
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy") as spy_strategy,
        ):
            result = _run_fallback(baseline_planner_evidence_result=baseline)
        spy_evidence.assert_called_once()
        spy_strategy.assert_not_called()
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "no_new_evidence"

    def test_different_coverage_calls_strategy_exactly_once(self):
        strategy_v2 = _strategy(evaluated=True, target_files=["a.py"], target_symbols=["A"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("enriched evidence -- more source than before", ["a.py:A"]),
            ) as spy_evidence,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=strategy_v2,
            ) as spy_strategy,
        ):
            result = _run_fallback()
        spy_evidence.assert_called_once()
        spy_strategy.assert_called_once()
        assert result["evidence_acquired"] is True
        assert result["rerun_performed"] is True
        assert result["strategy_result"] is strategy_v2
        assert result["enriched_planner_evidence_ctx"] == "enriched evidence -- more source than before"

    def test_downstream_sees_strategy_2_result_not_planner_targets(self):
        """The returned strategy_result is EXACTLY what
        generate_remediation_strategy (mocked) returned -- never
        constructed from plan_result.target_files/target_symbols, which
        differ from strategy_v2's here on purpose."""
        plan = _plan(target_files=["planner_only.py"], target_symbols=["PlannerOnlySymbol"])
        strategy_v2 = _strategy(evaluated=True, target_files=["real_target.py"], target_symbols=["RealTarget"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("enriched evidence", ["planner_only.py"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=strategy_v2,
            ),
        ):
            result = _run_fallback(plan_result=plan)
        assert result["strategy_result"].target_files == ["real_target.py"]
        assert result["strategy_result"].target_symbols == ["RealTarget"]
        assert "planner_only.py" not in result["strategy_result"].target_files
        assert "PlannerOnlySymbol" not in result["strategy_result"].target_symbols

    def test_no_synthetic_strategy_result_when_generate_strategy_never_called(self):
        """If coverage never changed, generate_remediation_strategy is
        never called at all, and strategy_result stays strictly None --
        never a hand-built substitute from Planner data."""
        baseline = _evidence_result("thin", ["a.py:A"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("thin", ["a.py:A"]),
            ) as spy_evidence,
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy") as spy_strategy,
        ):
            result = _run_fallback(baseline_planner_evidence_result=baseline)
        spy_evidence.assert_called_once()
        spy_strategy.assert_not_called()
        assert result["strategy_result"] is None

    def test_acquisition_failure_degrades_without_raising(self):
        """build_planner_evidence_with_budget is documented never to raise,
        but this function's own outer try/except must still degrade
        safely if it somehow did (defense in depth, mirroring every other
        best-effort section in this module)."""
        with mock.patch(
            "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
            side_effect=RuntimeError("boom"),
        ):
            result = _run_fallback()
        assert result["rerun_performed"] is False
        assert result["skip_reason"].startswith("acquisition_failed")

    def test_strategy_failure_degrades_without_raising(self):
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("enriched evidence", ["a.py:A"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=RuntimeError("boom"),
            ),
        ):
            result = _run_fallback()
        assert result["rerun_performed"] is False
        assert result["skip_reason"].startswith("rerun_failed")

    def test_model_unavailable_error_propagates(self):
        from utilities.autopatcher.pipeline import ModelUnavailableError
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("enriched evidence", ["a.py:A"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=ModelUnavailableError("declined"),
            ),
        ):
            with pytest.raises(ModelUnavailableError):
                _run_fallback()

    def test_budget_controller_is_passed_through_unchanged(self):
        """`--max-context-budget-windows` is never bypassed -- the run's own
        budget_controller is passed straight through to the shared helper,
        which alone decides how much ceiling growth policy allows."""
        budget_controller = mock.MagicMock()
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("enriched evidence", ["a.py:A"]),
            ) as spy_evidence,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ),
        ):
            _run_fallback(budget_controller=budget_controller)
        _, kwargs = spy_evidence.call_args
        assert kwargs.get("budget_controller") is budget_controller


# ---------------------------------------------------------------------------
# Full pipeline.run() tests -- these prove the WIRING (trigger, one-shot
# guard, authority handoff to Strategy #2, existing-behavior regression),
# not just the orchestration functions in isolation. Same hermetic style as
# test_planner_claim_verifier_orchestration.py: an empty/small tmp_path
# repo_root, api_key="" (mock LLM mode), source-level mocks/spies.
# ---------------------------------------------------------------------------

class TestFullPipelineWiring:
    def test_fallback_triggers_and_strategy_2_targets_reach_final_target_slice(self, tmp_path):
        strategy_v1 = _strategy(
            evaluated=True, target_files=[], target_symbols=[],
            insufficient_evidence=["some evidence gap"],
        )
        strategy_v2 = _strategy(evaluated=True, target_files=["target.py"], target_symbols=["Target"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["target.py"], target_symbols=["Target"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                side_effect=[
                    _evidence_result("thin evidence", []),
                    _evidence_result("enriched evidence", ["target.py:Target"]),
                ],
            ) as spy_evidence,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=[strategy_v1, strategy_v2],
            ) as spy_strategy,
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_final_target_slice",
                side_effect=RuntimeError("reached with the effective strategy result -- proves this branch ran"),
            ) as mock_slice,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_evidence.call_count == 2
        assert spy_strategy.call_count == 2
        mock_slice.assert_called_once()
        called_strategy = mock_slice.call_args[0][0]
        assert called_strategy.target_files == ["target.py"]
        assert called_strategy.target_symbols == ["Target"]

    def test_one_shot_guard_no_third_strategy_call(self, tmp_path):
        """Strategy #2 ALSO reports evaluated=True, zero targets, and a
        non-empty insufficient_evidence -- must not trigger a second
        fallback attempt. Existing fail-closed behavior applies to
        Strategy #2's result exactly as it would have to Strategy #1's."""
        strategy_v1 = _strategy(
            evaluated=True, target_files=[], target_symbols=[], insufficient_evidence=["gap one"],
        )
        strategy_v2 = _strategy(
            evaluated=True, target_files=[], target_symbols=[], insufficient_evidence=["gap two"],
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                side_effect=[_evidence_result("thin evidence", []), _evidence_result("enriched evidence", ["a.py:A"])],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=[strategy_v1, strategy_v2],
            ) as spy_strategy,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_strategy.call_count == 2  # never a third call

    def test_no_fallback_when_insufficient_evidence_empty(self, tmp_path):
        """Genuine 'no viable target' Strategy #1 decision -- the fallback
        must never even attempt acquisition."""
        strategy_v1 = _strategy(evaluated=True, target_files=[], target_symbols=[], insufficient_evidence=[])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("thin evidence", []),
            ) as spy_evidence,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=strategy_v1,
            ) as spy_strategy,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_evidence.call_count == 1  # only Stage 1's own call
        assert spy_strategy.call_count == 1  # never rerun

    def test_no_fallback_when_strategy_already_has_targets(self, tmp_path):
        strategy_v1 = _strategy(
            evaluated=True, target_files=["target.py"], target_symbols=["Target"],
            insufficient_evidence=["a note, but a real decision was still made"],
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["target.py"], target_symbols=["Target"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("evidence", ["target.py:Target"]),
            ) as spy_evidence,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=strategy_v1,
            ) as spy_strategy,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_evidence.call_count == 1
        assert spy_strategy.call_count == 1


class TestExistingBehaviorRegressionWhenNoTrigger:
    """When the trigger never fires, the run must behave EXACTLY as before
    this feature existed."""

    def test_default_mock_llm_run_unaffected(self, tmp_path):
        # Deliberately no mocks at all -- the default mock-mode LLM's
        # unparseable Planner response (-> _EMPTY_PLAN_RESULT) is exactly
        # the pre-existing "no plan" degradation this feature must not
        # disturb; Strategy is never evaluated at all, so the trigger can
        # never fire.
        report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert "# Auto Patcher MVP" in report

    def test_normal_strategy_success_path_unaffected(self, tmp_path):
        """Strategy #1 itself already names a real target on the first
        try -- the fallback must never engage, and generate_remediation_
        strategy must be called exactly once."""
        strategy_v1 = _strategy(evaluated=True, target_files=["target.py"], target_symbols=["Target"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["target.py"], target_symbols=["Target"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("evidence", ["target.py:Target"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=strategy_v1,
            ) as spy_strategy,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_strategy.call_count == 1


class TestExecutionArtifactObservability:
    """The Evidence-Gap Strategy Fallback's own outcome must be visible in
    S2's existing execution record -- never a new stage/execution record
    -- and must never expose Planner's retrieval seeds as if they were an
    authoritative target list."""

    def _run_with_recorder(self, tmp_path, strategy_side_effect, evidence_side_effect):
        import json
        from utilities.autopatcher.execution_recorder import ExecutionRecorder

        recorder = ExecutionRecorder(
            call_log=[], run_dir=str(tmp_path / "run"), artifacts_dir=tmp_path / "run" / "executions",
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["target.py"], target_symbols=["Target"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                side_effect=evidence_side_effect,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=strategy_side_effect,
            ),
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path), execution_recorder=recorder,
            )
        s2 = next(e for e in recorder.executions if e["canonical_stage"] == "remediation_strategy")
        artifact = json.loads(open(s2["artifact_path"], encoding="utf-8").read())
        return artifact

    def test_fallback_metadata_recorded_when_triggered(self, tmp_path):
        strategy_v1 = _strategy(evaluated=True, target_files=[], target_symbols=[], insufficient_evidence=["gap"])
        strategy_v2 = _strategy(evaluated=True, target_files=["target.py"], target_symbols=["Target"])
        artifact = self._run_with_recorder(
            tmp_path, [strategy_v1, strategy_v2],
            [_evidence_result("thin evidence", []), _evidence_result("enriched evidence", ["target.py:Target"])],
        )
        fallback = artifact["evidence_gap_fallback"]
        assert fallback["attempted"] is True
        assert fallback["evidence_acquired"] is True
        assert fallback["rerun_performed"] is True
        # Strategy #2's own result -- not Planner's -- is the recorded,
        # authoritative strategy_result.
        assert artifact["strategy_result"]["target_files"] == ["target.py"]
        assert artifact["strategy_result"]["target_symbols"] == ["Target"]
        # Planner's own retrieval-seed identifiers never appear anywhere
        # in this artifact under a key that looks authoritative.
        assert "target_files" not in fallback
        assert "target_symbols" not in fallback

    def test_fallback_metadata_recorded_when_not_triggered(self, tmp_path):
        strategy_v1 = _strategy(evaluated=True, target_files=["target.py"], target_symbols=["Target"])
        artifact = self._run_with_recorder(
            tmp_path, [strategy_v1], [_evidence_result("evidence", ["target.py:Target"])],
        )
        assert artifact["evidence_gap_fallback"] is None


class TestUrllib3TraceReplayRegression:
    """Regression modeled on a real captured urllib3/CVE-2023-43804 run
    (trace artifact: 003_remediation_strategy.response.txt) whose Final
    Strategy #1 explicitly reported these evidence gaps (quoted verbatim
    from that captured response, as test DATA only -- no urllib3-specific
    reasoning appears anywhere in production code) and returned zero
    targets, demonstrating the exact deadlock this fallback fixes: guided
    context acquisition (S3) could never run because it is itself gated on
    Final Strategy already having named a target."""

    _CAPTURED_INSUFFICIENT_EVIDENCE = [
        "The verified source for src/urllib3/connectionpool.py:HTTPConnectionPool.urlopen "
        "was omitted (budget), so the exact redirect-following branch, the existing "
        "cross-host header-stripping mechanism it must extend, and the origin-normalization "
        "helper to reuse cannot be identified from the evidence provided.",
        "The verified source for src/urllib3/util/retry.py:Retry contains only the class "
        "docstring; whether any change is needed there to expose the redirect target, and "
        "if so which method, cannot be determined from the evidence provided.",
        "No verified evidence shows where or how Authorization/Proxy-Authorization are "
        "currently stripped on cross-host redirects, so the specific existing mechanism to "
        "extend for Cookie cannot be named.",
    ]

    def test_evidence_gap_recovery_avoids_skipped_no_strategy_targets(self, tmp_path):
        import json
        from utilities.autopatcher.execution_recorder import ExecutionRecorder

        # A small, self-contained stand-in fixture (never the real urllib3
        # checkout) -- real enough that Strategy #2's named target/symbol
        # resolve to genuine repository source once authorized.
        (tmp_path / "retry.py").write_text(
            'class Retry:\n'
            '    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])\n',
            encoding="utf-8",
        )
        plan_result = _plan(target_files=["retry.py"], target_symbols=["Retry"])
        strategy_v1 = _strategy(
            evaluated=True, target_files=[], target_symbols=[],
            insufficient_evidence=self._CAPTURED_INSUFFICIENT_EVIDENCE,
        )
        strategy_v2 = _strategy(evaluated=True, target_files=["retry.py"], target_symbols=["Retry"])

        recorder = ExecutionRecorder(
            call_log=[], run_dir=str(tmp_path / "run"), artifacts_dir=tmp_path / "run" / "executions",
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=plan_result,
            ),
            # The real on-disk fixture above is tiny -- its actual source
            # coverage would already be identical at both budgets. Mocked
            # here to drive the scenario this regression replays (a real
            # captured run where the larger budget genuinely recovered
            # previously-omitted source), rather than relying on the
            # fixture happening to be large enough to omit anything itself.
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                side_effect=[
                    _evidence_result("thin evidence -- HTTPConnectionPool.urlopen omitted", []),
                    _evidence_result("enriched evidence -- Retry source recovered", ["retry.py:Retry"]),
                ],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=[strategy_v1, strategy_v2],
            ) as spy_strategy,
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path), execution_recorder=recorder,
            )

        assert spy_strategy.call_count == 2

        s3 = next(e for e in recorder.executions if e["canonical_stage"] == "guided_context_acquisition")
        assert s3["outcome"] != "skipped_no_strategy_targets"

        s2 = next(e for e in recorder.executions if e["canonical_stage"] == "remediation_strategy")
        artifact = json.loads(open(s2["artifact_path"], encoding="utf-8").read())
        assert artifact["strategy_result"]["target_files"] == ["retry.py"]
        assert artifact["strategy_result"]["target_symbols"] == ["Retry"]
        assert artifact["evidence_gap_fallback"]["rerun_performed"] is True


class TestProductionAndReplayShareTheSameStage3Gate:
    """The Evidence-Gap Strategy Fallback replaces _strategy_result BEFORE
    Stage 3 (guided_context_acquisition) runs -- Stage 3's own gate
    (pipeline._run_guided_context_acquisition) is completely untouched by
    this feature and is the same function object replay_engine.py uses."""

    def test_replay_engine_imports_the_same_function_object(self):
        import utilities.autopatcher.replay_engine as replay_engine_mod

        assert replay_engine_mod._run_guided_context_acquisition is pipeline_mod._run_guided_context_acquisition


# ---------------------------------------------------------------------------
def _make_investigation_context(functions, repo_path):
    """Minimal, self-contained InvestigationContext for a real (on-disk)
    fixture -- deliberately defined locally rather than imported from
    another test module (no existing precedent for that in this suite);
    mirrors test_post_patch_recovery.py's own `_make_context` shape."""
    from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.autopatcher.candidate_enrichment import InvestigationContext

    index = RepositoryIndex({"functions": functions}, repo_path=str(repo_path))
    reachability = ReachabilityAnalyzer(functions, {}, set())
    return InvestigationContext(
        index=index, call_graph={}, reverse_call_graph={}, reachability=reachability, constants={},
    )


# EVIDENCE-01 -- "new evidence actually acquired" must be decided from
# structural source coverage (which candidates' source actually fits the
# budget), never from comparing two RENDERED Markdown strings. A rendered
# omission notice embeds the budget ceiling itself ("...within the
# {N}-character budget..."), so two calls at different `max_chars` values
# always produce different text even when the exact same symbol is omitted
# both times -- the rendered-text-equality check the fallback used to run
# was fooled by exactly this. These tests call the real, unmodified
# `_run_evidence_gap_strategy_fallback` end-to-end against a real on-disk
# fixture (no mocking of build_planner_evidence/generate_remediation_
# strategy) so the observed result reflects genuine repository resolution,
# not a hand-scripted string. `llm=None` is safe here: a genuine rerun
# attempt would fail inside generate_remediation_strategy's own
# `llm.complete(...)` call, caught by its existing `except Exception:
# return _EMPTY_STRATEGY_RESULT` -- no network call is ever made either way,
# and `rerun_performed` still correctly reports whether Step 2 was reached.
# ---------------------------------------------------------------------------

class TestEvidenceGapUsesStructuralCoverageNotRenderedText:
    def test_symbol_omitted_at_both_calls_is_not_reported_as_acquired(self, tmp_path):
        """FALSE-POSITIVE REGRESSION: with no budget_controller supplied
        (the degenerate, always-safe case -- see build_planner_evidence_
        with_budget's own docstring), both the baseline and the fallback's
        fresh call render at the identical, unexpandable base budget --
        must NOT be reported as newly acquired evidence, and must NOT
        trigger a Strategy #2 call. (The separate "a resolved candidate
        provably cannot fit within remaining legal windows" case is
        covered directly at build_planner_evidence_with_budget's own level
        in test_remediation_planner.py.)"""
        big_body = "\n".join(f"    line_{i} = {i}" for i in range(1, 1000))  # ~18,800 chars
        src = f"def big_function():\n{big_body}\n    return None\n"
        (tmp_path / "mod.py").write_text(src, encoding="utf-8")

        context = _make_investigation_context(functions={
            "mod.py:big_function": {"name": "big_function", "startLine": 1, "endLine": len(src.splitlines()), "code": src},
        }, repo_path=tmp_path)
        plan_result = _plan(target_files=["mod.py"], target_symbols=["mod.py:big_function"])

        from utilities.autopatcher.remediation_planner import build_planner_evidence_with_budget
        baseline = build_planner_evidence_with_budget(plan_result, tmp_path, _VULN_TEXT, context)
        assert baseline.excerpt_plan.symbol_omitted  # sanity: genuinely omitted at the default budget

        result = _run_evidence_gap_strategy_fallback(
            plan_result=plan_result, repo_root=tmp_path, vulnerability_text=_VULN_TEXT,
            investigation_context=context,
            budget_controller=None, llm=None,
            repo_grounding_ctx="", repository_understanding_ctx="", discovery_plan_ctx="",
            baseline_planner_evidence_result=baseline,
        )
        assert result["evidence_acquired"] is False
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "no_new_evidence"

    def test_symbol_genuinely_fits_at_enlarged_budget_is_reported_as_acquired(self, tmp_path):
        """POSITIVE CONTROL: the baseline reflects a symbol omitted at the
        base budget (as Strategy #1's own construction would see with no
        expansion yet applied); the fallback, given a REAL policy="always"
        ContextBudgetController, genuinely recovers it. This protects
        legitimate bounded recovery from being collaterally suppressed by
        the false-positive fix above -- exercised end-to-end against real
        repository resolution, not a mocked string."""
        body = "\n".join(f"    line_{i} = {i}" for i in range(1, 300))  # ~5,000-6,000 chars
        src = f"def medium_function():\n{body}\n    return None\n"
        (tmp_path / "mod.py").write_text(src, encoding="utf-8")

        context = _make_investigation_context(functions={
            "mod.py:medium_function": {"name": "medium_function", "startLine": 1, "endLine": len(src.splitlines()), "code": src},
        }, repo_path=tmp_path)
        plan_result = _plan(target_files=["mod.py"], target_symbols=["mod.py:medium_function"])

        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import build_planner_evidence_with_budget
        baseline = build_planner_evidence_with_budget(plan_result, tmp_path, _VULN_TEXT, context)
        assert baseline.excerpt_plan.symbol_omitted  # sanity: genuinely omitted at the default budget

        result = _run_evidence_gap_strategy_fallback(
            plan_result=plan_result, repo_root=tmp_path, vulnerability_text=_VULN_TEXT,
            investigation_context=context,
            budget_controller=ContextBudgetController(policy="always", max_windows=10), llm=None,
            repo_grounding_ctx="", repository_understanding_ctx="", discovery_plan_ctx="",
            baseline_planner_evidence_result=baseline,
        )
        assert result["evidence_acquired"] is True
        assert result["rerun_performed"] is True


class TestSharedHelperWiring:
    """Strategy #1's own evidence construction and the evidence-gap
    fallback call the exact SAME shared function
    (remediation_planner.build_planner_evidence_with_budget), passing the
    exact SAME run-scoped budget_controller object -- proving 'consistent
    semantics' structurally (same object identity), not by re-deriving
    behavior from two independent implementations."""

    def test_strategy1_construction_passes_run_budget_controller(self, tmp_path):
        budget_controller = mock.MagicMock()
        empty_result = _evidence_result("", [])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=empty_result,
            ) as spy,
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path),
                budget_controller=budget_controller,
            )
        assert spy.call_count >= 1
        _, kwargs = spy.call_args_list[0]
        assert kwargs.get("budget_controller") is budget_controller

    def test_fallback_construction_passes_same_run_budget_controller(self, tmp_path):
        budget_controller = mock.MagicMock()
        strategy_v1 = _strategy(
            evaluated=True, target_files=[], target_symbols=[], insufficient_evidence=["gap"],
        )
        strategy_v2 = _strategy(evaluated=True, target_files=["target.py"], target_symbols=["Target"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["target.py"], target_symbols=["Target"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                side_effect=[_evidence_result("thin", []), _evidence_result("enriched", ["target.py:Target"])],
            ) as spy,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=[strategy_v1, strategy_v2],
            ),
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path),
                budget_controller=budget_controller,
            )
        assert spy.call_count == 2
        for call in spy.call_args_list:
            assert call.kwargs.get("budget_controller") is budget_controller

    def test_v2_authoritative_rebuild_passes_same_run_budget_controller(self, tmp_path):
        """When the Planner Claim Verifier's revised (v2) plan becomes
        authoritative, pipeline.py's own rebuild of _planner_evidence_result
        for that revised plan must use the SAME run-scoped budget_controller
        Strategy #1's own (pre-revision) construction used -- not a
        controller-less rebuild that silently diverges from the rest of
        the run's budget-aware evidence semantics."""
        budget_controller = mock.MagicMock()
        plan_v1 = RemediationPlanResult(
            rendered="## Target Discovery Plan\n", target_files=["a.py"], target_symbols=["A"],
            narrower_alternative_decision="REJECTED", narrower_alternative_considered="a narrower alternative",
        )
        plan_v2 = RemediationPlanResult(
            rendered="## Target Discovery Plan (revised)\n", target_files=["a.py"], target_symbols=["A"],
        )
        verification_result = {
            "verifier_v1": None, "verifier_v2": None, "mode_v1": "REJECTED", "mode_v2": None,
            "revision_attempted": True, "forced_skip": False, "skip_reason": None,
            "broadening_unresolved": False, "authoritative": "v2",
            "revised_plan_result": plan_v2, "revised_plan_ctx": plan_v2.rendered,
            "revised_planner_evidence_ctx": "plain, unbudgeted v2 evidence -- must not be used verbatim",
        }
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=plan_v1,
            ),
            mock.patch(
                "utilities.autopatcher.pipeline._run_planner_claim_verification",
                return_value=verification_result,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                side_effect=[_evidence_result("v1 evidence", ["a.py:A"]), _evidence_result("v2 evidence", ["a.py:A"])],
            ) as spy,
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path),
                budget_controller=budget_controller,
            )
        # Two calls: (1) Strategy #1's own pre-revision construction for
        # plan_v1, (2) the v2-authoritative rebuild for plan_v2 -- both must
        # share the exact same run-scoped controller object.
        assert spy.call_count == 2
        _, v2_kwargs = spy.call_args_list[1]
        assert v2_kwargs.get("budget_controller") is budget_controller
