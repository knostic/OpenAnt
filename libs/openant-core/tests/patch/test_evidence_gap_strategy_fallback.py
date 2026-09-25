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
    target_authority_unresolved=False,
):
    return RemediationStrategyResult(
        rendered="", target_files=list(target_files), target_symbols=list(target_symbols),
        warnings=[], extended_mechanism=None, required_edits=list(required_edits),
        security_invariant=None, insufficient_evidence=list(insufficient_evidence), evaluated=evaluated,
        target_authority_unresolved=target_authority_unresolved,
    )


def _plan(target_files=("a.py",), target_symbols=("A",)):
    # Fix A: additional_evidence_required="explicit_false" -- this file is
    # about the Evidence-Gap Strategy Fallback (a Strategy-level, later
    # mechanism), not about Planning's own evidence-sufficiency gate; every
    # plan built here must already read as grounded so the pipeline
    # actually reaches Strategy at all.
    return RemediationPlanResult(
        rendered="## Target Discovery Plan\n", target_files=list(target_files), target_symbols=list(target_symbols),
        narrower_alternative_decision=None, narrower_alternative_considered=None,
        additional_evidence_required="explicit_false",
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

    # -- Named-target authority-gap case (additive, scope-v4 Run 5 fix) --

    def test_fires_on_named_target_with_authority_unresolved(self):
        strategy = _strategy(evaluated=True, target_files=["a.py"], target_authority_unresolved=True)
        assert _evidence_gap_fallback_trigger(strategy) is True

    def test_fires_on_named_symbol_with_authority_unresolved(self):
        strategy = _strategy(evaluated=True, target_symbols=["A"], target_authority_unresolved=True)
        assert _evidence_gap_fallback_trigger(strategy) is True

    def test_does_not_fire_on_named_target_with_authority_resolved(self):
        strategy = _strategy(evaluated=True, target_files=["a.py"], target_authority_unresolved=False)
        assert _evidence_gap_fallback_trigger(strategy) is False

    def test_named_target_authority_unresolved_fires_without_prose_corroboration(self):
        """The structured boolean is honored on its own -- insufficient_
        evidence being empty must not suppress the trigger."""
        strategy = _strategy(
            evaluated=True, target_files=["a.py"], insufficient_evidence=[],
            target_authority_unresolved=True,
        )
        assert _evidence_gap_fallback_trigger(strategy) is True

    def test_named_target_nonempty_insufficient_evidence_without_flag_does_not_fire(self):
        """Regression guard, mirror image of the test above: non-empty
        insufficient_evidence prose must never be inferred into a trigger
        on its own -- only the explicit structured field may do that."""
        strategy = _strategy(
            evaluated=True, target_files=["a.py"],
            insufficient_evidence=["override the default; custom, non-default, low-level"],
            target_authority_unresolved=False,
        )
        assert _evidence_gap_fallback_trigger(strategy) is False

    def test_zero_target_case_unaffected_by_authority_unresolved_value(self):
        """The zero-target trigger condition is decided by insufficient_
        evidence alone, exactly as before this field existed --
        target_authority_unresolved is irrelevant when there is no target."""
        strategy_true = _strategy(
            evaluated=True, target_files=[], target_symbols=[],
            insufficient_evidence=["gap"], target_authority_unresolved=True,
        )
        strategy_false = _strategy(
            evaluated=True, target_files=[], target_symbols=[],
            insufficient_evidence=["gap"], target_authority_unresolved=False,
        )
        assert _evidence_gap_fallback_trigger(strategy_true) is True
        assert _evidence_gap_fallback_trigger(strategy_false) is True


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


def _realistic_evidence_result(structural_facts: str, source_items: "list[tuple[str, str]]"):
    """A more faithful `PlannerEvidenceResult` stand-in than `_evidence_result`
    above: `source_items` is `[(label, code), ...]`, each rendered through
    the SAME header format `_render_source_excerpt` actually produces
    ("#### Verified source: `label` (lines 1-N)"), so tests of
    `_dedupe_source_excerpt_blocks`/`merge_baseline_and_reacquired_planner_
    evidence` exercise real per-block structure rather than one opaque
    string. `rendered` mirrors `_build_planner_evidence_result`'s own
    shape: structural facts, then `_SOURCE_SUBHEADING`, then the joined
    blocks -- so the merge function's own subheading-split logic is
    exercised against realistic input."""
    from utilities.autopatcher.remediation_planner import (
        PlannerEvidenceResult, _SourceExcerptPlan, _SOURCE_SUBHEADING, _SOURCE_DISCLAIMER,
    )
    blocks = tuple(
        f"#### Verified source: `{label}` (lines 1-{len(code.splitlines())})\n\n```python\n{code}\n```\n"
        for label, code in source_items
    )
    source_section = (
        f"{_SOURCE_SUBHEADING}\n\n{_SOURCE_DISCLAIMER}\n\n" + "\n".join(blocks)
        if blocks else ""
    )
    rendered = f"{structural_facts}\n\n{source_section}" if source_section else structural_facts
    return PlannerEvidenceResult(
        rendered=rendered,
        excerpt_plan=_SourceExcerptPlan(
            blocks=blocks,
            included_labels=frozenset(label for label, _ in source_items),
            symbol_omitted=(), fallback_omitted=(), read_failed=(),
            budget=4_000, omitted_sizes={},
        ),
    )


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

    # -- merge_with_baseline parameter (scope-v4/authority-v1 fix) --

    def test_merge_with_baseline_false_uses_fresh_evidence_alone(self):
        """Default/zero-target behavior must be byte-for-byte unchanged:
        Strategy #2 receives fresh's own rendered evidence alone, exactly
        as before this parameter existed."""
        baseline = _realistic_evidence_result("baseline facts", [("old.py:Old", "pass")])
        fresh = _realistic_evidence_result("fresh facts", [("a.py:A", "pass")])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=False,
            )
        _, kwargs = spy_strategy.call_args
        assert kwargs["planner_evidence_ctx"] == fresh.rendered
        assert "baseline facts" not in kwargs["planner_evidence_ctx"]
        assert result["enriched_planner_evidence_ctx"] == fresh.rendered

    def test_merge_with_baseline_true_combines_both(self):
        """The named-target authority-gap fix: Strategy #2 must receive
        baseline's evidence UNION fresh's evidence, not fresh alone."""
        baseline = _realistic_evidence_result(
            "PoolManager facts", [("poolmanager.py:PoolManager.urlopen", "def urlopen():\n    pass")],
        )
        fresh = _realistic_evidence_result("Retry facts", [("retry.py:Retry", "class Retry:\n    pass")])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["retry.py"]),
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
            )
        _, kwargs = spy_strategy.call_args
        assert "def urlopen():" in kwargs["planner_evidence_ctx"]
        assert "class Retry:" in kwargs["planner_evidence_ctx"]
        assert "def urlopen():" in result["enriched_planner_evidence_ctx"]
        assert "class Retry:" in result["enriched_planner_evidence_ctx"]

    def test_merge_with_baseline_records_combined_length_for_observability(self):
        """budget_controller.record_used is best-effort observability only
        (never consulted by request_extension's own decision -- see that
        method's docstring) -- but must reflect the ACTUAL combined size
        sent to Strategy #2, not fresh's smaller size alone. Wraps a real
        ContextBudgetController so effective_budget()/request_extension()
        behave functionally (the merge-size accounting block now calls
        them for real) while still allowing call assertions on the mock."""
        from utilities.autopatcher.context_budget import ContextBudgetController

        baseline = _realistic_evidence_result(
            "PoolManager facts", [("poolmanager.py:PoolManager.urlopen", "def urlopen():\n    pass")],
        )
        fresh = _realistic_evidence_result("Retry facts", [("retry.py:Retry", "class Retry:\n    pass")])
        budget_controller = mock.MagicMock(wraps=ContextBudgetController(policy="always", max_windows=10))
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["retry.py"]),
            ),
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=budget_controller,
            )
        budget_controller.record_used.assert_called_once_with(
            "planner_evidence", len(result["enriched_planner_evidence_ctx"]),
        )

    def test_merge_with_baseline_false_never_calls_record_used_for_merge(self):
        """No new/independent budget mechanism is introduced for the
        zero-target (merge_with_baseline=False) path -- record_used is
        never called by this function itself in that case (existing
        callers of build_planner_evidence_with_budget already record their
        own usage internally; this function must not double-record)."""
        budget_controller = mock.MagicMock()
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("enriched evidence", ["a.py:A"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ),
        ):
            _run_fallback(merge_with_baseline=False, budget_controller=budget_controller)
        budget_controller.record_used.assert_not_called()

    def test_default_merge_with_baseline_is_false(self):
        """Callers that don't pass this new parameter at all (e.g. any
        pre-existing/future direct caller) must get the exact prior
        behavior -- fresh evidence alone."""
        fresh = _realistic_evidence_result("fresh facts", [("a.py:A", "pass")])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=_realistic_evidence_result("baseline facts", [("old.py:Old", "pass")]),
            )
        _, kwargs = spy_strategy.call_args
        assert kwargs["planner_evidence_ctx"] == fresh.rendered
        assert result["enriched_planner_evidence_ctx"] == fresh.rendered


# ---------------------------------------------------------------------------
# Merge-size budget accounting (final read-only QA finding, this task): the
# merge's own combined size was never checked against the "planner_evidence"
# stage's live ceiling, nor routed through request_extension() -- unlike
# every other budget-governed accumulation in this module (e.g.
# run_deterministic_acquisition's own total_remaining/request_extension
# pattern for "final_target_slice"). These tests exercise the REAL
# merge_baseline_and_reacquired_planner_evidence and a REAL
# ContextBudgetController, only mocking the two LLM-adjacent calls exactly
# like every other test in this file.
# ---------------------------------------------------------------------------

class TestMergeBudgetAccounting:
    def test_merge_already_fits_no_extension_requested(self):
        """Case 1: merged evidence already fits inside the stage's current
        effective budget -- request_extension must never be called, and
        Strategy #2 still runs exactly once."""
        from utilities.autopatcher.context_budget import ContextBudgetController

        baseline = _evidence_result("small baseline evidence", ["old.py:Old"])
        fresh = _evidence_result("small fresh evidence", ["a.py:A"])
        budget_controller = mock.MagicMock(wraps=ContextBudgetController(policy="never", max_windows=10))
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=budget_controller,
            )
        budget_controller.request_extension.assert_not_called()
        spy_strategy.assert_called_once()
        assert result["rerun_performed"] is True
        assert result["skip_reason"] is None

    def test_merge_requires_one_additional_window(self):
        """Case 2: merged evidence needs exactly one more window than the
        stage's initial allowance -- exactly one request_extension call is
        approved, then Strategy #2 runs once with the full combined
        evidence (both baseline's and fresh's content present)."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import merge_baseline_and_reacquired_planner_evidence

        baseline = _evidence_result("A" * 60, ["old.py:Old"])
        fresh = _evidence_result("B" * 60, ["a.py:A"])
        merged_len = len(merge_baseline_and_reacquired_planner_evidence(baseline, fresh))
        window_size = -(-merged_len // 2)  # ceil(merged_len / 2): 1 window insufficient, 2 sufficient

        budget_controller = mock.MagicMock(wraps=ContextBudgetController(policy="always", max_windows=10))
        with (
            mock.patch("utilities.autopatcher.evidence_fusion.DEFAULT_MAX_CHARS", window_size),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=budget_controller,
            )
        assert budget_controller.request_extension.call_count == 1
        spy_strategy.assert_called_once()
        assert result["rerun_performed"] is True
        assert "A" * 60 in result["enriched_planner_evidence_ctx"]
        assert "B" * 60 in result["enriched_planner_evidence_ctx"]

    def test_merge_requires_multiple_bounded_windows(self):
        """Case 3: merged evidence needs several windows -- the loop
        requests exactly as many as needed (never more, never fewer),
        strictly bounded by max_windows, then Strategy #2 runs once."""
        import math

        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import merge_baseline_and_reacquired_planner_evidence

        baseline = _evidence_result("A" * 200, ["old.py:Old"])
        fresh = _evidence_result("B" * 200, ["a.py:A"])
        merged_len = len(merge_baseline_and_reacquired_planner_evidence(baseline, fresh))
        window_size = -(-merged_len // 5)  # ceil(merged_len / 5): forces several windows
        expected_windows = math.ceil(merged_len / window_size)
        assert expected_windows >= 3, "test setup must actually exercise multiple windows"

        budget_controller = mock.MagicMock(wraps=ContextBudgetController(policy="always", max_windows=10))
        with (
            mock.patch("utilities.autopatcher.evidence_fusion.DEFAULT_MAX_CHARS", window_size),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=budget_controller,
            )
        assert budget_controller.request_extension.call_count == expected_windows - 1
        spy_strategy.assert_called_once()
        assert result["rerun_performed"] is True

    def test_policy_always_reaches_sufficient_budget_and_proceeds(self):
        """Case 4: policy='always' auto-approves the needed windows without
        any interactive prompt, up to max_windows, then proceeds."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import merge_baseline_and_reacquired_planner_evidence

        baseline = _evidence_result("A" * 90, ["old.py:Old"])
        fresh = _evidence_result("B" * 90, ["a.py:A"])
        merged_len = len(merge_baseline_and_reacquired_planner_evidence(baseline, fresh))
        window_size = -(-merged_len // 3)

        confirm = mock.MagicMock()  # must never be consulted -- policy="always" never asks
        budget_controller = ContextBudgetController(policy="always", max_windows=10, confirm=confirm)
        with (
            mock.patch("utilities.autopatcher.evidence_fusion.DEFAULT_MAX_CHARS", window_size),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=budget_controller,
            )
        confirm.assert_not_called()
        spy_strategy.assert_called_once()
        assert result["rerun_performed"] is True

    def test_policy_never_and_merge_does_not_fit_fails_closed(self):
        """Case 6: policy='never' with insufficient initial budget -- no
        extension is ever approved, Strategy #2 is never called, and the
        fallback fails closed with the narrowly-named skip reason."""
        from utilities.autopatcher.context_budget import ContextBudgetController

        baseline = _evidence_result("A" * 200, ["old.py:Old"])
        fresh = _evidence_result("B" * 200, ["a.py:A"])
        budget_controller = ContextBudgetController(policy="never", max_windows=10)
        with (
            mock.patch("utilities.autopatcher.evidence_fusion.DEFAULT_MAX_CHARS", 50),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=budget_controller,
            )
        spy_strategy.assert_not_called()
        assert result["rerun_performed"] is False
        assert result["strategy_result"] is None
        assert result["skip_reason"] == "preserved_evidence_budget_exhausted"

    def test_policy_ask_refusal_fails_closed(self):
        """Case 7: policy='ask' with the user refusing every prompt -- no
        extension is approved, Strategy #2 is never called, fail-closed."""
        from utilities.autopatcher.context_budget import ContextBudgetController

        baseline = _evidence_result("A" * 200, ["old.py:Old"])
        fresh = _evidence_result("B" * 200, ["a.py:A"])
        budget_controller = ContextBudgetController(
            policy="ask", max_windows=10, interactive=True, confirm=lambda _prompt: False,
        )
        with (
            mock.patch("utilities.autopatcher.evidence_fusion.DEFAULT_MAX_CHARS", 50),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=budget_controller,
            )
        spy_strategy.assert_not_called()
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "preserved_evidence_budget_exhausted"

    def test_no_controller_bounded_and_fails_closed_when_over_base_ceiling(self):
        """Case 8: no controller at all -- must reproduce
        build_planner_evidence_with_budget's own no-controller behavior (a
        single fixed ceiling, no extension path) against the COMBINED
        size, so preserving baseline evidence never opens an unbounded
        path merely because no controller was supplied."""
        baseline = _evidence_result("A" * 200, ["old.py:Old"])
        fresh = _evidence_result("B" * 200, ["a.py:A"])
        with (
            mock.patch("utilities.autopatcher.evidence_fusion.DEFAULT_MAX_CHARS", 50),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=None,
            )
        spy_strategy.assert_not_called()
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "preserved_evidence_budget_exhausted"

    def test_no_controller_small_merge_still_proceeds(self):
        """Companion to the above: no controller, but the combined evidence
        fits within the single fixed base ceiling -- must proceed exactly
        as before this fix."""
        baseline = _evidence_result("small baseline", ["old.py:Old"])
        fresh = _evidence_result("small fresh", ["a.py:A"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=None,
            )
        spy_strategy.assert_called_once()
        assert result["rerun_performed"] is True

    def test_record_used_is_observability_only_not_enforcement(self):
        """Confirms record_used cannot enforce anything (per its own
        docstring): pre-recording a huge used_chars value for the stage
        must have zero effect on the extension/fail-closed decision, which
        depends only on effective_budget()/request_extension()."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.evidence_fusion import DEFAULT_MAX_CHARS

        budget_controller = ContextBudgetController(policy="never", max_windows=10)
        budget_controller.effective_budget("planner_evidence", DEFAULT_MAX_CHARS)  # registers the stage
        budget_controller.record_used("planner_evidence", 10**9)  # must not affect gating

        baseline = _evidence_result("small baseline", ["old.py:Old"])
        fresh = _evidence_result("small fresh", ["a.py:A"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy(evaluated=True, target_files=["a.py"]),
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=budget_controller,
            )
        spy_strategy.assert_called_once()
        assert result["rerun_performed"] is True
        assert result["skip_reason"] is None

    def test_extension_bounded_by_max_windows_never_exceeded(self):
        """The extension loop must never exceed max_windows total windows
        for the stage, regardless of how large the merged evidence is --
        proving the loop is structurally bounded, not just empirically
        bounded for the other tests' particular sizes."""
        from utilities.autopatcher.context_budget import ContextBudgetController

        baseline = _evidence_result("A" * 5000, ["old.py:Old"])
        fresh = _evidence_result("B" * 5000, ["a.py:A"])
        budget_controller = mock.MagicMock(wraps=ContextBudgetController(policy="always", max_windows=3))
        with (
            mock.patch("utilities.autopatcher.evidence_fusion.DEFAULT_MAX_CHARS", 10),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
            ) as spy_strategy,
        ):
            result = _run_fallback(
                baseline_planner_evidence_result=baseline, merge_with_baseline=True,
                budget_controller=budget_controller,
            )
        # At most max_windows(3) calls: up to 2 approvals (initial_windows=1
        # -> max_windows=3) plus exactly one final hard-cap refusal.
        assert budget_controller.request_extension.call_count <= 3
        spy_strategy.assert_not_called()
        assert result["skip_reason"] == "preserved_evidence_budget_exhausted"


# ---------------------------------------------------------------------------
# Baseline-evidence preservation (scope-v4/authority-v1 forensic finding):
# the named-target authority-gap reacquisition's own PlannerEvidenceResult
# has no memory of whatever Strategy #1's own (broader) evidence
# construction already resolved -- these are direct, pure-function tests of
# the combination/deduplication logic itself, with no mocking needed.
# ---------------------------------------------------------------------------

class TestDedupeSourceExcerptBlocks:
    def test_keeps_blocks_whose_label_is_not_already_included(self):
        from utilities.autopatcher.remediation_planner import _dedupe_source_excerpt_blocks
        block = "#### Verified source: `a.py:A` (lines 1-2)\n\n```python\npass\n```\n"
        assert _dedupe_source_excerpt_blocks((block,), frozenset()) == (block,)

    def test_drops_blocks_whose_label_is_already_included(self):
        from utilities.autopatcher.remediation_planner import _dedupe_source_excerpt_blocks
        block = "#### Verified source: `a.py:A` (lines 1-2)\n\n```python\npass\n```\n"
        assert _dedupe_source_excerpt_blocks((block,), frozenset({"a.py:A"})) == ()

    def test_partial_overlap_keeps_only_the_non_duplicate_block(self):
        from utilities.autopatcher.remediation_planner import _dedupe_source_excerpt_blocks
        dup = "#### Verified source: `a.py:A` (lines 1-2)\n\n```python\npass\n```\n"
        new = "#### Verified source: `b.py:B` (lines 1-2)\n\n```python\npass\n```\n"
        assert _dedupe_source_excerpt_blocks((dup, new), frozenset({"a.py:A"})) == (new,)

    def test_whole_file_label_without_symbol_suffix_is_recognized(self):
        """Pass 2 (full-file fallback) labels are a bare path, no `:symbol`
        suffix -- the header regex must handle both shapes identically."""
        from utilities.autopatcher.remediation_planner import _dedupe_source_excerpt_blocks
        block = "#### Verified source: `setup.py` (full file, 12 lines)\n\n```python\npass\n```\n"
        assert _dedupe_source_excerpt_blocks((block,), frozenset({"setup.py"})) == ()
        assert _dedupe_source_excerpt_blocks((block,), frozenset()) == (block,)

    def test_unrecognized_header_shape_is_conservatively_kept(self):
        """A block that doesn't match the exact, code-generated header
        format (should never happen for a real _SourceExcerptPlan.blocks
        entry) fails closed toward preserving evidence, never toward
        silently discarding it."""
        from utilities.autopatcher.remediation_planner import _dedupe_source_excerpt_blocks
        weird_block = "some unexpected text with no recognizable header\n"
        assert _dedupe_source_excerpt_blocks((weird_block,), frozenset({"anything"})) == (weird_block,)

    def test_empty_blocks_tuple_returns_empty(self):
        from utilities.autopatcher.remediation_planner import _dedupe_source_excerpt_blocks
        assert _dedupe_source_excerpt_blocks((), frozenset({"a.py:A"})) == ()


class TestMergeBaselineAndReacquiredPlannerEvidence:
    def test_no_overlap_preserves_both_baseline_and_fresh(self):
        from utilities.autopatcher.remediation_planner import merge_baseline_and_reacquired_planner_evidence
        baseline = _realistic_evidence_result(
            "### Repository Understanding\n\nPoolManager facts",
            [("poolmanager.py:PoolManager.urlopen", "def urlopen():\n    pass")],
        )
        fresh = _realistic_evidence_result(
            "### Repository Understanding\n\nRetry facts",
            [("retry.py:Retry", "class Retry:\n    pass")],
        )
        merged = merge_baseline_and_reacquired_planner_evidence(baseline, fresh)
        assert "def urlopen():" in merged
        assert "class Retry:" in merged
        assert "PoolManager facts" in merged
        assert "Retry facts" in merged

    def test_overlap_does_not_duplicate_the_shared_evidence_item(self):
        """CASE 2 -- structural-identity dedup: fresh re-includes a label
        baseline already fully had (e.g. because it had more budget room
        to itself this time); the shared source must appear exactly once
        in the combined evidence, and the genuinely new item must still
        be present."""
        from utilities.autopatcher.remediation_planner import merge_baseline_and_reacquired_planner_evidence
        baseline = _realistic_evidence_result(
            "### Repository Understanding\n\nfacts A",
            [("poolmanager.py:PoolManager.urlopen", "def urlopen():\n    pass")],
        )
        fresh = _realistic_evidence_result(
            "### Repository Understanding\n\nfacts B",
            [
                ("poolmanager.py:PoolManager.urlopen", "def urlopen():\n    pass"),
                ("retry.py:Retry", "class Retry:\n    pass"),
            ],
        )
        merged = merge_baseline_and_reacquired_planner_evidence(baseline, fresh)
        assert merged.count("def urlopen():") == 1
        assert "class Retry:" in merged
        assert "facts B" in merged  # fresh's own structural facts still survive

    def test_full_overlap_drops_all_of_fresh_source_but_keeps_baseline(self):
        from utilities.autopatcher.remediation_planner import merge_baseline_and_reacquired_planner_evidence
        item = ("poolmanager.py:PoolManager.urlopen", "def urlopen():\n    pass")
        baseline = _realistic_evidence_result("facts A", [item])
        fresh = _realistic_evidence_result("facts B (all redundant)", [item])
        merged = merge_baseline_and_reacquired_planner_evidence(baseline, fresh)
        assert merged.count("def urlopen():") == 1
        assert "facts A" in merged

    def test_empty_baseline_returns_fresh_unchanged(self):
        from utilities.autopatcher.remediation_planner import (
            merge_baseline_and_reacquired_planner_evidence, PlannerEvidenceResult, _EMPTY_SOURCE_EXCERPT_PLAN,
        )
        empty_baseline = PlannerEvidenceResult(rendered="", excerpt_plan=_EMPTY_SOURCE_EXCERPT_PLAN)
        fresh = _realistic_evidence_result("facts", [("a.py:A", "pass")])
        assert merge_baseline_and_reacquired_planner_evidence(empty_baseline, fresh) == fresh.rendered

    def test_empty_fresh_returns_baseline_unchanged(self):
        from utilities.autopatcher.remediation_planner import (
            merge_baseline_and_reacquired_planner_evidence, PlannerEvidenceResult, _EMPTY_SOURCE_EXCERPT_PLAN,
        )
        baseline = _realistic_evidence_result("facts", [("a.py:A", "pass")])
        empty_fresh = PlannerEvidenceResult(rendered="", excerpt_plan=_EMPTY_SOURCE_EXCERPT_PLAN)
        assert merge_baseline_and_reacquired_planner_evidence(baseline, empty_fresh) == baseline.rendered

    def test_no_prose_or_keyword_inspection_of_evidence_content(self):
        """Regression guard: the merge/dedup decision is driven entirely by
        `included_labels` (structural identity), never by scanning the
        actual source code or structural-facts text for keywords -- two
        DIFFERENT labels whose CODE happens to look identical must both
        survive (not collapsed as if they were 'the same' by content)."""
        from utilities.autopatcher.remediation_planner import merge_baseline_and_reacquired_planner_evidence
        baseline = _realistic_evidence_result("facts A", [("a.py:A", "def f():\n    pass")])
        fresh = _realistic_evidence_result("facts B", [("b.py:B", "def f():\n    pass")])
        merged = merge_baseline_and_reacquired_planner_evidence(baseline, fresh)
        assert merged.count("def f():") == 2  # different labels, both kept despite identical code


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


class TestNamedTargetAuthorityGapFullPipelineWiring:
    """Full pipeline.run() tests for the named-target authority-gap branch
    (scope-v4 Run 5 forensic finding, added by this task) -- proves the
    WIRING end to end, mirroring TestFullPipelineWiring above but for the
    new trigger case."""

    def test_seeds_reacquisition_from_strategy_target_not_planner_target(self, tmp_path):
        """CRITICAL control: Planner and Strategy propose DIFFERENT
        targets. Reacquisition must expand around Strategy's OWN chosen
        target (the one whose authority is actually in doubt), never
        silently fall back to Planner's original, different guess -- this
        test fails if the implementation accidentally seeds only from
        plan_result for this branch."""
        strategy_v1 = _strategy(
            evaluated=True, target_files=["strategy_target.py"], target_symbols=["StrategyTarget"],
            target_authority_unresolved=True,
        )
        strategy_v2 = _strategy(evaluated=True, target_files=["strategy_target.py"], target_symbols=["StrategyTarget"])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["planner_target.py"], target_symbols=["PlannerTarget"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                side_effect=[
                    _evidence_result("strategy 1 evidence", []),
                    _evidence_result("enriched evidence", ["strategy_target.py:StrategyTarget"]),
                ],
            ) as spy_evidence,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=[strategy_v1, strategy_v2],
            ) as spy_strategy,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_strategy.call_count == 2
        assert spy_evidence.call_count == 2
        # First call: Strategy #1's own construction, seeded from Planner's
        # guess -- unchanged, pre-existing behavior.
        first_plan = spy_evidence.call_args_list[0][0][0]
        assert first_plan.target_files == ["planner_target.py"]
        # Second call: the fallback's own reacquisition, seeded from
        # STRATEGY's chosen target -- never Planner's original guess.
        second_plan = spy_evidence.call_args_list[1][0][0]
        assert second_plan.target_files == ["strategy_target.py"]
        assert second_plan.target_symbols == ["StrategyTarget"]

    def test_strategy_2_receives_baseline_evidence_union_fresh_evidence(self, tmp_path):
        """THE forensic regression test (scope-v4/authority-v1): Strategy
        #1 had full consumer/mechanism evidence (e.g. PoolManager.urlopen's
        source) and set target_authority_unresolved=True only because its
        OWN selected target's source was omitted by budget. The named-
        target reacquisition must not replace that consumer evidence with
        the newly-fetched target evidence -- Strategy #2 must receive
        BOTH. This test fails if the implementation reverts to passing
        `fresh.rendered` alone as Strategy #2's `planner_evidence_ctx`."""
        strategy_v1 = _strategy(
            evaluated=True, target_files=["retry.py"], target_symbols=["Retry"],
            target_authority_unresolved=True,
        )
        strategy_v2 = _strategy(evaluated=True, target_files=["retry.py"], target_symbols=["Retry"])
        baseline_evidence = _realistic_evidence_result(
            "PoolManager structural facts",
            [("poolmanager.py:PoolManager.urlopen", "def urlopen():\n    pass  # cross-origin stripping")],
        )
        fresh_evidence = _realistic_evidence_result(
            "Retry structural facts", [("retry.py:Retry", "class Retry:\n    DEFAULT = None")],
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["poolmanager.py", "retry.py"], target_symbols=["PoolManager.urlopen"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                side_effect=[baseline_evidence, fresh_evidence],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=[strategy_v1, strategy_v2],
            ) as spy_strategy,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_strategy.call_count == 2
        # Strategy #2's own call -- the second one.
        _, kwargs = spy_strategy.call_args_list[1]
        strategy_2_ctx = kwargs["planner_evidence_ctx"]
        assert "def urlopen():" in strategy_2_ctx, (
            "Strategy #1's own consumer evidence (PoolManager.urlopen) must survive into Strategy #2's prompt"
        )
        assert "class Retry:" in strategy_2_ctx, (
            "the newly-reacquired target evidence (Retry) must also be present"
        )

    def test_gap_resolved_after_reacquisition_reaches_final_target_slice(self, tmp_path):
        strategy_v1 = _strategy(
            evaluated=True, target_files=["target.py"], target_symbols=["Target"],
            target_authority_unresolved=True,
        )
        strategy_v2 = _strategy(
            evaluated=True, target_files=["target.py"], target_symbols=["Target"],
            target_authority_unresolved=False,
        )
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
            ),
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
        assert spy_strategy.call_count == 2
        mock_slice.assert_called_once()
        called_strategy = mock_slice.call_args[0][0]
        assert called_strategy.target_authority_unresolved is False

    def test_gap_remains_after_reacquisition_fails_closed_to_no_patch(self, tmp_path):
        """Strategy #2 STILL reports target_authority_unresolved=True --
        must not silently proceed with the still-doubted target. No third
        attempt is made (one-shot discipline)."""
        strategy_v1 = _strategy(
            evaluated=True, target_files=["target.py"], target_symbols=["Target"],
            target_authority_unresolved=True,
        )
        strategy_v2 = _strategy(
            evaluated=True, target_files=["target.py"], target_symbols=["Target"],
            target_authority_unresolved=True,
        )
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
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                side_effect=[strategy_v1, strategy_v2],
            ) as spy_strategy,
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_final_target_slice",
            ) as mock_slice,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_strategy.call_count == 2  # one-shot: never a third call
        mock_slice.assert_not_called()  # doubted target must never reach the slice builder

    def test_no_new_evidence_available_fails_closed_without_rerun(self, tmp_path):
        """Bounded reacquisition finds no new structural coverage at all --
        Strategy is never rerun, and the doubted Strategy #1 target must
        never be used to proceed."""
        strategy_v1 = _strategy(
            evaluated=True, target_files=["target.py"], target_symbols=["Target"],
            target_authority_unresolved=True,
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
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_final_target_slice",
            ) as mock_slice,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_strategy.call_count == 1  # never rerun -- no new evidence to justify it
        mock_slice.assert_not_called()

    def test_multi_target_mechanism_authority_gap_applies_at_strategy_level(self, tmp_path):
        """A multi-file/symbol Strategy result with target_authority_
        unresolved=True must skip Patch Generation for the WHOLE mechanism
        -- this field applies Strategy-level, not per-target; existing
        per-symbol existence verification is untouched by this feature."""
        strategy_v1 = _strategy(
            evaluated=True, target_files=["a.py", "b.py"], target_symbols=["A", "B"],
            target_authority_unresolved=True,
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["a.py", "b.py"], target_symbols=["A", "B"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("evidence", ["a.py:A", "b.py:B"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=strategy_v1,
            ) as spy_strategy,
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_final_target_slice",
            ) as mock_slice,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_strategy.call_count == 1  # no new evidence supplied -> no rerun
        mock_slice.assert_not_called()

    def test_nonexistent_target_verification_unaffected(self, tmp_path):
        """target_authority_unresolved never bypasses _verify_strategy_
        targets' own repository-existence check -- a Strategy response
        naming a file that does not resolve is dropped exactly as before,
        regardless of this field's value."""
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["target.py"], target_symbols=["Target"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=_evidence_result("evidence", ["target.py:Target"]),
            ),
        ):
            # Real (unmocked) generate_remediation_strategy call would
            # normally hit the LLM; here we only need _verify_strategy_
            # targets' own existence check, exercised directly.
            from utilities.autopatcher.remediation_planner import _verify_strategy_targets
            kept_files, kept_symbols, warnings, rejected = _verify_strategy_targets(
                ["does_not_exist.py"], ["DoesNotExist"], str(tmp_path), None,
            )
        assert kept_files == []
        assert kept_symbols == []
        assert warnings  # recorded as unverified, exactly as before this feature

    def test_merge_budget_exhausted_fails_closed_strategy_1_remains_load_bearing(self, tmp_path):
        """Final read-only QA fix, Case 5 (full-pipeline): the hard
        max_windows cap is reached before the merged (preserved + fresh)
        evidence fits -- Strategy #2 must never be called, Strategy #1's
        own result (target_authority_unresolved=True) remains the
        pipeline's only Strategy result, and Patch Generation stays
        blocked exactly like every other unresolved-authority outcome
        (see test_gap_remains_after_reacquisition_fails_closed_to_no_patch
        above for the equivalent "still unresolved after rerun" shape;
        this is the "never even reran" shape)."""
        from utilities.autopatcher.context_budget import ContextBudgetController

        strategy_v1 = _strategy(
            evaluated=True, target_files=["target.py"], target_symbols=["Target"],
            target_authority_unresolved=True,
        )
        baseline_evidence = _evidence_result("baseline evidence " * 20, ["other.py:Other"])
        fresh_evidence = _evidence_result("fresh evidence " * 20, ["target.py:Target"])
        budget_controller = ContextBudgetController(policy="always", max_windows=1)
        with (
            mock.patch("utilities.autopatcher.evidence_fusion.DEFAULT_MAX_CHARS", 10),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=_plan(target_files=["target.py"], target_symbols=["Target"]),
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                side_effect=[baseline_evidence, fresh_evidence],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=strategy_v1,
            ) as spy_strategy,
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_final_target_slice",
            ) as mock_slice,
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path),
                budget_controller=budget_controller,
            )
        assert spy_strategy.call_count == 1  # Strategy #2 never called -- budget exhausted first, never a third either
        mock_slice.assert_not_called()  # Patch Generation gate stays blocked


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
            additional_evidence_required="explicit_false",
        )
        plan_v2 = RemediationPlanResult(
            rendered="## Target Discovery Plan (revised)\n", target_files=["a.py"], target_symbols=["A"],
            additional_evidence_required="explicit_false",
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
