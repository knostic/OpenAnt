"""Tests for ContextBudgetController and its integration into Slices 2/3/4
(run_deterministic_acquisition/run_guided_acquisition/
recover_post_patch_source) -- user-approved, fixed-size context-budget
window extensions for a run otherwise blocked purely by character
capacity.

Section map:
    TestContextBudgetControllerCore       -- the controller in isolation
    TestDeterministicAcquisitionExtension -- Slice 2 integration
    TestGuidedAcquisitionExtension        -- Slice 3 integration
    TestPostPatchRecoveryExtension        -- Slice 4 integration
    TestBudgetTraceArtifact               -- structured trace shape
    TestLibraryUseNeverPrompts            -- no controller == policy "never"
    TestRecommendationPolicyUnaffected    -- budget never reaches trust signals
    TestRealWorldFailureShapeIntegration  -- the urllib3-run failure shape
"""

from __future__ import annotations

import json
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Shared fixtures -- mirror test_remediation_planner.py's own helpers
# exactly (kept local, not cross-imported, per this repo's existing
# per-test-file convention).
# ---------------------------------------------------------------------------

def _make_context(functions=None, constants=None, repo_path=None):
    from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.autopatcher.candidate_enrichment import InvestigationContext

    functions = functions or {}
    index = RepositoryIndex({"functions": functions}, repo_path=str(repo_path) if repo_path else None)
    reachability = ReachabilityAnalyzer(functions, {}, set())
    return InvestigationContext(
        index=index, call_graph={}, reverse_call_graph={},
        reachability=reachability, constants=constants or {},
    )


def _make_strategy(target_files=None, target_symbols=None, extended_mechanism=None, required_edits=None):
    from utilities.autopatcher.remediation_planner import RemediationStrategyResult
    return RemediationStrategyResult(
        rendered="", target_files=target_files or [], target_symbols=target_symbols or [],
        warnings=[], extended_mechanism=extended_mechanism, required_edits=required_edits or [],
    )


def _make_slice_result(**overrides):
    from utilities.autopatcher.remediation_planner import FinalTargetSliceResult
    base = dict(
        rendered="", covered_target_files=[], covered_target_symbols=[],
        uncovered_target_files=[], uncovered_target_symbols=[],
        coverage_complete=False, has_any_coverage=False, warning_text="",
        resolved_target_symbols=[], full_file_fallback_covered=[],
        edit_target_budget_exhausted=False,
        resolved_symbol_files={}, identifier_definition_covered=[],
    )
    base.update(overrides)
    return FinalTargetSliceResult(**base)


def _guided_llm(response_obj):
    llm = mock.MagicMock()
    llm.complete.return_value = json.dumps(response_obj)
    return llm


def _make_conformance(**overrides):
    from utilities.autopatcher.remediation_planner import PatchConformanceReport
    base = dict(results=[], all_conformant=False, edited_files=[], unexpected_files=[],
                uncovered_files=[], no_match_files=[])
    base.update(overrides)
    return PatchConformanceReport(**base)


# ---------------------------------------------------------------------------
# ContextBudgetController -- unit tests
# ---------------------------------------------------------------------------

class TestContextBudgetControllerCore:
    def test_never_declines_and_records(self):
        """Test 1: policy="never" preserves fail-closed behavior --
        request_extension always returns False, and never touches stdin."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="never", interactive=True)
        approved = c.request_extension("final_target_slice", 10_000, reason="target_budget_exhausted")
        assert approved is False
        assert c.effective_budget("final_target_slice", 10_000) == 10_000
        trace = c.to_trace_dict()
        assert trace["stages"]["final_target_slice"]["extension_requests"][0]["decision_source"] == "policy_never"

    def test_always_adds_one_equal_sized_window(self):
        """Test 2: policy="always" adds exactly one window of the SAME
        size passed in, non-interactively."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="always", interactive=False)
        approved = c.request_extension("final_target_slice", 10_000, reason="target_budget_exhausted")
        assert approved is True
        assert c.effective_budget("final_target_slice", 10_000) == 20_000

    def test_multiple_extensions_are_additive_not_exponential(self):
        """Test 3: 10K -> 20K -> 30K, never 10K -> 20K -> 40K."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="always", interactive=False)
        for _ in range(3):
            c.request_extension("final_target_slice", 10_000, reason="target_budget_exhausted")
        assert c.effective_budget("final_target_slice", 10_000) == 40_000  # 1 initial + 3 approved windows

    def test_always_stops_at_configured_hard_maximum(self):
        """Test 4."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="always", max_windows=3, interactive=False)
        results = [
            c.request_extension("final_target_slice", 10_000, reason="target_budget_exhausted")
            for _ in range(5)
        ]
        assert results == [True, True, False, False, False]
        assert c.effective_budget("final_target_slice", 10_000) == 30_000  # 1 initial + 2 approved = 3 windows total
        last_request = c.to_trace_dict()["stages"]["final_target_slice"]["extension_requests"][-1]
        assert last_request["decision_source"] == "hard_budget_window_limit_reached"
        assert last_request["approved"] is False

    def test_ask_approval_adds_one_window(self):
        """Test 5."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="ask", interactive=True, confirm=lambda _prompt: True)
        approved = c.request_extension("final_target_slice", 10_000, reason="target_budget_exhausted")
        assert approved is True
        assert c.effective_budget("final_target_slice", 10_000) == 20_000

    def test_ask_decline_fails_closed(self):
        """Test 6."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="ask", interactive=True, confirm=lambda _prompt: False)
        approved = c.request_extension("final_target_slice", 10_000, reason="target_budget_exhausted")
        assert approved is False
        assert c.effective_budget("final_target_slice", 10_000) == 10_000

    def test_ask_default_is_no_on_empty_input(self):
        """Default answer must be No -- the built-in confirm treats a bare
        Enter (empty string) as decline, never accept."""
        from utilities.autopatcher.context_budget import _default_confirm
        with mock.patch("sys.stdin") as fake_stdin:
            fake_stdin.readline.return_value = "\n"
            assert _default_confirm("prompt? ") is False

    def test_ask_in_non_tty_environment_does_not_block_and_behaves_as_never(self):
        """Test 7: non-interactive "ask" never calls the confirm callback
        (never touches stdin) and is recorded, not silently guessed."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        confirm = mock.Mock(return_value=True)
        c = ContextBudgetController(policy="ask", interactive=False, confirm=confirm)
        approved = c.request_extension("final_target_slice", 10_000, reason="target_budget_exhausted")
        assert approved is False
        confirm.assert_not_called()
        record = c.to_trace_dict()["stages"]["final_target_slice"]["extension_requests"][0]
        assert record["decision_source"] == "non_interactive_fallback"

    def test_invalid_policy_rejected(self):
        from utilities.autopatcher.context_budget import ContextBudgetController
        with pytest.raises(ValueError):
            ContextBudgetController(policy="sometimes")

    @pytest.mark.parametrize("bad_value", [0, -1, 1.5, "10", True])
    def test_max_windows_must_be_a_positive_integer(self, bad_value):
        """No unbounded sentinel accepted -- 0/negative/non-int/bool all rejected."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        with pytest.raises(ValueError):
            ContextBudgetController(policy="always", max_windows=bad_value)

    def test_stage_specific_window_sizes_are_preserved(self):
        """Test 15: two different stages keep their own distinct window
        sizes -- extending one never changes the other's."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="always", interactive=False)
        c.request_extension("final_target_slice", 10_000, reason="target_budget_exhausted")
        c.request_extension("post_patch_recovery", 6_000, reason="target_budget_exhausted")
        assert c.effective_budget("final_target_slice", 10_000) == 20_000
        assert c.effective_budget("post_patch_recovery", 6_000) == 12_000

    def test_effective_budget_and_used_remaining_are_correct(self):
        """Test 16."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="always", interactive=False)
        c.effective_budget("final_target_slice", 10_000)  # registers the stage
        c.record_used("final_target_slice", 7_500)
        c.request_extension("final_target_slice", 10_000, reason="target_budget_exhausted")
        state = c.to_trace_dict()["stages"]["final_target_slice"]
        assert state["effective_budget"] == 20_000
        assert state["used_chars"] == 7_500
        assert state["remaining_chars"] == 12_500

    def test_no_extension_needed_case_is_not_recorded(self):
        """No spurious extension_requests entry when request_extension is
        never called at all (the common, non-exhausted case)."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="always", interactive=False)
        c.effective_budget("final_target_slice", 10_000)
        assert c.to_trace_dict()["stages"]["final_target_slice"]["extension_requests"] == []

    def test_trace_records_policy_and_interactive_flags(self):
        """Test 17 (partial): top-level trace fields."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(policy="ask", max_windows=7, interactive=False)
        trace = c.to_trace_dict()
        assert trace["policy"] == "ask"
        assert trace["interactive"] is False
        assert trace["max_windows"] == 7


# ---------------------------------------------------------------------------
# Slice 2 -- run_deterministic_acquisition integration
# ---------------------------------------------------------------------------

class TestDeterministicAcquisitionExtension:
    def test_never_preserves_existing_fail_closed_behavior(self, tmp_path):
        """Test 1 (integration) + Test 19: an explicit policy="never"
        controller must behave IDENTICALLY to passing no controller at
        all for the pre-existing total-budget-exhaustion scenario."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)

        result_no_controller = run_deterministic_acquisition(
            strategy, str(tmp_path), context, initial_slice, initial_readiness,
        )
        controller = ContextBudgetController(policy="never", interactive=False)
        result_never = run_deterministic_acquisition(
            strategy, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        for result in (result_no_controller, result_never):
            assert result.attempts[0].failure_reason == "target_budget_exhausted"
            assert len(result.slice_result.rendered) == rp.FINAL_TARGET_SLICE_MAX_CHARS

    def test_always_extends_and_retries_the_blocked_candidate(self, tmp_path):
        """Test 2 (integration) + Test 10: a candidate blocked SOLELY by
        the shared total budget is retried immediately after approval and
        becomes ready -- no second round, no Planner/Strategy rerun."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")

        # The shared total is already fully consumed by prior (unrelated,
        # already-committed) content -- exactly the observed real-run shape.
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)
        controller = ContextBudgetController(policy="always", interactive=False)

        result = run_deterministic_acquisition(
            strategy, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )

        assert result.attempts[0].success is True
        assert result.rounds_used == 1  # exactly one round -- no restart
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is True
        # Test 8: the previously-committed content is still present.
        assert "x" * 100 in result.slice_result.rendered
        assert controller.to_trace_dict()["stages"]["final_target_slice"]["approved_windows"] == 1

    def test_ask_decline_fails_closed_for_deterministic_acquisition(self, tmp_path):
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)
        controller = ContextBudgetController(policy="ask", interactive=True, confirm=lambda _p: False)

        result = run_deterministic_acquisition(
            strategy, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        assert result.attempts[0].failure_reason == "target_budget_exhausted"
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is False

    def test_extension_never_bypasses_max_acquisition_rounds(self, tmp_path):
        """Test 14: a symbol that never resolves (not a budget problem)
        still stops at MAX_ACQUISITION_ROUNDS, even with policy="always"."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
        context = _make_context(repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:NoSuchSymbol"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:NoSuchSymbol")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        controller = ContextBudgetController(policy="always", interactive=False)

        result = run_deterministic_acquisition(
            strategy, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        assert result.rounds_used == rp.MAX_ACQUISITION_ROUNDS
        # Never a budget problem -- no extension was ever REQUESTED (the
        # stage is registered for observability the moment the effective
        # ceiling is even read, but request_extension() itself is only
        # called when `available <= 0` or a "target_budget_exhausted"
        # attempt reason actually occurs -- neither happens here).
        assert controller.to_trace_dict()["stages"]["final_target_slice"]["extension_requests"] == []


# ---------------------------------------------------------------------------
# Slice 3 -- run_guided_acquisition integration
# ---------------------------------------------------------------------------

class TestGuidedAcquisitionExtension:
    def test_ambiguous_retrieval_never_prompts_for_more_budget(self, tmp_path):
        """Test 12: resolution runs BEFORE the budget is even consulted --
        an ambiguous symbol is rejected on its own reason, and no
        extension is ever requested, regardless of budget state."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "a.py").write_text("def m():\n    return 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("def m():\n    return 2\n", encoding="utf-8")
        context = _make_context(functions={
            "a.py:m": {"name": "m", "className": None, "startLine": 1, "endLine": 2, "code": "def m():\n    return 1\n"},
            "b.py:m": {"name": "m", "className": None, "startLine": 1, "endLine": 2, "code": "def m():\n    return 2\n"},
        }, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["a.py"], target_symbols=["a.py:m"])
        edit = IntendedEdit(file="a.py", symbol="a.py:m")
        # Budget already fully exhausted too -- must not matter: resolution
        # fails first, on its own non-budget reason.
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)
        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": None, "symbol": "m",
            "identifier": None, "reason": "y",
        }]})
        controller = ContextBudgetController(policy="always", interactive=False)

        result = run_guided_acquisition(
            strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        assert result.attempts[0].failure_reason == "ambiguous_symbol"
        # Resolution is rejected BEFORE the budget is even read -- the
        # controller was never touched at all for this request.
        assert controller.to_trace_dict()["stages"] == {}

    def test_unresolved_identifier_never_prompts_for_more_budget(self, tmp_path):
        """Test 13: a request that resolves to nothing at all is rejected
        on its own reason, never as a budget problem."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
        context = _make_context(repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"])
        edit = IntendedEdit(file="mod.py", symbol=None)
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)
        llm = _guided_llm({"context_requests": [{
            "request_type": "identifier_definition", "file_hint": "mod.py",
            "symbol": None, "identifier": "NoSuchIdentifier", "reason": "y",
        }]})
        controller = ContextBudgetController(policy="always", interactive=False)

        result = run_guided_acquisition(
            strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        assert result.attempts[0].failure_reason == "unresolved_identifier"
        assert controller.to_trace_dict()["stages"] == {}

    def test_budget_blocked_resolved_candidate_is_retried_after_approval(self, tmp_path):
        """Test 5 (integration) + Test 10: a request that has ALREADY
        resolved to a real, unambiguous location, and is blocked only by
        the shared total, gets one immediate retry once approved."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)
        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:CONST_A",
            "identifier": None, "reason": "need exact source",
        }]})
        controller = ContextBudgetController(policy="always", interactive=False)

        result = run_guided_acquisition(
            strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        assert result.attempts[0].verified is True
        assert result.attempts[0].readiness_improved is True
        assert result.readiness.edit_source_ready is True
        # Test 9: the LLM (Planner/Strategy-equivalent call here) is
        # never re-invoked by the retry -- exactly one call.
        assert llm.complete.call_count == 1

    def test_ask_decline_fails_closed_for_guided_acquisition(self, tmp_path):
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)
        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:CONST_A",
            "identifier": None, "reason": "need exact source",
        }]})
        controller = ContextBudgetController(policy="ask", interactive=True, confirm=lambda _p: False)

        result = run_guided_acquisition(
            strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        assert result.readiness.edit_source_ready is False
        assert result.attempts[0].failure_reason == "target_budget_exhausted"

    def test_budget_blocked_request_does_not_permanently_consume_request_allowance(self, tmp_path):
        """Test 11: MAX_CONTEXT_REQUESTS_PER_EDIT must count this as
        exactly ONE request for the edit -- the internal retry is not a
        second, separate request."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)
        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:CONST_A",
            "identifier": None, "reason": "need exact source",
        }]})
        controller = ContextBudgetController(policy="always", interactive=False, max_windows=2)

        result = run_guided_acquisition(
            strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        # Exactly one GuidedRetrievalAttempt was recorded for this request
        # -- the internal budget retry did not fabricate a second one, and
        # MAX_CONTEXT_REQUESTS_PER_EDIT (2) was never exhausted by it.
        assert len(result.attempts) == 1
        assert result.readiness.edit_source_ready is True


# ---------------------------------------------------------------------------
# Slice 4 -- recover_post_patch_source integration
# ---------------------------------------------------------------------------

class TestPostPatchRecoveryExtension:
    def test_never_preserves_existing_fail_closed_behavior(self, tmp_path):
        from utilities.autopatcher import remediation_planner as rp

        (tmp_path / "mod.py").write_text("CONST_B = 42\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = _make_conformance(edited_files=["mod.py"], unexpected_files=["mod.py"])
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_B = 42\n+CONST_B = 43\n"
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, initial_slice, conformance, patch,
        )
        assert result.attempts[0].failure_reason == "target_budget_exhausted"

    def test_always_extends_and_retries_the_blocked_recovery_target(self, tmp_path):
        """Test 2 (integration): the shared total is exhausted by prior
        content; approval raises the ceiling and the (small) recovery
        target is retrieved and succeeds."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController

        (tmp_path / "mod.py").write_text("CONST_B = 42\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = _make_conformance(edited_files=["mod.py"], unexpected_files=["mod.py"])
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_B = 42\n+CONST_B = 43\n"
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        controller = ContextBudgetController(policy="always", interactive=False)

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, initial_slice, conformance, patch,
            budget_controller=controller,
        )
        assert result.attempts[0].success is True
        assert result.ready_for_regeneration is True
        assert "x" * 100 in result.slice_result.rendered  # Test 8
        trace = controller.to_trace_dict()["stages"]
        assert trace["final_target_slice"]["approved_windows"] == 1

    def test_recovery_capped_at_three_targets_regardless_of_policy(self, tmp_path):
        """Test 14: too_many_recovery_targets is a non-budget, structural
        cap -- an extension is never even offered."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController

        files = [f"f{i}.py" for i in range(4)]
        conformance = _make_conformance(edited_files=files, unexpected_files=files)
        controller = ContextBudgetController(policy="always", interactive=False)

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), _make_context(repo_path=tmp_path),
            _make_slice_result(), conformance, "", budget_controller=controller,
        )
        assert result.failure_reason == "too_many_recovery_targets"
        assert controller.to_trace_dict()["stages"] == {}


# ---------------------------------------------------------------------------
# Structured trace
# ---------------------------------------------------------------------------

class TestBudgetTraceArtifact:
    def test_trace_records_approval_decline_and_hard_cap(self):
        """Test 17."""
        from utilities.autopatcher.context_budget import ContextBudgetController

        approve_ctl = ContextBudgetController(policy="always", max_windows=1, interactive=False)
        approve_ctl.request_extension("s", 100, reason="target_budget_exhausted")  # hits max immediately
        assert approve_ctl.to_trace_dict()["stages"]["s"]["extension_requests"][0]["decision_source"] in (
            "hard_budget_window_limit_reached",
        )

        decline_ctl = ContextBudgetController(policy="ask", interactive=True, confirm=lambda _p: False)
        decline_ctl.request_extension("s", 100, reason="target_budget_exhausted")
        rec = decline_ctl.to_trace_dict()["stages"]["s"]["extension_requests"][0]
        assert rec["approved"] is False and rec["decision_source"] == "interactive_user"

        fallback_ctl = ContextBudgetController(policy="ask", interactive=False)
        fallback_ctl.request_extension("s", 100, reason="target_budget_exhausted")
        rec = fallback_ctl.to_trace_dict()["stages"]["s"]["extension_requests"][0]
        assert rec["decision_source"] == "non_interactive_fallback"


# ---------------------------------------------------------------------------
# Library use -- no controller supplied
# ---------------------------------------------------------------------------

class TestLibraryUseNeverPrompts:
    def test_no_controller_never_reads_stdin(self, tmp_path, monkeypatch):
        """Test 18: budget_controller=None (every existing/library
        caller) must never attempt an interactive prompt."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )

        def _boom(*_a, **_kw):
            raise AssertionError("must never read stdin in library use")

        monkeypatch.setattr("sys.stdin.readline", _boom)

        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result(rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS)
        initial_readiness = check_edit_readiness([edit], initial_slice)

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].failure_reason == "target_budget_exhausted"


# ---------------------------------------------------------------------------
# Recommendation Policy independence
# ---------------------------------------------------------------------------

class TestRecommendationPolicyUnaffected:
    def test_recommendation_policy_source_never_mentions_budget_terms(self):
        """Test 20: extending _build_recommendation_v1 in Slices 2/3/4's
        own acquisition/recovery loops must never leak into the trust-
        signal/recommendation logic."""
        import inspect
        from utilities.autopatcher.pipeline import _build_recommendation_v1
        source = inspect.getsource(_build_recommendation_v1)
        for term in ("budget_controller", "context_budget", "ContextBudgetController", "final_target_slice"):
            assert term not in source


# ---------------------------------------------------------------------------
# The real-world failure shape (generic reproduction)
# ---------------------------------------------------------------------------

class TestRealWorldFailureShapeIntegration:
    def test_second_target_blocked_only_by_total_budget_is_recovered_with_always(self, tmp_path):
        """Matches the observed urllib3 run: one intended edit already
        consumes part of the initial context; a second, file-level target
        is blocked only by the total source budget; policy="always"
        grants another equal-sized window; the second target is
        retrieved and becomes ready -- Patch Generation is no longer
        skipped for budget exhaustion alone."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )

        (tmp_path / "target.py").write_text(
            "class Policy:\n    ALLOWED_VALUES = frozenset(['a'])\n", encoding="utf-8",
        )
        context = _make_context(constants={"target.py": {
            "Policy.ALLOWED_VALUES": {
                "qualified_name": "Policy.ALLOWED_VALUES", "class_name": "Policy",
                "name": "ALLOWED_VALUES", "line": 2, "end_line": 2,
            },
        }}, repo_path=tmp_path)
        strategy = _make_strategy(
            target_files=["ready.py", "target.py"], target_symbols=["ready.py:CONST_READY"],
            extended_mechanism="Policy.ALLOWED_VALUES",
        )
        edit_ready = IntendedEdit(file="ready.py", symbol="ready.py:CONST_READY")
        edit_unready = IntendedEdit(file="target.py", symbol=None)

        # edit_ready already satisfied and its (placeholder, real-sized)
        # source already consumed nearly the entire shared total -- the
        # exact shape of the observed real run.
        initial_slice = _make_slice_result(
            rendered="x" * rp.FINAL_TARGET_SLICE_MAX_CHARS,
            covered_target_symbols=["ready.py:CONST_READY"],
            resolved_target_symbols=["ready.py:CONST_READY"],
        )
        initial_readiness = check_edit_readiness([edit_ready, edit_unready], initial_slice)
        assert initial_readiness.edit_source_ready is False
        assert any(u.edit == edit_unready for u in initial_readiness.unready_edits)

        controller = ContextBudgetController(policy="always", interactive=False)
        result = run_deterministic_acquisition(
            strategy, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )

        final_readiness = check_edit_readiness([edit_ready, edit_unready], result.slice_result)
        assert final_readiness.edit_source_ready is True
        assert "target.py" in result.slice_result.identifier_definition_covered
        # The originally-ready edit's own committed source is untouched.
        assert "x" * 100 in result.slice_result.rendered
        assert controller.to_trace_dict()["stages"]["final_target_slice"]["approved_windows"] == 1
