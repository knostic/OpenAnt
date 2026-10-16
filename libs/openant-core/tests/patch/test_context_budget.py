"""Tests for ContextBudgetController and its integration into Slices 2/3/4
(run_deterministic_acquisition/run_guided_acquisition/
recover_post_patch_source) -- Fix B: repository-evidence visibility is
bounded by the real per-call TECHNICAL capacity of the active model
(utilities.autopatcher.technical_capacity), never by an arbitrary,
stage-local "budget window" grown via a user policy. There is no more
policy ("ask"/"always"/"never") and no more window-growth mechanism --
`ContextBudgetController` now only caches the ONE real capacity decision
per stage per run and records it for the trace.

Section map:
    TestContextBudgetControllerCore        -- the controller in isolation
    TestDeterministicAcquisitionCapacity   -- Slice 2 integration
    TestGuidedAcquisitionCapacity          -- Slice 3 integration
    TestPostPatchRecoveryCapacity          -- Slice 4 integration
    TestBudgetTraceArtifact                -- structured trace shape
    TestNoResourceMeterByDefault           -- no arbitrary ceiling without a controller
    TestBudgetExtensionDoesNotBypassConformance
    TestRecommendationPolicyUnaffected     -- capacity never reaches trust signals
    TestRealWorldFailureShapeIntegration   -- the urllib3-run failure shape, now fixed by default
"""

from __future__ import annotations

import json
from unittest import mock



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


def _real_final_target_ceiling(vulnerability_text="", budget_controller=None):
    """The exact real technical-capacity ceiling `_effective_final_target_
    max` computes today, in this test environment -- computed via the SAME
    production function every test below exercises indirectly (never a
    hardcoded, environment-sensitive magic number)."""
    from utilities.autopatcher.remediation_planner import _effective_final_target_max
    return _effective_final_target_max(budget_controller, vulnerability_text)


# ---------------------------------------------------------------------------
# ContextBudgetController -- unit tests
# ---------------------------------------------------------------------------

class TestContextBudgetControllerCore:
    def test_request_extension_always_returns_false(self):
        """Fix B: there is no more window to grant -- effective_budget()
        already returns the stage's full real technical capacity on its
        very first call. request_extension() is a deprecated no-op, kept
        only so every pre-existing Slice 2/3/4 retry call site needs no
        signature changes."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController()
        assert c.request_extension("final_target_slice", 10_000, reason="x") is False

    def test_effective_budget_computed_once_and_cached(self):
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController()
        first = c.effective_budget("planner_evidence", known_overhead_chars=100)
        # A later call with DIFFERENT overhead must not change the cached
        # ceiling -- exactly one real capacity decision per stage per run.
        second = c.effective_budget("planner_evidence", known_overhead_chars=99_999)
        assert first == second

    def test_capacity_result_exposes_full_structured_decision(self):
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController()
        assert c.capacity_result("planner_evidence") is None  # never registered yet
        c.effective_budget("planner_evidence", known_overhead_chars=0)
        result = c.capacity_result("planner_evidence")
        assert result is not None
        assert result.source_capacity_chars == c.effective_budget("planner_evidence")

    def test_record_used_is_observability_only(self):
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController()
        c.record_used("final_target_slice", 500)  # no-op: stage never registered via effective_budget
        c.effective_budget("final_target_slice", known_overhead_chars=0)
        c.record_used("final_target_slice", 500)
        c.record_used("final_target_slice", 200)  # smaller -- must not shrink the recorded max
        trace = c.to_trace_dict()
        assert trace["stages"]["final_target_slice"]["used_chars"] == 500

    def test_legacy_policy_max_windows_kwargs_accepted_but_inert(self):
        """The pre-Fix-B constructor kwargs are still accepted (no
        TypeError for an unmigrated caller) but have zero effect."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        legacy = ContextBudgetController(policy="always", max_windows=1, interactive=True, confirm=lambda _p: False)
        plain = ContextBudgetController()
        assert legacy.effective_budget("planner_evidence") == plain.effective_budget("planner_evidence")

    def test_no_provider_model_falls_back_conservatively(self):
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.technical_capacity import CAPACITY_SOURCE_CONSERVATIVE_FALLBACK
        c = ContextBudgetController()
        c.effective_budget("planner_evidence")
        assert c.capacity_result("planner_evidence").capacity_source == CAPACITY_SOURCE_CONSERVATIVE_FALLBACK

    def test_stages_are_independent(self):
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController()
        a = c.effective_budget("planner_evidence", known_overhead_chars=0)
        b = c.effective_budget("final_target_slice", known_overhead_chars=0)
        # Different overhead assumptions per stage -> not necessarily
        # equal, but both must be real, positive technical ceilings.
        assert a > 0 and b > 0


# ---------------------------------------------------------------------------
# Slice 2 -- run_deterministic_acquisition integration
# ---------------------------------------------------------------------------

class TestDeterministicAcquisitionCapacity:
    def test_candidate_included_by_default_no_controller_needed(self, tmp_path):
        """The exact urllib3-shaped scenario: a small target blocked ONLY
        by an artificially exhausted shared pool is now included on the
        FIRST attempt, with no controller and no policy at all -- the
        real technical ceiling was never small to begin with."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].success is True
        final_readiness = check_edit_readiness([edit], result.slice_result)
        assert final_readiness.edit_source_ready is True

    def test_candidate_blocked_by_real_capacity_stays_blocked(self, tmp_path):
        """Fix B: once the real technical ceiling is exhausted, there is
        no more extension to request -- the candidate stays blocked for
        this call, with an explicit `target_budget_exhausted` reason,
        never a retry that magically succeeds."""
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
        controller = ContextBudgetController()
        ceiling = _real_final_target_ceiling(budget_controller=controller)
        initial_slice = _make_slice_result(rendered="x" * ceiling)  # the real ceiling, already fully consumed
        initial_readiness = check_edit_readiness([edit], initial_slice)

        result = run_deterministic_acquisition(
            strategy, str(tmp_path), context, initial_slice, initial_readiness, budget_controller=controller,
        )
        assert result.attempts[0].failure_reason == "target_budget_exhausted"
        assert result.attempts[0].success is False

    def test_no_controller_matches_controller_behavior(self, tmp_path):
        """budget_controller=None must compute the exact same real
        technical ceiling as an explicit controller -- "no controller"
        has never meant "no ceiling", and it never means "a smaller,
        arbitrary ceiling" either."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_deterministic_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        ceiling = _real_final_target_ceiling()
        initial_slice = _make_slice_result(rendered="x" * ceiling)
        initial_readiness = check_edit_readiness([edit], initial_slice)

        result_no_controller = run_deterministic_acquisition(
            strategy, str(tmp_path), context, initial_slice, initial_readiness,
        )
        assert result_no_controller.attempts[0].failure_reason == "target_budget_exhausted"

    def test_extension_never_bypasses_max_acquisition_rounds(self, tmp_path):
        """A symbol that never resolves (not a capacity problem) still
        stops at MAX_ACQUISITION_ROUNDS -- structural bounds are
        independent of technical capacity."""
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
        controller = ContextBudgetController()

        result = run_deterministic_acquisition(
            strategy, str(tmp_path), context, initial_slice, initial_readiness, budget_controller=controller,
        )
        assert result.rounds_used == rp.MAX_ACQUISITION_ROUNDS


# ---------------------------------------------------------------------------
# Slice 3 -- run_guided_acquisition integration
# ---------------------------------------------------------------------------

class TestGuidedAcquisitionCapacity:
    def test_ambiguous_retrieval_never_touches_capacity(self, tmp_path):
        """Resolution runs BEFORE capacity is even consulted -- an
        ambiguous symbol is rejected on its own reason, and the
        controller is never touched at all for this request."""
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
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": None, "symbol": "m",
            "identifier": None, "reason": "y",
        }]})
        controller = ContextBudgetController()

        result = run_guided_acquisition(
            strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        assert result.attempts[0].failure_reason == "ambiguous_symbol"
        assert controller.to_trace_dict()["stages"] == {}

    def test_unresolved_identifier_never_touches_capacity(self, tmp_path):
        from utilities.autopatcher.context_budget import ContextBudgetController
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("x = 1\n", encoding="utf-8")
        context = _make_context(repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"])
        edit = IntendedEdit(file="mod.py", symbol=None)
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        llm = _guided_llm({"context_requests": [{
            "request_type": "identifier_definition", "file_hint": "mod.py",
            "symbol": None, "identifier": "NoSuchIdentifier", "reason": "y",
        }]})
        controller = ContextBudgetController()

        result = run_guided_acquisition(
            strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness,
            budget_controller=controller,
        )
        assert result.attempts[0].failure_reason == "unresolved_identifier"
        assert controller.to_trace_dict()["stages"] == {}

    def test_resolved_candidate_included_by_default(self, tmp_path):
        """A request that resolves to a real, unambiguous location is
        included on the first attempt against the real technical ceiling
        -- no controller, no policy, no retry required."""
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, check_edit_readiness, run_guided_acquisition,
        )
        (tmp_path / "mod.py").write_text("CONST_A = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_A": {"qualified_name": "CONST_A", "class_name": None, "name": "CONST_A", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        strategy = _make_strategy(target_files=["mod.py"], target_symbols=["mod.py:CONST_A"])
        edit = IntendedEdit(file="mod.py", symbol="mod.py:CONST_A")
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)
        llm = _guided_llm({"context_requests": [{
            "request_type": "symbol_definition", "file_hint": "mod.py", "symbol": "mod.py:CONST_A",
            "identifier": None, "reason": "need exact source",
        }]})

        result = run_guided_acquisition(
            strategy, "vuln", llm, str(tmp_path), context, initial_slice, initial_readiness,
        )
        assert result.attempts[0].verified is True
        assert result.attempts[0].readiness_improved is True
        assert result.readiness.edit_source_ready is True
        assert llm.complete.call_count == 1


# ---------------------------------------------------------------------------
# Slice 4 -- recover_post_patch_source integration
# ---------------------------------------------------------------------------

class TestPostPatchRecoveryCapacity:
    def test_recovery_included_by_default(self, tmp_path):
        from utilities.autopatcher import remediation_planner as rp

        (tmp_path / "mod.py").write_text("CONST_B = 42\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = _make_conformance(edited_files=["mod.py"], unexpected_files=["mod.py"])
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_B = 42\n+CONST_B = 43\n"
        initial_slice = _make_slice_result()

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, initial_slice, conformance, patch,
        )
        assert result.attempts[0].success is True
        assert result.ready_for_regeneration is True

    def test_recovery_capped_at_three_targets_regardless_of_capacity(self, tmp_path):
        """too_many_recovery_targets is a non-capacity, structural cap --
        no capacity decision is ever consulted."""
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController

        files = [f"f{i}.py" for i in range(4)]
        conformance = _make_conformance(edited_files=files, unexpected_files=files)
        controller = ContextBudgetController()

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), _make_context(repo_path=tmp_path),
            _make_slice_result(), conformance, "", budget_controller=controller,
        )
        assert result.failure_reason == "too_many_recovery_targets"
        assert controller.to_trace_dict()["stages"] == {}

    def test_target_blocked_by_real_capacity_stays_blocked(self, tmp_path):
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.context_budget import ContextBudgetController

        (tmp_path / "mod.py").write_text("CONST_B = 42\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = _make_conformance(edited_files=["mod.py"], unexpected_files=["mod.py"])
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_B = 42\n+CONST_B = 43\n"
        controller = ContextBudgetController()
        ceiling = _real_final_target_ceiling(budget_controller=controller)
        initial_slice = _make_slice_result(rendered="x" * ceiling)

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, initial_slice, conformance, patch,
            budget_controller=controller,
        )
        assert result.attempts[0].failure_reason == "target_budget_exhausted"


# ---------------------------------------------------------------------------
# A successful recovery must never bypass Patch Target Conformance / the
# Recommendation Policy -- capacity only ever supplies MORE EVIDENCE, never
# a shortcut past either gate.
# ---------------------------------------------------------------------------

class TestBudgetExtensionDoesNotBypassConformance:
    def test_check_patch_target_conformance_source_never_mentions_budget_terms(self):
        import inspect
        from utilities.autopatcher.remediation_planner import check_patch_target_conformance
        source = inspect.getsource(check_patch_target_conformance)
        for term in ("budget_controller", "context_budget", "ContextBudgetController", "_extend_post_patch_budget"):
            assert term not in source

    def test_recovered_evidence_does_not_make_an_out_of_scope_regenerated_patch_conformant(self, tmp_path):
        from utilities.autopatcher import remediation_planner as rp
        from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers
        from utilities.autopatcher.remediation_planner import (
            IntendedEdit, ReadyEdit, check_patch_target_conformance,
        )

        (tmp_path / "mod.py").write_text("CONST_B = 42\n", encoding="utf-8")
        (tmp_path / "other.py").write_text("X = 1\n", encoding="utf-8")
        context = _make_context(constants={"mod.py": {
            "CONST_B": {"qualified_name": "CONST_B", "class_name": None, "name": "CONST_B", "line": 1, "end_line": 1},
        }}, repo_path=tmp_path)
        conformance = _make_conformance(edited_files=["mod.py"], unexpected_files=["mod.py"])
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_B = 42\n+CONST_B = 43\n"

        result = rp.recover_post_patch_source(
            _make_strategy(), str(tmp_path), context, _make_slice_result(), conformance, patch,
        )
        assert result.attempts[0].success is True  # recovered normally

        ready_edits = [ReadyEdit(
            edit=IntendedEdit(file="mod.py", symbol="mod.py:CONST_B"),
            role="edit_target", file="mod.py", symbol="mod.py:CONST_B",
        )]
        out_of_scope_patch = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"
        out_of_scope_patch, meta = repair_hunk_headers(out_of_scope_patch, repo_root=tmp_path)

        report = check_patch_target_conformance(
            out_of_scope_patch, meta.relocations, ready_edits, result.slice_result,
        )
        assert report.all_conformant is False
        assert report.unexpected_files == ["other.py"]


# ---------------------------------------------------------------------------
# Structured trace
# ---------------------------------------------------------------------------

class TestBudgetTraceArtifact:
    def test_trace_records_capacity_source_and_provenance(self):
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController()
        c.effective_budget("final_target_slice", known_overhead_chars=100)
        stage = c.to_trace_dict()["stages"]["final_target_slice"]
        for key in (
            "source_capacity_chars", "capacity_source", "context_window_tokens",
            "reserved_output_tokens", "safety_margin_tokens", "chars_per_token_ratio",
            "known_overhead_chars", "capacity_is_approximate", "used_chars",
        ):
            assert key in stage

    def test_trace_includes_provider_and_model(self):
        from utilities.autopatcher.context_budget import ContextBudgetController
        c = ContextBudgetController(provider="anthropic", model="claude-sonnet-5")
        trace = c.to_trace_dict()
        assert trace["provider"] == "anthropic"
        assert trace["model"] == "claude-sonnet-5"


# ---------------------------------------------------------------------------
# No resource meter by default -- Fix B's central invariant
# ---------------------------------------------------------------------------

class TestNoResourceMeterByDefault:
    def test_no_controller_never_reads_stdin(self, tmp_path, monkeypatch):
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
        initial_slice = _make_slice_result()
        initial_readiness = check_edit_readiness([edit], initial_slice)

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)
        assert result.attempts[0].success is True

    def test_default_run_has_no_arbitrary_window_ceiling(self):
        """The historical 4,000/10,000/6,000-character constants no
        longer control the ceiling AT ALL -- even absent any controller,
        the real technical ceiling is orders of magnitude larger."""
        from utilities.autopatcher import remediation_planner as rp
        ceiling = _real_final_target_ceiling()
        assert ceiling > rp.FINAL_TARGET_SLICE_MAX_CHARS * 5

    def test_legacy_cli_flags_cannot_restore_old_window_behavior(self):
        """Passing the deprecated policy/max_windows kwargs -- exactly
        what the old --context-budget-policy/--max-context-budget-windows
        CLI flags used to construct -- must not shrink the ceiling back to
        the old arbitrary constants."""
        from utilities.autopatcher.context_budget import ContextBudgetController
        legacy = ContextBudgetController(policy="never", max_windows=1)
        ceiling = _real_final_target_ceiling(budget_controller=legacy)
        from utilities.autopatcher import remediation_planner as rp
        assert ceiling > rp.FINAL_TARGET_SLICE_MAX_CHARS


# ---------------------------------------------------------------------------
# Recommendation Policy independence
# ---------------------------------------------------------------------------

class TestRecommendationPolicyUnaffected:
    def test_recommendation_policy_source_never_mentions_budget_terms(self):
        import inspect
        from utilities.autopatcher.pipeline import _build_recommendation_v1
        source = inspect.getsource(_build_recommendation_v1)
        for term in (
            "budget_controller", "context_budget", "ContextBudgetController",
            "final_target_slice", "technical_capacity",
        ):
            assert term not in source


# ---------------------------------------------------------------------------
# The real-world failure shape (generic reproduction)
# ---------------------------------------------------------------------------

class TestRealWorldFailureShapeIntegration:
    def test_second_target_blocked_only_by_old_arbitrary_ceiling_now_included_by_default(self, tmp_path):
        """Matches the observed urllib3 run: one intended edit already
        consumes part of the initial context; a second, file-level target
        would have been blocked under the OLD 10,000-character ceiling.
        Under Fix B this is included by default -- no controller, no
        policy, no extension needed -- because the real technical ceiling
        was never artificially small to begin with."""
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

        initial_slice = _make_slice_result(
            covered_target_symbols=["ready.py:CONST_READY"],
            resolved_target_symbols=["ready.py:CONST_READY"],
        )
        initial_readiness = check_edit_readiness([edit_ready, edit_unready], initial_slice)
        assert initial_readiness.edit_source_ready is False
        assert any(u.edit == edit_unready for u in initial_readiness.unready_edits)

        result = run_deterministic_acquisition(strategy, str(tmp_path), context, initial_slice, initial_readiness)

        final_readiness = check_edit_readiness([edit_ready, edit_unready], result.slice_result)
        assert final_readiness.edit_source_ready is True
        assert "target.py" in result.slice_result.identifier_definition_covered
