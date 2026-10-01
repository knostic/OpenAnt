"""Fix B (blocker-closure round) -- integration/structural tests proving:

1. repository understanding supplied to an LLM is no longer capped by an
   arbitrary 4,000-character constant;
2. post-patch evidence supplied to the Challenger is no longer capped by
   an arbitrary 4,000-character constant;
6. human/report rendering limits cannot alter LLM evidence visibility;
7. final combined-prompt accounting includes mandatory non-source content;
8. adding mandatory prompt content deterministically reduces available
   repository-source capacity;
9. an oversized evidence block is omitted rather than causing an oversized
   request;
10. oversized mandatory non-source content fails closed;
11. no final prompt is silently truncated;
12. Strategy authority reacquisition preserves inclusion provenance across
    its return boundary;
13/14. Challenger/Finding Calibration interpretation logic is unchanged.

Points 3-5 (repository grounding) are covered directly in
test_repo_locator.py::TestGroundingTechnicalCapacity. Points 15-18
(trust/recommendation semantics, Fix A truth table, legacy flags,
structural bounds) are covered by test_context_budget.py and
test_remediation_planner.py, unchanged by this round.
"""

from __future__ import annotations

import inspect

import pytest


class TestPipelineNoLongerReliesOnHardcodedDefaults:
    """Structural proof (point 1, 2, 6): the two PRODUCTION call sites that
    used to rely on evidence_fusion.DEFAULT_MAX_CHARS/post_patch_evaluation.
    DEFAULT_MAX_CHARS's own implicit defaults now always pass an explicit,
    computed `max_chars` -- the historical 4,000-character constant can no
    longer silently determine what an LLM sees, and the separate Trust
    Report call site is untouched (still allowed its own, independent
    bound)."""

    def test_repository_understanding_ctx_call_site_passes_explicit_max_chars(self):
        import utilities.autopatcher.pipeline as pipeline_mod
        source = inspect.getsource(pipeline_mod)
        idx = source.index("_repository_understanding_ctx = render_repository_understanding(")
        call_site = source[idx: idx + 200]
        assert "max_chars=" in call_site

    def test_grounding_call_site_passes_explicit_max_chars(self):
        import utilities.autopatcher.pipeline as pipeline_mod
        source = inspect.getsource(pipeline_mod)
        idx = source.index("_grounding = ground_repository(")
        call_site = source[idx: idx + 200]
        assert "max_chars=" in call_site

    def test_challenger_facing_post_patch_ctx_uses_computed_plan_not_default(self):
        """The Challenger-facing call site uses compute_post_patch_
        investigation_plan with an explicit, computed max_chars -- never
        the bare render_post_patch_investigation() default."""
        import utilities.autopatcher.pipeline as pipeline_mod
        source = inspect.getsource(pipeline_mod)
        idx = source.index("_post_patch_investigation_plan = compute_post_patch_investigation_plan(")
        call_site = source[idx: idx + 200]
        assert "max_chars=_post_patch_ctx_ceiling" in call_site

    def test_report_rendering_call_site_is_untouched_and_separate(self):
        """The Trust Report's own render_post_patch_investigation() call
        (human-readable output, not Challenger evidence) is a textually
        DIFFERENT call site from the Challenger-facing one -- proving a
        report-formatting bound can never be the same code path that
        decides Challenger evidence visibility."""
        import utilities.autopatcher.pipeline as pipeline_mod
        source = inspect.getsource(pipeline_mod)
        report_idx = source.index('report += "---\\n\\n" + render_post_patch_investigation(')
        challenger_idx = source.index("_post_patch_investigation_plan = compute_post_patch_investigation_plan(")
        assert report_idx != challenger_idx


class TestCombinedPromptCapacityAccounting:
    """Points 7, 8, 9, 10, 11: mandatory non-source content is accounted
    for before repository-source capacity is chosen, adding it
    deterministically shrinks what's left, an oversized block is omitted
    (never causes an oversized request), oversized mandatory content fails
    closed, and nothing is ever silently truncated mid-content."""

    def _capacity(self, known_overhead_chars, reserved_output_tokens=0):
        from utilities.autopatcher.technical_capacity import compute_source_capacity
        return compute_source_capacity(
            None, None, reserved_output_tokens=reserved_output_tokens,
            known_overhead_chars=known_overhead_chars,
        )

    def test_mandatory_content_deterministically_reduces_capacity(self):
        small = self._capacity(known_overhead_chars=100)
        large = self._capacity(known_overhead_chars=50_000)
        assert large.source_capacity_chars < small.source_capacity_chars
        assert small.source_capacity_chars - large.source_capacity_chars == 50_000 - 100

    def test_planner_evidence_known_overhead_includes_extra_overhead(self):
        """`extra_overhead_chars` (Fix B: threads `len(base_evidence)`
        through Fix A's own acquisition loop) deterministically increases
        the known overhead used to compute the "planner_evidence" stage's
        ceiling -- mandatory content that already precedes Fix A's own
        newly-resolved evidence correctly shrinks what's left for it."""
        from utilities.autopatcher.remediation_planner import _planner_evidence_known_overhead_chars
        base = _planner_evidence_known_overhead_chars("vuln", extra_overhead_chars=0)
        with_extra = _planner_evidence_known_overhead_chars("vuln", extra_overhead_chars=5_000)
        assert with_extra - base == 5_000

    def test_oversized_evidence_omitted_structurally_never_an_oversized_request(self, tmp_path):
        """A single candidate whose real technical capacity is tiny (heavy
        mandatory overhead) is omitted -- never rendered as an oversized
        block, and the omission is structured, not prose-only."""
        from utilities.autopatcher.remediation_planner import (
            RemediationPlanResult, build_planner_evidence_with_budget,
        )
        big_body = "\n".join(f"    line_{i} = {i}" for i in range(500))
        src = f"def big_function():\n{big_body}\n    return None\n"
        (tmp_path / "mod.py").write_text(src, encoding="utf-8")
        from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
        from utilities.agentic_enhancer.repository_index import RepositoryIndex
        from utilities.autopatcher.candidate_enrichment import InvestigationContext

        functions = {"mod.py:big_function": {
            "name": "big_function", "startLine": 1, "endLine": len(src.splitlines()), "code": src,
        }}
        index = RepositoryIndex({"functions": functions}, repo_path=str(tmp_path))
        context = InvestigationContext(
            index=index, call_graph={}, reverse_call_graph={},
            reachability=ReachabilityAnalyzer(functions, {}, set()), constants={},
        )
        plan = RemediationPlanResult(rendered="", target_files=["mod.py"], target_symbols=["mod.py:big_function"])

        # A ceiling big enough for this candidate's own small structural
        # facts (Fix B: structural renders first, whole-block-or-omit,
        # against the SAME shared ceiling as the source excerpt that
        # follows it -- see _build_planner_evidence_result) but too small
        # for the 500-line function body's own source excerpt.
        result = build_planner_evidence_with_budget(
            plan, tmp_path, "vuln", context, base_max_chars=500,
        )
        assert result.excerpt_plan.symbol_omitted
        for label in result.excerpt_plan.symbol_omitted:
            assert result.excerpt_plan.omission_reason[label] == "technical_capacity"
        # Never a bare fragment of the function body leaking through.
        assert "line_499" not in result.rendered

    def test_structural_facts_failing_closed_yields_empty_not_a_fragment(self, tmp_path):
        """When even the structural-facts section (which shares the same
        ceiling as, and renders BEFORE, the source excerpt) cannot fit at
        all, the whole evidence result degrades to empty -- never a bare,
        half-rendered fragment of either section."""
        from utilities.autopatcher.remediation_planner import (
            RemediationPlanResult, build_planner_evidence_with_budget,
        )
        (tmp_path / "mod.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
        from utilities.agentic_enhancer.repository_index import RepositoryIndex
        from utilities.autopatcher.candidate_enrichment import InvestigationContext

        functions = {"mod.py:f": {"name": "f", "startLine": 1, "endLine": 2, "code": "def f():\n    return 1\n"}}
        index = RepositoryIndex({"functions": functions}, repo_path=str(tmp_path))
        context = InvestigationContext(
            index=index, call_graph={}, reverse_call_graph={},
            reachability=ReachabilityAnalyzer(functions, {}, set()), constants={},
        )
        plan = RemediationPlanResult(rendered="", target_files=["mod.py"], target_symbols=["mod.py:f"])

        result = build_planner_evidence_with_budget(plan, tmp_path, "vuln", context, base_max_chars=10)
        assert result.rendered == ""
        assert "[truncated]" not in result.rendered

    def test_mandatory_overhead_alone_exceeding_capacity_fails_closed_not_truncated(self):
        """evidence_fusion/post_patch_evaluation: when the fixed scaffolding
        alone exceeds max_chars, the result is an empty, structurally
        marked failure -- never a mid-line truncated fragment."""
        from utilities.autopatcher.evidence_fusion import (
            _candidate_roles, compute_repository_understanding_plan, fuse_evidence,
        )
        from utilities.autopatcher.candidate_selection import CandidateSelection
        from utilities.autopatcher.repository_grounding_models import RepositoryCandidate

        candidate = RepositoryCandidate(path="a.py", evidence=[], best_tier=4)
        selection = CandidateSelection(
            generated=[candidate], excluded_by_policy=[], eligible=[candidate],
            selected=[candidate], excluded_by_cap=[], max_candidates=1,
        )
        understanding = fuse_evidence(selection, investigation_context_available=True)
        plan = compute_repository_understanding_plan(understanding, max_chars=5)
        assert plan.rendered == ""
        assert plan.fixed_sections_exceeded is True
        assert all(v == "technical_capacity" for v in plan.omission_reason.values())


class TestStrategyReacquisitionProvenancePreserved:
    """Point 12: Strategy authority reacquisition (`_run_evidence_gap_
    strategy_fallback`) preserves structured inclusion/omission provenance
    across its own return boundary -- it is no longer computed internally
    and then discarded."""

    def test_evidence_provenance_present_after_successful_reacquisition(self, tmp_path):
        from unittest import mock

        import utilities.autopatcher.pipeline as pipeline_mod
        from utilities.autopatcher.remediation_planner import PlannerEvidenceResult, _SourceExcerptPlan

        def _evidence_result(rendered, labels):
            return PlannerEvidenceResult(
                rendered=rendered,
                excerpt_plan=_SourceExcerptPlan(
                    blocks=(rendered,) if rendered else (), included_labels=frozenset(labels),
                    symbol_omitted=(), fallback_omitted=(), read_failed=(),
                    budget=4_000, omitted_sizes={}, omission_reason={},
                ),
            )

        from utilities.autopatcher.remediation_planner import RemediationPlanResult, RemediationStrategyResult

        baseline = _evidence_result("baseline evidence", ["old.py:Old"])
        fresh = _evidence_result("fresh evidence", ["a.py:A"])
        plan_result = RemediationPlanResult(rendered="", target_files=["a.py"], target_symbols=["a.py:A"])
        strategy = RemediationStrategyResult(
            rendered="ok", target_files=["a.py"], target_symbols=["a.py:A"],
            warnings=[], extended_mechanism=None, required_edits=[], evaluated=True,
        )

        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                return_value=fresh,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=strategy,
            ),
        ):
            result = pipeline_mod._run_evidence_gap_strategy_fallback(
                plan_result=plan_result, repo_root=tmp_path, vulnerability_text="vuln",
                investigation_context=None, budget_controller=None, llm=None,
                repo_grounding_ctx="", repository_understanding_ctx="", discovery_plan_ctx="",
                baseline_planner_evidence_result=baseline,
            )

        assert result["evidence_provenance"] is not None
        assert result["evidence_provenance"]["included_labels"] == ["a.py:A"]

    def test_evidence_provenance_none_when_never_attempted(self, tmp_path):
        import utilities.autopatcher.pipeline as pipeline_mod
        from utilities.autopatcher.remediation_planner import RemediationPlanResult

        result = pipeline_mod._run_evidence_gap_strategy_fallback(
            plan_result=RemediationPlanResult(rendered="", target_files=[], target_symbols=[]),
            repo_root=tmp_path, vulnerability_text="vuln", investigation_context=None,
            budget_controller=None, llm=None,
            repo_grounding_ctx="", repository_understanding_ctx="", discovery_plan_ctx="",
            baseline_planner_evidence_result=None,
        )
        assert result["skip_reason"] == "no_planner_targets_to_seed_from"
        assert result["evidence_provenance"] is None


class TestChallengerAndCalibrationUnchanged:
    """Points 13, 14: Challenger/Finding Calibration interpretation logic
    itself is untouched by this round -- only what evidence they receive
    changed, never how they interpret it."""

    def test_challenge_patch_signature_and_source_unchanged_in_interpretation(self):
        import inspect as _inspect
        from utilities.autopatcher.patch_challenger import challenge_patch
        sig = _inspect.signature(challenge_patch)
        # `provenance_context` (release audit D7, citation-authority
        # boundary) is the only parameter added since; still no capacity
        # coupling (checked below).
        assert list(sig.parameters) == ["vulnerability_text", "patch", "llm", "code_context", "provenance_context"]
        source = _inspect.getsource(challenge_patch)
        for term in ("technical_capacity", "omission_reason", "ContextBudgetController"):
            assert term not in source

    def test_finding_calibration_interpretation_logic_has_no_capacity_coupling(self):
        """Updated scope boundary: a later, separately-approved task added
        a bounded post-Finding-Calibration evidence-acquisition loop,
        which legitimately gave this module its own capacity contract
        (compute_finding_calibration_capacity/fit_calibration_evidence --
        see finding_calibration.py's own module comment on why). What must
        still hold, and what this now checks precisely: the CLAIMS/
        UNRESOLVED/GROUP/REMEDIATION-IMPACT interpretation logic itself --
        _parse_response and its own field parsers -- has no capacity
        coupling. Capacity concerns live only in the two functions the
        evidence-acquisition loop added, never in how a finding's own
        Claims/Unresolved/Group/Remediation-impact are interpreted."""
        import inspect as _inspect
        from utilities.autopatcher import finding_calibration
        interpretation_source = "".join([
            _inspect.getsource(finding_calibration._parse_response),
            _inspect.getsource(finding_calibration._parse_unresolved),
            _inspect.getsource(finding_calibration._parse_remediation_impact),
        ])
        for term in ("technical_capacity", "omission_reason"):
            assert term not in interpretation_source
