"""Unit tests for candidate_selection.py (Phase 1: Candidate Selection).

No LLM calls, no OpenAnt investigation -- this phase only selects a bounded,
deterministically-ordered subset of RepositoryGroundingResult.candidates.
All fixtures use the real repository-grounding dataclasses directly.
"""

from __future__ import annotations

import pytest

from utilities.autopatcher.repository_grounding_models import (
    DiscoveryEvidence,
    RepositoryCandidate,
    RepositoryGroundingResult,
)
from utilities.autopatcher.candidate_selection import (
    DEFAULT_MAX_CANDIDATES,
    select_candidates,
)


EXPLICIT = ("explicit_path", 4)
SYMBOL_DEF = ("symbol_definition", 3)
SYMBOL_SEARCH = ("symbol_search", 2)
CWE = ("cwe_keywords", 1)


def _evidence(pass_name: str, tier: int) -> DiscoveryEvidence:
    return DiscoveryEvidence(
        pass_name=pass_name, tier=tier, matched_tokens=None,
        total_occurrences=None, hit_line=0, resolution_strategy=None,
    )


def _candidate(path: str, pass_name: str, tier: int) -> RepositoryCandidate:
    return RepositoryCandidate(path=path, evidence=[_evidence(pass_name, tier)], best_tier=tier)


def _grounding(*candidates: RepositoryCandidate) -> RepositoryGroundingResult:
    return RepositoryGroundingResult(
        rendered_context="", candidates=list(candidates), decisions=[],
        extraction_signals={}, budget=None,
    )


class TestOrderingByTier:
    def test_explicit_path_and_symbol_definition_outrank_weaker_tiers(self):
        strong_a = _candidate("app/auth.py", *EXPLICIT)
        strong_b = _candidate("app/session.py", *SYMBOL_DEF)
        weak = _candidate("app/utils.py", *SYMBOL_SEARCH)
        selection = select_candidates(_grounding(weak, strong_b, strong_a), max_candidates=3)
        assert [c.path for c in selection.selected] == [
            "app/auth.py", "app/session.py", "app/utils.py",
        ]

    def test_symbol_search_remains_eligible_below_stronger_evidence(self):
        strong = _candidate("app/auth.py", *EXPLICIT)
        weak = _candidate("app/utils.py", *SYMBOL_SEARCH)
        selection = select_candidates(_grounding(strong, weak), max_candidates=5)
        assert weak in selection.eligible
        assert weak in selection.selected  # capacity available

    def test_cwe_fallback_does_not_crowd_out_stronger_candidates_when_cap_reached(self):
        strong = [_candidate(f"app/strong_{i}.py", *EXPLICIT) for i in range(3)]
        weak = _candidate("app/weak.py", *CWE)
        selection = select_candidates(_grounding(*strong, weak), max_candidates=3)
        assert weak not in selection.selected
        assert weak in selection.excluded_by_cap

    def test_cwe_fallback_selected_when_no_stronger_candidate_exists(self):
        weak = _candidate("app/weak.py", *CWE)
        selection = select_candidates(_grounding(weak), max_candidates=3)
        assert weak in selection.selected


class TestCapBehavior:
    def test_more_eligible_than_cap_keeps_strongest_and_excludes_tail(self):
        candidates = [
            _candidate("app/a.py", *EXPLICIT),
            _candidate("app/b.py", *SYMBOL_DEF),
            _candidate("app/c.py", *SYMBOL_SEARCH),
            _candidate("app/d.py", *CWE),
        ]
        selection = select_candidates(_grounding(*candidates), max_candidates=2)
        assert [c.path for c in selection.selected] == ["app/a.py", "app/b.py"]
        assert [c.path for c in selection.excluded_by_cap] == ["app/c.py", "app/d.py"]
        assert len(selection.selected) <= selection.max_candidates

    def test_max_candidates_one_selects_single_strongest(self):
        candidates = [_candidate("app/a.py", *SYMBOL_DEF), _candidate("app/b.py", *EXPLICIT)]
        selection = select_candidates(_grounding(*candidates), max_candidates=1)
        assert [c.path for c in selection.selected] == ["app/b.py"]

    def test_max_candidates_zero_selects_nothing_and_is_not_an_error(self):
        selection = select_candidates(
            _grounding(_candidate("app/a.py", *EXPLICIT)), max_candidates=0
        )
        assert selection.selected == []
        assert selection.used_fallback is True

    def test_negative_max_candidates_raises(self):
        with pytest.raises(ValueError):
            select_candidates(_grounding(), max_candidates=-1)


class TestDeterministicOrdering:
    def test_tied_tier_breaks_by_path_and_is_stable_across_repeated_calls(self):
        a = _candidate("app/b.py", *SYMBOL_DEF)
        b = _candidate("app/a.py", *SYMBOL_DEF)
        grounding = _grounding(a, b)
        first = [c.path for c in select_candidates(grounding, max_candidates=5).selected]
        second = [c.path for c in select_candidates(grounding, max_candidates=5).selected]
        assert first == second == ["app/a.py", "app/b.py"]


class TestBookkeepingInvariants:
    def test_generated_eligible_selected_excluded_by_cap_partition_correctly(self):
        candidates = [_candidate(f"app/{i}.py", *SYMBOL_SEARCH) for i in range(5)]
        selection = select_candidates(_grounding(*candidates), max_candidates=2)

        generated_paths = {c.path for c in selection.generated}
        eligible_paths = {c.path for c in selection.eligible}
        excluded_by_policy_paths = {c.path for c in selection.excluded_by_policy}
        selected_paths = {c.path for c in selection.selected}
        excluded_by_cap_paths = {c.path for c in selection.excluded_by_cap}

        assert generated_paths == excluded_by_policy_paths | eligible_paths
        assert eligible_paths == selected_paths | excluded_by_cap_paths
        assert len(selection.selected) <= selection.max_candidates

    def test_empty_grounding_result_is_safe_and_uses_fallback(self):
        selection = select_candidates(_grounding(), max_candidates=DEFAULT_MAX_CANDIDATES)
        assert selection.generated == []
        assert selection.eligible == []
        assert selection.selected == []
        assert selection.excluded_by_cap == []
        assert selection.excluded_by_policy == []
        assert selection.used_fallback is True


class TestNoSideEffects:
    def test_does_not_mutate_grounding_result_or_its_candidates(self):
        candidates = [_candidate("app/a.py", *EXPLICIT), _candidate("app/b.py", *CWE)]
        grounding = _grounding(*candidates)
        before = list(grounding.candidates)

        select_candidates(grounding, max_candidates=1)

        assert grounding.candidates == before
        assert grounding.candidates == candidates

    def test_module_makes_no_llm_or_environment_calls(self):
        import ast
        import inspect

        from utilities.autopatcher import candidate_selection

        source = inspect.getsource(candidate_selection)
        tree = ast.parse(source)

        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)

        assert not any("llm" in name.lower() for name in imported), imported
        assert "os" not in imported

        # No os.environ / os.getenv attribute access anywhere in the module body.
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv"):
                pytest.fail(f"unexpected os.{node.attr} usage in candidate_selection.py")


class TestRealGroundingIntegration:
    def test_selects_from_real_ground_repository_output(self, tmp_path):
        from utilities.autopatcher.repo_locator import ground_repository

        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "auth.py").write_text(
            "def authenticate(u, p):\n    pass\n", encoding="utf-8"
        )
        (tmp_path / "app" / "other.py").write_text(
            "def unrelated():\n    pass\n", encoding="utf-8"
        )
        vuln_text = "Vulnerability in app/auth.py — authenticate() is exploitable"

        grounding = ground_repository(vuln_text, tmp_path)
        selection = select_candidates(grounding, max_candidates=DEFAULT_MAX_CANDIDATES)

        assert any("auth.py" in c.path for c in selection.selected)
        assert len(selection.selected) <= DEFAULT_MAX_CANDIDATES
