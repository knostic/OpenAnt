"""Unit tests for candidate_enrichment.py (Phase 2A: Candidate Enrichment).

Deterministic only -- no LLM calls, no vulnerability verdicts. Enrichment
attaches CandidateEnrichment metadata directly onto the existing
RepositoryCandidate objects (RepositoryCandidate.enrichment), never a
second candidate model.
"""

from __future__ import annotations

import ast
import inspect

from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.autopatcher.candidate_enrichment import (
    InvestigationContext,
    _resolve_containing_function,
    build_investigation_context,
    enrich_candidates,
)
from utilities.autopatcher.candidate_selection import CandidateSelection
from utilities.autopatcher.repository_grounding_models import (
    DiscoveryEvidence,
    RepositoryCandidate,
)


def _evidence(pass_name: str, tier: int, hit_line: "int | None" = 0) -> DiscoveryEvidence:
    return DiscoveryEvidence(
        pass_name=pass_name, tier=tier, matched_tokens=None,
        total_occurrences=None, hit_line=hit_line, resolution_strategy=None,
    )


def _candidate(path: str, pass_name: str, tier: int, hit_line: "int | None" = 0) -> RepositoryCandidate:
    return RepositoryCandidate(
        path=path, evidence=[_evidence(pass_name, tier, hit_line)], best_tier=tier
    )


def _selection(*candidates: RepositoryCandidate, max_candidates: int = 3) -> CandidateSelection:
    return CandidateSelection(
        generated=list(candidates),
        excluded_by_policy=[],
        eligible=list(candidates),
        selected=list(candidates)[:max_candidates],
        excluded_by_cap=list(candidates)[max_candidates:],
        max_candidates=max_candidates,
    )


def _func(name: str, start: int, end: int, code: str = "") -> dict:
    return {
        "name": name, "startLine": start, "endLine": end,
        "unitType": "function", "className": None, "code": code or f"def {name}(): pass\n",
    }


def _context(
    functions: dict,
    call_graph: "dict | None" = None,
    reverse_call_graph: "dict | None" = None,
    entry_points: "set | None" = None,
) -> InvestigationContext:
    index = RepositoryIndex({"functions": functions})
    call_graph = call_graph or {}
    reverse_call_graph = reverse_call_graph or {}
    reachability = ReachabilityAnalyzer(functions, reverse_call_graph, entry_points or set())
    return InvestigationContext(
        index=index, call_graph=call_graph,
        reverse_call_graph=reverse_call_graph, reachability=reachability,
    )


class TestResolveContainingFunction:
    def test_containment_succeeds_when_hit_line_falls_inside_function(self):
        candidate = _candidate("app/auth.py", "symbol_search", 2, hit_line=12)
        functions_in_file = [
            {"id": "app/auth.py:helper", "name": "helper", "startLine": 1, "endLine": 5},
            {"id": "app/auth.py:authenticate", "name": "authenticate", "startLine": 8, "endLine": 20},
        ]
        resolved, note = _resolve_containing_function(functions_in_file, candidate)
        assert resolved["id"] == "app/auth.py:authenticate"
        assert note is None

    def test_no_containing_function_falls_back_to_nearest_with_explicit_note(self):
        candidate = _candidate("app/auth.py", "symbol_search", 2, hit_line=100)
        functions_in_file = [
            {"id": "app/auth.py:a", "name": "a", "startLine": 1, "endLine": 5},
            {"id": "app/auth.py:b", "name": "b", "startLine": 50, "endLine": 60},
        ]
        resolved, note = _resolve_containing_function(functions_in_file, candidate)
        assert resolved["id"] == "app/auth.py:b"
        assert note is not None and "nearest" in note

    def test_file_with_no_functions_resolves_to_none_with_honest_note(self):
        candidate = _candidate("app/config.py", "symbol_search", 2, hit_line=3)
        resolved, note = _resolve_containing_function([], candidate)
        assert resolved is None
        assert note is not None and "no parsed functions" in note

    def test_strongest_evidence_used_when_multiple_tiers_present(self):
        candidate = RepositoryCandidate(
            path="app/auth.py",
            evidence=[
                _evidence("symbol_search", 2, hit_line=100),
                _evidence("symbol_definition", 3, hit_line=10),
            ],
            best_tier=3,
        )
        functions_in_file = [
            {"id": "app/auth.py:a", "name": "a", "startLine": 1, "endLine": 20},
            {"id": "app/auth.py:b", "name": "b", "startLine": 90, "endLine": 120},
        ]
        resolved, note = _resolve_containing_function(functions_in_file, candidate)
        # tier-3 evidence (hit_line=10) must win over tier-2 (hit_line=100)
        assert resolved["id"] == "app/auth.py:a"
        assert note is None


class TestEnrichCandidatesWithContext:
    def test_callees_and_callers_populated_from_call_graph(self, tmp_path):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "auth.py").write_text("def authenticate():\n    pass\n", encoding="utf-8")

        func_id = "app/auth.py:authenticate"
        callee_id = "app/db.py:query"
        caller_id = "app/routes.py:handler"
        functions = {func_id: _func("authenticate", 1, 2)}
        context = _context(
            functions,
            call_graph={func_id: [callee_id]},
            reverse_call_graph={func_id: [caller_id]},
        )
        candidate = _candidate("app/auth.py", "symbol_definition", 3, hit_line=1)
        selection = _selection(candidate)

        enrich_candidates(selection, repo_root=tmp_path, vulnerability_text="x", context=context)

        assert candidate.enrichment.callees == [callee_id]
        assert candidate.enrichment.callers_by_call_graph == [caller_id]

    def test_reachable_entry_point_sets_true_and_path(self, tmp_path):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "auth.py").write_text("def authenticate():\n    pass\n", encoding="utf-8")

        func_id = "app/auth.py:authenticate"
        functions = {func_id: _func("authenticate", 1, 2)}
        context = _context(functions, entry_points={func_id})
        candidate = _candidate("app/auth.py", "symbol_definition", 3, hit_line=1)
        selection = _selection(candidate)

        enrich_candidates(selection, repo_root=tmp_path, vulnerability_text="x", context=context)

        assert candidate.enrichment.is_reachable_from_entry_point is True
        assert candidate.enrichment.entry_point_path == [func_id]

    def test_unreachable_sets_false_and_no_path(self, tmp_path):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "auth.py").write_text("def authenticate():\n    pass\n", encoding="utf-8")

        func_id = "app/auth.py:authenticate"
        functions = {func_id: _func("authenticate", 1, 2)}
        context = _context(functions, entry_points=set())
        candidate = _candidate("app/auth.py", "symbol_definition", 3, hit_line=1)
        selection = _selection(candidate)

        enrich_candidates(selection, repo_root=tmp_path, vulnerability_text="x", context=context)

        assert candidate.enrichment.is_reachable_from_entry_point is False
        assert candidate.enrichment.entry_point_path is None


class TestEnrichCandidatesWithoutContext:
    def test_none_context_still_enriches_every_candidate(self, tmp_path):
        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "auth.py").write_text("def authenticate():\n    pass\n", encoding="utf-8")
        candidate = _candidate("app/auth.py", "symbol_search", 2, hit_line=0)
        selection = _selection(candidate)

        result = enrich_candidates(selection, repo_root=tmp_path, vulnerability_text="x", context=None)

        assert len(result) == 1
        assert candidate.enrichment is not None
        assert candidate.enrichment.resolved_function is None
        assert "no investigation context" in candidate.enrichment.resolution_note
        assert candidate.enrichment.callees == []
        assert candidate.enrichment.is_reachable_from_entry_point is None


class TestFailureIsolation:
    def test_one_candidate_failing_does_not_affect_others(self, tmp_path):
        (tmp_path / "a.py").write_text("def a(): pass\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("def b(): pass\n", encoding="utf-8")

        func_id_a = "a.py:a"
        func_id_b = "b.py:b"
        functions = {func_id_a: _func("a", 1, 2), func_id_b: _func("b", 1, 2)}
        context = _context(functions)

        good = _candidate("b.py", "symbol_search", 2, hit_line=1)
        bad = _candidate("a.py", "symbol_search", 2, hit_line=1)
        selection = _selection(bad, good, max_candidates=2)

        original = context.index.list_functions_in_file

        def _boom(path):
            if path == "a.py":
                raise RuntimeError("simulated failure")
            return original(path)

        context.index.list_functions_in_file = _boom

        result = enrich_candidates(selection, repo_root=tmp_path, vulnerability_text="x", context=context)

        assert len(result) == 2
        assert bad.enrichment.enrichment_errors  # recorded, not raised
        assert "simulated failure" in bad.enrichment.enrichment_errors[0]
        assert good.enrichment.enrichment_errors == []
        assert good.enrichment.resolved_function is not None


class TestOrderingAndIdentity:
    def test_returned_order_matches_selection_selected_order(self, tmp_path):
        for name in ("a", "b", "c"):
            (tmp_path / f"{name}.py").write_text(f"def {name}(): pass\n", encoding="utf-8")
        a = _candidate("a.py", "symbol_search", 2, hit_line=0)
        b = _candidate("b.py", "symbol_search", 2, hit_line=0)
        c = _candidate("c.py", "symbol_search", 2, hit_line=0)
        selection = _selection(a, b, c, max_candidates=3)

        result = enrich_candidates(selection, repo_root=tmp_path, vulnerability_text="x", context=None)

        assert [cand.path for cand in result] == ["a.py", "b.py", "c.py"]

    def test_same_object_identity_is_returned(self, tmp_path):
        (tmp_path / "a.py").write_text("def a(): pass\n", encoding="utf-8")
        candidate = _candidate("a.py", "symbol_search", 2, hit_line=0)
        selection = _selection(candidate)
        result = enrich_candidates(selection, repo_root=tmp_path, vulnerability_text="x", context=None)
        assert result[0] is candidate

    def test_evidence_and_best_tier_never_mutated(self, tmp_path):
        (tmp_path / "a.py").write_text("def a(): pass\n", encoding="utf-8")
        candidate = _candidate("a.py", "symbol_search", 2, hit_line=0)
        evidence_before = list(candidate.evidence)
        best_tier_before = candidate.best_tier
        selection = _selection(candidate)

        enrich_candidates(selection, repo_root=tmp_path, vulnerability_text="x", context=None)

        assert candidate.evidence == evidence_before
        assert candidate.best_tier == best_tier_before


class TestBackwardCompatibility:
    def test_unenriched_candidate_has_none_enrichment_by_default(self):
        candidate = RepositoryCandidate(path="a.py", evidence=[], best_tier=1)
        assert candidate.enrichment is None

    def test_existing_style_construction_still_valid(self):
        # Mirrors repo_locator.py's own construction call shape.
        candidate = RepositoryCandidate(
            path="a.py",
            evidence=[_evidence("explicit_path", 4, hit_line=0)],
            best_tier=4,
        )
        assert candidate.enrichment is None


class TestSinkMatches:
    def test_no_resolvable_vuln_class_gives_none_not_empty_list(self, tmp_path):
        (tmp_path / "a.py").write_text("def a(): pass\n", encoding="utf-8")
        candidate = _candidate("a.py", "symbol_search", 2, hit_line=0)
        selection = _selection(candidate)
        # CWE-200-shaped text -- resolves no covered vulnerability class.
        vulnerability_text = "Cookie header retained across cross-origin redirects"

        enrich_candidates(selection, repo_root=tmp_path, vulnerability_text=vulnerability_text, context=None)

        assert candidate.enrichment.sink_matches is None


class TestNoLLMPath:
    def test_module_imports_no_llm_machinery(self):
        from utilities.autopatcher import candidate_enrichment

        source = inspect.getsource(candidate_enrichment)
        tree = ast.parse(source)

        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)

        assert not any("llm" in name.lower() for name in imported), imported


class TestRealIntegration:
    def test_select_then_enrich_against_a_real_small_repo(self, tmp_path):
        from utilities.autopatcher.candidate_selection import select_candidates
        from utilities.autopatcher.repo_locator import ground_repository

        (tmp_path / "app").mkdir()
        (tmp_path / "app" / "auth.py").write_text(
            "def authenticate(u, p):\n"
            "    return check_password(u, p)\n"
            "\n"
            "def check_password(u, p):\n"
            "    return True\n",
            encoding="utf-8",
        )
        vuln_text = "Vulnerability in app/auth.py — authenticate() is exploitable"

        grounding = ground_repository(vuln_text, tmp_path)
        selection = select_candidates(grounding, max_candidates=3)
        assert selection.selected, "grounding must find the candidate for this test to be meaningful"

        context = build_investigation_context(tmp_path, tmp_path / "_investigation")
        assert context is not None, "a real Python file must produce a usable investigation context"

        result = enrich_candidates(selection, tmp_path, vuln_text, context)

        assert result
        enriched = result[0].enrichment
        assert enriched is not None
        assert enriched.enrichment_errors == []
        # The real parser must resolve authenticate() as the containing
        # function, and the real call graph must show it calling
        # check_password() -- proving the whole chain end to end, not just
        # that it didn't crash.
        assert enriched.resolved_function is not None
        assert enriched.resolved_function["name"] == "authenticate"
        assert any("check_password" in callee for callee in enriched.callees)
