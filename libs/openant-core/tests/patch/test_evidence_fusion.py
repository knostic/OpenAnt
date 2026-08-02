"""Unit tests for evidence_fusion.py (deterministic Evidence Fusion).

No LLM calls, no I/O, no parsing, no vulnerability verdicts. Fusion
preserves candidate identity: RepositoryUnderstanding.candidate_evidence
holds the exact same RepositoryCandidate objects candidate_selection.py/
candidate_enrichment.py already produced -- never copies, never wraps.
"""

from __future__ import annotations

import ast
import inspect

from utilities.autopatcher.candidate_selection import CandidateSelection
from utilities.autopatcher.evidence_fusion import (
    CandidateRelationship,
    RepositoryUnderstanding,
    fuse_evidence,
)
from utilities.autopatcher.repository_grounding_models import (
    CandidateEnrichment,
    DiscoveryEvidence,
    RepositoryCandidate,
)


def _evidence(pass_name: str, tier: int, hit_line: "int | None" = 0) -> DiscoveryEvidence:
    return DiscoveryEvidence(
        pass_name=pass_name, tier=tier, matched_tokens=None,
        total_occurrences=None, hit_line=hit_line, resolution_strategy=None,
    )


def _enrichment(
    resolved_function: "dict | None" = None,
    callees: "list[str] | None" = None,
    callers_by_call_graph: "list[str] | None" = None,
    callers_by_text_search: "list[dict] | None" = None,
    is_reachable_from_entry_point: "bool | None" = None,
    enrichment_errors: "list[str] | None" = None,
) -> CandidateEnrichment:
    return CandidateEnrichment(
        functions_in_file=[resolved_function] if resolved_function else [],
        resolved_function=resolved_function,
        resolution_note=None if resolved_function else "no function resolved",
        callees=callees or [],
        callers_by_call_graph=callers_by_call_graph or [],
        callers_by_text_search=callers_by_text_search or [],
        is_reachable_from_entry_point=is_reachable_from_entry_point,
        entry_point_path=None,
        related_tests=[],
        test_support_rating=None,
        sink_matches=None,
        enrichment_errors=enrichment_errors or [],
    )


def _candidate(
    path: str,
    pass_name: str,
    tier: int,
    hit_line: "int | None" = 0,
    enrichment: "CandidateEnrichment | None" = None,
) -> RepositoryCandidate:
    candidate = RepositoryCandidate(
        path=path, evidence=[_evidence(pass_name, tier, hit_line)], best_tier=tier
    )
    candidate.enrichment = enrichment
    return candidate


def _selection(*candidates: RepositoryCandidate, max_candidates: int = 3) -> CandidateSelection:
    return CandidateSelection(
        generated=list(candidates),
        excluded_by_policy=[],
        eligible=list(candidates),
        selected=list(candidates)[:max_candidates],
        excluded_by_cap=list(candidates)[max_candidates:],
        max_candidates=max_candidates,
    )


class TestCandidateIdentityPreserved:
    def test_candidate_evidence_holds_exact_same_objects(self):
        a = _candidate("a.py", "explicit_path", 4)
        b = _candidate("b.py", "symbol_search", 2)
        selection = _selection(a, b)

        understanding = fuse_evidence(selection, investigation_context_available=True)

        assert understanding.candidate_evidence[0] is a
        assert understanding.candidate_evidence[1] is b


class TestRelationshipDetection:
    def test_relationship_detected_from_callees(self):
        a = _candidate(
            "a.py", "explicit_path", 4,
            enrichment=_enrichment(
                resolved_function={"id": "a.py:foo", "name": "foo", "startLine": 1, "endLine": 3},
                callees=["b.py:bar"],
            ),
        )
        b = _candidate(
            "b.py", "symbol_search", 2,
            enrichment=_enrichment(
                resolved_function={"id": "b.py:bar", "name": "bar", "startLine": 1, "endLine": 3},
            ),
        )
        selection = _selection(a, b)

        understanding = fuse_evidence(selection, investigation_context_available=True)

        assert understanding.relationships == [
            CandidateRelationship(from_path="a.py", to_path="b.py", kind="calls", detail="b.py:bar")
        ]

    def test_same_edge_from_both_directions_deduplicated(self):
        a = _candidate(
            "a.py", "explicit_path", 4,
            enrichment=_enrichment(callees=["b.py:bar"]),
        )
        b = _candidate(
            "b.py", "symbol_search", 2,
            enrichment=_enrichment(callers_by_call_graph=["a.py:foo"]),
        )
        selection = _selection(a, b)

        understanding = fuse_evidence(selection, investigation_context_available=True)

        assert len(understanding.relationships) == 1
        assert understanding.relationships[0].from_path == "a.py"
        assert understanding.relationships[0].to_path == "b.py"

    def test_relationship_ignored_when_target_not_selected(self):
        a = _candidate(
            "a.py", "explicit_path", 4,
            enrichment=_enrichment(callees=["c.py:not_selected"]),
        )
        selection = _selection(a)

        understanding = fuse_evidence(selection, investigation_context_available=True)

        assert understanding.relationships == []

    def test_callers_by_text_search_never_asserts_a_relationship(self):
        a = _candidate(
            "a.py", "explicit_path", 4,
            enrichment=_enrichment(
                callers_by_text_search=[{"id": "b.py:bar", "name": "bar", "file": "b.py", "matches": []}],
            ),
        )
        b = _candidate("b.py", "symbol_search", 2, enrichment=_enrichment())
        selection = _selection(a, b)

        understanding = fuse_evidence(selection, investigation_context_available=True)

        assert understanding.relationships == []


class TestFusionNotes:
    def test_divergence_note_for_strong_tier_unresolved(self):
        strong_unresolved = _candidate("a.py", "explicit_path", 4, enrichment=_enrichment())
        weak_unresolved = _candidate("b.py", "symbol_search", 2, enrichment=_enrichment())
        selection = _selection(strong_unresolved, weak_unresolved)

        understanding = fuse_evidence(selection, investigation_context_available=True)

        joined = " ".join(understanding.fusion_notes)
        assert "a.py" in joined
        assert "b.py" not in joined

    def test_investigation_context_unavailable_note(self):
        a = _candidate("a.py", "explicit_path", 4, enrichment=_enrichment())
        selection = _selection(a)

        understanding = fuse_evidence(selection, investigation_context_available=False)

        assert any("investigation context unavailable" in n for n in understanding.fusion_notes)
        assert understanding.investigation_context_available is False
        assert understanding.candidate_evidence == [a]

    def test_enrichment_errors_surfaced_for_weak_tier_candidate(self):
        weak_with_error = _candidate(
            "a.py", "symbol_search", 2,
            enrichment=_enrichment(
                resolved_function={"id": "a.py:foo", "name": "foo", "startLine": 1, "endLine": 3},
                enrichment_errors=["graph enrichment failed: RuntimeError: boom"],
            ),
        )
        selection = _selection(weak_with_error)

        understanding = fuse_evidence(selection, investigation_context_available=True)

        joined = " ".join(understanding.fusion_notes)
        assert "a.py" in joined
        assert "boom" in joined

    def test_candidate_never_double_reported_when_strong_and_erroring(self):
        strong_with_error = _candidate(
            "a.py", "explicit_path", 4,
            enrichment=_enrichment(enrichment_errors=["boom"]),
        )
        selection = _selection(strong_with_error)

        understanding = fuse_evidence(selection, investigation_context_available=True)

        a_notes = [n for n in understanding.fusion_notes if n.startswith("a.py:")]
        assert len(a_notes) == 1


class TestEmptySelection:
    def test_empty_selection_returns_empty_understanding(self):
        selection = _selection()

        understanding = fuse_evidence(selection, investigation_context_available=True)

        assert understanding.candidate_evidence == []
        assert understanding.relationships == []
        assert understanding.fusion_notes == []


class TestPurity:
    def test_fuse_evidence_does_not_mutate_inputs(self):
        enrichment = _enrichment(
            resolved_function={"id": "a.py:foo", "name": "foo", "startLine": 1, "endLine": 3},
            callees=["b.py:bar"],
        )
        a = _candidate("a.py", "explicit_path", 4, enrichment=enrichment)
        b = _candidate("b.py", "symbol_search", 2, enrichment=_enrichment())
        selection = _selection(a, b)

        evidence_before = list(a.evidence)
        best_tier_before = a.best_tier
        enrichment_before = a.enrichment
        selected_before = list(selection.selected)

        fuse_evidence(selection, investigation_context_available=True)

        assert a.evidence == evidence_before
        assert a.best_tier == best_tier_before
        assert a.enrichment is enrichment_before
        assert selection.selected == selected_before


class TestConsumerPattern:
    def test_reachable_paths_derivable_directly_from_candidate_evidence(self):
        reachable = _candidate(
            "a.py", "explicit_path", 4,
            enrichment=_enrichment(is_reachable_from_entry_point=True),
        )
        unreachable = _candidate(
            "b.py", "symbol_search", 2,
            enrichment=_enrichment(is_reachable_from_entry_point=False),
        )
        selection = _selection(reachable, unreachable)

        understanding = fuse_evidence(selection, investigation_context_available=True)

        reachable_paths = [
            c.path
            for c in understanding.candidate_evidence
            if c.enrichment and c.enrichment.is_reachable_from_entry_point
        ]
        assert reachable_paths == ["a.py"]


class TestNoLLMPath:
    def test_module_imports_no_llm_machinery(self):
        from utilities.autopatcher import evidence_fusion

        source = inspect.getsource(evidence_fusion)
        tree = ast.parse(source)

        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)

        assert not any("llm" in name.lower() for name in imported), imported
