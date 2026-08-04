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
    DEFAULT_MAX_CHARS,
    CandidateRelationship,
    RepositoryUnderstanding,
    fuse_evidence,
    render_repository_understanding,
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
    resolution_note: "str | None" = "_unset_",
    entry_point_path: "list[str] | None" = None,
    related_tests: "list[dict] | None" = None,
    test_support_rating: "tuple | None" = None,
    sink_matches: "list[dict] | None" = None,
) -> CandidateEnrichment:
    if resolution_note == "_unset_":
        resolution_note = None if resolved_function else "no function resolved"
    return CandidateEnrichment(
        functions_in_file=[resolved_function] if resolved_function else [],
        resolved_function=resolved_function,
        resolution_note=resolution_note,
        callees=callees or [],
        callers_by_call_graph=callers_by_call_graph or [],
        callers_by_text_search=callers_by_text_search or [],
        is_reachable_from_entry_point=is_reachable_from_entry_point,
        entry_point_path=entry_point_path,
        related_tests=related_tests or [],
        test_support_rating=test_support_rating,
        sink_matches=sink_matches,
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


# ---------------------------------------------------------------------------
# render_repository_understanding -- deterministic Markdown rendering.
# ---------------------------------------------------------------------------

def _heavy_candidate(i: int) -> RepositoryCandidate:
    """A candidate whose rendered block is large (8 callees) -- used to
    exercise the character-budget/truncation behavior without needing a
    real repository."""
    return _candidate(
        f"file_{i}.py", "symbol_search", 2, hit_line=i,
        enrichment=_enrichment(
            resolved_function={"id": f"file_{i}.py:fn", "name": "fn", "startLine": 1, "endLine": 50},
            callees=[f"callee_{i}_{j}.py:x" for j in range(8)],
        ),
    )


class TestRenderHeadingAndOrdering:
    def test_heading_and_candidate_order_preserved(self):
        strong = _candidate("a.py", "explicit_path", 4)
        weak = _candidate("b.py", "symbol_search", 2)
        # candidate_selection.py already orders by (-best_tier, path) before
        # this renderer ever sees the list -- simulate that ordering here
        # rather than re-deriving it, since the renderer must trust it.
        selection = _selection(strong, weak)

        understanding = fuse_evidence(selection, investigation_context_available=True)
        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert rendered.startswith("## Repository Understanding")
        assert rendered.index("`a.py`") < rendered.index("`b.py`")


class TestRenderCandidateFacts:
    def test_path_and_grounding_evidence_rendered(self):
        a = _candidate("app/auth.py", "explicit_path", 4, hit_line=10)
        selection = _selection(a)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert "`app/auth.py`" in rendered
        assert "best tier 4" in rendered
        assert "explicit_path (tier 4)" in rendered

    def test_resolved_function_details_rendered(self):
        a = _candidate(
            "app/auth.py", "symbol_definition", 3,
            enrichment=_enrichment(
                resolved_function={
                    "id": "app/auth.py:authenticate", "name": "authenticate",
                    "startLine": 10, "endLine": 20,
                },
            ),
        )
        selection = _selection(a)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert "Resolved near grounding evidence" in rendered
        assert "`authenticate`" in rendered
        assert "lines 10-20" in rendered

    def test_unresolved_function_uses_honest_wording(self):
        a = _candidate(
            "app/config.py", "symbol_search", 2,
            enrichment=_enrichment(resolution_note="no function contains hit_line 3"),
        )
        selection = _selection(a)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert "No function was resolved" in rendered
        assert "no function contains hit_line 3" in rendered
        assert "Resolved near grounding evidence" not in rendered

    def test_reachability_true_false_none_are_distinguishable(self):
        reachable = _candidate(
            "a.py", "explicit_path", 4,
            enrichment=_enrichment(
                is_reachable_from_entry_point=True,
                entry_point_path=["a.py:entry", "a.py:foo"],
            ),
        )
        unreachable = _candidate(
            "b.py", "symbol_search", 2,
            enrichment=_enrichment(is_reachable_from_entry_point=False),
        )
        not_evaluated = _candidate(
            "c.py", "cwe_keywords", 1,
            enrichment=_enrichment(is_reachable_from_entry_point=None),
        )
        selection = _selection(reachable, unreachable, not_evaluated, max_candidates=3)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert "detected as reachable by current entry-point heuristics (path:" in rendered
        assert "detected as not reachable by current entry-point heuristics" in rendered
        assert "not evaluated (no investigation context available)" in rendered

    def test_enrichment_errors_visible_when_present(self):
        a = _candidate(
            "a.py", "symbol_search", 2,
            enrichment=_enrichment(enrichment_errors=["graph enrichment failed: RuntimeError: boom"]),
        )
        selection = _selection(a)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert "Enrichment errors:" in rendered
        assert "boom" in rendered

    def test_missing_enrichment_is_stated_honestly(self):
        a = RepositoryCandidate(
            path="a.py",
            evidence=[_evidence("cwe_keywords", 1)],
            best_tier=1,
        )  # enrichment left as default None -- never enriched
        selection = _selection(a)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert "Enrichment: not attempted for this candidate" in rendered


class TestRenderCandidateRoles:
    def test_single_candidate_is_labeled_primary_only(self):
        a = _candidate("a.py", "symbol_search", 2)
        selection = _selection(a)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert "**Primary evidence**" in rendered
        assert "**Supporting evidence**" not in rendered
        assert "**Additional candidate**" not in rendered

    def test_second_candidate_connected_by_call_graph_is_labeled_supporting(self):
        primary = _candidate(
            "primary.py", "explicit_path", 4,
            enrichment=_enrichment(callees=["other.py:helper"]),
        )
        other = _candidate("other.py", "symbol_search", 2, enrichment=_enrichment())
        selection = _selection(primary, other)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        primary_block = rendered.split("### `primary.py`", 1)[1].split("### `other.py`", 1)[0]
        other_block = rendered.split("### `other.py`", 1)[1].split("###", 1)[0]

        assert "**Primary evidence**" in primary_block
        assert "**Supporting evidence**" in other_block
        assert "**Additional candidate**" not in other_block

    def test_relationship_detected_from_either_direction_still_labels_supporting(self):
        # The edge is recorded via the OTHER candidate's callers_by_call_graph
        # naming the primary, not via the primary's own callees -- role
        # assignment must not care which side recorded it.
        primary = _candidate("primary.py", "explicit_path", 4, enrichment=_enrichment())
        other = _candidate(
            "other.py", "symbol_search", 2,
            enrichment=_enrichment(callers_by_call_graph=["primary.py:entry"]),
        )
        selection = _selection(primary, other)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        other_block = rendered.split("### `other.py`", 1)[1].split("###", 1)[0]
        assert "**Supporting evidence**" in other_block

    def test_second_candidate_with_no_relationship_is_labeled_independent(self):
        primary = _candidate("primary.py", "explicit_path", 4, enrichment=_enrichment())
        unrelated = _candidate("unrelated.py", "symbol_search", 2, enrichment=_enrichment())
        selection = _selection(primary, unrelated)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        unrelated_block = rendered.split("### `unrelated.py`", 1)[1].split("###", 1)[0]

        assert "**Additional candidate**" in unrelated_block
        assert "**Supporting evidence**" not in unrelated_block

    def test_text_search_only_connection_does_not_count_as_supporting(self):
        # callers_by_text_search is regex-based and noisier than the call
        # graph -- _find_call_relationships deliberately never builds a
        # relationship from it, so role assignment must not either.
        primary = _candidate(
            "primary.py", "explicit_path", 4,
            enrichment=_enrichment(
                callers_by_text_search=[
                    {"id": "other.py:maybe", "name": "maybe", "file": "other.py", "matches": []}
                ],
            ),
        )
        other = _candidate("other.py", "symbol_search", 2, enrichment=_enrichment())
        selection = _selection(primary, other)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        other_block = rendered.split("### `other.py`", 1)[1].split("###", 1)[0]
        assert "**Additional candidate**" in other_block
        assert "**Supporting evidence**" not in other_block

    def test_only_relationships_touching_the_primary_count_as_supporting(self):
        # b and c are connected to EACH OTHER but neither is connected to
        # the primary (a) -- that must not make either one "supporting";
        # the signal is specifically "connected to the primary."
        a = _candidate("a.py", "explicit_path", 4, enrichment=_enrichment())
        b = _candidate("b.py", "symbol_search", 2, enrichment=_enrichment(callees=["c.py:helper"]))
        c = _candidate("c.py", "cwe_keywords", 1, enrichment=_enrichment())
        selection = _selection(a, b, c, max_candidates=3)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        b_block = rendered.split("### `b.py`", 1)[1].split("### `c.py`", 1)[0]
        c_block = rendered.split("### `c.py`", 1)[1].split("###", 1)[0]

        assert "**Additional candidate**" in b_block
        assert "**Additional candidate**" in c_block

    def test_role_labels_do_not_change_candidate_order(self):
        a = _candidate("a.py", "explicit_path", 4, enrichment=_enrichment())
        b = _candidate("b.py", "symbol_search", 2, enrichment=_enrichment())
        selection = _selection(a, b)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert rendered.index("`a.py`") < rendered.index("`b.py`")


class TestRenderRelationshipsAndNotes:
    def test_relationship_rendered_once_not_duplicated_in_notes(self):
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

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert "### Structural relationships" in rendered
        assert "direct call-graph relationship" in rendered
        # the raw fusion-note form of this same relationship must not also
        # be echoed under Notes -- stated once, not twice.
        assert "a.py calls b.py (via b.py:bar)" not in rendered

    def test_callers_by_text_search_never_rendered_as_a_relationship(self):
        a = _candidate(
            "a.py", "explicit_path", 4,
            enrichment=_enrichment(
                callers_by_text_search=[{"id": "b.py:bar", "name": "bar", "file": "b.py", "matches": []}],
            ),
        )
        b = _candidate("b.py", "symbol_search", 2, enrichment=_enrichment())
        selection = _selection(a, b)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        section = rendered.split("### Structural relationships", 1)[1].split("###", 1)[0]
        assert "None detected." in section
        assert "b.py:bar" not in section

    def test_divergence_note_visible_in_notes_section(self):
        strong_unresolved = _candidate("a.py", "explicit_path", 4, enrichment=_enrichment())
        selection = _selection(strong_unresolved)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        section = rendered.split("### Notes", 1)[1].split("###", 1)[0]
        assert "strong grounding" in section
        assert "a.py" in section

    def test_investigation_context_unavailable_is_explicit_and_not_duplicated(self):
        a = _candidate("a.py", "explicit_path", 4, enrichment=_enrichment())
        selection = _selection(a)
        understanding = fuse_evidence(selection, investigation_context_available=False)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert "### Investigation context" in rendered
        assert "Investigation context unavailable" in rendered
        notes_section = rendered.split("### Notes", 1)[1].split("### Investigation context", 1)[0]
        assert "investigation context unavailable" not in notes_section


class TestRenderEmptyUnderstanding:
    def test_empty_understanding_renders_a_valid_honest_section(self):
        selection = _selection()
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding)

        assert rendered.startswith("## Repository Understanding")
        assert "No repository candidates were selected" in rendered
        assert "### Structural relationships" in rendered
        assert "None detected." in rendered
        assert "### Notes" in rendered
        assert "None." in rendered
        assert "### Investigation context" in rendered
        assert len(rendered) <= DEFAULT_MAX_CHARS


class TestRenderCharacterBudget:
    def test_representative_two_candidate_understanding_fits_default_budget(self):
        """A realistically-enriched, two-candidate understanding -- the
        common case, since candidate_selection.py caps selection at 3 --
        must fit under DEFAULT_MAX_CHARS without omitting either
        candidate."""
        retry = _candidate(
            "src/urllib3/util/retry.py", "explicit_path", 4, hit_line=92,
            enrichment=_enrichment(
                resolved_function={
                    "id": "src/urllib3/util/retry.py:Retry.increment",
                    "name": "increment", "startLine": 92, "endLine": 134,
                },
                callees=[
                    "src/urllib3/util/retry.py:Retry.is_retry",
                    "src/urllib3/util/retry.py:Retry.get_backoff_time",
                ],
                callers_by_call_graph=["src/urllib3/connectionpool.py:HTTPConnectionPool.urlopen"],
                is_reachable_from_entry_point=True,
                entry_point_path=[
                    "src/urllib3/poolmanager.py:PoolManager.urlopen",
                    "src/urllib3/connectionpool.py:HTTPConnectionPool.urlopen",
                    "src/urllib3/util/retry.py:Retry.increment",
                ],
                related_tests=[
                    {"path": "test/test_retry.py", "proximity": "same-module", "reason": "imports urllib3.util.retry"},
                ],
                test_support_rating=("Good", 0.05, {}),
            ),
        )
        connectionpool = _candidate(
            "src/urllib3/connectionpool.py", "symbol_search", 2, hit_line=700,
            enrichment=_enrichment(
                resolution_note="no function contains hit_line 700; used nearest function by start line",
                callers_by_text_search=[
                    {"id": "src/urllib3/util/retry.py:Retry.increment", "name": "increment",
                     "file": "src/urllib3/util/retry.py", "matches": []},
                ],
                sink_matches=[
                    {"file": "src/urllib3/connectionpool.py", "line": 705, "method": "urlopen",
                     "snippet": 'headers.pop("Authorization", None)'},
                ],
            ),
        )
        selection = _selection(retry, connectionpool)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding)  # default budget

        assert len(rendered) <= DEFAULT_MAX_CHARS
        assert "omitted" not in rendered
        assert "truncated" not in rendered
        assert "`src/urllib3/util/retry.py`" in rendered
        assert "`src/urllib3/connectionpool.py`" in rendered

    def test_budget_respected_with_no_truncation_needed(self):
        a = _candidate("a.py", "explicit_path", 4)
        b = _candidate("b.py", "symbol_search", 2)
        selection = _selection(a, b)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=4_000)

        assert len(rendered) <= 4_000
        assert "omitted" not in rendered
        assert "truncated" not in rendered

    def test_budget_never_exceeded_with_many_heavy_candidates(self):
        candidates = [_heavy_candidate(i) for i in range(10)]
        selection = _selection(*candidates, max_candidates=10)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=500)

        assert len(rendered) <= 500

    def test_budget_never_exceeded_at_a_pathologically_small_budget(self):
        a = _candidate("a.py", "explicit_path", 4, enrichment=_enrichment())
        selection = _selection(a)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        rendered = render_repository_understanding(understanding, max_chars=10)

        assert len(rendered) <= 10

    def test_truncation_is_explicit_and_deterministic(self):
        candidates = [_heavy_candidate(i) for i in range(3)]
        selection = _selection(*candidates, max_candidates=3)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        budget = 900
        rendered_1 = render_repository_understanding(understanding, max_chars=budget)
        rendered_2 = render_repository_understanding(understanding, max_chars=budget)

        assert rendered_1 == rendered_2, "rendering must be a pure, deterministic function"
        assert len(rendered_1) <= budget
        assert f"omitted to stay within the {budget}-character budget" in rendered_1
        omission_text = rendered_1[rendered_1.index("omitted to stay within") :]
        assert any(f"file_{i}.py" in omission_text for i in range(3))


class TestRenderPurity:
    def test_render_does_not_mutate_understanding_or_candidates(self):
        enrichment = _enrichment(
            resolved_function={"id": "a.py:foo", "name": "foo", "startLine": 1, "endLine": 3},
            callees=["b.py:bar"],
        )
        a = _candidate("a.py", "explicit_path", 4, enrichment=enrichment)
        b = _candidate("b.py", "symbol_search", 2, enrichment=_enrichment())
        selection = _selection(a, b)
        understanding = fuse_evidence(selection, investigation_context_available=True)

        candidate_evidence_before = list(understanding.candidate_evidence)
        relationships_before = list(understanding.relationships)
        fusion_notes_before = list(understanding.fusion_notes)
        evidence_before = list(a.evidence)
        best_tier_before = a.best_tier
        enrichment_before = a.enrichment

        render_repository_understanding(understanding, max_chars=100)  # tiny budget, forces truncation path
        render_repository_understanding(understanding, max_chars=4_000)

        assert understanding.candidate_evidence == candidate_evidence_before
        assert understanding.relationships == relationships_before
        assert understanding.fusion_notes == fusion_notes_before
        assert a.evidence == evidence_before
        assert a.best_tier == best_tier_before
        assert a.enrichment is enrichment_before


class TestRenderNoRuntimeIntegration:
    def test_module_introduces_no_io_network_or_environment_access(self):
        from utilities.autopatcher import evidence_fusion

        source = inspect.getsource(evidence_fusion)
        tree = ast.parse(source)

        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)

        disallowed = {"os", "sys", "socket", "subprocess", "requests", "urllib", "pathlib"}
        assert not (imported & disallowed), imported
