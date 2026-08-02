"""Deterministic Evidence Fusion.

Fuses every selected candidate's enrichment (see candidate_enrichment.py)
into a RepositoryUnderstanding that preserves candidate identity rather
than flattening candidates into global summary lists. Every
RepositoryCandidate already carries its own grounding evidence
(.evidence/.best_tier) and enrichment (.enrichment) -- this module adds
exactly two things beyond passthrough: relationships between candidates,
and a short fusion_notes trail recording what fusion noticed.

No LLM calls, no I/O, no parsing, no vulnerability judgement anywhere in
this module. Pure data in (a CandidateSelection, already produced by
candidate_selection.py/candidate_enrichment.py), pure data out.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from utilities.autopatcher.candidate_selection import CandidateSelection
from utilities.autopatcher.repository_grounding_models import RepositoryCandidate

# best_tier values strong enough that a failure to resolve a function is
# worth flagging as a divergence -- explicit_path (4) and symbol_definition
# (3), per repo_locator.py's tier constants. Weaker tiers (symbol_search=2,
# cwe_keywords=1) matching no function is expected/unremarkable, not
# flagged.
_STRONG_TIER_THRESHOLD = 3


@dataclass
class CandidateRelationship:
    """A directly-observed structural link between two selected
    candidates. Flat -- not a graph edge type, no traversal, no
    transitive closure, nothing scored."""

    from_path: str
    to_path: str
    kind: str  # "calls" -- the only kind in this phase
    detail: str  # the func_id that evidences this link


@dataclass
class RepositoryUnderstanding:
    """Deterministic fusion of every selected candidate's enrichment.

    ``candidate_evidence`` holds the exact same ``RepositoryCandidate``
    objects produced by candidate_selection.py/candidate_enrichment.py --
    never copies, never reconstructs, never wraps them. No LLM output, no
    vulnerability verdict, no confidence score anywhere here.
    """

    candidate_evidence: list[RepositoryCandidate]
    relationships: list[CandidateRelationship] = field(default_factory=list)
    fusion_notes: list[str] = field(default_factory=list)
    investigation_context_available: bool = True


def fuse_evidence(
    selection: CandidateSelection,
    investigation_context_available: bool,
) -> RepositoryUnderstanding:
    """Fuse every selected candidate's enrichment into a
    RepositoryUnderstanding.

    Pure and deterministic: no LLM calls, no I/O, no parsing. Reads only
    fields already populated by select_candidates()/enrich_candidates().
    Never mutates ``selection`` or any ``RepositoryCandidate``/
    ``CandidateEnrichment`` it reads.
    """
    candidate_evidence = list(selection.selected)
    relationships = _find_call_relationships(candidate_evidence)
    fusion_notes = _build_fusion_notes(
        candidate_evidence, investigation_context_available, relationships
    )
    return RepositoryUnderstanding(
        candidate_evidence=candidate_evidence,
        relationships=relationships,
        fusion_notes=fusion_notes,
        investigation_context_available=investigation_context_available,
    )


def _file_part(func_id: str) -> str:
    """Extract the file portion of a func_id (``"file/path.py:funcName"``
    -> ``"file/path.py"``), matching ``RepositoryIndex._build_index``'s
    own convention (split on the last colon)."""
    colon_idx = func_id.rfind(":")
    if colon_idx <= 0:
        return func_id
    return func_id[:colon_idx]


def _find_call_relationships(
    candidate_evidence: list[RepositoryCandidate],
) -> list[CandidateRelationship]:
    """Structural call-graph adjacency between selected candidates only.

    Uses only ``callees``/``callers_by_call_graph`` (deterministic, from
    the parser's own call graph) -- never ``callers_by_text_search``,
    which is regex-based and noisier; asserting a structural relationship
    from it would claim more than that signal supports.

    The same real edge can be discovered from either candidate's
    perspective (A's ``callees`` names B, or B's ``callers_by_call_graph``
    names A) -- deduplicated by ``(from_path, to_path, kind)`` so it is
    reported once.
    """
    by_path = {c.path: c for c in candidate_evidence}
    seen: set[tuple[str, str, str]] = set()
    relationships: list[CandidateRelationship] = []

    for candidate in candidate_evidence:
        if candidate.enrichment is None:
            continue

        for callee_id in candidate.enrichment.callees:
            callee_file = _file_part(callee_id)
            if callee_file == candidate.path or callee_file not in by_path:
                continue
            key = (candidate.path, callee_file, "calls")
            if key not in seen:
                seen.add(key)
                relationships.append(
                    CandidateRelationship(
                        from_path=candidate.path,
                        to_path=callee_file,
                        kind="calls",
                        detail=callee_id,
                    )
                )

        for caller_id in candidate.enrichment.callers_by_call_graph:
            caller_file = _file_part(caller_id)
            if caller_file == candidate.path or caller_file not in by_path:
                continue
            key = (caller_file, candidate.path, "calls")
            if key not in seen:
                seen.add(key)
                relationships.append(
                    CandidateRelationship(
                        from_path=caller_file,
                        to_path=candidate.path,
                        kind="calls",
                        detail=caller_id,
                    )
                )

    return relationships


def _build_fusion_notes(
    candidate_evidence: list[RepositoryCandidate],
    investigation_context_available: bool,
    relationships: list[CandidateRelationship],
) -> list[str]:
    """Deterministic, human-readable trail of what fusion noticed. Never
    a verdict, never a score -- just an honest record of divergences,
    degraded-mode operation, enrichment failures, and the relationships
    found. Each candidate contributes at most one divergence/error note,
    never both, to avoid redundant reporting of the same candidate."""
    notes: list[str] = []

    if not investigation_context_available:
        notes.append(
            "investigation context unavailable -- candidates enriched in "
            "degraded, file/test/sink-only mode (no parse/call-graph/reachability)"
        )

    for candidate in candidate_evidence:
        enrichment = candidate.enrichment
        if enrichment is None:
            continue

        is_strong = (
            candidate.best_tier is not None
            and candidate.best_tier >= _STRONG_TIER_THRESHOLD
        )
        unresolved = enrichment.resolved_function is None
        has_error = bool(enrichment.enrichment_errors)

        if is_strong and (unresolved or has_error):
            notes.append(
                f"{candidate.path}: strong grounding (best_tier={candidate.best_tier}) "
                f"but enrichment could not confirm a function "
                f"(resolved_function={enrichment.resolved_function!r}, "
                f"enrichment_errors={enrichment.enrichment_errors!r})"
            )
        elif has_error:
            # Not a "strong grounding" divergence, but errors must never
            # be silently swallowed regardless of grounding strength.
            notes.append(f"{candidate.path}: enrichment_errors={enrichment.enrichment_errors!r}")

    for rel in relationships:
        notes.append(f"{rel.from_path} {rel.kind} {rel.to_path} (via {rel.detail})")

    return notes
