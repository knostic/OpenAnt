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
        notes.append(_relationship_note(rel))

    return notes


def _relationship_note(rel: CandidateRelationship) -> str:
    """The exact fusion-note text for one relationship. Factored out so the
    renderer below can recognise (and skip) these lines when rendering
    fusion_notes separately from the Structural relationships section --
    same wording either place, computed once."""
    return f"{rel.from_path} {rel.kind} {rel.to_path} (via {rel.detail})"


# ---------------------------------------------------------------------------
# Deterministic Markdown rendering of RepositoryUnderstanding.
#
# This is the sole consumption boundary this phase adds: a pure function
# from RepositoryUnderstanding to a Markdown string, meant to be appended
# into pipeline.run()'s existing `code_context` string alongside the repo
# code / vulnerability-pattern-guidance blocks it already builds. Nothing
# here calls that pipeline -- this module remains dormant until a later,
# separate wiring phase.
#
# No LLM calls, no I/O, no verdicts, no confidence scores. Every line is
# either a literal passthrough of an existing field or an explicit "not
# resolved / not evaluated" statement -- never a positive claim inferred
# from missing evidence.
# ---------------------------------------------------------------------------

DEFAULT_MAX_CHARS = 4_000
"""Matches repo_locator.py's _MAX_CONTEXT_CHARS. Candidate selection is
already bounded to at most DEFAULT_MAX_CANDIDATES (3) candidates
(candidate_selection.py), so this budget is sized to normally preserve the
complete deterministic understanding for all of them, not to further
ration an already-small set."""

_MAX_LIST_ITEMS = 5
"""Per-list cap (callees, callers, tests, sinks, relationships, notes)
before a deterministic "(+N more)" note. Keeps any single candidate's
block bounded regardless of how noisy its enrichment is."""

_TRUNCATION_MARKER = "\n\n*(truncated to fit the character budget)*\n"

_HEADING = "## Repository Understanding"

_PREAMBLE = (
    "*Deterministic repository analysis, not a vulnerability verdict. These "
    "are structural facts (parsing, call graph, reachability, tests) -- not "
    "confirmation that a candidate is vulnerable, exploitable, or on the "
    "attack path. Missing evidence is reported as missing, never as a "
    "negative finding.*"
)


def render_repository_understanding(
    understanding: RepositoryUnderstanding,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    """Render a RepositoryUnderstanding into one deterministic Markdown
    block, starting with a top-level ``## Repository Understanding``
    heading.

    Candidates are rendered in the exact order already given by
    ``understanding.candidate_evidence`` (candidate_selection.py's
    tier-descending, path-ascending order) -- this function never
    re-sorts or re-selects. If the character budget cannot fit every
    candidate, weaker (later) candidates are dropped first and an explicit
    note names what was omitted; malformed truncation mid-candidate never
    happens -- a candidate's block is included whole or not at all.

    Never mutates ``understanding`` or anything it references. No LLM
    calls, no I/O, no parsing.

    The returned string never exceeds ``max_chars`` -- a final safety-net
    truncation (at a line boundary, with an explicit marker) applies in the
    unlikely case that even omitting every candidate can't make the fixed
    sections (heading, preamble, relationships, notes, investigation-context
    line) fit.
    """
    candidate_blocks = [_render_candidate(c) for c in understanding.candidate_evidence]
    relationships_block = _render_relationships(understanding.relationships)
    notes_block = _render_notes(understanding)
    context_block = _render_investigation_context(understanding.investigation_context_available)

    header = _HEADING + "\n\n" + _PREAMBLE + "\n"

    if not candidate_blocks:
        body = "\nNo repository candidates were selected for investigation.\n"
    else:
        fixed_cost = len(header) + len(relationships_block) + len(notes_block) + len(context_block)
        budget_for_candidates = max(max_chars - fixed_cost, 0)

        included: list[str] = []
        omitted_paths: list[str] = []
        running = 0
        for candidate, block in zip(understanding.candidate_evidence, candidate_blocks):
            if running + len(block) <= budget_for_candidates:
                included.append(block)
                running += len(block)
            else:
                omitted_paths.append(candidate.path)

        body = "\n" + "\n".join(included)
        if omitted_paths:
            body += (
                f"\n\n*{len(omitted_paths)} candidate(s) omitted to stay within the "
                f"{max_chars}-character budget: {', '.join(omitted_paths)}.*\n"
            )

    rendered = header + body + "\n" + relationships_block + "\n" + notes_block + "\n" + context_block

    if len(rendered) > max_chars:
        rendered = _hard_clamp(rendered, max_chars)

    return rendered


def _hard_clamp(rendered: str, max_chars: int) -> str:
    """Absolute backstop: truncate at the last full line boundary that fits,
    so the result is never split mid-item, and append an explicit marker.
    Guarantees len(result) <= max_chars."""
    limit = max_chars - len(_TRUNCATION_MARKER)
    if limit <= 0:
        return _TRUNCATION_MARKER[:max_chars]
    cut = rendered.rfind("\n", 0, limit)
    if cut <= 0:
        cut = limit
    return rendered[:cut] + _TRUNCATION_MARKER


def _render_candidate(candidate: RepositoryCandidate) -> str:
    lines = [f"### `{candidate.path}`", "", _render_grounding_line(candidate)]

    enrichment = candidate.enrichment
    if enrichment is None:
        lines.append("- Enrichment: not attempted for this candidate")
        return "\n".join(lines) + "\n"

    lines.append(_render_resolution_line(enrichment))
    lines.append(_render_list_line("Direct callees", enrichment.callees, "none found"))
    lines.append(
        _render_list_line("Direct callers (call graph)", enrichment.callers_by_call_graph, "none found")
    )
    lines.append(_render_reachability_line(enrichment))
    lines.append(_render_test_support_lines(enrichment))
    lines.append(_render_sink_matches_lines(enrichment))
    lines.append(_render_enrichment_errors_line(enrichment))

    return "\n".join(lines) + "\n"


def _render_grounding_line(candidate: RepositoryCandidate) -> str:
    ordered = sorted(
        candidate.evidence,
        key=lambda e: (-(e.tier if e.tier is not None else -1), e.pass_name),
    )
    passes = ", ".join(
        f"{e.pass_name} (tier {e.tier})" if e.tier is not None else f"{e.pass_name} (tier unknown)"
        for e in ordered
    )
    best = candidate.best_tier if candidate.best_tier is not None else "unknown"
    return f"- Grounding: best tier {best}; evidence passes: {passes or 'none'}"


def _render_resolution_line(enrichment: CandidateEnrichment) -> str:
    fn = enrichment.resolved_function
    if fn is None:
        reason = enrichment.resolution_note or "not attempted"
        return f"- No function was resolved (reason: {reason})"
    name = fn.get("name", "?")
    func_id = fn.get("id", "?")
    start = fn.get("startLine")
    end = fn.get("endLine")
    span = f"lines {start}-{end}" if start is not None and end is not None else "line range unknown"
    note = f" (note: {enrichment.resolution_note})" if enrichment.resolution_note else ""
    return f"- Resolved near grounding evidence: `{name}` (id: `{func_id}`, {span}){note}"


def _render_list_line(label: str, items: list[str], empty_text: str) -> str:
    if not items:
        return f"- {label}: {empty_text}"
    shown = items[:_MAX_LIST_ITEMS]
    remainder = len(items) - len(shown)
    text = ", ".join(f"`{i}`" for i in shown)
    if remainder > 0:
        text += f" (+{remainder} more)"
    return f"- {label}: {text}"


def _render_reachability_line(enrichment: CandidateEnrichment) -> str:
    reachable = enrichment.is_reachable_from_entry_point
    if reachable is None:
        return "- Reachability: not evaluated (no investigation context available)"
    if reachable is False:
        return "- Reachability: detected as not reachable by current entry-point heuristics"

    path = enrichment.entry_point_path or []
    shown = path[:_MAX_LIST_ITEMS]
    remainder = len(path) - len(shown)
    path_text = " → ".join(f"`{p}`" for p in shown) if shown else "path unavailable"
    if remainder > 0:
        path_text += f" (+{remainder} more hop(s))"
    return f"- Reachability: detected as reachable by current entry-point heuristics (path: {path_text})"


def _render_test_support_lines(enrichment: CandidateEnrichment) -> str:
    rating_tuple = enrichment.test_support_rating
    tests = enrichment.related_tests or []
    if rating_tuple is None:
        return "- Test support: not evaluated (see enrichment errors, if any)"

    rating = rating_tuple[0] if rating_tuple else "unknown"
    lines = [f"- Test support: {rating} ({len(tests)} related test file(s))"]
    shown = tests[:_MAX_LIST_ITEMS]
    remainder = len(tests) - len(shown)
    for t in shown:
        lines.append(f"  - `{t.get('path', '?')}` ({t.get('proximity', '?')})")
    if remainder > 0:
        lines.append(f"  - (+{remainder} more test file(s))")
    return "\n".join(lines)


def _render_sink_matches_lines(enrichment: CandidateEnrichment) -> str:
    sinks = enrichment.sink_matches
    if sinks is None:
        return "- Sink matches: not evaluated (vulnerability class not recognized, or not attempted)"
    if not sinks:
        return "- Sink matches: none found"

    lines = [f"- Sink matches: {len(sinks)} found"]
    shown = sinks[:_MAX_LIST_ITEMS]
    remainder = len(sinks) - len(shown)
    for s in shown:
        method = s.get("method") or "module level"
        lines.append(f"  - `{s.get('file', '?')}`:{s.get('line', '?')} in `{method}`")
    if remainder > 0:
        lines.append(f"  - (+{remainder} more sink match(es))")
    return "\n".join(lines)


def _render_enrichment_errors_line(enrichment: CandidateEnrichment) -> str:
    errors = enrichment.enrichment_errors
    if not errors:
        return "- Enrichment errors: none"

    shown = errors[:_MAX_LIST_ITEMS]
    remainder = len(errors) - len(shown)
    lines = ["- Enrichment errors:"]
    for e in shown:
        lines.append(f"  - {e}")
    if remainder > 0:
        lines.append(f"  - (+{remainder} more)")
    return "\n".join(lines)


def _render_relationships(relationships: list[CandidateRelationship]) -> str:
    lines = ["### Structural relationships", ""]
    if not relationships:
        lines.append("None detected.")
        return "\n".join(lines) + "\n"

    shown = relationships[:_MAX_LIST_ITEMS]
    remainder = len(relationships) - len(shown)
    for rel in shown:
        lines.append(
            f"- `{rel.from_path}` → `{rel.to_path}` -- direct call-graph relationship "
            f"(via `{rel.detail}`)"
        )
    if remainder > 0:
        lines.append(f"- (+{remainder} more relationship(s))")
    return "\n".join(lines) + "\n"


def _render_notes(understanding: RepositoryUnderstanding) -> str:
    """Renders fusion_notes minus the entries already covered by their own
    dedicated sections -- relationship echoes (see Structural relationships,
    above) and the investigation-context-unavailable note (see Investigation
    context, below) -- so the same fact is never stated twice in one
    rendered block."""
    relationship_texts = {_relationship_note(r) for r in understanding.relationships}
    other_notes = [
        n
        for n in understanding.fusion_notes
        if n not in relationship_texts and not n.startswith("investigation context unavailable")
    ]

    lines = ["### Notes", ""]
    if not other_notes:
        lines.append("None.")
        return "\n".join(lines) + "\n"

    shown = other_notes[:_MAX_LIST_ITEMS]
    remainder = len(other_notes) - len(shown)
    for n in shown:
        lines.append(f"- {n}")
    if remainder > 0:
        lines.append(f"- (+{remainder} more)")
    return "\n".join(lines) + "\n"


def _render_investigation_context(available: bool) -> str:
    lines = ["### Investigation context", ""]
    if available:
        lines.append("Investigation context was available for this run.")
    else:
        lines.append(
            "Investigation context unavailable -- candidates were enriched in degraded, "
            "file/test/sink-only mode (no parse/call-graph/reachability)."
        )
    return "\n".join(lines) + "\n"
