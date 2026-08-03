"""Repository Grounding domain objects.

Pure data only — no I/O, no discovery/ranking/selection/rendering logic.
See ``repo_locator.py`` for the algorithm that populates these directly
from its own canonical state (``candidates``/``best``/``ranked`` and the
real selection/rendering variables) — independent of that module's
debug-only ``_debug_raw_candidates``/``_debug_by_file`` structures.

Only DiscoveryEvidence is modeled: it is the only Evidence kind today's
passes actually produce. Repository-Relative and Structural Evidence are
not computed anywhere yet and are deliberately not represented here.

``CandidateEnrichment`` is a later, optional addition (populated by
``utilities/autopatcher/candidate_enrichment.py``): deterministic
repository facts about one ``RepositoryCandidate``, gathered from the
existing parser/call-graph/reachability/test-discovery machinery. It is
attached via ``RepositoryCandidate.enrichment`` rather than wrapping the
candidate in a second model — a candidate without it behaves exactly as
it always has.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DiscoveryEvidence:
    """One pass's raw contribution to a candidate."""
    pass_name: str
    tier: "int | None"
    matched_tokens: "dict | None"
    total_occurrences: "int | None"
    hit_line: "int | None"
    resolution_strategy: "str | None"


@dataclass
class CandidateEnrichment:
    """Deterministic repository facts about one RepositoryCandidate.

    No LLM output, no vulnerability verdict, no confidence score anywhere
    here — every field is either a verbatim existing function's return
    value or an explicit, honest reason nothing was resolved. ``None``
    means "not attempted / not applicable"; ``[]`` means "attempted, found
    nothing" — the two are never conflated.
    """

    functions_in_file: list[dict] = field(default_factory=list)
    resolved_function: "dict | None" = None
    resolution_note: "str | None" = None

    callees: list[str] = field(default_factory=list)
    callers_by_call_graph: list[str] = field(default_factory=list)
    callers_by_text_search: list[dict] = field(default_factory=list)

    is_reachable_from_entry_point: "bool | None" = None
    entry_point_path: "list[str] | None" = None

    related_tests: list[dict] = field(default_factory=list)
    test_support_rating: "tuple | None" = None

    sink_matches: "list[dict] | None" = None

    # Module-level and class-level literal assignments in scope for this
    # candidate (see candidate_enrichment.InvestigationContext.constants).
    # Each dict: {"qualified_name", "class_name", "name", "outcome"
    # ("literal"|"non_literal"|"augmented_assign"|"unsupported_target"|
    # "annotation_only"), "ast_literal_kind", "value", "line", "end_line"}.
    # [] means "no context, or no literal assignments found" -- there is
    # no separate "not applicable" case beyond a parse failure, which
    # already routes to enrichment_errors like every other concern here.
    scope_constants: list[dict] = field(default_factory=list)

    enrichment_errors: list[str] = field(default_factory=list)


@dataclass
class RepositoryCandidate:
    """One discovered file and everything known about it.

    ``enrichment`` is optional and additive: a candidate produced by
    ``repo_locator.py`` today has ``enrichment=None`` and behaves exactly
    as before this field existed. Setting it never changes ``path``,
    ``evidence``, or ``best_tier`` — those remain the sole grounding/
    ranking inputs (see ``candidate_selection.py``).
    """
    path: str
    evidence: list[DiscoveryEvidence]
    best_tier: "int | None"
    enrichment: "CandidateEnrichment | None" = None


@dataclass
class GroundingDecision:
    """The outcome for one candidate. References its candidate by path;
    is never embedded inside RepositoryCandidate."""
    path: str
    outcome: str  # exact selection_outcome values find_code_context() already produces
    snippet_ranges: "list | None"  # shape exactly as find_code_context() stores it today
    bytes_contributed: int
    truncated: bool


@dataclass
class RepositoryGroundingResult:
    """The full record of one find_code_context() call."""
    rendered_context: str
    candidates: list[RepositoryCandidate]
    decisions: list[GroundingDecision]
    extraction_signals: dict
    budget: "dict | None"
