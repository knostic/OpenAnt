"""Repository Grounding domain objects.

Pure data only — no I/O, no discovery/ranking/selection/rendering logic.
See ``repo_locator.py`` for the algorithm that populates these directly
from its own canonical state (``candidates``/``best``/``ranked`` and the
real selection/rendering variables) — independent of that module's
debug-only ``_debug_raw_candidates``/``_debug_by_file`` structures.

Only DiscoveryEvidence is modeled: it is the only Evidence kind today's
passes actually produce. Repository-Relative and Structural Evidence are
not computed anywhere yet and are deliberately not represented here.
"""

from __future__ import annotations

from dataclasses import dataclass


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
class RepositoryCandidate:
    """One discovered file and everything known about it."""
    path: str
    evidence: list[DiscoveryEvidence]
    best_tier: "int | None"


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
