"""Bounded candidate selection over existing repository-grounding output.

Phase 1 of the multi-candidate investigation design: this module decides
*which* of the candidates ``ground_repository()`` already found are worth
investigating later, and *how many* -- nothing else. It adds no discovery,
ranking, or scoring logic of its own: ordering reuses ``RepositoryCandidate.
best_tier`` verbatim (the existing repository-grounding tier, not a new
confidence/investigation/fusion score -- those are separate concepts for a
later phase, if introduced at all).

Selection proves nothing about a candidate. A ``selected`` candidate is a
repository location worth investigating later, not a confirmed vulnerable
location. The cap exists solely to bound the LLM cost, latency, and Trust
Report noise a later investigation phase would otherwise incur against an
unbounded candidate set -- no investigation happens in this module.

No LLM calls. No I/O. No environment reads. Pure data in, pure data out.
"""

from __future__ import annotations

from dataclasses import dataclass

from utilities.autopatcher.repository_grounding_models import (
    RepositoryCandidate,
    RepositoryGroundingResult,
)

DEFAULT_MAX_CANDIDATES = 3


def _is_structurally_valid(candidate: RepositoryCandidate) -> bool:
    """Defensive validity check -- not a strength/tier judgment.

    Real ``ground_repository()`` output should never fail this. It exists
    so ``excluded_by_policy`` has an honest, distinct meaning from "weak
    evidence": a candidate whose only evidence is the weakest existing tier
    (``cwe_keywords``) is still structurally valid and therefore eligible
    -- see ``select_candidates()``'s docstring for why weak evidence is
    never excluded outright, only ranked last.
    """
    return bool(candidate.path) and bool(candidate.evidence) and candidate.best_tier is not None


@dataclass
class CandidateSelection:
    """Complete accounting of one candidate-selection decision.

    Every list holds ``RepositoryCandidate`` objects directly -- no wrapper
    model is introduced in this phase. If a later phase needs
    investigation-specific metadata (e.g. a resolved symbol, a snippet), a
    dedicated model should be introduced then, scoped to what that phase
    can genuinely populate.

    Invariants (see tests):
        generated == excluded_by_policy + eligible   (as sets)
        eligible  == selected + excluded_by_cap       (as sets)
        len(selected) <= max_candidates
    """

    generated: list[RepositoryCandidate]
    excluded_by_policy: list[RepositoryCandidate]
    eligible: list[RepositoryCandidate]
    selected: list[RepositoryCandidate]
    excluded_by_cap: list[RepositoryCandidate]
    max_candidates: int

    @property
    def used_fallback(self) -> bool:
        """True iff nothing was selected.

        The caller must fall back to today's existing grounding behavior
        (``pipeline.run()``'s own internal ``ground_repository()`` call)
        rather than fail the patch run or widen the search.
        """
        return len(self.selected) == 0


def select_candidates(
    grounding: RepositoryGroundingResult,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> CandidateSelection:
    """Select a bounded, deterministically-ordered subset of
    ``grounding.candidates`` for later investigation.

    Does not investigate anything and does not call an LLM: this is pure
    selection policy over data ``ground_repository()`` already computed.

    Ordering is by the existing ``best_tier`` descending (stronger evidence
    first: ``explicit_path``=4 > ``symbol_definition``=3 >
    ``symbol_search``=2 > ``cwe_keywords``=1 -- see repo_locator.py's tier
    constants), then by ``path`` ascending as a pure, deterministic
    tie-break. Neither key depends on dict insertion order, filesystem
    traversal order, or time -- two calls against the same
    ``RepositoryGroundingResult`` always produce the same order.

    Weak evidence (e.g. a ``cwe_keywords``-only match) is never excluded
    outright: it is ranked last and only enters ``selected`` if capacity
    remains after every stronger candidate has been placed. This is
    deliberate: a broad/noisy advisory should not let weak candidates
    crowd out strong ones, but a sparse advisory with no explicit-path or
    symbol evidence should still be able to select its best available
    (weak) candidate rather than select nothing.

    ``max_candidates`` bounds how many candidates are ever selected,
    regardless of how many are eligible -- this is what prevents a broad
    or noisy advisory from producing unbounded downstream cost, latency,
    or report noise in a later phase. ``0`` is valid (selects nothing; a
    legitimate dry-run/audit mode -- ``used_fallback`` correctly reads
    True). Negative values have no sensible meaning and raise
    ``ValueError``.

    Raises:
        ValueError: if max_candidates < 0.
    """
    if max_candidates < 0:
        raise ValueError(f"max_candidates must be >= 0, got {max_candidates}")

    generated = list(grounding.candidates)
    eligible = [c for c in generated if _is_structurally_valid(c)]
    excluded_by_policy = [c for c in generated if not _is_structurally_valid(c)]

    ordered = sorted(eligible, key=lambda c: (-c.best_tier, c.path))
    selected = ordered[:max_candidates]
    excluded_by_cap = ordered[max_candidates:]

    return CandidateSelection(
        generated=generated,
        excluded_by_policy=excluded_by_policy,
        eligible=eligible,
        selected=selected,
        excluded_by_cap=excluded_by_cap,
        max_candidates=max_candidates,
    )
