"""Deterministic, read-only telemetry for Candidate 1 (content-based hunk
relocation in diff_hunk_repair.py) -- observability only.

Answers, for one generated patch against one repo_root: would `git apply`
already have accepted this patch WITHOUT content relocation (i.e. with only
the pre-existing, unrelated count-arithmetic repair applied), and does it
accept the patch WITH relocation? Combined with each hunk's own
relocation_attempted / relocation_performed / relocation_reason (recorded
by diff_hunk_repair.RepairResult.relocations), this lets a caller tell apart:

  1. git would already have accepted the patch      -> git_apply_before_relocation is True
  2. Candidate 1 actually rescued applicability       -> before is False, after is True
  3. Candidate 1 did nothing                          -> before == after (no rescue, no harm)
  4. Candidate 1 couldn't relocate safely              -> after is still False despite one or
                                                           more hunk-level relocation attempts

This module never feeds back into patch generation, retries, hygiene, or
the Recommendation Policy -- nothing downstream reads its return value
except to log/store it. It independently recomputes both repair variants
and both applicability checks from the SAME raw patch text the caller
already has, rather than reusing the pipeline's own `patch`/
`applicability_result` state, specifically so a bug in this module can
never mutate or influence the production path: build_relocation_telemetry
has no side effects (git apply --check never modifies the working tree)
and every one of its internal steps is wrapped so a failure degrades to
returning None, never raises.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from .diff_hunk_repair import repair_hunk_headers
from .patch_applicability import check_applicability
from .source_verification import classify_source_verification


@dataclass(frozen=True)
class HunkRelocationTelemetry:
    """One hunk's relocation telemetry, copied verbatim from the WITH-
    relocation repair pass's RepairResult.relocations -- see
    diff_hunk_repair.HunkRelocationRecord for field meaning."""
    file: str
    relocation_attempted: bool
    relocation_performed: bool
    relocation_reason: str
    original_hunk_start: int
    relocated_hunk_start: "int | None"


@dataclass(frozen=True)
class RelocationTelemetry:
    git_apply_before_relocation: "bool | None"
    git_apply_after_relocation: "bool | None"
    hunks: "list[HunkRelocationTelemetry]"
    # Evidence Sufficiency Gate (Phase 1) signal — see source_verification.py.
    # Computed from the SAME `hunks` list above (the WITH-relocation pass),
    # exposed here purely for visibility in this debug/telemetry artifact.
    # Observability only: nothing in this module or its caller consumes
    # this to change any decision.
    source_verification: dict

    def to_dict(self) -> dict:
        return {
            "git_apply_before_relocation": self.git_apply_before_relocation,
            "git_apply_after_relocation": self.git_apply_after_relocation,
            "hunks": [asdict(h) for h in self.hunks],
            "source_verification": self.source_verification,
        }


def build_relocation_telemetry(raw_patch: str, repo_root: "object") -> "RelocationTelemetry | None":
    """Best-effort, read-only telemetry for one generated patch.

    Parameters
    ----------
    raw_patch:
        The patch text exactly as produced by generate_patch(), BEFORE any
        repair pass -- both variants below are derived from this same raw
        input, so they are a fair apples-to-apples comparison (the
        pre-existing count-arithmetic repair applies identically to both;
        only the presence/absence of content relocation differs).
    repo_root:
        Passed straight through to repair_hunk_headers/check_applicability.

    Returns None when there is nothing meaningful to measure (no patch
    text, or no repo_root) -- never raises.
    """
    if not raw_patch or not raw_patch.strip() or not repo_root:
        return None
    try:
        # WITHOUT Candidate 1: counts-only repair, no repo_root -> no
        # relocation attempted at all (see diff_hunk_repair.py's own
        # backward-compatibility guarantee).
        before_patch, _before_meta = repair_hunk_headers(raw_patch)
        # WITH Candidate 1: the same starting text, now also relocated.
        after_patch, after_meta = repair_hunk_headers(raw_patch, repo_root=repo_root)

        before_result = check_applicability(before_patch, repo_root)
        after_result = check_applicability(after_patch, repo_root)

        hunks = [
            HunkRelocationTelemetry(
                file=record.file,
                relocation_attempted=record.relocation_attempted,
                relocation_performed=record.relocation_performed,
                relocation_reason=record.relocation_reason,
                original_hunk_start=record.original_hunk_start,
                relocated_hunk_start=record.relocated_hunk_start,
            )
            for record in after_meta.relocations
        ]

        return RelocationTelemetry(
            git_apply_before_relocation=before_result.get("applicable"),
            git_apply_after_relocation=after_result.get("applicable"),
            hunks=hunks,
            source_verification=classify_source_verification(after_meta.relocations),
        )
    except Exception:
        return None


def summarize(telemetry: "RelocationTelemetry | None") -> str:
    """One-line, human-readable summary for a stderr log line. Never
    raises; returns a fixed string when telemetry is None."""
    if telemetry is None:
        return "unavailable (no patch or no repo_root)"

    attempted = sum(1 for h in telemetry.hunks if h.relocation_attempted)
    performed = sum(1 for h in telemetry.hunks if h.relocation_performed)
    before = telemetry.git_apply_before_relocation
    after = telemetry.git_apply_after_relocation

    if before is True:
        outcome = "git already accepted it unaided"
    elif before is False and after is True:
        outcome = "RESCUED by relocation"
    elif before is False and after is False:
        outcome = "still rejected after relocation"
    else:
        outcome = "before/after applicability unavailable"

    return (
        f"{outcome} — {attempted} hunk(s) attempted, {performed} relocated "
        f"(before={before}, after={after}); source verification: "
        f"{telemetry.source_verification['value']}"
    )
