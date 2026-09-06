"""Regression tests for issue #296 — the conclusive-path guards and the
incomplete-verification signal, at the call site (the direction-aware fix,
landed in this PR after the issue's own 2026-08-21 re-scoping):

1. The matched marker is a NAMED constant (``INCOMPLETE_VERIFICATION_MARKER``)
   — it stays as the legacy arm covering rows that predate the structured
   flag.
2. The raw helpers below are SHAPE-ONLY characterizations (both still
   free-text/marker-driven by design — the incomplete-awareness lives at the
   consistency CALL SITE, not in the helpers, so the #195/#243 mirror
   contract is untouched).
3. The call-site behavior: an INCOMPLETE verification never vetoes a
   correction (arm 1) and never drops out of disclosure (arm 2 — a
   correction into any DISCLOSURE_DROPPED verdict is blocked with an audit
   record carrying ``incomplete: True``); the incomplete flag survives an
   allowed correction (pinned).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.finding_verifier import (  # noqa: E402
    INCOMPLETE_VERIFICATION_MARKER,
    FindingVerifier,
)

_INTACT = {"entry_point": "h", "sink_reached": True,
           "attacker_control_at_sink": "full", "path_broken_at": None}
_BROKEN = {"sink_reached": False, "attacker_control_at_sink": "none",
           "path_broken_at": "validated at :112"}

_MODEL_TEXT = ("I traced the path but could not confirm the sink guard.")


def _exploit_path(verification):
    return FindingVerifier._has_conclusive_exploit_path(
        None, {"verification": verification})


def _exploitable(verification):
    return FindingVerifier._has_conclusive_exploitable_path(
        None, {"verification": verification})


def test_marker_constant_is_exactly_todays_match_set():
    """The constant must not widen the match set: more markers => both
    guards return False more often => the traced FN direction (Stage-1
    verdict protection lost; downgrade block lost). Widening requires the
    direction-aware fix first (#296)."""
    assert INCOMPLETE_VERIFICATION_MARKER == "Max iterations reached"


def test_marker_still_disqualifies_both_guards():
    v = {"explanation": INCOMPLETE_VERIFICATION_MARKER,
         "exploit_path": dict(_BROKEN)}
    assert _exploit_path(v) is False
    v2 = {"explanation": INCOMPLETE_VERIFICATION_MARKER,
          "exploit_path": dict(_INTACT)}
    assert _exploitable(v2) is False


def test_asymmetry_incomplete_intact_path_blocks_downgrade():
    """The issue's suggested test 3: incomplete:True + intact path +
    model-authored explanation (the _parse_finish_result shape) — the
    MIRROR guard must stay True so the DISCLOSURE_DROPPED downgrade is
    blocked. This is the protective outcome PR #195/#243 established; any
    signal-aware rework must preserve it."""
    v = {"incomplete": True, "explanation": _MODEL_TEXT,
         "exploit_path": dict(_INTACT)}
    assert _exploitable(v) is True, (
        "an incomplete verification with an intact, attacker-controlled "
        "path must still block the downgrade — the protective direction")
    # and the broken-path guard is not involved (an intact path is not
    # conclusively broken)
    assert _exploit_path(v) is False


def test_characterization_incomplete_broken_path_helper_still_marker_driven():
    """CHARACTERIZATION (the helper's shape contract, unchanged by the fix):
    incomplete:True + BROKEN path + model-authored explanation still reads
    as conclusive to the RAW helper — the incomplete-awareness lives at the
    consistency call site (which skips the helper for incomplete rows), not
    in the helper itself, so the #195/#243 mirror contract is untouched."""
    v = {"incomplete": True, "explanation": _MODEL_TEXT,
         "exploit_path": dict(_BROKEN)}
    assert _exploit_path(v) is True, (
        "the raw helper must stay marker-driven (the #195/#243 contract); "
        "incomplete-awareness belongs to the call site")


def _verifier():
    v = FindingVerifier.__new__(FindingVerifier)
    v._use_logger = False
    v.verbose = False
    return v


def test_e2e_incomplete_intact_path_downgrade_still_blocked():
    """The asymmetry at the call site: a downgrade proposal into a
    DISCLOSURE_DROPPED verdict is still blocked for an INCOMPLETE
    verification with an intact exploit path (PR #243's protection,
    surviving #296's signal-awareness question)."""
    from utilities.finding_verifier import ConsistencyCheckResult

    v = _verifier()
    rk = "pkg/logger/console.go:runMsg.json"
    sibling = "pkg/logger/console.go:infoMsg.json"
    v._resolve_inconsistency = lambda group, cbr: ConsistencyCheckResult(
        "logger json emitter", "safe",
        [{"route_key": rk, "should_be": "safe", "reason": "looks safe"}], "x")
    incomplete_v = {"incomplete": True, "correct_finding": "vulnerable",
                    "explanation": _MODEL_TEXT,
                    "exploit_path": dict(_INTACT)}
    out = v._check_consistency([
        {"route_key": rk, "finding": "vulnerable",
         "verification": incomplete_v},
        {"route_key": sibling, "finding": "safe",
         "verification": {"correct_finding": "safe"}}], {})
    got = next(r for r in out if r["route_key"] == rk)
    assert got.get("finding") == "vulnerable", "the downgrade was applied!"
    assert "consistency_downgrade_blocked" in got
    assert got["consistency_downgrade_blocked"]["incomplete"] is True


# ---------------------------------------------------------------------------
# #296's direction-aware fix (adjudicated round 3): the finish-path window.
# _parse_finish_result can mark a verification incomplete WHILE preserving a
# populated exploit_path and model-authored explanation (agree-missing,
# self-contradictory finishes) — the string-marker test passes and the
# incomplete evidence vetoes a CORRECTION. The structured signal exists on
# the same object: verification["incomplete"].
# ---------------------------------------------------------------------------

def test_finish_path_incomplete_with_populated_path_allows_correction():
    """#296's fix: an agree-missing finish (incomplete=True, populated
    BROKEN exploit_path, model text != the marker) must NOT count as a
    conclusive exploit path — pre-fix it did (the broken-path conclusive
    check vetoed), and the unfinished evidence suppressed the correction.
    Route keys follow the *Msg grouping the pattern detector uses; the
    proposal (vulnerable -> bypassable) stays inside DISCLOSURE_ELIGIBLE,
    so the disclosure-drop guard is not the thing under test here. The
    incomplete flag SURVIVES the correction: a consistency opinion is not
    a completed verification."""
    from utilities.finding_verifier import ConsistencyCheckResult
    v = _verifier()
    rk = "app/api/handler.go:serveMsg.json"
    sibling = "app/api/handler.go:helperMsg.json"
    v._resolve_inconsistency = lambda group, cbr: ConsistencyCheckResult(
        "handler", "bypassable",
        [{"route_key": rk, "should_be": "bypassable", "reason": "consistent"}], "x")
    agree_missing_v = {
        "incomplete": True,  # the structured signal the guard now reads
        "correct_finding": "vulnerable",  # the group IS inconsistent (sibling says bypassable)
        "explanation": _MODEL_TEXT,  # model text — not the marker
        "exploit_path": dict(_BROKEN),  # populated, BROKEN — the finish-path shape
    }
    out = v._check_consistency([
        {"route_key": rk, "finding": "vulnerable",
         "verification": agree_missing_v},
        {"route_key": sibling, "finding": "bypassable",
         "verification": {"correct_finding": "bypassable"}}], {})
    got = next(r for r in out if r["route_key"] == rk)
    assert got.get("finding") == "bypassable", (
        "the incomplete finish-path window still vetoed the correction "
        "(the guard treats incomplete-but-populated evidence as "
        "conclusive)")
    assert got["verification"]["incomplete"] is True, (
        "the correction must not clear the incomplete flag — a "
        "consistency opinion is not a completed verification")


def test_incomplete_correction_may_not_drop_disclosure():
    """The astra-round guard: once the veto is lifted, a correction of an
    INCOMPLETE verification into any DISCLOSURE_DROPPED verdict must be
    blocked (mirroring the conclusive-exploitable block) — the mirror guard
    alone cannot catch broken-path shapes (its return requires a reached
    sink, attacker control, and no break). On pristine master the
    broken-path conclusive check silently blocked the correction with NO
    audit record; fix-(1)-alone would let it through — this guard is what
    keeps the block, now with a record."""
    from utilities.finding_verifier import ConsistencyCheckResult
    v = _verifier()
    rk = "app/api/admin.go:deleteMsg.json"
    sibling = "app/api/admin.go:listMsg.json"
    v._resolve_inconsistency = lambda group, cbr: ConsistencyCheckResult(
        "admin handlers", "safe",
        [{"route_key": rk, "should_be": "inconclusive", "reason": "pattern"}], "x")
    incomplete_broken_v = {
        "incomplete": True,
        "correct_finding": "vulnerable",  # inconsistent with the sibling's safe
        "explanation": _MODEL_TEXT,
        "exploit_path": dict(_BROKEN),  # BROKEN — the mirror returns False on this shape
    }
    out = v._check_consistency([
        {"route_key": rk, "finding": "vulnerable",
         "verification": incomplete_broken_v},
        {"route_key": sibling, "finding": "safe",
         "verification": {"correct_finding": "safe"}}], {})
    got = next(r for r in out if r["route_key"] == rk)
    assert got.get("finding") == "vulnerable", (
        "an incomplete verification was corrected into a disclosure-"
        "dropping verdict (inconclusive is in DISCLOSURE_DROPPED) with no block")
    assert "consistency_downgrade_blocked" in got
    assert got["consistency_downgrade_blocked"]["incomplete"] is True
