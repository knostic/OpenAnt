"""Regression tests for issue #296 — the conclusive-exploit-path guards
test a free-text explanation string; the structured signal
(``verification["incomplete"]``) sits unused on the same object.

Scope of this change (the issue's lower-risk items, explicitly NOT the
direction-aware behavior change the maintainer raised as an open question):

1. The matched marker is a NAMED constant (``INCOMPLETE_VERIFICATION_MARKER``)
   with the match set UNCHANGED — widening it is the false-negative direction
   for BOTH guards and must wait for the direction-awareness analysis.
2. The ASYMMETRY is pinned (the issue's suggested test 3): an INCOMPLETE
   verification carrying an INTACT exploit path must still leave
   ``_has_conclusive_exploitable_path`` True — the downgrade into
   DISCLOSURE_DROPPED stays BLOCKED. Whatever future fix makes the guards
   signal-aware, it must not let an unfinished verification become the
   reason a finding is downgraded out of disclosure.
3. The guards' current behavior on the marker and on the constructed
   defect input is characterized so any change forces a conscious decision.
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


def test_characterization_incomplete_broken_path_is_the_open_defect():
    """CHARACTERIZATION (the open defect, pinned so any change is a
    conscious decision): incomplete:True + BROKEN path + model-authored
    explanation reads as conclusive today, suppressing a consistency
    correction. #296's traced constraint: the obvious tightening re-opens
    the disclosure FN via the consistency update at :918 — the fix must be
    direction-aware (skip only for non-downgrade updates). Changing this
    assertion without that analysis is exactly what #296 warns against."""
    v = {"incomplete": True, "explanation": _MODEL_TEXT,
         "exploit_path": dict(_BROKEN)}
    assert _exploit_path(v) is True, (
        "KNOWN DEFECT (see #296): an incomplete verification's broken path "
        "currently suppresses corrections — fix requires direction-awareness")


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
