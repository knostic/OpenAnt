"""Disclosure-bypass FN: Stage-2 pattern-consistency must NOT silently downgrade a
conclusively-EXPLOITABLE finding to ANY disclosure-dropping verdict.

The anti-downgrade guard (``_has_conclusive_exploitable_path`` call site in
``_check_consistency``) originally blocked only ``{"safe", "protected"}``. But
``core.verdict_taxonomy.DISCLOSURE_DROPPED == {rejected, safe, protected,
inconclusive}`` — a consistency downgrade to ``inconclusive`` or ``rejected``
suppresses the finding from disclosure IDENTICALLY while BYPASSING the guard.
That is a silent security false-negative.

The guard's block-set must equal DISCLOSURE_DROPPED (referenced, not hardcoded)
so the two sets cannot drift apart again. These tests pin every dropping verdict
and assert a legit downgrade of a NON-exploitable finding still succeeds.
"""
from core.verdict_taxonomy import DISCLOSURE_DROPPED
from utilities.finding_verifier import FindingVerifier, ConsistencyCheckResult


def _verifier():
    v = FindingVerifier.__new__(FindingVerifier)
    v._use_logger = False
    v.verbose = False
    return v


FILE = "pkg/logger/console.go"
EXPLOIT_RK = f"{FILE}:runMsg.json"    # -> *Msg.json (groups with the safe sibling)
SIB_RK = f"{FILE}:infoMsg.json"

_EXPLOIT_V = {"correct_finding": "vulnerable",
              "exploit_path": {"entry_point": "h", "sink_reached": True,
                               "attacker_control_at_sink": "full", "path_broken_at": None}}


def _run_downgrade(downgrade_to):
    v = _verifier()
    v._resolve_inconsistency = lambda group, cbr: ConsistencyCheckResult(
        "logger json emitter", downgrade_to,
        [{"route_key": EXPLOIT_RK, "should_be": downgrade_to, "reason": "sibling pattern"}], "x")
    out = v._check_consistency([
        {"route_key": EXPLOIT_RK, "finding": "vulnerable", "verification": dict(_EXPLOIT_V)},
        {"route_key": SIB_RK, "finding": downgrade_to,
         "verification": {"correct_finding": downgrade_to}}], {})
    return next(r for r in out if r["route_key"] == EXPLOIT_RK)


def test_exploitable_not_downgraded_to_inconclusive():
    got = _run_downgrade("inconclusive")
    verdict = got.get("verification", {}).get("correct_finding") or got.get("finding")
    assert verdict == "vulnerable", f"exploitable finding was dropped to {verdict!r}"
    assert "consistency_downgrade_blocked" in got


def test_exploitable_not_downgraded_to_rejected():
    # #448 (wave r1): "rejected" is now rejected by the VALIDITY gate first
    # (it is not in FINDING_VERDICT_ORDER — no producer writes it into
    # `finding`), so the breadcrumb is consistency_invalid_verdict_blocked;
    # the outcome contract is unchanged — preserved + audited.
    got = _run_downgrade("rejected")
    verdict = got.get("verification", {}).get("correct_finding") or got.get("finding")
    assert verdict == "vulnerable", f"exploitable finding was dropped to {verdict!r}"
    assert ("consistency_downgrade_blocked" in got
            or "consistency_invalid_verdict_blocked" in got)


def test_exploitable_not_downgraded_to_any_disclosure_dropped_verdict():
    # Full sweep: no verdict in DISCLOSURE_DROPPED may silently drop the finding.
    # #448 (wave r1): values NOT in the correctable vocabulary (rejected) now
    # take the invalid-verdict branch — either breadcrumb satisfies the
    # preserved+audited contract.
    for dv in sorted(DISCLOSURE_DROPPED):
        got = _run_downgrade(dv)
        verdict = got.get("verification", {}).get("correct_finding") or got.get("finding")
        assert verdict == "vulnerable", f"downgrade to {dv!r} silently dropped the finding"
        assert ("consistency_downgrade_blocked" in got
                or "consistency_invalid_verdict_blocked" in got), (
            f"no audit breadcrumb for {dv!r}")


def test_non_exploitable_downgrade_still_applies():
    # Regression guard against over-blocking: a finding with NO conclusive exploit
    # path (neither broken nor exploitable) must still be consistency-downgraded.
    v = _verifier()
    v._resolve_inconsistency = lambda group, cbr: ConsistencyCheckResult(
        "logger", "inconclusive",
        [{"route_key": EXPLOIT_RK, "should_be": "inconclusive", "reason": "no path"}], "x")
    out = v._check_consistency([
        {"route_key": EXPLOIT_RK, "finding": "vulnerable",
         "verification": {"correct_finding": "vulnerable"}},   # no exploit_path -> not conclusive
        {"route_key": SIB_RK, "finding": "inconclusive",
         "verification": {"correct_finding": "inconclusive"}}], {})
    got = next(r for r in out if r["route_key"] == EXPLOIT_RK)
    verdict = got.get("verification", {}).get("correct_finding") or got.get("finding")
    assert verdict == "inconclusive", f"legit downgrade was over-blocked (verdict={verdict!r})"
    assert "consistency_downgrade_blocked" not in got
