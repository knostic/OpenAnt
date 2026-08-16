"""FIX4 RED: Stage-1 pattern-consistency must also block VULNERABLE/BYPASSABLE ->
INCONCLUSIVE, not only ->SAFE/PROTECTED. `inconclusive` is a disclosure-dropped
verdict (core/verdict_taxonomy.py DISCLOSURE_DROPPED), so a weak-signal pattern
downgrade to INCONCLUSIVE silently drops a real finding from disclosure — the same
false-negative F-KB-1a exists to prevent. Also guards the .upper() case invariant.
"""
from utilities import stage1_consistency as s1

VULN_RK = "libs/a/client_utils.py:build_async_httpx_client"
SAFE_RK = "libs/b/client_utils.py:get_async_httpx_client"


def _run(resolver, results):
    orig = s1._resolve_stage1_inconsistency
    s1._resolve_stage1_inconsistency = resolver
    try:
        return s1.run_stage1_consistency_check(
            [dict(r) for r in results], {}, binding=object(), tracker=None)
    finally:
        s1._resolve_stage1_inconsistency = orig


def test_vulnerable_not_downgraded_to_inconclusive_by_pattern():
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "async httpx client builder", "INCONCLUSIVE",
            [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
              "should_be": "INCONCLUSIVE", "reason": "pattern resembles uncertain sibling"}],
            "grouped")
    out = _run(resolver, [
        {"route_key": VULN_RK, "verdict": "VULNERABLE", "confidence": 0.9},
        {"route_key": SAFE_RK, "verdict": "SAFE", "confidence": 0.8}])
    vuln = next(r for r in out if r["route_key"] == VULN_RK)
    assert vuln["verdict"] == "VULNERABLE", "INCONCLUSIVE downgrade silently dropped a real finding"
    assert "stage1_consistency_downgrade_blocked" in vuln


def test_bypassable_not_downgraded_to_inconclusive():
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "INCONCLUSIVE",
            [{"route_key": VULN_RK, "original_verdict": "BYPASSABLE",
              "should_be": "INCONCLUSIVE", "reason": "x"}], "g")
    out = _run(resolver, [
        {"route_key": VULN_RK, "verdict": "BYPASSABLE", "confidence": 0.9},
        {"route_key": SAFE_RK, "verdict": "SAFE", "confidence": 0.8}])
    vuln = next(r for r in out if r["route_key"] == VULN_RK)
    assert vuln["verdict"] == "BYPASSABLE"
    assert "stage1_consistency_downgrade_blocked" in vuln


def test_dropped_to_dropped_still_applies_not_overblocked():
    """Guard must fire only on an ELIGIBLE->DROPPED crossing. A safe->inconclusive
    move (dropped->dropped, no disclosure change) must NOT be blocked, proving the
    ELIGIBLE-keyed old-side did not over-block ordinary non-eligible corrections."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "INCONCLUSIVE",
            [{"route_key": SAFE_RK, "original_verdict": "SAFE",
              "should_be": "INCONCLUSIVE", "reason": "x"}], "g")
    out = _run(resolver, [
        {"route_key": VULN_RK, "verdict": "VULNERABLE", "confidence": 0.9},
        {"route_key": SAFE_RK, "verdict": "SAFE", "confidence": 0.8}])
    safe = next(r for r in out if r["route_key"] == SAFE_RK)
    assert "stage1_consistency_downgrade_blocked" not in safe


def test_whitespace_padded_downgrade_still_blocked():
    """sol-caught: should_be must be .strip()'d before the guard compares, or a padded
    '  inconclusive  ' bypasses the block AND is written as an invalid verdict (Stage-2
    strips; Stage-1 must too)."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "INCONCLUSIVE",
            [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
              "should_be": "  inconclusive  ", "reason": "x"}], "g")
    out = _run(resolver, [
        {"route_key": VULN_RK, "verdict": "VULNERABLE", "confidence": 0.9},
        {"route_key": SAFE_RK, "verdict": "SAFE", "confidence": 0.8}])
    vuln = next(r for r in out if r["route_key"] == VULN_RK)
    assert vuln["verdict"] == "VULNERABLE", "padded verdict bypassed the guard"
    assert "stage1_consistency_downgrade_blocked" in vuln


def test_case_invariant_safe_still_blocked():
    """Regression lock: the guard compares UPPERCASE; ensure adding INCONCLUSIVE did
    not break the existing SAFE block (e.g. via a lowercase-set import mistake)."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "SAFE",
            [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
              "should_be": "safe", "reason": "x"}], "g")  # lowercase input -> .upper()
    out = _run(resolver, [
        {"route_key": VULN_RK, "verdict": "VULNERABLE", "confidence": 0.9},
        {"route_key": SAFE_RK, "verdict": "SAFE", "confidence": 0.8}])
    vuln = next(r for r in out if r["route_key"] == VULN_RK)
    assert vuln["verdict"] == "VULNERABLE"
    assert "stage1_consistency_downgrade_blocked" in vuln
