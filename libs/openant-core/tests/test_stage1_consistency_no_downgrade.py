"""F-KB-1a regression: Stage-1 pattern-consistency must NOT silently downgrade a
surfaced (VULNERABLE/BYPASSABLE) finding to SAFE/PROTECTED.

At Stage 1 there is no per-finding exploit evidence — only pattern similarity, the
weakest signal in the pipeline. Letting it overwrite a vulnerable verdict to safe is a
silent security false-negative (the scan reports clean). The guard blocks downgrades,
records the rejected suggestion for audit, and leaves upgrades/lateral moves untouched.
"""
from utilities import stage1_consistency as s1

# Two route keys that normalize to one grouping key: client_utils.py:*_async_httpx_client
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


def test_route_keys_group_together():
    assert s1._extract_function_signature_pattern(VULN_RK) == \
        s1._extract_function_signature_pattern(SAFE_RK)


def test_vulnerable_not_downgraded_to_safe_by_pattern():
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "async httpx client builder", "SAFE",
            [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
              "should_be": "SAFE", "reason": "resembles safe sibling"}], "grouped")
    out = _run(resolver, [
        {"route_key": VULN_RK, "verdict": "VULNERABLE", "confidence": 0.9},
        {"route_key": SAFE_RK, "verdict": "SAFE", "confidence": 0.8}])
    vuln = next(r for r in out if r["route_key"] == VULN_RK)
    assert vuln["verdict"] == "VULNERABLE"                     # not silenced
    assert "stage1_consistency_downgrade_blocked" in vuln       # audit trail kept


def test_legitimate_upgrade_still_applies():
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "VULNERABLE",
            [{"route_key": SAFE_RK, "should_be": "VULNERABLE",
              "reason": "sibling is exploitable"}], "x")
    out = _run(resolver, [
        {"route_key": VULN_RK, "verdict": "VULNERABLE", "confidence": 0.9},
        {"route_key": SAFE_RK, "verdict": "SAFE", "confidence": 0.8}])
    upgraded = next(r for r in out if r["route_key"] == SAFE_RK)
    assert upgraded["verdict"] == "VULNERABLE"                  # upgrades flow freely
