"""#331: a Stage-1 consistency correction writes BOTH keys — gated on eligibility.

When the Stage-1 consistency pass corrects a unit's verdict it wrote `result["verdict"]`
and never `result["finding"]`. Ingestion (core/analyzer.py:149-152) always sets a
lowercase `finding`, and every canonical downstream read is finding-first —
`str(r.get("finding") or r.get("verdict", "")).lower()` (core/verifier.py:118) — so the
stale `finding` short-circuited the `or` and the correction was invisible: a
safe -> VULNERABLE correction left {finding: "safe", verdict: "VULNERABLE"}, counted
safe, filtered out of Stage 2 entirely, absent from the disclosure document.

The second edge points the other way: the stale finding also survives a downgrade to
a verdict the block-list does not cover — `DISCLOSURE_DROPPED` is
{inconclusive, protected, rejected, safe}, so `VULNERABLE -> INSUFFICIENT_CONTEXT`
passes unblocked, and today the stale `finding` is an ACCIDENTAL SAFETY NET keeping the
row disclosed. An ungated write of `finding` would remove that net and drop a disclosed
vulnerability (measured in the issue: VULNERABLE -> INSUFFICIENT_CONTEXT /
NOT_VULNERABLE both move out of `confirmed` under the naive fix).

So the write is GATED: `finding` is updated only when the new verdict is
disclosure-eligible (DISCLOSURE_ELIGIBLE); unrecognised downgrades keep the stale
finding (still disclosed via the net) with the correction recorded in
`stage1_consistency_update`.
"""
from core.analyzer import _count_verdicts
from core.verdict_taxonomy import DISCLOSURE_ELIGIBLE
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


def _by_rk(out, rk):
    return next(r for r in out if r["route_key"] == rk)


def _canonical(r):
    """The finding-first canonical downstream read (core/verifier.py:118)."""
    return str(r.get("finding") or r.get("verdict", "")).lower()


INGESTED_SAFE = {"route_key": SAFE_RK, "verdict": "SAFE", "finding": "safe"}
INGESTED_VULN = {"route_key": VULN_RK, "verdict": "VULNERABLE", "finding": "vulnerable"}


def test_safe_to_vulnerable_correction_lands():
    """The issue's regression (1): after safe -> VULNERABLE the unit is in
    _count_verdicts' vulnerable bucket and reads 'vulnerable' canonically
    (in confirmed / the Stage-2 input gate)."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "async httpx client builder", "VULNERABLE",
            [{"route_key": SAFE_RK, "original_verdict": "SAFE",
              "should_be": "VULNERABLE", "reason": "pattern identical to vulnerable sibling"}],
            "grouped")
    out = _run(resolver, [INGESTED_SAFE, INGESTED_VULN])
    row = _by_rk(out, SAFE_RK)
    assert row["verdict"] == "VULNERABLE"
    assert row["finding"] == "vulnerable", (
        "the correction must write BOTH keys — finding-first reads shadow a "
        f"verdict-only write: {row}"
    )
    counts = _count_verdicts(out)
    assert counts["vulnerable"] == 2 and counts["safe"] == 0, (
        f"the corrected unit must count vulnerable (pre-fix: safe=1, vulnerable=0): {counts}"
    )
    assert _canonical(row) == "vulnerable"


def test_unrecognised_downgrade_keeps_disclosure():
    """The issue's regression (2): VULNERABLE -> INSUFFICIENT_CONTEXT is NOT
    in F-KB-1a's block-set — the row must REMAIN disclosed. On #331 alone the
    net was the STALE FINDING (verdict moved, finding kept); stacked with
    #425's validity gate the proposal is REJECTED WHOLESALE — a stronger
    preservation with no split-brain row (wave r1 fable+sonnet: the pass is
    never asked for INSUFFICIENT_CONTEXT — its enum is
    VULNERABLE | SAFE | INCONCLUSIVE)."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "INSUFFICIENT_CONTEXT",
            [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
              "should_be": "INSUFFICIENT_CONTEXT", "reason": "x"}], "g")
    out = _run(resolver, [INGESTED_VULN, INGESTED_SAFE])
    row = _by_rk(out, VULN_RK)
    # the row is preserved UNCHANGED — the strongest form of disclosure.
    assert row["verdict"] in ("INSUFFICIENT_CONTEXT", "VULNERABLE"), row
    assert row["finding"] == "vulnerable"
    assert _canonical(row) == "vulnerable", (
        "an ungated write would drop this disclosed vulnerability"
    )
    counts = _count_verdicts(out)
    assert counts["vulnerable"] == 1, (
        f"the row must still count vulnerable (the net): {counts}"
    )


def test_gate_writes_finding_only_when_eligible():
    """The gate itself: safe -> INCONCLUSIVE (dropped->dropped, unblocked by
    F-KB-1a's old-side scope) writes verdict but NOT finding — an ineligible
    verdict never lands in the canonical read."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "INCONCLUSIVE",
            [{"route_key": SAFE_RK, "original_verdict": "SAFE",
              "should_be": "INCONCLUSIVE", "reason": "x"}], "g")
    out = _run(resolver, [INGESTED_VULN, INGESTED_SAFE])
    row = _by_rk(out, SAFE_RK)
    assert row["verdict"] == "INCONCLUSIVE"
    assert row["finding"] == "safe", (
        "ineligible new verdicts must not rewrite finding (the write is gated "
        "on DISCLOSURE_ELIGIBLE)"
    )


def test_verdict_only_row_counts_via_verdict_fallback():
    """Prior-art pin (test_verifier_verdictonly_confirmed_drop's domain): a row
    with NO finding key still counts via the verdict fallback — the fix must
    not narrow #324's absent-key handling."""
    counts = _count_verdicts([
        {"route_key": "a", "verdict": "VULNERABLE", "finding": None},
        {"route_key": "b", "verdict": None, "finding": None},
    ])
    assert counts["vulnerable"] == 1
    assert counts["errors"] == 1


def test_stage2_vocabulary_keeps_the_net():
    """Wave r1 (three axes, one root cause): DISCLOSURE_ELIGIBLE admitted
    Stage-2 vocabulary the finding-first readers REJECT — a
    VULNERABLE -> UNVERIFIED correction wrote finding="unverified" and
    dropped a disclosed vulnerability from Stage-2 input, confirmed_findings,
    and disclosure: the net's own failure mode reintroduced through the gate."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "UNVERIFIED",
            [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
              "should_be": "UNVERIFIED", "reason": "x"}], "g")
    out = _run(resolver, [INGESTED_VULN, INGESTED_SAFE])
    row = _by_rk(out, VULN_RK)
    # (stacked #425: the validity gate REJECTS the Stage-2 vocabulary
    # outright, so the verdict stays VULNERABLE on this branch; on #331
    # alone it wrote UNVERIFIED with the finding net. Both keep the row
    # disclosed — the invariant under test.)
    assert row["verdict"] in ("UNVERIFIED", "VULNERABLE"), row
    assert row["finding"] == "vulnerable", (
        "the Stage-2 vocabulary must keep the stale-finding net "
        f"(got {row['finding']!r})"
    )
    for token in ("CONFIRMED", "AGREED", "ERROR"):
        def r2(binding, group, code_by_route, tracker, _tok=token):
            return s1.Stage1ConsistencyResult(
                "p", _tok,
                [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
                  "should_be": _tok, "reason": "x"}], "g")
        out = _run(r2, [INGESTED_VULN, INGESTED_SAFE])
        assert _by_rk(out, VULN_RK)["finding"] == "vulnerable", token


def test_promoted_errored_row_clears_the_stale_error_key():
    """Wave r1 (fable): a promoted ERROR row kept its stale `error` key —
    one row counted as BOTH a confirmed finding (finding-first) and an error
    (r.get("error")). The gated write clears it."""
    errored = dict(INGESTED_SAFE)
    errored["verdict"] = "ERROR"
    errored["finding"] = "error"
    errored["error"] = "LLMConnectionError: DNS lookup failed"
    errored["route_key"] = VULN_RK

    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "VULNERABLE",
            [{"route_key": VULN_RK, "original_verdict": "ERROR",
              "should_be": "VULNERABLE", "reason": "pattern matches sibling"}],
            "g")
    out = _run(resolver, [errored, INGESTED_SAFE])
    row = _by_rk(out, VULN_RK)
    assert row["verdict"] == "VULNERABLE"
    assert row["finding"] == "vulnerable"
    assert "error" not in row, (
        f"the stale error key makes the promoted row count as both a finding "
        f"and an error: {row}"
    )
