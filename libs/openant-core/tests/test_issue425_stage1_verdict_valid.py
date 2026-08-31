"""#425: a consistency correction writes only a CANONICAL verdict.

apply_stage1_consistency rewrites a Stage-1 result's `verdict` from the consistency
model's unconstrained `should_be` string — AFTER verdict normalization has run — and
the only gate before the write was the F-KB-1a downgrade block, which is correct for
its purpose but is not a VALIDITY gate: anything outside `_DISCLOSURE_DROPPED_UPPER` —
"MAYBE VULNERABLE", "probably fine" — landed in result["verdict"] verbatim. That is the
same escape #316/#324 closed at `_normalize_result` / the JSON corrector, surviving at
the one producer that runs AFTER those gates.

The fix applies the #316/#324 producer discipline to this site: validate `new_verdict`
against the Stage-1 verdict vocabulary (the `_normalize_result` finding_to_verdict map,
uppercased: VULNERABLE / SAFE / PROTECTED / BYPASSABLE / INCONCLUSIVE /
INSUFFICIENT_CONTEXT) — a value outside it is model noise, REJECTED with an audit
record (the row keeps its valid pre-consistency verdict; the proposal is visible, and
no information is destroyed by overwriting a valid verdict with garbage or with ERROR).

Stacked on #331 (the finding co-write, gated on disclosure-eligibility): a valid
correction still updates BOTH keys so finding-first consumers see it — pinned here so
the validity gate cannot over-block.
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


def _by_rk(out, rk):
    return next(r for r in out if r["route_key"] == rk)


INGESTED_SAFE = {"route_key": SAFE_RK, "verdict": "SAFE", "finding": "safe"}
INGESTED_VULN = {"route_key": VULN_RK, "verdict": "VULNERABLE", "finding": "vulnerable"}


def test_unrecognized_should_be_is_rejected_not_written():
    """The issue's executed shape: `MAYBE VULNERABLE` must NOT land in
    verdict verbatim — the row keeps its valid pre-consistency verdict, the
    proposal is audited."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "MAYBE VULNERABLE",
            [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
              "should_be": "MAYBE VULNERABLE", "reason": "x"}], "g")
    out = _run(resolver, [INGESTED_VULN, INGESTED_SAFE])
    row = _by_rk(out, VULN_RK)
    assert row["verdict"] == "VULNERABLE", (
        f"the unrecognized should_be landed in verdict verbatim: {row['verdict']!r}"
    )
    assert row["finding"] == "vulnerable"
    assert "stage1_consistency_invalid_verdict_blocked" in row, (
        "the rejected proposal must be audited (visible/countable), not silent"
    )
    assert "stage1_consistency_update" not in row


def test_lowercase_garbage_is_rejected_not_lowered_into_validity():
    """"probably fine" — a valid-looking phrase is still not a verdict."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "SAFE",
            [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
              "should_be": "probably fine", "reason": "x"}], "g")
    out = _run(resolver, [INGESTED_VULN, INGESTED_SAFE])
    row = _by_rk(out, VULN_RK)
    assert row["verdict"] == "VULNERABLE"
    assert "stage1_consistency_invalid_verdict_blocked" in row


def test_valid_upgrade_still_lands_both_keys():
    """Stack pin (#331): the validity gate must not over-block — a canonical
    safe->VULNERABLE upgrade updates verdict AND finding."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "VULNERABLE",
            [{"route_key": SAFE_RK, "original_verdict": "SAFE",
              "should_be": "VULNERABLE", "reason": "pattern matches sibling"}], "g")
    out = _run(resolver, [INGESTED_VULN, INGESTED_SAFE])
    row = _by_rk(out, SAFE_RK)
    assert row["verdict"] == "VULNERABLE"
    assert row["finding"] == "vulnerable"
    assert "stage1_consistency_update" in row


def test_canonical_intermediate_recognized_keeps_the_331_net():
    """INSUFFICIENT_CONTEXT is IN the vocabulary (the _normalize_result map):
    the correction is written to verdict, and #331's finding-gate keeps the
    stale finding (the accidental safety net for the unrecognised-downgrade
    case)."""
    def resolver(binding, group, code_by_route, tracker):
        return s1.Stage1ConsistencyResult(
            "p", "INSUFFICIENT_CONTEXT",
            [{"route_key": VULN_RK, "original_verdict": "VULNERABLE",
              "should_be": "INSUFFICIENT_CONTEXT", "reason": "x"}], "g")
    out = _run(resolver, [INGESTED_VULN, INGESTED_SAFE])
    row = _by_rk(out, VULN_RK)
    assert row["verdict"] == "INSUFFICIENT_CONTEXT", (
        "a CANONICAL verdict must not be rejected by the validity gate"
    )
    assert row["finding"] == "vulnerable", "the #331 net stays"
    assert "stage1_consistency_update" in row
