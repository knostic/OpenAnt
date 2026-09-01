"""#448: finding_verifier._check_consistency validates its should_be — the Stage-2 twin.

The Stage-2 consistency site is the exact twin of the stage1_consistency site #425 fixed:
same `findings_to_update`/`should_be` contract, same F-KB-1b/F-KB-1a comment pairing — but
it writes `finding` VERBATIM with no strip, no validation:

```
new_verdict = finding_update.get("should_be")      # unconstrained model output
...
old_verdict != new_verdict:
    result["finding"] = new_verdict                # the key _count_verdicts + disclosure read FIRST
    result["verification"]["correct_finding"] = new_verdict
```

A garbage `should_be` ("MAYBE VULNERABLE") passes the downgrade guard (not in
DISCLOSURE_DROPPED) and is written into `finding` — the row drops from every `_count_verdicts`
bucket (the F13 else-branch, not even `errors`) and from disclosure: a real VULNERABLE finding
vanishes silently, on the more load-bearing key. Weaker than the pre-#425 Stage-1 site: not even
`.strip()`, so "  VULNERABLE  " lands padded and the comparison is raw.

The #316/#324/#425/#427 producer discipline at this site: normalize (strip/lower — this
module's storage convention is lowercase `correct_finding`), validate against the canonical
`finding` vocabulary (STAGE1_VERDICTS ∪ STAGE2_VERDICTS — every value `finding`/
`correct_finding` legitimately takes), reject-audit unrecognized values (the
`consistency_invalid_verdict_blocked` pattern). Found during #425's wave review (opus, three
axes: "the commit says 'the one producer that runs LAST' — it isn't").
"""
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

from utilities.finding_verifier import FindingVerifier, ConsistencyCheckResult  # noqa: E402


FILE = "pkg/logger/console.go"
VULN_RK = f"{FILE}:runMsg.json"      # groups with the safe sibling (same .json pattern)
SAFE_RK = f"{FILE}:infoMsg.json"


def _verifier():
    v = FindingVerifier.__new__(FindingVerifier)
    v._use_logger = False
    v.verbose = False
    return v


def _rows(finding_vuln="vulnerable", finding_safe="safe"):
    return [
        {"route_key": VULN_RK, "finding": finding_vuln,
         "verification": {"correct_finding": finding_vuln}},
        {"route_key": SAFE_RK, "finding": finding_safe,
         "verification": {"correct_finding": finding_safe}},
    ]


def _run(v, should_be, rows=None):
    v._resolve_inconsistency = lambda group, cbr: ConsistencyCheckResult(
        "logger json emitter", should_be,
        [{"route_key": VULN_RK, "should_be": should_be, "reason": "x"}], "g")
    return v._check_consistency(rows or _rows(), {})


def _by_rk(out, rk):
    return next(r for r in out if r["route_key"] == rk)


def test_unrecognized_should_be_is_rejected_not_written():
    """The issue's headline: a garbage should_be passes the downgrade guard and
    lands in `finding` verbatim — the row drops from every count and from
    disclosure. Rejected with an audit record; the row keeps its verdict."""
    out = _run(_verifier(), "MAYBE VULNERABLE")
    row = _by_rk(out, VULN_RK)
    assert row["finding"] == "vulnerable", (
        f"a garbage should_be landed in finding verbatim: {row['finding']!r}"
    )
    assert row["verification"]["correct_finding"] == "vulnerable"
    assert "consistency_invalid_verdict_blocked" in row, (
        "the rejected proposal must be audited, not silent"
    )
    assert "consistency_update" not in row


def test_padded_should_be_is_normalized():
    """The #448 body's weaker-than-stage-1 case: '  vulnerable  ' landed PADDED
    (the raw compare old != new fired, the raw string was written) — the padded
    value then failed every downstream lowercase vocabulary read. Normalized."""
    out = _run(_verifier(), "  vulnerable  ")
    row = _by_rk(out, VULN_RK)
    assert row["finding"] == "vulnerable", (
        f"the padded should_be was written raw: {row['finding']!r}"
    )
    assert row["verification"]["correct_finding"] == "vulnerable"


def test_uppercase_should_be_normalizes_to_the_storage_convention():
    """The site's storage convention is lowercase correct_finding; a model's
    'VULNERABLE' was written UPPERCASE and then missed the lowercase reads."""
    out = _run(_verifier(), "VULNERABLE")
    row = _by_rk(out, VULN_RK)
    assert row["finding"] == "vulnerable", row["finding"]


def test_empty_should_be_writes_nothing():
    """should_be=None previously OVERWROTE finding with None (the raw compare
    vulnerable != None is True) — the row degraded to its verdict fallback.
    An empty proposal applies nothing."""
    out = _run(_verifier(), None)
    row = _by_rk(out, VULN_RK)
    assert row["finding"] == "vulnerable"
    assert "consistency_update" not in row


def test_legitimate_correction_still_lands():
    """A canonical downgrade on a NON-conclusive row still applies (the pass's
    whole purpose) — the gate must not over-block."""
    out = _run(_verifier(), "safe")
    row = _by_rk(out, VULN_RK)
    assert row["finding"] == "safe"
    assert row["verification"]["correct_finding"] == "safe"
    assert "consistency_update" in row


def test_conclusive_exploitable_guard_unchanged():
    """The F-KB-1b pin: a conclusively-EXPLOITABLE row is never downgraded to a
    DROPPED verdict by pattern matching — the validity gate must not disturb
    the guard's precedence."""
    v = _verifier()
    rows = [
        {"route_key": VULN_RK, "finding": "vulnerable",
         "verification": {"correct_finding": "vulnerable",
                           "exploit_path": {"entry_point": "h", "sink_reached": True,
                                            "attacker_control_at_sink": "full",
                                            "path_broken_at": None}}},
        {"route_key": SAFE_RK, "finding": "safe",
         "verification": {"correct_finding": "safe"}},
    ]
    out = _run(v, "safe", rows=rows)
    row = _by_rk(out, VULN_RK)
    assert row["finding"] == "vulnerable", "the conclusive-exploitable guard was disturbed"
    assert "consistency_downgrade_blocked" in row


def test_stage2_vocabulary_is_rejected_not_written():
    """Wave r1 (three axes): STAGE2_VERDICTS is the reporter's DERIVED
    stage2_verdict key — no producer ever writes confirmed/agreed/unverified/
    rejected into `finding`. The round-1 gate admitted them, and a
    conformant-looking "confirmed" (a MORE plausible model emission than the
    garbage string) reproduced the exact bucket-drop: _count_verdicts' F13
    else-branch + the reporter's disclosure filter. Rejected now."""
    for token in ("confirmed", "agreed", "unverified", "rejected"):
        out = _run(_verifier(), token)
        row = _by_rk(out, VULN_RK)
        assert row["finding"] == "vulnerable", (
            f"{token!r} — a stage2_verdict value — was written into finding: {row}"
        )
        assert "consistency_invalid_verdict_blocked" in row, token


def test_error_is_not_a_correction_target_on_conclusive_rows():
    """Wave r1 (fable, the F-KB-1b bypass): error is a legitimate STATE of
    finding but not a legitimate CORRECTION TARGET — it is outside
    DISCLOSURE_DROPPED, so admitting it let a pattern-similarity pass move a
    conclusively-EXPLOITABLE row to the error shape PAST the guard (the exact
    class #195/#243 closed)."""
    v = _verifier()
    rows = [
        {"route_key": VULN_RK, "finding": "vulnerable",
         "verification": {"correct_finding": "vulnerable",
                          "exploit_path": {"entry_point": "h", "sink_reached": True,
                                           "attacker_control_at_sink": "full",
                                           "path_broken_at": None}}},
        {"route_key": SAFE_RK, "finding": "safe",
         "verification": {"correct_finding": "safe"}},
    ]
    for token in ("error", "insufficient_context"):
        out = _run(v, token, rows=[dict(r) for r in rows])
        row = _by_rk(out, VULN_RK)
        assert row["finding"] == "vulnerable", (
            f"{token!r} moved a conclusively-exploitable row past the guard: {row}"
        )
        assert "consistency_invalid_verdict_blocked" in row, token


def test_uppercase_old_verdict_compare_is_normalized():
    """Wave r1 (fable): _parse_finish_result stores correct_finding verbatim —
    an uppercase-stamped row vs a normalized proposal previously produced a
    spurious consistency_update record. The old side is normalized too."""
    out = _run(_verifier(), "vulnerable",
               rows=[{"route_key": VULN_RK, "finding": "vulnerable",
                      "verification": {"correct_finding": "VULNERABLE"}},
                     {"route_key": SAFE_RK, "finding": "safe",
                      "verification": {"correct_finding": "safe"}}])
    row = _by_rk(out, VULN_RK)
    assert "consistency_update" not in row, (
        f"a case-only difference produced a spurious update record: {row}"
    )
    # no update fired — the row's stored stamp is untouched (the write site
    # never runs on a normalized-equal compare; readers lowercase on read)
    assert row["verification"]["correct_finding"] == "VULNERABLE"
