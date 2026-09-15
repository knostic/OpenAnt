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


def test_the_correctable_set_equals_the_finish_enum():
    """Wave r2 (fable+opus) + wave r3 (all three axes): the round-2 pin located
    the PROSE copy (_VERIFY_JSON_SCHEMA's docstring) — appending a value to
    the finish TOOL'S enum left it green, and the set-against-its-definition
    assertion was a tautology. The real pin: read VERIFICATION_TOOLS, select
    the finish entry, and assert its correct_finding ENUM as a set equals the
    correctable set — a change to either copy now surfaces HERE."""
    from core.verdict_taxonomy import FINDING_VERDICT_ORDER
    import utilities.finding_verifier as fv
    finish = next(t for t in fv.VERIFICATION_TOOLS if t["name"] == "finish")
    enum_vals = set(finish["input_schema"]["properties"]["correct_finding"]["enum"])
    assert enum_vals == set(FINDING_VERDICT_ORDER), (
        f"the finish tool's enum drifted from FINDING_VERDICT_ORDER: {enum_vals}"
    )
    assert fv._CORRECTABLE_STAGE2_FINDINGS == enum_vals, (
        "the correctable set drifted from the finish tool's enum — the gate "
        "must stay exactly the model-facing declaration"
    )


def test_audit_from_keeps_the_raw_stored_stamp():
    """Wave r2 (fable+sonnet+opus): `from` records the RAW stored value —
    a case/whitespace anomaly in stored data is itself an upstream-bug
    signal (experiment.py prints it verbatim); the normalized form is for
    the compare only."""
    out = _run(_verifier(), "safe",
               rows=[{"route_key": VULN_RK, "finding": "vulnerable",
                      "verification": {"correct_finding": "VULNERABLE"}},
                     {"route_key": SAFE_RK, "finding": "safe",
                      "verification": {"correct_finding": "safe"}}])
    row = _by_rk(out, VULN_RK)
    assert "consistency_update" in row, "the (real) case difference must fire"
    assert row["consistency_update"]["from"] == "VULNERABLE", (
        f"the audit from-field lost the raw stamp: {row['consistency_update']}"
    )
    assert row["consistency_update"]["to"] == "safe"


def test_case_only_group_is_not_inconsistent():
    """Wave r2 (opus): the DETECTOR compares raw — an all-vulnerable group
    stamped VULNERABLE/vulnerable previously read as inconsistent and spent
    a full LLM resolution call every batch."""
    v = _verifier()
    called = {"n": 0}

    def _fake_resolve(group, cbr):
        called["n"] += 1
        return None

    v._resolve_inconsistency = _fake_resolve
    v._check_consistency([
        {"route_key": VULN_RK, "finding": "vulnerable",
         "verification": {"correct_finding": "VULNERABLE"}},
        {"route_key": SAFE_RK, "finding": "vulnerable",
         "verification": {"correct_finding": "vulnerable"}},
    ], {})
    assert called["n"] == 0, (
        "a case-only difference spent an LLM resolution call — the detector "
        "must compare normalized"
    )


def test_malformed_nonstring_proposal_is_audited():
    """Wave r2 (fable): a list/dict/number should_be is a MALFORMED proposal —
    audited, not silently dropped. None/empty stay a silent no-proposal."""
    out = _run(_verifier(), ["VULNERABLE"])
    row = _by_rk(out, VULN_RK)
    assert row["finding"] == "vulnerable"
    assert "consistency_invalid_verdict_blocked" in row, (
        "a structured malformed proposal must leave an audit record"
    )
    assert row["consistency_invalid_verdict_blocked"]["proposed"] == ["VULNERABLE"]


def test_hallucinated_updates_do_not_apply_when_consistency_is_false(monkeypatch):
    """Wave r2 (fable) + wave r3 (all three axes): should_be_consistent=FALSE
    plus a hallucinated findings_to_update — the one conformant field that
    says DO NOT APPLY must win over the hallucinated payload. Driven through
    the REAL _resolve_inconsistency parse path (the round-2 test stubbed the
    resolver and degenerated into a duplicate of the apply control)."""
    import json as _json
    import utilities.llm as fv_llm
    v = _verifier()
    v.binding = object()
    v.tracker = None            # the method passes tracker= to simple_text

    the_reply = _json.dumps({
        "should_be_consistent": False,
        "consistent_verdict": "safe",
        "explanation": "not actually the same",
        "findings_to_update": [{"route_key": VULN_RK, "should_be": "safe"}],
    })
    monkeypatch.setattr(fv_llm, "simple_text", lambda *a, **k: the_reply)
    got = v._resolve_inconsistency(
        [{"route_key": VULN_RK, "finding": "vulnerable",
          "verification": {"correct_finding": "vulnerable"}},
         {"route_key": SAFE_RK, "finding": "safe",
          "verification": {"correct_finding": "safe"}}], {})
    assert got is None, (
        "a FALSE should_be_consistent must gate its hallucinated payload"
    )
    # the tolerant read (wave r3): the string "false" and 0 gate too
    for falsy in ("false", 0, "no"):
        reply = _json.dumps({
            "should_be_consistent": falsy,
            "consistent_verdict": "safe",
            "explanation": "x",
            "findings_to_update": [{"route_key": VULN_RK, "should_be": "safe"}],
        })
        monkeypatch.setattr(fv_llm, "simple_text", lambda *a, r=reply, **k: r)
        got = v._resolve_inconsistency(
            [{"route_key": VULN_RK, "finding": "vulnerable",
              "verification": {"correct_finding": "vulnerable"}},
             {"route_key": SAFE_RK, "finding": "safe",
              "verification": {"correct_finding": "safe"}}], {})
        assert got is None, f"should_be_consistent={falsy!r} must gate"
    # the control: a TRUE reply still parses its payload
    reply = _json.dumps({
        "should_be_consistent": True,
        "consistent_verdict": "safe",
        "explanation": "x",
        "findings_to_update": [{"route_key": VULN_RK, "should_be": "safe"}],
    })
    monkeypatch.setattr(fv_llm, "simple_text", lambda *a, r=reply, **k: r)
    got = v._resolve_inconsistency(
        [{"route_key": VULN_RK, "finding": "vulnerable",
          "verification": {"correct_finding": "vulnerable"}},
         {"route_key": SAFE_RK, "finding": "safe",
          "verification": {"correct_finding": "safe"}}], {})
    assert got is not None and got.findings_updated, (
        "control: a TRUE reply's payload still flows"
    )


def test_out_of_group_route_key_is_ignored():
    """Wave r3 (opus): an update is scoped to the GROUP that fired the call —
    a hallucinated route_key naming any OTHER row in the batch previously
    moved that row (or stamped its audit) regardless of the pattern the
    model was shown. The apply gate's threat model is precisely the
    fully-hallucinated payload."""
    OTHER_RK = f"{FILE}:otherFn.json"

    def resolver(group, code_by_route):
        return ConsistencyCheckResult(
            "logger json emitter", "safe",
            [{"route_key": OTHER_RK, "should_be": "safe", "reason": "x"}], "g")

    rows = _rows() + [{"route_key": OTHER_RK, "finding": "vulnerable",
                       "verification": {"correct_finding": "vulnerable"}}]
    v = _verifier()
    v._resolve_inconsistency = resolver
    out = v._check_consistency(rows, {})
    other = _by_rk(out, OTHER_RK)
    assert other["finding"] == "vulnerable", (
        f"an out-of-group route_key was moved: {other}"
    )
    assert "consistency_invalid_verdict_blocked" not in other
    assert "consistency_update" not in other


def test_group_route_key_still_applies():
    """The group scoping must not over-block: an update naming an IN-group
    row still applies."""
    def resolver(group, code_by_route):
        return ConsistencyCheckResult(
            "logger json emitter", "safe",
            [{"route_key": VULN_RK, "should_be": "safe", "reason": "x"}], "g")

    v = _verifier()
    v._resolve_inconsistency = resolver
    out = v._check_consistency(_rows(), {})
    assert _by_rk(out, VULN_RK)["finding"] == "safe"


def test_whitespace_only_should_be_is_a_silent_no_proposal():
    """Wave r3 (opus): '   ' normalizes empty — a no-proposal, not a
    malformed-structured audit (the comment and the code agree now)."""
    out = _run(_verifier(), "   ")
    row = _by_rk(out, VULN_RK)
    assert row["finding"] == "vulnerable"
    assert "consistency_invalid_verdict_blocked" not in row


def test_malformed_payload_container_and_elements_never_crash(monkeypatch):
    """Wave r4 (fable+opus): the hallucinated payload's container and
    elements are shape-checked — "findings_to_update": null / a string / a
    dict, and list members that are strings or null, previously crashed the
    Verify phase AFTER every per-unit LLM call was paid (TypeError at the
    for; AttributeError at .get). All three shapes now leave every row
    untouched."""
    import json as _json
    import utilities.llm as fv_llm

    rows = [{"route_key": VULN_RK, "finding": "vulnerable",
             "verification": {"correct_finding": "vulnerable"}},
            {"route_key": SAFE_RK, "finding": "safe",
             "verification": {"correct_finding": "safe"}}]
    v = _verifier()
    v.binding = object()
    v.tracker = None
    bad_payloads = [
        None,                                   # null container
        "all",                                  # a string container
        {"route": "safe"},                      # a dict container
        [VULN_RK],                              # a list of strings
        [None, 3],                              # non-dict elements
        [{"route_key": ["a", "b"], "should_be": "safe"}],  # unhashable route_key
    ]
    for payload in bad_payloads:
        reply = _json.dumps({"should_be_consistent": True,
                             "consistent_verdict": "safe",
                             "explanation": "x",
                             "findings_to_update": payload})
        monkeypatch.setattr(fv_llm, "simple_text", lambda *a, r=reply, **k: r)
        # (wave r5 fable+opus: the r4 ternary was a TAUTOLOGY — got is never
        # None for a well-formed reply, so _check_consistency was never
        # called and the guards had zero coverage. The apply loop is driven
        # unconditionally here — _check_consistency invokes the patched
        # resolver itself.)
        out = v._check_consistency([dict(r) for r in rows], {})
        vuln = next(r for r in out if r["route_key"] == VULN_RK)
        assert vuln["finding"] == "vulnerable", (
            f"payload {payload!r} moved or crashed a row"
        )
        assert "consistency_update" not in vuln, payload


def test_unhashable_verdict_never_crashes_the_detector():
    """Wave r6 (opus): a non-string correct_finding (a list/dict from a
    text-mode reply or a checkpoint restore — never type-coerced on the way
    in) crashed the DETECTOR's set construction: unhashable TypeError, in the
    code path that ALWAYS runs. The Stage-1 twin coerces to "" — same guard
    here."""
    v = _verifier()
    called = {"n": 0}

    def _fake_resolve(group, cbr):
        called["n"] += 1
        return None

    v._resolve_inconsistency = _fake_resolve
    out = v._check_consistency([
        {"route_key": VULN_RK, "finding": ["safe"],
         "verification": {"correct_finding": ["safe"]}},
        {"route_key": SAFE_RK, "finding": "vulnerable",
         "verification": {"correct_finding": "vulnerable"}},
    ], {})
    # no crash, and the malformed row was NOT treated as equal to the
    # canonical one ("" from the list, "vulnerable" from the sibling ->
    # inconsistent -> the resolver was called)
    assert called["n"] == 1
    assert all(isinstance(r["finding"], (str, list)) for r in out)
