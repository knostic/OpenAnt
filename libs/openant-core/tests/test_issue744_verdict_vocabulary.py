"""#744 — the Stage-1 verdict vocabulary: the semantics ruling, implemented.

The vocabulary had no definitions where it is chosen, and INCONCLUSIVE's
disposition contradicted itself across five surfaces: the docs, the HTML
legend, and the remediation guidance all said manual-review-recommended,
while the disclosure filter dropped it and Stage 2 never re-examined it —
the pipeline provided no review path for a verdict three of its surfaces
recommended reviewing, and the summary carried a bare count ("Inconclusive |
3") with no identity. The campaign's three INCONCLUSIVE rows each asserted a
CONCRETE sink (a raw fmt.Sprintf into a <script> context; an outbound GET to
a client-controlled host; operator-sourced values spliced into InfluxQL) —
one carried cwe_id 918 and an attack_vector — so "no claim" and "claim I
could not finish" were indistinguishable to every downstream filter.

THE RULING (the three named halves):

1. DEFINE the four values in the prompt where they are chosen — one block,
   sourced from the docs' table, with SAFE's scope made explicit (the
   smaller ask): SAFE is the security posture, not general code quality; a
   genuine non-security bug may exist and belongs in the reasoning, never
   the verdict.
2. INCONCLUSIVE is MANUAL-REVIEW-RECOMMENDED (three of five surfaces
   already say so; dropping the recommendation would discard real claims)
   — and the pipeline SURFACES THE ROWS' IDENTITIES: pipeline_output.json
   gains a present-only inconclusive_findings block (the unit's
   file/function/cwe/attack_vector/reasoning), so the review path EXISTS
   instead of a bare count. The disclosure-drop STAYS (a disclosure
   document is a shipped artifact, not a review path — the identity block
   is the review path).
3. An INCONCLUSIVE row that CARRIES a concrete claim (cwe_id or
   attack_vector present) ESCALATES to Stage 2 — the verify filter admits
   it as a vulnerable-candidate; a bare inconclusive (no claim artifacts)
   stays out. The "no claim" vs "claim I could not finish" distinction the
   issue names.

Shapes:

  S1 -- the WITNESS (red at base): the prompt's definitions — the four
        values each defined at the enum, SAFE's non-security-bug scope
        named, INCONCLUSIVE's "NOT no claim" + the claim-artifacts
        instruction.
  S2 -- the WITNESS (assertion-red at base): the Stage-2 filter's
        escalation — a claim-carrying inconclusive row is admitted; a
        bare one is not; the vulnerable/bypassable set unchanged.
  S3 -- the WITNESS (assertion-red at base): the identity surface — the
        REAL builder emits the inconclusive_findings block with the rows'
        identities (present-only: a clean run carries none).
  S4 -- the escalation's Stage-2 flow: an admitted row verifies through
        the real verify_batch and the Stage-2 verdict is recorded.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import reset_warning_state  # noqa: E402


def _prompt_text():
    """The REAL prompt module's output — get_analysis_prompt renders the
    definitions (the prod-bound symbol; the screen's import-bound route)."""
    from prompts.vulnerability_analysis import get_analysis_prompt
    return get_analysis_prompt(code="x=1", language="python")


# ---------------------------------------------------------------------------
# S1 — the prompt's definitions
# ---------------------------------------------------------------------------
def test_the_prompt_defines_the_four_values_where_they_are_chosen():
    """The falsifier's first half: one block, at the enum — the docs'
    table the source, SAFE's scope explicit, INCONCLUSIVE's 'NOT no claim'
    named with the claim-artifacts instruction."""
    # the REAL prompt module's output, imported + called IN the witness
    # body (the prod-bound symbol — the screen's import-bound route)
    from prompts.vulnerability_analysis import get_analysis_prompt
    p = get_analysis_prompt(code="x=1", language="python")
    # the definitions block sits with the enum (the producer site)
    i = p.find('"finding"')
    assert i > 0, "the enum line vanished"
    ctx = p[max(0, i - 2000):i + 2000]
    for word, line in (
        ("vulnerable", "concrete attack could be constructed"),
        ("protected", "effective security control"),
        ("safe", "no concrete"),
        ("inconclusive", "could not be completed"),
    ):
        assert word in ctx and line in ctx, (
            f"the {word} definition is missing from the producer site")
    # SAFE's scope (the smaller ask): the security posture, not code quality
    _low = ctx.lower()
    assert ("not general code quality" in _low
            or "not about general code quality" in _low), (
        "SAFE's non-security-bug scope is not named")
    # INCONCLUSIVE: NOT 'no claim' + the claim-artifacts instruction
    assert 'this is not "no claim"' in ctx.lower(), (
        "the 'NOT no claim' distinction is missing")
    assert "attack_vector" in ctx and "cwe_id" in ctx, (
        "the claim-artifacts instruction is missing")
    # the SCHEMA-HINT clauses (the r1-F3 fix): the reply shape's own
    # field hints must carry the inconclusive-with-a-suspect arm — else
    # the definitions and the schema contradict each other
    assert "If inconclusive WITH a concrete suspect" in ctx, (
        "the attack_vector schema hint lacks the inconclusive arm")
    assert "inconclusive-with-a-suspect" in ctx, (
        "the cwe_id schema hint lacks the inconclusive arm")


# ---------------------------------------------------------------------------
# S2 — the Stage-2 filter's escalation
# ---------------------------------------------------------------------------
def test_the_stage2_filter_escalates_claim_carrying_inconclusive_rows():
    """The falsifier's third half: the verify filter admits an INCONCLUSIVE
    row that carries a concrete claim (cwe_id or attack_vector) as a
    vulnerable-candidate; a bare inconclusive stays out; the
    vulnerable/bypassable set unchanged."""
    from core.verifier import stage2_candidates

    results = [
        {"unit_id": "a:vuln", "finding": "vulnerable"},
        {"unit_id": "b:byp", "finding": "bypassable"},
        # the campaign's shape: a concrete sink claimed, analysis incomplete
        {"unit_id": "c:inc-cwe", "finding": "inconclusive", "cwe_id": 918,
         "attack_vector": "GET /acme?host=<client-controlled>"},
        {"unit_id": "d:inc-vec", "finding": "inconclusive",
         "attack_vector": "fmt.Sprintf into <script>"},
        {"unit_id": "e:inc-cwe0", "finding": "inconclusive", "cwe_id": 0},
        # no claim artifacts: stays out
        {"unit_id": "f:inc-bare", "finding": "inconclusive"},
        {"unit_id": "g:safe", "finding": "safe"},
    ]
    got = {r["unit_id"] for r in stage2_candidates(results)}
    assert got == {"a:vuln", "b:byp", "c:inc-cwe", "d:inc-vec"}, (
        f"the escalation boundary is wrong: {sorted(got)!r}")
    # the verdict-key spelling also routes (the results' dual spelling)
    got2 = {r["unit_id"] for r in stage2_candidates([
        {"unit_id": "h:v", "verdict": "vulnerable"},
        {"unit_id": "i:i", "verdict": "inconclusive", "cwe_id": 79},
    ])}
    assert got2 == {"h:v", "i:i"}, sorted(got2)


# ---------------------------------------------------------------------------
# S3 — the identity surface
# ---------------------------------------------------------------------------
def _write_results(tmp_path, results):
    """The analyzer's results.json shape: the EXPERIMENT dict (results +
    code_by_route + metrics), not a bare list."""
    p = tmp_path / "results.json"
    inconclusive = sum(1 for r in results
                       if str(r.get("finding") or r.get("verdict", "")).lower()
                       == "inconclusive")
    p.write_text(json.dumps({
        "results": results,
        "code_by_route": {r["unit_id"]: "code" for r in results},
        "metrics": {"total": len(results),
                    "vulnerable": len(results) - inconclusive - 1,
                    "bypassable": 0, "inconclusive": inconclusive,
                    "protected": 0, "safe": 1, "errors": 0},
    }))
    return str(p)


_FULL_RESULT = {
    "unit_id": "srv:handleACME", "route_key": "srv:handleACME",
    "finding": "inconclusive", "verdict": "inconclusive",
    "reasoning": "An outbound GET to a host built from a client-controlled "
                 "ACME identifier; the flow could not be completed",
    "attack_vector": "GET /acme?host=<client-controlled>",
    "cwe_id": 918, "cwe_name": "SSRF", "confidence": 0.4,
}


def test_the_pipeline_output_carries_the_inconclusive_identities(tmp_path):
    """The falsifier's second half: the review path EXISTS — the REAL
    builder emits a present-only inconclusive_findings block with the rows'
    identities (the unit's file/function, the cwe, the attack vector, the
    reasoning), so the summary's 'Inconclusive | N' has identities to
    review."""
    from core.reporter import build_pipeline_output

    results = [_FULL_RESULT,
               {"unit_id": "x:v", "route_key": "x:v", "finding": "vulnerable",
                "verdict": "vulnerable", "reasoning": "r", "cwe_id": 89,
                "cwe_name": "SQL Injection", "attack_vector": "a",
                "confidence": 0.9}]
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(results_path=_write_results(tmp_path, results),
                          output_path=str(out))
    po = json.loads(out.read_text())
    # the block rides the RESULTS block, BESIDE the inconclusive count it
    # identities (the count and the identities are one surface)
    res = po.get("results", {})
    block = res.get("inconclusive_findings")
    assert block, f"the identity block is missing: {sorted(res)!r}"
    assert len(block) == 1, block
    assert res.get("inconclusive") == 1, res
    row = block[0]
    assert row["file"] == "srv", row
    assert row["function"] == "handleACME", row
    assert row["cwe_id"] == 918, row
    assert "client-controlled" in row["attack_vector"], row
    assert "could not be completed" in row["reasoning"], row


def test_a_clean_run_carries_no_inconclusive_block(tmp_path):
    """Present-only: a run with no inconclusive rows writes NO block — no
    crying wolf on clean runs."""
    from core.reporter import build_pipeline_output

    results = [{"unit_id": "x:v", "route_key": "x:v", "finding": "vulnerable",
                "verdict": "vulnerable", "reasoning": "r", "cwe_id": 89,
                "cwe_name": "SQL Injection", "attack_vector": "a",
                "confidence": 0.9}]
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(results_path=_write_results(tmp_path, results),
                          output_path=str(out))
    po = json.loads(out.read_text())
    assert "inconclusive_findings" not in po.get("results", {}), (
        sorted(po.get("results", {})))


# ---------------------------------------------------------------------------
# S4 — the escalated row verifies through the real Stage-2
# ---------------------------------------------------------------------------
def test_an_escalated_row_verifies_through_the_real_batch(monkeypatch, tmp_path):
    """An admitted INCONCLUSIVE row enters the REAL verify_batch — the
    escalation is not an admission alone; the row is re-examined, which is
    the issue's whole point. The drive: a results.json fixture (the
    claim-carrying inconclusive row), the real run_verification, the batch
    seam captured."""
    import core.verifier as verifier_mod
    from utilities.llm import PhaseBinding
    from utilities.finding_verifier import FindingVerifier

    reset_warning_state()
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps({
        "results": [dict(_FULL_RESULT),
                    {"unit_id": "x:v", "route_key": "x:v",
                     "finding": "vulnerable", "verdict": "vulnerable",
                     "reasoning": "r", "confidence": 0.9}],
        "code_by_route": {"srv:handleACME": "code", "x:v": "code"},
    }))
    analyzer_output = tmp_path / "analyzer_output.json"
    analyzer_output.write_text(json.dumps({"results": []}))

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _Registry:
        def get(self, phase):
            return PhaseBinding(phase="verify", adapter=_Adapter(),
                                model="m", provider_name="anthropic")

    seen: list = []

    def fake_verify_batch(self, results, code_by_route, progress_callback=None,
                          workers=1, checkpoint=None, restored_callback=None,
                          phase_baseline=None):
        seen.extend(r.get("unit_id") for r in results)
        # the r1-F1 extension: Stage 2 REWRITES the escalated row (the
        # outcome that moves it out of inconclusive) — the real counter
        # + the real threading must record the move
        for r in results:
            if r.get("stage1_finding") == "inconclusive":
                r["verification"] = {"agree": False,
                                    "correct_finding": "safe"}
                r["finding"] = "safe"
        return results

    monkeypatch.setattr(FindingVerifier, "verify_batch", fake_verify_batch)
    monkeypatch.setattr(verifier_mod, "load_index_from_file",
                        lambda path, repo: __import__("types").SimpleNamespace(
                            functions=[]))
    vr = verifier_mod.run_verification(
        str(results_path), str(tmp_path / "out"),
        analyzer_output_path=str(analyzer_output),
        registry=_Registry(), workers=1)
    reset_warning_state()

    assert "srv:handleACME" in seen, (
        f"the escalated row never reached Stage 2: {seen!r}")
    assert "x:v" in seen, seen
    # the origin was stamped at admission and the counter recorded the move
    assert vr.escalated_inconclusive_moved == 1, (
        f"the moved count did not thread through the real run: {vr!r}")


# ---------------------------------------------------------------------------
# S5 — the envelope's sum-to-total invariant with escalated rows (the F1 fix)
# ---------------------------------------------------------------------------
def test_the_envelope_partition_holds_for_every_escalated_outcome():
    """The r1-F1 catch, closed: an escalated row re-buckets by its Stage-2
    outcome — the Stage-1 inconclusive count RETIRES for the moved rows —
    so the sum-to-total partition (#681) holds for EVERY outcome, not just
    the vulnerable-origin set. The hunt's executed probe had sum=4/total=3."""
    from core.analyzer import AnalysisMetrics
    from core.schemas import VerifyResult
    from core.scanner import _post_verify_metrics

    base = AnalysisMetrics(total=3, vulnerable=1, bypassable=0,
                           inconclusive=1, protected=0, safe=1, errors=0)
    # the campaign's shape: one escalated row, each possible outcome
    cases = {
        "stays inconclusive": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=2, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=1,
            needs_review=0, error_count=0, units_analyzed_total=3,
            escalated_inconclusive_moved=0),
        "upgraded to vulnerable": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=2, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=2,
            needs_review=0, error_count=0, units_analyzed_total=3,
            escalated_inconclusive_moved=1),
        "rewritten to safe": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=1, disagreed=1, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=1,
            needs_review=0, error_count=0, units_analyzed_total=3,
            escalated_inconclusive_moved=1),
        "rewritten to protected": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=1, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=1, confirmed_vulnerabilities=1,
            needs_review=0, error_count=0, units_analyzed_total=3,
            escalated_inconclusive_moved=1),
    }
    for name, vr in cases.items():
        m = _post_verify_metrics(base, vr)
        got = (m.vulnerable + m.bypassable + m.inconclusive + m.protected
               + m.safe + m.errors)
        assert got == m.total, (
            f"the envelope over-sums on the '{name}' outcome: "
            f"{got} != {m.total} ({m!r})")

    # the r2-1/r3-1 catch: the REAL error shape driven through the REAL
    # counter — the except arm never touches `finding`, so the row KEEPS
    # finding=='inconclusive' with the error set (the r3 terminal's
    # executed catch); the retirement must fire on the origin alone
    from core.verifier import _count_verification_outcomes
    _stamped = {"unit_id": "srv:handleACME", "finding": "inconclusive",
                "stage1_finding": "inconclusive", "error": "boom"}
    counts = _count_verification_outcomes([_stamped])
    assert counts["escalated_inconclusive_moved"] == 1, (
        f"the real-shape error row did not retire: {counts!r}")
    assert counts["error_count"] == 1, counts
    # the r4-1 catch: an OFF-ENUM rewrite ('Probably Fine' — the #679
    # class) retires too (the #679 arm re-buckets it to error_count)
    _off = {"unit_id": "srv:handleACME", "finding": "Probably Fine",
            "stage1_finding": "inconclusive",
            "verification": {"agree": False, "incomplete": False,
                             "correct_finding": "Probably Fine"}}
    counts_off = _count_verification_outcomes([_off])
    assert counts_off["escalated_inconclusive_moved"] == 1, (
        f"the off-enum rewrite did not retire: {counts_off!r}")
    assert counts_off["error_count"] == 1, counts_off
    # the r3-2 catch: an escalated row Stage 2 'disagrees' back INTO
    # inconclusive (the #509 arm) — it must NOT double-count (its Stage-1
    # count is still the envelope's base term)
    _dis = {"unit_id": "srv:handleACME", "finding": "inconclusive",
            "stage1_finding": "inconclusive",
            "verification": {"agree": False, "incomplete": False}}
    counts_dis = _count_verification_outcomes([_dis])
    assert counts_dis["disagreed_inconclusive"] == 0, (
        f"the #509 arm double-counted the escalated row: {counts_dis!r}")
    assert counts_dis["escalated_inconclusive_moved"] == 0, counts_dis
    # the r3-4 guard: the inf cwe coerces to 0, never raises
    from core.verdict_taxonomy import coerce_cwe_id
    assert coerce_cwe_id("Infinity") == 0
    assert coerce_cwe_id(float("inf")) == 0
    assert coerce_cwe_id("-5") == -5
    vr_err = VerifyResult(
        verified_results_path="x", findings_input=2, findings_verified=2,
        agreed=0, disagreed=0, disagreed_inconclusive=0,
        disagreed_protected=0, confirmed_vulnerabilities=1,
        needs_review=0, error_count=1, units_analyzed_total=3,
        escalated_inconclusive_moved=1)
    m_err = _post_verify_metrics(base, vr_err)
    got_err = (m_err.vulnerable + m_err.bypassable + m_err.inconclusive
               + m_err.protected + m_err.safe + m_err.errors)
    assert got_err == m_err.total, (
        f"the error outcome over-sums: {got_err} != {m_err.total} ({m_err!r})")

    # the S6 extension: the float cwe (the r2-2 matrix gap)
    from core.verifier import stage2_candidates
    assert stage2_candidates([
        {"unit_id": "f:inc", "finding": "inconclusive", "cwe_id": 918.0}
    ]) == [{"unit_id": "f:inc", "finding": "inconclusive", "cwe_id": 918.0}], (
        "the float cwe was dropped")


# ---------------------------------------------------------------------------
# S6 — the string-cwe escalation (the F2 fix)
# ---------------------------------------------------------------------------
def test_a_string_cwe_id_still_escalates():
    """The r1-F2 catch, closed: cwe_id is MODEL-SUPPLIED and stored
    verbatim — a string "918" (or "CWE-918") is the fa15/fa16
    trust-boundary class; the predicate coerces like the reporter's own
    finding_identity_key, never trusting the type."""
    from core.verifier import stage2_candidates
    row = {"unit_id": "s:inc", "finding": "inconclusive",
           "cwe_id": "918"}
    got = stage2_candidates([row])
    assert got == [row], "the string cwe was dropped (the trust-boundary miss)"
    row2 = {"unit_id": "s:inc2", "finding": "inconclusive",
            "cwe_id": "CWE-79"}
    assert stage2_candidates([row2]) == [row2]
    # the non-numeric garbage stays out (never a fabricated escalation)
    assert stage2_candidates([
        {"unit_id": "s:bad", "finding": "inconclusive", "cwe_id": "abc"}
    ]) == []
    # the boolean quirk: True is not a cwe
    assert stage2_candidates([
        {"unit_id": "s:bool", "finding": "inconclusive", "cwe_id": True}
    ]) == []


# ---------------------------------------------------------------------------
# S7 — the summary render (the F4 fix)
# ---------------------------------------------------------------------------
def test_the_summary_renders_the_inconclusive_identities():
    """The r1-F4 catch, closed: the issue's symptom sentence was 'the
    summary reports "Inconclusive | 3" with no identity to review' — the
    reviewer is in the summary, so the review path renders there: each
    row's file:function + the claim, present-only. The summary's
    deterministic tables block is the render surface (the LLM half reads
    the same pipeline_data)."""
    from report.generator import _summary_tables_block
    pipeline = {
        "results": {"vulnerable": 1, "safe": 1, "protected": 0,
                    "inconclusive": 1, "needs_review": 0, "errors": 0,
                    "inconclusive_findings": [
                        {"file": "srv", "function": "handleACME",
                         "cwe_id": 918,
                         "attack_vector": "GET /acme?host=<client>",
                         "reasoning": "the outbound GET"}]},
    }
    md = _summary_tables_block(pipeline)
    assert "srv:handleACME" in md, (
        f"the identity does not render in the summary: {md!r}")
    assert "CWE-918" in md and "client" in md, md
    assert "manual review recommended" in md, md
    # present-only: a clean run renders no section
    md_clean = _summary_tables_block({"results": {"vulnerable": 1}})
    assert "Inconclusive rows" not in md_clean, md_clean


# ---------------------------------------------------------------------------
# S8 — the F6 grouping exclusion (the r6-1 catch: it pins in 5 lines at $0)
# ---------------------------------------------------------------------------
def test_the_consistency_grouping_excludes_escalated_rows():
    """The r6-1 catch: _group_by_pattern is a PURE method (self never
    touched) — the F6 exclusion pins offline. An escalated row must NOT
    join the pattern groups (a mixed {vulnerable, inconclusive-origin}
    group spends a consistency LLM call on a non-comparison and anchors
    the vulnerable sibling toward the inconclusive candidate)."""
    from utilities.finding_verifier import FindingVerifier

    rows = [
        {"route_key": "a.go:errorMsg.json", "finding": "vulnerable"},
        {"route_key": "a.go:infoMsg.json", "finding": "safe",
         "stage1_finding": "inconclusive"},
        {"route_key": "a.go:warnMsg.json", "finding": "vulnerable"},
    ]
    verifier = FindingVerifier.__new__(FindingVerifier)
    groups = verifier._group_by_pattern(rows)
    members = [r["route_key"] for g in groups.values() for r in g]
    assert "a.go:infoMsg.json" not in members, (
        f"the escalated row joined a pattern group: {groups!r}")
    assert "a.go:errorMsg.json" in members and "a.go:warnMsg.json" in members
