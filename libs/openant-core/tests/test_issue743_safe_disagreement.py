"""#743 — a SAFE verdict resting on a factually false claim about the code
is never re-examined: Stage 2 admits only vulnerable/bypassable; the one
stage that reads SAFE reasoning (the consistency check) fires only on
mixed-verdict groups. The campaign's corpus: in one 3,401-row run, 36 SAFE
rows carry ``security_classification`` ``exploitable`` (20) or
``vulnerable_internal`` (16) — the ENHANCE stage's own disagreement with
Stage 1's SAFE — plus 3 INCONCLUSIVE/exploitable rows: 39 rows where a
second look is already internally signaled and none gets one.

THE RULING (the issue's third named option — the adjudication of the
classification-disagreement set, the cheapest of the three): the
disagreement rows ENTER Stage 2. A SAFE row whose result carries an
enhance classification of ``exploitable`` or ``vulnerable_internal`` is
admitted as a Stage-2 candidate alongside the vulnerable/bypassable set
(the #744 claim-carrying escalation rides the same seam — this PR stacks
on #830's retirement machinery and generalizes it: the origin stamp, the
moved counter, and the fold's retirement extended to the safe origin).

The stacked-dependency: #830 (the #744 fix) built the retirement machinery
(origin stamp → escalated_inconclusive_moved → the envelope fold) for the
inconclusive origin; this PR adds the safe origin on the same rails — the
counter, the #509 arm's skip, the consistency grouping exclusion, and the
fold all key on the ORIGIN SET now, not the single origin.

Shapes:

  S1 -- the WITNESS (assertion-red at base): the disagreement admission —
        a SAFE row with security_classification 'exploitable' or
        'vulnerable_internal' joins the Stage-2 candidates; a SAFE row with
        a sentinel or absent classification stays out; a classified
        vulnerable row was already in.
  S2 -- the WITNESS (assertion-red at base): the envelope retirement for the
        safe origin — a SAFE-disagreement row Stage 2 rewrites (to
        vulnerable, to safe, to inconclusive) or that errors retires its
        Stage-1 safe count; every outcome sums to total (the #681
        partition); the #509 arm skips the safe origin (no double-count).
  S3 -- the WITNESS (assertion-red at base): the real-run admission + the
        moved count — the REAL run_verification with a results fixture
        carrying the disagreement row: the batch receives it, the origin
        stamp lands, the count threads to the VerifyResult.
  S4 -- the no-cry-wolf guards: a clean scan (all classifications agree
        with the verdicts) admits ONLY the vulnerable/bypassable set — the
        disagreement arm never blanket-escalates; the consistency grouping
        excludes the safe-origin escalated rows.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import reset_warning_state  # noqa: E402


# ---------------------------------------------------------------------------
# S1 — the disagreement admission
# ---------------------------------------------------------------------------
def test_the_disagreement_set_enters_stage2():
    """The falsifier: a SAFE row whose enhance classification disagrees
    (exploitable / vulnerable_internal) is admitted as a Stage-2 candidate;
    a SAFE row with a sentinel or absent classification stays out."""
    from core.verifier import stage2_candidates

    results = [
        {"unit_id": "a:v", "finding": "vulnerable"},
        {"unit_id": "b:safe-expl", "finding": "safe",
         "security_classification": "exploitable"},
        {"unit_id": "c:safe-vi", "finding": "safe",
         "security_classification": "vulnerable_internal"},
        {"unit_id": "d:safe-agree", "finding": "safe",
         "security_classification": "safe"},
        {"unit_id": "e:safe-sentinel", "finding": "safe",
         "security_classification": "unknown"},
        {"unit_id": "f:safe-bare", "finding": "safe"},
        {"unit_id": "g:inc-expl", "finding": "inconclusive",
         "security_classification": "exploitable",
         "attack_vector": "the claim"},
    ]
    got = {r["unit_id"] for r in stage2_candidates(results)}
    assert got == {"a:v", "b:safe-expl", "c:safe-vi", "g:inc-expl"}, (
        f"the disagreement boundary is wrong: {sorted(got)!r}")
    # the verdict spelling routes too; the classification is a STRING gate
    got2 = {r["unit_id"] for r in stage2_candidates([
        {"unit_id": "h:v", "verdict": "vulnerable"},
        {"unit_id": "i:safe", "verdict": "safe",
         "security_classification": "exploitable"},
    ])}
    assert got2 == {"h:v", "i:safe"}, sorted(got2)


def test_the_bare_safe_stays_out_and_no_cry_wolf():
    """A clean scan (all agree) admits ONLY vulnerable/bypassable — the
    arm never blanket-escalates."""
    from core.verifier import stage2_candidates
    results = [
        {"unit_id": "a:v", "finding": "vulnerable"},
        {"unit_id": "b:safe", "finding": "safe",
         "security_classification": "safe"},
        {"unit_id": "c:prot", "finding": "protected",
         "security_classification": "security_control"},
    ]
    got = {r["unit_id"] for r in stage2_candidates(results)}
    assert got == {"a:v"}, sorted(got)


# ---------------------------------------------------------------------------
# S2 — the envelope retirement for the safe origin
# ---------------------------------------------------------------------------
def test_the_envelope_retires_the_safe_origin_every_outcome():
    """The #681 partition for every SAFE-disagreement outcome: the Stage-1
    safe count retires when Stage 2 rewrites or errors the row; the #509
    arm skips the safe origin (no double-count)."""
    from core.analyzer import AnalysisMetrics
    from core.schemas import VerifyResult
    from core.scanner import _post_verify_metrics

    base = AnalysisMetrics(total=3, vulnerable=1, bypassable=0,
                           inconclusive=0, protected=0, safe=2, errors=0)
    cases = {
        "stays safe (agreed)": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=2, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=1,
            needs_review=0, error_count=0, units_analyzed_total=3,
            escalated_inconclusive_moved=0, escalated_safe_moved=0),
        "rewritten to vulnerable": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=2, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=2,
            needs_review=0, error_count=0, units_analyzed_total=3,
            escalated_inconclusive_moved=0, escalated_safe_moved=1),
        "rewritten to inconclusive": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=1, disagreed=0, disagreed_inconclusive=1,
            disagreed_protected=0, confirmed_vulnerabilities=1,
            needs_review=0, error_count=0, units_analyzed_total=3,
            escalated_inconclusive_moved=0, escalated_safe_moved=1),
        "rewritten to protected": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=1, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=1, confirmed_vulnerabilities=1,
            needs_review=0, error_count=0, units_analyzed_total=3,
            escalated_inconclusive_moved=0, escalated_safe_moved=1),
        "errored": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=0, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=1,
            needs_review=0, error_count=1, units_analyzed_total=3,
            escalated_inconclusive_moved=0, escalated_safe_moved=1),
        # the T1-r1 F1 shape: the incomplete-upgrade lands in needs_review
        # (a side metric), so the Stage-1 safe count is NOT retired — the
        # partition keeps the row in its base term
        "incomplete-upgrade": VerifyResult(
            verified_results_path="x", findings_input=2, findings_verified=2,
            agreed=1, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=1,
            needs_review=1, error_count=0, units_analyzed_total=3,
            escalated_inconclusive_moved=0, escalated_safe_moved=0),
    }
    for name, vr in cases.items():
        m = _post_verify_metrics(base, vr)
        got = (m.vulnerable + m.bypassable + m.inconclusive + m.protected
               + m.safe + m.errors)
        assert got == m.total, (
            f"the envelope over-sums on the '{name}' outcome: "
            f"{got} != {m.total} ({m!r})")


def test_the_counter_retires_the_safe_origin_real_shapes():
    """The REAL counter on the real SAFE-disagreement shapes: the rewrite
    moves, the error retires, the #509-back-into-inconclusive does NOT
    double-count (its Stage-1 safe count retires), and a same-origin
    re-inconclusive (agree=False but correct_finding=inconclusive again)
    leaves the buckets alone."""
    from core.verifier import _count_verification_outcomes

    # rewritten to vulnerable: the move recorded + the destination counted
    c1 = _count_verification_outcomes([
        {"unit_id": "u", "finding": "vulnerable",
         "stage1_finding": "safe",
         "verification": {"agree": False, "incomplete": False,
                          "correct_finding": "vulnerable"}}])
    assert c1["escalated_safe_moved"] == 1, c1
    assert c1["confirmed_vulnerabilities"] == 1, c1
    # errored: the retirement fires on the origin alone
    c2 = _count_verification_outcomes([
        {"unit_id": "u", "finding": "safe",
         "stage1_finding": "safe", "error": "boom"}])
    assert c2["escalated_safe_moved"] == 1, c2
    assert c2["error_count"] == 1, c2
    # #509 back: the arm COUNTS the safe origin — the row MOVES
    # safe→inconclusive (the retirement drops the base term; this arm is
    # its destination, the mirror of the vulnerable-origin replacement
    # drop). The r3-2 skip stays inconclusive-origin-only: an
    # inconclusive origin's base term already holds the row, a safe
    # origin's does not.
    c3 = _count_verification_outcomes([
        {"unit_id": "u", "finding": "inconclusive",
         "stage1_finding": "safe",
         "verification": {"agree": False, "incomplete": False,
                          "correct_finding": "inconclusive"}}])
    assert c3["disagreed_inconclusive"] == 1, c3
    assert c3["escalated_safe_moved"] == 1, c3
    # the vulnerable-origin #509 arm unchanged (no regression)
    c4 = _count_verification_outcomes([
        {"unit_id": "v", "finding": "inconclusive",
         "verification": {"agree": False, "incomplete": False,
                          "correct_finding": "inconclusive"}}])
    assert c4["disagreed_inconclusive"] == 1, c4
    assert c4["escalated_safe_moved"] == 0, c4
    # the drift shape: agree=False but the "corrected" finding is safe
    # again (self-contradictory for an escalated safe row, but the
    # #679/#744 lessons say off-shape arrivals happen) — the base term
    # already holds the row, so the plain disagreed add-on must NOT fire
    c5 = _count_verification_outcomes([
        {"unit_id": "u", "finding": "safe",
         "stage1_finding": "safe",
         "verification": {"agree": False, "incomplete": False,
                          "correct_finding": "safe"}}])
    assert c5["disagreed"] == 0, c5
    assert c5["escalated_safe_moved"] == 0, c5
    # incomplete: the row keeps its Stage-1 bucket (needs_review is the
    # side metric) — no retirement
    c6 = _count_verification_outcomes([
        {"unit_id": "u", "finding": "safe",
         "stage1_finding": "safe",
         "verification": {"agree": False, "incomplete": True}}])
    assert c6["needs_review"] == 1, c6
    assert c6["escalated_safe_moved"] == 0, c6
    # the T1-r1 F1 catch (FAM-REPORT-2, EXECUTED through the real
    # finding_verifier): a finish that AGREES but is truncated mid-answer
    # serializes agree=False + correct_finding=<the more-severe verdict> +
    # incomplete=True (the parse flips agree at the FAM-REPORT-2 block —
    # the serialized dict NEVER carries agree=True with incomplete=True;
    # the c10 seam pin below proves the producer's actual output), and the
    # result assembly propagates finding=correct_finding — an
    # INCOMPLETE-UPGRADE. The retirement must NOT fire: the row lands in
    # needs_review (a side metric, not an envelope column), so retiring the
    # Stage-1 safe count under-sums the #681 partition by exactly one. The
    # class is SHARED with the inconclusive-origin arm (the #830 rails this
    # PR generalizes — the twin shape is c8; both gates land in this fix).
    c7 = _count_verification_outcomes([
        {"unit_id": "u", "finding": "vulnerable",
         "stage1_finding": "safe",
         "verification": {"agree": False, "incomplete": True,
                         "correct_finding": "vulnerable"}}])
    assert c7["needs_review"] == 1, c7
    assert c7["escalated_safe_moved"] == 0, (
        f"the incomplete-upgrade retired its Stage-1 count (under-sum): {c7!r}")
    # the inconclusive-origin twin (the #830-shared class): the SAME
    # FAM-REPORT-2 shape on a claim-carrying inconclusive row must not
    # retire its Stage-1 inconclusive count
    c8 = _count_verification_outcomes([
        {"unit_id": "w", "finding": "vulnerable",
         "stage1_finding": "inconclusive",
         "verification": {"agree": False, "incomplete": True,
                          "correct_finding": "vulnerable"}}])
    assert c8["needs_review"] == 1, c8
    assert c8["escalated_inconclusive_moved"] == 0, (
        f"the inconclusive incomplete-upgrade retired its Stage-1 count "
        f"(under-sum): {c8!r}")
    # the error PRECEDENCE guard (the r3-1/r4-1 class): an escalated row
    # whose adapter RAISED carries error=… AND verification.incomplete=True
    # (the except arm surfaces the minimal incomplete dict) — the
    # retirement STILL fires (the error re-buckets the row into
    # error_count, an envelope column; the incomplete gate must not
    # swallow it back into the base term)
    c9 = _count_verification_outcomes([
        {"unit_id": "x", "finding": "safe",
         "stage1_finding": "safe", "error": "Boom: adapter raised",
         "verification": {"agree": False, "incomplete": True}}])
    assert c9["escalated_safe_moved"] == 1, c9
    assert c9["error_count"] == 1, c9


def test_the_producer_seam_pins_the_real_incomplete_upgrade_shape():
    """The T1-r2 N1 catch: the counter pins (c7/c8) must match the
    PRODUCER's actual serialization, not a hand-written variant — the
    FAM-REPORT-2 parse flips ``agree`` to False, so the serialized dict
    carries agree=False + incomplete=True + correct_finding=<the
    more-severe verdict>, and the result assembly propagates
    finding=correct_finding. Driven through the REAL _parse_finish_result
    (the seam the counter consumes)."""
    from utilities.finding_verifier import FindingVerifier

    verifier = FindingVerifier.__new__(FindingVerifier)
    # the finish model AGREES (agree=True) but asserts a divergent
    # correct_finding — the FAM-REPORT-2 self-contradictory finish
    parsed = verifier._parse_finish_result(
        {"agree": True, "correct_finding": "vulnerable",
         "explanation": "truncated mid-answer"},
        "safe", 1, 1)
    got = parsed.to_dict()
    assert got["agree"] is False, (
        f"the parse did NOT flip the self-contradictory agree: {got!r}")
    assert got["incomplete"] is True, got
    assert got["correct_finding"] == "vulnerable", got
    # and the counter consumes exactly this shape without retiring (c7):
    from core.verifier import _count_verification_outcomes
    row = {"unit_id": "seam", "finding": "vulnerable",
           "stage1_finding": "safe", "verification": got}
    c = _count_verification_outcomes([row])
    assert c["needs_review"] == 1, c
    assert c["escalated_safe_moved"] == 0, (
        f"the REAL producer shape retired its Stage-1 count: {c!r}")


# ---------------------------------------------------------------------------
# S3 — the real-run admission + the threading
# ---------------------------------------------------------------------------
def test_the_real_run_admits_and_counts_the_disagreement_row(monkeypatch, tmp_path):
    """The REAL run_verification with a results fixture carrying the
    disagreement row: the batch receives it (with the origin stamp), and
    the VerifyResult threads escalated_safe_moved."""
    import core.verifier as verifier_mod
    from utilities.llm import PhaseBinding
    from utilities.finding_verifier import FindingVerifier

    reset_warning_state()
    results_path = tmp_path / "results.json"
    results_path.write_text(json.dumps({
        "results": [
            {"unit_id": "a:v", "route_key": "a:v", "finding": "vulnerable",
             "verdict": "vulnerable", "reasoning": "r", "confidence": 0.9},
            {"unit_id": "b:safe", "route_key": "b:safe", "finding": "safe",
             "verdict": "safe", "reasoning": "r",
             "security_classification": "exploitable"},
        ],
        "code_by_route": {"a:v": "code", "b:safe": "code"},
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
        seen.extend((r.get("unit_id"), r.get("stage1_finding"))
                    for r in results)
        # Stage 2 CONFIRMS the enhance disagreement: the row is vulnerable
        for r in results:
            if r.get("stage1_finding") == "safe":
                r["verification"] = {"agree": False,
                                     "correct_finding": "vulnerable"}
                r["finding"] = "vulnerable"
        return results

    monkeypatch.setattr(FindingVerifier, "verify_batch", fake_verify_batch)
    monkeypatch.setattr(verifier_mod, "load_index_from_file",
                        lambda path, repo: SimpleNamespace(functions=[]))
    vr = verifier_mod.run_verification(
        str(results_path), str(tmp_path / "out"),
        analyzer_output_path=str(analyzer_output),
        registry=_Registry(), workers=1)
    reset_warning_state()

    assert ("b:safe", "safe") in seen, (
        f"the disagreement row never reached Stage 2 (or the stamp missed): "
        f"{seen!r}")
    assert vr.escalated_safe_moved == 1, (
        f"the moved count did not thread through the real run: {vr!r}")


# ---------------------------------------------------------------------------
# S7 — the scan-path gate (the T1-r3 catch): the 0-positive corpus reaches Stage 2
# ---------------------------------------------------------------------------
def test_the_scan_gate_opens_for_the_all_safe_corpus():
    """The T1-r3 F1 catch: the scanner's Stage-2 gate gated on the raw
    vulnerable/bypassable count, so a scan where Stage 1 marked every unit
    SAFE — the #743 headline corpus, where the classification disagreement
    is the ONLY second look — never reached Stage 2 through the scan path.
    The gate's authority is the admission filter: a Stage-1 positive OR a
    non-empty stage2_candidates set opens it."""
    from core.analyzer import AnalysisMetrics
    from core.verifier import stage2_candidates, stage2_gate_open

    all_safe_metrics = AnalysisMetrics(
        total=3, vulnerable=0, bypassable=0, inconclusive=0,
        protected=0, safe=3, errors=0)
    disagreement_rows = [
        {"unit_id": "a:safe", "finding": "safe",
         "security_classification": "exploitable"},
        {"unit_id": "b:safe", "finding": "safe",
         "security_classification": "vulnerable_internal"},
    ]
    clean_rows = [
        {"unit_id": "a:safe", "finding": "safe",
         "security_classification": "safe"},
    ]
    # the all-SAFE corpus WITH the enhancer's disagreement: OPEN
    assert stage2_gate_open(all_safe_metrics, disagreement_rows) is True, (
        "the 0-positive corpus never reaches Stage 2 through the scan path")
    # the all-SAFE corpus with a clean scan: CLOSED (no cry-wolf)
    assert stage2_gate_open(all_safe_metrics, clean_rows) is False
    # a Stage-1 positive: OPEN regardless of the rows
    pos_metrics = AnalysisMetrics(
        total=1, vulnerable=1, bypassable=0, inconclusive=0,
        protected=0, safe=0, errors=0)
    assert stage2_gate_open(pos_metrics, []) is True
    # consistency: the gate never opens past the admission filter
    assert not (stage2_candidates(disagreement_rows)
                and not stage2_gate_open(all_safe_metrics, disagreement_rows))
    assert not (stage2_candidates(clean_rows)
                and not stage2_gate_open(all_safe_metrics, clean_rows))


# ---------------------------------------------------------------------------
# S8 — the scan-path WIRING (the T1-r3 catch): the REAL scan_repository
# opens its verify branch for the 0-positive corpus
# ---------------------------------------------------------------------------
def test_the_real_scan_opens_stage2_for_the_all_safe_corpus(
        tmp_path, monkeypatch):
    """The T1-r3 F1 falsifier, driven end-to-end: a REAL scan_repository
    whose Stage-1 metrics say vulnerable=0/bypassable=0 (the all-SAFE
    corpus) while the results carry the enhance disagreement reaches
    run_verification — and a clean all-SAFE corpus records the
    ``no_candidates`` skip instead."""
    import core.analyzer as analyzer
    import core.parser_adapter as parser_adapter
    import core.verifier as verifier_mod
    from core.analyzer import AnalysisMetrics
    from core.schemas import VerifyResult
    from utilities.llm_client import reset_warning_state
    import utilities.llm as llm_mod

    reset_warning_state()

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 2
            self.language = "python"
            self.processing_level = "reachable"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        Path(pr.dataset_path).write_text('{"units": [], "metadata": {}}')
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    all_safe_metrics = AnalysisMetrics(
        total=2, vulnerable=0, bypassable=0, inconclusive=0,
        protected=0, safe=2, errors=0)

    class _AnalyzeResult:
        def __init__(self, output_dir, rows):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text(
                json.dumps({"results": rows, "code_by_route": {}}))
            self.metrics = all_safe_metrics

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None)

    seen: list = []

    def _fake_run_verification(*, results_path, output_dir, **kwargs):
        seen.append(results_path)
        out = Path(output_dir) / "results_verified.json"
        out.write_text(json.dumps({"results": [], "code_by_route": {}}))
        return VerifyResult(
            verified_results_path=str(out),
            findings_input=2, findings_verified=2,
            agreed=1, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=1,
            needs_review=0, error_count=0, units_analyzed_total=2)

    monkeypatch.setattr(verifier_mod, "run_verification",
                        _fake_run_verification)

    from core import scanner as scanner_mod

    def _scan(rows):
        nonlocal seen
        seen = []
        monkeypatch.setattr(
            analyzer, "run_analysis",
            lambda *, output_dir, **kw: _AnalyzeResult(output_dir, rows))
        return scanner_mod.scan_repository(
            repo_path=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            generate_context=False,
            enhance=False,
            verify=True,
            generate_report=False,
            dynamic_test=False,
            processing_level="reachable",
        )

    reset_warning_state()
    # the 0-positive corpus WITH the enhancer's disagreement: Stage 2 RUNS
    disagreement_rows = [
        {"unit_id": "a:safe", "finding": "safe", "verdict": "safe",
         "security_classification": "exploitable"},
        {"unit_id": "b:safe", "finding": "safe", "verdict": "safe",
         "security_classification": "vulnerable_internal"},
    ]
    r1 = _scan(disagreement_rows)
    assert seen, (
        "the all-SAFE corpus never reached Stage 2 through the REAL scan "
        f"(the T1-r3 gate): skips={getattr(r1, 'skipped_step_reasons', None)!r}")
    assert "verify" not in (r1.skipped_steps or []), (
        f"verify skipped on a disagreement corpus: {r1.skipped_step_reasons!r}")

    # the CLEAN all-SAFE corpus: the no_candidates skip fires (no cry-wolf)
    clean_rows = [
        {"unit_id": "a:safe", "finding": "safe", "verdict": "safe",
         "security_classification": "safe"},
        {"unit_id": "b:safe", "finding": "safe", "verdict": "safe",
         "security_classification": "neutral"},
    ]
    seen2 = _scan(clean_rows)
    assert not seen, (
        f"a clean corpus escalated to Stage 2: {seen!r}")
    assert (getattr(seen2, "skipped_step_reasons", {}) or {}).get(
        "verify") == "no_candidates", (
        f"the clean-corpus skip reason is wrong: "
        f"{seen2.skipped_step_reasons!r}")
    reset_warning_state()


# ---------------------------------------------------------------------------
# S9 — the T1-r4 consequence: the downstream gates read the POST-VERIFY
# metrics, not the Stage-1 snapshot
# ---------------------------------------------------------------------------
def test_the_post_verify_findings_drive_the_downstream_gates(
        tmp_path, monkeypatch):
    """The T1-r4 F1 falsifier, driven end-to-end: a widened-gate scan (the
    0-positive corpus) whose Stage 2 CONFIRMS a vulnerability leaves the
    post-verify metrics carrying it — the downstream dynamic-test gate
    must read that post-verify truth, not the Stage-1 snapshot (else
    metrics.vulnerable=1 / a pipeline finding / CLI exit 1 while
    dynamic-test records ``no_candidates`` — the #799 machine-artifacts-
    disagree class). Docker is forced absent so the decision is observable
    as ``docker_unavailable``, never ``no_candidates``."""
    import core.analyzer as analyzer
    import core.parser_adapter as parser_adapter
    import core.verifier as verifier_mod
    from core.analyzer import AnalysisMetrics
    from core.schemas import VerifyResult
    from utilities.llm_client import reset_warning_state
    import utilities.llm as llm_mod

    reset_warning_state()

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 2
            self.language = "python"
            self.processing_level = "reachable"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        Path(pr.dataset_path).write_text('{"units": [], "metadata": {}}')
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    all_safe_metrics = AnalysisMetrics(
        total=2, vulnerable=0, bypassable=0, inconclusive=0,
        protected=0, safe=2, errors=0)

    class _AnalyzeResult:
        def __init__(self, output_dir, rows):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text(
                json.dumps({"results": rows, "code_by_route": {}}))
            self.metrics = all_safe_metrics

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None)

    def _fake_run_verification(*, results_path, output_dir, **kwargs):
        out = Path(output_dir) / "results_verified.json"
        out.write_text(json.dumps({"results": [], "code_by_route": {}}))
        return VerifyResult(
            verified_results_path=str(out),
            findings_input=2, findings_verified=2,
            agreed=0, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=1,
            needs_review=0, error_count=0, units_analyzed_total=2)

    monkeypatch.setattr(verifier_mod, "run_verification",
                        _fake_run_verification)
    # docker FORCED absent so the dynamic-test decision is observable
    # (docker_unavailable), never a run
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda p: None)

    disagreement_rows = [
        {"unit_id": "a:safe", "finding": "safe", "verdict": "safe",
         "security_classification": "exploitable"},
        {"unit_id": "b:safe", "finding": "safe", "verdict": "safe",
         "security_classification": "vulnerable_internal"},
    ]
    monkeypatch.setattr(
        analyzer, "run_analysis",
        lambda *, output_dir, **kw: _AnalyzeResult(output_dir, disagreement_rows))

    from core import scanner as scanner_mod
    reset_warning_state()
    r = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        generate_context=False,
        enhance=False,
        verify=True,
        generate_report=False,
        dynamic_test=True,
        processing_level="reachable",
    )
    reset_warning_state()

    # Stage 2 confirmed a vulnerability out of the all-SAFE corpus
    assert r.metrics.vulnerable == 1, (
        f"the post-verify metrics lost the confirmation: {r.metrics!r}")
    # the dynamic-test gate read the POST-VERIFY truth: docker_unavailable
    # (a decision), never no_candidates (the Stage-1 snapshot's stale skip)
    dt_reason = (getattr(r, "skipped_step_reasons", {}) or {}).get(
        "dynamic-test")
    assert dt_reason != "no_candidates", (
        f"the downstream gate read the Stage-1 snapshot: "
        f"metrics.vulnerable={r.metrics.vulnerable} while dynamic-test "
        f"records {dt_reason!r} — the #799 machine-artifacts-disagree class")
    assert dt_reason == "docker_unavailable", (
        f"docker forced absent but the decision was {dt_reason!r}")


# ---------------------------------------------------------------------------
# S10 — the T1-r5 F1 pin: the re-derivation is MONOTONE — the pre-existing
# verify-succeeded path keeps its gates
# ---------------------------------------------------------------------------
def test_a_stage1_positive_never_loses_its_downstream_gates(
        tmp_path, monkeypatch):
    """The T1-r5 F1 falsifier, driven end-to-end: a scan whose Stage 1 had
    positives and whose Stage 2 confirmed NONE (the rows left
    unverified/errored — the #284 real-run shape) must keep its downstream
    gates OPEN (the #69 F4/F5 fail-safe: unverified rows are
    DISCLOSURE_ELIGIBLE, and dynamic-test must see a decision, not the
    stale no_candidates). A naive re-derivation (has_findings := post-verify
    count) flips True→False here — the disclosure fail-safe regressed and
    the #799 machine-artifacts-disagree class lands on a PRE-EXISTING path.
    The monotone form (Stage-1 True OR post-verify positive) is the no-op
    the r4 consequence fix claimed."""
    import core.analyzer as analyzer
    import core.parser_adapter as parser_adapter
    import core.verifier as verifier_mod
    from core.analyzer import AnalysisMetrics
    from core.schemas import VerifyResult
    from utilities.llm_client import reset_warning_state
    import utilities.llm as llm_mod

    reset_warning_state()

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 1
            self.language = "python"
            self.processing_level = "reachable"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        Path(pr.dataset_path).write_text('{"units": [], "metadata": {}}')
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    stage1_positive = AnalysisMetrics(
        total=1, vulnerable=1, bypassable=0, inconclusive=0,
        protected=0, safe=0, errors=0)

    class _AnalyzeResult:
        def __init__(self, output_dir, rows):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text(
                json.dumps({"results": rows, "code_by_route": {}}))
            self.metrics = stage1_positive

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None)

    def _fake_run_verification(*, results_path, output_dir, **kwargs):
        out = Path(output_dir) / "results_verified.json"
        out.write_text(json.dumps({"results": [], "code_by_route": {}}))
        # Stage 2 ran and confirmed NOTHING: the row left needs_review
        return VerifyResult(
            verified_results_path=str(out),
            findings_input=1, findings_verified=1,
            agreed=0, disagreed=0, disagreed_inconclusive=0,
            disagreed_protected=0, confirmed_vulnerabilities=0,
            needs_review=1, error_count=0, units_analyzed_total=1)

    monkeypatch.setattr(verifier_mod, "run_verification",
                        _fake_run_verification)
    import shutil as _shutil
    monkeypatch.setattr(_shutil, "which", lambda p: None)

    monkeypatch.setattr(
        analyzer, "run_analysis",
        lambda *, output_dir, **kw: _AnalyzeResult(
            output_dir, [{"unit_id": "a:v", "finding": "vulnerable"}]))

    from core import scanner as scanner_mod
    reset_warning_state()
    r = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        generate_context=False,
        enhance=False,
        verify=True,
        generate_report=False,
        dynamic_test=True,
        processing_level="reachable",
    )
    reset_warning_state()

    # the downstream gate stays OPEN for the Stage-1-positive corpus whose
    # Stage 2 confirmed none: the decision is docker_unavailable (a
    # decision), never the stale no_candidates — the same ``has_findings``
    # value also gates the report step's disclosures (the #69 fail-safe:
    # the unverified row is DISCLOSURE_ELIGIBLE)
    dt_reason = (getattr(r, "skipped_step_reasons", {}) or {}).get(
        "dynamic-test")
    assert dt_reason != "no_candidates", (
        f"the pre-existing verify-succeeded path lost its downstream gates "
        f"(the naive re-derivation): dt={dt_reason!r} while Stage 1 had a "
        f"positive awaiting its manual review")
    assert dt_reason == "docker_unavailable", (
        f"docker forced absent but the decision was {dt_reason!r}")


# ---------------------------------------------------------------------------
# S4 — the consistency grouping excludes the safe-origin escalated rows
# ---------------------------------------------------------------------------
def test_the_consistency_grouping_excludes_the_safe_origin_rows():
    """The #744 F6 rule generalized: an escalated row (ANY origin) does not
    join the pattern groups — a {vulnerable, safe-origin-escalated} group
    would spend a consistency LLM call on a non-comparison and anchor the
    vulnerable sibling toward the escalated candidate."""
    from utilities.finding_verifier import FindingVerifier

    rows = [
        {"route_key": "a.go:errorMsg.json", "finding": "vulnerable"},
        {"route_key": "a.go:infoMsg.json", "finding": "vulnerable",
         "stage1_finding": "safe",
         "security_classification": "exploitable"},
        {"route_key": "a.go:warnMsg.json", "finding": "vulnerable"},
    ]
    verifier = FindingVerifier.__new__(FindingVerifier)
    groups = verifier._group_by_pattern(rows)
    members = [r["route_key"] for g in groups.values() for r in g]
    assert "a.go:infoMsg.json" not in members, (
        f"the safe-origin escalated row joined a pattern group: {groups!r}")
    assert "a.go:errorMsg.json" in members and "a.go:warnMsg.json" in members
