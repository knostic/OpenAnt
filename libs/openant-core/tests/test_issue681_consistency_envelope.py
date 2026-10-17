"""#681: a consistency-rewritten row reaches its scanner-envelope bucket.

An agreed Stage-2 consistency reply that volunteers findings_to_update can
rewrite a row's finding (e.g. vulnerable -> protected) with agree=True —
the rewritten row previously reached NO envelope bucket: the envelope's
`protected = analyze.protected + disagreed_protected` counts neither term
(the analysis metrics counted the row vulnerable at Stage 1; the rewrite
is not a disagreement). The recount (which reads the finding field) said
protected while the envelope said otherwise — two numbers across three
surfaces, the envelope the outlier (#654's named fix: source the partition
from the recount's own buckets).

The fix: the per-row counter (#622's authority, the one the envelope
already consumes) gains the consistency-rewrite buckets by destination,
and the scanner envelope folds them — the sum-to-total property restored.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.verifier import _count_verification_outcomes  # noqa: E402


def _rewritten(from_="vulnerable", to="protected", agree=True, **extra):
    """An agreed row the consistency pass rewrote — the apply loop's shape
    (finding_verifier.py:1337): finding := new_verdict, verification.agree
    untouched (True), consistency_update records the from/to."""
    return {
        "route_key": "test:f",
        "finding": to,
        "verdict": from_,
        "verification": {"agree": agree, "correct_finding": to,
                         "explanation": "consistent"},
        "consistency_update": {"from": from_, "to": to,
                               "reason": "wave catch", "pattern": "p"},
        **extra,
    }


def test_consistency_rewritten_to_protected_reaches_its_bucket():
    """THE #681 SHAPE: the agreed+rewritten-to-protected row counts
    consistency_protected — the bucket the envelope folds into protected."""
    counts = _count_verification_outcomes([_rewritten("vulnerable", "protected")])
    assert counts["consistency_protected"] == 1, (
        "the consistency-rewritten-to-protected row must reach its own "
        "bucket (the envelope's protected fold) — the #681 invisibility"
    )
    # the agreement surfaces stay honest: the row DID agree, and the
    # direction computation still counts the rewrite (the #302 wave catch)
    assert counts["agreed"] == 1
    assert counts["downgraded"] == 1


def test_consistency_rewritten_to_safe_reaches_its_bucket():
    counts = _count_verification_outcomes([_rewritten("vulnerable", "safe")])
    assert counts["consistency_safe"] == 1, (
        "a rewrite to safe must thread to the safe fold — otherwise the "
        "envelope under-counts safe and the sum-to-total property breaks"
    )


def test_consistency_rewritten_to_inconclusive_reaches_its_bucket():
    counts = _count_verification_outcomes([_rewritten("vulnerable", "inconclusive")])
    assert counts["consistency_inconclusive"] == 1, (
        "a rewrite to inconclusive threads to the inconclusive fold (#509's "
        "sibling — an explicitly-unconfirmable finding, never a safe fold)"
    )


def test_a_plain_agreed_row_counts_no_consistency_bucket():
    """The control: agree=True WITHOUT a consistency rewrite touches no
    new bucket (the gate is the record the apply loop writes, not the
    agreement)."""
    row = _rewritten()
    del row["consistency_update"]
    counts = _count_verification_outcomes([row])
    assert counts["consistency_protected"] == 0
    assert counts["consistency_safe"] == 0
    assert counts["consistency_inconclusive"] == 0
    assert counts["agreed"] == 1


def test_a_disagreed_row_counts_no_consistency_bucket():
    """The control: the #622 arm is unchanged — a DISAGREED corrected row
    still counts disagreed_protected, never consistency_protected (the
    two surfaces stay distinguishable)."""
    row = _rewritten("vulnerable", "protected", agree=False)
    del row["consistency_update"]
    counts = _count_verification_outcomes([row])
    assert counts["disagreed_protected"] == 1
    assert counts["consistency_protected"] == 0


def test_the_envelope_folds_the_consistency_buckets():
    """THE #681 ENVELOPE HALF: the post-verify metrics assembly folds the
    consistency buckets into their columns — the envelope and the recount
    agree (the #654-named fix; the two-numbers-three-surfaces defect)."""
    from core.scanner import _post_verify_metrics
    from core.schemas import AnalysisMetrics

    analyze = AnalysisMetrics(total=2, vulnerable=1, safe=0, protected=0,
                               inconclusive=0, errors=0, bypassable=0)
    verify = type("V", (), {
        "confirmed_vulnerabilities": 0, "disagreed_inconclusive": 0,
        "disagreed_protected": 0, "disagreed": 0, "error_count": 0,
        "findings_verified": 1, "agreed": 1, "needs_review": 0,
        "consistency_protected": 1, "consistency_safe": 1,
        "consistency_inconclusive": 1})()
    m = _post_verify_metrics(analyze, verify)
    assert m.protected == 1, (
        "the envelope's protected must fold consistency_protected "
        "(analyze 0 + consistency 1) — the #681 envelope invisibility"
    )
    assert m.safe == 1
    assert m.inconclusive == 1


def test_e2e_consistency_rewrite_threads_to_every_surface(tmp_path, monkeypatch):
    """THE #681 E2E (the three wiring gaps the P3 cycle's surviving mutants
    proved): an agreed row the consistency pass rewrites must thread from
    ONE real run_verification drive to EVERY surface — the VerifyResult
    FIELD (the scanner envelope's fold source), the step SUMMARY (the
    display), and the DICT (the Go/CSV consumers' source). The unit tests
    drive _count and _post_verify_metrics directly; this is the wiring
    between them."""
    import json as _json

    import core.verifier as verifier_mod
    from core.schemas import verify_step_summary
    from utilities.file_io import write_json
    from utilities.llm import ToolUseBlock, CompletionResult

    CONSISTENCY_JSON = _json.dumps({
        "should_be_consistent": "true",
        "pattern_identified": "the shared validated sink",
        "consistent_verdict": "safe",
        "findings_to_update": [
            {"route_key": "s.py:errorMsg", "should_be": "safe",
             "reason": "both routes validated at the boundary"},
            {"route_key": "s.py:warnMsg", "should_be": "safe",
             "reason": "the wave catch: the guard holds here too"}],
        "explanation": "the pair shares the guard"})

    import utilities.llm as llm_mod
    monkeypatch.setattr(
        llm_mod, "simple_text",
        lambda binding, prompt, **kw: CONSISTENCY_JSON, raising=True)

    class _Scripted:
        supports_tools = True

        def __init__(self, responses):
            self._responses = responses
            self._n = 0

        def complete(self, *, model, system, messages, max_tokens, tools=None):
            self._n += 1
            resp = self._responses[min(self._n, len(self._responses)) - 1]
            return CompletionResult(
                content=[ToolUseBlock(id=f"finish-{self._n}", name="finish",
                                      input=resp)],
                input_tokens=1, output_tokens=1, stop_reason="tool_use")

    class _OfflineRegistry:
        def __init__(self, adapter):
            self._adapter = adapter

        def get(self, phase):
            from types import SimpleNamespace
            return SimpleNamespace(phase=phase, adapter=self._adapter,
                                   model="fake-model", provider_name="fake")

    payload = {
        "results": [
            {"unit_id": "u1", "route_key": "s.py:errorMsg",
             "finding": "vulnerable", "file": "s.py", "function": "errorMsg"},
            {"unit_id": "u2", "route_key": "s.py:warnMsg",
             "finding": "vulnerable", "file": "s.py", "function": "warnMsg"},
            {"unit_id": "u3", "route_key": "s.py:infoMsg",
             "finding": "vulnerable", "file": "s.py", "function": "infoMsg"},
            {"unit_id": "u4", "route_key": "s.py:failMsg",
             "finding": "vulnerable", "file": "s.py", "function": "failMsg"},
        ],
        "code_by_route": {"s.py:errorMsg": "def errorMsg(): pass",
                          "s.py:warnMsg": "def warnMsg(): pass",
                          "s.py:infoMsg": "def infoMsg(): pass",
                          "s.py:failMsg": "def failMsg(): pass"},
        "metrics": {"total": 4, "vulnerable": 4},
    }
    results_path = tmp_path / "results.json"
    write_json(results_path, payload)
    analyzer_path = tmp_path / "analyzer_output.json"
    write_json(analyzer_path, {"functions": {}})
    vr = verifier_mod.run_verification(
        results_path=str(results_path),
        output_dir=str(tmp_path),
        analyzer_output_path=str(analyzer_path),
        workers=1,
        registry=_OfflineRegistry(_Scripted([
            {"agree": True, "correct_finding": "vulnerable",
             "explanation": "confirmed exploitable"},
            {"agree": True, "correct_finding": "vulnerable",
             "explanation": "confirmed exploitable too"},
            {"agree": True, "correct_finding": "vulnerable",
             "explanation": "confirmed exploitable as well"},
            {"agree": False, "correct_finding": "safe",
             "explanation": "input validated; controls hold"},
        ])))
    # THE FIELD (the threading): the DISTINCT tuple — agreed=3, rewritten=2,
    # disagreed=1, confirmed=1 — so a cross-wire (threading the wrong
    # count) is visible at every surface, not just the zero/nonzero (the
    # T1's F1: the degenerate 1/1/1 let wrong-field mutants survive)
    assert (vr.consistency_safe, vr.agreed, vr.disagreed,
            vr.confirmed_vulnerabilities) == (2, 3, 1, 1), (
        f"the distinct counts must reach the FIELDS (got "
        f"consistency_safe={vr.consistency_safe}, agreed={vr.agreed}, "
        f"disagreed={vr.disagreed}, "
        f"confirmed={vr.confirmed_vulnerabilities}) — the e2e wiring")
    # THE SUMMARY (the display): the step summary threads it beside #622
    summary = verify_step_summary(vr)
    assert (summary.get("consistency_safe"),
            summary.get("agreed")) == (2, 3), (
        f"the step SUMMARY must thread the distinct counts "
        f"(got consistency_safe={summary.get('consistency_safe')}, "
        f"agreed={summary.get('agreed')}) — the display surface")
    # THE DICT (the consumers' source)
    d = vr.to_dict()
    assert (d.get("consistency_safe"), d.get("agreed")) == (2, 3), (
        f"the DICT must thread the distinct counts "
        f"(got consistency_safe={d.get('consistency_safe')}, "
        f"agreed={d.get('agreed')}) — the Go/CSV consumers' source")
