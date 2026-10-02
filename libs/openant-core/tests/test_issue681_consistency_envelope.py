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
             "reason": "both routes validated at the boundary"}],
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
            {"unit_id": "u2", "route_key": "s.py:infoMsg",
             "finding": "vulnerable", "file": "s.py", "function": "infoMsg"},
        ],
        "code_by_route": {"s.py:errorMsg": "def errorMsg(): pass",
                          "s.py:infoMsg": "def infoMsg(): pass"},
        "metrics": {"total": 2, "vulnerable": 2},
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
            {"agree": False, "correct_finding": "safe",
             "explanation": "input validated; controls hold"},
        ])))
    # THE FIELD (the threading): the rewrite reached its VerifyResult bucket
    assert vr.consistency_safe == 1, (
        f"the consistency-rewritten-to-safe row must reach the FIELD "
        f"(got consistency_safe={vr.consistency_safe}) — the scanner "
        "envelope's safe fold threads from here (the e2e wiring)")
    assert vr.agreed == 1, "the rewritten row agreed (the rewrite class)"
    # THE SUMMARY (the display): the step summary threads it beside #622
    summary = verify_step_summary(vr)
    assert summary.get("consistency_safe") == 1, (
        f"the step SUMMARY must thread consistency_safe "
        f"(got {summary.get('consistency_safe')}) — the display surface")
    # THE DICT (the consumers' source)
    d = vr.to_dict()
    assert d.get("consistency_safe") == 1, (
        f"the DICT must thread consistency_safe "
        f"(got {d.get('consistency_safe')}) — the Go/CSV consumers' source")
