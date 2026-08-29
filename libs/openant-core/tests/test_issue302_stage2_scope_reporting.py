"""Regression tests for issue #302 — Stage 2's scope (the denominator and
the one-directionality of its changes) is absent from the persisted
artifacts: the step reports and SUMMARY_REPORT.md.

Stage 2 only examines Stage-1 positives (on the filing run, 223 of 5,475
analyzed units, 4.1%); every completed disagreement was a downgrade (40 of
41) — structural, not incidental, because only vulnerable/bypassable units
enter. The ratio is printed to stderr (#212) but reaches no persisted
artifact, and nothing records the direction of changes or notes when
analyze and verify resolve to the same model (Stage 2 then is not an
independent instrument).

Contract locked here (the issue's reporting suggestions 1-3):
- the verify step summary carries `units_analyzed_total` (M), `downgraded`,
  and `upgraded` — so "adjudicated N of M" and the one-directionality are
  visible in the step report;
- the direction counts come from `_count_verification_outcomes`, computed
  against the UN-overwritten `verdict` field (the Stage-1 original) via
  FINDING_VERDICT_ORDER severity rank;
- pipeline_stats forwards the scope fields (present-only) from the verify
  step report, so the summary generator's single input can state them;
- the summary template instructs the Stage-2 scope + direction lines;
- a same-model analyze/verify configuration is noted (scanner helper
  returns the note; it lands in the step summary as
  `same_model_verification`).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.schemas import VerifyResult, verify_step_summary  # noqa: E402
from core.verifier import _count_verification_outcomes  # noqa: E402

VR = VerifyResult(
    verified_results_path="/tmp/v.json", findings_input=223,
    findings_verified=41, agreed=1, disagreed=40,
    confirmed_vulnerabilities=1, needs_review=134, error_count=48,
    units_analyzed_total=5475, downgraded=40, upgraded=0,
)


def test_step_summary_carries_the_scope_fields():
    s = verify_step_summary(VR)
    assert s["units_analyzed_total"] == 5475
    assert s["downgraded"] == 40
    assert s["upgraded"] == 0


def test_verify_result_to_dict_carries_the_scope_fields():
    assert VR.to_dict()["units_analyzed_total"] == 5475
    assert VR.to_dict()["downgraded"] == 40


def _v(verdict, corrected, agree=False, **extra):
    """A verified-result shape: `verdict` is the UN-overwritten Stage-1
    original; `finding` is what the verifier wrote (the correction)."""
    r = {"verdict": verdict, "finding": corrected,
         "verification": {"agree": agree, "incomplete": False}}
    r.update(extra)
    return r


def test_direction_counts_downgrades():
    counts = _count_verification_outcomes([
        _v("vulnerable", "safe"),       # idx 0 -> 4: downgrade
        _v("vulnerable", "protected"),  # idx 0 -> 3: downgrade
    ])
    assert counts["downgraded"] == 2
    assert counts["upgraded"] == 0


def test_direction_counts_upgrades_and_neutrals():
    counts = _count_verification_outcomes([
        _v("bypassable", "vulnerable"),  # idx 1 -> 0: upgrade
        _v("vulnerable", "bypassable"),  # idx 0 -> 1: a severity DOWNGRADE
                                         # within the disclosure tier (still
                                         # disclosure-eligible — not a drop)
    ])
    assert counts["upgraded"] == 1
    assert counts["downgraded"] == 1


def test_direction_counts_only_completed_disagreements():
    """Agreed-with-unchanged-finding / incomplete / errored units contribute
    no direction."""
    counts = _count_verification_outcomes([
        _v("vulnerable", "vulnerable", agree=True),   # agreed, unchanged
        {"error": "boom", "verdict": "vulnerable", "finding": "vulnerable",
         "verification": {}},                          # errored
        _v("vulnerable", "vulnerable",
           verification={"agree": False, "incomplete": True}),  # incomplete
    ])
    assert counts["downgraded"] == 0
    assert counts["upgraded"] == 0


def test_consistency_pass_change_on_an_agreed_unit_counts_direction():
    """Wave catch (e2e MAJOR 2): the post-batch consistency pass can
    overwrite `finding` on an unit whose verification.agree is True —
    that change is a Stage-2 change and must reach the direction counters
    (it previously escaped them silently)."""
    counts = _count_verification_outcomes([
        _v("vulnerable", "safe", agree=True),  # agreed BUT consistency-downgraded
    ])
    assert counts["agreed"] == 1
    assert counts["downgraded"] == 1


def test_missing_verdict_field_contributes_no_direction():
    """A verdict-less record (finding overwritten, original unrecoverable)
    abstains from the direction counts rather than guessing."""
    counts = _count_verification_outcomes([
        {"finding": "safe", "verification": {"agree": False,
                                             "incomplete": False}},
    ])
    assert counts["downgraded"] == 0
    assert counts["upgraded"] == 0


# ---------------------------------------------------------------------------
# the reporter forwarding (pipeline_stats — the summary generator's input)
# ---------------------------------------------------------------------------
def _po(step_reports=None):
    import json
    import tempfile
    from core.reporter import build_pipeline_output
    from utilities.file_io import write_json

    tmp = Path(tempfile.mkdtemp())
    write_json(tmp / "results.json", {
        "dataset": "t", "code_by_route": {}, "metrics": {"total": 2},
        "confirmed_findings": [], "results": []})
    out = tmp / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp / "results.json"), output_path=str(out),
        language="python", repo_name="t/r", processing_level="reachable",
        step_reports=step_reports)
    return json.loads(out.read_text())


def test_reporter_forwards_verify_scope_from_step_reports():
    po = _po(step_reports=[{"step": "verify", "summary": {
        "findings_input": 223, "units_analyzed_total": 5475,
        "downgraded": 40, "upgraded": 0,
        "same_model_verification": True,
    }}])
    stats = po["pipeline_stats"]
    assert stats["units_analyzed_total"] == 5475
    assert stats["downgraded"] == 40
    assert stats["upgraded"] == 0
    assert stats["same_model_verification"] is True
    # wave catch (BLOCKER): the template's "adjudicated N of M" reads N from
    # pipeline_stats.findings_input — it must actually be forwarded
    assert stats["findings_input"] == 223


def test_reporter_same_model_false_forwarded():
    po = _po(step_reports=[{"step": "verify", "summary": {
        "findings_input": 5, "units_analyzed_total": 100,
        "downgraded": 1, "upgraded": 0,
        "same_model_verification": False,
    }}])
    assert po["pipeline_stats"]["same_model_verification"] is False


def test_same_model_note_none_inputs():
    from core.scanner import same_model_verification_note
    class _B:
        model = "m"
        provider_name = "anthropic"
    assert same_model_verification_note(None, _B()) is None
    assert same_model_verification_note(_B(), None) is None


def test_reporter_scope_fields_absent_without_a_verify_report():
    po = _po(step_reports=[{"step": "analyze", "summary": {"total_units": 5}}])
    stats = po["pipeline_stats"]
    for k in ("units_analyzed_total", "downgraded", "upgraded",
              "same_model_verification"):
        assert k not in stats


# ---------------------------------------------------------------------------
# the same-model note (scanner helper)
# ---------------------------------------------------------------------------
def test_same_model_note():
    from core.scanner import same_model_verification_note

    class _B:
        def __init__(self, model, provider):
            self.model = model
            self.provider_name = provider

    assert same_model_verification_note(_B("m", "anthropic"),
                                         _B("m", "anthropic")) is not None
    note = same_model_verification_note(_B("m", "anthropic"),
                                         _B("m", "anthropic"))
    assert "same model" in note.lower() and "not an independent" in note.lower()
    assert same_model_verification_note(_B("m", "anthropic"),
                                         _B("other", "anthropic")) is None
    assert same_model_verification_note(_B("m", "anthropic"),
                                         _B("m", "openai")) is None


# ---------------------------------------------------------------------------
# the summary template instruction
# ---------------------------------------------------------------------------
def test_summary_template_states_stage2_scope():
    src = (PROJECT_ROOT / "report" / "prompts" / "summary.txt").read_text()
    assert "units_analyzed_total" in src, (
        "the template must instruct the Stage-2 denominator line "
        "(adjudicated N of M; the rest not re-examined)")
    assert "downgraded" in src and "upgraded" in src, (
        "the template must state the direction of Stage-2 changes")
    assert "same_model_verification" in src, (
        "the template must instruct the same-model independence caveat")
