"""#742 — an all-incomplete enhancement phase still rolls up as status
``success``: ``incomplete_count`` is recorded as a summary counter only and
never derives a step status (``step_context`` computes ``partial`` from
``errors``/``error_count`` alone). The campaign evidence: ``--limit 3`` runs
that enhanced 2 of 3 units — the third hit ``max_iterations`` (the
context-discard class, #730) — still reported ``status: "success"``,
``errors: []`` at the top level; an ALL-incomplete enhancement (every unit
discarded its gathered context) reads the same green.

THE RULING (the issue's suggested fix, both halves):
  1. the generic derivation: a step whose summary carries a well-typed
     ``incomplete_count > 0`` derives AT LEAST ``partial`` — the symmetric
     rule to ``error_count`` (one incomplete unit degrades the step exactly
     as one errored unit does; no fraction threshold, the same contract
     shape #285/#376 established for errors);
  2. the aggregate surface: ``scan.report.json``'s step summary gains a
     present-only ``steps_incomplete`` map (``{step: count}``) next to the
     degraded status, so the top level says WHAT was incomplete, not only
     that something degraded.

Shapes:
  S1 -- the WITNESS (assertion-red at base): the ALL-incomplete step -- the
        REAL step_context, an enhance-shaped summary with
        incomplete_count == total_units and ZERO errors -- derives
        ``partial``, never ``success``.
  S2 -- the campaign shape: 1 of 3 incomplete (the measured evidence)
        derives ``partial``.
  S3 -- the error_count parity control: errors alone still degrade (the
        pre-existing contract, the regression bound).
  S4 -- the clean control: no errors, no incompletes -> ``success`` (the
        no-cry-wolf bound).
  S5 -- the degrade idiom survives: an explicit ``skipped`` status with no
        errors and no incompletes stays ``skipped`` (the scanner's
        status-first idiom unaffected).
  S6 -- the WITNESS for the aggregate half (assertion-red at base): the
        REAL _write_scan_report with an enhance step report carrying
        incomplete_count surfaces ``steps_incomplete: {"enhance": N}`` in
        the scan report's summary beside the degraded aggregate status.
  S7 -- the aggregate control: a clean steps list carries NO
        steps_incomplete key (present-only, additive/non-breaking).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.step_report import step_context  # noqa: E402


def _read_report(tmp_path: Path, step: str) -> dict:
    return json.loads(
        (tmp_path / f"{step}.report.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# S1/S2 — the incomplete_count derivation (the status half)
# ---------------------------------------------------------------------------
def test_all_incomplete_step_derives_partial_not_success(tmp_path):
    """The #742 headline shape: every unit hit the iteration limit — zero
    errors, zero enhanced context — the step must not claim success."""
    with step_context("enhance", str(tmp_path)) as ctx:
        ctx.summary = {
            "units_enhanced": 0,
            "error_count": 0,
            "classifications": {},
            "mode": "agentic",
            "incomplete_count": 3,
            "total_units": 3,
        }
        ctx.outputs = {"enhanced_dataset_path": "x.json"}
    report = _read_report(tmp_path, "enhance")
    assert report["status"] == "partial", (
        f"an all-incomplete enhancement step still claims "
        f"{report['status']!r} — the top level reads green on a scan whose "
        f"enhancement produced nothing (the #742 gap)")


def test_one_of_three_incomplete_still_degrades(tmp_path):
    """The campaign's measured shape: 2 of 3 enhanced, the third hit
    max_iterations — the step's summary counter alone must degrade."""
    with step_context("enhance", str(tmp_path)) as ctx:
        ctx.summary = {
            "units_enhanced": 2,
            "error_count": 0,
            "incomplete_count": 1,
            "total_units": 3,
        }
    assert _read_report(tmp_path, "enhance")["status"] == "partial"


# ---------------------------------------------------------------------------
# S3/S4/S5 — the controls (the pre-existing contract + the bounds)
# ---------------------------------------------------------------------------
def test_error_count_alone_still_degrades(tmp_path):
    """The #285/#376 contract, unchanged: error_count > 0 -> partial."""
    with step_context("enhance", str(tmp_path)) as ctx:
        ctx.summary = {"units_enhanced": 0, "error_count": 2,
                       "incomplete_count": 0, "total_units": 3}
    assert _read_report(tmp_path, "enhance")["status"] == "partial"


def test_clean_step_still_success(tmp_path):
    """The no-cry-wolf bound: no errors, no incompletes -> success."""
    with step_context("enhance", str(tmp_path)) as ctx:
        ctx.summary = {"units_enhanced": 3, "error_count": 0,
                       "incomplete_count": 0, "total_units": 3}
    assert _read_report(tmp_path, "enhance")["status"] == "success"


def test_explicit_skipped_with_zero_incomplete_unchanged(tmp_path):
    """The scanner's degrade idiom (status='skipped', no errors, no
    incompletes) is unaffected — the #742 rule never un-skips a step."""
    with step_context("enhance", str(tmp_path)) as ctx:
        ctx.status = "skipped"
        ctx.summary = {"skipped": True, "reason": "api down",
                       "incomplete_count": 0, "error_count": 0}
    assert _read_report(tmp_path, "enhance")["status"] == "skipped"


# ---------------------------------------------------------------------------
# S6/S7 — the aggregate surface (the surfacing half)
# ---------------------------------------------------------------------------
def _step_report_dict(step, status, summary=None, errors=None):
    return {
        "step": step,
        "status": status,
        "errors": errors or [],
        "summary": summary or {},
        "cost_usd": 0.0,
        "duration_seconds": 0.01,
    }


def test_the_scan_report_surfaces_steps_incomplete_beside_the_status(tmp_path):
    """The issue's second half: ``summary.incomplete_count`` must surface in
    the AGGREGATE scan report next to the step status — the top level says
    WHAT was incomplete (the per-step count), not only that something
    degraded."""
    from core.schemas import ScanResult
    from core.scanner import _write_scan_report

    result = ScanResult(output_dir=str(tmp_path), units_count=3,
                        language="python")
    step_reports = [
        _step_report_dict("parse", "success", {"total_units": 3}),
        _step_report_dict("enhance", "partial", {
            "units_enhanced": 0, "error_count": 0,
            "incomplete_count": 3, "total_units": 3,
        }),
        _step_report_dict("report", "success"),
    ]
    report_path = _write_scan_report(
        str(tmp_path), result, step_reports, repo_path=str(tmp_path))
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    # the aggregate degraded (the worst-per-step rule, #285)
    assert report["status"] == "partial", (
        f"the aggregate lost the degraded step: {report['status']!r}")
    # AND the count surfaces beside it (the #742 half)
    summary = report.get("summary") or {}
    assert summary.get("steps_incomplete") == {"enhance": 3}, (
        f"the aggregate does not name WHAT was incomplete: "
        f"{summary.get('steps_incomplete')!r}")


def test_the_clean_scan_carries_no_steps_incomplete_key(tmp_path):
    """Present-only, additive/non-breaking: a clean steps list adds NO
    steps_incomplete key (consumers of the summary dict see no new key on
    the clean path)."""
    from core.schemas import ScanResult
    from core.scanner import _write_scan_report

    result = ScanResult(output_dir=str(tmp_path), units_count=1,
                        language="python")
    step_reports = [
        _step_report_dict("parse", "success", {"total_units": 1}),
        _step_report_dict("enhance", "success", {
            "units_enhanced": 1, "error_count": 0,
            "incomplete_count": 0, "total_units": 1,
        }),
    ]
    report_path = _write_scan_report(
        str(tmp_path), result, step_reports, repo_path=str(tmp_path))
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    summary = report.get("summary") or {}
    assert "steps_incomplete" not in summary, (
        f"the clean scan grew a steps_incomplete key: "
        f"{summary.get('steps_incomplete')!r}")
    assert report["status"] == "success"


# ---------------------------------------------------------------------------
# S8 — the END-TO-END leg (the T1-r1 F1 catch): the REAL step_context
# writes the report to disk, the scanner's own _load_step_report loads it
# back, and _write_scan_report aggregates the loaded dicts — the full
# round-trip the scan pipeline actually performs. The #742 reason must hold
# through the round-trip (S6 hand-feeds the degraded status, so its status
# assertion alone cannot fail for the #742 reason — the pre-existing #285
# worst-rank rule satisfies it whatever the derivation does).
# ---------------------------------------------------------------------------
def test_the_full_round_trip_degrades_and_surfaces(tmp_path):
    """The e2e falsifier, driven through the pipeline's own path: the
    derive-at-exit rule (step_context) → StepReport.write → disk →
    _load_step_report → _write_scan_report. If the on-disk round-trip ever
    dropped or retyped ``summary.incomplete_count``, or the derivation
    stopped degrading, the aggregate would read success and the map would
    be absent — both assertions fail for the #742 reason."""
    from core.scanner import _load_step_report, _write_scan_report
    from core.schemas import ScanResult

    with step_context("enhance", str(tmp_path)) as ctx:
        ctx.summary = {
            "units_enhanced": 0, "error_count": 0,
            "incomplete_count": 3, "total_units": 3,
        }
        ctx.outputs = {"enhanced_dataset_path": "x.json"}

    # the scanner's own loader — the exact round-trip the aggregate performs
    loaded = _load_step_report(str(tmp_path), "enhance")
    assert isinstance(loaded, dict) and loaded, "the step report did not load"

    # a clean sibling, loaded the same way, for the aggregate to rank
    with step_context("parse", str(tmp_path)) as ctx:
        ctx.summary = {"total_units": 3}
    loaded_parse = _load_step_report(str(tmp_path), "parse")

    result = ScanResult(output_dir=str(tmp_path), units_count=3,
                        language="python")
    report_path = _write_scan_report(
        str(tmp_path), result, [loaded_parse, loaded],
        repo_path=str(tmp_path))
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    # the derived status — through the round-trip, not hand-fed — degraded
    assert loaded.get("status") == "partial", (
        f"the disk round-trip lost the derivation: {loaded.get('status')!r}")
    assert report["status"] == "partial", (
        f"the aggregate reads {report['status']!r} on an all-incomplete "
        f"enhancement")
    # and the dimension surfaced beside it
    summary = report.get("summary") or {}
    assert summary.get("steps_incomplete") == {"enhance": 3}, (
        f"the round-trip dropped the incomplete dimension: "
        f"{summary.get('steps_incomplete')!r}")
