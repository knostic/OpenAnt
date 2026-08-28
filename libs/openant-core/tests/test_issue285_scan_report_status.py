"""Regression tests for issue #285 — the scan aggregate report is
unconditionally green.

``_write_scan_report`` built the aggregate ``StepReport(step="scan", ...)``
with no ``status=`` and no ``errors=``, and read only cost/duration/tokens/
step from the per-step reports it aggregates. ``StepReport.status`` defaults
to ``"success"`` — so a scan whose verify step recorded ``error_count: 48``
in its own summary, or whose report step appended to ``ctx.errors``, still
wrote ``scan.report.json: status=success, errors: []``. A partially-degraded
scan and a clean one were indistinguishable at the top level.

Contract locked here:
- ``step_context``: a body that records errors without raising ⇒ the step's
  status is ``"partial"`` (NOT "error" — nothing that branches on "error"
  changes behaviour), and the errors list is written;
- a body that completes clean with no errors ⇒ still ``"success"``;
- steps that count per-item failures in ``summary["error_count"]`` fire
  "partial" too (the REQUIRED step 3 — without it the derivation is inert
  for the most common degradation shape: verify with 48 errors);
- ``_write_scan_report`` aggregates: the scan status is the WORST per-step
  status (error > partial > skipped > success), and the aggregate errors
  list carries every per-step error.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.step_report import step_context  # noqa: E402


def _read(tmp_path: Path, step: str) -> dict:
    return json.loads((tmp_path / f"{step}.report.json").read_text())


# ---------------------------------------------------------------------------
# step-level: partial status derivation
# ---------------------------------------------------------------------------

def test_errors_without_raise_yields_partial(tmp_path: Path):
    """A step that records errors without raising gets status="partial"
    (not "success", not "error")."""
    with step_context("report", str(tmp_path)) as ctx:
        ctx.errors.append("Summary report: boom")
        ctx.summary = {"formats_generated": []}
    report = _read(tmp_path, "report")
    assert report["status"] == "partial", (
        f"recorded errors must not read as success (got {report['status']!r})"
    )
    assert report["errors"] == ["Summary report: boom"]


def test_clean_step_still_success(tmp_path: Path):
    with step_context("parse", str(tmp_path)) as ctx:
        ctx.summary = {"ok": True}
    assert _read(tmp_path, "parse")["status"] == "success"


def test_summary_error_count_fires_partial(tmp_path: Path):
    """The REQUIRED step-3: verify counts failures in summary["error_count"]
    without touching ctx.errors — the derivation must see them (the issue's
    own correction: without this, the fix is inert for the reporter's run
    shape: verify with 48 errors, all ten step reports success)."""
    with step_context("verify", str(tmp_path)) as ctx:
        ctx.summary = {"error_count": 48, "needs_review": 134,
                       "agreed": 1, "disagreed": 40}
    report = _read(tmp_path, "verify")
    assert report["status"] == "partial", (
        f"error_count>0 in summary must fire partial (got {report['status']!r})"
    )


def test_summary_zero_error_count_stays_success(tmp_path: Path):
    with step_context("verify", str(tmp_path)) as ctx:
        ctx.summary = {"error_count": 0, "needs_review": 0, "agreed": 5}
    assert _read(tmp_path, "verify")["status"] == "success"


def test_skipped_still_skipped(tmp_path: Path):
    """The #254 catch-and-continue degrade idiom is unaffected."""
    with step_context("enhance", str(tmp_path)) as ctx:
        ctx.status = "skipped"
        ctx.summary = {"skipped": True, "reason": "api down"}
    assert _read(tmp_path, "enhance")["status"] == "skipped" or \
        _read(tmp_path, "enhance")["status"] == "partial"
    # skipped + no errors → skipped (no false partial)
    if _read(tmp_path, "enhance")["status"] == "partial":
        assert _read(tmp_path, "enhance").get("errors"), "partial fired without errors"


# ---------------------------------------------------------------------------
# aggregate: _write_scan_report derives the worst status + collects errors
# ---------------------------------------------------------------------------

def _write_scan(tmp_path: Path, step_reports: list[dict]):
    from core.scanner import _write_scan_report
    from core.schemas import ScanResult, AnalysisMetrics
    metrics = AnalysisMetrics(total=0, vulnerable=0, bypassable=0, inconclusive=0,
                              protected=0, safe=0, errors=0)
    result = ScanResult(output_dir=str(tmp_path), units_count=0,
                        language="python", metrics=metrics)
    return _write_scan_report(str(tmp_path), result, step_reports)


def test_aggregate_status_worst_wins(tmp_path: Path):
    """The scan status = the worst per-step status; the aggregate errors
    carry every per-step error."""
    step_reports = [
        {"step": "parse", "status": "success", "errors": [],
         "cost_usd": 0.0, "duration_seconds": 1.0,
         "token_usage": {"input_tokens": 5, "output_tokens": 5, "total_tokens": 10}},
        {"step": "verify", "status": "partial", "errors": ["boom-1", "boom-2"],
         "cost_usd": 0.0, "duration_seconds": 1.0,
         "token_usage": {"input_tokens": 5, "output_tokens": 5, "total_tokens": 10}},
    ]
    path = _write_scan(tmp_path, step_reports)
    agg = json.loads(Path(path).read_text())
    assert agg["status"] == "partial"
    assert sorted(agg["errors"]) == ["boom-1", "boom-2"]


def test_aggregate_all_success(tmp_path):
    step_reports = [
        {"step": "parse", "status": "success", "errors": [],
         "cost_usd": 0.1, "duration_seconds": 1.0,
         "token_usage": {"input_tokens": 5, "output_tokens": 5, "total_tokens": 10}},
    ]
    path = _write_scan(tmp_path, step_reports)
    agg = json.loads(Path(path).read_text())
    assert agg["status"] == "success"
    assert agg["errors"] == []


def test_analyze_stage_summary_error_count_fires_partial(tmp_path):
    """kimi wave MAJOR-1: analyze counts per-unit failures in
    metrics.errors — its summary now carries the flat error_count the
    derivation reads, so an every-unit-errors Stage 1 is no longer
    status='success'."""
    with step_context("analyze", str(tmp_path)) as ctx:
        ctx.summary = {"total_units": 3, "analyzed": 1, "error_count": 2,
                       "verdicts": {"vulnerable": 0, "bypassable": 0,
                                    "inconclusive": 0, "protected": 0,
                                    "safe": 1, "errors": 2}}
    report = _read(tmp_path, "analyze")
    assert report["status"] == "partial"


def test_scanresult_carries_derived_status(tmp_path):
    """sonnet wave BLOCKER-1: the derived status/errors reach the
    ScanResult (envelope/webui consumers), not just the on-disk report."""
    from core.schemas import ScanResult, AnalysisMetrics
    from core.scanner import _write_scan_report
    metrics = AnalysisMetrics(total=0, vulnerable=0, bypassable=0, inconclusive=0,
                              protected=0, safe=0, errors=0)
    result = ScanResult(output_dir=str(tmp_path), units_count=0,
                        language="python", metrics=metrics)
    step_reports = [
        {"step": "verify", "status": "partial", "errors": ["e1"],
         "cost_usd": 0.0, "duration_seconds": 1.0,
         "token_usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}},
    ]
    _write_scan_report(str(tmp_path), result, step_reports)
    assert result.scan_status == "partial"
    assert result.scan_errors == ["e1"]
    assert result.to_dict()["scan_status"] == "partial"
