"""Regression tests for issue #305 — the SARIF output cannot express a
degraded scan, and the line anchor is dropped at the report boundary.

SARIF 2.1.0's designated place is `runs[].invocations[]` with
`executionSuccessful` + `toolExecutionNotifications`; the degradation data
exists in the run's step reports but the report-data projection copied five
display fields and dropped the rest. The adjacent finding (from the issue
comment): the parsers emit `start_line` in `primary_origin` and it survived
enhancement — the projection never read it, so the SARIF region had nothing
to anchor to (the Go side had been waiting for exactly that, per its own
comment).

Contract locked here (Python side; the Go behavior is pinned in
sarif_test.go):
- `_step_report_rows` threads `error_count` (the #285 flat key, falling
  back to the raw errors list), the `errors` themselves (capped at 5), and
  each step's disambiguated `skipped_reason` from the scan aggregate;
- a bool/None error_count never masquerades as a count;
- the finding projection carries `start_line` from the unit's
  `code.primary_origin.start_line`, defaulting to 0 for every shape of
  missing data (never a crash on malformed units).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from openant.cli import _step_report_rows  # noqa: E402


def test_rows_carry_the_degradation_channel():
    rows = _step_report_rows([
        {"step": "verify", "status": "partial", "duration_seconds": 90,
         "cost_usd": 0.5, "timestamp": "t1", "errors": ["adapter raise"],
         "summary": {"error_count": 48}},
        {"step": "parse", "status": "success", "duration_seconds": 30,
         "cost_usd": 0.1, "timestamp": "t2", "errors": []},
    ], skip_reasons={"app-context": "module_unavailable"})
    by_step = {r["step"]: r for r in rows}
    assert by_step["verify"]["error_count"] == 48
    assert by_step["verify"]["errors"] == ["adapter raise"]
    assert by_step["parse"]["error_count"] == 0
    # the skip reason rides on its step (the app-context row is absent
    # here, but the map lookup is the contract)
    rows2 = _step_report_rows([
        {"step": "app-context", "status": "skipped",
         "duration_seconds": 0, "cost_usd": 0, "timestamp": "t0",
         "errors": []},
    ], skip_reasons={"app-context": "module_unavailable"})
    assert rows2[0]["skipped_reason"] == "module_unavailable"


def test_rows_error_count_falls_back_to_the_errors_list():
    rows = _step_report_rows([
        {"step": "analyze", "status": "partial", "errors": ["e1", "e2"],
         "summary": {}},
    ])
    assert rows[0]["error_count"] == 2


def test_rows_reject_bool_and_none_error_counts():
    """A bool/None summary value must never masquerade as a count."""
    rows = _step_report_rows([
        {"step": "analyze", "errors": ["e1"],
         "summary": {"error_count": True}},
        {"step": "verify", "errors": ["e2"],
         "summary": {"error_count": None}},
    ])
    assert rows[0]["error_count"] == 1  # bool rejected → the errors list
    assert rows[1]["error_count"] == 1  # None rejected → the errors list


def test_rows_cap_the_error_strings():
    rows = _step_report_rows([
        {"step": "verify", "errors": [f"e{i}" for i in range(20)],
         "summary": {"error_count": 20}},
    ])
    assert len(rows[0]["errors"]) == 5


def test_finding_projection_carries_start_line():
    """The adjacent finding: the projection reads
    code.primary_origin.start_line — every missing-data shape defaults
    to 0 (the SARIF side stays file-scoped), never a crash. Tested
    against the REAL helper (wave catch: a hand-copied replica would
    survive a regression that changed the inline code)."""
    from openant.cli import _unit_start_line

    assert _unit_start_line({"code": {"primary_origin": {"start_line": 42}}}) == 42
    assert _unit_start_line({"code": {"primary_origin": {"start_line": 0}}}) == 0
    assert _unit_start_line({"code": {"primary_origin": None}}) == 0
    assert _unit_start_line({"code": "not-a-dict"}) == 0
    assert _unit_start_line({}) == 0
    assert _unit_start_line({"code": {"primary_origin": {"start_line": True}}}) == 0
    assert _unit_start_line({"code": {"primary_origin": {"start_line": "42"}}}) == 0


def test_excluded_languages_projection_is_a_list_and_filters_optouts():
    """Wave catches (BLOCKER 1+2): the summary's excluded_languages is a
    {lang: reason} DICT — the Go consumer unmarshals []string, so an
    unconverted dict would break report generation outright; and an
    operator --languages opt-out ('not requested via --languages') is a
    legitimate scoping choice, NOT a degradation — only involuntary
    exclusions reach the deliverable."""
    import json
    import os
    import tempfile
    from openant.cli import _load_step_reports

    d = tempfile.mkdtemp()
    with open(os.path.join(d, "scan.report.json"), "w") as f:
        json.dump({"step": "scan", "status": "success",
                   "duration_seconds": 1, "cost_usd": 0, "timestamp": "t",
                   "errors": [], "summary": {
                       "steps_skipped_reasons": {},
                       "excluded_languages": {
                           "python": "not requested via --languages",
                           "swift": "no parser for .swift files",
                       }}}, f)

    # the REAL helper (the self-audit of this campaign's tests caught this
    # as a replica-of-inline-code fake: the test used to re-implement the
    # loop, so a change to the production loop left the test green)
    from openant.cli import _excluded_languages_for_report
    summary = _load_step_reports(d)[0]["summary"]
    excluded = _excluded_languages_for_report(summary)
    assert excluded == ["swift (no parser for .swift files)"]
    assert isinstance(excluded, list)  # json.dumps-safe for []string
