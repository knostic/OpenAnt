"""Tests for ``core.reporter`` pipeline-status fidelity.

Regression coverage for a report-correctness class: ``build_pipeline_output``
hand-assembled ``pipeline_stats`` from a subset of telemetry and fabricated a
clean constant for status it wasn't handed — ``pipeline_stats.skipped_steps``
was always ``[]`` (the reporter received no ``result`` and read only
cost/duration from the step reports). So a scan where a step was skipped — most
importantly a **crashed Stage-2 verify** (caught, non-aborting) — rendered in
the human summary (``report/prompts/summary.txt``) as "No steps were skipped",
indistinguishable from a clean fully-verified scan.

The fix plumbs the authoritative ``ScanResult.skipped_steps`` /
``skipped_step_reasons`` into ``build_pipeline_output`` and emits them as
``[{step, reason}]`` (the shape summary.txt already expects). This is
report-fidelity ONLY — per-finding disclosure is unchanged: unverified findings
stay included, distinguishable by ``stage2_verdict`` ('vulnerable' vs
'confirmed'). It does NOT gate disclosure (that would drop findings = FN).

The last test is the completeness guard (mirrors parsers' schema-completeness
tests): a skipped/failed verify MUST surface in ``pipeline_output.json`` — the
gap that existing ``tests/test_scanner.py`` misses because it asserts the
``ScanResult`` object, never the artifact.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.reporter import build_pipeline_output
from utilities.file_io import write_json


def _run(tmp_path: Path, *, skipped_steps=None, skipped_step_reasons=None,
         findings=None, metrics=None) -> dict:
    results = {
        "dataset": "t",
        "code_by_route": {"a.py:f": "def f(): ..."},
        "metrics": metrics or {"total": len(findings or []), "errors": 0},
        "confirmed_findings": findings or [],
    }
    write_json(tmp_path / "results.json", results)
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"),
        output_path=str(out),
        language="python",
        repo_name="t/r",
        processing_level="reachable",
        skipped_steps=skipped_steps,
        skipped_step_reasons=skipped_step_reasons,
    )
    return json.loads(out.read_text())


def test_skipped_steps_populated_from_scanresult(tmp_path: Path):
    """pipeline_stats.skipped_steps mirrors ScanResult skips as [{step,reason}]."""
    out = _run(
        tmp_path,
        skipped_steps=["verify", "enhance"],
        skipped_step_reasons={"verify": "failed", "enhance": "not_requested"},
    )
    assert out["pipeline_stats"]["skipped_steps"] == [
        {"step": "verify", "reason": "failed"},
        {"step": "enhance", "reason": "not_requested"},
    ]


def test_crashed_verify_is_visible_not_masked(tmp_path: Path):
    """The security-relevant core: a crashed verify surfaces in the artifact."""
    out = _run(
        tmp_path,
        skipped_steps=["verify"],
        skipped_step_reasons={"verify": "failed"},
        findings=[{"route_key": "a.py:f", "unit_id": "a.py:f",
                   "finding": "vulnerable", "name": "SQLi"}],
        metrics={"total": 1, "vulnerable": 1, "errors": 0},
    )
    stats = out["pipeline_stats"]
    skipped = [s["step"] for s in stats["skipped_steps"]]
    assert "verify" in skipped, "a crashed verify must not render as 'nothing skipped'"
    # disclosure unchanged: the finding is still included, labeled Stage-1
    assert out["findings"][0]["stage2_verdict"] == "vulnerable"


def test_no_skips_stays_empty(tmp_path: Path):
    """No false positives: a clean scan reports no skipped steps."""
    out = _run(tmp_path, skipped_steps=[], skipped_step_reasons={})
    assert out["pipeline_stats"]["skipped_steps"] == []


def test_missing_reason_degrades_to_empty_string(tmp_path: Path):
    """A skip with no recorded reason still surfaces (reason='')."""
    out = _run(tmp_path, skipped_steps=["dynamic-test"], skipped_step_reasons=None)
    assert out["pipeline_stats"]["skipped_steps"] == [
        {"step": "dynamic-test", "reason": ""}
    ]


def test_step_context_swallow_path_records_skipped_status(tmp_path: Path):
    """The scanner's catch-and-continue (verify/enhance/etc.) must record
    status='skipped' on the step report — not the default 'success' — so the
    HTML step table (success->green, else->grey) stops rendering a crashed
    verify as green. Mirrors the scanner pattern without running a full scan."""
    import os
    from core.step_report import step_context
    with step_context("verify", str(tmp_path)) as ctx:
        # simulate run_verification raising and being caught locally (no re-raise)
        ctx.status = "skipped"
        ctx.summary = {"skipped": True, "reason": "Anthropic 529 overloaded"}
    rep = json.loads((tmp_path / "verify.report.json").read_text())
    assert rep["status"] == "skipped"          # not the default "success"
    assert rep["summary"]["skipped"] is True
