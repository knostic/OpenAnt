"""Regression tests for issue #209 (per-step status half).

``step_context`` only set ``status="partial"`` when an exception PROPAGATED out
of the ``with`` block. A step that catches its own exception by design and
records it via ``ctx.errors.append(...)`` — exactly what the scan's report
phase does for summary/disclosure generation (``core/scanner.py`` handlers,
paired with PR #279's empty-summary producer guard) — wrote
``status: "success"`` next to a non-empty ``errors`` list. ``report.report.json``
claimed success while the primary human-readable deliverable was missing.

Contract locked here: a step report with a non-empty ``errors`` list can never
claim ``status: "success"`` — the status is derived from the errors at context
exit. The existing 3-value vocabulary is unchanged (success / error / skipped);
``skipped`` is the scanner's degrade idiom and never records errors.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.step_report import step_context


def _read_report(tmp_path: Path, step: str) -> dict:
    return json.loads((tmp_path / f"{step}.report.json").read_text())


def test_errors_recorded_without_exception_yield_error_status(tmp_path: Path):
    """The #209 shape: handler catches by design, appends to ctx.errors.

    Mirrors the report phase's exact handler shape (try/except INSIDE the
    with-block, exception swallowed, error recorded, scan continues): the step
    report must not claim success.
    """
    with step_context("report", str(tmp_path)) as ctx:
        outputs = {}
        try:
            raise ValueError("SUMMARY_REPORT.md is empty (0 bytes)")
        except Exception as e:  # mirrors core/scanner.py report-phase handler
            ctx.errors.append(f"Summary report: {e}")
        ctx.summary = {"formats_generated": list(outputs.keys())}
        ctx.outputs = outputs

    report = _read_report(tmp_path, "report")
    assert report["errors"], "errors list must be recorded"
    assert report["status"] == "partial", (
        f"a step with recorded errors must not claim success (got {report['status']!r})"
    )


def test_clean_step_still_success(tmp_path: Path):
    with step_context("parse", str(tmp_path)) as ctx:
        ctx.summary = {"total_units": 1}
    assert _read_report(tmp_path, "parse")["status"] == "success"


def test_propagated_exception_still_error(tmp_path: Path):
    with pytest.raises(RuntimeError):
        with step_context("analyze", str(tmp_path)):
            raise RuntimeError("boom")
    report = _read_report(tmp_path, "analyze")
    # The escaping exception keeps the RESERVED "error" status (#285: only
    # caught-by-design errors/downgrades are "partial").
    assert report["status"] == "error"
    assert any("boom" in e for e in report["errors"])


def test_explicit_skipped_without_errors_unchanged(tmp_path: Path):
    """scanner.py's degrade idiom (status='skipped', no ctx.errors) is unaffected."""
    with step_context("enhance", str(tmp_path)) as ctx:
        ctx.status = "skipped"
        ctx.summary = {"skipped": True, "reason": "api down"}
    assert _read_report(tmp_path, "enhance")["status"] == "skipped"


def test_errors_recorded_override_explicit_skipped(tmp_path: Path):
    """Discriminates the shipped rule from the '== success' variant.

    A step that BOTH marks itself skipped AND records an error (no current
    scanner.py call site produces this, but the API does not forbid it):
    errors win — status must be "error", not "skipped". Without this test a
    future refactor to the conservative-looking
    ``report.status == "success"`` guard would silently change the artifact
    and no test would fail.
    """
    with step_context("weird", str(tmp_path)) as ctx:
        ctx.status = "skipped"
        ctx.errors.append("boom")
    assert _read_report(tmp_path, "weird")["status"] == "partial"


# ---------------------------------------------------------------------------
# Integration: the actual reachable code path from the issue — the scan's
# report-phase handlers (core/scanner.py) driving step_context with a caught
# exception. Scaffold mirrors tests/test_pr69_report_llmconfig_forwarding.py.
# ---------------------------------------------------------------------------

import sys  # noqa: E402

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import scanner as scanner_mod  # noqa: E402
from core.schemas import AnalysisMetrics  # noqa: E402


@pytest.fixture(autouse=True)
def _offline_registry(monkeypatch):
    """Neuter the credential probe and accept any llm-config name offline.

    MUST be autouse: without it ``scan_repository`` runs the real registry
    probe (a live 1-token provider API call) and the tests stop being
    hermetic — passing on machines with credentials, failing on keyless CI
    (mirrors tests/test_pr69_report_llmconfig_forwarding.py's fixture).
    """
    import utilities.llm as llm_mod

    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None, raising=True
    )
    orig_resolve = llm_mod.resolve_llm_config
    monkeypatch.setattr(
        llm_mod, "resolve_llm_config",
        lambda cf, name: orig_resolve(cf, None), raising=True,
    )


def _install_minimal_pipeline(monkeypatch):
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.reporter as reporter
    import core.tracking as tracking

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 3
            self.language = "python"
            self.processing_level = "all"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        Path(pr.dataset_path).write_text('{"units": []}')
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    metrics = AnalysisMetrics(
        total=3, vulnerable=1, bypassable=0, inconclusive=0,
        protected=0, safe=2, errors=0,
    )

    class _AnalyzeResult:
        def __init__(self, output_dir):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text("[]")
            self.metrics = metrics

    def _fake_analysis(*, output_dir, **kwargs):
        return _AnalyzeResult(output_dir)

    def _fake_build_output(*, results_path, output_path, **kwargs):
        Path(output_path).write_text("{}")
        return output_path

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis", _fake_analysis)
    monkeypatch.setattr(reporter, "build_pipeline_output", _fake_build_output)
    tracking.reset_tracking()


def _scan_with_report_failures(monkeypatch, tmp_path, *, summary_fails, disclosures_fail):
    _install_minimal_pipeline(monkeypatch)
    import core.reporter as reporter

    def _fake_summary(results_path, output_path, llm_config_name=None):
        if summary_fails:
            raise RuntimeError(
                "summary report generation returned empty output; refusing "
                "to write a summary-free SUMMARY_REPORT.md and report success"
            )
        Path(output_path).write_text("# summary")
        return None

    def _fake_disclosure(results_path, output_dir, llm_config_name=None):
        if disclosures_fail:
            raise RuntimeError("disclosure generation failed (test)")
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return None

    monkeypatch.setattr(reporter, "generate_summary_report", _fake_summary)
    monkeypatch.setattr(reporter, "generate_disclosure_docs", _fake_disclosure)

    out = tmp_path / "out"
    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(out),
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=True,
        dynamic_test=False,
    )
    report = json.loads((out / "report.report.json").read_text())
    return result, report


def test_scan_report_step_error_status_when_summary_fails(
    monkeypatch, tmp_path
):
    """The #209 end-to-end shape: summary raises (#279's guard), handler
    catches by design, scan continues — and report.report.json must say
    status="partial" with the recorded error, not success."""
    result, report = _scan_with_report_failures(
        monkeypatch, tmp_path, summary_fails=True, disclosures_fail=False
    )
    assert result is not None, "scan must COMPLETE (report failure must not abort)"
    assert report["status"] == "partial"
    assert len(report["errors"]) == 1
    assert "Summary report" in report["errors"][0]


def test_scan_report_step_error_status_when_both_fail(monkeypatch, tmp_path):
    """Both deliverables fail: two recorded errors, still status="partial",
    scan still completes (multiple-errors shape)."""
    result, report = _scan_with_report_failures(
        monkeypatch, tmp_path, summary_fails=True, disclosures_fail=True
    )
    assert result is not None
    assert report["status"] == "partial"
    assert len(report["errors"]) == 2


def test_scan_report_step_error_status_when_only_disclosures_fail(
    monkeypatch, tmp_path
):
    """Partial-failure shape: summary OK, disclosures fail — the step still
    reports error (disclosures are a deliverable), with exactly the
    disclosure error recorded."""
    result, report = _scan_with_report_failures(
        monkeypatch, tmp_path, summary_fails=False, disclosures_fail=True
    )
    assert result is not None
    assert report["status"] == "partial"
    assert len(report["errors"]) == 1
    assert "Disclosure docs" in report["errors"][0]


def test_scan_report_step_success_when_both_deliverables_succeed(
    monkeypatch, tmp_path
):
    """Clean-success path through the REAL report phase: both deliverables
    succeed ⇒ status stays "success" with an empty errors list. Guards the
    false-positive direction — a stray errors.append on a non-exceptional
    branch in the report handlers would flip a clean scan's report step to
    error, and nothing else in the suite drives this path."""
    result, report = _scan_with_report_failures(
        monkeypatch, tmp_path, summary_fails=False, disclosures_fail=False
    )
    assert result is not None
    assert report["status"] == "success"
    assert report["errors"] == []
    assert set(report.get("outputs", {})) == {"summary_path", "disclosures_dir"}
