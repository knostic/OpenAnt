"""Unit tests for scanner optional-stage isolation and skip-cause reporting.

Covers two areas:

- error-handling: the OPTIONAL stages (enhance, verify, dynamic-test) were
  wrapped in ``step_context`` but had NO inner try/except. ``step_context``
  re-raises (core/step_report.py:57), so an optional-stage error escaped
  ``scan_repository`` to cli.py's blanket ``except`` and discarded all completed
  parse/analyze work. The fix adds an inner warn-and-continue try/except around
  each optional stage, matching the existing app-context / llm-reachability
  pattern.

- skip-cause conflation: ``skipped_steps`` recorded the IDENTICAL bare string
  for distinct skip causes (verify auto-skip vs opt-out both -> 'verify';
  dynamic-test collapsed ~3 causes -> 'dynamic-test'). The fix ADDITIVELY records
  a disambiguated reason per skipped step in a NEW ``skipped_step_reasons`` dict,
  WITHOUT changing the existing bare ``skipped_steps`` list (telemetry consumers
  read it).

These tests monkeypatch the heavy LLM/Docker stages so we exercise the
orchestration control-flow without real API/Docker calls.
"""

import sys
from pathlib import Path

import pytest

# Project root must be importable (mirrors conftest). core.scanner is a unique
# module name, so a normal import is safe; we do NOT import any parser modules
# here, so we cannot pollute sys.modules with shared parser basenames.
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import scanner as scanner_mod  # noqa: E402
from core.schemas import AnalysisMetrics, ScanResult  # noqa: E402


@pytest.fixture(autouse=True)
def _stub_registry_probe(monkeypatch):
    """Neutralize the real Anthropic credential probe.

    Post-#69, ``scan_repository`` calls ``probe_registry_or_raise(registry)``
    (core/scanner.py) which issues a real 1-token Anthropic request to
    validate credentials before any work begins. These orchestration tests
    run fully offline, so we replace the probe with a no-op. The registry is
    still built (from the dummy key) and threaded through every stage exactly
    as in production; only the network round-trip is removed. ``scan_repository``
    does ``from utilities.llm import ... probe_registry_or_raise`` at call time,
    so patching the attribute on ``utilities.llm`` takes effect.
    """
    import utilities.llm as llm_mod

    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None, raising=True
    )


# ---------------------------------------------------------------------------
# Shared stubs — make parse + analyze succeed cheaply, with no LLM/network.
# ---------------------------------------------------------------------------

class _ParseResult:
    def __init__(self, output_dir):
        self.dataset_path = str(Path(output_dir) / "dataset.json")
        self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
        self.units_count = 3
        self.language = "python"
        self.processing_level = "all"


def _install_minimal_pipeline(monkeypatch, *, vulnerable=0, bypassable=0):
    """Stub parse + analyze + build_pipeline_output so a scan runs offline.

    Returns nothing; the caller drives optional-stage behaviour via flags /
    further monkeypatching.
    """
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.reporter as reporter
    import core.tracking as tracking

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        # Write the files downstream stages expect to exist.
        Path(pr.dataset_path).write_text('{"units": []}')
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    metrics = AnalysisMetrics(
        total=3,
        vulnerable=vulnerable,
        bypassable=bypassable,
        inconclusive=0,
        protected=0,
        safe=3 - vulnerable - bypassable,
        errors=0,
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
    # Keep tracking quiet/deterministic.
    tracking.reset_tracking()


# ---------------------------------------------------------------------------
# Optional-stage errors must NOT abort the scan.
# ---------------------------------------------------------------------------

def test_enhance_failure_does_not_abort_scan(monkeypatch, tmp_path):
    """An exception in the OPTIONAL enhance stage must be caught (warn+continue),
    not propagated out of scan_repository (which would discard parse/analyze)."""
    _install_minimal_pipeline(monkeypatch)

    import core.enhancer as enhancer

    def _boom(**kwargs):
        raise RuntimeError("enhance blew up")

    monkeypatch.setattr(enhancer, "enhance_dataset", _boom)

    out = tmp_path / "out"
    # Must NOT raise. Pre-fix this propagates RuntimeError out of scan_repository.
    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(out),
        generate_context=False,
        enhance=True,
        verify=False,
        generate_report=False,
        dynamic_test=False,
    )
    assert isinstance(result, ScanResult)
    # The completed analyze work survived.
    assert result.metrics.total == 3


def test_verify_failure_does_not_abort_scan(monkeypatch, tmp_path):
    """An exception in the OPTIONAL verify stage must be caught, not propagated."""
    _install_minimal_pipeline(monkeypatch, vulnerable=1)

    import core.verifier as verifier

    def _boom(**kwargs):
        raise RuntimeError("verify blew up")

    monkeypatch.setattr(verifier, "run_verification", _boom)

    out = tmp_path / "out"
    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(out),
        generate_context=False,
        enhance=False,
        verify=True,
        generate_report=False,
        dynamic_test=False,
    )
    assert isinstance(result, ScanResult)
    assert result.metrics.total == 3


def test_dynamic_test_failure_does_not_abort_scan(monkeypatch, tmp_path):
    """An exception in the OPTIONAL dynamic-test stage must be caught."""
    _install_minimal_pipeline(monkeypatch, vulnerable=1)

    import shutil as _shutil
    import core.dynamic_tester as dynamic_tester

    # Force the "docker present" branch so we reach run_tests.
    monkeypatch.setattr(scanner_mod.shutil, "which", lambda name: "/usr/bin/docker")

    def _boom(**kwargs):
        raise RuntimeError("docker blew up")

    monkeypatch.setattr(dynamic_tester, "run_tests", _boom)

    out = tmp_path / "out"
    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(out),
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=True,
    )
    assert isinstance(result, ScanResult)
    assert result.metrics.total == 3


def test_required_stage_failure_still_propagates(monkeypatch, tmp_path):
    """The REQUIRED analyze stage must still propagate its error (regression
    guard so the fix does not over-broadly swallow required-stage failures)."""
    _install_minimal_pipeline(monkeypatch)

    import core.analyzer as analyzer

    def _boom(**kwargs):
        raise RuntimeError("analyze blew up")

    monkeypatch.setattr(analyzer, "run_analysis", _boom)

    out = tmp_path / "out"
    with pytest.raises(RuntimeError, match="analyze blew up"):
        scanner_mod.scan_repository(
            repo_path=str(tmp_path),
            output_dir=str(out),
            generate_context=False,
            enhance=False,
            verify=False,
            generate_report=False,
            dynamic_test=False,
        )


# ---------------------------------------------------------------------------
# Disambiguated skip reasons (ADDITIVE; bare list unchanged).
# ---------------------------------------------------------------------------

def test_verify_skip_reasons_distinguish_autoskip_vs_optout(monkeypatch, tmp_path):
    """verify auto-skip (no findings) vs opt-out (--no-verify) must record
    DISTINCT reasons in the new skipped_step_reasons dict, while the existing
    bare skipped_steps list stays IDENTICAL ('verify')."""
    # Case A: verify requested but no findings -> auto-skip.
    _install_minimal_pipeline(monkeypatch, vulnerable=0)
    out_a = tmp_path / "out_a"
    res_a = scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(out_a),
        generate_context=False, enhance=False, verify=True,
        generate_report=False, dynamic_test=False,
    )

    # Case B: verify not requested -> opt-out.
    out_b = tmp_path / "out_b"
    res_b = scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(out_b),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False,
    )

    # Bare list unchanged in BOTH cases (consumers read this).
    assert "verify" in res_a.skipped_steps
    assert "verify" in res_b.skipped_steps

    # New disambiguated reasons differ.
    assert res_a.skipped_step_reasons["verify"] != res_b.skipped_step_reasons["verify"]


def test_dynamic_test_skip_reasons_distinct(monkeypatch, tmp_path):
    """dynamic-test no-findings skip vs not-enabled skip must record DISTINCT
    reasons, with the bare list still 'dynamic-test'."""
    # Case A: dynamic_test requested but no findings.
    _install_minimal_pipeline(monkeypatch, vulnerable=0)
    out_a = tmp_path / "dt_a"
    res_a = scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(out_a),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=True,
    )

    # Case B: dynamic_test not enabled.
    out_b = tmp_path / "dt_b"
    res_b = scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(out_b),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False,
    )

    assert "dynamic-test" in res_a.skipped_steps
    assert "dynamic-test" in res_b.skipped_steps
    assert res_a.skipped_step_reasons["dynamic-test"] != res_b.skipped_step_reasons["dynamic-test"]


def test_skipped_step_reasons_serialized_in_scan_report(monkeypatch, tmp_path):
    """The new reason map must be emitted in scan.report.json alongside the
    existing flat steps_skipped, and steps_skipped must be unchanged."""
    import json
    _install_minimal_pipeline(monkeypatch, vulnerable=0)
    out = tmp_path / "out"
    scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(out),
        generate_context=False, enhance=False, verify=True,
        generate_report=False, dynamic_test=False,
    )
    report = json.loads((out / "scan.report.json").read_text())
    summary = report["summary"]
    # Existing flat list still present and bare.
    assert "verify" in summary["steps_skipped"]
    # New disambiguated map present.
    assert "steps_skipped_reasons" in summary
    assert "verify" in summary["steps_skipped_reasons"]
