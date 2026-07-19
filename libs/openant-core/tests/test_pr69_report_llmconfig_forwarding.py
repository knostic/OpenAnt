"""PR #69 (FAM-REPORT): the scan's ``--llm-config`` must reach the report step.

``scan_repository`` builds one PhaseRegistry from ``llm_config_name`` and threads
that name through every LLM step. The Step-8 report block, however, called
``generate_summary_report`` / ``generate_disclosure_docs`` with only two
positional args — dropping ``llm_config_name`` — so the report/disclosure phase
silently fell back to the file's ``default_llm`` instead of the config the user
selected for the scan.

This test drives ``scan_repository`` fully offline (parse/analyze/build-output
stubbed, credential probe neutered) and captures the ``llm_config_name`` the two
reporter functions actually receive. Pre-fix the captured value is ``None`` for
both; post-fix it is the scan's own config name.
"""

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import scanner as scanner_mod  # noqa: E402
from core.schemas import AnalysisMetrics, ScanResult  # noqa: E402

SENTINEL_CONFIG = "sentinel-report-cfg"


@pytest.fixture(autouse=True)
def _offline_registry(monkeypatch):
    """Neuter the credential probe and accept any llm-config name offline.

    ``scan_repository`` does ``from utilities.llm import ...`` at call time, so
    patching the attributes on ``utilities.llm`` takes effect. ``resolve_llm_config``
    is wrapped to ignore the (non-existent, in-test) name and return the default
    config, so the scan-level registry still builds without a real config file.
    """
    import utilities.llm as llm_mod

    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None, raising=True
    )
    orig_resolve = llm_mod.resolve_llm_config
    monkeypatch.setattr(
        llm_mod,
        "resolve_llm_config",
        lambda cf, name: orig_resolve(cf, None),
        raising=True,
    )


class _ParseResult:
    def __init__(self, output_dir):
        self.dataset_path = str(Path(output_dir) / "dataset.json")
        self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
        self.units_count = 3
        self.language = "python"
        self.processing_level = "all"


def _install_minimal_pipeline(monkeypatch):
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.reporter as reporter
    import core.tracking as tracking

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


def test_report_step_forwards_scan_llm_config(monkeypatch, tmp_path):
    """The report + disclosure calls must receive the scan's llm_config_name."""
    _install_minimal_pipeline(monkeypatch)

    import core.reporter as reporter

    captured = {}

    def _fake_summary(results_path, output_path, llm_config_name=None):
        captured["summary"] = llm_config_name
        Path(output_path).write_text("# summary")
        return None

    def _fake_disclosure(results_path, output_dir, llm_config_name=None):
        captured["disclosure"] = llm_config_name
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
        llm_config_name=SENTINEL_CONFIG,
    )

    assert isinstance(result, ScanResult)
    # vulnerable=1 ⇒ both the summary and the disclosure paths run.
    assert captured.get("summary") == SENTINEL_CONFIG, (
        f"summary report got llm_config_name={captured.get('summary')!r}, "
        f"expected {SENTINEL_CONFIG!r} (scan's --llm-config was dropped)"
    )
    assert captured.get("disclosure") == SENTINEL_CONFIG, (
        f"disclosure docs got llm_config_name={captured.get('disclosure')!r}, "
        f"expected {SENTINEL_CONFIG!r} (scan's --llm-config was dropped)"
    )
