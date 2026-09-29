"""#684 (the wiring half): the scanner's startup-validated registry reaches
BOTH report entry points.

The unit tests in test_issue684_report_registry_thread.py cover the report
entry points' ``registry`` param in isolation. They cannot fail on the
call-site wiring: with ``registry=registry`` removed from both scanner.py call
sites, the whole suite stays green (13 passed — the E1 finding, executed
2026-09-27). This test drives ``scan_repository`` fully offline (the pr69
template) and captures the ``registry`` the two reporter functions actually
receive, asserting it IS the scan's own registry object.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import scanner as scanner_mod  # noqa: E402
from core.schemas import AnalysisMetrics, ScanResult  # noqa: E402


class _SentinelBinding:
    """A JSON-serializable stand-in for a phase binding (attribute access,
    string fields — the step-report serializers accept it)."""
    model = "sentinel-model"
    provider_name = "sentinel-provider"
    config_name = "sentinel-registry"
    adapter = None  # binding_policy_summary reads .adapter.thinking


class _SentinelRegistry:
    """The scan's registry, identity-assertable: the SAME object the scanner
    builds at startup must be the one both report entry points receive."""
    config_name = "sentinel-registry"

    def get(self, phase):
        return _SentinelBinding()


@pytest.fixture(autouse=True)
def _offline_registry(monkeypatch):
    """Neuter the credential probe and make build_phase_registry return ONE
    shared sentinel registry the test can assert identity against."""
    import utilities.llm as llm_mod

    the_registry = _SentinelRegistry()

    monkeypatch.setattr(llm_mod, "probe_registry_or_raise",
                        lambda *a, **k: None, raising=True)
    orig_resolve = llm_mod.resolve_llm_config
    monkeypatch.setattr(llm_mod, "resolve_llm_config",
                        lambda cf, name: orig_resolve(cf, None),
                        raising=True)
    monkeypatch.setattr(llm_mod, "build_phase_registry",
                        lambda cf, name: the_registry, raising=True)

    yield the_registry


class _ParseResult:
    def __init__(self, output_dir):
        self.dataset_path = str(Path(output_dir) / "dataset.json")
        self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
        self.units_count = 3
        self.language = "python"
        self.processing_level = "all"


def _install_minimal_pipeline(monkeypatch, metrics):
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.reporter as reporter
    import core.tracking as tracking

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        Path(pr.dataset_path).write_text('{"units": []}')
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    def _fake_analysis(*, output_dir, **kwargs):
        class _AnalyzeResult:
            def __init__(self, output_dir):
                self.results_path = str(Path(output_dir) / "results.json")
                Path(self.results_path).write_text("[]")
                self.metrics = metrics
        return _AnalyzeResult(output_dir)

    def _fake_build_output(*, results_path, output_path, **kwargs):
        Path(output_path).write_text("{}")
        return output_path

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis", _fake_analysis)
    monkeypatch.setattr(reporter, "build_pipeline_output", _fake_build_output)
    tracking.reset_tracking()


def test_the_scan_threads_its_validated_registry(monkeypatch, tmp_path,
                                                 _offline_registry):
    """THE #684 WIRING: both report entry points receive the scan's own
    startup-validated registry (identity-asserted — a fresh re-built or None
    binding fails)."""
    # vulnerable=1 => findings exist => the disclosure path runs too
    metrics = AnalysisMetrics(
        total=3, vulnerable=1, bypassable=0, inconclusive=0,
        protected=0, safe=2, errors=0,
    )
    _install_minimal_pipeline(monkeypatch, metrics)

    import core.reporter as reporter

    captured = {}

    def _fake_summary(results_path, output_path, llm_config_name=None,
                      registry=None, **kwargs):
        captured["summary"] = registry
        Path(output_path).write_text("# summary")
        return None

    def _fake_disclosure(results_path, output_dir, llm_config_name=None,
                         registry=None, **kwargs):
        captured["disclosure"] = registry
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
        llm_config_name="sentinel-report-cfg",
    )

    assert isinstance(result, ScanResult)
    assert captured.get("summary") is _offline_registry, (
        f"generate_summary_report received registry={captured.get('summary')!r} "
        "— the scanner did NOT thread its startup-validated registry to the "
        "summary report (the #684 call-site wiring)"
    )
    assert captured.get("disclosure") is _offline_registry, (
        f"generate_disclosure_docs received registry={captured.get('disclosure')!r} "
        "— the scanner did NOT thread its startup-validated registry to the "
        "disclosure docs (the #684 call-site wiring)"
    )
