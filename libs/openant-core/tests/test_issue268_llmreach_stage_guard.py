"""Regression tests for issue #268 — the llm-reachability stage body must
degrade, not abort.

The stage's try/except guarded only the dataset read; everything after it
(the app-context read, the LLM call, signal application, the post-LLM
re-filter, the dataset re-write) ran inside ``step_context``, which
re-raises — so a NON-LLM failure there (a corrupt/truncated
``call_graph.json`` hit by the re-filter's unguarded ``read_json`` at
``parser_adapter.py:472``; a failed ``write_json`` at ``scanner.py:527``/
``:704``) aborted the whole scan instead of degrading the way ``enhance``
and ``verify`` do.

Contract locked here: ANY exception in the stage body (after the dataset
read) records a skip (``ctx.status = "skipped"`` + ``_record_skip``) and
the scan continues with the pre-reachability dataset — matching the
enhance/verify pattern. Provider errors are NOT the concern:
``analyze_reachability`` already skips failed batches and re-raises only
``LLMAuthError`` by design (that one SHOULD abort — bad credentials).
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.schemas import AnalysisMetrics  # noqa: E402


@pytest.fixture(autouse=True)
def _offline_registry(monkeypatch):
    import utilities.llm as llm_mod

    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None, raising=True)
    orig_resolve = llm_mod.resolve_llm_config
    monkeypatch.setattr(
        llm_mod, "resolve_llm_config",
        lambda cf, name: orig_resolve(cf, None), raising=True)


def _install_pipeline(monkeypatch, tmp_path, *, llm_reach_body=None):
    """Offline parse → llm-reachability scaffold. ``llm_reach_body`` is a
    callable run INSIDE the stage body (after the dataset read) — raise
    from it to simulate #268's non-LLM failures."""
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
            self.processing_level = "reachable"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        Path(pr.dataset_path).write_text('{"units": [], "metadata": {}}')
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    metrics = AnalysisMetrics(total=3, vulnerable=1, bypassable=0, inconclusive=0,
                              protected=0, safe=2, errors=0)

    class _AnalyzeResult:
        def __init__(self, output_dir):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text("[]")
            self.metrics = metrics

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis",
                        lambda *, output_dir, **kw: _AnalyzeResult(output_dir))
    monkeypatch.setattr(
        reporter, "build_pipeline_output",
        lambda *, results_path, output_path, **kw:
        (Path(output_path).write_text("{}"), output_path)[1])
    tracking.reset_tracking()

    # The scanner imports analyze_reachability from core.llm_reachability
    # INSIDE scan_repository at call time — patch the SOURCE module.
    import core.llm_reachability as lr
    if llm_reach_body is not None:
        monkeypatch.setattr(lr, "analyze_reachability", llm_reach_body)
    monkeypatch.setattr(
        lr, "apply_signals",
        lambda dataset, signals: {"signals_applied": 0, "entry_points_promoted": 0,
                                  "units_touched": 0})
    monkeypatch.setattr(lr, "signals_to_json", lambda signals: [])


def _scan(tmp_path, monkeypatch, **kwargs):
    from core import scanner as scanner_mod
    _install_pipeline(monkeypatch, tmp_path, **kwargs)
    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        generate_context=False,
        enhance=False,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        llm_reachability=True,
        processing_level="reachable",
    )
    return result, tmp_path / "out"


def test_stage_body_failure_degrades_not_aborts(tmp_path, monkeypatch):
    """#268's core: a non-LLM exception in the stage body (e.g. the re-filter
    hitting a corrupt call graph) records a skip and the scan COMPLETES."""
    import json

    def _body(**kwargs):
        # Simulate the post-LLM re-filter's corrupt-call_graph failure class
        raise json.JSONDecodeError("Expecting value", "doc", 0)

    result, out = _scan(tmp_path, monkeypatch, llm_reach_body=_body)
    assert result is not None, "the scan must COMPLETE (degrade, not abort)"
    report = json.loads((out / "llm-reachability.report.json").read_text())
    assert report["status"] == "skipped"
    assert "llm-reachability" in result.skipped_steps


def test_write_failure_degrades_not_aborts(tmp_path, monkeypatch, capsys):
    """The write_json path (:527/:704) failing (disk full / permissions)."""
    import core.scanner as scanner_mod

    real_write = scanner_mod.write_json

    def _failing_write(path, *a, **kw):
        # Fail only the dataset re-write inside the reachability stage
        if str(path).endswith("dataset.json"):
            raise OSError(28, "No space left on device")
        return real_write(path, *a, **kw)

    monkeypatch.setattr(scanner_mod, "write_json", _failing_write)
    import core.llm_reachability as lr
    monkeypatch.setattr(lr, "analyze_reachability", lambda **kw: [])
    monkeypatch.setattr(
        lr, "apply_signals",
        lambda dataset, signals: {"signals_applied": 0, "entry_points_promoted": 0,
                                  "units_touched": 0})
    monkeypatch.setattr(lr, "signals_to_json", lambda signals: [])
    result, out = _scan(tmp_path, monkeypatch)
    assert result is not None
    # degraded: the stage skipped, the scan completed
    assert "llm-reachability" in result.skipped_steps


def test_clean_stage_still_succeeds(tmp_path, monkeypatch):
    """No failure → the stage behaves exactly as before (no false skips)."""
    result, out = _scan(tmp_path, monkeypatch, llm_reach_body=lambda **kw: [])
    import json
    report = json.loads((out / "llm-reachability.report.json").read_text())
    assert report["status"] == "success"
    assert "llm-reachability" not in result.skipped_steps


def test_auth_error_still_aborts(tmp_path, monkeypatch):
    """LLMAuthError is the DESIGNED abort (bad credentials must not be
    silently skipped) — analyze_reachability re-raises it; the stage wrap
    must not swallow it either."""
    from utilities.llm.adapter import LLMAuthError
    import core.scanner as scanner_mod

    def _auth_fail(**kwargs):
        raise LLMAuthError("bad key")

    monkeypatch.setattr("core.llm_reachability.analyze_reachability", _auth_fail)
    _install_pipeline(monkeypatch, tmp_path)
    with pytest.raises(LLMAuthError):
        scanner_mod.scan_repository(
            repo_path=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            generate_context=False, enhance=False, verify=False,
            generate_report=False, dynamic_test=False,
            llm_reachability=True, processing_level="reachable")


def test_refilter_corrupt_call_graph_degrades_not_aborts(tmp_path, monkeypatch):
    """The commit's OWN headline example (sonnet-2 BLOCKER): a corrupt
    call_graph.json in the post-LLM re-filter — drive it through the REAL
    stage body with a REAL parse fixture that persists a call graph."""
    import json

    # parse fixture that ALSO writes a corrupt call_graph.json so the
    # re-filter's read_json raises
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.reporter as reporter
    import core.tracking as tracking
    from core.schemas import AnalysisMetrics

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 3
            self.language = "python"
            self.processing_level = "reachable"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        Path(pr.dataset_path).write_text(
            json.dumps({"units": [{"id": "a.py:f", "language": "python",
                                   "unit_id": "a.py:f"}],
                        "metadata": {}}))
        Path(pr.analyzer_output_path).write_text("{}")
        # the corrupt call graph: the re-filter's read_json raises here.
        # Multi-language layout needs the call_graphs.json index too
        # (resolve_call_graph_dirs reads it; the per-lang dir alone is not
        # found without it).
        cg_dir = Path(output_dir) / "python"
        cg_dir.mkdir(exist_ok=True)
        (cg_dir / "call_graph.json").write_text("{corrupt json")
        (Path(output_dir) / "call_graphs.json").write_text(
            json.dumps({"python": "python/call_graph.json"}))
        return pr

    metrics = AnalysisMetrics(total=3, vulnerable=1, bypassable=0, inconclusive=0,
                              protected=0, safe=2, errors=0)

    class _AnalyzeResult:
        def __init__(self, output_dir):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text("[]")
            self.metrics = metrics

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis",
                        lambda *, output_dir, **kw: _AnalyzeResult(output_dir))
    monkeypatch.setattr(
        reporter, "build_pipeline_output",
        lambda *, results_path, output_path, **kw:
        (Path(output_path).write_text("{}"), output_path)[1])
    tracking.reset_tracking()

    import core.llm_reachability as lr
    monkeypatch.setattr(lr, "analyze_reachability", lambda **kw: [])
    monkeypatch.setattr(
        lr, "apply_signals",
        lambda dataset, signals: {"signals_applied": 0, "entry_points_promoted": 0,
                                  "units_touched": 0})
    monkeypatch.setattr(lr, "signals_to_json", lambda signals: [])

    from core import scanner as scanner_mod
    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False,
        llm_reachability=True, processing_level="reachable")
    assert result is not None, "the scan must COMPLETE (degrade, not abort)"
    assert "llm-reachability" in result.skipped_steps
    report = json.loads((tmp_path / "out" / "llm-reachability.report.json").read_text())
    assert report["status"] == "skipped"


def test_units_count_restored_on_stage_failure(tmp_path, monkeypatch):
    """Wave MAJOR-1 (discriminating form): the re-filter MUST run (call-graph
    fixture present) so units_count is actually mutated mid-body, THEN the
    persist write fails — the except restores the pre-stage count. Removing
    the restore makes this test fail (mutation-discriminating)."""
    import json
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.reporter as reporter
    import core.tracking as tracking
    import core.llm_reachability as lr
    import core.scanner as scanner_mod
    from core.schemas import AnalysisMetrics

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 3
            self.language = "python"
            self.processing_level = "reachable"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        Path(pr.dataset_path).write_text(
            json.dumps({"units": [{"id": "a.py:f", "language": "python",
                                   "unit_id": "a.py:f"}],
                        "metadata": {}}))
        Path(pr.analyzer_output_path).write_text("{}")
        cg_dir = Path(output_dir) / "python"
        cg_dir.mkdir(exist_ok=True)
        (cg_dir / "call_graph.json").write_text(
            json.dumps({"functions": {}, "callGraph": {}}))
        (Path(output_dir) / "call_graphs.json").write_text(
            json.dumps({"python": "python/call_graph.json"}))
        return pr

    metrics = AnalysisMetrics(total=3, vulnerable=1, bypassable=0, inconclusive=0,
                              protected=0, safe=2, errors=0)

    class _AnalyzeResult:
        def __init__(self, output_dir):
            self.results_path = str(Path(output_dir) / "results.json")
            Path(self.results_path).write_text("[]")
            self.metrics = metrics

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis",
                        lambda *, output_dir, **kw: _AnalyzeResult(output_dir))
    monkeypatch.setattr(
        reporter, "build_pipeline_output",
        lambda *, results_path, output_path, **kw:
        (Path(output_path).write_text("{}"), output_path)[1])
    tracking.reset_tracking()
    monkeypatch.setattr(lr, "analyze_reachability", lambda **kw: [])
    monkeypatch.setattr(
        lr, "apply_signals",
        lambda dataset, signals: {"signals_applied": 0, "entry_points_promoted": 0,
                                  "units_touched": 0})
    monkeypatch.setattr(lr, "signals_to_json", lambda signals: [])

    real_write = scanner_mod.write_json

    def _failing_dataset_write(path, *a, **kw):
        if str(path).endswith("dataset.json"):
            raise OSError(28, "No space left on device")
        return real_write(path, *a, **kw)

    monkeypatch.setattr(scanner_mod, "write_json", _failing_dataset_write)

    result = scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False,
        llm_reachability=True, processing_level="reachable")
    assert result is not None
    assert "llm-reachability" in result.skipped_steps
    # the PRE-stage count (3) is what flows downstream — the restore undid
    # the mid-body mutation (the re-filter ran: call-graph fixture present)
    assert result.units_count == 3
