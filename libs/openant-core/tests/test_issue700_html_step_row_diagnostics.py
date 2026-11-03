"""#700: the HTML step rows carry the diagnostics the JSON lanes already carry.

The step-report projection that feeds the Go report (`openant.cli
._step_report_rows`) built each row from exactly eight keys — and dropped
every diagnostic class the step reports actually carry:

* ``token_usage["cost_incomplete"]`` (+ ``unpriced_models``) — the #216/#605
  incompleteness markers, so an incomplete mixed-cost step rendered as
  ``$0.25`` / ``success`` with no label and no attribution;
* ``summary["discovery"]`` — the #600 block (the excluded dirs NAMED per
  language, never summed);
* ``summary["signals_skipped_unknown_unit"]`` — the #602/#798 skip counter;
* ``units_newly_reachable`` — the #602 decomposition, which reached the scan
  aggregate and the reporter but never a step report (the one key whose loss
  is at the SOURCE, not the projection: the reach step's summary never
  carried it).

The Go ``StepReport`` struct mirrored the eight keys and the templates
rendered four — so even the degradation channel that DID reach Go
(``error_count`` / ``errors`` / ``skipped_reason``, the #305 SARIF lane)
never appeared in an HTML step row.

Contract locked here (Python side; the Go struct/methods/templates are
pinned in test_issue700_step_row_diagnostics_test.go):

- the projection carries the diagnostics PRESENT-ONLY — a clean step's row
  keeps exactly the eight pre-#700 keys (byte-identical clean artifacts);
- the discovery exclusions carry PER LANGUAGE (the #600 contract: the flat
  count measures prune observations, never a cross-language total);
- the reach step's summary threads ``units_newly_reachable`` from the
  dataset's reachability_filter aggregate — present-only per #602 (absent
  when the baseline was unmeasurable, never a fabricated 0).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from openant.cli import _step_report_rows  # noqa: E402


def test_rows_carry_the_incompleteness_markers():
    """A step whose cost is incomplete (an unpriced model in the run)
    carries the flag AND the model attribution in its row — the HTML
    'incomplete' label's data. Base: the projection never read
    ``token_usage``."""
    rows = _step_report_rows([
        {"step": "analyze", "status": "success", "duration_seconds": 61,
         "cost_usd": 0.25, "timestamp": "t1", "errors": [],
         "summary": {},
         "token_usage": {"input_tokens": 10, "output_tokens": 5,
                         "total_tokens": 15, "cost_incomplete": True,
                         "unpriced_models": ["mystery/model"]}},
    ])
    row = rows[0]
    assert row["cost"] == "$0.25"
    assert row.get("cost_incomplete") is True, (
        "the projection dropped token_usage.cost_incomplete — the HTML row "
        "cannot carry the incompleteness label (the issue's exact "
        "'renders as $0.25 / success' shape)")
    assert row.get("unpriced_models") == ["mystery/model"], (
        "the projection dropped the unpriced-model attribution")


def test_rows_carry_the_skip_counter():
    rows = _step_report_rows([
        {"step": "llm-reachability", "status": "success",
         "duration_seconds": 30, "cost_usd": 0.1, "timestamp": "t2",
         "errors": [],
         "summary": {"signals_skipped_unknown_unit": 3}},
    ])
    assert rows[0].get("signals_skipped_unknown_unit") == 3, (
        "the projection dropped the #602/#798 skip counter")


def test_rows_carry_the_discovery_exclusions_per_language():
    """The #600 contract rides through: per-language flat counts, NEVER a
    cross-language sum (the flat count measures prune observations)."""
    rows = _step_report_rows([
        {"step": "parse", "status": "success", "duration_seconds": 5,
         "cost_usd": 0, "timestamp": "t3", "errors": [],
         "summary": {"discovery": {
             "per_language": {
                 "python": {"directories_excluded": 7,
                            "excluded_dir_names": {"venv": 3, ".git": 4}},
                 "go": {"directories_excluded": 5},
             },
             "languages_without_discovery_data": ["js"],
         }}},
    ])
    row = rows[0]
    assert row.get("excluded_directories") == ["go 5", "python 7"], (
        "the projection dropped the #600 discovery block's per-language "
        "exclusion counts — display-ready and SORTED (the Go consumer "
        "joins in order, sorts nothing)")
    assert "excluded_directories_total" not in row, (
        "the cross-language total is FORBIDDEN (the #600 docstring: the "
        "flat count measures prune observations, not unique excluded dirs)")


def test_rows_carry_both_unpriced_kinds_f1():
    """F1 (the fable r1 catch): a cache-only incompleteness names its model
    under the cache kind — the row must carry it or the HTML tooltip lies
    with 'unattributable (no model ids)'."""
    rows = _step_report_rows([
        {"step": "enhance", "status": "success", "duration_seconds": 10,
         "cost_usd": 0.0, "timestamp": "t8", "errors": [], "summary": {},
         "token_usage": {"input_tokens": 0, "output_tokens": 0,
                         "total_tokens": 0, "cost_incomplete": True,
                         "unpriced_models": [],
                         "unpriced_cache_models": ["anthropic/claude-x"]}},
    ])
    row = rows[0]
    assert row["cost_incomplete"] is True
    assert row["unpriced_cache_models"] == ["anthropic/claude-x"], (
        "the cache kind's model is dropped — the HTML renders the false "
        "unattributable shape")
    assert "unpriced_models" not in row  # empty is not an attribution


def test_rows_carry_the_accounting_sentinel_f1():
    """F1's other half: the #605 sentinel (the delta unavailable) carries
    its CAUSE — the row must show accounting_error, or the tooltip
    misnames a pricing gap that never happened."""
    rows = _step_report_rows([
        {"step": "verify", "status": "success", "duration_seconds": 10,
         "cost_usd": 0.0, "timestamp": "t9", "errors": [], "summary": {},
         "token_usage": {"input_tokens": 0, "output_tokens": 0,
                         "total_tokens": 0, "cost_incomplete": True,
                         "accounting_error": True}},
    ])
    row = rows[0]
    assert row["cost_incomplete"] is True
    assert row["accounting_error"] is True, (
        "the sentinel's cause is dropped — the HTML blames a per-model "
        "pricing gap for an accounting error")


def test_rows_zero_exclusions_carry_no_key_f2():
    """F2 (the fable r1 catch): the real scanner writes
    directories_excluded: 0 on a clean repo — a carried zero would give
    every clean parse row a ninth key and break the clean-row contract in
    production. Zeros are NOT disclosures."""
    rows = _step_report_rows([
        {"step": "parse", "status": "success", "duration_seconds": 5,
         "cost_usd": 0, "timestamp": "t10", "errors": [],
         "summary": {"discovery": {"per_language": {
             "python": {"directories_excluded": 0}}}}},
    ])
    assert "excluded_directories" not in rows[0], (
        "a zero-exclusion language carried a fabricated disclosure")


def test_rows_clean_step_unchanged():
    """The present-only control: a clean step's row keeps EXACTLY the eight
    pre-#700 keys — a clean step's JSON stays byte-identical (the fix
    direction's own constraint)."""
    rows = _step_report_rows([
        {"step": "parse", "status": "success", "duration_seconds": 5,
         "cost_usd": 0, "timestamp": "t4", "errors": [], "summary": {},
         "token_usage": {"input_tokens": 0, "output_tokens": 0,
                         "total_tokens": 0}},
    ], {"parse": "config"})
    assert rows[0] == {
        "step": "parse",
        "duration": "5.0s",
        "cost": "-",
        "status": "success",
        "timestamp": "t4",
        "error_count": 0,
        "errors": [],
        "skipped_reason": "config",
    }, f"the clean row changed: {rows[0]}"


def test_rows_partial_step_keeps_the_base_shape():
    """The counters ride ALONGSIDE the #305 degradation channel — a partial
    step (errors + a skip counter + an incomplete cost) carries all three
    classes at once."""
    rows = _step_report_rows([
        {"step": "verify", "status": "partial", "duration_seconds": 90,
         "cost_usd": 0.5, "timestamp": "t5", "errors": ["adapter raise"],
         "summary": {"error_count": 2, "signals_skipped_unknown_unit": 1},
         "token_usage": {"input_tokens": 1, "output_tokens": 1,
                         "total_tokens": 2, "cost_incomplete": True}},
    ])
    row = rows[0]
    assert row["error_count"] == 2 and row["errors"] == ["adapter raise"]
    assert row["signals_skipped_unknown_unit"] == 1
    assert row["cost_incomplete"] is True


def test_rows_garbage_shapes_never_crash_or_fabricate():
    """Hostile summaries never fabricate a counter (a bool is not a count;
    a negative is not a skip; a non-int newly-reachable never lands)."""
    rows = _step_report_rows([
        {"step": "parse", "status": "success", "duration_seconds": 5,
         "cost_usd": 0, "timestamp": "t6", "errors": [],
         "summary": {"signals_skipped_unknown_unit": True,
                     "units_newly_reachable": "9",
                     "discovery": {"per_language": {
                         "python": {"directories_excluded": True},
                         "go": {"directories_excluded": None},
                         "js": "not-a-dict"}}},
         "token_usage": {"cost_incomplete": True,
                         "unpriced_models": []}},
    ])
    row = rows[0]
    assert "signals_skipped_unknown_unit" not in row, row
    assert "units_newly_reachable" not in row, row
    # the flag still carries (the label's data is independent of the counts)
    assert row.get("cost_incomplete") is True
    # an empty unpriced list is NOT an attribution
    assert "unpriced_models" not in row, row
    # per-language garbage drops every fabricated count — and an
    # all-garbage block carries NO key at all (present-only)
    assert "excluded_directories" not in row, (
        "the hostile-language block must carry no fabricated counts")


def test_rows_carry_the_newly_reachable_counter():
    rows = _step_report_rows([
        {"step": "llm-reachability", "status": "success",
         "duration_seconds": 30, "cost_usd": 0.1, "timestamp": "t7",
         "errors": [],
         "summary": {"units_newly_reachable": 12}},
    ])
    assert rows[0].get("units_newly_reachable") == 12


def test_reach_step_summary_threads_the_newly_reachable_counter(
        monkeypatch, tmp_path):
    """The EXECUTED artifact pin for the one key whose loss is at the SOURCE:
    the reach step's summary must thread the dataset's aggregated
    ``reachability_filter.units_newly_reachable`` into its step report
    (present-only per #602 — the reporter's own source, reporter.py:800).
    Base: the summary never carried it, so no projection could ever render
    it."""
    import json

    from pathlib import Path
    import utilities.llm as llm_mod
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.reporter as reporter
    import core.tracking as tracking
    import core.scanner as scanner_mod
    from core.schemas import AnalysisMetrics
    import core.llm_reachability as lr

    monkeypatch.setattr(llm_mod, "probe_registry_or_raise",
                        lambda reg: None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-offline-000")

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
        # the legacy flat call-graph layout: a graph at the run root makes
        # resolve_call_graph_dirs return {None: run_dir} and the reach
        # step's post-LLM re-filter block RUNS (without it the block is
        # skipped and no reachability_filter record is ever built). The
        # dataset carries one python unit — the per-language re-filter
        # loop iterates PARTITIONS, so an empty dataset never reaches the
        # filter at all.
        Path(output_dir, "call_graph.json").write_text("{}")
        Path(pr.dataset_path).write_text(
            '{"units": [{"id": "a.py:f", "language": "python"}], '
            '"metadata": {}}')
        return pr

    metrics = AnalysisMetrics(total=3, vulnerable=0, bypassable=0,
                              inconclusive=0, protected=0, safe=3, errors=0)

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

    def _fake_analyze(*, dataset, app_context, binding, max_code_bytes,
                      stats=None, **kw):
        stats["signals_skipped_unknown_unit"] = 0
        return []

    monkeypatch.setattr(lr, "analyze_reachability", _fake_analyze)
    monkeypatch.setattr(
        lr, "apply_signals",
        lambda dataset, signals: {"signals_applied": 0,
                                  "entry_points_promoted": 0,
                                  "units_touched": 0,
                                  "signals_dropped_unknown_unit": 0,
                                  "promote_set": []})
    monkeypatch.setattr(lr, "signals_to_json", lambda signals: [])

    def _fake_filter(dataset, call_graph_dir, processing_level, *,
                     extra_entry_points=None, library_mode=False):
        # the #602 decomposition as the real filter records it (a measured
        # baseline): the aggregate the reporter reads at reporter.py:800
        md = dict(dataset.get("metadata") or {})
        md["reachability_filter"] = {
            "original_units": 3, "reachable_units": 2, "filtered_out": 1,
            "structural_reachable_units": 1, "units_newly_reachable": 1,
        }
        return {**dataset, "metadata": md}

    monkeypatch.setattr(parser_adapter, "apply_reachability_filter",
                        _fake_filter)

    scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(tmp_path / "out"),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False,
        llm_reachability=True, processing_level="reachable")

    report = json.loads(
        (tmp_path / "out" / "llm-reachability.report.json").read_text())
    s = report["summary"]
    assert s.get("units_newly_reachable") == 1, (
        "the reach step's summary dropped the dataset's aggregated "
        "units_newly_reachable — the one #700 key whose loss is at the "
        "source: no projection could ever render it")


def test_reach_step_summary_omits_the_counter_when_unmeasured(
        monkeypatch, tmp_path):
    """The #602 absence semantics ride through: a baseline that could not be
    measured (the keep-all / no-extras case) leaves the key ABSENT in the
    step report — never a fabricated 0."""
    import json

    from pathlib import Path
    import utilities.llm as llm_mod
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.reporter as reporter
    import core.tracking as tracking
    import core.scanner as scanner_mod
    from core.schemas import AnalysisMetrics
    import core.llm_reachability as lr

    monkeypatch.setattr(llm_mod, "probe_registry_or_raise",
                        lambda reg: None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-offline-000")

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
        # the legacy flat call-graph layout: a graph at the run root makes
        # resolve_call_graph_dirs return {None: run_dir} and the reach
        # step's post-LLM re-filter block RUNS (without it the block is
        # skipped and no reachability_filter record is ever built). The
        # dataset carries one python unit — the per-language re-filter
        # loop iterates PARTITIONS, so an empty dataset never reaches the
        # filter at all.
        Path(output_dir, "call_graph.json").write_text("{}")
        Path(pr.dataset_path).write_text(
            '{"units": [{"id": "a.py:f", "language": "python"}], '
            '"metadata": {}}')
        return pr

    metrics = AnalysisMetrics(total=3, vulnerable=0, bypassable=0,
                              inconclusive=0, protected=0, safe=3, errors=0)

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

    def _fake_analyze(*, dataset, app_context, binding, max_code_bytes,
                      stats=None, **kw):
        stats["signals_skipped_unknown_unit"] = 0
        return []

    monkeypatch.setattr(lr, "analyze_reachability", _fake_analyze)
    monkeypatch.setattr(
        lr, "apply_signals",
        lambda dataset, signals: {"signals_applied": 0,
                                  "entry_points_promoted": 0,
                                  "units_touched": 0,
                                  "signals_dropped_unknown_unit": 0,
                                  "promote_set": []})
    monkeypatch.setattr(lr, "signals_to_json", lambda signals: [])

    def _fake_filter(dataset, call_graph_dir, processing_level, *,
                     extra_entry_points=None, library_mode=False):
        # the unmeasurable-baseline record: the keys stay ABSENT (the #602
        # contract), the marker explains why
        md = dict(dataset.get("metadata") or {})
        md["reachability_filter"] = {
            "original_units": 3, "reachable_units": 3, "filtered_out": 0,
            "reachability_baseline": "keep-all",
        }
        return {**dataset, "metadata": md}

    monkeypatch.setattr(parser_adapter, "apply_reachability_filter",
                        _fake_filter)

    scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(tmp_path / "out"),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False,
        llm_reachability=True, processing_level="reachable")

    report = json.loads(
        (tmp_path / "out" / "llm-reachability.report.json").read_text())
    assert "units_newly_reachable" not in report["summary"], (
        "an unmeasured baseline fabricated a 0 — the #602 absence contract "
        "is load-bearing here")
