"""#602: the llr report gaps — the skip line carries its class, the counter
reaches the step report, and the promoted-vs-retained relationship is
self-explaining.

Three additive telemetry keys, no behavior change (the scope-conflict
comment on the issue resolved: the reconciliation is NOT this PR):

* the SKIP CLASS: ``parse_response``'s unknown-unit_id line carries the
  signal's kind/confidence/batch; an entry_point/high skip (could have
  promoted) is distinguishable in the record from an external_input/low
  skip (could not); ``signals_skipped_unknown_unit`` counts occurrences in
  ACCEPTED responses only (attempt-local collection, folded at the
  batch's commit point — a max_tokens drop discards them with the batch;
  split-retry halves contribute their own; nothing is ever subtracted);
  ``signals_skipped_promotable`` sizes the loss at report time from THIS
  run's promote_set (parse_response stays policy-free).
* the DECOMPOSITION: the structural baseline (detector + library seeds,
  WITHOUT the LLM extras) is computed inside the same filter invocation
  — the counterfactual BFS the promoted-vs-retained explanation needs:
  ``structural_reachable_units`` + ``units_newly_reachable`` per language,
  lifted through the aggregation whitelist (the #328 class: a new
  per-language key silently vanishes otherwise).
* The keys are ABSENT when unmeasurable (no LLM extras: nothing to
  decompose; the keep-all path: retained units are not proven reachable —
  reporting them as gains would fabricate).
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.llm_reachability import (  # noqa: E402
    analyze_reachability,
    parse_response,
)


def _sig(unit_id, kind="entry_point", confidence="high"):
    return {
        "unit_id": unit_id, "kind": kind, "confidence": confidence,
        "reason": "test",
    }


# ---------------------------------------------------------------------------
# the skip line + the callback (parse level)
# ---------------------------------------------------------------------------

def test_skip_line_carries_kind_confidence_and_batch(capsys):
    """The unknown-unit_id line names WHAT was skipped — an entry_point/high
    skip is distinguishable in the record from an external_input/low one."""
    body = json.dumps({"signals": [
        _sig("b.py:other"),
        _sig("b.py:x", "external_input", "low")]})
    parse_response(body, valid_unit_ids={"a.py:f"})
    err = capsys.readouterr().err
    assert "unknown unit_id 'b.py:other'" in err
    assert "kind='entry_point'" in err
    assert "confidence='high'" in err
    assert "kind='external_input'" in err
    assert "confidence='low'" in err


def test_on_signal_skip_receives_the_class():
    """The callback kwargs: reason/kind/confidence (policy-free — the
    promotable subset is derived at report time, never here)."""
    seen = []
    body = json.dumps({"signals": [
        _sig("b.py:other"),
        _sig("b.py:x", "external_input", "low")]})
    parse_response(body, valid_unit_ids={"a.py:f"},
                   on_signal_skip=lambda **kw: seen.append(kw))
    assert seen == [
        {"reason": "unknown_unit_id", "kind": "entry_point",
         "confidence": "high"},
        {"reason": "unknown_unit_id", "kind": "external_input",
         "confidence": "low"},
    ]


# ---------------------------------------------------------------------------
# the analyze-level counters: accepted-response accounting only
# ---------------------------------------------------------------------------

class _StableAdapter:
    """A canned adapter for the analyze loop: one batch, two signals, one
    for a unit OUTSIDE the batch (the skip), one inside."""

    def __init__(self, body):
        self._body = body
        self.model = "claude-test"
        self.calls = 0

    def complete(self, **kw):
        from utilities.llm import CompletionResult, TextBlock
        self.calls += 1
        return CompletionResult(
            content=[TextBlock(self._body)], stop_reason="end_turn",
            input_tokens=1, output_tokens=1, usage_details=None)


class _Binding:
    def __init__(self, adapter):
        self.adapter = adapter
        self.model = "claude-test"


def _unit(uid):
    return {"id": uid, "unit_type": "function",
            "code": {"primary_code": "def f(): pass"}}


def test_analyze_counts_the_skip_class_into_stats():
    """The counter reaches the stats dict (the step report's source)."""
    body = json.dumps({"signals": [
        _sig("b.py:other"),
        _sig("a.py:f", "entry_point", "high")]})
    stats = {}
    analyze_reachability(
        {"units": [_unit("a.py:f")]},
        binding=_Binding(_StableAdapter(body)), stats=stats,
    )
    assert stats["signals_skipped_unknown_unit"] == 1
    assert stats["signals_skipped_unknown_unit_by_class"] == {
        "entry_point/high": 1}
    # error_count doctrine: a skipped signal is NOT a coverage failure
    assert stats["batches_dropped"] == 0


def test_max_tokens_batch_discards_its_skips():
    """A truncated response's skips never reach the stage totals (the
    double-count guard: the batch is counted in units_not_reviewed —
    counting its signals too would double-account the loss)."""
    from utilities.llm import CompletionResult, TextBlock
    body = json.dumps({"signals": [
        _sig("b.py:other"),
        _sig("a.py:f")]})
    stats = {}

    class _Trunc(_StableAdapter):
        def complete(self, **kw):
            self.calls += 1
            return CompletionResult(
                content=[TextBlock(body)], stop_reason="max_tokens",
                input_tokens=1, output_tokens=1, usage_details=None)

    analyze_reachability(
        {"units": [_unit("a.py:f")]},
        binding=_Binding(_Trunc(body)), stats=stats,
    )
    assert stats["signals_skipped_unknown_unit"] == 0
    assert stats["batches_dropped"] == 1  # the batch loss counted once


# ---------------------------------------------------------------------------
# the refilter decomposition (the counterfactual baseline)
# ---------------------------------------------------------------------------

def _run_refilter(units, functions, call_graph, reverse, extra_eps=None,
                  tmp_path=None):
    """Drive apply_reachability_filter through its real contract: a
    call_graph.json artifact in an output dir (the module reads files, not
    kwargs)."""
    import tempfile
    from core.parser_adapter import apply_reachability_filter
    tmp = tmp_path if tmp_path is not None else tempfile.mkdtemp()
    (Path(tmp) / "call_graph.json").write_text(json.dumps({
        "functions": functions,
        "call_graph": call_graph,
        "reverse_call_graph": reverse,
    }))
    dataset = {"units": [dict(u) for u in units]}
    return apply_reachability_filter(
        dataset, str(tmp), "reachable",
        extra_entry_points=extra_eps), tmp


def test_newly_reachable_decomposes_the_promotion(tmp_path):
    """A leaf unit reachable ONLY through the LLM-promoted seed:
    units_newly_reachable == 1; the structural baseline == the detector
    seed alone."""
    units = [
        {"id": "app.py:main", "unit_type": "function",
         "code": {"primary_code": "def main(): pass"}},
        {"id": "lib.py:helper", "unit_type": "function",
         "code": {"primary_code": "def helper(): pass"}},
    ]
    functions = {
        "app.py:main": {"file": "app.py", "name": "main"},
        "lib.py:helper": {"file": "lib.py", "name": "helper"},
    }
    call_graph = {"app.py:main": ["lib.py:helper"]}
    reverse = {"lib.py:helper": ["app.py:main"]}  # the analyzer rebuilds
    # forward adjacency from the REVERSE graph (reachability_analyzer.py's
    # own contract) — a flat call_graph alone walks nothing.
    # no LLM extras -> no baseline (nothing to decompose)
    ds, tmp = _run_refilter(units, functions, call_graph, reverse, tmp_path=tmp_path)
    rec = ds["metadata"]["reachability_filter"]
    assert "units_newly_reachable" not in rec
    # the LLM promotes lib.py:helper as a seed: helper becomes newly
    # reachable (the detector's main-only closure did not include it)
    ds2, tmp = _run_refilter(units, functions, call_graph, reverse,
                             extra_eps={"lib.py:helper"}, tmp_path=tmp_path)
    rec2 = ds2["metadata"]["reachability_filter"]
    assert rec2["structural_reachable_units"] == 2  # main + helper(main's callee)
    assert rec2["units_newly_reachable"] == 0
    # a TRULY new seed: a unit the structural closure never touched
    units.append({"id": "extra.py:alone", "unit_type": "function",
                  "code": {"primary_code": "def alone(): pass"}})
    functions["extra.py:alone"] = {"file": "extra.py", "name": "alone"}
    ds3, tmp = _run_refilter(units, functions, call_graph, reverse,
                             extra_eps={"extra.py:alone"}, tmp_path=tmp_path)
    rec3 = ds3["metadata"]["reachability_filter"]
    assert rec3["units_newly_reachable"] == 1
    assert rec3["structural_reachable_units"] == 2


def test_keep_all_path_never_reports_gains(tmp_path):
    """The empty-seed keep-all retains units WITHOUT proving reachability —
    the decomposition keys stay ABSENT (a fabricated gain is worse than a
    missing one)."""
    units = [{"id": "x.py:f", "unit_type": "function",
              "code": {"primary_code": "def f(): pass"}}]
    ds, tmp = _run_refilter(units, {}, {}, {}, tmp_path=tmp_path)
    rec = ds["metadata"]["reachability_filter"]
    assert "units_newly_reachable" not in rec
    assert rec["effective_processing_level"] == "all"


# ---------------------------------------------------------------------------
# the aggregation lift (the #328 class) + the summary keys
# ---------------------------------------------------------------------------

def test_aggregate_lifts_the_new_keys():
    from core.scanner import aggregate_reachability_telemetry
    # a record WITH the classification keys keeps the invariant key (a
    # measured 0 from a classified record is the healthy signal):
    out = aggregate_reachability_telemetry({
        "python": {"pruned_orphan_count": 1,
                   "structural_reachable_units": 10,
                   "units_newly_reachable": 2},
        "javascript": {"units_newly_reachable": 1},
    })
    assert out["structural_reachable_units"] == 10
    assert out["units_newly_reachable"] == 3
    assert out["pruned_forward_called_by_reachable_count"] == 0  # classified
    # the asym guard: a record with ONLY the decomposition keys (the
    # classification never ran for it) must NOT fabricate the invariant —
    # the #602 trap (agg truthiness is no longer the condition).
    out2 = aggregate_reachability_telemetry({
        "python": {"structural_reachable_units": 10,
                   "units_newly_reachable": 2},
    })
    assert out2["units_newly_reachable"] == 2
    assert "pruned_forward_called_by_reachable_count" not in out2
    assert "pruned_orphan_count" not in out2
    # the measured-languages denominator
    out3 = aggregate_reachability_telemetry({
        "python": {"structural_reachable_units": 10, "units_newly_reachable": 2},
        "javascript": {"units_newly_reachable": 1},
    })
    assert out3["reachability_baseline_languages"] == 2
    # the string marker lifts language-prefixed, never summed
    out4 = aggregate_reachability_telemetry({
        "python": {"reachability_baseline": "no_real_structural_seeds"},
    })
    assert out4["reachability_baseline"] == "python: no_real_structural_seeds"


def test_split_batch_halves_commit_their_own_skips():
    """The claimed receipt, made real: a max_tokens parent batch discards
    its own skip; each split half commits ITS OWN skips exactly once
    (nothing subtracted, nothing double-counted) — and the cross-half
    references read as skips by batching geometry (the disclosed
    non-invariance: split-recovered runs read higher)."""
    from utilities.llm import CompletionResult, TextBlock
    parent_body = json.dumps({"signals": [
        _sig("ghost.py:x")]})  # discarded with the truncated batch
    halves_body = json.dumps({"signals": [
        _sig("a.py:f"),                            # the half's own unit
        _sig("b.py:g", "external_input", "low"),   # the OTHER half — a skip
    ]})

    class _SplitAdapter:
        model = "claude-test"

        def __init__(self):
            self.calls = 0

        def complete(self, **kw):
            self.calls += 1
            if self.calls == 1:  # the full batch — truncated, split fires
                return CompletionResult(
                    content=[TextBlock(parent_body)],
                    stop_reason="max_tokens", input_tokens=1,
                    output_tokens=1, usage_details=None)
            return CompletionResult(  # each half — accepted
                content=[TextBlock(halves_body)], stop_reason="end_turn",
                input_tokens=1, output_tokens=1, usage_details=None)

    stats = {}
    analyze_reachability(
        {"units": [_unit("a.py:f"), _unit("b.py:g")]},
        binding=_Binding(_SplitAdapter()), stats=stats, batch_size=4)
    assert stats["signals_skipped_unknown_unit"] == 2  # one per half
    assert stats["signals_skipped_unknown_unit_by_class"] == {
        "entry_point/high": 1, "external_input/low": 1}
    assert stats["batches_split_recovered"] == 1
    assert stats["batches_dropped"] == 0
    assert stats["batches_truncated"] == 0


def test_step_report_carries_the_skip_keys(monkeypatch, tmp_path):
    """The EXECUTED artifact pin (the source-string pin retired): the real
    scan path's llm-reachability.report.json carries the skip counters AND
    the promotable subset sized from THIS run's promote_set."""
    from pathlib import Path
    import utilities.llm as llm_mod
    from core import parser_adapter, analyzer, reporter, tracking
    from core import scanner as scanner_mod
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
        assert isinstance(stats, dict), "scanner must pass a stats dict"
        stats["signals_skipped_unknown_unit"] = 2
        stats["signals_skipped_unknown_unit_by_class"] = {
            "entry_point/high": 1, "external_input/low": 1}
        return []

    monkeypatch.setattr(lr, "analyze_reachability", _fake_analyze)
    monkeypatch.setattr(
        lr, "apply_signals",
        lambda dataset, signals: {"signals_applied": 0,
                                  "entry_points_promoted": 0,
                                  "units_touched": 0,
                                  "promote_set": ["high"]})
    monkeypatch.setattr(lr, "signals_to_json", lambda signals: [])

    scanner_mod.scan_repository(
        repo_path=str(tmp_path), output_dir=str(tmp_path / "out"),
        generate_context=False, enhance=False, verify=False,
        generate_report=False, dynamic_test=False,
        llm_reachability=True, processing_level="reachable")

    report = json.loads(
        (tmp_path / "out" / "llm-reachability.report.json").read_text())
    s = report["summary"]
    assert s["signals_skipped_unknown_unit"] == 2
    assert s["signals_skipped_unknown_unit_by_class"] == {
        "entry_point/high": 1, "external_input/low": 1}
    # the promotable subset: entry_point/high (in promote_set) only
    assert s["signals_skipped_promotable"] == 1


def test_reporter_forwards_the_decomposition_executed(tmp_path):
    """The EXECUTED forwarding pin (the AST source pin retired): the three
    int keys and the string marker reach pipeline_output.json's
    pipeline_stats through the REAL build_pipeline_output."""
    from tests.test_issue301_prune_telemetry_deliverable import _write_scan
    po = _write_scan(tmp_path, telemetry={
        "structural_reachable_units": 10, "units_newly_reachable": 3,
        "reachability_baseline_languages": 1,
        "reachability_baseline": "python: no_real_structural_seeds"})
    ps = po["pipeline_stats"]
    assert ps["structural_reachable_units"] == 10
    assert ps["units_newly_reachable"] == 3
    assert ps["reachability_baseline_languages"] == 1
    assert ps["reachability_baseline"] == "python: no_real_structural_seeds"


def test_promotable_sizing_the_real_function():
    """The sizing via the FACTORED scanner helper — the guard (malformed
    keys never crash the report assembly), the gate (entry_point + the
    confidence in THIS run's promote_set)."""
    from core.scanner import _promotable_skip_count
    by_class = {"entry_point/high": 1, "entry_point/medium": 1,
                "external_input/high": 5}
    assert _promotable_skip_count(by_class, ["high"]) == 1
    # a malformed key (no slash / a non-int) never crashes
    assert _promotable_skip_count(
        {"entry_point": 3, "x/y": "not-int"}, ["y"]) == 0


def test_baseline_marker_for_the_synthetic_only_case(tmp_path):
    """The most-informative decomposition case — the LLM extras are the ONLY
    real seeds (the structural pass found none): the baseline is
    unmeasurable and DISCLOSED (never silently absent — absence reads as
    'no LLM extras')."""
    units = [{"id": "x.py:f", "unit_type": "function",
              "code": {"primary_code": "def f(): pass"}}]
    ds, tmp = _run_refilter(units, {}, {}, {},
                            extra_eps={"x.py:f"}, tmp_path=tmp_path)
    rec = ds["metadata"]["reachability_filter"]
    assert rec.get("reachability_baseline") == "no_real_structural_seeds"
    assert "units_newly_reachable" not in rec


def test_baseline_marker_on_the_keep_all_pass_through(tmp_path):
    """The pass-through (keep-all) branch of the marker: extras present but
    every seed synthetic — the most-informative case disclosed on the
    keep-all path too, not only the filtered one."""
    units = [{"id": "x.py:f", "unit_type": "function",
              "code": {"primary_code": "def f(): pass"}}]
    functions = {"x.py:fuzz": {"file": "x.py", "name": "fuzz",
                               "synthetic_harness": True,
                               "unit_type": "main"}}
    ds, tmp = _run_refilter(units, functions, {}, {},
                            extra_eps={"x.py:fuzz"}, tmp_path=tmp_path)
    rec = ds["metadata"]["reachability_filter"]
    assert rec.get("reachability_baseline") == "no_real_structural_seeds"
    assert "units_newly_reachable" not in rec
