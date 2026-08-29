"""Regression tests for issue #294 — llm-reachability's batch-parse failure
is undiagnosable: six materially different failures emit one byte-identical
log line, the raw response is discarded, the batch index is absent, and
nothing counts the drop (the step report said ``units_reviewed: 10845`` for
a run in which ~250 units were never reviewed — 10 of 434 batches lost).

Contract locked here:
- each failure SHAPE is named in the message: empty response / non-JSON
  prose / truncated-or-unbalanced JSON / valid-JSON-array / valid JSON of
  another named type — six shapes, six distinct messages;
- the batch-level drop message carries the caller's batch label and a
  truncated raw snippet (the evidence, previously discarded);
- ``analyze_reachability`` counts dropped batches and the units they
  carried into an optional ``stats`` dict (exact, computed at drop time —
  batch membership is known there);
- the scanner surfaces ``batches_dropped`` / ``units_not_reviewed`` in the
  step report summary alongside ``units_reviewed``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.llm_reachability import analyze_reachability, parse_response  # noqa: E402

SHAPES = {
    "bare array": (
        '[{"unit_id":"a.py:f","signal":"entry_point"}]',
        "valid JSON array, expected an object"),
    "fenced bare array": (
        '```json\n[{"unit_id":"a.py:f"}]\n```',
        "valid JSON array, expected an object"),
    "truncated mid-string": (
        '{"signals": [{"unit_id": "a.py:f", "reason": "this got cut',
        "truncated or unbalanced JSON"),
    "truncated mid-array": (
        '{"signals": [{"unit_id": "a.py:f"},',
        "truncated or unbalanced JSON"),
    "prose refusal": (
        "I can't help with analyzing this code for security purposes.",
        "non-JSON text (prose/refusal)"),
    "empty completion": (
        "",
        "empty response (no content)"),
}


def test_six_shapes_six_distinct_named_messages():
    """The six shapes from the issue produce DISTINCT messages, each naming
    its shape (previously: one byte-identical line for all six). The
    distinctness check is isolated from the raw-snippet suffix — the
    snippet differs per input regardless of classification, so comparing
    whole messages would pass even with a collapsed classifier (wave catch)."""
    prefixes = []
    for name, (text, expected_shape) in SHAPES.items():
        got: list[str] = []
        parse_response(text, valid_unit_ids={"a.py:f"}, on_error=got.append)
        assert len(got) == 1, name
        assert expected_shape in got[0], (name, got[0])
        # strip the evidence suffix: compare ONLY the classified part
        prefixes.append(got[0].split("; raw[:200]=")[0])
    assert len(set(prefixes)) == 4, (
        "6 shapes → 4 distinct classified messages: bare-array and "
        "fenced-array share the array classifier, and the two truncation "
        "variants share the truncation classifier — both by design; "
        "empty / prose / wrong-type must be distinct from all others")


def test_none_response_classifies_not_raises():
    """The docstring promises malformed entries are skipped, not raised —
    a None response_text must classify (wave catch: the snippet slice
    previously raised TypeError before reaching the classifier)."""
    got: list[str] = []
    out = parse_response(None, on_error=got.append)
    assert out == []
    assert "empty response (no content)" in got[0]


def test_wrong_type_json_named():
    got: list[str] = []
    parse_response('"just a string"', on_error=got.append)
    assert "valid JSON of wrong type str, expected an object" in got[0]


def test_drop_message_carries_batch_label_and_raw_snippet():
    got: list[str] = []
    parse_response(
        "I can't help with this.",
        on_error=got.append,
        batch_label="batch 7/434, units m.py:a..m.py:z",
    )
    assert "batch 7/434, units m.py:a..m.py:z" in got[0]
    assert "raw[:200]=" in got[0]
    assert "I can" in got[0], "the raw evidence is retained in the line"


def test_signals_missing_branch_names_type_and_counts_drop():
    got: list[str] = []
    drops = []
    parse_response(
        '{"signals": "nope"}',
        on_error=got.append,
        batch_label="batch 1/1",
        on_batch_drop=lambda: drops.append(1),
    )
    assert "'signals' missing or not a list (got str)" in got[0]
    assert drops == [1]


def test_valid_response_does_not_fire_drop_callback():
    drops = []
    out = parse_response(
        '{"signals": [{"unit_id": "a.py:f", "kind": "entry_point", '
        '"confidence": "high", "reason": "r"}]}',
        valid_unit_ids={"a.py:f"},
        on_batch_drop=lambda: drops.append(1),
    )
    assert len(out) == 1
    assert drops == []


# ---------------------------------------------------------------------------
# analyze_reachability — the count (exact, computed at drop time)
# ---------------------------------------------------------------------------
def _dataset(n_units: int) -> dict:
    return {"units": [
        {"id": f"f{i}.py:fn", "code": "x = 1", "is_entry_point": False}
        for i in range(n_units)
    ]}


class _ScriptedBinding:
    """simple_text is monkeypatched at module level; binding is opaque."""

    def __init__(self):  # pragma: no cover - opaque to analyze_reachability
        self.model = "m"
        self.adapter = None
        self.provider_name = "anthropic"


def test_analyze_reachability_counts_dropped_units(tmp_path, monkeypatch):

    dataset = _dataset(4)  # batch_size=2 → 2 batches
    responses = iter([
        # batch 1: valid
        ('{"signals": [{"unit_id": "f0.py:fn", "kind": "entry_point", '
         '"confidence": "high", "reason": "ok"}]}'),
        # batch 2: malformed (prose refusal)
        "I can't help with analyzing this code for security purposes.",
    ])
    errs: list[str] = []

    import utilities.llm as llm_mod
    monkeypatch.setattr(llm_mod, "simple_text",
                        lambda binding, prompt, **kw: next(responses))

    stats: dict = {}
    signals = analyze_reachability(
        dataset, binding=_ScriptedBinding(), batch_size=2,
        on_error=errs.append, stats=stats)

    # batch 1's signal survived the drop of batch 2
    assert [s.unit_id for s in signals] == ["f0.py:fn"]
    assert stats["batches_dropped"] == 1
    assert stats["units_not_reviewed"] == 2, "exact: batch membership known"
    # the drop message is attributable
    assert any("batch 2/2" in e and "prose/refusal" in e for e in errs), errs


def test_analyze_reachability_stats_absent_means_uncounted(tmp_path, monkeypatch):
    """No stats dict → no counting (backwards-compatible call shape)."""

    dataset = _dataset(2)
    import utilities.llm as llm_mod
    monkeypatch.setattr(llm_mod, "simple_text",
                        lambda binding, prompt, **kw: "not json at all")
    signals = analyze_reachability(dataset, binding=_ScriptedBinding(),
                                   batch_size=2)
    assert signals == []


# ---------------------------------------------------------------------------
# scanner — the step-report summary surface
# ---------------------------------------------------------------------------
def test_scanner_summary_surfaces_drop_counts(tmp_path, monkeypatch):
    from core.schemas import AnalysisMetrics
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.reporter as reporter
    import core.tracking as tracking
    # Module-style import is REQUIRED here (do not "consolidate" with the
    # file's top-level from-import): this test monkeypatches attributes ON
    # the core.llm_reachability module (analyze_reachability, apply_signals,
    # signals_to_json) that core.scanner resolves through the module at call
    # time — the from-imported name would bypass the patch.
    import core.llm_reachability as lr

    # hermetic registry: no config file, no keys, no probe calls
    import utilities.llm as llm_mod

    class _StubAdapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _StubRegistry:
        config_name = "stub"
        def get(self, phase):
            return llm_mod.PhaseBinding(phase=phase, adapter=_StubAdapter(),
                                        model="stub-model",
                                        provider_name="anthropic")

    monkeypatch.setattr(llm_mod, "build_phase_registry",
                        lambda cf, cfg: _StubRegistry())
    monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda reg: None)

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

    metrics = AnalysisMetrics(total=3, vulnerable=1, bypassable=0,
                              inconclusive=0, protected=0, safe=2, errors=0)

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
        # mirror the real contract: fill the stats dict the scanner passed
        assert isinstance(stats, dict), "scanner must pass a stats dict"
        stats["batches_dropped"] = 1
        stats["units_not_reviewed"] = 2
        return []

    monkeypatch.setattr(lr, "analyze_reachability", _fake_analyze)
    monkeypatch.setattr(
        lr, "apply_signals",
        lambda dataset, signals: {"signals_applied": 0,
                                  "entry_points_promoted": 0,
                                  "units_touched": 0})
    monkeypatch.setattr(lr, "signals_to_json", lambda signals: [])

    from core import scanner as scanner_mod
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

    # the step report is a per-step file (scan.report.json is the aggregate)
    report = json.loads(
        (tmp_path / "out" / "llm-reachability.report.json").read_text())
    summary = report.get("summary", {})
    assert summary.get("batches_dropped") == 1
    assert summary.get("units_not_reviewed") == 2
    assert "units_reviewed" in summary, "the drop count sits beside it"
    assert result is not None
