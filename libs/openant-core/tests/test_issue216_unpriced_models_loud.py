"""Regression tests for issue #216 — unpriced models must be loud in artifacts.

A model absent from config/models.json dispatched normally: every phase
reported ``cost_usd: 0.0000`` with correct token counts (only money blind),
and NOTHING in any artifact recorded that the cost was incomplete — the
null-price convention's exact failure mode, reached via the missing-record
path. A one-time stderr warning existed but is invisible in a 7-phase run's
noise and leaves no durable trace.

Contract locked here:
- ``TokenTracker`` records every unpriced call and the unpriced model set;
  ``get_totals``/``get_summary`` expose ``cost_incomplete`` + ``unpriced_models``;
- ``UsageInfo`` carries the same two fields, so step reports and
  ``scan.report.json`` surface them (the deterministic advisory surface —
  same class as the #212 coverage headline);
- the scanner's aggregate token_usage OR-aggregates ``cost_incomplete``
  across step reports (a rebuild-from-parts must not drop the marker);
- the report-generator's own costing fallback annotates the same marker
  (it duplicates the tracker's miss path outside the tracker).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import TokenTracker  # noqa: E402


def test_tracker_records_unpriced_models():
    t = TokenTracker()
    t.record_call(model="totally/unknown-model", input_tokens=100,
                  output_tokens=50)  # no pricing → $0 + unpriced
    totals = t.get_totals()
    assert totals["cost_incomplete"] is True
    assert "totally/unknown-model" in totals["unpriced_models"]


def test_tracker_priced_call_is_complete():
    t = TokenTracker()
    t.record_call(model="m", input_tokens=10, output_tokens=5,
                  pricing={"input": 1.0, "output": 2.0})
    totals = t.get_totals()
    assert totals["cost_incomplete"] is False
    assert totals["unpriced_models"] == []


def test_mixed_run_incomplete_and_both_models_listed():
    t = TokenTracker()
    t.record_call(model="known/m", input_tokens=10, output_tokens=5,
                  pricing={"input": 1.0, "output": 2.0})
    t.record_call(model="unknown/a", input_tokens=10, output_tokens=5)
    t.record_call(model="unknown/a", input_tokens=10, output_tokens=5)  # dedup
    t.record_call(model="unknown/b", input_tokens=10, output_tokens=5)
    totals = t.get_totals()
    assert totals["cost_incomplete"] is True
    assert sorted(totals["unpriced_models"]) == ["unknown/a", "unknown/b"]


def test_usage_info_carries_the_marker():
    from core.schemas import UsageInfo
    from core import tracking
    tracker = tracking.get_global_tracker()
    tracker.reset()
    tracker.record_call(model="unknown/x", input_tokens=1, output_tokens=1)
    usage = tracking.get_usage()
    assert isinstance(usage, UsageInfo)
    assert usage.cost_incomplete is True
    assert "unknown/x" in usage.unpriced_models
    assert "cost_incomplete" in usage.to_dict()


def test_step_report_serializes_the_marker(tmp_path: Path):
    from core.step_report import step_context
    from core import tracking
    tracker = tracking.get_global_tracker()
    tracker.reset()
    tracker.record_call(model="unknown/x", input_tokens=1, output_tokens=1)
    with step_context("analyze", str(tmp_path)):
        pass
    import json
    report = json.loads((tmp_path / "analyze.report.json").read_text())
    assert report["token_usage"]["cost_incomplete"] is True


def test_registry_records_for_the_issue_slugs_exist():
    """Data half: the three missing slugs from the issue now have
    records with the live-catalogue source convention."""
    import json
    from pathlib import Path as P
    registry = json.loads(
        (P(__file__).parents[3] / "config" / "models.json").read_text())
    ids = {m["id"] for m in registry["models"]}
    for slug in ("anthropic/claude-opus-5", "anthropic/claude-sonnet-5",
                 "anthropic/claude-fable-5"):
        assert slug in ids, f"{slug} missing from config/models.json"
        rec = next(m for m in registry["models"] if m["id"] == slug)
        assert rec["price"]["input"] > 0 and rec["price"]["output"] > 0
        assert "retrieved" in rec and "source" in rec


def test_scan_report_aggregate_or_aggregates_marker(tmp_path, monkeypatch):
    """_write_scan_report rebuilds token_usage from step reports — the
    incomplete-cost marker must survive the rebuild (OR across steps)."""
    import json
    from core.scanner import _write_scan_report
    from core.schemas import ScanResult, AnalysisMetrics

    metrics = AnalysisMetrics(total=0, vulnerable=0, bypassable=0, inconclusive=0,
                              protected=0, safe=0, errors=0)
    result = ScanResult(output_dir=str(tmp_path), units_count=0,
                        language="python", metrics=metrics)
    step_reports = [
        {"step": "parse", "cost_usd": 0.0, "duration_seconds": 1.0,
         "token_usage": {"input_tokens": 5, "output_tokens": 5,
                         "total_tokens": 10, "cost_incomplete": True,
                         "unpriced_models": ["unknown/a"]}},
        {"step": "analyze", "cost_usd": 0.1, "duration_seconds": 1.0,
         "token_usage": {"input_tokens": 5, "output_tokens": 5,
                         "total_tokens": 10}},
    ]
    path = _write_scan_report(str(tmp_path), result, step_reports)
    agg = json.loads(Path(path).read_text())
    tu = agg["token_usage"]
    assert tu["cost_incomplete"] is True
    assert tu["unpriced_models"] == ["unknown/a"]


def test_scan_report_aggregate_clean_when_all_steps_clean(tmp_path):
    import json
    from core.scanner import _write_scan_report
    from core.schemas import ScanResult, AnalysisMetrics
    metrics = AnalysisMetrics(total=0, vulnerable=0, bypassable=0, inconclusive=0,
                              protected=0, safe=0, errors=0)
    result = ScanResult(output_dir=str(tmp_path), units_count=0,
                        language="python", metrics=metrics)
    step_reports = [{"step": "parse", "cost_usd": 0.1, "duration_seconds": 1.0,
                     "token_usage": {"input_tokens": 5, "output_tokens": 5,
                                     "total_tokens": 10}}]
    path = _write_scan_report(str(tmp_path), result, step_reports)
    agg = json.loads(Path(path).read_text())
    assert "cost_incomplete" not in agg["token_usage"]


# ---------------------------------------------------------------------------
# Wave-1 additions: generator annotation, merge OR, unit-level + resume restore
# ---------------------------------------------------------------------------

def test_generator_fallback_annotates_incomplete():
    """BLOCKER catch (3-seat convergence): _extract_usage with no pricing
    must mark its OWN usage dict cost_incomplete (the commit claimed this
    and it wasn't there)."""
    from report.generator import _extract_usage
    u = _extract_usage(100, 50, "totally/unknown")
    assert u["cost_incomplete"] is True
    priced = _extract_usage(100, 50, "m", pricing={"input": 1.0, "output": 2.0})
    assert "cost_incomplete" not in priced


def test_merge_usage_ors_incomplete():
    from report.generator import _merge_usage
    merged = _merge_usage([
        {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15, "cost_usd": 0.01},
        {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15, "cost_usd": 0.0,
         "cost_incomplete": True},
    ])
    assert merged.get("cost_incomplete") is True


def test_unit_usage_carries_own_unpriced_models():
    t = TokenTracker()
    t.start_unit_tracking()
    t.record_call(model="unknown/u", input_tokens=1, output_tokens=1)
    usage = t.get_unit_usage()
    assert usage["cost_incomplete"] is True
    assert usage["unpriced_models"] == ["unknown/u"]


def test_add_prior_usage_restores_marker_across_resume():
    """BLOCKER catch: a resumed run's tracker must not silently look
    complete when the prior run had unpriced models."""
    t = TokenTracker()
    t.add_prior_usage(100, 50, 0.0, unpriced_models=["unknown/a"])
    totals = t.get_totals()
    assert totals["cost_incomplete"] is True
    assert totals["unpriced_models"] == ["unknown/a"]


def test_analyzer_resume_restores_marker(tmp_path, monkeypatch):
    """The analyzer's checkpoint-restore path re-injects unpriced models
    from per-unit records into the tracker."""
    import json
    from core import checkpoint as cp_mod
    from core import tracking
    from utilities.file_io import write_json
    import tempfile, os

    td = tempfile.mkdtemp()
    # one per-unit checkpoint carrying the marker
    write_json(os.path.join(td, "unit_a.json"),
               {"result": {"verdict": "safe"}, "usage": {
                   "input_tokens": 10, "output_tokens": 5, "cost_usd": 0.0,
                   "cost_incomplete": True, "unpriced_models": ["unknown/a"]}})
    tracker = tracking.get_global_tracker()
    tracker.reset()
    # drive the same accumulation the resume loop performs
    _existing = {"unit_a": json.loads(
        open(os.path.join(td, "unit_a.json")).read())}
    unpriced = set()
    for _uid, _cp in _existing.items():
        unpriced.update(_cp.get("usage", {}).get("unpriced_models") or [])
    tracker.add_prior_usage(10, 5, 0.0,
                            unpriced_models=sorted(unpriced) or None)
    totals = tracker.get_totals()
    assert totals["cost_incomplete"] is True
    assert totals["unpriced_models"] == ["unknown/a"]


def test_agent_result_metadata_carries_unpriced_models():
    """Confirm-round BLOCKER fix: the ENHANCER's per-unit record
    (agent_metadata) must carry the marker — the #211-style real-loop test
    with an unpriced (no-pricing) adapter."""
    from utilities.agentic_enhancer.agent import ContextAgent
    from utilities.llm.adapter import CompletionResult, TextBlock, ToolUseBlock
    from utilities.llm.registry import PhaseBinding
    from utilities.llm_client import TokenTracker
    from utilities.agentic_enhancer.repository_index import RepositoryIndex

    class _UnpricedAdapter:
        name = "fake"
        supports_tools = True
        pricing = {}  # NO pricing for fake-model → unpriced path

        def __init__(self):
            self.turn = 0

        def complete(self, *, model, max_tokens, system, tools, messages):
            self.turn += 1
            if self.turn == 1:
                return CompletionResult(
                    content=(ToolUseBlock(id="t1", name="finish",
                                          input={"security_classification": "exploitable",
                                                 "usage_context": "ctx",
                                                 "include_functions": [],
                                                 "classification_reasoning": "r",
                                                 "confidence": 0.9}),),
                    input_tokens=10, output_tokens=5, stop_reason="tool_use")
            return CompletionResult(
                content=(TextBlock("done"),),
                input_tokens=8, output_tokens=4, stop_reason="end_turn")

    tracker = TokenTracker()
    binding = PhaseBinding(phase="enhance", adapter=_UnpricedAdapter(),
                           model="fake-model", provider_name="fake")
    agent = ContextAgent(index=RepositoryIndex({}, repo_path=None),
                         binding=binding, tracker=tracker)
    tracker.start_unit_tracking()
    result = agent.analyze_unit(
        unit_id="a.py:f", unit_type="function",
        primary_code="def f(): ...", static_deps=[], static_callers=[])
    d = result.to_dict()
    meta = d["agent_metadata"]
    assert meta.get("cost_incomplete") is True, (
        f"agent_metadata must carry the incomplete-cost marker for an "
        f"unpriced unit (got {meta!r})"
    )
    assert meta.get("unpriced_models") == ["fake-model"]
