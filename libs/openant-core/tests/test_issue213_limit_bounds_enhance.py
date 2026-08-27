"""Regression tests for issue #213 — ``--limit`` bounds the enhance phase.

``scan --limit 2`` ran the agentic enhancer across the ENTIRE dataset before
analyzing 2 units — the cheapest-looking way to try OpenAnt on a real repo
incurred near-full cost, with no warning (the reporter measured 1351 units
enhanced on a ``--limit 2`` run).

The plumbing already existed: ``enhance_dataset(limit=...)`` ("Mirrors
``analyze --limit``", applied as a head-slice). The scanner simply never
threaded the scan's ``--limit`` into it. Contract locked here: the scan's
``--limit`` bounds BOTH the enhance phase and the analyze phase; the LLM
reachability pass deliberately remains unbounded (scanner's documented
rationale — it must see the full codebase to find missed entry points).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.schemas import AnalysisMetrics, ParseResult  # noqa: E402


@pytest.fixture(autouse=True)
def _offline_registry(monkeypatch):
    """Hermetic: neuter the credential probe + config resolution offline."""
    import utilities.llm as llm_mod

    monkeypatch.setattr(
        llm_mod, "probe_registry_or_raise", lambda *a, **k: None, raising=True)
    orig_resolve = llm_mod.resolve_llm_config
    monkeypatch.setattr(
        llm_mod, "resolve_llm_config",
        lambda cf, name: orig_resolve(cf, None), raising=True)


def _install_pipeline(monkeypatch, tmp_path, *, enhance_calls):
    """Offline parse → enhance → analyze scaffold (the pr69 pattern)."""
    import core.parser_adapter as parser_adapter
    import core.analyzer as analyzer
    import core.tracking as tracking

    class _ParseResult:
        def __init__(self, output_dir):
            self.dataset_path = str(Path(output_dir) / "dataset.json")
            self.analyzer_output_path = str(Path(output_dir) / "analyzer.json")
            self.units_count = 5
            self.language = "python"
            self.processing_level = "all"

    def _fake_parse(*, output_dir, **kwargs):
        pr = _ParseResult(output_dir)
        Path(pr.dataset_path).write_text('{"units": []}')
        Path(pr.analyzer_output_path).write_text("{}")
        return pr

    metrics = AnalysisMetrics(total=5, vulnerable=1, bypassable=0, inconclusive=0,
                              protected=0, safe=4, errors=0)

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

    def _fake_enhance(*, dataset_path, output_path, limit=None, **kwargs):
        enhance_calls.append({"limit": limit,
                              "dataset_path": dataset_path})
        Path(output_path).write_text(Path(dataset_path).read_text())
        class _ER:
            enhanced_dataset_path = output_path
            units_enhanced = limit or 5
            error_count = 0
            classifications = {}
            error_summary = None
        return _ER()

    monkeypatch.setattr(parser_adapter, "parse_repository", _fake_parse)
    monkeypatch.setattr(analyzer, "run_analysis", _fake_analysis)
    import core.enhancer as enhancer
    monkeypatch.setattr(enhancer, "enhance_dataset", _fake_enhance)
    import core.reporter as reporter
    monkeypatch.setattr(reporter, "build_pipeline_output", _fake_build_output)
    tracking.reset_tracking()


def _scan(tmp_path, monkeypatch, *, limit):
    from core import scanner as scanner_mod
    calls = []
    _install_pipeline(monkeypatch, tmp_path, enhance_calls=calls)
    scanner_mod.scan_repository(
        repo_path=str(tmp_path),
        output_dir=str(tmp_path / "out"),
        generate_context=False,
        enhance=True,
        verify=False,
        generate_report=False,
        dynamic_test=False,
        limit=limit,
    )
    return calls


def test_scan_limit_threads_into_enhance(tmp_path, monkeypatch):
    """The scan's --limit must bound the enhance phase (#213)."""
    calls = _scan(tmp_path, monkeypatch, limit=2)
    assert calls, "enhance must have run"
    assert calls[0]["limit"] == 2, (
        f"scan --limit 2 must thread limit=2 into enhance_dataset "
        f"(got {calls[0]['limit']!r}) — the unbounded enhance was #213's "
        "near-full-cost surprise"
    )


def test_scan_without_limit_enhances_all(tmp_path, monkeypatch):
    calls = _scan(tmp_path, monkeypatch, limit=None)
    assert calls[0]["limit"] is None


def test_scan_help_text_states_enhance_bounded():
    """#213 ask: the help text must state exactly what --limit bounds —
    locked on the ACTUAL argparse help string of the scan verb's --limit
    (not a source-substring match, which a comment could satisfy)."""
    import argparse
    from openant.cli import build_parser

    parser = build_parser()
    subparsers_actions = [
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    scan_parser = subparsers_actions[0].choices["scan"]
    # Lock the --limit ACTION's OWN help string — a whole-block render could
    # be satisfied by a sibling flag's text (sonnet confirm-round catch).
    limit_action = next(
        a for a in scan_parser._actions if "--limit" in (a.option_strings or []))
    help_text = limit_action.help or ""
    assert "Max units to analyze and enhance" in help_text
    assert "full codebase" in help_text


def test_enhance_limit_slices_diff_selected_population():
    """glm-5.3 MAJOR: --limit + --diff markers must slice the DIFF-SELECTED
    population (analyze's semantics: filter-then-limit), never the raw
    alphabetical head — else a limited diff run enhances/analyzes ~0 units
    and exits clean (false coverage). Observes the dataset actually handed
    to the enhancer (the post-slice population)."""
    import os
    import tempfile
    from pathlib import Path
    import unittest.mock as mock

    from core.enhancer import enhance_dataset
    from utilities.file_io import write_json

    units = ([{"unit_id": f"a.py:f{i}", "diff_selected": False} for i in range(5)]
             + [{"unit_id": f"z.py:g{i}", "diff_selected": True} for i in range(5)])

    captured = {}

    class _StubEnhancer:
        def __init__(self, *a, **k):
            pass

        def enhance_dataset_agentic(self, dataset=None, **kwargs):
            captured["unit_ids"] = [u["unit_id"] for u in dataset.get("units", [])]
            return {"units": dataset.get("units", [])}

    with tempfile.TemporaryDirectory() as td:
        ds = os.path.join(td, "dataset.json")
        write_json(ds, {"units": units})
        out = os.path.join(td, "enhanced.json")
        import utilities.context_enhancer as ctx_mod
        with mock.patch.object(ctx_mod, "ContextEnhancer", _StubEnhancer):
            enhance_dataset(dataset_path=ds, output_path=out,
                            analyzer_output_path=os.path.join(td, "ao.json"),
                            repo_path=td, mode="agentic", limit=2)
    assert captured["unit_ids"] == ["z.py:g0", "z.py:g1"], (
        f"limit must slice the DIFF-SELECTED population (analyze's "
        f"filter-then-limit order), got {captured['unit_ids']!r} — a raw "
        "alphabetical head-slice silently drops diff-selected units and "
        "produces a false-coverage empty scan"
    )


def test_enhance_limit_zero_diff_selection_spends_nothing():
    """A diff that selected ZERO units is still an annotated dataset
    (key-presence predicate, analyzer.py:523's mirror): enhance filters to
    0 units rather than spending the limit on unrelated units."""
    import os
    import tempfile
    import unittest.mock as mock

    from core.enhancer import enhance_dataset
    from utilities.file_io import write_json

    units = [{"unit_id": f"a.py:f{i}", "diff_selected": False} for i in range(5)]
    captured = {}

    class _StubEnhancer:
        def __init__(self, *a, **k):
            pass

        def enhance_dataset_agentic(self, dataset=None, **kwargs):
            captured["unit_ids"] = [u["unit_id"] for u in dataset.get("units", [])]
            return {"units": dataset.get("units", [])}

    with tempfile.TemporaryDirectory() as td:
        ds = os.path.join(td, "dataset.json")
        write_json(ds, {"units": units})
        import utilities.context_enhancer as ctx_mod
        with mock.patch.object(ctx_mod, "ContextEnhancer", _StubEnhancer):
            enhance_dataset(dataset_path=ds,
                            output_path=os.path.join(td, "e.json"),
                            analyzer_output_path=os.path.join(td, "ao.json"),
                            repo_path=td, mode="agentic", limit=2)
    assert captured["unit_ids"] == [], (
        f"a zero-selection diff must enhance 0 units, not spend the limit on "
        f"unrelated units (got {captured['unit_ids']!r})"
    )
