"""Drives the per-language re-filter LOOP BODY itself — not its helpers.

Three prior attempts to "cover this loop" tested the functions the loop calls
and left the body unentered. The guard against a fourth is
``test_the_loop_body_actually_executed``: it asserts a marker set INSIDE the
loop, so the file cannot pass while the branch is skipped.

Fully offline — the LLM reachability call is stubbed.
"""

import json
from pathlib import Path

import pytest

import core.scanner as scanner_mod

LOOP_MARKER: list[str] = []


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    import utilities.llm as llm_mod
    monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda *a, **k: None)


@pytest.fixture
def repo(tmp_path):
    src = tmp_path / "repo"
    (src / "web").mkdir(parents=True)
    (src / "app.py").write_text("def handler():\n    pass\n")
    (src / "web" / "app.js").write_text("function route() {}\n")
    return src


@pytest.fixture
def fake_parsers(monkeypatch):
    """Per-language parsers that emit a real call_graph.json each."""
    graphs = {
        "python": (["app.py:handler", "app.py:helper"], ["app.py:handler"]),
        "javascript": (["web/app.js:route", "web/app.js:util"], []),  # NO entry point
    }

    def fake_parser_for(language):
        def _parse(repo_path, output_dir, processing_level, skip_tests=True,
                   name=None, library_mode=False):
            ids, entries = graphs[language]
            d = Path(output_dir); d.mkdir(parents=True, exist_ok=True)
            (d / "dataset.json").write_text(json.dumps({
                "units": [{"id": i, "code": "x"} for i in ids],
                "statistics": {}, "metadata": {},
            }))
            (d / "analyzer_output.json").write_text(json.dumps(
                {"functions": {i: {} for i in ids}}))
            (d / "call_graph.json").write_text(json.dumps({
                "functions": {i: {"is_entry_point": i in entries} for i in ids},
                "call_graph": {i: [] for i in ids},
                "reverse_call_graph": {},
            }))
            from core.schemas import ParseResult
            return ParseResult(
                dataset_path=str(d / "dataset.json"),
                analyzer_output_path=str(d / "analyzer_output.json"),
                units_count=len(ids), language=language,
                processing_level=processing_level,
            )
        return _parse

    import core.parser_adapter as pa
    monkeypatch.setattr(pa, "_parser_for", fake_parser_for)


@pytest.fixture
def stub_llm_reachability(monkeypatch):
    """Stub the LLM stage so the re-filter branch is reached with no API call."""
    import core.llm_reachability as lr

    monkeypatch.setattr(lr, "analyze_reachability", lambda *a, **k: [])

    def fake_apply(dataset, signals):
        # Promote exactly one PYTHON unit — the cross-language seed hazard.
        for u in dataset.get("units", []):
            if u.get("id") == "app.py:handler":
                u["is_entry_point"] = True
        return {"signals_applied": 1, "entry_points_promoted": 1, "units_touched": 1}

    monkeypatch.setattr(lr, "apply_signals", fake_apply)
    monkeypatch.setattr(lr, "signals_to_json", lambda s: [])


@pytest.fixture
def probe_loop(monkeypatch):
    """Record that the loop body ran, by wrapping a function only it calls."""
    LOOP_MARKER.clear()
    real = scanner_mod.partition_units_by_language

    def traced(units):
        LOOP_MARKER.append("entered")
        return real(units)

    monkeypatch.setattr(scanner_mod, "partition_units_by_language", traced)


def run(repo, out):
    return scanner_mod.scan_repository(
        repo_path=str(repo), output_dir=str(out),
        languages=["python", "javascript"],
        processing_level="reachable",
        llm_reachability=True,
        generate_context=False, generate_report=False,
        enhance=False, verify=False,
    )


class TestLoopBodyExecutes:
    def test_the_loop_body_actually_executed(self, repo, tmp_path, fake_parsers,
                                             stub_llm_reachability, probe_loop):
        """THE GATE. Three prior 'coverage' attempts never entered this branch."""
        run(repo, tmp_path / "out")
        assert LOOP_MARKER, (
            "the per-language re-filter loop body did NOT execute — this file "
            "is testing helpers again, not the loop"
        )

    def test_language_without_entry_points_is_not_blacked_out(self, repo, tmp_path,
                                                             fake_parsers,
                                                             stub_llm_reachability,
                                                             probe_loop):
        """The bug: JS has no entry point, python's seed must not reach it."""
        out = tmp_path / "out"
        result = run(repo, out)

        dataset = json.loads(Path(result.dataset_path).read_text())
        langs = {u.get("language") for u in dataset["units"]}
        assert "javascript" in langs, (
            "every javascript unit was dropped — cross-language seeds defeated "
            "the empty-seed blackout guard"
        )

    def test_units_are_never_lost_by_the_partition(self, repo, tmp_path, fake_parsers,
                                                   stub_llm_reachability, probe_loop):
        out = tmp_path / "out"
        result = run(repo, out)
        dataset = json.loads(Path(result.dataset_path).read_text())
        assert len(dataset["units"]) >= 2, "partition/recombine lost units"
