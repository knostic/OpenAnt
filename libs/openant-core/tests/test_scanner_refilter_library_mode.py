"""S3: ``--library-mode`` must survive the post-LLM per-language re-filter.

``scan_repository`` forwards ``library_mode`` to the initial parse
(scanner.py:269/306) but the post-LLM re-filter call to
``apply_reachability_filter`` (scanner.py:542) omitted it. Under
``--llm-reachability`` the initial parse runs at level ``all`` (scanner.py:233),
so that re-filter is the ONLY structural filter — meaning
``--library-mode --llm-reachability --level reachable`` silently dropped the
library public-API seeds.

This asserts the kwarg reaches that call. Fully offline — the LLM stage is
stubbed, so there is no API cost.
"""

import json
from pathlib import Path

import pytest

import core.scanner as scanner_mod


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    import utilities.llm as llm_mod
    monkeypatch.setattr(llm_mod, "probe_registry_or_raise", lambda *a, **k: None)


@pytest.fixture
def repo(tmp_path):
    src = tmp_path / "repo"
    src.mkdir(parents=True)
    (src / "app.py").write_text("def handler():\n    pass\n")
    return src


@pytest.fixture
def fake_parsers(monkeypatch):
    """A python parser that emits a real call_graph.json (one entry point)."""
    def fake_parser_for(language):
        def _parse(repo_path, output_dir, processing_level, skip_tests=True,
                   name=None, library_mode=False):
            ids = ["app.py:handler", "app.py:helper"]
            entries = ["app.py:handler"]
            d = Path(output_dir)
            d.mkdir(parents=True, exist_ok=True)
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
    monkeypatch.setattr(lr, "apply_signals", lambda dataset, signals: {
        "signals_applied": 0, "entry_points_promoted": 0, "units_touched": 0})
    monkeypatch.setattr(lr, "signals_to_json", lambda s: [])


def test_refilter_forwards_library_mode(repo, tmp_path, fake_parsers,
                                        stub_llm_reachability, monkeypatch):
    """The post-LLM re-filter (scanner.py:542) must pass library_mode through.

    RED before the fix: the call omits ``library_mode=`` so the spy records
    ``None``. GREEN after: it records ``True``.
    """
    import core.parser_adapter as pa
    captured = {}
    real = pa.apply_reachability_filter

    def spy(dataset, lang_dir, processing_level, **kwargs):
        captured["library_mode"] = kwargs.get("library_mode")
        return real(dataset, lang_dir, processing_level, **kwargs)

    monkeypatch.setattr(pa, "apply_reachability_filter", spy)

    scanner_mod.scan_repository(
        repo_path=str(repo), output_dir=str(tmp_path / "out"),
        languages=["python"], processing_level="reachable",
        llm_reachability=True, library_mode=True,
        generate_context=False, generate_report=False,
        enhance=False, verify=False,
    )

    assert captured.get("library_mode") is True, (
        "scanner.py post-LLM re-filter dropped library_mode — "
        "`--library-mode --llm-reachability` silently ignores the flag"
    )
