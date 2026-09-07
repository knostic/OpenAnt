"""#516: a post-persist failure leaves units_count describing the DISK.

The #268 handler restored the PRE-stage units_count unconditionally —
correct when the dataset never reached disk, wrong when write_json had
already landed the re-filtered dataset (it is ATOMIC: after it returns,
the disk IS the post-filter state and downstream consumes the DISK, not
the local). A failure in the post-write bookkeeping window (the ctx
summary build) left the count describing a dataset that no longer
exists. The fix: gate the restore on the persist; record which state
won in the step report.
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
    (src / "web").mkdir(parents=True)
    (src / "app.py").write_text("def handler():\n    pass\n")
    (src / "web" / "app.js").write_text("function route() {}\n")
    return src


@pytest.fixture
def fake_parsers(monkeypatch):
    """python: 2 units, 1 entry point (post-filter keeps 1); js: 2 units, no
    entry point (empty-seed net keeps both). Post-filter total = 3."""
    graphs = {
        "python": (["app.py:handler", "app.py:helper"], ["app.py:handler"]),
        "javascript": (["web/app.js:route", "web/app.js:util"], []),
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
def post_write_failure(monkeypatch):
    """The #516 window: the re-filtered dataset PERSISTS, then the post-write
    bookkeeping raises — apply_signals returns a summary MISSING the
    'signals_applied' key the ctx summary build indexes (a real KeyError
    shape, injected genuinely AFTER the write by construction)."""
    import core.llm_reachability as lr

    monkeypatch.setattr(lr, "analyze_reachability", lambda *a, **k: [])

    def fake_apply(dataset, signals):
        for u in dataset.get("units", []):
            if u.get("id") == "app.py:handler":
                u["is_entry_point"] = True
        # deliberately missing "signals_applied" -> KeyError at ctx.summary
        return {"entry_points_promoted": 1, "units_touched": 1}

    monkeypatch.setattr(lr, "apply_signals", fake_apply)
    monkeypatch.setattr(lr, "signals_to_json", lambda s: [])


def run(repo, out):
    return scanner_mod.scan_repository(
        repo_path=str(repo), output_dir=str(out),
        languages=["python", "javascript"],
        processing_level="reachable",
        llm_reachability=True,
        generate_context=False, generate_report=False,
        enhance=False, verify=False,
    )


def test_post_persist_failure_leaves_count_at_disk_truth(
        repo, tmp_path, fake_parsers, post_write_failure):
    """THE #516 case: the dataset on disk is the POST-filter one (3 units);
    a bookkeeping failure after the persist must leave units_count == 3.
    Pre-fix: the unconditional restore reported 4 — a count for a dataset
    that no longer exists."""
    out = tmp_path / "out"
    result = run(repo, out)

    disk_units = len(json.loads(Path(result.dataset_path).read_text())["units"])
    assert disk_units == 3, f"fixture drift: expected 3 disk units, got {disk_units}"
    assert result.units_count == disk_units, (
        f"units_count={result.units_count} describes a dataset that is not "
        f"on disk (disk={disk_units}) — the #516 post-persist divergence")


def test_step_report_records_which_state_won(
        repo, tmp_path, fake_parsers, post_write_failure):
    """The skip must not read as 'no effects' while downstream consumes the
    re-filtered dataset: the step report carries dataset_persisted."""
    out = tmp_path / "out"
    run(repo, out)

    step = json.loads((out / "llm-reachability.report.json").read_text())
    assert step.get("summary", {}).get("dataset_persisted") is True, (
        "the skipped step report does not record that the dataset persisted "
        "— it reads as 'no effects' while downstream consumes the "
        "re-filtered dataset")
    assert step.get("status") == "skipped"
