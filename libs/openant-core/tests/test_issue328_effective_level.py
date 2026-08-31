"""#328: a Python-path level fallback is recorded in the artifact, not stderr-only.

On a Python-language scan, `--processing-level codeql` / `exploitable` fall back to
reachability-only filtering with a WARNING PRINTED TO STDERR — and nothing else. The emitted
`pipeline_output.json` then claims `"processing_level": "exploitable"` (the level REQUESTED,
not the one that ran) with an empty `reachability_warnings` list. Fail-safe in the security
direction (the skipped filters are narrowing — MORE units analysed, none dropped), so the
defect is truth-in-labelling and cost, not a missed vulnerability.

Executed at b5019628 (the issue's level_repro.py): the three levels return identical units,
and the probe of the emitted JSON finds no trace of the fallback — `reachability_warnings`
exists, is the right place, and is empty.

The fix: the fallback warning reaches the result structure the way the asymmetry warning
already does (parser_adapter :578-579), in its OWN key — the reserved ``warning`` slot may
already hold the blackout text, and silently dropping the fallback note there would be the
same silent drop this fixes — and the record carries the level that actually ran, so the
artifact answers "what filtering was applied?". `processing_level` stays the requested level
(no consumer break); `effective_processing_level` is forwarded present-only.
"""
import importlib.util
import json
import pathlib
import sys

_CORE = pathlib.Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))


def _load_parser_adapter():
    spec = importlib.util.spec_from_file_location(
        "isolated_parser_adapter_328", _CORE / "core" / "parser_adapter.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path, obj):
    path.write_text(json.dumps(obj))


def _make_fixture(tmp_path):
    """One entry point (main), one called function, one orphan — 3 units.

    The kept set is 2 of 3: the filter demonstrably ran and the level agreement
    below is informative (the issue's NON-VACUOUS control — a fixture that pruned
    everything would make identical outputs meaningless).
    """
    call_graph = {
        "functions": {
            "m.py:main": {"name": "main", "unit_type": "function", "code": "run()"},
            "m.py:run": {"name": "run", "unit_type": "function", "code": "pass"},
            "m.py:orphan": {"name": "orphan", "unit_type": "function", "code": "pass"},
        },
        "call_graph": {"m.py:main": ["m.py:run"]},
        "reverse_call_graph": {"m.py:run": ["m.py:main"]},
    }
    _write_json(tmp_path / "call_graph.json", call_graph)
    return {
        "units": [
            {"id": "m.py:main"},
            {"id": "m.py:run"},
            {"id": "m.py:orphan"},
        ],
        "metadata": {},
    }


def _run_filter(tmp_path, level):
    pa = _load_parser_adapter()
    return pa.apply_reachability_filter(_make_fixture(tmp_path), str(tmp_path), level)


def test_fallback_warning_reaches_filter_metadata(tmp_path):
    """level=exploitable: the fallback note is IN the rf record, not stderr-only."""
    out = _run_filter(tmp_path, "exploitable")
    rf = out["metadata"]["reachability_filter"]
    fb = rf.get("level_fallback_warning")
    assert isinstance(fb, str) and fb, (
        "the Python-path fallback must be recorded in the filter metadata "
        "(it was print-to-stderr only; pipeline_output.json showed no trace)"
    )
    assert "reachable" in fb.lower()


def test_requested_and_effective_levels_recorded(tmp_path):
    """codeql: the record answers 'what filtering was actually applied?'."""
    out = _run_filter(tmp_path, "codeql")
    rf = out["metadata"]["reachability_filter"]
    assert rf.get("requested_processing_level") == "codeql"
    assert rf.get("effective_processing_level") == "reachable"


def test_plain_reachable_records_no_fallback(tmp_path):
    """level=reachable: no fallback keys; effective still says what ran."""
    out = _run_filter(tmp_path, "reachable")
    rf = out["metadata"]["reachability_filter"]
    assert not rf.get("level_fallback_warning")
    assert not rf.get("requested_processing_level")
    assert rf.get("effective_processing_level") == "reachable"


def test_three_levels_identical_units_nonvacuous(tmp_path):
    """The issue's part 1 (the control): the fallback is fail-safe — identical
    kept units at all three levels, and non-vacuous (0 < kept < original)."""
    kept = {}
    for level in ("reachable", "codeql", "exploitable"):
        out = _run_filter(tmp_path, level)
        kept[level] = sorted(u["id"] for u in out["units"])
    assert 0 < len(kept["reachable"]) < 3, "the fixture must prune some, keep some"
    assert kept["codeql"] == kept["reachable"]
    assert kept["exploitable"] == kept["reachable"]


def test_reporter_artifact_carries_the_fallback(tmp_path):
    """The issue's part 2: pipeline_output.json no longer claims the requested
    level silently — the warning reaches pipeline_stats.reachability_warnings
    and the effective level is forwarded; the requested level is preserved."""
    from core.reporter import build_pipeline_output
    from utilities.file_io import write_json

    rf = {
        "original_units": 3,
        "reachable_units": 2,
        "reduction_percentage": 33.3,
        "requested_processing_level": "exploitable",
        "effective_processing_level": "reachable",
        "level_fallback_warning": (
            "Exploitable filter (CodeQL + LLM classification) not yet wired "
            "into the Python parser path. Returning reachable units only."
        ),
    }
    results = {
        "dataset": "test",
        "code_by_route": {},
        "metrics": {"total": 2, "errors": 0},
        "confirmed_findings": [],
    }
    results_path = tmp_path / "results.json"
    write_json(results_path, results)
    write_json(tmp_path / "dataset.json", {"units": [], "metadata": {"reachability_filter": rf}})
    out_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(results_path), output_path=str(out_path),
        language="python", repo_name="t/r", processing_level="exploitable",
    )
    stats = json.loads(out_path.read_text())["pipeline_stats"]
    warnings = stats.get("reachability_warnings") or []
    assert any("not yet wired" in w for w in warnings), (
        "the fallback warning must reach pipeline_stats.reachability_warnings "
        "(the probe at b5019628 found it empty)"
    )
    assert stats.get("effective_processing_level") == "reachable"
    assert stats.get("processing_level") == "exploitable", (
        "the requested level is preserved (keep+add; no consumer break)"
    )


def test_reporter_forward_is_present_only(tmp_path):
    """A record WITHOUT the fallback keys (non-Python path / plain reachable)
    emits no effective field — the forward never fabricates."""
    from core.reporter import build_pipeline_output
    from utilities.file_io import write_json

    results = {
        "dataset": "test", "code_by_route": {},
        "metrics": {"total": 2, "errors": 0}, "confirmed_findings": [],
    }
    results_path = tmp_path / "results.json"
    write_json(results_path, results)
    write_json(tmp_path / "dataset.json", {
        "units": [],
        "metadata": {"reachability_filter": {"original_units": 2, "reachable_units": 2,
                                              "reduction_percentage": 0}},
    })
    out_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(results_path), output_path=str(out_path),
        language="javascript", repo_name="t/r", processing_level="codeql",
    )
    stats = json.loads(out_path.read_text())["pipeline_stats"]
    assert "effective_processing_level" not in stats
    assert not any("not yet wired" in w for w in (stats.get("reachability_warnings") or []))
