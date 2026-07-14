"""Bug (N4): the Ruby reachability filter silently blacks out a no-entry-point
dataset.

`apply_reachability_filter` seeds the BFS from EntryPointDetector's result. A
library / no-entry-point target (no `main`, no route/CLI/decorator marker) yields
ZERO entry points, so `ReachabilityAnalyzer.get_all_reachable()` returns the
empty set, every unit is pruned, and the scan reports a clean 0-unit success —
a silent blackout (the dominant failure mode for library targets) at the default
`--processing-level reachable`.

The fix mirrors core/parser_adapter.py: when there are no entry points but there
ARE units, degrade to keep-all + a stderr warning instead of an empty dataset.

(Ruby) This drives the REAL `apply_reachability_filter` (real EntryPointDetector + real
ReachabilityAnalyzer) over a two-function library fixture with no entry marker.
RED→GREEN verified against master's unfixed parser file.

test_pipeline.py shares its basename across all six parsers, so it is loaded
under a unique module name via importlib (mirrors test_zig_reachability_api.py).
"""
import importlib.util
import json
import pathlib
import sys
import tempfile

_CORE = pathlib.Path(__file__).resolve().parents[3]
_TP = _CORE / "parsers" / "ruby" / "test_pipeline.py"


def _load_pipeline():
    for p in (str(_TP.parent), str(_CORE)):
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location("isolated_ruby_test_pipeline", _TP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Two ordinary library functions: no `main`, no route/CLI/decorator marker, no
# user-input pattern in the code → EntryPointDetector must return zero seeds.
_FUNCTIONS = {
    "lib.rb:add": {"name": "add", "unit_type": "function", "file_path": "lib.rb", "code": "return a + b"},
    "lib.rb:scale": {"name": "scale", "unit_type": "function", "file_path": "lib.rb",
                    "code": "return add(a, a)"},
}
_UNITS = [
    {"id": "lib.rb:add",
     "metadata": {"direct_calls": [], "direct_callers": ["lib.rb:scale"]}},
    {"id": "lib.rb:scale",
     "metadata": {"direct_calls": ["lib.rb:add"], "direct_callers": []}},
]


def _make_pipeline():
    mod = _load_pipeline()
    tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
    (tmp / "analyzer.json").write_text(json.dumps({"functions": _FUNCTIONS}))
    (tmp / "dataset.json").write_text(json.dumps({"units": [dict(u) for u in _UNITS]}))
    p = mod.RubyPipelineTest(repo_path=str(tmp))
    p.analyzer_output_file = str(tmp / "analyzer.json")
    p.dataset_file = str(tmp / "dataset.json")
    return p


def test_no_entry_points_is_the_precondition():
    # Guard the guard: if this fixture ever grows an accidental entry point the
    # keep-all path would not be what's under test, so assert the precondition.
    p = _make_pipeline()
    assert p.apply_reachability_filter() is True
    assert p.entry_points == set(), (
        f"fixture unexpectedly produced entry points: {p.entry_points}"
    )


def test_empty_seed_keeps_all_units():
    p = _make_pipeline()
    p.apply_reachability_filter()
    assert p.reachable_units == {"lib.rb:add", "lib.rb:scale"}, (
        "empty-seed safety-net must keep all units; got "
        f"{p.reachable_units} (blackout = the N4 bug)"
    )


def test_written_dataset_retains_every_unit_at_zero_reduction():
    p = _make_pipeline()
    p.apply_reachability_filter()
    dataset = json.loads(pathlib.Path(p.dataset_file).read_text())
    ids = {u["id"] for u in dataset["units"]}
    assert ids == {"lib.rb:add", "lib.rb:scale"}, "units were dropped (blackout)"
    assert all(u.get("reachable") for u in dataset["units"])
    assert dataset["metadata"]["reachability_filter"]["reduction_percentage"] == 0.0
