"""#768: the go reachability_filter record carries the ONE shape.

The record diverged per producing path before #768: the core Python path
wrote ``warning`` plus the seed-class counts (the #520 fold), while the five
per-language pipelines (javascript/c/go/php/ruby) wrote a bare five-field
record with NEITHER — so a keep-all report from this pipeline read as a
completed 0.0%-reduction scan with nothing naming what happened, and the
report consumer (core/reporter.py forwards exactly ``warning`` and
``blackout_advisory``) had nothing to lift.

This drives the REAL pipeline's ``apply_reachability_filter`` (real
EntryPointDetector + ReachabilityAnalyzer) over the same fixture shape the
N4 keep-all test uses, and asserts BOTH branches of the record carry the
core-shaped fields: the seed-class counts always, the keep-all warning on
the keep-all branch.
"""
import importlib.util
import json
import pathlib
import sys
import tempfile

_CORE = pathlib.Path(__file__).resolve().parents[3]
_TP = _CORE / "parsers" / "go" / "test_pipeline.py"


class _ShapeOracle:
    """The builder-oracle stub: the record's key contract is the BUILDER's
    (the ONE shape — #768); any detector with the same (empty) details
    produces the same keys, so the pipeline's record is compared against
    the builder's output directly."""
    entry_point_details = {}


def _load_pipeline():
    for p in (str(_TP.parent), str(_CORE)):
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location("isolated_go_issue768", _TP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Two ordinary library functions: no `main`, no route/CLI/decorator marker →
# EntryPointDetector must return zero seeds (the keep-all precondition).
_FUNCTIONS = {
    "lib.go:add": {"name": "add", "unit_type": "function", "file_path": "lib.go", "code": "func add(a, b int) int { return a + b }"},
    "lib.go:scale": {"name": "scale", "unit_type": "function", "file_path": "lib.go", "code": "func scale(a int) int { return add(a, a) }"},
}
_UNITS = [
    {"id": "lib.go:add",
      "metadata": {"direct_calls": [], "direct_callers": ["lib.go:scale"]}},
    {"id": "lib.go:scale",
      "metadata": {"direct_calls": ["lib.go:add"], "direct_callers": []}},
]

# A real structural entry point: a file-scoped `main` (the detector's
# name rule) plus an unreached library function → the filtered branch.
_MAIN_FUNCTIONS = {
    "app.go:main": {
        "name": "main", "unit_type": "function", "file_path": "app.go",
        "code": "func main() { helper() }"},
    "app.go:helper": {
        "name": "helper", "unit_type": "function", "file_path": "app.go",
        "code": "func helper() int { return 1 }"},
}


def _make_pipeline(functions=None, units=None):
    mod = _load_pipeline()
    tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
    (tmp / "analyzer.json").write_text(json.dumps({"functions": functions or _FUNCTIONS}))
    (tmp / "dataset.json").write_text(json.dumps({"units": [dict(u) for u in units or _UNITS]}))
    p = mod.GoPipelineTest(repo_path=str(tmp))
    p.analyzer_output_file = str(tmp / "analyzer.json")
    p.dataset_file = str(tmp / "dataset.json")
    return p


def test_keep_all_record_carries_the_warning_and_seed_classes():
    p = _make_pipeline()
    assert p.apply_reachability_filter() is True
    from utilities.agentic_enhancer import reachability_filter_record
    rec = json.loads(pathlib.Path(p.dataset_file).read_text())[
        "metadata"]["reachability_filter"]
    assert rec.get("structural_entry_points") == 0, rec
    assert rec.get("incidental_entry_points") == 0, rec
    assert "kept all units unfiltered" in rec.get("warning", ""), (
        "the keep-all record carries no warning — the bare five-field shape "
        "read as a completed scan with nothing naming what happened: %r" % rec)
    assert rec["reduction_percentage"] == 0, rec
    # the ONE-shape contract: the record IS the builder's shape (the oracle)
    assert set(rec) == set(reachability_filter_record(
        _ShapeOracle(), 2, 0, 2, keep_all_why="No entry points detected")), (
        "the record's key set diverges from the shared builder's: %r" % sorted(rec))


def test_filtered_record_carries_the_seed_classes_and_no_warning():
    units = [
        {"id": "app.go:main",
          "metadata": {"direct_calls": [], "direct_callers": []}},
        {"id": "app.go:helper",
          "metadata": {"direct_calls": [], "direct_callers": []}},
    ]
    p = _make_pipeline(functions=_MAIN_FUNCTIONS, units=units)
    p.apply_reachability_filter()
    from utilities.agentic_enhancer import reachability_filter_record
    rec = json.loads(pathlib.Path(p.dataset_file).read_text())[
        "metadata"]["reachability_filter"]
    assert rec["entry_points"] == 1, rec
    # the count itself: the main IS reachable (its id matches the unit ids —
    # a bare-id fixture blacked out and the >= oracle passed on the
    # advisory's strength: the count is the load-bearing half)
    assert rec["reachable_units"] == 1, (
        f"the filtered record's count is wrong: %r" % rec)
    assert rec.get("structural_entry_points") == 1, (
        "the filtered record carries no seed-class counts: %r" % rec)
    assert "warning" not in rec, (
        "the filtered branch stamped a keep-all warning: %r" % rec)
    # the ONE-shape contract: the builder's keys are ALL present (the
    # caller may stamp its own extras — blackout_advisory here — but the
    # shared shape's keys may never be missing)
    assert set(rec) >= set(reachability_filter_record(
        _ShapeOracle(), 0, 0, 0)), (
        "the record's key set diverges from the shared builder's: %r" % sorted(rec))
