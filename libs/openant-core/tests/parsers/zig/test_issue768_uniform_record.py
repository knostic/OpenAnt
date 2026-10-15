"""#768: the zig reachability_filter record exists and reaches the dataset.

Rust wrote NO ``metadata.reachability_filter`` record at all before #768 —
the filter's keep-all net and the blackout advisory were stderr-only, and
the #520 seed-class fold rode an inert ``_seed_class_counts`` field with no
downstream reader. The dataset (the reader surface core/reporter.py lifts
into reports) never carried the record.

This drives the REAL ``apply_reachability_filter`` (the pure-function
contract) for both record branches, and the REAL pipeline subprocess (the
argv contract core/parser_adapter invokes) end-to-end over a no-entry-point
repo to prove the record reaches the DATASET.
"""
import importlib
import json
import pathlib
import subprocess
import sys
import tempfile

_CORE = pathlib.Path(__file__).resolve().parents[3]
_TP = _CORE / "parsers" / "zig" / "test_pipeline.py"

if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))


class _ShapeOracle:
    """The builder-oracle stub: the record's key contract is the BUILDER's
    (the ONE shape — #768); any detector with the same (empty) details
    produces the same keys, so the pipeline's record is compared against
    the builder's output directly."""
    entry_point_details = {}


def _apply(cg, repo_path):
    return importlib.import_module(
        "parsers.zig.test_pipeline"
    ).apply_reachability_filter(cg, str(repo_path))


_NO_ENTRY_CG = {
    "functions": {
        "src/lib.zig:add": {
            "name": "add", "unit_type": "function", "file_path": "src/lib.zig",
            "code": "pub fn add(a: i32, b: i32) -> i32 { a + b }"},
        "src/lib.zig:scale": {
            "name": "scale", "unit_type": "function", "file_path": "src/lib.zig",
            "code": "pub fn scale(a: i32) -> i32 { add(a, a) }"},
    },
    "call_graph": {"src/lib.zig:scale": ["src/lib.zig:add"]},
    "reverse_call_graph": {"src/lib.zig:add": ["src/lib.zig:scale"]},
    "statistics": {"total_edges": 1},
}

_MAIN_CG = {
    "functions": {
        "src/main.zig:main": {
            "name": "main", "unit_type": "function", "file_path": "src/main.zig",
            "code": "fn main() { helper(); }"},
        "src/main.zig:helper": {
            "name": "helper", "unit_type": "function", "file_path": "src/main.zig",
            "code": "fn helper() -> i32 { 1 }"},
        "src/main.zig:orphan": {
            "name": "orphan", "unit_type": "function", "file_path": "src/main.zig",
            "code": "fn orphan() -> i32 { 2 }"},
    },
    "call_graph": {"src/main.zig:main": ["src/main.zig:helper"]},
    "reverse_call_graph": {"src/main.zig:helper": ["src/main.zig:main"]},
    "statistics": {"total_edges": 1},
}


def test_keep_all_output_carries_the_record_with_warning_and_seed_classes():
    out = _apply(_NO_ENTRY_CG, "/tmp/repo")
    rec = out.get("_reachability_filter")
    assert rec is not None, (
        "the filter attached no record to its output — zig's keep-all state "
        "had no reader-reaching record at all")
    assert rec.get("structural_entry_points") == 0, rec
    assert rec.get("incidental_entry_points") == 0, rec
    assert "kept all units unfiltered" in rec.get("warning", ""), (
        "the keep-all record carries no warning: %r" % rec)
    assert rec["reduction_percentage"] == 0, rec
    assert rec["reachable_units"] == 2, rec
    from utilities.agentic_enhancer import reachability_filter_record
    assert set(rec) == set(reachability_filter_record(
        _ShapeOracle(), 2, 0, 2, keep_all_why="No entry points detected")), (
        "the record's key set diverges from the shared builder's: %r" % sorted(rec))


def test_filtered_output_carries_the_record_with_seed_classes_and_no_warning():
    out = _apply(_MAIN_CG, "/tmp/repo")
    rec = out.get("_reachability_filter")
    assert rec is not None, rec
    assert rec["entry_points"] == 1, rec
    assert rec.get("structural_entry_points") == 1, (
        "the filtered record carries no seed-class counts: %r" % rec)
    assert "warning" not in rec, rec
    # the ONE-shape contract: the builder's keys are ALL present (the
    # caller may stamp its own extras — blackout_advisory here — but the
    # shared shape's keys may never be missing)
    from utilities.agentic_enhancer import reachability_filter_record
    assert set(rec) >= set(reachability_filter_record(
        _ShapeOracle(), 0, 0, 0)), (
        "the record's key set diverges from the shared builder's: %r" % sorted(rec))


def test_the_record_reaches_the_dataset_through_the_real_pipeline():
    """The end-to-end carry: the REAL subprocess (the argv contract core's
    _parse_via_subprocess invokes) over a no-entry-point repo — the dataset
    on disk must carry the record."""
    repo = pathlib.Path(tempfile.mkdtemp())
    (repo / "src").mkdir()
    (repo / "src" / "lib.zig").write_text(
        "pub fn add(a: i32, b: i32) i32 { return a + b; }\n"
        "pub fn scale(a: i32) i32 { return add(a, a); }\n", encoding="utf-8")
    out = pathlib.Path(tempfile.mkdtemp())
    # The REAL child env (the one core/parser_adapter's subprocess contract
    # uses: the core root prepended to PYTHONPATH — the zig script's own
    # bootstrap insert comes after its module-top utilities import).
    from utilities.child_interp import child_interpreter_env
    r = subprocess.run(
        [sys.executable, str(_TP), str(repo), "--output", str(out),
         "--processing-level", "reachable", "--name", "issue-768"],
        capture_output=True, text=True, timeout=240, cwd=str(_CORE),
        env=child_interpreter_env())
    assert r.returncode == 0, (
        f"the real zig pipeline failed: {r.stderr[-400:]}")
    dataset = json.loads((out / "dataset.json").read_text(encoding="utf-8"))
    rec = dataset.get("metadata", {}).get("reachability_filter")
    assert rec is not None, (
        "the DATASET carries no reachability_filter record — the filter's "
        "record never reached the reader surface (the #768 zig shape: "
        f"stderr-only): metadata={dataset.get('metadata')}")
    assert "kept all units unfiltered" in rec.get("warning", ""), rec
    assert "structural_entry_points" in rec, rec
    from utilities.agentic_enhancer import reachability_filter_record
    assert set(rec) == set(reachability_filter_record(
        _ShapeOracle(), 0, 0, 0, keep_all_why="No entry points detected")), (
        "the dataset record's key set diverges from the shared builder's: %r" % sorted(rec))
