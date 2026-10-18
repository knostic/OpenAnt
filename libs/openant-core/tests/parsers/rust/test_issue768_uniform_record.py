"""#768: the rust reachability_filter record exists and reaches the dataset.

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
_TP = _CORE / "parsers" / "rust" / "test_pipeline.py"

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
        "parsers.rust.test_pipeline"
    ).apply_reachability_filter(cg, str(repo_path))


_NO_ENTRY_CG = {
    "functions": {
        "src/lib.rs:add": {
            "name": "add", "unit_type": "function", "file_path": "src/lib.rs",
            "code": "pub fn add(a: i32, b: i32) -> i32 { a + b }"},
        "src/lib.rs:scale": {
            "name": "scale", "unit_type": "function", "file_path": "src/lib.rs",
            "code": "pub fn scale(a: i32) -> i32 { add(a, a) }"},
    },
    "call_graph": {"src/lib.rs:scale": ["src/lib.rs:add"]},
    "reverse_call_graph": {"src/lib.rs:add": ["src/lib.rs:scale"]},
    "statistics": {"total_edges": 1},
}

_MAIN_CG = {
    "functions": {
        "src/main.rs:main": {
            "name": "main", "unit_type": "function", "file_path": "src/main.rs",
            "code": "fn main() { helper(); }"},
        "src/main.rs:helper": {
            "name": "helper", "unit_type": "function", "file_path": "src/main.rs",
            "code": "fn helper() -> i32 { 1 }"},
        "src/main.rs:orphan": {
            "name": "orphan", "unit_type": "function", "file_path": "src/main.rs",
            "code": "fn orphan() -> i32 { 2 }"},
    },
    "call_graph": {"src/main.rs:main": ["src/main.rs:helper"]},
    "reverse_call_graph": {"src/main.rs:helper": ["src/main.rs:main"]},
    "statistics": {"total_edges": 1},
}


def test_keep_all_output_carries_the_record_with_warning_and_seed_classes():
    out = _apply(_NO_ENTRY_CG, "/tmp/repo")
    rec = out.get("_reachability_filter")
    assert rec is not None, (
        "the filter attached no record to its output — rust's keep-all state "
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


def test_synthetic_only_keep_all_names_the_cause_and_counts_units():
    """The rust net's OTHER arm (the real-entry-points check): a repo whose
    ONLY seeds are synthetic fuzz harnesses keeps all units, and the record
    names the synthetic cause (r1-F3) — with NO blackout advisory on the
    keep-all arm (core parity: the keep-all warning is the whole story) —
    and counts DATASET UNITS (r1-F1: the generator drops the synthetic
    harness, so the pre-fix functions-based count exceeded the dataset's
    total and the reporter read the excess as a false --limit subset).
    """
    # the REAL fuzz_target! macro form (the synthesis path — a plain fn
    # named target is no fuzz harness, it never synthesizes)
    repo = pathlib.Path(tempfile.mkdtemp())
    (repo / "fuzz").mkdir()
    (repo / "fuzz" / "h.rs").write_text(
        "fuzz_target!(|data: &[u8]| { lib::parse(data); });\n", encoding="utf-8")
    (repo / "src").mkdir()
    (repo / "src" / "lib.rs").write_text(
        "pub mod lib { pub fn parse(d: &[u8]) {} }\n", encoding="utf-8")
    out = pathlib.Path(tempfile.mkdtemp())
    from utilities.child_interp import child_interpreter_env
    r = subprocess.run(
        [sys.executable, str(_TP), str(repo), "--output", str(out),
         "--processing-level", "reachable", "--name", "issue-768-synthetic"],
        capture_output=True, text=True, timeout=240, cwd=str(_CORE),
        env=child_interpreter_env())
    assert r.returncode == 0, f"the real rust pipeline failed: {r.stderr[-400:]}"
    dataset = json.loads((out / "dataset.json").read_text(encoding="utf-8"))
    rec = dataset.get("metadata", {}).get("reachability_filter")
    assert rec is not None, (
        f"the dataset carries no record: metadata={dataset.get('metadata')}")
    # r1-F3: the warning NAMES the synthetic cause (the net's other arm)
    assert "Only synthetic fuzz-harness entry points detected" in rec.get("warning", ""), (
        f"the synthetic-only keep-all warning does not name the cause: {rec!r}")
    assert "kept all units unfiltered" in rec.get("warning", ""), rec
    # r1-F3 (core parity): NO advisory on the keep-all arm
    assert "blackout_advisory" not in rec, (
        f"the keep-all arm stamped a blackout advisory (core's keep-all "
        f"branch never does — the keep-all warning is the whole story): {rec!r}")
    # r1-F1: the record counts DATASET UNITS — the synthetic harness is
    # dropped by the generator, so the count equals total_units (the
    # pre-fix functions-based count would EXCEED it: a false subset)
    assert rec["original_units"] == dataset["statistics"]["total_units"], (
        f"the record's original_units ({rec['original_units']}) diverges "
        f"from the dataset's total_units "
        f"({dataset['statistics']['total_units']}) — the false-subset shape: {rec!r}")
    assert rec["reachable_units"] == dataset["statistics"]["total_units"], rec
    assert "structural_entry_points" in rec, rec
    # the ONE-shape oracle (the superset contract: the keep-all record
    # carries every builder key)
    from utilities.agentic_enhancer import reachability_filter_record
    assert set(rec) >= set(reachability_filter_record(
        _ShapeOracle(), 0, 0, 0,
        keep_all_why="Only synthetic fuzz-harness entry points detected")), (
        "the record's key set diverges from the shared builder's: %r" % sorted(rec))


def test_the_reporter_reads_the_keep_all_warning_off_the_real_dataset():
    """The consumer clause (the issue's falsifier): the REPORTER's reader —
    core/reporter._load_reachability_metadata, the function whose record the
    warning forwarding (:739) and the CLI envelope block read — lifts the
    keep-all record (warning included) off a REAL pipeline dataset. The
    EXECUTED pins downstream of this read: test_reporter_reachable_units
    (the warning forward drives the reporter) + test_issue323
    (the _reachability_envelope_block drives); THIS is the read end of the
    chain over the unified record.
    """
    from utilities.child_interp import child_interpreter_env
    repo = pathlib.Path(tempfile.mkdtemp())
    (repo / "src").mkdir()
    (repo / "src" / "lib.rs").write_text(
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n"
        "pub fn scale(a: i32) -> i32 { add(a, a) }\n", encoding="utf-8")
    out = pathlib.Path(tempfile.mkdtemp())
    r = subprocess.run(
        [sys.executable, str(_TP), str(repo), "--output", str(out),
         "--processing-level", "reachable", "--name", "issue-768-consumer"],
        capture_output=True, text=True, timeout=240, cwd=str(_CORE),
        env=child_interpreter_env())
    assert r.returncode == 0, f"the real rust pipeline failed: {r.stderr[-400:]}"
    dataset = json.loads((out / "dataset.json").read_text(encoding="utf-8"))
    rec = dataset.get("metadata", {}).get("reachability_filter")
    assert rec is not None and "kept all units unfiltered" in rec.get("warning", ""), rec
    # the CONSUMER's read: the reporter's reader over the same scan_dir
    from core.reporter import _load_reachability_metadata
    rec2 = _load_reachability_metadata(str(out))
    assert rec2 == rec, (
        f"the reporter's reader diverges from the dataset's record: "
        f"{rec2!r} vs {rec!r}")
    assert "kept all units unfiltered" in rec2.get("warning", ""), (
        "the keep-all warning does not reach the reporter's read — the "
        f"consumer surface: {rec2!r}")
    # the ONE-shape oracle on the consumer's read too (the builder is the
    # shape the consumer must see — the same key set the pipeline wrote)
    from utilities.agentic_enhancer import reachability_filter_record
    assert set(rec2) >= set(reachability_filter_record(
        _ShapeOracle(), 0, 0, 0, keep_all_why="No entry points detected")), (
        "the consumer's record diverges from the shared builder's: %r" % sorted(rec2))


def test_the_record_reaches_the_dataset_through_the_real_pipeline():
    """The end-to-end carry: the REAL subprocess (the argv contract core's
    _parse_via_subprocess invokes) over a no-entry-point repo — the dataset
    on disk must carry the record."""
    repo = pathlib.Path(tempfile.mkdtemp())
    (repo / "src").mkdir()
    (repo / "src" / "lib.rs").write_text(
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n"
        "pub fn scale(a: i32) -> i32 { add(a, a) }\n", encoding="utf-8")
    out = pathlib.Path(tempfile.mkdtemp())
    # The REAL child env (the one core/parser_adapter's subprocess contract
    # uses: the core root prepended to PYTHONPATH — the same contract the
    # registry invokes this pipeline with).
    from utilities.child_interp import child_interpreter_env
    r = subprocess.run(
        [sys.executable, str(_TP), str(repo), "--output", str(out),
         "--processing-level", "reachable", "--name", "issue-768"],
        capture_output=True, text=True, timeout=240, cwd=str(_CORE),
        env=child_interpreter_env())
    assert r.returncode == 0, (
        f"the real rust pipeline failed: {r.stderr[-400:]}")
    dataset = json.loads((out / "dataset.json").read_text(encoding="utf-8"))
    rec = dataset.get("metadata", {}).get("reachability_filter")
    assert rec is not None, (
        "the DATASET carries no reachability_filter record — the filter's "
        "record never reached the reader surface (the #768 rust shape: "
        f"stderr-only): metadata={dataset.get('metadata')}")
    assert "kept all units unfiltered" in rec.get("warning", ""), rec
    assert "structural_entry_points" in rec, rec
    from utilities.agentic_enhancer import reachability_filter_record
    assert set(rec) == set(reachability_filter_record(
        _ShapeOracle(), 0, 0, 0, keep_all_why="No entry points detected")), (
        "the dataset record's key set diverges from the shared builder's: %r" % sorted(rec))
