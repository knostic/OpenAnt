"""B3: per-unit prune telemetry on the Swift *production* filter path.

The default `reachable` Swift path shells out to `parsers/swift/test_pipeline.py`,
whose local reachability filter historically emitted NO prune telemetry / sidecar /
asymmetry invariant (unlike the instrumented core filter, which only ran on the
Python parse path and the `--llm-reachability` re-filter). This wires the Swift
filter to the SHARED core telemetry helper, so the same auditability holds on the
default Swift path — additively, with zero change to which units survive.

Mirrors tests/test_reachability_prune_telemetry.py, but drives the Swift filter.

Note on the invariant: the Swift call-graph builder writes forward+reverse edges in
lockstep (symmetric by construction), so a real Swift repo cannot produce a forward
asymmetry. The invariant is therefore a REGRESSION GUARD; to prove it fires *through*
the Swift path we hand-build an asymmetric call_graph_output (same technique the core
test uses). The load-bearing signal for real Swift repos is the orphan/dead_cluster
sidecar, exercised by the end-to-end test below.
"""
import importlib.util
import json
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_CORE = _HERE.parents[2]                                  # libs/openant-core
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_CORE))


def _load_pipeline():
    spec = importlib.util.spec_from_file_location(
        "swift_pipeline_iso_b3", _CORE / "parsers" / "swift" / "test_pipeline.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _rf(result):
    """The stashed reachability-filter telemetry the Swift filter attaches."""
    return result.get("_reachability_filter")


# --- unit-level: the filter emits telemetry + sidecar, over the PRE-FILTER graph ---

def test_swift_filter_prune_buckets_and_sidecar(tmp_path):
    # main -> A (kept). B orphan. D orphan, D -> C (C dead_cluster, caller D pruned).
    fns = {k: {} for k in ["a.swift:A", "a.swift:B", "b.swift:C", "b.swift:D"]}
    fns["a.swift:main"] = {"name": "main"}                 # structural entry point
    cg = {"a.swift:main": ["a.swift:A"], "b.swift:D": ["b.swift:C"]}
    rcg = {"a.swift:A": ["a.swift:main"], "b.swift:C": ["b.swift:D"]}
    cgo = {"functions": fns, "call_graph": cg, "reverse_call_graph": rcg}

    pipeline = _load_pipeline()
    result = pipeline.apply_reachability_filter(cgo, str(tmp_path), output_dir=str(tmp_path))
    m = _rf(result)
    assert m is not None, "Swift filter must stash reachability_filter telemetry"
    assert m["reachable_units"] == 2                       # main, A
    assert m["filtered_out"] == 3                          # B, C, D
    assert m["pruned_orphan_count"] == 2                   # B, D (no caller)
    assert m["pruned_in_dead_cluster_count"] == 1          # C (caller D pruned)
    assert m["pruned_forward_called_by_reachable_count"] == 0
    for k in ("original_units", "entry_points", "reachable_units", "filtered_out",
              "reduction_percentage"):
        assert k in m
    # sidecar written to output_dir with every pruned unit + classification
    side = json.loads((tmp_path / m["pruned_units_path"]).read_text())
    ids = {u["id"]: u for u in side["units"]}
    assert set(ids) == {"a.swift:B", "b.swift:C", "b.swift:D"}
    assert ids["a.swift:B"]["bucket"] == "orphan"
    assert ids["b.swift:C"]["bucket"] == "dead_cluster"


def test_swift_filter_forward_asymmetry_invariant_fires(tmp_path):
    # main -> A -> X forward, but reverse[X] MISSING A => X pruned yet reachable A
    # forward-calls it. The invariant must catch it THROUGH the Swift filter.
    fns = {"a:main": {"name": "main"}, "a:A": {}, "a:X": {}}
    cg = {"a:main": ["a:A"], "a:A": ["a:X"]}               # forward: A calls X
    rcg = {"a:A": ["a:main"]}                              # reverse: X's caller MISSING
    cgo = {"functions": fns, "call_graph": cg, "reverse_call_graph": rcg}

    pipeline = _load_pipeline()
    result = pipeline.apply_reachability_filter(cgo, str(tmp_path), output_dir=str(tmp_path))
    m = _rf(result)
    assert m["reachable_units"] == 2                       # main, A (X pruned)
    assert m["pruned_forward_called_by_reachable_count"] == 1   # X — the asymmetry victim
    assert "warning" in m and "asymmetr" in m["warning"].lower()


def test_swift_filter_uses_prefilter_graph_not_pruned(tmp_path):
    """Guard the single highest-risk line: the invariant MUST be computed over the
    UN-pruned graph. If the pruned graph were fed to the helper, asym would be a
    manufactured 0 (every edge to a pruned node already stripped)."""
    fns = {"a:main": {"name": "main"}, "a:A": {}, "a:X": {}}
    cg = {"a:main": ["a:A"], "a:A": ["a:X"]}
    rcg = {"a:A": ["a:main"]}
    cgo = {"functions": fns, "call_graph": cg, "reverse_call_graph": rcg}
    pipeline = _load_pipeline()
    result = pipeline.apply_reachability_filter(cgo, str(tmp_path), output_dir=str(tmp_path))
    # returned (filtered) graph has X stripped from A's out-edges ...
    assert "a:X" not in result["call_graph"].get("a:A", [])
    # ... yet the invariant still saw the asymmetry (proves pre-filter graph was used)
    assert _rf(result)["pruned_forward_called_by_reachable_count"] == 1


def test_swift_filter_empty_seed_reduced_schema(tmp_path):
    """No entry points -> N4 keep-all. Must mirror core's reduced schema: NO pruned_*
    keys and NO sidecar (pinned for core by test_reachability_prune_telemetry)."""
    fns = {"a:foo": {}, "a:bar": {}}                       # nothing entry-point-shaped
    cgo = {"functions": fns, "call_graph": {}, "reverse_call_graph": {}}
    pipeline = _load_pipeline()
    result = pipeline.apply_reachability_filter(cgo, str(tmp_path), output_dir=str(tmp_path))
    m = _rf(result)
    assert m["filtered_out"] == 0 and m["reachable_units"] == 2
    assert "pruned_orphan_count" not in m                  # reduced schema on keep-all
    assert not (tmp_path / "pruned_units.json").exists()   # no sidecar when nothing pruned
    # exact parity with core's empty-seed record: int 0, not float 0.0
    assert m["reduction_percentage"] == 0 and isinstance(m["reduction_percentage"], int)


def test_swift_filter_output_dir_optional_and_neutral(tmp_path):
    """output_dir is optional (existing 3-arg callers). Its presence must not change
    which functions survive (telemetry is additive-only)."""
    fns = {"a:main": {"name": "main"}, "a:A": {}, "a:orphan": {}}
    cg = {"a:main": ["a:A"]}
    rcg = {"a:A": ["a:main"]}
    cgo = lambda: {"functions": dict(fns), "call_graph": dict(cg),
                   "reverse_call_graph": dict(rcg)}
    pipeline = _load_pipeline()
    no_dir = pipeline.apply_reachability_filter(cgo(), str(tmp_path))            # 3-arg form
    with_dir = pipeline.apply_reachability_filter(cgo(), str(tmp_path), output_dir=str(tmp_path))
    # neutrality: which functions survive is identical with or without output_dir
    assert set(no_dir["functions"]) == set(with_dir["functions"]) == {"a:main", "a:A"}
    # output_dir=None => telemetry still computed, but no sidecar file
    assert "pruned_units_path" not in no_dir["_reachability_filter"]
    # output_dir given + a unit pruned => sidecar written
    assert with_dir["_reachability_filter"]["pruned_units_path"] == "pruned_units.json"
    assert (tmp_path / "pruned_units.json").exists()


# --- end-to-end: the real production main() writes the metadata + sidecar ---

def test_swift_pipeline_main_writes_reachability_metadata(tmp_path, monkeypatch):
    """Drive the actual production entry (main()) on a synthetic main.swift repo:
    dataset.json must carry metadata.reachability_filter and a pruned_units.json
    sidecar must sit beside it in output_dir."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.swift").write_text(
        "let x = reached()\n"
        "func reached() { deep() }\n"
        "func deep() {}\n"
        "func orphan() { orphanCallee() }\n"
        "func orphanCallee() {}\n"
    )
    out = tmp_path / "out"
    out.mkdir()
    pipeline = _load_pipeline()
    monkeypatch.setattr(sys, "argv", [
        "test_pipeline.py", str(repo), "--output", str(out),
        "--processing-level", "reachable",
    ])
    rc = pipeline.main()
    assert rc == 0
    dataset = json.loads((out / "dataset.json").read_text())
    rf = dataset.get("metadata", {}).get("reachability_filter")
    assert rf is not None, "main() must merge reachability_filter into dataset metadata"
    assert "pruned_forward_called_by_reachable_count" in rf
    # orphan / orphanCallee are unreachable from main -> pruned -> sidecar present
    assert (out / "pruned_units.json").exists()
