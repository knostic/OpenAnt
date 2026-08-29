"""Per-unit reachability-prune telemetry (Sol+Fable design).

The default `reachable` filter prunes units unreachable from entry points via a forward
BFS over call_graph edges. A known-incomplete graph => genuinely-reachable units silently
pruned. This telemetry makes every prune auditable (additive, all-language, no behavior
change) and surfaces the two hard signals:
  - pruned_forward_called_by_reachable: a reachable unit forward-calls a pruned one =>
    call_graph/reverse_call_graph ASYMMETRY (a reachable unit was silently pruned). Expect 0.
  - pruned_orphan: no (non-self) caller => the missing-edge ROOT candidate (first-class suspect).
  - pruned_in_dead_cluster: has a pruned caller => downstream shadow of a broken chain.
"""
import importlib.util
import json
import pathlib

_CORE = pathlib.Path(__file__).resolve().parents[1]          # libs/openant-core


def _load_mod():
    spec = importlib.util.spec_from_file_location("pa", _CORE / "core" / "parser_adapter.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_filter():
    return _load_mod().apply_reachability_filter


def test_null_call_graph_does_not_crash_telemetry(tmp_path):
    # A malformed call_graph.json can carry a present-but-null graph (get(...,{}) only
    # defends a MISSING key). The ADVISORY telemetry must not crash the filter step —
    # this guards BOTH callers of compute_prune_telemetry (the core one is unwrapped).
    (tmp_path / "call_graph.json").write_text(json.dumps(
        {"functions": {"f:main": {}, "f:dead": {}}, "call_graph": None, "reverse_call_graph": {}}))
    ds = _load_mod().apply_reachability_filter(
        {"units": [{"id": "f:main"}, {"id": "f:dead"}]}, str(tmp_path), "reachable",
        extra_entry_points={"f:main"})
    rf = ds["metadata"]["reachability_filter"]
    assert rf["filtered_out"] == 1                                  # f:dead pruned, no crash
    assert rf["pruned_forward_called_by_reachable_count"] == 0      # null graph => no false asym


def _load_helper():
    spec = importlib.util.spec_from_file_location(
        "pt", _CORE / "utilities" / "prune_telemetry.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.compute_prune_telemetry


def test_compute_prune_telemetry_tolerates_null_graphs():
    extra, warn, advisory = _load_helper()({"f:a"}, ["f:b"], None, None, None)
    assert extra == {"pruned_orphan_count": 1, "pruned_in_dead_cluster_count": 0,
                     "pruned_forward_called_by_reachable_count": 0, "pruned_by_file": {"f": 1}}
    assert warn is None


def _run(tmp_path, functions, call_graph, reverse_call_graph, unit_ids, entry):
    out = tmp_path
    (out / "call_graph.json").write_text(json.dumps({
        "functions": functions, "call_graph": call_graph,
        "reverse_call_graph": reverse_call_graph,
    }))
    dataset = {"units": [{"id": i} for i in unit_ids]}
    apply = _load_filter()
    ds = apply(dataset, str(out), "reachable", extra_entry_points={entry})
    return ds["metadata"]["reachability_filter"]


def test_prune_buckets_and_sidecar(tmp_path):
    # E -> A (kept). B orphan. D orphan, D -> C (C in a dead cluster with pruned caller D).
    fns = {k: {} for k in ["a.swift:E", "a.swift:A", "a.swift:B", "b.swift:C", "b.swift:D"]}
    cg = {"a.swift:E": ["a.swift:A"], "b.swift:D": ["b.swift:C"]}
    rcg = {"a.swift:A": ["a.swift:E"], "b.swift:C": ["b.swift:D"]}
    m = _run(tmp_path, fns, cg, rcg, list(fns), "a.swift:E")
    assert m["reachable_units"] == 2                       # E, A
    assert m["filtered_out"] == 3                          # B, C, D
    assert m["pruned_orphan_count"] == 2                   # B, D (no caller)
    assert m["pruned_in_dead_cluster_count"] == 1          # C (caller D is pruned)
    assert m["pruned_forward_called_by_reachable_count"] == 0   # invariant: symmetric graph
    # existing keys must be unchanged (additive only)
    for k in ("original_units", "entry_points", "reachable_units", "filtered_out", "reduction_percentage"):
        assert k in m
    # sidecar written with EVERY pruned unit + classification
    side = json.loads((tmp_path / m["pruned_units_path"]).read_text())
    ids = {u["id"]: u for u in side["units"]}
    assert set(ids) == {"a.swift:B", "b.swift:C", "b.swift:D"}
    assert ids["a.swift:B"]["bucket"] == "orphan"
    assert ids["b.swift:C"]["bucket"] == "dead_cluster"
    assert "b.swift" in m["pruned_by_file"]


def test_forward_asymmetry_invariant_fires(tmp_path):
    # E -> A -> X in the FORWARD graph, but reverse_call_graph[X] is MISSING A (asymmetry).
    # BFS uses reverse => X pruned, yet reachable A forward-calls it => a silently-pruned
    # reachable unit. The invariant must catch it (count > 0 + warning).
    fns = {k: {} for k in ["a:E", "a:A", "a:X"]}
    cg = {"a:E": ["a:A"], "a:A": ["a:X"]}          # forward: A calls X
    rcg = {"a:A": ["a:E"]}                          # reverse: X's caller A is MISSING
    m = _run(tmp_path, fns, cg, rcg, list(fns), "a:E")
    assert m["reachable_units"] == 2               # E, A only (X pruned)
    assert m["pruned_forward_called_by_reachable_count"] == 1   # X — the asymmetry victim
    assert "warning" in m and "asymmetr" in m["warning"].lower()


def test_empty_entrypoints_passthrough_schema_unchanged(tmp_path):
    # No entry points -> early pass-through branch. Telemetry keys must NOT be added there
    # (that branch has its own schema); nothing was pruned.
    fns = {"a:foo": {}, "a:bar": {}}
    m = _run.__wrapped__ if False else None
    out = tmp_path
    (out / "call_graph.json").write_text(json.dumps(
        {"functions": fns, "call_graph": {}, "reverse_call_graph": {}}))
    ds = _load_filter()({"units": [{"id": i} for i in fns]}, str(out), "reachable")
    rf = ds["metadata"]["reachability_filter"]
    assert rf["filtered_out"] == 0 and rf.get("reachable_units") == 2
    assert "pruned_orphan_count" not in rf          # early branch untouched
    assert not (out / "pruned_units.json").exists()  # no sidecar when nothing pruned
