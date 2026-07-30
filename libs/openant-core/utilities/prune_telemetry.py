"""Shared per-unit reachability-prune telemetry (Sol+Fable design).

Lives in ``utilities`` so BOTH the core (Python) reachability filter and the
per-language parser filters (Swift today; the class-based siblings can adopt it)
import it without a parser->core layering inversion — parsers already depend on
``utilities`` (file_io, agentic_enhancer), never on ``core``.

ADDITIVE, all-language, NO change to which units survive.
"""
import os
import sys

from utilities.file_io import open_utf8


def compute_prune_telemetry(reachable_ids, pruned_ids, call_graph, reverse_call_graph,
                            output_dir=None):
    """Classify every pruned unit + enforce the forward-asymmetry invariant.

    Classifies each prune as ``orphan`` (no non-self caller => missing-edge ROOT
    candidate) or ``dead_cluster`` (has a pruned caller => downstream shadow), and
    computes the hard INVARIANT ``pruned_forward_called_by_reachable_count`` (a REACHABLE
    unit forward-calling a PRUNED one = call_graph/reverse_call_graph asymmetry = a
    definitively wrong prune; expect 0).

    Contract:
      - ``pruned_ids`` is iterated as given — pass a SORTED list for a deterministic
        ``pruned_by_file`` tie-ordering.
      - ``call_graph``/``reverse_call_graph`` MUST be the UN-pruned graphs. Feeding a
        pruned graph (every edge to a pruned node already stripped) forces the invariant
        to a manufactured 0 — silently disabling it. This is the single highest-risk arg.
      - When ``output_dir`` is given and something was pruned, writes ``pruned_units.json``
        (best-effort; a telemetry failure never propagates).

    Returns ``(extra_rf_keys, asym_warning_or_None)`` — the caller merges the keys into
    its own base rf (original_units/entry_points/... stay caller-owned) and applies its
    own warning precedence (e.g. a blackout warning may override the asymmetry one).

    Telemetry is ADVISORY and must never crash the filter step, so a malformed
    present-but-null graph is treated as empty (consistent with the callers' missing-key
    defaulting) rather than raising.
    """
    from collections import Counter
    call_graph = call_graph or {}
    reverse_call_graph = reverse_call_graph or {}
    pruned_set = set(pruned_ids)
    pruned_records, by_file = [], Counter()
    orphan_ct = cluster_ct = 0
    for pid in pruned_ids:
        callers = [c for c in (reverse_call_graph.get(pid) or []) if c != pid]
        bucket = "dead_cluster" if callers else "orphan"
        orphan_ct += bucket == "orphan"
        cluster_ct += bucket == "dead_cluster"
        by_file[pid.split(":", 1)[0]] += 1
        pruned_records.append({"id": pid, "file": pid.split(":", 1)[0],
                               "callers": sorted(callers), "bucket": bucket})
    asym = {callee for c in reachable_ids for callee in (call_graph.get(c) or [])
            if callee in pruned_set}
    extra = {
        "pruned_orphan_count": orphan_ct,
        "pruned_in_dead_cluster_count": cluster_ct,
        "pruned_forward_called_by_reachable_count": len(asym),
        "pruned_by_file": dict(by_file.most_common(20)),
    }
    if pruned_ids and output_dir:   # full sidecar (uncapped, id-sorted); best-effort
        try:
            import json as _json
            # open_utf8 (not bare open) per the repo file-io convention enforced by
            # tests/test_file_io.py::test_no_bare_open_in_non_test_code.
            with open_utf8(os.path.join(output_dir, "pruned_units.json"), "w") as _f:
                _json.dump({"schema_version": 1,
                            "units": sorted(pruned_records, key=lambda r: r["id"])}, _f, indent=2)
            extra["pruned_units_path"] = "pruned_units.json"
        except Exception as _e:
            print(f"  [Warning] could not write pruned_units.json: {_e}", file=sys.stderr)
    asym_warning = None
    if asym:
        asym_warning = (
            f"{len(asym)} pruned unit(s) are forward-called by a REACHABLE unit "
            "(call_graph/reverse_call_graph ASYMMETRY) — genuinely-reachable units were silently "
            "pruned. Investigate graph symmetry (test_callgraph_symmetry).")
    return extra, asym_warning
