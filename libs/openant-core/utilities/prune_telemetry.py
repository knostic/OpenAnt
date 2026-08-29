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


# #301: above this share of pruned units being ORPHANS, surface a scan-summary
# advisory. Advisory only, deliberately NOT the reserved ``warning`` slot (the
# forward-asymmetry / blackout class owns that): an orphan is a missing-edge
# ROOT *candidate* — genuinely dead code is also an orphan, so a high rate is a
# call-graph HEALTH signal to check (dispatch-table targets prune as orphans:
# #295/#298/#299), never a proven defect count.
ORPHAN_RATE_WARN_THRESHOLD = 0.5

# #301 (wave catch): the advisory stays silent on tiny prune sets — the same
# rate on 3 units is noise where on 3,000 it is the signal the issue filed.
ORPHAN_MIN_PRUNED_FOR_ADVISORY = 10


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
    orphan_by_file = Counter()
    orphan_ct = cluster_ct = 0
    for pid in pruned_ids:
        callers = [c for c in (reverse_call_graph.get(pid) or []) if c != pid]
        bucket = "dead_cluster" if callers else "orphan"
        orphan_ct += bucket == "orphan"
        cluster_ct += bucket == "dead_cluster"
        by_file[pid.split(":", 1)[0]] += 1
        # wave catch (test-validity): the advisory's "top files" pointer must
        # rank by ORPHAN-heavy files (the missing-edge candidates), not the
        # combined counter — a dead-cluster-heavy file is downstream of a
        # pruned root and would misdirect the edge-coverage check.
        if bucket == "orphan":
            orphan_by_file[pid.split(":", 1)[0]] += 1
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
    # #301: the orphan-rate advisory — the classification that distinguishes
    # "genuinely dead code" from "the call graph is missing an edge" previously
    # reached no consumer at all. Present-only (None at/below the threshold and
    # when nothing pruned).
    # wave catches: (a) an absolute floor — 2-of-3 at 66% is not the same
    # evidence as 3128-of-5370 at 58%, so tiny sets stay silent; (b) absence is
    # a three-way overload (never ran / nothing pruned / rate at-or-below) — a
    # consumer distinguishing them checks pruned_orphan_count's presence.
    orphan_advisory = None
    if (len(pruned_ids) >= ORPHAN_MIN_PRUNED_FOR_ADVISORY
            and orphan_ct / len(pruned_ids) > ORPHAN_RATE_WARN_THRESHOLD):
        rate = round(100 * orphan_ct / len(pruned_ids), 1)
        orphan_advisory = (
            f"{orphan_ct} of {len(pruned_ids)} pruned units ({rate}%) are ORPHANS: "
            "no non-self caller, so each is a missing-edge ROOT candidate (genuinely "
            "dead code is also an orphan — a rate above "
            f"{int(ORPHAN_RATE_WARN_THRESHOLD * 100)}% is a call-graph health "
            "signal, not a proven defect count; dispatch-table targets prune "
            "as orphans). Check call-graph edge coverage; top files: "
            + ", ".join(f"{f} ({c})" for f, c in sorted(
                orphan_by_file.items(), key=lambda kv: (-kv[1], kv[0]))[:3]))
    return extra, asym_warning, orphan_advisory
