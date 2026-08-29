"""Regression tests for issue #301 — the orphan/dead-cluster prune
classification is computed, written into dataset metadata, and then dropped
before the deliverable.

`compute_prune_telemetry` classifies every pruned unit as an ``orphan`` (no
non-self caller — a missing-edge ROOT candidate) or a ``dead_cluster`` (has a
pruned caller — a downstream shadow). On the run that filed this, 3,128 of
5,370 pruned units (58.2%) were orphans — the exact signal that distinguishes
"genuinely dead code" from "our call graph is missing an edge" (the #295/#298/
#299 dispatch-table shape prunes as orphans). The counts reached
``dataset.metadata`` and no further: the reporter copies only four reachability
fields into ``pipeline_output.json``, no code reads the counts, and the
multi-language aggregate never sums them.

Contract locked here:
- the four telemetry keys forward into ``pipeline_output.pipeline_stats``
  (present-only: absent when no filter record / no telemetry ran);
- the multi-language aggregate SUMS the per-language counts (the filing run's
  shape: keys existed per-language under ``reachability_filter.per_language``,
  never at the top level the reporter reads) and merges the by-file pointer;
- an orphan rate above the threshold surfaces a scan-summary advisory
  (stderr + its own metadata key), worded as the issue requires: orphans are
  missing-edge CANDIDATES — genuinely dead code is also an orphan;
- the advisory does NOT claim the reserved ``warning`` slot (the
  forward-asymmetry / blackout class owns it).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.prune_telemetry import (  # noqa: E402
    compute_prune_telemetry,
)
from core.reporter import build_pipeline_output  # noqa: E402
from utilities.file_io import write_json  # noqa: E402


# ---------------------------------------------------------------------------
# the advisory (item 2)
# ---------------------------------------------------------------------------
def _simple_graphs(orphan_ids, cluster_root):
    """A graph where orphan_ids have no callers (orphans) and cluster_root
    calls everything else (which itself prunes as a dead cluster)."""
    cg = {cluster_root: []}
    rcg = {}
    return cg, rcg


def _many_orphan_fixture(n_orphan=8, n_cluster=2):
    """n_orphan orphans + n_cluster dead-cluster units (called by a pruned
    root, itself an orphan)."""
    pruned = [f"a.py:o{i}" for i in range(n_orphan)] + \
             [f"a.py:c{i}" for i in range(n_cluster)]
    reachable = ["a.py:root"]
    call_graph = {"a.py:root": [], "a.py:cr": [f"a.py:c{i}" for i in range(n_cluster)]}
    rcg = {f"a.py:c{i}": ["a.py:cr"] for i in range(n_cluster)}
    return reachable, pruned, call_graph, rcg


def test_advisory_fires_above_threshold():
    # 8 orphans of 10 pruned (cr is NOT pruned in this fixture) = 80%
    reachable, pruned, call_graph, rcg = _many_orphan_fixture()
    extra, warning, advisory = compute_prune_telemetry(
        reachable, pruned, call_graph, rcg)
    assert extra["pruned_orphan_count"] == 8
    assert advisory is not None
    assert "candidate" in advisory.lower(), (
        "the issue's wording requirement: orphans are missing-edge "
        "CANDIDATES, not proven missing edges")
    assert "80.0%" in advisory  # the measured rate, rendered


def test_advisory_silent_on_tiny_sets_below_floor():
    """Wave catch (e2e): 2-of-3 at 66% is not the evidence 3128-of-5370 is;
    the advisory stays silent below ORPHAN_MIN_PRUNED_FOR_ADVISORY."""
    reachable, pruned, call_graph, rcg = _many_orphan_fixture(2, 1)
    extra, warning, advisory = compute_prune_telemetry(
        reachable, pruned, call_graph, rcg)
    assert advisory is None


def test_advisory_silent_at_exactly_threshold():
    """Wave catch (test-validity): the boundary — exactly 50% does NOT fire
    (strictly greater), pinning > vs >=."""
    reachable, pruned, call_graph, rcg = _many_orphan_fixture(4, 4)
    extra, warning, advisory = compute_prune_telemetry(
        reachable, pruned, call_graph, rcg)
    # 4 orphans of 8 pruned = exactly 50% -> silent (strictly-greater)
    assert extra["pruned_orphan_count"] == 4
    assert advisory is None


def test_advisory_pointer_ranks_orphan_files_not_dead_clusters():
    """Wave catch (test-validity MAJOR 2): the 'top files' pointer must rank
    by ORPHAN-heavy files. A dead-cluster-heavy file with MORE total prunes
    (d.py: 1 orphan root + 12 downstream shadows = 13) must NOT outrank the
    orphan-heavy file (o.py: 12 orphans) — the combined counter would lead
    with d.py; the orphan-only counter must lead with o.py."""
    pruned = ([f"o.py:o{i}" for i in range(12)]
              + [f"d.py:dr"] + [f"d.py:c{i}" for i in range(12)])
    reachable = ["x.py:root"]
    call_graph = {"x.py:root": [], "d.py:dr": [f"d.py:c{i}" for i in range(12)]}
    rcg = {f"d.py:c{i}": ["d.py:dr"] for i in range(12)}
    extra, warning, advisory = compute_prune_telemetry(
        reachable, pruned, call_graph, rcg)
    # 13 orphans (12 o.py + dr) of 25 = 52% > 50%, above the floor
    assert advisory is not None
    assert "o.py (12)" in advisory
    assert "d.py (13)" not in advisory  # the combined-counter ranking would show 13
    # and o.py ranks FIRST (the orphan-heavy pointer)
    assert advisory.index("o.py") < advisory.index("d.py")


def test_advisory_silent_below_threshold_at_scale():
    """11 units: 1 orphan of 11 = 9% — above the floor, below the rate."""
    reachable, pruned, call_graph, rcg = _many_orphan_fixture(1, 9)
    extra, warning, advisory = compute_prune_telemetry(
        reachable, pruned, call_graph, rcg)
    assert advisory is None  # 2 orphans (o0 + cr) of 11 = 18% < threshold


def test_advisory_silent_when_nothing_pruned():
    extra, warning, advisory = compute_prune_telemetry(
        ["a.py:root"], [], {"a.py:root": []}, {})
    assert advisory is None
    assert extra["pruned_orphan_count"] == 0


def test_asymmetry_warning_unchanged():
    """The hard invariant keeps its own warning channel (contract guard)."""
    reachable = ["a.py:root"]
    pruned = ["a.py:p1"]
    call_graph = {"a.py:root": ["a.py:p1"]}  # reachable -> pruned: ASYMMETRY
    rcg = {"a.py:p1": ["a.py:root"]}
    extra, warning, advisory = compute_prune_telemetry(
        reachable, pruned, call_graph, rcg)
    assert extra["pruned_forward_called_by_reachable_count"] == 1
    assert warning is not None and "ASYMMETRY" in warning


# ---------------------------------------------------------------------------
# the deliverable forwarding (item 1)
# ---------------------------------------------------------------------------
def _write_scan(tmp_path, telemetry=None):
    results = {"dataset": "t", "code_by_route": {}, "metrics": {"total": 2},
               "confirmed_findings": [], "results": []}
    write_json(tmp_path / "results.json", results)
    if telemetry is not None:
        write_json(tmp_path / "dataset.json", {
            "metadata": {"reachability_filter": {
                "reachable_units": 2, "original_units": 10,
                "reduction_percentage": 80.0, **telemetry,
            }},
            "units": []})
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"), output_path=str(out),
        language="python", repo_name="t/r", processing_level="reachable")
    return json.loads(out.read_text())


TELEMETRY = {
    "pruned_orphan_count": 8,
    "pruned_in_dead_cluster_count": 6,
    "pruned_forward_called_by_reachable_count": 0,
    "pruned_by_file": {"a.py": 8, "b.py": 6},
    "pruned_units_path": "pruned_units.json",
}


def test_reporter_forwards_the_four_telemetry_keys(tmp_path):
    po = _write_scan(tmp_path, telemetry=TELEMETRY)
    stats = po["pipeline_stats"]
    assert stats["pruned_orphan_count"] == 8
    assert stats["pruned_in_dead_cluster_count"] == 6
    assert stats["pruned_forward_called_by_reachable_count"] == 0
    assert stats["pruned_by_file"] == {"a.py": 8, "b.py": 6}


def test_reporter_keys_absent_when_no_record(tmp_path):
    """Present-only: no filter record → no fabricated zeros."""
    po = _write_scan(tmp_path, telemetry=None)
    stats = po["pipeline_stats"]
    assert "pruned_orphan_count" not in stats
    assert "pruned_by_file" not in stats


# ---------------------------------------------------------------------------
# the multi-language aggregate (the filing run's shape)
# ---------------------------------------------------------------------------
def test_scanner_aggregates_per_language_telemetry():
    """The merged-run shape: telemetry exists per-language under
    reachability_filter.per_language; the aggregate the reporter reads must
    SUM the counts and merge the by-file pointer."""
    from core.scanner import aggregate_reachability_telemetry

    per_lang = {
        "python": dict(TELEMETRY),
        "go": {"pruned_orphan_count": 2,
               "pruned_in_dead_cluster_count": 1,
               "pruned_forward_called_by_reachable_count": 0,
               "pruned_by_file": {"x.go": 3}},
    }
    agg = aggregate_reachability_telemetry(per_lang)
    assert agg["pruned_orphan_count"] == 10
    assert agg["pruned_in_dead_cluster_count"] == 7
    assert agg["pruned_forward_called_by_reachable_count"] == 0
    assert agg["pruned_by_file"]["a.py"] == 8
    assert agg["pruned_by_file"]["x.go"] == 3


def test_scanner_aggregate_absent_when_no_telemetry():
    from core.scanner import aggregate_reachability_telemetry

    per_lang = {"python": {"original_units": 4, "reachable_units": 4}}
    agg = aggregate_reachability_telemetry(per_lang)
    assert "pruned_orphan_count" not in agg


# ---------------------------------------------------------------------------
# wave catches: the INTEGRATION sites (test-validity BLOCKER + MAJOR 3)
# ---------------------------------------------------------------------------
def test_parser_adapter_integration_stores_advisory_in_its_own_key(tmp_path, capsys):
    """Drive the REAL apply_reachability_filter: the advisory lands in its own
    metadata key (NEVER the reserved warning slot) and reaches stderr."""
    from core.parser_adapter import apply_reachability_filter

    ids = ["f.py:root"] + [f"f.py:o{i}" for i in range(8)] + ["f.py:cr", "f.py:c1"]
    (tmp_path / "call_graph.json").write_text(json.dumps({
        "functions": {u: {} for u in ids},
        "call_graph": {"f.py:root": [], "f.py:cr": ["f.py:c1"]},
        "reverse_call_graph": {"f.py:c1": ["f.py:cr"]},
    }))
    ds = {"units": [{"id": i} for i in ids]}
    res = apply_reachability_filter(ds, str(tmp_path), "reachable",
                                    extra_entry_points={"f.py:root"})
    rf = res["metadata"]["reachability_filter"]
    assert "orphan_advisory" in rf
    assert "ORPHANS" in rf["orphan_advisory"]
    # the reserved slot belongs to the asymmetry/blackout class only
    assert "warning" not in rf or "ORPHAN" not in rf.get("warning", "")
    err = capsys.readouterr().err
    assert "[Advisory]" in err and "ORPHANS" in err


def test_parser_adapter_no_advisory_no_stderr_noise(tmp_path, capsys):
    """Below the rate: no key, no stderr line."""
    from core.parser_adapter import apply_reachability_filter

    ids = ["f.py:root", "f.py:a", "f.py:b", "f.py:c"]
    (tmp_path / "call_graph.json").write_text(json.dumps({
        "functions": {u: {} for u in ids},
        "call_graph": {"f.py:root": ["f.py:a", "f.py:b", "f.py:c"],
                       "f.py:a": [], "f.py:b": [], "f.py:c": []},
        "reverse_call_graph": {},
    }))
    ds = {"units": [{"id": i} for i in ids]}
    res = apply_reachability_filter(ds, str(tmp_path), "reachable",
                                    extra_entry_points={"f.py:root"})
    rf = res["metadata"]["reachability_filter"]
    assert "orphan_advisory" not in rf
    assert "[Advisory]" not in capsys.readouterr().err


def test_reporter_forwards_the_advisory(tmp_path):
    po = _write_scan(tmp_path, telemetry={
        "pruned_orphan_count": 8, "pruned_in_dead_cluster_count": 6,
        "pruned_forward_called_by_reachable_count": 0,
        "pruned_by_file": {"a.py": 14},
        "orphan_advisory": "9 of 11 pruned units (81.8%) are ORPHANS",
    })
    assert "ORPHANS" in po["pipeline_stats"]["orphan_advisory"]


def test_scanner_lift_aggregates_per_language_advisories():
    from core.scanner import aggregate_reachability_telemetry

    per_lang = {
        "python": {"pruned_orphan_count": 8, "pruned_in_dead_cluster_count": 2,
                   "pruned_forward_called_by_reachable_count": 0,
                   "pruned_by_file": {"a.py": 10},
                   "orphan_advisory": "8 of 10 pruned units (80%) are ORPHANS"},
        "go": {"pruned_orphan_count": 2, "pruned_in_dead_cluster_count": 1,
               "pruned_forward_called_by_reachable_count": 0,
               "pruned_by_file": {"x.go": 3}},
    }
    agg = aggregate_reachability_telemetry(per_lang)
    assert agg["orphan_advisory"].startswith("python: ")
    assert "go" not in agg["orphan_advisory"]  # go had no advisory


def test_scanner_aggregate_recaps_by_file_at_20():
    """Wave catch (test-validity MINOR 4): the documented top-20 re-cap."""
    from core.scanner import aggregate_reachability_telemetry

    per_lang = {"python": {
        "pruned_orphan_count": 25,
        "pruned_by_file": {f"f{i:02d}.py": 26 - i for i in range(25)},
    }}
    agg = aggregate_reachability_telemetry(per_lang)
    assert len(agg["pruned_by_file"]) == 20
    assert "f00.py" in agg["pruned_by_file"]      # highest count survives
    assert "f24.py" not in agg["pruned_by_file"]  # lowest is capped away
