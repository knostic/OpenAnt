"""#520: the library-blackout advisory is no longer silent under the band.

The measured cliff: an incidental-only corpus (every real seed an
``input_pattern`` match, zero structural seeds) at 87.9% pruning sat
UNDER the advisory's 0.90 ratio gate — the collapse was silent. The fix
(adjudicated): drop the ratio gate (the advisory fires whenever every
real seed is incidental, at any reduction, with wording scaled to what
happened — a sub-threshold reduction kept most units and must not claim
the core was dropped), and record the seed-class counts
(structural/incidental) in the reachability metadata on both branches,
via a shared classifier so the three pipeline sites cannot drift.
ADVISORY-ONLY: no unit set changes anywhere.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utilities.agentic_enhancer import blackout_warning  # noqa: E402
from utilities.agentic_enhancer.entry_point_detector import classify_seeds  # noqa: E402


def _details(*reason_lists, **extra):
    d = {f"f{i}": {"reasons": rs} for i, rs in enumerate(reason_lists)}
    d.update({k: {"reasons": [], **v} for k, v in extra.items()})
    return d


# --- the silence fix: the ratio gate is gone -------------------------------

def test_incidental_only_below_the_band_now_warns():
    """THE #520 case: the measured cliff — 735 of 6089 kept (87.9% pruned,
    under the old 0.90 gate), every seed incidental. Pre-fix: None (silent)."""
    details = _details(["input_pattern:read"], ["input_pattern:fopen"])
    w = blackout_warning(details, original_count=6089, reachable_count=735)
    assert w is not None, "the sub-band incidental-only collapse is silent again"
    # astra's caveat: sub-threshold wording must NOT claim the core was dropped
    assert "was dropped" not in w
    assert "was not seeded" in w
    assert "--library-mode" in w


def test_incidental_only_at_low_reduction_also_warns():
    """The gate is gone entirely: even a modest pruning with zero structural
    seeds names the unseeded public API (the user can judge)."""
    details = _details(["input_pattern:getenv"])
    w = blackout_warning(details, original_count=100, reachable_count=95)
    assert w is not None
    assert "was dropped" not in w


def test_incidental_only_above_the_band_keeps_the_strong_wording():
    details = _details(["input_pattern:fopen"], ["input_pattern:read"])
    w = blackout_warning(details, original_count=712, reachable_count=24)
    assert w is not None
    assert "library-blackout pattern" in w
    assert "was dropped" in w  # above the band, the claim is earned


def test_structural_seed_still_suppresses():
    details = _details(["unit_type:main"], ["input_pattern:read"])
    assert blackout_warning(details, original_count=712, reachable_count=24) is None
    assert blackout_warning(details, original_count=100, reachable_count=95) is None


def test_library_mode_and_empty_unchanged():
    details = _details(["input_pattern:read"])
    assert blackout_warning(details, 712, 24, library_mode=True) is None
    assert blackout_warning(_details(), 0, 0) is None
    assert blackout_warning(_details(), 500, 0) is not None  # total blackout


# --- the shared classifier ---------------------------------------------------

def test_classify_seeds_counts_and_excludes():
    details = _details(
        ["unit_type:main"],                      # structural
        ["decorator:@app.route"],                # structural
        ["input_pattern:read"],                  # incidental
        ["name:main"],                           # structural
    )
    # synthetic harness + non-runtime main: excluded from BOTH counts
    details["h"] = {"reasons": ["unit_type:main"], "synthetic_harness": True}
    details["nr"] = {"reasons": ["unit_type:main"], "non_runtime_main": True}
    structural, incidental = classify_seeds(details)
    assert (structural, incidental) == (3, 1)


def test_classify_seeds_empty():
    assert classify_seeds({}) == (0, 0)
    assert classify_seeds(None) == (0, 0)


# --- the metadata counts + the no-set-change proof (core site) --------------

def _write_graph(out: Path, functions: dict, graph: dict):
    out.mkdir(parents=True, exist_ok=True)
    (out / "call_graph.json").write_text(json.dumps({
        "functions": functions, "call_graph": graph,
        "reverse_call_graph": {k: [] for k in graph},
    }))


def test_filtered_branch_records_seed_class_counts(tmp_path):
    """Incidental-only seeding: the metadata carries the counts, the warning
    rides the record, and the retained set is EXACTLY the BFS-from-the-seed
    set — proving the fix changed no unit set (advisory-only)."""
    from core.parser_adapter import apply_reachability_filter

    out = tmp_path / "out"
    # f_read contains an input pattern -> the detector seeds it (incidental);
    # f_dead is caller-less; f_main has no seedable shape.
    _write_graph(out, {
        "a.py:f_read": {"code": "def f_read(p):\n    return open(p, \"r\").read()\n"},
        "a.py:f_dead": {"code": "def f_dead():\n    return 1\n"},
        "a.py:f_main": {"code": "def f_main():\n    return f_dead()\n"},
    }, {"a.py:f_read": [], "a.py:f_dead": [], "a.py:f_main": ["a.py:f_dead"]})

    dataset = {"units": [
        {"id": "a.py:f_read"}, {"id": "a.py:f_dead"}, {"id": "a.py:f_main"}]}
    result = apply_reachability_filter(dataset, str(out), "reachable")

    rf = result["metadata"]["reachability_filter"]
    assert rf["structural_entry_points"] == 0
    assert rf["incidental_entry_points"] == 1
    assert "warning" in rf, "the incidental-only record carries no advisory"
    # the no-set-change proof: the retained set is the seed + its callees only
    # (f_main has no caller edge INTO it; f_dead reachable only via f_main,
    # which is not reachable from the seed) — the BFS set, unchanged by the fix
    kept = {u["id"] for u in result["units"]}
    assert kept == {"a.py:f_read"}, (
        f"the retained set changed: {kept} — the fix is advisory-only")


def test_keep_all_branch_records_seed_class_counts(tmp_path):
    from core.parser_adapter import apply_reachability_filter

    out = tmp_path / "out2"
    _write_graph(out, {
        "a.py:plain": {"code": "def plain():\n    return 1\n"},
    }, {"a.py:plain": []})
    dataset = {"units": [{"id": "a.py:plain"}]}
    result = apply_reachability_filter(dataset, str(out), "reachable")

    rf = result["metadata"]["reachability_filter"]
    # keep-all fired (zero real seeds); the counts are present and honest
    assert rf.get("structural_entry_points") == 0
    assert rf.get("incidental_entry_points") == 0
    assert "warning" in rf
    assert {u["id"] for u in result["units"]} == {"a.py:plain"}  # keep-all kept all
