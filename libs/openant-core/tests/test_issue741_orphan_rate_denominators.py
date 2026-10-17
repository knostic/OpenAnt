"""#741: the orphan-rate advisory's denominator inverts its meaning on a small prune set.

The advisory renders ``orphans / pruned_units``. When the filter keeps almost
everything — the library-mode case — the PRUNED denominator shrinks toward the
orphan count and the rate explodes, so the advisory reads scariest exactly where
coverage is best. The reported measurement (swift-binary-parsing, ``--library-mode``):
95% orphans == 76 of 80 pruned, while only 80 of 359 parsed units were pruned at all
and the library core was kept 164/172. 95% was a statement about the 80, never about
the analysis.

This is the PRESENTATION defect. #722 is the POLICY ask (promote the advisory to a
decision input); the fire condition here is deliberately BYTE-UNCHANGED —
``test_the_fire_condition_is_untouched`` is the lock that proves it.

The fix prints all three numbers the issue asks for, in the one channel that reaches a
human on a multi-language scan (``core/scanner.py:217`` lifts the advisory STRING;
its int whitelist at :172 silently drops any new numeric key — the #328 class the
scanner's own comment names):
  - ``orphan_rate_pruned``  = 76/80  = 95.0%  (the current rate — a share of the PRUNED set)
  - ``prune_fraction``      = 80/359 = 22.3%  (how much was pruned at all; == ``reduction_percentage``)
  - ``orphan_rate_parsed``  = 76/359 = 21.2%  (the coverage signal)
"""
import importlib.util
import json
import pathlib

import core.parser_adapter as parser_adapter
import parsers.swift.test_pipeline as swift_pipeline
import utilities.prune_telemetry as prune_telemetry

_CORE = pathlib.Path(__file__).resolve().parents[1]           # libs/openant-core

# The issue's measured shape, exactly.
N_TOTAL, N_PRUNED, N_ORPHAN = 359, 80, 76
N_CLUSTER = N_PRUNED - N_ORPHAN                               # 4 dead-cluster members
N_KEEP = N_TOTAL - N_PRUNED - 1                               # + main == 279 kept
N_PHANTOM = 10                                                # graph-only reachable nodes

# The three numbers the advisory must carry (1-dp, the module's existing rendering).
RATE_PRUNED = 95.0                                            # 76/80
RATE_PARSED = 21.2                                            # 76/359
PRUNE_FRACTION = 22.3                                         # 80/359
# What the rate would read if the denominator were the REACHABLE CLOSURE
# (len(reachable_ids) + len(pruned)) instead of the parsed units: the closure carries
# N_PHANTOM call-graph-only nodes that are not dataset units.
WRONG_TOTAL = (N_TOTAL - N_PRUNED) + N_PHANTOM + N_PRUNED     # 369
RATE_PARSED_WRONG = round(100 * N_ORPHAN / WRONG_TOTAL, 1)    # 20.6


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _library_fixture():
    """359 parsed units, 80 pruned (76 orphans + 4 dead-cluster), library mode on.

    The 80 are ``is_exported: False`` — #722's own observation about the pruned Swift
    core ("``Spectral.decode`` is ``static func`` with ``is_exported: False``, so
    library-mode seeding cannot rescue it"), which is what makes a library-mode run
    prune a small, almost-all-orphan set in the first place.
    """
    main = "App/main.swift:main"
    keeps = [f"App/keep.swift:k{i}" for i in range(N_KEEP)]
    orph = [f"Sources/BinaryParsing/core.swift:o{i}" for i in range(N_ORPHAN)]
    clus = [f"Sources/BinaryParsing/tail.swift:c{i}" for i in range(N_CLUSTER)]
    phantom = [f"External/stdlib.swift:x{i}" for i in range(N_PHANTOM)]
    functions = {main: {"name": "main", "is_exported": True}}
    for fid in keeps:
        functions[fid] = {"is_exported": True}
    for fid in orph + clus:
        functions[fid] = {"is_exported": False}
    reverse_call_graph = {fid: [main] for fid in keeps}
    reverse_call_graph.update({fid: [main] for fid in phantom})   # reachable, NOT a unit
    reverse_call_graph.update({fid: [orph[0]] for fid in clus})   # caller is a PRUNED orphan
    call_graph = {main: keeps + phantom, orph[0]: clus}
    return {"functions": functions, "call_graph": call_graph,
            "reverse_call_graph": reverse_call_graph}, [main] + keeps + orph + clus


def _core_rf(tmp_path, module, library_mode=True):
    cgo, unit_ids = _library_fixture()
    (tmp_path / "call_graph.json").write_text(json.dumps(cgo))
    ds = module.apply_reachability_filter(
        {"units": [{"id": i} for i in unit_ids]}, str(tmp_path), "reachable",
        library_mode=library_mode)
    return ds["metadata"]["reachability_filter"]


def _swift_rf(tmp_path, module):
    cgo, _ = _library_fixture()
    result = module.apply_reachability_filter(cgo, str(tmp_path), library_mode=True,
                                              output_dir=str(tmp_path))
    return result.get("_reachability_filter")


def _assert_fixture_is_the_issues_shape(rf):
    """The fixture reproduces the filed measurement before anything is asserted
    about the rendering — a drifted fixture must fail HERE, not as a rate mismatch."""
    assert rf["original_units"] == N_TOTAL
    assert rf["filtered_out"] == N_PRUNED
    assert rf["pruned_orphan_count"] == N_ORPHAN
    assert rf["pruned_in_dead_cluster_count"] == N_CLUSTER
    assert rf["reduction_percentage"] == PRUNE_FRACTION


# --- the issue's regression-test shape, on BOTH production callers ---------------

def test_core_advisory_carries_both_rates_and_the_prune_fraction(tmp_path):
    rf = _core_rf(tmp_path, module=parser_adapter)
    _assert_fixture_is_the_issues_shape(rf)
    advisory = rf["orphan_advisory"]
    # the current rate, unchanged (76/80)
    assert f"{N_ORPHAN} of {N_PRUNED} pruned units" in advisory
    assert f"{RATE_PRUNED}%" in advisory
    # the coverage signal (76/359) — absent at the base
    assert f"{RATE_PARSED}%" in advisory, (
        "the advisory must carry orphans/parsed — the coverage signal; "
        f"got: {advisory}")
    assert f"{N_ORPHAN}/{N_TOTAL}" in advisory
    # the prune fraction (80/359) — without it the per-pruned rate is unreadable
    assert f"{PRUNE_FRACTION}%" in advisory
    assert f"{N_PRUNED}/{N_TOTAL}" in advisory
    # all three carry their NAME, so the advisory says which denominator is which
    for token in ("orphan_rate_pruned", "orphan_rate_parsed", "prune_fraction"):
        assert token in advisory, f"{token} must be named in the advisory; got: {advisory}"


def test_core_rate_keys_reach_the_record(tmp_path):
    rf = _core_rf(tmp_path, module=parser_adapter)
    assert rf["orphan_rate_pruned"] == RATE_PRUNED
    assert rf["orphan_rate_parsed"] == RATE_PARSED


def test_swift_advisory_carries_both_rates_and_the_prune_fraction(tmp_path):
    """The REPORTED path: swift-binary-parsing --library-mode runs the Swift
    pipeline's own filter, not core's. The PARITY assert cross-checks the same
    fixture through the core caller (a prod-hunk file — the swift pipeline
    file is the declared hunk_derivation_blind_spot: production code mis-
    classified as a test path), so the two renderings cannot drift apart."""
    rf = _swift_rf(tmp_path, module=swift_pipeline)
    rf_core = _core_rf(tmp_path, module=parser_adapter)
    assert rf is not None
    _assert_fixture_is_the_issues_shape(rf)
    advisory = rf["orphan_advisory"]
    assert f"{RATE_PRUNED}%" in advisory and f"{RATE_PARSED}%" in advisory
    assert f"{PRUNE_FRACTION}%" in advisory
    assert rf["orphan_rate_pruned"] == RATE_PRUNED
    assert rf["orphan_rate_parsed"] == RATE_PARSED
    # the parity: the swift pipeline's rendering equals core's for the same
    # fixture (both route through compute_prune_telemetry — one wiring)
    assert rf["orphan_advisory"] == rf_core["orphan_advisory"]


def test_parsed_denominator_is_parsed_units_not_the_reachable_closure(tmp_path):
    """The denominator trap: ``reachable_ids`` is the closure over the CALL GRAPH's
    functions (parser_adapter.py:580), while the pruned set is over DATASET UNITS
    (:665) — the two live in different universes, so len(reachable_ids)+len(pruned)
    over-counts by every graph-only node. The fixture plants N_PHANTOM of them."""
    rf = _core_rf(tmp_path, module=parser_adapter)
    assert RATE_PARSED != RATE_PARSED_WRONG, "the fixture must discriminate"
    assert rf["orphan_rate_parsed"] == RATE_PARSED
    assert f"{RATE_PARSED_WRONG}%" not in rf["orphan_advisory"], (
        "the parsed rate must divide by original_units (359), not by the "
        f"reachable closure + pruned ({WRONG_TOTAL})")


# --- the #722 locks: the POLICY is untouched -------------------------------------

def test_the_fire_condition_is_untouched():
    """#741 is presentation-only: the set of runs that emit an advisory is identical.
    The threshold, the floor, and the strictly-greater boundary are #722's policy.
    GREEN on BOTH sides by design — this is the lock, not a witness."""
    pt = _load(_CORE / "utilities" / "prune_telemetry.py", "pt741")
    assert prune_telemetry.ORPHAN_RATE_WARN_THRESHOLD == 0.5
    assert pt.ORPHAN_MIN_PRUNED_FOR_ADVISORY == 10
    # exactly 50% of 8 pruned -> silent (strictly-greater)
    _e, _w, at_threshold = prune_telemetry.compute_prune_telemetry(
        ["a.py:root"], [f"a.py:o{i}" for i in range(4)] + [f"a.py:c{i}" for i in range(4)],
        {"a.py:root": [], "a.py:o0": [f"a.py:c{i}" for i in range(4)]},
        {f"a.py:c{i}": ["a.py:o0"] for i in range(4)})
    assert at_threshold is None, "a presentation fix must not widen the fire condition"
    # 1 pruned, 100% orphan -> below the floor -> silent
    _e2, _w2, below_floor = prune_telemetry.compute_prune_telemetry(
        ["a.py:root"], ["a.py:o0"], {"a.py:root": []}, {})
    assert below_floor is None


def _silent_fixture():
    """20 pruned, 8 orphans = 40% -> above the floor, BELOW the rate: silent."""
    main = "App/main.swift:main"
    keeps = [f"App/keep.swift:k{i}" for i in range(20)]
    orph = [f"Lib/a.swift:o{i}" for i in range(8)]
    clus = [f"Lib/b.swift:c{i}" for i in range(12)]
    functions = {main: {"name": "main", "is_exported": True}}
    for fid in keeps:
        functions[fid] = {"is_exported": True}
    for fid in orph + clus:
        functions[fid] = {"is_exported": False}
    rcg = {fid: [main] for fid in keeps}
    rcg.update({fid: [orph[0]] for fid in clus})
    return {"functions": functions, "call_graph": {main: keeps, orph[0]: clus},
            "reverse_call_graph": rcg}, [main] + keeps + orph + clus


def test_prune_fraction_matches_the_recorded_reduction_percentage():
    """F1 (fable T1 r1): the printed prune_fraction and the recorded
    reduction_percentage must be the SAME number.

    The callers record reduction_percentage with the float path
    ``round((1 - kept/total) * 100, 1)`` (core/parser_adapter.py:598); the helper
    originally printed ``round(100 * pruned/total, 1)``. The two are algebraically
    equal but round differently on 819 (total, pruned) pairs in [1, 3000] (float
    half-rounding), so the advisory could print prune_fraction=11.2% while the
    record says reduction_percentage=11.3. t=160, p=18 is one such pair: the
    helper must render the CALLERS' number.
    """
    t, p = 160, 18                       # round(100*18/160,1)=11.2 vs callers' 11.3
    pruned = [f"a.py:o{i}" for i in range(p)]
    cg = {"a.py:root": []}
    rcg = {}                             # no callers: every pruned unit is an orphan
    _e, _w, adv = prune_telemetry.compute_prune_telemetry(["a.py:root"], pruned, cg, rcg,
                                             total_parsed_units=t)
    assert adv is not None, "100% orphan rate over 18 pruned must fire the advisory"
    recorded = round((1 - (t - p) / t) * 100, 1)      # the callers' formula = 11.3
    assert f"prune_fraction={recorded}%" in adv, (
        f"the advisory's prune_fraction must equal the recorded "
        f"reduction_percentage ({recorded}); got: {adv}")
    # F2 (fable T1 r2): every printed share of total_parsed_units renders on the
    # SAME float path — when ALL pruned units are orphans the two printed rates
    # are the same fraction and must print the same number (the naive
    # 100*n/total path rendered 11.2 beside the fraction's 11.3).
    assert f"orphan_rate_parsed={recorded}%" in adv, (
        f"orphan_rate_parsed and prune_fraction share one denominator and here "
        f"one numerator ({p}/{t}) — they must print the same number; got: {adv}")
    # F4 (fable T1 r3): no separate ordering assert here — brute force shows an
    # o<p ordering violation never occurs on ANY float path (a <= check would
    # pass identically pre- and post-fix, so it witnesses nothing); the o==p
    # equality assert above is the discriminator.


def test_omission_renders_the_pre741_advisory_byte_identically():
    """The OMISSION lock (fable T1 r6, the claim's refuted half): a caller that
    does NOT supply total_parsed_units gets the advisory the pre-#741 base
    would have rendered — no DENOMINATORS sentence, no orphan_rate_parsed key.
    parser_adapter always supplies the arg (:668-670), so this locks the
    optional-arg contract for every other caller (the direct-call shape the
    fire-condition lock uses). The isolating mutant (a guessed-denominator
    _denoms on the omitted path) must FAIL here."""
    t, p = 40, 10                       # >= floor 10; 100% orphans > threshold
    pruned = [f"a.py:o{i}" for i in range(p)]
    cg = {"a.py:root": []}
    rcg = {}
    with_total = prune_telemetry.compute_prune_telemetry(
        ["a.py:root"], pruned, cg, rcg, total_parsed_units=t)
    without_total = prune_telemetry.compute_prune_telemetry(["a.py:root"], pruned, cg, rcg)
    # the firing sanity: both fire (10 >= 10 floor, 100% > 50%)
    assert with_total[2] is not None and without_total[2] is not None
    # the presence half: the supplied call carries the sentence + the key
    assert "DENOMINATORS:" in with_total[2]
    assert with_total[0].get("orphan_rate_parsed") is not None
    # THE LOCK: the omitted call renders the pre-#741 shape —
    # no DENOMINATORS, no guessed denominator, no parsed-rate key
    assert "DENOMINATORS:" not in without_total[2], (
        "an omitted total_parsed_units must not render a guessed-denominator "
        f"sentence; got: {without_total[2]}")
    assert "orphan_rate_parsed" not in without_total[0], (
        "an omitted total_parsed_units must not fabricate a parsed-rate key")
    # and the omitted advisory equals the BASE's (fc886b35) rendering for
    # the same fired fixture — the pre-#741 shape carried no DENOMINATORS
    # sentence at all. PINNED AS A LITERAL, not derived from git
    # (`git show <base>:...` would crash CI's depth-1 clones where the base
    # commit is absent — fable T1 r7 F6): the omitted path adds nothing, so
    # this string is deterministic.
    _base_advisory = (
        "10 of 10 pruned units (100.0%) are ORPHANS: no non-self caller, so "
        "each is a missing-edge ROOT candidate (genuinely dead code is also "
        "an orphan — a rate above 50% is a call-graph health signal, not a "
        "proven defect count; dispatch-table targets prune as orphans). "
        "Check call-graph edge coverage; top files: a.py (10)")
    assert without_total[2] == _base_advisory, (
        "the omitted-arg advisory must equal the base's rendering "
        f"byte-for-byte; head: {without_total[2]!r} base: {_base_advisory!r}")


def test_rate_keys_are_present_only(tmp_path):
    """Absence discipline (the module's own convention, and the contract pinned by
    tests/test_reachability_prune_telemetry.py:54's EXACT-equality assertion on
    ``extra``): the rate keys ride the advisory — never a fabricated rate on a
    silent run. GREEN on BOTH sides by design."""
    cgo, unit_ids = _silent_fixture()
    (tmp_path / "call_graph.json").write_text(json.dumps(cgo))
    mod = _load(_CORE / "core" / "parser_adapter.py", "pa741b")
    ds = mod.apply_reachability_filter(
        {"units": [{"id": i} for i in unit_ids]}, str(tmp_path), "reachable",
        library_mode=True)
    rf = ds["metadata"]["reachability_filter"]
    assert rf["filtered_out"] == 20 and rf["pruned_orphan_count"] == 8   # 40%
    assert "orphan_advisory" not in rf                                   # below the rate
    assert "orphan_rate_pruned" not in rf
    assert "orphan_rate_parsed" not in rf
