"""Regression tests for #754: the C parser consumes its call-graph edge sets unsorted.

`parsers/c/call_graph_builder.py` builds each caller's callees in a `set()`
(`:197` tree-sitter path, `:818` regex fallback) and the consumer at `:850-851`
filters that set into a list WITHOUT sorting it, so every function's edge ORDER
is whatever the process's string hashing produced. Four surfaces follow that
order:

  * `call_graph[func_id]` itself (and `units[*].metadata.direct_calls`, which is
    that same list) -- the recorded output contract;
  * `reverse_call_graph`'s KEY creation order, because the reverse edges are
    appended while iterating the unsorted forward list (`:854-858`);
  * `UnitGenerator.get_dependencies`' append order (`parsers/c/unit_generator.py:68-88`),
    which is first-discovery order over those edges;
  * therefore `assemble_enhanced_code`'s `FILE_BOUNDARY` join
    (`parsers/c/unit_generator.py:112-140`) -- i.e. the recorded `primary_code`
    STRING, which downstream hashes (`core/llm_reachability.py:578-594`
    `_projection_sha`) key resume adoption on.

The repair is the one line the Python parser already carries at its own
consumer (`parsers/python/call_graph_builder.py:1336`, `sorted(...)`). Two
locks guard the shape the issue explicitly forbids changing: the edge SET must
stay constant (an ordering repair, never an edge drop), and the list
`get_dependencies` returns must stay DEPTH-MAJOR from the FIFO walk -- flat
sorting it would destroy the depth ordering the inliner relies on.

The seed-varied rows drive the product's own `CallGraphBuilder` /
`UnitGenerator` in fresh interpreters with only `PYTHONHASHSEED` changed --
the same control shape `tests/parsers/c/test_c_include_map_determinism.py`
(PR #84) uses for the include-map half of this family.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[3]  # libs/openant-core (test is at tests/parsers/c/)
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

pytest.importorskip("tree_sitter_c")  # CallGraphBuilder builds a tree-sitter C Parser at init

from parsers.c.call_graph_builder import CallGraphBuilder  # noqa: E402
from parsers.c.unit_generator import FILE_BOUNDARY, UnitGenerator  # noqa: E402

SEEDS = ("0", "1", "2", "3", "4", "7", "11")

# Eight same-file callees, so the unsorted set has 8! orders available and the
# hash seed reliably moves it. Names are deliberately NOT in call-site order,
# so "sorted" is distinguishable from "source order" too.
CALLEES = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta")


def _flat_extractor_output():
    fns = {
        "main.c:main": {
            "name": "main", "file_path": "main.c",
            "code": "int main(void){ " + " ".join("%s();" % c for c in CALLEES) + " return 0; }",
        },
    }
    for c in CALLEES:
        fns["main.c:" + c] = {
            "name": c, "file_path": "main.c",
            "code": "void %s(void){ /* %s */ }" % (c, c),
        }
    return {"functions": fns, "includes": {"main.c": []}, "repository": "/r"}


DEPTH1 = ("m_one", "m_two", "m_three", "m_four", "m_five", "m_six")


def _depth_extractor_output():
    """main -> six depth-1 functions; m_one -> a_deep (depth 2).

    Lexicographically `a_deep` sorts FIRST of all seven, so a flat sort of the
    dependency list would hoist a depth-2 function above every depth-1 one --
    exactly what the issue forbids.
    """
    fns = {
        "main.c:main": {"name": "main", "file_path": "main.c",
                        "code": "int main(void){ " + " ".join("%s();" % c for c in reversed(DEPTH1)) + " return 0; }"},
        "main.c:m_one": {"name": "m_one", "file_path": "main.c",
                         "code": "void m_one(void){ a_deep(); }"},
        "main.c:a_deep": {"name": "a_deep", "file_path": "main.c",
                          "code": "void a_deep(void){ /* depth 2 */ }"},
    }
    for c in DEPTH1[1:]:
        fns["main.c:" + c] = {"name": c, "file_path": "main.c",
                              "code": "void %s(void){ /* leaf */ }" % c}
    return {"functions": fns, "includes": {"main.c": []}, "repository": "/r"}


def _primary_code(builder, unit_id="main.c:main"):
    """The recorded primary_code for one unit, through the real UnitGenerator."""
    ds = UnitGenerator(builder.export(), {"max_depth": 3}).generate_units()
    return [u for u in ds["units"] if u["id"] == unit_id][0]["code"]["primary_code"]


_DRIVER = (
    "import json, sys; sys.path.insert(0, %r);"
    "from parsers.c.call_graph_builder import CallGraphBuilder;"
    "from parsers.c.unit_generator import UnitGenerator;"
    "eo = %r;"
    "b = CallGraphBuilder(eo); b.build_call_graph();"
    "ug = UnitGenerator(b.export(), {'max_depth': 3});"
    "ds = ug.generate_units();"
    "u = [x for x in ds['units'] if x['id'] == 'main.c:main'][0];"
    "print(json.dumps({'edges': b.call_graph['main.c:main'],"
    " 'rev_keys': list(b.reverse_call_graph.keys()),"
    " 'deps': ug.get_dependencies('main.c:main'),"
    " 'direct_calls': u['metadata']['direct_calls'],"
    " 'primary_code': u['code']['primary_code']}))"
)


def _across_seeds(eo):
    """Run the product's own builder+generator once per PYTHONHASHSEED."""
    rows = []
    for seed in SEEDS:
        env = dict(os.environ, PYTHONHASHSEED=seed)
        out = subprocess.run(
            [sys.executable, "-B", "-c", _DRIVER % (str(CORE), eo)],
            capture_output=True, text=True, env=env, cwd=str(CORE),
        )
        assert out.returncode == 0, "driver failed (seed=%s): %s" % (seed, out.stderr)
        rows.append(json.loads(out.stdout.strip().splitlines()[-1]))
    return rows


# --------------------------------------------------------------------------
# WITNESSES -- these fail on the unsorted consumer at :850-851.
#
# Each one drives the product's own `CallGraphBuilder` TWICE: once in this
# process, and once per PYTHONHASHSEED in a fresh interpreter. The in-process
# object is the subject of the assertion; the seed sweep proves this process's
# own hash seed is not a special case.
# --------------------------------------------------------------------------

def test_c_edge_order_is_deterministic_across_hashseeds():
    """The per-function edge list must have ONE order in every process, and it
    must be the order this process's own CallGraphBuilder produces."""
    eo = _flat_extractor_output()
    builder = CallGraphBuilder(eo)
    builder.build_call_graph()
    here = tuple(builder.call_graph["main.c:main"])
    orders = {tuple(r["edges"]) for r in _across_seeds(eo)}
    assert orders == {here}, (
        "call_graph edge order varies with PYTHONHASHSEED: %d distinct order(s) over %d seeds, "
        "and this process produced %r"
        % (len(orders), len(SEEDS), list(here))
    )


def test_c_edge_order_is_the_sorted_order():
    """The named repair: the consumer emits the sorted order (Python's shape)."""
    builder = CallGraphBuilder(_flat_extractor_output())
    builder.build_call_graph()
    edges = builder.call_graph["main.c:main"]
    assert edges == sorted(edges), (
        "edge list is not sorted -- the set at :197/:818 is consumed unsorted at :850: %r" % (edges,)
    )


def test_dataset_direct_calls_metadata_is_deterministic_across_hashseeds():
    """`units[*].metadata.direct_calls` IS the builder's own edge list -- the
    recorded output contract moves with it."""
    eo = _flat_extractor_output()
    builder = CallGraphBuilder(eo)
    builder.build_call_graph()
    here = tuple(builder.call_graph["main.c:main"])
    seen = {tuple(r["direct_calls"]) for r in _across_seeds(eo)}
    assert seen == {here}, (
        "dataset metadata.direct_calls order varies with PYTHONHASHSEED: %d distinct over %d seeds "
        "(this process: %r)" % (len(seen), len(SEEDS), list(here))
    )


def test_reverse_call_graph_key_order_is_deterministic_across_hashseeds():
    """The reverse map's KEYS are created while iterating the unsorted forward
    list (:854-858), so call_graph.json's reverse section churns too."""
    eo = _flat_extractor_output()
    builder = CallGraphBuilder(eo)
    builder.build_call_graph()
    here = tuple(builder.reverse_call_graph.keys())
    seen = {tuple(r["rev_keys"]) for r in _across_seeds(eo)}
    assert seen == {here}, (
        "reverse_call_graph key order varies with PYTHONHASHSEED: %d distinct over %d seeds "
        "(this process: %r)" % (len(seen), len(SEEDS), list(here))
    )


def test_recorded_primary_code_is_reproducible_across_hashseeds():
    """#754's second consequence: two parses of the same source must record the
    SAME primary_code string, not a per-run permutation of the same blocks."""
    eo = _flat_extractor_output()
    builder = CallGraphBuilder(eo)
    builder.build_call_graph()
    here = _primary_code(builder)
    codes = {r["primary_code"] for r in _across_seeds(eo)}
    assert codes == {here}, (
        "recorded primary_code varies with PYTHONHASHSEED: %d distinct string(s) over %d seeds, "
        "and this process produced a %s one (blocks: %s)"
        % (len(codes), len(SEEDS),
           "matching" if here in codes else "further different",
           "same multiset, different order"
           if len({frozenset(c.split(FILE_BOUNDARY)) for c in codes | {here}}) == 1
           else "DIFFERENT blocks -- not a permutation")
    )


def test_inlined_dependency_order_is_the_sorted_order():
    """The inliner's append order follows the edge list, so after the repair the
    dependency blocks appear in sorted order at each depth."""
    builder = CallGraphBuilder(_flat_extractor_output())
    builder.build_call_graph()
    deps = UnitGenerator(builder.export(), {"max_depth": 3}).get_dependencies("main.c:main")
    assert deps == sorted(deps), (
        "depth-1-only fixture: the inlined dependency order is not sorted: %r" % (deps,)
    )


def test_depth_major_block_order_is_deterministic_across_hashseeds():
    """The same sweep over a MULTI-DEPTH fixture: one identical dependency
    order in every process, with the depth-2 function still last."""
    eo = _depth_extractor_output()
    builder = CallGraphBuilder(eo)
    builder.build_call_graph()
    here = tuple(UnitGenerator(builder.export(), {"max_depth": 3}).get_dependencies("main.c:main"))
    seen = {tuple(r["deps"]) for r in _across_seeds(eo)}
    assert seen == {here}, (
        "multi-depth dependency order varies with PYTHONHASHSEED: %d distinct over %d seeds "
        "(this process: %r)" % (len(seen), len(SEEDS), list(here))
    )
    assert list(here) == sorted("main.c:" + c for c in DEPTH1) + ["main.c:a_deep"], (
        "expected the six depth-1 functions sorted, then the depth-2 one: %r" % (list(here),)
    )


# --------------------------------------------------------------------------
# LOCK -- green on BOTH sides by design. It pins what the repair must NOT do.
# --------------------------------------------------------------------------

def test_get_dependencies_keeps_depth_major_shape_and_is_never_flat_sorted():
    """Green on BOTH sides, whatever the hash order: the depth-2 function comes
    after every depth-1 one, the set is complete, and the list is NEVER the
    flat-sorted order (which would put `a_deep` first)."""
    builder = CallGraphBuilder(_depth_extractor_output())
    builder.build_call_graph()
    deps = UnitGenerator(builder.export(), {"max_depth": 3}).get_dependencies("main.c:main")
    assert set(deps) == {"main.c:" + c for c in DEPTH1} | {"main.c:a_deep"}, (
        "the dependency SET moved: %r" % (deps,)
    )
    assert deps[-1] == "main.c:a_deep", (
        "depth-2 function must follow every depth-1 one (FIFO walk): %r" % (deps,)
    )
    assert deps != sorted(deps), (
        "the dependency list was flat-sorted -- that destroys the depth ordering: %r" % (deps,)
    )


def test_the_edge_set_is_unchanged_by_the_ordering_repair():
    """An ORDERING repair: the edge SET is constant across seeds and complete.
    This is the issue's own `edge_set_constant: true` -- no edge may drop."""
    eo = _flat_extractor_output()
    builder = CallGraphBuilder(eo)
    builder.build_call_graph()
    sets = {frozenset(r["edges"]) for r in _across_seeds(eo)}
    sets.add(frozenset(builder.call_graph["main.c:main"]))
    assert len(sets) == 1, "the edge SET moved across seeds -- not an ordering defect: %r" % (sets,)
    assert sets.pop() == {"main.c:" + c for c in CALLEES}, "an edge was dropped or invented"
