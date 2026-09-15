"""Y-test (per-parser call-graph symmetry) for C.

Asserts the call-graph invariants reachability depends on:
  - every call_graph / reverse_call_graph key AND callee/caller is a real
    function id (no phantom nodes);
  - exact BIDIRECTIONAL consistency — B in call_graph[A] iff A in
    reverse_call_graph[B] (reachability BFS-walks the reverse graph, so a
    one-directional edge silently corrupts it);
  - no self-edges (A -> A).

CallGraphBuilder consumes a plain extractor_output dict and builds the graph
directly (no repo fixture / extractor run), matching the other C tests. It
builds a tree-sitter C parser at init, so the module skips where tree_sitter_c
is unavailable. Mirrors tests/parsers/rust/test_rust_callgraph_symmetry.py.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[3]  # libs/openant-core
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

pytest.importorskip("tree_sitter_c")

from parsers.c.call_graph_builder import CallGraphBuilder  # noqa: E402
from parsers.c.function_extractor import FunctionExtractor  # noqa: E402


def _assert_symmetric(fids, fwd, rev):
    """The three call-graph invariants reachability depends on."""
    for k, callees in fwd.items():
        assert k in fids, f"call_graph key {k} is not a function id"
        assert len(callees) == len(set(callees)), f"duplicate forward edge from {k}"
        for c in callees:
            assert c in fids, f"callee {c} is not a function id"
            assert c != k, f"self-edge {k} -> {k}"
    for k, callers in rev.items():
        assert k in fids, f"reverse_call_graph key {k} is not a function id"
        assert len(callers) == len(set(callers)), f"duplicate reverse edge into {k}"
        for c in callers:
            assert c in fids
    fwd_edges = {(a, b) for a, bs in fwd.items() for b in bs}
    rev_edges = {(a, b) for b, as_ in rev.items() for a in as_}
    assert fwd_edges == rev_edges, (
        f"only-forward={fwd_edges - rev_edges}, only-reverse={rev_edges - fwd_edges}")


def _graph():
    """A small C program exercising free calls, a shared callee (two callers),
    a leaf, recursion (self-call), and a call to an undeclared function."""
    eo = {
        "functions": {
            "m.c:helper": {"name": "helper", "file_path": "m.c",
                           "code": "int helper(int x){ return x + 1; }"},
            "m.c:a": {"name": "a", "file_path": "m.c",
                      "code": "int a(int x){ return helper(x); }"},
            "m.c:b": {"name": "b", "file_path": "m.c",
                      "code": "int b(int x){ return helper(x) + a(x); }"},
            "m.c:fact": {"name": "fact", "file_path": "m.c",
                         "code": "int fact(int n){ return n <= 1 ? 1 : n * fact(n - 1); }"},
            "m.c:main": {"name": "main", "file_path": "m.c",
                         "code": "int main(void){ return a(1) + b(2) + fact(3) + missing(); }"},
        }
    }
    b = CallGraphBuilder(eo)
    b.build_call_graph()
    return set(eo["functions"].keys()), b.call_graph, b.reverse_call_graph


def test_callgraph_keys_and_edges_are_functions():
    fids, fwd, rev = _graph()
    for k, callees in fwd.items():
        assert k in fids, f"call_graph key {k} is not a function id"
        for c in callees:
            assert c in fids, f"callee {c} is not a function id"
    for k, callers in rev.items():
        assert k in fids, f"reverse_call_graph key {k} is not a function id"
        for c in callers:
            assert c in fids, f"caller {c} is not a function id"


def test_callgraph_bidirectional_consistency():
    fids, fwd, rev = _graph()
    fwd_edges = {(a, b) for a, bs in fwd.items() for b in bs}
    rev_edges = {(a, b) for b, as_ in rev.items() for a in as_}
    assert fwd_edges == rev_edges, (
        "forward and reverse call graphs disagree: "
        f"only-forward={fwd_edges - rev_edges}, only-reverse={rev_edges - fwd_edges}"
    )


def test_no_self_edges():
    _, fwd, _ = _graph()
    for a, bs in fwd.items():
        assert a not in bs, f"self-edge {a} -> {a}"


def test_undeclared_callee_is_not_an_edge():
    # `main` calls missing() which is not in the function set -> no phantom node.
    fids, fwd, _ = _graph()
    assert "m.c:missing" not in fids
    for callees in fwd.values():
        assert "m.c:missing" not in callees
        assert not any(c.endswith(":missing") for c in callees)


def test_shared_callee_has_both_callers_in_reverse():
    # helper is called by both a and b -> reverse must list both (bidirectional).
    _, _, rev = _graph()
    assert set(rev.get("m.c:helper", [])) == {"m.c:a", "m.c:b"}


def _pipeline_graph(src, filename="p.c"):
    """Run the REAL extractor -> builder pipeline on a .c file (as the rust/swift
    canonical symmetry tests do), so the invariant is proven on genuine extractor
    output — macro_aliases, callback-arg resolution, member-call decline — not a
    hand-shaped dict."""
    repo = os.path.realpath(tempfile.mkdtemp())
    (Path(repo) / filename).write_text(src)
    eo = FunctionExtractor(repo).extract_all(files=[filename])
    b = CallGraphBuilder(eo)
    b.build_call_graph()
    return set(eo["functions"].keys()), b.call_graph, b.reverse_call_graph, eo


# A fixture that exercises the edge-producing paths with documented bug history —
# callback-argument, member/field-expression call, and macro-alias resolution —
# so a future construct-specific fwd/rev desync (not just a wholesale break) is
# caught. (sol's empirical finding: the dict-only fixture misses these paths.)
_REAL = """
#define OPENSSL_malloc(s) CRYPTO_malloc(s)
int CRYPTO_malloc(int n){ return n; }
int my_cmp(const void *a, const void *b){ return 0; }
void shared(void){ }
void x(void){ shared(); }
void y(void){ shared(); }
void driver(struct S *obj, int *arr, int n){
    qsort(arr, n, sizeof(int), my_cmp);
    obj->cb();
    OPENSSL_malloc(4);
    x();
    y();
}
"""


def test_pipeline_symmetry_over_special_edge_paths():
    fids, fwd, rev, _ = _pipeline_graph(_REAL)
    _assert_symmetric(fids, fwd, rev)


def test_pipeline_member_call_is_not_a_phantom_node():
    # `obj->cb()` is a member / function-pointer call; the parser declines it, so
    # no phantom `cb` node/edge — and the caller's OTHER edges stay symmetric.
    fids, fwd, rev, _ = _pipeline_graph(_REAL)
    for callees in fwd.values():
        assert not any(c.endswith(":cb") for c in callees), "phantom obj->cb() edge"
    _assert_symmetric(fids, fwd, rev)


def test_no_duplicate_edges():
    # Defense-in-depth: the bidirectional check above is set-based and would not
    # catch a duplicated forward edge (call_graph[A] == [B, B]) that corrupts edge
    # counts while looking symmetric. This is unreachable today (the extractor
    # returns a set of calls), but a future refactor to a list would regress it
    # silently — so assert every adjacency list is duplicate-free.
    _, fwd, rev = _graph()
    for a, bs in fwd.items():
        assert len(bs) == len(set(bs)), f"duplicate forward edge from {a}: {bs}"
    for b, callers in rev.items():
        assert len(callers) == len(set(callers)), f"duplicate reverse edge into {b}: {callers}"
