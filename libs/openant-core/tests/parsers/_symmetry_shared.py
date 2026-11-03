"""#702: the shared per-parser call-graph symmetry assertions.

Promoted from tests/parsers/c/test_c_callgraph_symmetry.py (the strongest of
the four pre-existing suites) so the five missing languages instantiate the
SAME invariants instead of five hand-rolled copies. The parametrisation is
over (language, fixture) — never over the assertions.

The three invariants reachability depends on (a parser that violates any of
them silently corrupts reachability — the BFS walks the reverse graph):

  1. NODE-REALNESS — every call_graph / reverse_call_graph key AND every
     callee/caller is a real function id (no phantom nodes);
  2. EXACT BIDIRECTIONAL CONSISTENCY — B in call_graph[A] iff A in
     reverse_call_graph[B];
  3. NO SELF-EDGES and no duplicate adjacency entries.

Plus the VACUOUS-GREEN GUARD the intake review taught: the invariants hold
trivially on an empty graph, so every suite must also assert its fixture
produced at least one edge (a fixture that stops parsing reads as "no edge"
and every symmetry check passes — the #747 control lesson).

Not collected by pytest (no ``test_`` prefix); imported by the per-language
symmetry suites.
"""

from __future__ import annotations


def assert_callgraph_symmetry(fids, fwd, rev, *, context=""):
    """The three invariants over (function-ids, call_graph, reverse_call_graph)."""
    pre = f"{context}: " if context else ""
    for k, callees in fwd.items():
        assert k in fids, f"{pre}call_graph key {k} is not a function id"
        assert len(callees) == len(set(callees)), f"{pre}duplicate forward edge from {k}"
        for c in callees:
            assert c in fids, f"{pre}callee {c} is not a function id"
            assert c != k, f"{pre}self-edge {k} -> {k}"
    for k, callers in rev.items():
        assert k in fids, f"{pre}reverse_call_graph key {k} is not a function id"
        assert len(callers) == len(set(callers)), f"{pre}duplicate reverse edge into {k}"
        for c in callers:
            assert c in fids, f"{pre}caller {c} is not a function id"
    fwd_edges = {(a, b) for a, bs in fwd.items() for b in bs}
    rev_edges = {(a, b) for b, as_ in rev.items() for a in as_}
    assert fwd_edges == rev_edges, (
        f"{pre}only-forward={fwd_edges - rev_edges}, "
        f"only-reverse={rev_edges - fwd_edges}")


def assert_no_self_edges(fwd, *, context=""):
    pre = f"{context}: " if context else ""
    for a, bs in fwd.items():
        assert a not in bs, f"{pre}self-edge {a} -> {a}"


def assert_graph_is_nonempty(fwd, *, context=""):
    """The vacuous-green guard: an empty graph satisfies every symmetry
    invariant trivially — a fixture that fails to parse produces one."""
    n = sum(len(bs) for bs in fwd.values())
    assert n > 0, (
        f"{context}: the fixture produced NO call-graph edges — either the "
        f"fixture stopped parsing (the #747 control lesson) or the parser "
        f"dropped every edge; the symmetry assertions above are vacuous "
        f"without this guard")
