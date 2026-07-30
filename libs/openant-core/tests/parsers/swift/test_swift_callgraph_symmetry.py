"""Y-test (per-parser call-graph symmetry) for Swift.

Stronger than the minimal keys-subset check: asserts exact BIDIRECTIONAL
consistency (Sol §"Tests are too weak") — B in call_graph[A] iff A in
reverse_call_graph[B] — plus every graph key is a real function id. A parser that
populates one direction but not the other silently corrupts reachability (which
BFS-walks the reverse graph)."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build  # noqa: E402

_REPO = {
    "A.swift": """
        protocol P { func req() }
        extension P { func req() { helper() } }
        func helper() {}
        class Base { func base() {} }
        public class Impl: Base, P {
            public init() {}
            public func req() { self.base() }
            func run() { let x = Impl(); x.req() }
            var status: Int { return compute() }
            private func compute() -> Int { return 0 }
        }
    """,
    "main.swift": """
        let app = Impl()
        app.run()
    """,
}


def test_callgraph_keys_are_functions(tmp_path):
    _, cg = build(tmp_path, _REPO)
    fids = set(cg["functions"].keys())
    for k, callees in cg["call_graph"].items():
        assert k in fids, f"call_graph key {k} is not a function id"
        for c in callees:
            assert c in fids, f"callee {c} is not a function id"
    for k, callers in cg["reverse_call_graph"].items():
        assert k in fids
        for c in callers:
            assert c in fids


def test_callgraph_bidirectional_consistency(tmp_path):
    _, cg = build(tmp_path, _REPO)
    fwd = cg["call_graph"]
    rev = cg["reverse_call_graph"]

    fwd_edges = {(a, b) for a, bs in fwd.items() for b in bs}
    rev_edges = {(a, b) for b, as_ in rev.items() for a in as_}
    assert fwd_edges == rev_edges, (
        "forward and reverse call graphs disagree: "
        f"only-forward={fwd_edges - rev_edges}, only-reverse={rev_edges - fwd_edges}"
    )


def test_no_self_edges(tmp_path):
    _, cg = build(tmp_path, _REPO)
    for a, bs in cg["call_graph"].items():
        assert a not in bs, f"self-edge on {a}"
