"""Y-test (per-parser call-graph symmetry) for Rust.

Asserts exact BIDIRECTIONAL consistency — B in call_graph[A] iff A in
reverse_call_graph[B] — plus every graph key is a real function id. A parser that
populates one direction but not the other silently corrupts reachability (which
BFS-walks the reverse graph). Mirrors the swift/zig symmetry tests.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _helpers import build  # noqa: E402

_REPO = {
    "lib.rs": """
        pub trait Greeter {
            fn greet(&self) -> i32 { self.helper() }
            fn helper(&self) -> i32 { 1 }
        }
        pub struct Robot { level: i32 }
        impl Robot {
            pub fn new() -> Self { Robot { level: 0 } }
            pub fn boot(&self) -> i32 { self.level }
            pub fn run(&self) -> i32 {
                let r = Robot::new();   // Robot::new (assoc)
                r.boot()                // receiver.method via inferred type
            }
        }
        pub fn free_fn() -> i32 { 7 }
        pub fn caller() -> i32 { free_fn() + Robot::new().boot() }
    """,
    "main.rs": """
        fn main() {
            let r = Robot::new();
            r.run();
        }
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
