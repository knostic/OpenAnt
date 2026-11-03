"""Y-test (per-parser call-graph symmetry) for JavaScript — #702.

The suite the #147-#153 wave promised as a follow-up and never shipped.
Asserts the shared invariants via tests/parsers/_symmetry_shared.py over the
REAL parse_repository pipeline, plus the construct pins the JS parser's edge
classes make load-bearing: a shared callee (bidirectional), an undeclared
callee (no phantom node), and a member call (declined, no phantom).
"""

import json
import os
import sys
import tempfile
from pathlib import Path

from core.parser_adapter import parse_repository

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from _symmetry_shared import (  # noqa: E402
    assert_callgraph_symmetry,
    assert_graph_is_nonempty,
    assert_no_self_edges,
)

_REPO = {
    "lib.js": """
        function helper(x) { return x + 1; }
        function shared() { }
        function a() { helper(1); shared(); }
        function b() { helper(2); shared(); }
        function leaf() { }
        function driver(obj) {
            a();
            b();
            leaf();
            obj.memberCall();
            missing();
        }
        module.exports = { a, b, driver };
    """,
}


def _cg(files):
    with tempfile.TemporaryDirectory() as _repo, tempfile.TemporaryDirectory() as out:
        repo = os.path.realpath(_repo)
        for rel, content in files.items():
            p = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
        parse_repository(repo, out, language="javascript",
                         processing_level="all", skip_tests=True, name="r")
        return json.loads((Path(out) / "call_graph.json").read_text(encoding="utf-8"))


def _graph():
    cg = _cg(_REPO)
    return (set((cg.get("functions") or {}).keys()),
            cg.get("call_graph") or {}, cg.get("reverse_call_graph") or {})


def test_callgraph_symmetry_invariants():
    fids, fwd, rev = _graph()
    assert_callgraph_symmetry(fids, fwd, rev, context="javascript")
    assert_no_self_edges(fwd, context="javascript")
    assert_graph_is_nonempty(fwd, context="javascript")


def test_shared_callee_has_both_callers_in_reverse():
    _, _, rev = _graph()
    callers = rev.get("lib.js:shared", [])
    assert set(callers) == {"lib.js:a", "lib.js:b"}, (
        f"the shared callee's reverse set must carry both callers: {callers}")


def test_undeclared_and_member_callees_are_not_phantom_nodes():
    """`missing()` is undeclared and `obj.memberCall()` is a member call the
    parser declines — neither may appear as a node or an edge (the phantom
    class corrupts reachability from the other direction)."""
    fids, fwd, _ = _graph()
    assert not any(c.endswith(":missing") for c in fids), "phantom missing()"
    assert not any(c.endswith(":memberCall") for c in fids), "phantom member call"
    for callees in fwd.values():
        assert not any(c.endswith(":missing") for c in callees)
        assert not any(c.endswith(":memberCall") for c in callees)
