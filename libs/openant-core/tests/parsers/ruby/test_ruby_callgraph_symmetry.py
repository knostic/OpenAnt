"""Y-test (per-parser call-graph symmetry) for Ruby — #702.

The suite the #147-#153 wave promised as a follow-up and never shipped.
Asserts the shared invariants via tests/parsers/_symmetry_shared.py over the
REAL parse_repository pipeline, plus the construct pins the Ruby parser's
edge classes make load-bearing: a shared callee (bidirectional), a
define_method edge (the metaprogramming class), and an undeclared callee
(no phantom node).
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
    "lib.rb": """
        def helper(x)
          x + 1
        end

        def shared
        end

        def a
          helper(1)
          shared
        end

        def b
          helper(2)
          shared
        end

        class Widget
          define_method(:dyn) { helper(3) }
        end

        def driver
          a
          b
          missing_call
        end
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
        parse_repository(repo, out, language="ruby", processing_level="all",
                         skip_tests=True, name="r")
        return json.loads((Path(out) / "call_graph.json").read_text(encoding="utf-8"))


def _graph():
    cg = _cg(_REPO)
    return (set((cg.get("functions") or {}).keys()),
            cg.get("call_graph") or {}, cg.get("reverse_call_graph") or {})


def test_callgraph_symmetry_invariants():
    fids, fwd, rev = _graph()
    assert_callgraph_symmetry(fids, fwd, rev, context="ruby")
    assert_no_self_edges(fwd, context="ruby")
    assert_graph_is_nonempty(fwd, context="ruby")


def test_shared_callee_has_both_callers_in_reverse():
    fids, _, rev = _graph()
    shared = [k for k in fids if k.endswith(":shared")]
    a = [k for k in fids if k.endswith(":a")]
    b = [k for k in fids if k.endswith(":b")]
    assert shared and a and b, sorted(fids)
    assert set(rev[shared[0]]) == {a[0], b[0]}, (
        f"the shared callee's reverse set must carry both callers: "
        f"{rev[shared[0]]}")


def test_define_method_edge_is_present_and_symmetric():
    """The metaprogramming class: `define_method(:dyn) { helper(3) }` must
    produce the dyn -> helper edge in BOTH directions (the define_method
    body is a real caller; a parser that indexes the method but not its
    body edges corrupts reachability silently)."""
    fids, fwd, rev = _graph()
    # Ruby method ids are CLASS-QUALIFIED: `lib.rb:Widget.dyn` (a dot, not a
    # colon, before the method name)
    dyn = [k for k in fids if k.endswith(".dyn")]
    helper = [k for k in fids if k.endswith(":helper")]
    assert dyn and helper, sorted(fids)
    assert helper[0] in (fwd.get(dyn[0]) or []), (
        f"the define_method body's edge to helper is absent: "
        f"{fwd.get(dyn[0])}")
    assert dyn[0] in (rev.get(helper[0]) or []), (
        "the reverse side lost the define_method caller")


def test_undeclared_callee_is_not_a_phantom_node():
    fids, fwd, _ = _graph()
    assert not any(c.endswith(":missing_call") for c in fids), "phantom callee"
    for callees in fwd.values():
        assert not any(c.endswith(":missing_call") for c in callees)
