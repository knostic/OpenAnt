"""Direct call of a callable instance dispatches to __call__ (reachability FN fix).

`h = H(); h(cmd)` invokes H.__call__, but the call-graph builder's ast.Name branch
did not consult `local_types` (the constructed-variable type map), so the edge to
H.__call__ was dropped while `h.method()` on the IDENTICAL binding resolved (the
ast.Attribute branch already uses local_types). Self-inconsistent -> a reachable
os.system sink inside __call__ was unreachable.
"""
import os
import tempfile

from parsers.python.function_extractor import FunctionExtractor
from parsers.python.call_graph_builder import CallGraphBuilder


def _build(src: str):
    d = os.path.realpath(tempfile.mkdtemp())
    with open(os.path.join(d, "m.py"), "w") as fh:
        fh.write(src)
    b = CallGraphBuilder(FunctionExtractor(d).extract_all())
    b.build_call_graph()
    return b


def _edges(b, caller_suffix):
    keys = [k for k in b.call_graph if k.endswith(caller_suffix)]
    return [e for k in keys for e in b.call_graph[k]]


_SRC = (
    "import os\n"
    "class H:\n"
    "    def __call__(self, c):\n        os.system(c)\n"
    "    def foo(self, c):\n        os.system(c)\n"
    "def run(cmd):\n    h = H()\n    h(cmd)\n"       # __call__ dispatch (was DROPPED)
    "def run2(cmd):\n    h = H()\n    h.foo(cmd)\n"   # attribute dispatch (already resolves)
)


def test_local_instance_call_dispatches_to_dunder_call():
    b = _build(_SRC)
    assert any("H.__call__" in e for e in _edges(b, ":run")), (
        f"h(cmd) on a local H() instance must dispatch to H.__call__; got {_edges(b, ':run')}"
    )


def test_attribute_dispatch_not_regressed():
    # No-regression: the sibling h.foo() path (which already consulted local_types)
    # must still resolve.
    b = _build(_SRC)
    assert any("H.foo" in e for e in _edges(b, ":run2")), (
        f"h.foo() must still resolve to H.foo; got {_edges(b, ':run2')}"
    )


def test_no_phantom_when_no_dunder_call():
    # Precision: a local instance whose class has NO __call__ must not invent an edge.
    b = _build(
        "class Plain:\n    def foo(self):\n        return 1\n"
        "def run(cmd):\n    p = Plain()\n    p(cmd)\n"
    )
    assert not any("Plain" in e for e in _edges(b, ":run")), (
        f"Plain() has no __call__; p() must not connect a phantom edge; got {_edges(b, ':run')}"
    )
