"""Local-type inference must not leak across nested scopes (poison FP fix).

`_collect_local_types` used `ast.walk(tree)` over the WHOLE caller source, flattening
every nested function/lambda/class scope into ONE variable->type map. A same-named
variable constructed in an INNER scope (`def inner(): x = Danger()`) then leaked its
type onto the OUTER scope's same-named variable, so a bare `x.run()` in the outer
frame -- where `x` is really an untyped parameter -- was misdirected to Danger.run.
That fabricates a phantom reachability edge (here: a path to an os.system sink).
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
    "class Danger:\n"
    "    def run(self, c):\n        os.system(c)\n"
    "class Widget:\n"
    "    def run(self, c):\n        return c\n"
    # outer.x is a PARAMETER (untyped here); the nested inner() constructs a
    # DIFFERENT variable also named x. Its Danger type must NOT leak onto outer.x.
    "def outer(x):\n"
    "    x.run('boom')\n"
    "    def inner():\n"
    "        x = Danger()\n"
    "        return x\n"
    "    inner()\n"
    # Same-scope construction must still resolve (no-regression).
    "def legit():\n"
    "    w = Widget()\n"
    "    w.run('ok')\n"
)


def test_inner_scope_type_does_not_poison_outer():
    b = _build(_SRC)
    edges = _edges(b, ":outer")
    assert not any("Danger.run" in e for e in edges), (
        f"outer.x is an untyped param; the nested inner() `x = Danger()` must not "
        f"leak onto it and fabricate an edge to Danger.run; got {edges}"
    )


def test_same_scope_construction_still_resolves():
    # No-regression: a var constructed in the caller's OWN scope must still dispatch.
    b = _build(_SRC)
    edges = _edges(b, ":legit")
    assert any("Widget.run" in e for e in edges), (
        f"legit()'s own-scope `w = Widget(); w.run()` must still resolve; got {edges}"
    )
