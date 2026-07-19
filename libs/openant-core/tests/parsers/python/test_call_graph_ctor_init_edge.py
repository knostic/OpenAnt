"""Regression test for the constructor -> __init__ call-graph edge.

Bug (py-ctor-init-edge-drop, FAM-A):
    A bare Name call that names a repo class -- `Thing()` -- is a real call to
    that class's `__init__`, but `_resolve_call_node`'s ast.Name branch only
    tried function resolution (_resolve_local_function / _resolve_simple_call),
    both of which filter OUT methods (`class_name` set). A constructor call
    therefore resolved to None and the edge to `Thing.__init__` was dropped
    from reachability entirely -- `__init__` (and everything only it reaches)
    looked unreachable.

Fixing ADDS the missing edge; it never removes one (raises reachability).
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.call_graph_builder import CallGraphBuilder


def _ctor_extractor_output() -> dict:
    """A module-level factory function that constructs `Thing`, plus the class."""
    file_path = "m.py"
    return {
        "repository": "/tmp/fake",
        "imports": {file_path: {}},
        "classes": {f"{file_path}:Thing": {"name": "Thing", "file_path": file_path}},
        "functions": {
            f"{file_path}:make_thing": {
                "name": "make_thing",
                "qualified_name": "make_thing",
                "file_path": file_path,
                "unit_type": "function",
                "code": (
                    "def make_thing():\n"
                    "    return Thing()\n"
                ),
            },
            f"{file_path}:Thing.__init__": {
                "name": "__init__",
                "qualified_name": "Thing.__init__",
                "file_path": file_path,
                "class_name": "Thing",
                "unit_type": "method",
                "code": (
                    "    def __init__(self):\n"
                    "        self.x = 1\n"
                ),
            },
        },
    }


def test_constructor_call_emits_init_edge():
    builder = CallGraphBuilder(_ctor_extractor_output())
    builder.build_call_graph()

    caller = "m.py:make_thing"
    callee = "m.py:Thing.__init__"

    assert callee in builder.call_graph.get(caller, []), (
        f"Constructor call Thing() did not emit an edge to {callee}.\n"
        f"  caller edges: {builder.call_graph.get(caller)}"
    )
    assert caller in builder.reverse_call_graph.get(callee, []), (
        f"Reverse edge missing: {callee} does not list caller {caller}."
    )


def _collision_extractor_output() -> dict:
    """Import/ctor NAME COLLISION.

    a.py:  `from b import Widget` (b.Widget is a FUNCTION), `def caller(): return Widget()`
    b.py:  `def Widget(): ...`    (a module-level factory function)
    c.py:  `class Widget` with `__init__`

    `Widget()` in a.py is a call to the IMPORTED FUNCTION b.Widget, NOT to the
    unrelated class c.Widget's `__init__`. The true edge is a.py:caller ->
    b.py:Widget; the ctor resolver must NOT preempt it.
    """
    return {
        "repository": "/tmp/fake",
        # `from b import Widget` -> {name: module.name}
        "imports": {"a.py": {"Widget": "b.Widget"}, "b.py": {}, "c.py": {}},
        "classes": {"c.py:Widget": {"name": "Widget", "file_path": "c.py"}},
        "functions": {
            "a.py:caller": {
                "name": "caller",
                "qualified_name": "caller",
                "file_path": "a.py",
                "unit_type": "function",
                "code": "def caller():\n    return Widget()\n",
            },
            "b.py:Widget": {
                "name": "Widget",
                "qualified_name": "Widget",
                "file_path": "b.py",
                "unit_type": "function",
                "code": "def Widget():\n    return object()\n",
            },
            "c.py:Widget.__init__": {
                "name": "__init__",
                "qualified_name": "Widget.__init__",
                "file_path": "c.py",
                "class_name": "Widget",
                "unit_type": "method",
                "code": "    def __init__(self):\n        self.x = 1\n",
            },
        },
    }


def test_imported_factory_function_wins_over_same_named_class_ctor():
    """RED without the fallback-ordering fix.

    With the buggy order (ctor resolved BEFORE _resolve_simple_call), `Widget()`
    binds to c.py:Widget.__init__ (the unique cross-file class) and the true
    import edge to b.py:Widget is DROPPED -- an additive branch LOWERING recall
    via preemption (memory S2). The fix makes ctor a FALLBACK, so real import
    resolution wins.
    """
    builder = CallGraphBuilder(_collision_extractor_output())
    builder.build_call_graph()

    caller = "a.py:caller"
    true_edge = "b.py:Widget"           # the imported factory FUNCTION
    wrong_edge = "c.py:Widget.__init__"  # the same-named class ctor

    edges = builder.call_graph.get(caller, [])
    assert true_edge in edges, (
        f"true import edge {true_edge} was DROPPED (ctor preempted import "
        f"resolution). caller edges: {edges}"
    )
    assert wrong_edge not in edges, (
        f"ctor edge {wrong_edge} wrongly preempted the imported function. "
        f"caller edges: {edges}"
    )
