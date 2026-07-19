"""Uniqueness-gate must not resolve a bare cross-file call to a module-level lambda.

Bug (py-module-lambda-uniqgate-poison, S2/FAM-A): `_resolve_simple_call` step 3
(`call_graph_builder.py:466-470`) resolves a simple name to its single same-named
candidate across ALL files:

    candidates = self.functions_by_name.get(func_name, [])
    candidates = [c for c in candidates if not ...class_name]
    if len(candidates) == 1:
        return candidates[0]

A module-level lambda (`handler = lambda ...`, emitted with is_lambda=True) is a
MODULE-LOCAL binding: it is reachable only from its own file (step 1, same-file) or
via an explicit `import` (step 2). A bare cross-file call `handler()` in another
file that never imported it must NOT resolve to that lambda -- doing so poisons the
edge with a spurious/wrong target. This is the S2 class: the additive lambda
emission fed a name into the uniqueness gate that the gate then mis-resolves.

Fix: exclude is_lambda candidates from the step-3 cross-file uniqueness gate.
Same-file (step 1) and imported (step 2) lambda resolution are untouched.
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.call_graph_builder import CallGraphBuilder


def _build(functions: dict, imports: dict) -> CallGraphBuilder:
    b = CallGraphBuilder({"repository": "/tmp/fake", "imports": imports,
                          "classes": {}, "functions": functions})
    b.build_call_graph()
    return b


def _fn(file_path, name, code, class_name=None, is_lambda=False):
    d = {"name": name,
         "qualified_name": (f"{class_name}.{name}" if class_name else name),
         "file_path": file_path, "class_name": class_name,
         "unit_type": "function", "code": code}
    if is_lambda:
        d["is_lambda"] = True
    return d


# ---------- PRECISION: the poison edge must NOT appear ----------

def test_no_poison_edge_to_module_lambda_cross_file():
    """A bare cross-file call must NOT resolve to a module-level lambda."""
    fns = {
        "main.py:run": _fn("main.py", "run", "def run():\n    return handler()\n"),
        "a.py:handler": _fn("a.py", "handler", "handler = lambda x: x\n", is_lambda=True),
    }
    b = _build(fns, imports={})  # main.py never imports handler
    edges = b.call_graph.get("main.py:run", [])
    assert "a.py:handler" not in edges, (
        f"poison edge to module-level lambda a.py:handler: {edges}")


# ---------- RECALL: legitimate lambda resolution paths must survive ----------

def test_same_file_lambda_call_still_resolves():
    """Step-1 same-file resolution of a module-level lambda is untouched."""
    fns = {
        "a.py:run": _fn("a.py", "run", "def run():\n    return handler()\n"),
        "a.py:handler": _fn("a.py", "handler", "handler = lambda x: x\n", is_lambda=True),
    }
    b = _build(fns, imports={})
    edges = b.call_graph.get("a.py:run", [])
    assert "a.py:handler" in edges, (
        f"same-file lambda edge lost: {edges}")


def test_imported_lambda_call_still_resolves():
    """Step-2 import resolution of a module-level lambda is untouched."""
    fns = {
        "main.py:run": _fn("main.py", "run", "def run():\n    return handler()\n"),
        "a.py:handler": _fn("a.py", "handler", "handler = lambda x: x\n", is_lambda=True),
    }
    b = _build(fns, imports={"main.py": {"handler": "a.handler"}})
    edges = b.call_graph.get("main.py:run", [])
    assert "a.py:handler" in edges, (
        f"imported lambda edge lost: {edges}")


# ---------- RECALL: a real def uniquely named still resolves cross-file ----------

def test_unique_real_def_still_resolves_cross_file():
    """Excluding lambdas must not break the uniqueness gate for real defs."""
    fns = {
        "main.py:run": _fn("main.py", "run", "def run():\n    return helper()\n"),
        "u.py:helper": _fn("u.py", "helper", "def helper():\n    return 1\n"),
    }
    b = _build(fns, imports={})
    edges = b.call_graph.get("main.py:run", [])
    assert "u.py:helper" in edges, (
        f"unique-def cross-file edge lost: {edges}")
