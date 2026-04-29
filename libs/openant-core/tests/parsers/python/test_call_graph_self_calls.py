"""Regression tests for the Python call graph builder.

Bug report (dbt-core scan, 2026-04-26):
    `core/dbt/task/run.py:ModelRunner._execute_model` appears unreachable in
    the parsed dataset, even though `ModelRunner.execute` calls
    `self._execute_model(...)` on line 359.

Root cause hypothesis:
    The function code stored by `function_extractor` preserves the original
    indentation (methods sit inside class blocks, so each line starts with
    4 spaces). `call_graph_builder._extract_calls_from_code` calls
    `ast.parse(code)` on that indented body, which raises `IndentationError`
    (a subclass of `SyntaxError`). The except clause catches `SyntaxError`
    and falls back to `_extract_calls_regex`, which has no `self.X()`
    handling — every `self.method()` call silently disappears from the
    call graph. The blast radius is "every method call inside every method
    of every Python codebase," which matches the dbt-core scan stats:
    72% of functions isolated, avg out-degree 0.31.

These tests pin both the unit-level behavior (ast.parse on indented code)
and the end-to-end behavior (self-method call appears in the graph).
"""

import ast
import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.call_graph_builder import CallGraphBuilder


def test_ast_parse_fails_on_indented_method_body():
    """Pin the underlying Python behavior: indented method bodies don't ast.parse.

    This isn't testing our code — it's documenting the trap that the call
    graph builder falls into. If this test ever starts failing (Python
    changes the rule, or someone wraps the code in a `with textwrap.dedent`),
    the call graph builder needs updating too.
    """
    indented = "    def execute(self):\n        return self._other()\n"
    with pytest.raises((IndentationError, SyntaxError)):
        ast.parse(indented)


def _make_extractor_output() -> dict:
    """Build a minimal extractor output that mirrors the dbt-core ModelRunner shape.

    Two methods on the same class, where one calls the other via `self.`.
    Critically, the `code` field preserves leading indentation — that's
    what the function extractor actually stores.
    """
    file_path = "core/dbt/task/run.py"
    return {
        "repository": "/tmp/fake",
        "imports": {file_path: {}},
        "classes": {
            f"{file_path}:ModelRunner": {
                "name": "ModelRunner",
                "file_path": file_path,
            }
        },
        "functions": {
            f"{file_path}:ModelRunner.execute": {
                "name": "execute",
                "qualified_name": "ModelRunner.execute",
                "file_path": file_path,
                "class_name": "ModelRunner",
                "unit_type": "method",
                "code": (
                    "    def execute(self, model, manifest):\n"
                    "        return self._execute_model(model, manifest)\n"
                ),
            },
            f"{file_path}:ModelRunner._execute_model": {
                "name": "_execute_model",
                "qualified_name": "ModelRunner._execute_model",
                "file_path": file_path,
                "class_name": "ModelRunner",
                "unit_type": "method",
                "code": (
                    "    def _execute_model(self, model, manifest):\n"
                    "        return None\n"
                ),
            },
        },
    }


def test_self_method_call_appears_in_forward_call_graph():
    """ModelRunner.execute calls self._execute_model — the edge must exist."""
    builder = CallGraphBuilder(_make_extractor_output())
    builder.build_call_graph()

    caller = "core/dbt/task/run.py:ModelRunner.execute"
    callee = "core/dbt/task/run.py:ModelRunner._execute_model"

    assert callee in builder.call_graph[caller], (
        f"Forward call graph missing self-call edge.\n"
        f"  Expected: {caller} -> {callee}\n"
        f"  Got: {builder.call_graph[caller]}"
    )


def test_self_method_call_appears_in_reverse_call_graph():
    """The callee must list its caller — otherwise reachability filtering drops it."""
    builder = CallGraphBuilder(_make_extractor_output())
    builder.build_call_graph()

    caller = "core/dbt/task/run.py:ModelRunner.execute"
    callee = "core/dbt/task/run.py:ModelRunner._execute_model"

    callers = builder.reverse_call_graph.get(callee, [])
    assert caller in callers, (
        f"Reverse call graph missing caller for {callee}.\n"
        f"  Expected to contain: {caller}\n"
        f"  Got: {callers}"
    )


def test_callee_is_not_isolated_in_statistics():
    """The dbt-core scan reported 72% isolated functions, driven by this bug.

    A two-method class with one self-call should produce ZERO isolated
    functions (one has an outgoing edge, the other has an incoming edge).
    """
    builder = CallGraphBuilder(_make_extractor_output())
    builder.build_call_graph()

    stats = builder.get_statistics()
    assert stats["isolated_functions"] == 0, (
        f"Expected 0 isolated functions in a two-method class with a "
        f"self-call, got {stats['isolated_functions']}.\n"
        f"  total_edges: {stats['total_edges']}\n"
        f"  call_graph: {builder.call_graph}\n"
        f"  reverse_call_graph: {builder.reverse_call_graph}"
    )
