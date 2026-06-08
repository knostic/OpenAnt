"""Regression tests for two confirmed PHP CallGraphBuilder edge-resolution bugs.

Both drive the FULL real pipeline (FunctionExtractor -> CallGraphBuilder) on
real PHP source and assert that the expected call-graph *edge* is present,
matching the way the bugs were reproduced on the live parser.

[BUG 20] variable-function dataflow loss
    ``$f = 'helper'; $f();`` -- the call node is a ``function_call_expression``
    whose callee child is a ``variable_name`` (``$f``), not a ``name`` /
    ``qualified_name``. ``_resolve_function_call`` only matched ``name`` /
    ``identifier`` / ``qualified_name`` callees, so ``func_name`` stayed None
    and the call was dropped -- the edge caller -> helper was never emitted.
    Fix: when the callee is a ``variable_name``, follow a single unconditional
    string-literal binding (``$f = 'helper';``) in the caller's body and resolve
    the bound name.

[BUG 52] parent:: scoped-call dispatch
    ``parent::greet()`` -- the scope child is a ``relative_scope`` node (text
    ``parent``), not a ``name`` / ``qualified_name``. ``_resolve_scoped_call``
    only populated ``scope`` from ``name`` / ``qualified_name``, so both
    ``scope`` and ``method_name`` stayed None and the call was dropped. The
    pre-existing ``parent`` branch was unreachable dead code. ``parent``
    additionally cannot be resolved by the same-class self-call resolver: the
    method lives on the PARENT class, possibly in another file. Fix: read the
    ``relative_scope``; for ``parent`` look up the caller class's ``superclass``
    (class->parent index) and resolve the method on that parent class via the
    cross-file class-method resolver.
"""

import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder


def _build_graph(files: dict) -> dict:
    """Run the real PHP pipeline on {filename: source}; return the call_graph."""
    repo = tempfile.mkdtemp()
    for name, src in files.items():
        Path(repo, name).write_text(src)

    extractor = FunctionExtractor(repo)
    extractor_output = extractor.extract_all(list(files.keys()))

    builder = CallGraphBuilder(extractor_output)
    builder.build_call_graph()
    return builder.call_graph


# --- BUG 20: variable-function dataflow ------------------------------------

_VARFN_SOURCE = (
    "<?php\n"
    "function helper() {\n"
    "    return 42;\n"
    "}\n"
    "function caller() {\n"
    "    $f = 'helper';\n"
    "    return $f();\n"
    "}\n"
)


def test_variable_function_string_binding_emits_edge():
    """`$f = 'helper'; $f();` must produce a caller -> helper edge."""
    graph = _build_graph({"main.php": _VARFN_SOURCE})
    edges = graph.get("main.php:caller", [])
    assert "main.php:helper" in edges, (
        "variable-function edge dropped: $f='helper';$f() lost the edge to "
        "helper (callee is a variable_name; string binding not followed).\n"
        f"  caller edges: {edges!r}"
    )


def test_variable_function_conditional_binding_not_followed():
    """Precision guard: a non-unique / reassigned binding must NOT be resolved."""
    src = (
        "<?php\n"
        "function helper() { return 1; }\n"
        "function other() { return 2; }\n"
        "function caller() {\n"
        "    $f = 'helper';\n"
        "    $f = 'other';\n"
        "    return $f();\n"
        "}\n"
    )
    graph = _build_graph({"main.php": src})
    edges = graph.get("main.php:caller", [])
    # Ambiguous binding (two assignments): must not guess an edge.
    assert "main.php:helper" not in edges and "main.php:other" not in edges, (
        "ambiguous variable-function binding should not be resolved "
        f"(got edges {edges!r})"
    )


# --- BUG 52: parent:: scoped dispatch (cross-file) -------------------------


def test_parent_scoped_call_cross_file_emits_edge():
    """`parent::greet()` must resolve to the inherited method in ANOTHER file."""
    graph = _build_graph({
        "base.php": "<?php\nclass Base { public function greet(){ return 1; } }\n",
        "child.php": (
            "<?php\n"
            "class Child extends Base { public function run(){ "
            "return parent::greet(); } }\n"
        ),
    })
    edges = graph.get("child.php:Child.run", [])
    assert "base.php:Base.greet" in edges, (
        "parent:: edge dropped: parent::greet() did not resolve to the "
        "inherited Base.greet in another file (relative_scope unhandled / "
        "no class->parent cross-file lookup).\n"
        f"  Child.run edges: {edges!r}"
    )


def test_parent_scoped_call_same_file_emits_edge():
    """`parent::greet()` must also resolve when parent is in the same file."""
    src = (
        "<?php\n"
        "class Base { public function greet(){ return 1; } }\n"
        "class Child extends Base { public function run(){ "
        "return parent::greet(); } }\n"
    )
    graph = _build_graph({"p.php": src})
    edges = graph.get("p.php:Child.run", [])
    assert "p.php:Base.greet" in edges, (
        f"parent:: same-file edge dropped (got {edges!r})"
    )


# --- BUG 52 siblings: self:: / static:: ------------------------------------


def test_self_scoped_call_emits_edge():
    """Sibling check: self::other() resolves within the same class."""
    src = (
        "<?php\n"
        "class C {\n"
        "  public function a(){ return self::b(); }\n"
        "  public function b(){ return 1; }\n"
        "}\n"
    )
    graph = _build_graph({"c.php": src})
    edges = graph.get("c.php:C.a", [])
    assert "c.php:C.b" in edges, f"self:: edge dropped (got {edges!r})"


def test_static_scoped_call_emits_edge():
    """Sibling check: static::other() resolves within the same class."""
    src = (
        "<?php\n"
        "class C {\n"
        "  public function a(){ return static::b(); }\n"
        "  public function b(){ return 1; }\n"
        "}\n"
    )
    graph = _build_graph({"c.php": src})
    edges = graph.get("c.php:C.a", [])
    assert "c.php:C.b" in edges, f"static:: edge dropped (got {edges!r})"
