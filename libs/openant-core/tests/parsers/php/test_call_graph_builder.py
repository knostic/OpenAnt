r"""PHP call-graph resolution: a bare function call must not resolve across namespaces.

`_resolve_simple_call` consulted class_name but never namespace_name, so a bare
`helper()` from namespace App\Other leaked an edge to App\Utils\helper.

The module basename ``call_graph_builder.py`` recurs across every parser, so the
PHP builder is loaded under a UNIQUE importlib name.
"""
import importlib.util
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[3]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


def _load(unique_name, relpath):
    spec = importlib.util.spec_from_file_location(unique_name, str(CORE / relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cgb = _load("php_call_graph_builder_isolated", "parsers/php/call_graph_builder.py")
CallGraphBuilder = _cgb.CallGraphBuilder


def _build(funcs):
    b = CallGraphBuilder({"functions": funcs, "classes": {}, "imports": {}, "repository": "/r"})
    b.build_call_graph()
    return b


def test_bare_call_does_not_leak_across_namespaces():
    """A bare helper() in App\\Other must NOT edge to App\\Utils\\helper.

    Driven through the full call-graph build so the caller's namespace is threaded
    exactly as in production; the base builder ignores namespace_name and leaks the
    edge.
    """
    funcs = {
        "utils.php:helper": {
            "name": "helper", "file_path": "utils.php",
            "class_name": None, "namespace_name": "App\\Utils",
            "code": "<?php function helper($x) { return $x; }",
        },
        "other.php:caller": {
            "name": "caller", "file_path": "other.php",
            "class_name": None, "namespace_name": "App\\Other",
            "code": "<?php function caller() { helper(1); }",
        },
    }
    b = _build(funcs)
    assert b.call_graph.get("other.php:caller") == [], (
        f"namespace leak: App\\Other caller resolved to a App\\Utils function: {b.call_graph}"
    )


def test_bare_call_resolves_within_same_namespace():
    """Guard: a bare helper() within App\\Utils still resolves (no over-tightening)."""
    funcs = {
        "utils.php:helper": {
            "name": "helper", "file_path": "utils.php",
            "class_name": None, "namespace_name": "App\\Utils",
            "code": "<?php function helper($x) { return $x; }",
        },
        "consumer.php:caller": {
            "name": "caller", "file_path": "consumer.php",
            "class_name": None, "namespace_name": "App\\Utils",
            "code": "<?php function caller() { helper(1); }",
        },
    }
    b = _build(funcs)
    assert b.call_graph.get("consumer.php:caller") == ["utils.php:helper"], (
        f"same-namespace bare call must still resolve: {b.call_graph}"
    )


def test_this_call_to_builtin_named_same_class_method_resolves():
    """$this->count() must edge to the same-class count() method (B2).

    A same-class method named like a PHP builtin (count/next/key) was dropped by a
    premature _is_builtin() short-circuit in _resolve_member_call before it could
    route to _resolve_self_call. Driven through the real builder on real PHP source.
    """
    funcs = {
        "bag.php:Bag::count": {
            "name": "count", "file_path": "bag.php", "class_name": "Bag",
            "namespace_name": None,
            "code": "function count() { return 1; }",
        },
        "bag.php:Bag::total": {
            "name": "total", "file_path": "bag.php", "class_name": "Bag",
            "namespace_name": None,
            "code": "function total() { return $this->count() * 2; }",
        },
    }
    b = _build(funcs)
    assert b.call_graph.get("bag.php:Bag::total") == ["bag.php:Bag::count"], (
        f"$this->count() must resolve to same-class count(): {b.call_graph}"
    )


def test_scoped_call_to_builtin_named_same_class_method_resolves():
    """self::count() must edge to the same-class count() method (B2).

    Same bug in _resolve_scoped_call: the premature _is_builtin() short-circuit
    dropped self::/static::/Class:: calls to a builtin-named own method.
    """
    funcs = {
        "bag.php:Bag::count": {
            "name": "count", "file_path": "bag.php", "class_name": "Bag",
            "namespace_name": None,
            "code": "function count() { return 1; }",
        },
        "bag.php:Bag::total": {
            "name": "total", "file_path": "bag.php", "class_name": "Bag",
            "namespace_name": None,
            "code": "function total() { return self::count() * 2; }",
        },
    }
    b = _build(funcs)
    assert b.call_graph.get("bag.php:Bag::total") == ["bag.php:Bag::count"], (
        f"self::count() must resolve to same-class count(): {b.call_graph}"
    )


def test_same_file_name_colliding_globals_all_resolved():
    """Two method-nested `function g(){}` in one file (re-keyed to file-scope
    globals with de-collided ids `app.php:g` / `app.php:g#L9`) must BOTH receive an
    edge from a bare `g()` — not just the first.

    `_resolve_simple_call` returns the first same-file global, so both Alpha::run
    and Beta::run resolved only to `app.php:g`; `app.php:g#L9` (and its sink
    subtree) was orphaned — a reachability false negative. The resolution must
    over-approximate to every same-name same-namespace file-scope global.
    """
    funcs = {
        "app.php:Alpha.run": {
            "name": "run", "file_path": "app.php",
            "class_name": "Alpha", "namespace_name": None,
            "code": "<?php function run() { g(); }",
        },
        "app.php:Beta.run": {
            "name": "run", "file_path": "app.php",
            "class_name": "Beta", "namespace_name": None,
            "code": "<?php function run() { g(); }",
        },
        "app.php:g": {
            "name": "g", "file_path": "app.php",
            "class_name": None, "namespace_name": None,
            "code": "<?php function g() { sinkC(); }",
        },
        "app.php:g#L9": {
            "name": "g", "file_path": "app.php",
            "class_name": None, "namespace_name": None,
            "code": "<?php function g() { sinkD(); }",
        },
        "app.php:sinkC": {
            "name": "sinkC", "file_path": "app.php",
            "class_name": None, "namespace_name": None, "code": "<?php function sinkC() {}",
        },
        "app.php:sinkD": {
            "name": "sinkD", "file_path": "app.php",
            "class_name": None, "namespace_name": None, "code": "<?php function sinkD() {}",
        },
    }
    b = _build(funcs)
    assert set(b.call_graph.get("app.php:Alpha.run", [])) == {"app.php:g", "app.php:g#L9"}, (
        f"Alpha::run must edge to BOTH colliding globals: {b.call_graph.get('app.php:Alpha.run')}"
    )
    assert set(b.call_graph.get("app.php:Beta.run", [])) == {"app.php:g", "app.php:g#L9"}, (
        f"Beta::run must edge to BOTH colliding globals: {b.call_graph.get('app.php:Beta.run')}"
    )
