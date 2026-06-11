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
