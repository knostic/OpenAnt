"""Namespaced static-method string callback must resolve to its target (reachability FN fix).

A single-quoted callback like 'App\\Sanitizer::run' carries a namespace-qualified class name,
but the class index (methods_by_class) is keyed by BARE class name. The callback resolver funneled
the qualified name straight into _resolve_class_call without stripping the namespace prefix, so the
lookup missed -> the handler (and its sink) was unreachable. Sibling call sites (_resolve_new,
_resolve_scoped_call) already stripped the prefix; the callback path did not.
"""
import os
import tempfile

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder


def _build(src: str):
    repo = os.path.realpath(tempfile.mkdtemp())
    p = os.path.join(repo, "app.php")
    with open(p, "w") as fh:
        fh.write(src)
    b = CallGraphBuilder(FunctionExtractor(repo).extract_all([p]))
    b.build_call_graph()
    return b


def _all_edges(b):
    return [e for edges in b.call_graph.values() for e in edges]


def test_namespaced_static_string_callback_resolves():
    # 'App\Sanitizer::run' passed to a builtin higher-order call.
    b = _build(
        "<?php\n"
        "namespace App;\n"
        "class Sanitizer {\n"
        "  public static function run($v){ system($v); return $v; }\n"
        "}\n"
        "call_user_func('App\\\\Sanitizer::run', $_GET['x']);\n"
    )
    edges = _all_edges(b)
    assert any(e.endswith("Sanitizer.run") for e in edges), (
        f"namespaced static callback 'App\\Sanitizer::run' dropped; edges={edges}"
    )


def test_namespaced_static_array_callback_resolves():
    # ['App\Sanitizer', 'run'] array-form static callback also carries the namespace prefix.
    b = _build(
        "<?php\n"
        "namespace App;\n"
        "class Sanitizer {\n"
        "  public static function run($v){ system($v); return $v; }\n"
        "}\n"
        "array_map(['App\\\\Sanitizer', 'run'], $items);\n"
    )
    edges = _all_edges(b)
    assert any(e.endswith("Sanitizer.run") for e in edges), (
        f"namespaced array static callback ['App\\Sanitizer','run'] dropped; edges={edges}"
    )
