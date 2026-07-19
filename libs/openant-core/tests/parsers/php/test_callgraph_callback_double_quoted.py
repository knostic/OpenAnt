"""Double-quoted (encapsed_string) callback targets must resolve (PR#147 FN).

_resolve_callback_arg only recognized single-quoted `string` nodes, so a double-quoted
callback -- `add_action('init', "handler")`, `spl_autoload_register(["Loader", "load"])`,
`call_user_func("Cls::m")` -- parsed as `encapsed_string` and was dropped, leaving the
registered handler (and its sink) unreachable. PR#147 already added encapsed_string support
in _string_literal_value; the callback resolver just did not use it.
"""
import os
import tempfile

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder


def _build(src: str):
    repo = os.path.realpath(tempfile.mkdtemp())
    p = os.path.join(repo, "plugin.php")
    with open(p, "w") as fh:
        fh.write(src)
    b = CallGraphBuilder(FunctionExtractor(repo).extract_all([p]))
    b.build_call_graph()
    return b


def _all_edges(b):
    return [e for edges in b.call_graph.values() for e in edges]


def test_framework_callback_double_quoted_name():
    b = _build(
        '<?php\n'
        'add_action("init", "cleanup");\n'
        'function cleanup(){ system("x"); }\n'
    )
    edges = _all_edges(b)
    assert any(e.endswith(":cleanup") for e in edges), (
        f"double-quoted framework callback not registered as an edge; edges={edges}"
    )


def test_builtin_callback_double_quoted_scoped():
    b = _build(
        '<?php\n'
        'call_user_func("Loader::load");\n'
        'class Loader { static function load(){ system("x"); } }\n'
    )
    edges = _all_edges(b)
    assert any(e.endswith(":Loader.load") for e in edges), (
        f"double-quoted Class::method callback not resolved; edges={edges}"
    )


def test_framework_callback_array_double_quoted():
    b = _build(
        '<?php\n'
        'spl_autoload_register(["Loader", "load"]);\n'
        'class Loader { static function load(){ system("x"); } }\n'
    )
    edges = _all_edges(b)
    assert any(e.endswith(":Loader.load") for e in edges), (
        f"double-quoted array callback not resolved; edges={edges}"
    )
