"""Double-quoted (encapsed_string) callback arguments must resolve to an edge (#147 sibling gap).

PR #147 taught `_string_literal_value` that double-quoted strings parse as `encapsed_string`,
but `_resolve_callback_arg` still only matched `value.type == 'string'` (single-quoted). So a
double-quoted callback -- array_map("cb", ...), add_action('h', "cb") -- was dropped from the
call graph, making the handler (and its sink) unreachable.
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


def test_double_quoted_builtin_callback_resolved():
    # array_map is a PHP builtin higher-order call; its callback here is double-quoted.
    b = _build(
        "<?php\n"
        'array_map("cleanse", [1,2,3]);\n'
        "function cleanse($x){ system($x); return $x; }\n"
    )
    edges = _all_edges(b)
    assert any(e.endswith(":cleanse") for e in edges), (
        f"double-quoted array_map callback must register an edge; edges={edges}"
    )


def test_double_quoted_framework_callback_resolved():
    b = _build(
        "<?php\n"
        'add_action("init", "cleanup");\n'
        "function cleanup(){ system('x'); }\n"
    )
    edges = _all_edges(b)
    assert any(e.endswith(":cleanup") for e in edges), (
        f"double-quoted framework callback must register an edge; edges={edges}"
    )


def test_double_quoted_static_array_callback_resolved():
    # ['Class', 'method'] array callback with double-quoted members.
    b = _build(
        "<?php\n"
        'array_map(["Sanitizer", "run"], [1]);\n'
        "class Sanitizer { static function run($x){ system($x); return $x; } }\n"
    )
    edges = _all_edges(b)
    assert any(e.endswith("Sanitizer.run") for e in edges), (
        f"double-quoted array static callback must register an edge; edges={edges}"
    )
