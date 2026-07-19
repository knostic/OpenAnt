r"""Namespaced string callbacks must resolve to the real class method, not a truncated/false target.

PR#147 rerouted the callback resolver through `_string_literal_value`, which returned only the
FIRST `string_content` child of a string literal. tree-sitter splits an escaped literal like the
idiomatic `'App\\Sanitizer::run'` (double-backslash namespace separator) into
`string_content('App') + escape_sequence('\\') + string_content('Sanitizer::run')`, so the resolver
saw only `App` -- truncating the class/method away (a dropped or false edge). The double-quoted
variant fared worse: any `escape_sequence` child made `_string_literal_value` decline outright, so
the callback (and its sink) vanished entirely.

The fix concatenates + unescapes every chunk (so the name is the real PHP value `App\Sanitizer::run`)
and reduces the qualified class to its bare name so it resolves exactly like a plain callback.
Covers both quote styles and both single- and double-backslash source spellings.
"""
import os
import tempfile

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder

BS = chr(92)  # a single backslash


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


def _assert_resolves(callback_literal: str):
    # `Sanitizer::run` is the real sink; class lives under namespace App.
    src = (
        "<?php\n"
        "namespace App;\n"
        "class Sanitizer { static function run(){ system('x'); } }\n"
        f"add_action('init', {callback_literal});\n"
    )
    b = _build(src)
    edges = _all_edges(b)
    assert any(e.endswith(":Sanitizer.run") for e in edges), (
        f"namespaced callback {callback_literal} did not resolve to the real class method; edges={edges}"
    )
    # Must NOT produce the truncated / false `App` target.
    assert not any(e.endswith(":App") or e.endswith(".App") for e in edges), (
        f"namespaced callback {callback_literal} produced a truncated `App` target; edges={edges}"
    )


def test_single_quoted_double_backslash():
    # Idiomatic PHP: 'App\\Sanitizer::run' -> tree-sitter escape_sequence -> was truncated to `App`.
    _assert_resolves("'App" + BS + BS + "Sanitizer::run'")


def test_double_quoted_double_backslash():
    # "App\\Sanitizer::run" -> escape_sequence made _string_literal_value decline -> dropped edge.
    _assert_resolves('"App' + BS + BS + 'Sanitizer::run"')


def test_single_quoted_single_backslash():
    # 'App\Sanitizer::run' -> single string_content, but namespace prefix never matched the index.
    _assert_resolves("'App" + BS + "Sanitizer::run'")


def test_double_quoted_single_backslash():
    # "App\Sanitizer::run" -> single string_content, same namespace-prefix miss.
    _assert_resolves('"App' + BS + 'Sanitizer::run"')


def test_array_form_namespaced():
    # spl_autoload_register(['App\\Sanitizer', 'run']) -- array-form namespaced callback.
    src = (
        "<?php\n"
        "namespace App;\n"
        "class Sanitizer { static function run(){ system('x'); } }\n"
        "spl_autoload_register(['App" + BS + BS + "Sanitizer', 'run']);\n"
    )
    b = _build(src)
    edges = _all_edges(b)
    assert any(e.endswith(":Sanitizer.run") for e in edges), (
        f"array-form namespaced callback did not resolve; edges={edges}"
    )
