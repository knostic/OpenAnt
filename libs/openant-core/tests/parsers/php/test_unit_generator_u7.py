"""Regression tests for the PHP unit generator's metadata field-contract.

Two confirmed producer->consumer field-drift bugs between
``parsers/php/function_extractor.py`` (PRODUCER, writes ``func_data``) and
``parsers/php/unit_generator.py`` (CONSUMER, ``UnitGenerator.create_unit``):

[BUG 28] ``is_static``
    The extractor computes ``func_data["is_static"]`` (function_extractor.py,
    ``_process_function_node``), but ``create_unit`` never copies it into the
    assembled unit's ``metadata``. The unit cannot tell static methods apart.

[BUG 43] ``namespace`` key-drift
    The extractor writes the declared namespace under the key
    ``func_data["namespace_name"]``, but ``create_unit`` reads
    ``func_data.get("namespace")`` -- a key-name mismatch -- so the unit's
    ``metadata["namespace"]`` is ALWAYS ``None``.

These tests drive the FULL real pipeline (FunctionExtractor ->
CallGraphBuilder -> UnitGenerator) on real PHP source, matching the way the
bugs were reproduced on the live parser.

Construct-isolation note (BUG 43):
    A *non-braced* ``namespace App\\Foo;`` declaration is, in the tree-sitter
    grammar, a sibling of the following ``class_declaration`` rather than its
    parent, and the extractor's traversal does NOT propagate the namespace to
    those siblings -- a SEPARATE extractor traversal bug that also yields a
    ``None`` namespace. To test the key-drift in ``create_unit`` in isolation
    (and avoid confounding it with that traversal bug), these tests use a
    *braced* ``namespace App\\Foo { ... }`` block, for which the extractor
    demonstrably produces a correct ``namespace_name``. See the module-level
    note in the report for the separate non-braced finding.
"""

import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.php.function_extractor import FunctionExtractor
from parsers.php.call_graph_builder import CallGraphBuilder
from parsers.php.unit_generator import UnitGenerator


def _generate_units(php_source: str, filename: str = "m.php") -> dict:
    """Run the real PHP pipeline on a source string; return units keyed by id."""
    repo = tempfile.mkdtemp()
    Path(repo, filename).write_text(php_source)

    extractor = FunctionExtractor(repo)
    extractor_output = extractor.extract_all([filename])

    builder = CallGraphBuilder(extractor_output)
    builder.build_call_graph()

    result = UnitGenerator(builder.export()).generate_units()
    return {u["id"]: u for u in result["units"]}


# --- BUG 43: namespace key-drift ------------------------------------------

_NS_SOURCE = (
    "<?php\n"
    "namespace App\\Foo {\n"
    "  class C {\n"
    "    public function pub(){ return 1; }\n"
    "  }\n"
    "}\n"
)


def test_namespace_reaches_unit_metadata():
    """The declared namespace must appear in the unit's metadata, not None."""
    units = _generate_units(_NS_SOURCE)
    unit = units["m.php:C.pub"]
    assert unit["metadata"]["namespace"] == "App\\Foo", (
        "Unit namespace dropped to None by key-drift "
        "(extractor writes 'namespace_name', create_unit read 'namespace').\n"
        f"  Got: {unit['metadata']['namespace']!r}"
    )


# --- BUG 28: is_static dropped --------------------------------------------

_STATIC_SOURCE = (
    "<?php\n"
    "class C {\n"
    "    public static function f() {\n"
    "        return 1;\n"
    "    }\n"
    "}\n"
)


def test_is_static_reaches_unit_metadata():
    """A static method must expose is_static==True on the unit."""
    units = _generate_units(_STATIC_SOURCE)
    unit = units["m.php:C.f"]
    assert unit["metadata"].get("is_static") is True, (
        "Unit is_static missing/false: extractor produced is_static=True but "
        "create_unit never copied it into the unit metadata.\n"
        f"  Got: {unit['metadata'].get('is_static')!r}"
    )


def test_non_static_method_is_static_false():
    """A non-static method must expose is_static==False (not None/missing)."""
    src = (
        "<?php\n"
        "class C {\n"
        "    public function g() { return 2; }\n"
        "}\n"
    )
    units = _generate_units(src)
    unit = units["m.php:C.g"]
    assert unit["metadata"].get("is_static") is False, (
        f"Expected is_static False for a non-static method, "
        f"got {unit['metadata'].get('is_static')!r}"
    )
