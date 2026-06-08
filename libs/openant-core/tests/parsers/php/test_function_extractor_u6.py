"""Regression tests for four confirmed PHP function_extractor.py bugs (U6).

All tests drive the REAL extractor (``FunctionExtractor.extract_all``) on a
temp ``.php`` file and assert on the resulting ``functions`` dict.

[BUG 7]  nested function: a ``function`` declared inside another function's
         body is never extracted (the function/method branches process the
         node but never push its body children).

[BUG 25] attribute start_line: a method carrying a PHP8 attribute
         ``#[Route(...)]`` reports its ``start_line`` at the attribute line
         (tree-sitter's ``method_declaration`` node spans the attribute_list),
         but the intended ``start_line`` is the ``public function`` declaration
         line.

[BUG 36] enum: methods of a PHP ``enum`` are dropped from class context --
         there is no ``enum_declaration`` traversal branch, so the method is
         recorded bare (``color``) instead of qualified (``Suit.color``) and
         the enum never appears in ``classes``.

[BUG 54] braceless namespace: under a braceless ``namespace App\\Svc;`` the
         following class is a SIBLING of the ``namespace_definition`` node (not
         a child), so the braceless branch -- which only recurses the namespace
         node's own children -- never reaches the class and its method's
         ``namespace_name`` stays ``None``.
"""

import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.php.function_extractor import FunctionExtractor


def _extract(php_source: str, filename: str = "u6.php") -> dict:
    """Run the real extractor on a source string; return the full export dict."""
    repo = tempfile.mkdtemp()
    Path(repo, filename).write_text(php_source)
    extractor = FunctionExtractor(repo)
    return extractor.extract_all([filename])


# --- BUG 7: nested function never extracted -------------------------------

_NESTED_SOURCE = (
    "<?php\n"
    "function outer() {\n"
    "    function inner() {\n"
    "        return 1;\n"
    "    }\n"
    "    return inner();\n"
    "}\n"
)


def test_nested_function_is_extracted():
    """A function declared inside another function's body must be extracted."""
    out = _extract(_NESTED_SOURCE)
    funcs = out["functions"]
    assert "u6.php:outer" in funcs, "outer must still be extracted"
    assert "u6.php:inner" in funcs, (
        "Nested function 'inner' is missing -- the function branch never "
        "pushes body children.\n"
        f"  functions keys: {sorted(funcs)}"
    )


# --- BUG 25: attribute start_line off-by-one ------------------------------

_ATTRIBUTE_SOURCE = (
    "<?php\n"
    "class Foo {\n"
    '    #[Route("/x")]\n'
    "    public function bar() {\n"
    "        return 1;\n"
    "    }\n"
    "}\n"
)


def test_attribute_method_start_line():
    """A method with a #[Attribute] reports start_line at the declaration line,
    not at the attribute line."""
    out = _extract(_ATTRIBUTE_SOURCE, filename="m.php")
    funcs = out["functions"]
    assert "m.php:Foo.bar" in funcs, f"Foo.bar missing: {sorted(funcs)}"
    # The 'public function bar' line is line 4; the attribute is line 3.
    assert funcs["m.php:Foo.bar"]["start_line"] == 4, (
        "Attribute-decorated method start_line should be the declaration line "
        "(4), not the attribute line (3).\n"
        f"  Got: {funcs['m.php:Foo.bar']['start_line']}"
    )


# --- BUG 36: enum methods dropped from class context ----------------------

_ENUM_SOURCE = (
    "<?php\n"
    "function control_fn() { return 1; }\n"
    "\n"
    "enum Suit: string {\n"
    "    case Hearts = 'H';\n"
    '    public function color(): string { return "red"; }\n'
    "}\n"
)


def test_enum_method_is_qualified():
    """An enum method must be recorded under its qualified id (Suit.color),
    with class_name=Suit, and the enum must appear in classes."""
    out = _extract(_ENUM_SOURCE, filename="t.php")
    funcs = out["functions"]
    assert "t.php:Suit.color" in funcs, (
        "Enum method 'Suit.color' missing -- no enum_declaration branch sets "
        "class context.\n"
        f"  functions keys: {sorted(funcs)}"
    )
    assert funcs["t.php:Suit.color"]["class_name"] == "Suit"
    assert "t.php:Suit" in out["classes"], (
        "Enum 'Suit' should be registered in classes.\n"
        f"  classes keys: {sorted(out['classes'])}"
    )


# --- BUG 54: braceless namespace not propagated to sibling class ----------

_BRACELESS_NS_SOURCE = (
    "<?php\n"
    "namespace App\\Svc;\n"
    "class Foo { public function open() { return 2; } }\n"
)


def test_braceless_namespace_propagates_to_method():
    """A method under a braceless 'namespace App\\Svc;' must carry that
    namespace_name, not None."""
    out = _extract(_BRACELESS_NS_SOURCE, filename="f.php")
    funcs = out["functions"]
    assert "f.php:Foo.open" in funcs, f"Foo.open missing: {sorted(funcs)}"
    assert funcs["f.php:Foo.open"]["namespace_name"] == "App\\Svc", (
        "Braceless namespace dropped to None -- the class is a SIBLING of the "
        "namespace_definition, not a child, and is never reached by the "
        "braceless branch.\n"
        f"  Got: {funcs['f.php:Foo.open']['namespace_name']!r}"
    )
