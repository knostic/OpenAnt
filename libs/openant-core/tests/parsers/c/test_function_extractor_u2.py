"""Regression tests for the C/C++ FunctionExtractor — U2 blind-fix batch.

Seven confirmed bugs (OpenAnt base 601e588 / 2e78d6a), all reproduced on the
real extractor (`FunctionExtractor(...).process_file(...)`):

  [15] out-of-line C++ constructor `Foo::Foo` recorded unit_type='method'
       instead of 'constructor' (qualified name compared whole to class_name).
  [14] out-of-line C++ destructor `Foo::~Foo` recorded 'method' not
       'destructor' (same qualified-vs-unqualified comparison bug).
  [32] C++ struct member fn dropped class_name / unit_type='function' — the
       tree walk only special-cased `class_specifier`, not `struct_specifier`.
  [33] file-scope C++ lambda (`auto f = [](){...}`) never extracted — it lives
       in a `declaration`/`init_declarator`/`lambda_expression`, not a
       `function_definition`.
  [35] C++ operator overload (`operator+`) never extracted — the
       `operator_name` declarator node was unhandled, name resolved to None.
  [39] explicit template specialization `g<int>` collided with the primary
       template `g` on func_id and silently overwrote it (template args
       dropped from the id).
  [40] free function inside a `namespace` wrongly carried class_name=<namespace>
       — namespace `::` qualifier conflated with a class qualifier.
"""

import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.c.function_extractor import FunctionExtractor


def _extract(filename: str, source: str) -> dict:
    """Run the real extractor on a temp source file; return the functions dict."""
    repo = Path(tempfile.mkdtemp()).resolve()
    fp = repo / filename
    fp.write_text(source)
    ex = FunctionExtractor(str(repo))
    ex.process_file(fp)
    return ex.functions


def _find(functions: dict, predicate):
    for fid, data in functions.items():
        if predicate(fid, data):
            return data
    return None


# ---------------------------------------------------------------- [15] ctor
def test_outofline_constructor_classified_constructor():
    functions = _extract("ctor.cpp", "Foo::Foo() { }\n")
    data = _find(functions, lambda fid, d: d["name"] == "Foo::Foo")
    assert data is not None, f"ctor not extracted; got {list(functions)}"
    assert data["unit_type"] == "constructor", (
        f"expected constructor, got {data['unit_type']!r}"
    )


# ---------------------------------------------------------------- [14] dtor
def test_outofline_destructor_classified_destructor():
    functions = _extract("dtor.cpp", "Foo::~Foo() { }\n")
    data = _find(functions, lambda fid, d: d["name"] == "Foo::~Foo")
    assert data is not None, f"dtor not extracted; got {list(functions)}"
    assert data["unit_type"] == "destructor", (
        f"expected destructor, got {data['unit_type']!r}"
    )


# ------------------------------------------------------------ [32] struct member
def test_struct_member_method_metadata():
    functions = _extract("m.cpp", "struct Point {\n  int dist() { return 0; }\n};\n")
    data = _find(functions, lambda fid, d: d["name"].endswith("dist"))
    assert data is not None, f"struct member not extracted; got {list(functions)}"
    assert data["unit_type"] == "method", (
        f"expected method, got {data['unit_type']!r}"
    )
    assert data["class_name"] == "Point", (
        f"expected class_name Point, got {data['class_name']!r}"
    )


# ------------------------------------------------------------ [32b] union member
def test_union_member_method_metadata():
    functions = _extract("u.cpp", "union U {\n  int tag() { return 0; }\n};\n")
    data = _find(functions, lambda fid, d: d["name"].endswith("tag"))
    assert data is not None, f"union member not extracted; got {list(functions)}"
    assert data["unit_type"] == "method", (
        f"expected method, got {data['unit_type']!r}"
    )
    assert data["class_name"] == "U", (
        f"expected class_name U, got {data['class_name']!r}"
    )


# ---------------------------------------------------------------- [33] lambda
def test_file_scope_lambda_extracted():
    functions = _extract(
        "m.cpp", "int ctrl() { return 0; }\nauto f = [](int x){ return x + 1; };\n"
    )
    data = _find(functions, lambda fid, d: d["name"] == "f")
    assert data is not None, f"lambda 'f' not extracted; got {list(functions)}"


# ---------------------------------------------------------------- [35] operator
def test_operator_overload_extracted():
    functions = _extract(
        "m.cpp",
        "int ctrl() { return 0; }\n\nclass V {\npublic:\n"
        "    int operator+(int x) { return x + 1; }\n};\n",
    )
    data = _find(functions, lambda fid, d: "operator" in d["name"])
    assert data is not None, f"operator+ not extracted; got {list(functions)}"
    assert data["class_name"] == "V", (
        f"expected class_name V, got {data['class_name']!r}"
    )


# ------------------------------------------------------------ [39] template spec
def test_template_specialization_distinct_from_primary():
    functions = _extract(
        "m.cpp",
        "int control(){return 1;}\n"
        "template<typename T> T g(T x){return x;}\n"
        "template<> int g<int>(int x){return x+1;}\n",
    )
    # Both the primary template `g` and the specialization `g<int>` must survive.
    spec = _find(functions, lambda fid, d: "g<int>" in fid or "g<int>" in d["name"])
    primary = _find(
        functions,
        lambda fid, d: (fid.endswith(":g") or d["name"] == "g"),
    )
    assert spec is not None, f"g<int> specialization absent; got {list(functions)}"
    assert primary is not None, f"primary g absent; got {list(functions)}"


# ------------------------------------------------------------ [40] namespace free fn
def test_namespace_free_function_no_class_name():
    functions = _extract(
        "m.cpp", "namespace ns {\nint freefunc(int x) {\n    return x;\n}\n}\n"
    )
    data = _find(functions, lambda fid, d: d["name"].endswith("freefunc"))
    assert data is not None, f"freefunc not extracted; got {list(functions)}"
    assert data["class_name"] is None, (
        f"expected class_name None for namespace free fn, got {data['class_name']!r}"
    )
    assert data["unit_type"] != "method", (
        f"namespace free fn must not be a method, got {data['unit_type']!r}"
    )
