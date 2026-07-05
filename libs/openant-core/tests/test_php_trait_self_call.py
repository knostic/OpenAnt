"""Regression test for F12 sub-defect (3): trait-composition self-calls.

Sub-defects (1) [the `<?php ` re-parse prepend] and (2) [the `relative_scope`
branch for self::/static::/parent::] already ship on this branch. What remained
is the class->trait composition index: a class that pulls a method in via
`use TraitName;` had no edge from `$this->m()` / `self::m()` to the trait's
method, because `_resolve_self_call` only looked at methods physically declared
in the class body and never the methods of its used traits.

Two layers are exercised:
  * builder layer -- given a `traits` field on the class record, the
    CallGraphBuilder must fall back to the used traits' methods.
  * extractor layer -- the FunctionExtractor must populate that `traits` field
    from the in-class `use_declaration` node so the builder has data to use.

Loads both modules under UNIQUE importlib names (call_graph_builder /
function_extractor are basenames shared by every parser).
"""
import importlib.util
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


def _load(unique, relpath):
    spec = importlib.util.spec_from_file_location(unique, str(CORE / relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cgb = _load("php_call_graph_builder_trait", "parsers/php/call_graph_builder.py")
_fe = _load("php_function_extractor_trait", "parsers/php/function_extractor.py")
CallGraphBuilder = _cgb.CallGraphBuilder
FunctionExtractor = _fe.FunctionExtractor


def _build(funcs, classes=None, imports=None):
    b = CallGraphBuilder({"functions": funcs, "classes": classes or {}, "imports": imports or {},
                          "repository": "/r"})
    b.build_call_graph()
    return b


# F12 #3 builder layer: $this->g() and self::g() resolve into a used trait's method.
def test_trait_self_call_resolves_into_used_trait():
    b = _build({
        "a.php:C.f": {"name": "f", "file_path": "a.php", "class_name": "C",
                      "code": "function f() { $this->g(); }"},
        "a.php:C.h": {"name": "h", "file_path": "a.php", "class_name": "C",
                      "code": "function h() { self::g(); }"},
        "a.php:T.g": {"name": "g", "file_path": "a.php", "class_name": "T",
                      "code": "function g() {}"},
    }, classes={
        "a.php:C": {"name": "C", "file_path": "a.php", "superclass": None, "traits": ["T"]},
        "a.php:T": {"name": "T", "file_path": "a.php", "superclass": None, "traits": []},
    })
    assert b.call_graph.get("a.php:C.f") == ["a.php:T.g"], b.call_graph
    assert b.call_graph.get("a.php:C.h") == ["a.php:T.g"], b.call_graph


# F12 #3 extractor layer: the in-class `use T;` is captured onto the class record,
# and the full extract->build pipeline yields the trait edges from real source.
def test_extractor_captures_trait_use_and_builds_edges(tmp_path):
    src = (
        "<?php\n"
        "trait T { function g() {} }\n"
        "class C {\n"
        "    use T;\n"
        "    function f() { $this->g(); }\n"
        "    function h() { self::g(); }\n"
        "}\n"
    )
    f = tmp_path / "trait_case.php"
    f.write_text(src)

    ex = FunctionExtractor(str(tmp_path))
    out = ex.extract_all()

    # Class record must carry the used trait.
    c_key = next(k for k in out["classes"] if k.endswith(":C"))
    assert "T" in out["classes"][c_key].get("traits", []), out["classes"][c_key]

    b = CallGraphBuilder(out)
    b.build_call_graph()

    f_id = next(k for k in out["functions"]
                if out["functions"][k].get("name") == "f"
                and out["functions"][k].get("class_name") == "C")
    h_id = next(k for k in out["functions"]
                if out["functions"][k].get("name") == "h"
                and out["functions"][k].get("class_name") == "C")
    g_id = next(k for k in out["functions"]
                if out["functions"][k].get("name") == "g"
                and out["functions"][k].get("class_name") == "T")

    assert g_id in b.call_graph.get(f_id, []), b.call_graph.get(f_id)
    assert g_id in b.call_graph.get(h_id, []), b.call_graph.get(h_id)
