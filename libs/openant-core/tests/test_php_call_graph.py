"""Regression tests for defects in parsers/php/call_graph_builder.py + function_extractor.py.

#1 (tag): the re-parser used the tag-requiring grammar on tag-stripped function bodies, so
   the whole PHP call graph was empty (0 edges). Fixed by language_php_only().
#2 (callbacks): higher-order builtins (call_user_func, array_map,
   ...) dropped their callback argument. Now resolved via CALLBACK_BUILTINS.
#5 (new): `new Foo()` (object_creation_expression) was not traversed -> __construct untracked.
#6 (parent::): parent:: was resolved in the caller's own class, not the superclass.
#4 (import): use/require resolution used an unanchored `import_name in file_path` substring.
#7 (case): _is_builtin compared case-sensitively though PHP names are case-insensitive.
#3 (use node type): _extract_imports checked `use_declaration` but tree-sitter-php emits
   `namespace_use_declaration`, so use-imports were never recorded.
(#8: `indirect_calls` is a phantom field -- documented, no code.)

Loads both modules under UNIQUE importlib names (call_graph_builder / function_extractor are basenames
shared by every parser).
"""
import importlib.util
import sys
from pathlib import Path

import tree_sitter_php as _tsphp
from tree_sitter import Language, Parser

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


def _load(unique, relpath):
    spec = importlib.util.spec_from_file_location(unique, str(CORE / relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_cgb = _load("php_call_graph_builder_isolated", "parsers/php/call_graph_builder.py")
_fe = _load("php_function_extractor_isolated", "parsers/php/function_extractor.py")
CallGraphBuilder = _cgb.CallGraphBuilder
FunctionExtractor = _fe.FunctionExtractor


def _build(funcs, classes=None, imports=None):
    b = CallGraphBuilder({"functions": funcs, "classes": classes or {}, "imports": imports or {},
                          "repository": "/r"})
    b.build_call_graph()
    return b


# #1 tag-grammar: tagless function bodies now parse -> edges exist at all
def test_tagless_body_produces_edges():
    b = _build({
        "a.php:a": {"name": "a", "file_path": "a.php", "class_name": None, "code": "function a() { b(); }"},
        "a.php:b": {"name": "b", "file_path": "a.php", "class_name": None, "code": "function b() {}"},
    })
    assert b.call_graph.get("a.php:a") == ["a.php:b"], b.call_graph


# #2 callbacks: call_user_func('cb') and array_map('cb2', ...) resolve their callback arg
def test_callback_builtins_resolve_callback_arg():
    b = _build({
        "f.php:f": {"name": "f", "file_path": "f.php", "class_name": None,
                    "code": "function f() { call_user_func('cb'); array_map('cb2', $x); }"},
        "f.php:cb": {"name": "cb", "file_path": "f.php", "class_name": None, "code": "function cb() {}"},
        "f.php:cb2": {"name": "cb2", "file_path": "f.php", "class_name": None, "code": "function cb2($v) {}"},
    })
    edges = set(b.call_graph.get("f.php:f", []))
    assert edges == {"f.php:cb", "f.php:cb2"}, edges


# #5 new Foo() -> Foo::__construct
def test_new_resolves_to_construct():
    b = _build({
        "a.php:f": {"name": "f", "file_path": "a.php", "class_name": None, "code": "function f() { new Foo(); }"},
        "a.php:Foo.__construct": {"name": "__construct", "file_path": "a.php", "class_name": "Foo",
                                  "code": "function __construct() {}"},
    }, classes={"a.php:Foo": {"name": "Foo", "file_path": "a.php", "superclass": None}})
    assert b.call_graph.get("a.php:f") == ["a.php:Foo.__construct"], b.call_graph


# #6 parent::m() resolves in the superclass
def test_parent_resolves_in_superclass():
    b = _build({
        "a.php:Child.doit": {"name": "doit", "file_path": "a.php", "class_name": "Child",
                             "code": "function doit() { parent::base_m(); }"},
        "a.php:Base.base_m": {"name": "base_m", "file_path": "a.php", "class_name": "Base",
                              "code": "function base_m() {}"},
    }, classes={
        "a.php:Child": {"name": "Child", "file_path": "a.php", "superclass": "Base"},
        "a.php:Base": {"name": "Base", "file_path": "a.php", "superclass": None},
    })
    assert b.call_graph.get("a.php:Child.doit") == ["a.php:Base.base_m"], b.call_graph


# #6 parent:: with a NAMESPACED superclass (extends App\Base) resolves by the unqualified class name
def test_parent_resolves_namespaced_superclass():
    b = _build({
        "a.php:Child.doit": {"name": "doit", "file_path": "a.php", "class_name": "Child",
                             "code": "function doit() { parent::base_m(); }"},
        "b.php:Base.base_m": {"name": "base_m", "file_path": "b.php", "class_name": "Base",
                              "code": "function base_m() {}"},
    }, classes={
        "a.php:Child": {"name": "Child", "file_path": "a.php", "superclass": "App\\Base"},
        "b.php:Base": {"name": "Base", "file_path": "b.php", "superclass": None},
    })
    assert b.call_graph.get("a.php:Child.doit") == ["b.php:Base.base_m"], b.call_graph


# #7 _is_builtin is case-insensitive (PHP function names are case-insensitive)
def test_is_builtin_case_insensitive():
    b = CallGraphBuilder({"functions": {}, "classes": {}, "imports": {}, "repository": "/r"})
    assert b._is_builtin("CALL_USER_FUNC") is True
    assert b._is_builtin("StrLen") is True
    assert b._is_builtin("myCustomFunc") is False


# #4 import resolution matches the import FILE name, not an unanchored substring
def test_import_match_anchored_not_substring():
    # 'app/BarBaz/x.php' contains the substring 'Bar' but is NOT Bar.php; the real target is sub/Bar.php.
    b = CallGraphBuilder({"functions": {
        "app/BarBaz/x.php:helper": {"name": "helper", "file_path": "app/BarBaz/x.php", "class_name": None, "code": ""},
        "sub/Bar.php:helper": {"name": "helper", "file_path": "sub/Bar.php", "class_name": None, "code": ""},
    }, "classes": {}, "imports": {"caller.php": {"Bar": "use"}}, "repository": "/r"})
    assert b._resolve_simple_call("helper", "caller.php", None) == "sub/Bar.php:helper"


# #3 _extract_imports records `namespace_use_declaration` (the real tree-sitter-php node type)
def test_extract_imports_namespace_use_declaration():
    src = b"<?php use App\\Service\\Foo; use App\\Bar as B;"
    parser = Parser(Language(_tsphp.language_php()))
    tree = parser.parse(src)
    imports = FunctionExtractor("/r")._extract_imports(tree, src)
    assert "App\\Service\\Foo" in imports, imports
    assert "App\\Bar" in imports, imports  # alias stripped to the namespace path
