"""Regression tests for the C call-graph resolver precision/recall defects.

Defects covered:
  - regex fallback scans raw code -> phantom edges from identifiers inside // and
    /* */ comments and "..." string literals.
  - obj->cb() (field_expression callee) was reduced to the bare field name and
    name-resolved against the global free-function index, wiring a
    member/function-pointer call to an unrelated free function.
  - a function passed by name as a callback argument (qsort(..., my_cmp),
    pthread_create(..., worker, ...)) produced no edge because only the call's
    'function' child was inspected, never its args.
  - the repo-wide unique-name fallback returned a `static` (file-local) function
    defined in another translation unit, violating C file-scope (a static helper()
    in b.c resolving a helper() call in a.c).

CallGraphBuilder consumes a plain extractor_output dict, so these drive it directly
(no repo fixture / extractor run). It builds a tree-sitter C Parser at init, so the
module skips where tree_sitter_c is unavailable, matching the other C tests.
"""
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[3]  # libs/openant-core (test is at tests/parsers/c/)
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

pytest.importorskip("tree_sitter_c")  # CallGraphBuilder builds a tree-sitter C Parser at init

from parsers.c.call_graph_builder import CallGraphBuilder  # noqa: E402


# --- regex fallback must not match comment/string content ----------------

def test_regex_fallback_ignores_comments_and_string_literals():
    """A // line comment, a /* */ block comment, and a "..." string literal each
    contain a call-shaped token (bar/baz/qux). The fallback must not emit edges for
    them; only real code calls should resolve."""
    eo = {
        "functions": {
            "m.c:f": {"name": "f", "file_path": "m.c", "code": "stub"},
            "m.c:bar": {"name": "bar", "file_path": "m.c", "code": "void bar(void){}"},
            "m.c:baz": {"name": "baz", "file_path": "m.c", "code": "void baz(void){}"},
            "m.c:qux": {"name": "qux", "file_path": "m.c", "code": "void qux(void){}"},
            "m.c:real": {"name": "real", "file_path": "m.c", "code": "void real(void){}"},
        }
    }
    b = CallGraphBuilder(eo)
    code = 'void f(void){ // bar()\n /* baz() */ const char *s = "qux()"; real(); }'
    edges = b._extract_calls_regex(code, "m.c:f")
    assert "m.c:bar" not in edges, f"phantom edge from // comment: {sorted(edges)}"
    assert "m.c:baz" not in edges, f"phantom edge from /* */ comment: {sorted(edges)}"
    assert "m.c:qux" not in edges, f"phantom edge from string literal: {sorted(edges)}"
    assert "m.c:real" in edges, f"real call dropped after stripping: {sorted(edges)}"


# --- field_expression callee must not bind to a free function ------------

def test_field_call_does_not_bind_to_unrelated_free_function():
    """obj->cb() is a member / function-pointer call. It must not be wired to a
    repo-unique free function named cb."""
    eo = {
        "functions": {
            "main.c:caller": {"name": "caller", "file_path": "main.c",
                              "code": "void caller(struct S *obj){ obj->cb(); }"},
            "util.c:cb": {"name": "cb", "file_path": "util.c", "code": "void cb(void){}"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code("void caller(struct S *obj){ obj->cb(); }", "main.c:caller")
    assert "util.c:cb" not in edges, f"false edge obj->cb() -> unrelated free cb: {sorted(edges)}"


def test_direct_free_call_still_resolves():
    """Guard: the field-expression decline must not break ordinary direct calls."""
    eo = {
        "functions": {
            "main.c:caller": {"name": "caller", "file_path": "main.c",
                              "code": "void caller(void){ helper(); }"},
            "main.c:helper": {"name": "helper", "file_path": "main.c", "code": "void helper(void){}"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code("void caller(void){ helper(); }", "main.c:caller")
    assert "main.c:helper" in edges, f"direct call regressed: {sorted(edges)}"


# --- callback function passed by name as an argument -------------------

def test_callback_argument_to_qsort_creates_edge():
    """qsort(arr, n, sz, my_cmp) invokes my_cmp indirectly; the by-name callback
    argument must produce a caller -> my_cmp edge."""
    eo = {
        "functions": {
            "m.c:caller": {"name": "caller", "file_path": "m.c",
                           "code": "void caller(int *a, int n){ qsort(a, n, sizeof(int), my_cmp); }"},
            "m.c:my_cmp": {"name": "my_cmp", "file_path": "m.c",
                           "code": "int my_cmp(const void *a, const void *b){ return 0; }"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code(
        "void caller(int *a, int n){ qsort(a, n, sizeof(int), my_cmp); }", "m.c:caller"
    )
    assert "m.c:my_cmp" in edges, f"callback arg my_cmp not tracked: {sorted(edges)}"


def test_callback_argument_to_pthread_create_creates_edge():
    """pthread_create(&t, NULL, worker, NULL) launches worker; the by-name argument
    must produce a caller -> worker edge."""
    eo = {
        "functions": {
            "m.c:caller": {"name": "caller", "file_path": "m.c",
                           "code": "void caller(void){ pthread_create(&t, NULL, worker, NULL); }"},
            "m.c:worker": {"name": "worker", "file_path": "m.c",
                           "code": "void *worker(void *arg){ return NULL; }"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code(
        "void caller(void){ pthread_create(&t, NULL, worker, NULL); }", "m.c:caller"
    )
    assert "m.c:worker" in edges, f"callback arg worker not tracked: {sorted(edges)}"


def test_non_function_identifier_arguments_do_not_create_edges():
    """Guard: plain data arguments (variables, not functions) must not produce edges."""
    eo = {
        "functions": {
            "m.c:caller": {"name": "caller", "file_path": "m.c",
                           "code": "void caller(int x){ helper(x, count); }"},
            "m.c:helper": {"name": "helper", "file_path": "m.c", "code": "void helper(int a, int b){}"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code("void caller(int x){ helper(x, count); }", "m.c:caller")
    assert edges == {"m.c:helper"}, f"data args x/count must not be edges: {sorted(edges)}"


# --- static (file-local) over-resolution across translation units -----

def test_unique_name_fallback_skips_static_in_other_file():
    """A repo-unique helper() that is `static` in b.c must NOT resolve a helper()
    call in a.c (C file-scope)."""
    eo = {
        "functions": {
            "a.c:caller": {"name": "caller", "file_path": "a.c", "code": "void caller(void){ helper(); }"},
            "b.c:helper": {"name": "helper", "file_path": "b.c",
                           "code": "static void helper(void){}", "is_static": True},
        }
    }
    b = CallGraphBuilder(eo)
    assert b._resolve_call("helper", "a.c") is None, "static helper() in b.c wrongly resolved cross-TU"


def test_same_file_static_call_still_resolves():
    """Guard: a static function is fully callable from its own file."""
    eo = {
        "functions": {
            "a.c:caller": {"name": "caller", "file_path": "a.c", "code": "void caller(void){ helper(); }"},
            "a.c:helper": {"name": "helper", "file_path": "a.c",
                           "code": "static void helper(void){}", "is_static": True},
        }
    }
    b = CallGraphBuilder(eo)
    assert b._resolve_call("helper", "a.c") == "a.c:helper", "same-file static call must resolve"


def test_non_static_unique_name_still_resolves_cross_file():
    """Guard: a non-static repo-unique function still resolves cross-file (extern linkage)."""
    eo = {
        "functions": {
            "a.c:caller": {"name": "caller", "file_path": "a.c", "code": "void caller(void){ shared(); }"},
            "b.c:shared": {"name": "shared", "file_path": "b.c",
                           "code": "void shared(void){}", "is_static": False},
        }
    }
    b = CallGraphBuilder(eo)
    assert b._resolve_call("shared", "a.c") == "b.c:shared", "extern unique-name resolution regressed"
