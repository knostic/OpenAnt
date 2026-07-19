"""Regression: a qualified C++ template call must resolve to its definition.

Bug (c-template-specialization-unreachable, FAM-A): a qualified template call
like ``ns::foo<int>()`` parses as a ``qualified_identifier`` whose leaf ``name``
is a ``template_function`` (``foo<int>``). ``_extract_call_name`` returned the
raw node text ``ns::foo<int>`` — with the ``<int>`` template argument list still
attached — which never matches a definition named ``ns::foo``. The specialized/
template function was therefore unreachable in the call graph. The bare
(non-qualified) case ``foo<int>()`` was already handled at the ``template_function``
branch; only the qualified case leaked the argument list.
"""
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[3]  # libs/openant-core (test is at tests/parsers/c/)
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

pytest.importorskip("tree_sitter_cpp")  # qualified template calls need the C++ grammar

from parsers.c.call_graph_builder import CallGraphBuilder  # noqa: E402


def test_qualified_template_call_resolves_to_specialized_function():
    """ns::foo<int>() must produce an edge to the ns::foo definition."""
    code = "void caller(){ ns::foo<int>(1); }"
    eo = {
        "functions": {
            "app.cpp:caller": {"name": "caller", "file_path": "app.cpp", "code": code},
            "app.cpp:ns::foo": {"name": "ns::foo", "file_path": "app.cpp",
                                "code": "template<typename T> void foo(T x){}"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code(code, "app.cpp:caller")
    assert "app.cpp:ns::foo" in edges, (
        f"qualified template call ns::foo<int>() did not resolve; edges={sorted(edges)}"
    )


def test_nested_namespace_template_call_resolves():
    """a::b::bar<T,U>() (nested qualified_identifier) must resolve to a::b::bar."""
    code = "void caller(){ a::b::bar<int,long>(1); }"
    eo = {
        "functions": {
            "app.cpp:caller": {"name": "caller", "file_path": "app.cpp", "code": code},
            "app.cpp:a::b::bar": {"name": "a::b::bar", "file_path": "app.cpp",
                                  "code": "template<class T,class U> void bar(T x){}"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code(code, "app.cpp:caller")
    assert "app.cpp:a::b::bar" in edges, (
        f"nested qualified template call did not resolve; edges={sorted(edges)}"
    )


def test_plain_qualified_call_still_resolves():
    """Guard: a non-template qualified call ns::foo() must keep resolving."""
    code = "void caller(){ ns::foo(1); }"
    eo = {
        "functions": {
            "app.cpp:caller": {"name": "caller", "file_path": "app.cpp", "code": code},
            "app.cpp:ns::foo": {"name": "ns::foo", "file_path": "app.cpp",
                                "code": "void foo(int x){}"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code(code, "app.cpp:caller")
    assert "app.cpp:ns::foo" in edges, (
        f"plain qualified call regressed; edges={sorted(edges)}"
    )


# --- FA3 completeness: the template-arg-stripping helper must be CONSERVATIVE ---
# An exotic qualified form whose scope OR name is a node shape the helper does not
# cleanly model (decltype scope, destructor_name / operator_name / conversion
# name) must NOT be normalised into a bare/partial name. Dropping the unmodelled
# segment fabricates a name (e.g. "foo" or "ns") that resolves to an unrelated
# function — a FALSE call-graph edge HEAD never emitted. The helper must return
# None so the qualified branch falls back to the raw node text (which resolves to
# nothing, exactly like HEAD).

def test_exotic_decltype_scope_does_not_fabricate_edge():
    """decltype(x)::compute() must NOT resolve to the unrelated global compute()."""
    code = "void caller(){ decltype(x)::compute(1); }"
    eo = {
        "functions": {
            "app.cpp:caller": {"name": "caller", "file_path": "app.cpp", "code": code},
            "app.cpp:compute": {"name": "compute", "file_path": "app.cpp",
                                "code": "void compute(int x){}"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code(code, "app.cpp:caller")
    assert "app.cpp:compute" not in edges, (
        f"exotic decltype-scoped call fabricated a false edge; edges={sorted(edges)}"
    )


def test_exotic_destructor_name_does_not_fabricate_edge():
    """ns::~Widget() (destructor_name leaf) must NOT resolve to a function named ns."""
    code = "void caller(){ ns::~Widget(); }"
    eo = {
        "functions": {
            "app.cpp:caller": {"name": "caller", "file_path": "app.cpp", "code": code},
            "app.cpp:ns": {"name": "ns", "file_path": "app.cpp", "code": "void ns(){}"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code(code, "app.cpp:caller")
    assert "app.cpp:ns" not in edges, (
        f"exotic destructor-name call fabricated a false edge; edges={sorted(edges)}"
    )


def test_exotic_operator_name_does_not_fabricate_edge():
    """ns::operator+() (operator_name leaf) must NOT resolve to a function named ns."""
    code = "void caller(){ ns::operator+(a, b); }"
    eo = {
        "functions": {
            "app.cpp:caller": {"name": "caller", "file_path": "app.cpp", "code": code},
            "app.cpp:ns": {"name": "ns", "file_path": "app.cpp", "code": "void ns(){}"},
        }
    }
    b = CallGraphBuilder(eo)
    edges = b._extract_calls_from_code(code, "app.cpp:caller")
    assert "app.cpp:ns" not in edges, (
        f"exotic operator-name call fabricated a false edge; edges={sorted(edges)}"
    )
