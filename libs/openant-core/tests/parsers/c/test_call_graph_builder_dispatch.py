"""Regression tests for the C/C++ call graph builder — member-dispatch (bug [51]).

Bug report (C member-dispatch):
    `Widget w; w.compute();` (and `Widget* w = ...; w->compute();`) should resolve
    to `Widget::compute` (the method on w's known type), but the current resolver
    discards the receiver and resolves `compute` base-name-first — linking a free
    function `compute` (or, with two classes, the first-defined sibling method).

Root cause:
    parsers/c/call_graph_builder.py `_extract_call_name` returns ONLY the field
    name for a `field_expression`, dropping the receiver. `_resolve_call` then has
    no type context and resolves the bare base name (first/unique same-file match).

Fix scope: SAME-FILE only. The receiver's static type is inferred from a local
variable declaration in the caller's body; if the type is unknown or has no such
method in the same translation unit, resolution FALLS BACK to the existing
base-name behavior (no false edge).

Each test builds a real FunctionExtractor output from temp C++ source and runs the
real CallGraphBuilder pipeline, then asserts on the resulting edges. The RED cases
are constructed so the base-name-first resolver picks the WRONG target pre-fix.
"""

import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.c.call_graph_builder import CallGraphBuilder
from parsers.c.function_extractor import FunctionExtractor


def _extract(source: str, filename: str = "main.cpp") -> dict:
    """Write source to a temp repo, run the real extractor, return its output."""
    tmpdir = tempfile.mkdtemp()
    src_path = Path(tmpdir) / filename
    src_path.write_text(source, encoding="utf-8")
    extractor = FunctionExtractor(tmpdir)
    return extractor.extract_all([filename])


def _build(source: str, filename: str = "main.cpp") -> CallGraphBuilder:
    builder = CallGraphBuilder(_extract(source, filename))
    builder.build_call_graph()
    return builder


# --------------------------------------------------------------------------- #
# RED1: value-receiver member dispatch  (Widget w; w.compute();)
#   A free `compute` is present, so the base-name-first resolver mislinks to it
#   pre-fix. Post-fix it must resolve to Widget::compute (the method on w's type).
# --------------------------------------------------------------------------- #

_VALUE_SRC = """
void compute() { }
class Widget {
public:
    void compute() { }
    void run() {
        Widget w;
        w.compute();
    }
};
"""


def test_value_receiver_member_call_resolves_to_method():
    builder = _build(_VALUE_SRC)
    caller = "main.cpp:Widget::run"
    method = "main.cpp:Widget::compute"
    free = "main.cpp:compute"
    edges = builder.call_graph.get(caller, [])
    assert method in edges, (
        f"Member call w.compute() did not resolve to the method on w's type.\n"
        f"  Expected edge to: {method}\n"
        f"  Got: {edges}\n"
        f"  Functions: {list(builder.functions)}"
    )
    assert free not in edges, (
        f"Member call w.compute() wrongly linked to the free function compute.\n"
        f"  Got: {edges}"
    )


# --------------------------------------------------------------------------- #
# RED1b: pointer-receiver member dispatch  (Widget* w = ...; w->compute();)
# --------------------------------------------------------------------------- #

_PTR_SRC = """
void compute() { }
class Widget {
public:
    void compute() { }
};
Widget* acquire();
void run() {
    Widget* w = acquire();
    w->compute();
}
"""


def test_pointer_receiver_member_call_resolves_to_method():
    builder = _build(_PTR_SRC)
    caller = "main.cpp:run"
    method = "main.cpp:Widget::compute"
    free = "main.cpp:compute"
    edges = builder.call_graph.get(caller, [])
    assert method in edges, (
        f"Member call w->compute() did not resolve to the method on w's type.\n"
        f"  Expected edge to: {method}\n"
        f"  Got: {edges}\n"
        f"  Functions: {list(builder.functions)}"
    )
    assert free not in edges, (
        f"Member call w->compute() wrongly linked to the free function compute.\n"
        f"  Got: {edges}"
    )


# --------------------------------------------------------------------------- #
# PRECISION NEG1: unknown receiver type must fall back to base-name resolution
#   (and never invent a type-dispatch edge). `x` is not declared in run(); the
#   only same-file `compute` is a free function — fallback links it, as today.
# --------------------------------------------------------------------------- #

_UNKNOWN_RECV_SRC = """
void compute() { }
void run() {
    x.compute();
}
"""


def test_unknown_receiver_falls_back_to_base_name():
    builder = _build(_UNKNOWN_RECV_SRC)
    caller = "main.cpp:run"
    free = "main.cpp:compute"
    assert builder.call_graph.get(caller, []) == [free], (
        f"Unknown-receiver member call did not resolve as the base-name fallback.\n"
        f"  Expected: [{free}]\n"
        f"  Got: {builder.call_graph.get(caller)}"
    )


# --------------------------------------------------------------------------- #
# PRECISION NEG2: plain free-function call (no receiver) unchanged
# --------------------------------------------------------------------------- #

_FREE_SRC = """
void helper() { }
void run() {
    helper();
}
"""


def test_plain_free_function_call_unchanged():
    builder = _build(_FREE_SRC)
    caller = "main.cpp:run"
    callee = "main.cpp:helper"
    assert builder.call_graph.get(caller, []) == [callee], (
        f"Plain free-function call regressed.\n"
        f"  Expected: [{callee}]\n"
        f"  Got: {builder.call_graph.get(caller)}"
    )


# --------------------------------------------------------------------------- #
# PRECISION NEG3: two classes each with compute; B defined FIRST so the
#   base-name-first resolver would pick B::compute pre-fix. `A a; a.compute()`
#   must resolve to A::compute, NOT the sibling B::compute.
# --------------------------------------------------------------------------- #

_TWO_CLASS_SRC = """
class B {
public:
    void compute() { }
};
class A {
public:
    void compute() { }
};
void run() {
    A a;
    a.compute();
}
"""


def test_member_call_resolves_to_correct_class_not_sibling():
    builder = _build(_TWO_CLASS_SRC)
    caller = "main.cpp:run"
    a_compute = "main.cpp:A::compute"
    b_compute = "main.cpp:B::compute"
    edges = builder.call_graph.get(caller, [])
    assert a_compute in edges, (
        f"a.compute() did not resolve to A::compute.\n  Got: {edges}"
    )
    assert b_compute not in edges, (
        f"a.compute() wrongly linked to the sibling (first-defined) B::compute.\n"
        f"  Got: {edges}"
    )


# =========================================================================== #
# Bug [30]: virtual / inherited member dispatch — inheritance walk.
#
#   `Base* b = ...; b->compute();` where compute is defined on Base (or an
#   ancestor) and the receiver's STATICALLY-DECLARED type does NOT define it
#   directly. Resolution must walk UP the base-class chain to the first
#   ancestor that defines compute. This is the SOUND FLOOR: it resolves to the
#   static type's method (or its nearest ancestor's), and deliberately does NOT
#   link every derived override (a documented non-goal that creates false
#   edges). Same-file only; no ancestor defining the method => no edge.
# =========================================================================== #


# --------------------------------------------------------------------------- #
# RED1 (inherited, non-virtual): Derived doesn't define compute -> walk up to
#   Base::compute. A free `compute` is present so the pre-fix base-name-first
#   resolver mislinks; pre-[30] the receiver-type path also fails (Derived has
#   no compute) and falls back to the free function.
# --------------------------------------------------------------------------- #

_INHERITED_SRC = """
void compute() { }
struct Base {
    void compute() { }
};
struct Derived : Base {
    void run() {
        Derived* d = nullptr;
        d->compute();
    }
};
"""


def test_inherited_member_call_walks_up_to_base():
    builder = _build(_INHERITED_SRC)
    caller = "main.cpp:Derived::run"
    base_compute = "main.cpp:Base::compute"
    free = "main.cpp:compute"
    edges = builder.call_graph.get(caller, [])
    assert base_compute in edges, (
        f"d->compute() did not walk up to the ancestor that defines compute.\n"
        f"  Expected edge to: {base_compute}\n"
        f"  Got: {edges}\n"
        f"  Functions: {list(builder.functions)}"
    )
    assert free not in edges, (
        f"d->compute() wrongly linked to the free function compute.\n"
        f"  Got: {edges}"
    )


# --------------------------------------------------------------------------- #
# RED2 (virtual, static-type floor): Base declares+defines virtual compute;
#   Derived overrides it. Called via a Base* receiver -> resolve to the STATIC
#   type's method, Base::compute (the sound floor). Derived::compute is
#   intentionally NOT also linked (documented non-goal: no over-approximation).
# --------------------------------------------------------------------------- #

_VIRTUAL_SRC = """
struct Base {
    virtual void compute() { }
};
struct Derived : Base {
    void compute() override { }
};
void run() {
    Base* b = nullptr;
    b->compute();
}
"""


def test_virtual_member_call_resolves_to_static_type_floor():
    builder = _build(_VIRTUAL_SRC)
    caller = "main.cpp:run"
    base_compute = "main.cpp:Base::compute"
    derived_compute = "main.cpp:Derived::compute"
    edges = builder.call_graph.get(caller, [])
    assert base_compute in edges, (
        f"b->compute() (Base* receiver) did not resolve to the static type's "
        f"method Base::compute.\n  Expected edge to: {base_compute}\n  Got: {edges}"
    )
    # Documented FLOOR: the derived override is NOT linked from a Base* call.
    assert derived_compute not in edges, (
        f"b->compute() over-approximated: linked the derived override "
        f"{derived_compute}. The [30] floor links only the static type's method.\n"
        f"  Got: {edges}"
    )


# --------------------------------------------------------------------------- #
# PRECISION NEG1: Derived DOES define compute (override) called via Derived* ->
#   resolves to Derived::compute (its own), NOT Base::compute. The walk stops at
#   the first definer (the receiver's own type).
# --------------------------------------------------------------------------- #

_OVERRIDE_SRC = """
struct Base {
    virtual void compute() { }
};
struct Derived : Base {
    void compute() override { }
    void run() {
        Derived* d = nullptr;
        d->compute();
    }
};
"""


def test_override_resolves_to_own_method_not_ancestor():
    builder = _build(_OVERRIDE_SRC)
    caller = "main.cpp:Derived::run"
    derived_compute = "main.cpp:Derived::compute"
    base_compute = "main.cpp:Base::compute"
    edges = builder.call_graph.get(caller, [])
    assert derived_compute in edges, (
        f"d->compute() (Derived* receiver, Derived overrides) did not resolve to "
        f"its own Derived::compute.\n  Got: {edges}"
    )
    assert base_compute not in edges, (
        f"d->compute() walked past its own override to Base::compute. The walk "
        f"must stop at the first definer.\n  Got: {edges}"
    )


# --------------------------------------------------------------------------- #
# PRECISION NEG2: no ancestor defines the method -> NO type-dispatch edge, and
#   no mislink to an unrelated free `compute`. Receiver type is known (Derived)
#   but neither Derived nor its base Base defines `compute`; a free compute
#   exists. The inheritance walk must return None (fall back). Fallback then
#   links the free function (unchanged base-name behavior), but crucially the
#   walk must NOT have invented a Base::compute / Derived::compute edge.
# --------------------------------------------------------------------------- #

_NO_ANCESTOR_DEF_SRC = """
void compute() { }
struct Base {
    void other() { }
};
struct Derived : Base {
    void run() {
        Derived* d = nullptr;
        d->compute();
    }
};
"""


def test_no_ancestor_defines_method_no_false_edge():
    builder = _build(_NO_ANCESTOR_DEF_SRC)
    caller = "main.cpp:Derived::run"
    edges = builder.call_graph.get(caller, [])
    base_compute = "main.cpp:Base::compute"
    derived_compute = "main.cpp:Derived::compute"
    # The walk must not fabricate a method edge for a method no ancestor defines.
    assert base_compute not in edges and derived_compute not in edges, (
        f"Inheritance walk fabricated a method edge for an undefined method.\n"
        f"  Got: {edges}"
    )


# --------------------------------------------------------------------------- #
# PRECISION NEG3: cycle in (malformed) inheritance -> the BFS terminates and
#   does not crash. A: B, B: A, neither defines compute; a call via A* must not
#   hang/recurse forever and must produce no fabricated method edge.
# --------------------------------------------------------------------------- #

_CYCLE_SRC = """
struct B;
struct A : B {
    void run() {
        A* a = nullptr;
        a->compute();
    }
};
struct B : A {
};
"""


def test_inheritance_cycle_terminates_no_crash():
    # Must not raise / hang.
    builder = _build(_CYCLE_SRC)
    caller = "main.cpp:A::run"
    edges = builder.call_graph.get(caller, [])
    assert "main.cpp:A::compute" not in edges
    assert "main.cpp:B::compute" not in edges
