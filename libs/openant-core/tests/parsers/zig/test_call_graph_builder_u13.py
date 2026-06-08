"""Regression tests for the Zig call graph builder (u13).

Three confirmed call-graph recall bugs, each reproduced through the REAL
extractor -> builder pipeline (FunctionExtractor.extract() feeding
CallGraphBuilder(...).build()), asserting the dropped edge is present.

- [BUG 3]  local-type dispatch: `const o = Foo{}; o.method()` (and the
           direct `Foo{}.method()`) produces no `caller -> method` edge,
           because call-name extraction never recognises a tree-sitter
           `field_expression` callee, so the method name is never emitted.
- [BUG 17] builtin-filter leak: a user-defined fn whose name collides with
           a ZIG_BUILTINS entry (e.g. `expect`) is dropped by the builtin
           filter before resolution, even though a same-file user function
           of that name exists.
- [BUG 41] const-alias dataflow: `const f = handler; f()` loses the edge to
           `handler`, because the name index maps only fn-decl names, never
           the simple const alias binding.
"""

import os
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.zig.function_extractor import FunctionExtractor
from parsers.zig.call_graph_builder import CallGraphBuilder


def _run_pipeline(src: str) -> dict:
    """Run the real extractor -> builder pipeline on a single zig source file."""
    workdir = tempfile.mkdtemp()
    file_path = os.path.join(workdir, "m.zig")
    with open(file_path, "w") as fh:
        fh.write(src)
    scan_results = {"files": [{"path": "m.zig"}]}
    extractor_output = FunctionExtractor(workdir, scan_results).extract()
    return CallGraphBuilder(extractor_output).build()


def test_bug3_local_type_dispatch_method_call_edge():
    """`const o = C{}; o.m()` must yield an `f -> C.m` call-graph edge.

    Note: the target id is the QUALIFIED `m.zig:C.m`. Prior to the u14 [BUG 37]
    fix, struct methods were (incorrectly) emitted under their bare name, so this
    assertion read `m.zig:m`. The method is now correctly keyed by its qualified
    `Container.method` id; the edge itself is unchanged.
    """
    src = (
        "const C = struct { fn m(self: C) i32 { _ = self; return 1; } };\n"
        "fn f() i32 { const o = C{}; return o.m(); }\n"
    )
    cg = _run_pipeline(src)["call_graph"]
    assert "m.zig:C.m" in cg.get("m.zig:f", []), (
        f"Expected f -> C.m method-call edge, got call_graph={cg}"
    )


def test_bug3_direct_struct_init_method_call_edge():
    """The direct `C{}.m()` form must also yield an `f -> C.m` edge.

    See the qualified-id note on test_bug3_local_type_dispatch_method_call_edge.
    """
    src = (
        "const C = struct { fn m(self: C) i32 { _ = self; return 1; } };\n"
        "fn f() i32 { return C{}.m(); }\n"
    )
    cg = _run_pipeline(src)["call_graph"]
    assert "m.zig:C.m" in cg.get("m.zig:f", []), (
        f"Expected f -> C.m direct-init method-call edge, got call_graph={cg}"
    )


def test_bug17_user_fn_shadowing_builtin_is_not_filtered():
    """A user fn named `expect` (a ZIG_BUILTINS name) must keep its edge."""
    src = (
        "fn expect(ok: bool) void {\n"
        "    _ = ok;\n"
        "}\n"
        "\n"
        "fn main() void {\n"
        "    expect(true);\n"
        "}\n"
    )
    cg = _run_pipeline(src)["call_graph"]
    assert "m.zig:expect" in cg.get("m.zig:main", []), (
        f"Expected main -> expect edge (user fn shadows builtin), got call_graph={cg}"
    )


def test_bug17_genuine_builtin_call_is_still_filtered():
    """Scope guard: a builtin call with NO same-file user fn stays filtered.

    `@import` is a genuine builtin and there is no user `@import` function,
    so it must not appear as an edge — the fix only un-filters builtins that
    are shadowed by a same-file user definition.
    """
    src = (
        "fn main() void {\n"
        "    const std = @import(\"std\");\n"
        "    _ = std;\n"
        "}\n"
    )
    cg = _run_pipeline(src)["call_graph"]
    # No user fn named @import / import exists, so main has no resolvable edge.
    assert cg.get("m.zig:main", []) == [], (
        f"Genuine builtin call should not produce an edge, got call_graph={cg}"
    )


def test_bug41_const_alias_call_edge():
    """`const f = handler; f()` must yield a `viaAlias -> handler` edge."""
    src = (
        "fn handler() void {}\n"
        "fn viaAlias() void {\n"
        "    const f = handler;\n"
        "    f();\n"
        "}\n"
        "fn direct() void {\n"
        "    handler();\n"
        "}\n"
    )
    cg = _run_pipeline(src)["call_graph"]
    assert "m.zig:handler" in cg.get("m.zig:viaAlias", []), (
        f"Expected viaAlias -> handler alias edge, got call_graph={cg}"
    )
    # Control: the direct call must keep working too.
    assert "m.zig:handler" in cg.get("m.zig:direct", []), (
        f"Direct call edge regressed, got call_graph={cg}"
    )
