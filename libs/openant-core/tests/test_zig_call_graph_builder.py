"""Regression tests for defects in parsers/zig/call_graph_builder.py.

API parity: zig exposed build()->Dict + save_results() only, missing the canonical
  build_call_graph()->None / export() / get_statistics() / get_dependencies() / get_callers() surface.
Statistics: statistics omitted avg_in_degree / max_in_degree.
@call extraction: @call(.modifier, fn, args) -- a `builtin_function` node -- dropped its
  wrapped function, so the real callee was never recorded.
Method-call recall + safe resolution: method calls (`obj.method()`, a `call_expression` over a
  `field_expression`) were not extracted at all -- the code checked the non-existent `field_access`
  node type -- a recall gap; and _resolve_call returned ALL same-named candidates on a bare-name
  collision (a namespace leak). Fixed: extract field_expression callees +
  resolve conservatively (return [] when genuinely ambiguous).
Import-file matching: import resolution used an unanchored `imp in candidate_file` substring.
Stdlib import filter: @import("std")/("builtin") leaked in and substring-matched candidate paths.
(Phantom field: `indirect_calls` is a phantom field -- 0 repo hits, by design -- documented,
  no code change.)

Loads the module under a UNIQUE importlib name (call_graph_builder is a basename shared by every parser).
"""
import importlib.util
import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))
_spec = importlib.util.spec_from_file_location(
    "zig_call_graph_builder_isolated", str(CORE / "parsers" / "zig" / "call_graph_builder.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
CallGraphBuilder = _mod.CallGraphBuilder


def _ext(funcs, imports=None):
    return {"functions": funcs, "classes": {}, "imports": imports or {}, "repository": "/r"}


# canonical API parity + in-degree statistics
def test_canonical_api_parity_and_in_degree_stats():
    b = CallGraphBuilder(_ext({
        "a.zig:f": {"name": "f", "file_path": "a.zig", "code": "fn f() void { g(); }"},
        "a.zig:g": {"name": "g", "file_path": "a.zig", "code": "fn g() void {}"},
    }))
    for m in ("build_call_graph", "export", "get_statistics", "get_dependencies", "get_callers"):
        assert hasattr(b, m), f"missing canonical API method: {m}"
    b.build_call_graph()                                  # mutates state, returns None
    assert b.call_graph.get("a.zig:f") == ["a.zig:g"], b.call_graph
    stats = b.export()["statistics"]
    assert "avg_in_degree" in stats and "max_in_degree" in stats, stats
    assert b.get_dependencies("a.zig:f") == ["a.zig:g"]
    assert b.get_callers("a.zig:g") == ["a.zig:f"]


# @call extracts the wrapped function
def test_at_call_extracts_wrapped_function():
    out = CallGraphBuilder(_ext({
        "a.zig:f": {"name": "f", "file_path": "a.zig", "code": "fn f() void { @call(.auto, g, .{}); }"},
        "a.zig:g": {"name": "g", "file_path": "a.zig", "code": "fn g() void {}"},
    })).build()
    assert out["call_graph"].get("a.zig:f") == ["a.zig:g"], \
        f"@call(.auto, g, ...) should edge to g, got {out['call_graph']}"


# method-call recall via field_expression
def test_method_call_extracted_via_field_expression():
    out = CallGraphBuilder(_ext({
        "a.zig:f": {"name": "f", "file_path": "a.zig", "code": "fn f() void { obj.method(); }"},
        "a.zig:method": {"name": "method", "file_path": "a.zig", "code": "fn method() void {}"},
    })).build()
    assert out["call_graph"].get("a.zig:f") == ["a.zig:method"], out["call_graph"]


# exact-import / stdlib-filter / conservative resolution
def test_resolve_call_exact_import_stdlib_filter_and_conservative():
    b = CallGraphBuilder(_ext({}, imports={"main.zig": ["util.zig", "std"]}))
    # (a) exact import-FILE match, not substring: 'util.zig' picks src/util.zig, not myutil.zig_x/
    nm = {"helper": ["myutil.zig_x/x.zig:helper", "src/util.zig:helper"]}
    assert b._resolve_call("helper", "main.zig", nm) == ["src/util.zig:helper"]
    # (b) 'std' is a non-file import (filtered); two std_*-pathed candidates, none import-resolved ->
    #     ambiguous -> [] (no namespace-leak over-connection, no stdlib substring match)
    nm3 = {"bar": ["lib/std_x.zig:bar", "other/std_y.zig:bar"]}
    assert b._resolve_call("bar", "main.zig", nm3) == []
