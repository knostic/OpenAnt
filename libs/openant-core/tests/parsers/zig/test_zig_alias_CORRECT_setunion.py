"""
Edge-set conformance test for the zig const-fn-alias multi-target bug.

Bug: parsers/zig/call_graph_builder.py `_collect_aliases_from_node` (and the
struct-field sibling `_collect_field_fn_bindings`) recorded each alias with a
last-wins overwrite `aliases[name] = target`, whose value type
Dict[str, Optional[str]] cannot represent one alias name bound to MULTIPLE
targets on different control-flow paths (`const doit = foo` in one branch,
`const doit = bar` in another). One of the two caller->target edges was lost.

Correct (over-approximating, SAFE) fix: alias value is a Set[str] populated via
`aliases.setdefault(name, set()).add(target)`, and `_resolve_call` unions ids
across every alias target so `doit()` yields caller -> {foo, bar}.

This test asserts on the PUBLIC EDGE SET (builder.call_graph[caller]) -- the
observable call-graph output -- NOT on the internal alias map. It CONTAINS-checks
both targets so it stays valid regardless of edge ordering or extra edges.

Run against a specific module file via env CGB_PATH (defaults to the repo file):
    CGB_PATH=/path/to/call_graph_builder.py pytest test_zig_alias_multipath_edgeset.py
"""

import importlib.util
import os
import sys

import pytest

# openant-core root must be importable for the module's own imports
# (`utilities.file_io`, `tree_sitter_zig`).
_CORE_ROOT = os.environ.get(
    "OPENANT_CORE_ROOT",
    "/Users/gadievron/Documents/ClaudeNew/OpenAnt/new-bugs-2/OpenAnt/libs/openant-core",
)
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)

_CGB_PATH = os.environ.get(
    "CGB_PATH",
    os.path.join(_CORE_ROOT, "parsers", "zig", "call_graph_builder.py"),
)


def _load_builder_class():
    spec = importlib.util.spec_from_file_location("_cgb_under_test", _CGB_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.CallGraphBuilder


FILE = "app.zig"

# `doit` is bound to `foo` on the then-branch and to `bar` on the else-branch,
# then called on each path. Both caller->foo and caller->bar are real edges.
CALLER_CODE = """fn caller(cond: bool) void {
    if (cond) {
        const doit = foo;
        doit();
    } else {
        const doit = bar;
        doit();
    }
}"""

# Struct-field variant: h.cb bound to foo on one path, bar on the other.
CALLER_FIELD_CODE = """fn callerField(cond: bool) void {
    if (cond) {
        const h = T{ .cb = foo };
        h.cb();
    } else {
        const h = T{ .cb = bar };
        h.cb();
    }
}"""


def _extractor_output(caller_name, caller_code):
    def fn(name):
        return {
            "name": name,
            "qualified_name": name,
            "code": f"fn {name}() void {{}}",
            "file_path": FILE,
        }

    return {
        "repository": "fixture",
        "functions": {
            f"{FILE}:foo": fn("foo"),
            f"{FILE}:bar": fn("bar"),
            f"{FILE}:{caller_name}": {
                "name": caller_name,
                "qualified_name": caller_name,
                "code": caller_code,
                "file_path": FILE,
            },
        },
        "classes": {},
        "imports": {},
    }


@pytest.mark.parametrize(
    "caller_name,caller_code",
    [
        ("caller", CALLER_CODE),
        ("callerField", CALLER_FIELD_CODE),
    ],
)
def test_multipath_alias_edge_set_contains_both_targets(caller_name, caller_code):
    CallGraphBuilder = _load_builder_class()
    builder = CallGraphBuilder(_extractor_output(caller_name, caller_code))
    builder.build_call_graph()

    caller_id = f"{FILE}:{caller_name}"
    foo_id = f"{FILE}:foo"
    bar_id = f"{FILE}:bar"

    # Assert on the PUBLIC edge set, contains-both (order-independent).
    edge_set = set(builder.call_graph.get(caller_id, []))
    assert foo_id in edge_set, (
        f"{caller_name}: missing caller->foo edge; got {sorted(edge_set)}"
    )
    assert bar_id in edge_set, (
        f"{caller_name}: missing caller->bar edge (multi-path alias target dropped); "
        f"got {sorted(edge_set)}"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
