"""Deep-tree robustness regression for the zig call-graph tree walks.

Finding: zig-alias-index-recursion-no-depth-bound.

parsers/zig/call_graph_builder.py had TWO self-recursive parse-tree walks with
no bound on Python-stack growth:

  * `_collect_aliases_from_node` -- driven by `_build_alias_index`, which is
    invoked OUTSIDE the try/except that guards parsing. A deeply-nested parse
    tree therefore drove Python past its recursion limit, and the RecursionError
    propagated up and aborted the ENTIRE zig call-graph build.
  * `_extract_calls_from_node` -- the DIRECT TWIN, same unbounded recursion.

A prior draft fix added a static `depth >= 500` cap to the alias walker only.
That cap was ambient-stack-dependent (the overflow point shifts with whatever
frames are already on the stack) and, worse, SILENTLY TRUNCATED any alias
declared deeper than 500 nodes into the tree -- a real recall loss. The correct
fix rewrites BOTH walks ITERATIVELY (explicit worklist stack, zero Python frame
growth) so they are robust for any AST depth and never truncate.

This test drives the REAL top-level `build_call_graph()` entry (not the walker
in isolation) on a pathologically deep parse tree whose alias binding and call
site sit at the very bottom, PLUS a shallow control function. It asserts:

  1. build_call_graph() COMPLETES without raising (the recursive walk raised
     RecursionError here and aborted the whole build).
  2. the DEEP alias edge is still produced -- proving no truncation (the 500-cap
     draft dropped it).
  3. the SHALLOW alias edge is still produced -- proving no behaviour change on
     ordinary shallow ASTs.

Select the module under test with env CGB_PATH (defaults to the repo file):
    CGB_PATH=/path/to/call_graph_builder.py pytest test_...depth_bound.py
"""

import importlib.util
import os
import sys

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
    from parsers.zig.call_graph_builder import CallGraphBuilder
    return CallGraphBuilder


FILE = "deep.zig"

# Nesting depth far past Python's default recursion limit (~1000) so the old
# recursive walks overflow, and far past the abandoned 500 cap so a truncating
# walker would miss the innermost alias.
_DEPTH = 1600


def _deep_caller_code():
    # A chain of nested anonymous blocks with the const-fn alias + its call at
    # the very bottom. tree-sitter parses this into a tree whose depth is
    # proportional to the nesting, so the walker must descend _DEPTH levels to
    # reach the `const g = target; g();` binding.
    open_braces = "{" * _DEPTH
    close_braces = "}" * _DEPTH
    return (
        "fn deepCaller() void {\n"
        + open_braces
        + "\nconst g = target;\ng();\n"
        + close_braces
        + "\n}"
    )


# Ordinary shallow alias -- must keep working unchanged.
SHALLOW_CALLER_CODE = """fn shallowCaller() void {
    const s = target;
    s();
}"""


def _extractor_output():
    return {
        "repository": "fixture",
        "functions": {
            f"{FILE}:target": {
                "name": "target",
                "qualified_name": "target",
                "code": "fn target() void {}",
                "file_path": FILE,
            },
            f"{FILE}:deepCaller": {
                "name": "deepCaller",
                "qualified_name": "deepCaller",
                "code": _deep_caller_code(),
                "file_path": FILE,
            },
            f"{FILE}:shallowCaller": {
                "name": "shallowCaller",
                "qualified_name": "shallowCaller",
                "code": SHALLOW_CALLER_CODE,
                "file_path": FILE,
            },
        },
        "classes": {},
        "imports": {},
    }


def test_build_call_graph_completes_on_deep_tree_without_truncation():
    CallGraphBuilder = _load_builder_class()
    builder = CallGraphBuilder(_extractor_output())

    # (1) Completes: the recursive walk raised RecursionError from inside the
    # un-guarded _build_alias_index call and aborted the whole build here.
    builder.build_call_graph()

    target_id = f"{FILE}:target"
    deep_edges = set(builder.call_graph.get(f"{FILE}:deepCaller", []))
    shallow_edges = set(builder.call_graph.get(f"{FILE}:shallowCaller", []))

    # (3) Shallow alias still resolves -- no behaviour change on real ASTs.
    assert target_id in shallow_edges, (
        f"shallowCaller->target edge missing; got {sorted(shallow_edges)}"
    )

    # (2) Deep alias still resolves -- the walk descended the full tree and did
    # not truncate past any static depth cap.
    assert target_id in deep_edges, (
        "deepCaller->target edge missing: the deeply-nested `const g = target` "
        f"alias was truncated; got {sorted(deep_edges)}"
    )


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-v"]))
