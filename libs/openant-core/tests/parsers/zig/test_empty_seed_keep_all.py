"""Bug (N4): the Zig reachability filter silently blacks out a no-entry-point
module.

`apply_reachability_filter` seeds its BFS from the detected entry points. A Zig
library / no-entry target (no `pub fn main`, no entry marker) yields ZERO entry
points, so the reachable set is empty, every function is pruned, and the parse
reports a clean 0-unit success — a silent blackout at the default
`--processing-level reachable`.

The fix mirrors core/parser_adapter.py: no entry points but functions present →
keep all + warn instead of emptying the module.

This drives the REAL module-level `apply_reachability_filter` over a two-function
library fixture with no `main`. RED→GREEN verified against master's unfixed file.
Companion to test_zig_reachability_api.py (which covers the seeded path).

test_pipeline.py shares its basename across all six parsers, so it is loaded
under a unique module name via importlib.
"""
import importlib.util
import pathlib
import sys

_CORE = pathlib.Path(__file__).resolve().parents[3]
_ZIG_TP = _CORE / "parsers" / "zig" / "test_pipeline.py"


def _load_zig_pipeline():
    for p in (str(_ZIG_TP.parent), str(_CORE)):
        if p not in sys.path:
            sys.path.insert(0, p)
    spec = importlib.util.spec_from_file_location("isolated_zig_empty_seed", _ZIG_TP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _no_entry_call_graph_output():
    # Two ordinary library functions, NO `main`, no entry marker → zero seeds.
    return {
        "functions": {
            "src/lib.zig:add": {
                "name": "add",
                "unit_type": "function",
                "code": "fn add(a: i32, b: i32) i32 { return a + b; }",
            },
            "src/lib.zig:scale": {
                "name": "scale",
                "unit_type": "function",
                "code": "fn scale(a: i32) i32 { return add(a, a); }",
            },
        },
        "call_graph": {"src/lib.zig:scale": ["src/lib.zig:add"]},
        "reverse_call_graph": {"src/lib.zig:add": ["src/lib.zig:scale"]},
        "statistics": {"total_edges": 1},
    }


def test_empty_seed_keeps_all_functions():
    mod = _load_zig_pipeline()
    out = mod.apply_reachability_filter(_no_entry_call_graph_output(), repo_path="/tmp/repo")
    fids = set(out["functions"].keys())
    assert fids == {"src/lib.zig:add", "src/lib.zig:scale"}, (
        "empty-seed safety-net must keep all functions when no entry point can "
        f"seed the frontier; got {fids} (blackout = the N4 bug)"
    )
