"""Zig reachability-filter API crash.

parsers/zig/test_pipeline.py apply_reachability_filter was written against an
EntryPointDetector / ReachabilityAnalyzer API that never existed:

    detector = EntryPointDetector(repo_path)        # ctor needs (functions, call_graph)
    entry_points = detector.detect()                # real: detect_entry_points()
    analyzer = ReachabilityAnalyzer(call_graph_output, entry_points)
                                                    # real: (functions, reverse_call_graph, entry_points)
    reachable = analyzer.get_reachable_functions()  # real: get_all_reachable()

Because test_pipeline.py puts libs/openant-core on sys.path, the two imports
SUCCEED, so the `except ImportError` guard never fires — the wrong-arity call
raises a TypeError that escapes the helper and crashes the whole Zig parse
(exit 1, zero output) at the default --processing-level reachable.

This test calls apply_reachability_filter directly with a tiny call graph whose
`main` is an entry point and which calls a helper; the fixed function must (a)
not raise, and (b) keep the reachable functions (main + helper) while dropping an
unreachable orphan.

test_pipeline.py shares its basename across all six parsers, so it is loaded
under a unique module name via importlib.
"""

import importlib.util
import pathlib
import sys

_CORE = pathlib.Path(__file__).resolve().parents[3]
_ZIG_TP = _CORE / "parsers" / "zig" / "test_pipeline.py"


def _load_zig_pipeline():
    # The Zig pipeline does bare local imports (`from repository_scanner import`)
    # relative to its own dir, mirroring how it is invoked as a script.
    zig_dir = str(_ZIG_TP.parent)
    core_dir = str(_CORE)
    added = []
    for p in (zig_dir, core_dir):
        if p not in sys.path:
            sys.path.insert(0, p)
            added.append(p)
    spec = importlib.util.spec_from_file_location("isolated_zig_test_pipeline", _ZIG_TP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _call_graph_output():
    # main (entry) -> helper ; orphan is unreachable.
    return {
        "functions": {
            "src/main.zig:main": {
                "name": "main",
                "unit_type": "main",
                "code": "pub fn main() void { helper(); }",
            },
            "src/main.zig:helper": {
                "name": "helper",
                "unit_type": "function",
                "code": "fn helper() void {}",
            },
            "src/main.zig:orphan": {
                "name": "orphan",
                "unit_type": "function",
                "code": "fn orphan() void {}",
            },
        },
        "call_graph": {
            "src/main.zig:main": ["src/main.zig:helper"],
        },
        "reverse_call_graph": {
            "src/main.zig:helper": ["src/main.zig:main"],
        },
        "statistics": {"total_edges": 1},
    }


def test_apply_reachability_filter_does_not_crash_and_seeds_main():
    mod = _load_zig_pipeline()
    out = mod.apply_reachability_filter(_call_graph_output(), repo_path="/tmp/repo")

    fids = set(out["functions"].keys())
    assert "src/main.zig:main" in fids, (
        "main is an entry point and must survive the reachability filter"
    )
    assert "src/main.zig:helper" in fids, (
        "helper is reachable from main and must survive"
    )
    assert "src/main.zig:orphan" not in fids, (
        "orphan is unreachable and must be filtered out — proving the filter "
        "actually ran rather than passing everything through"
    )


def test_apply_reachability_filter_filters_call_graph_too():
    mod = _load_zig_pipeline()
    out = mod.apply_reachability_filter(_call_graph_output(), repo_path="/tmp/repo")
    # orphan must not linger in the (reverse) call graphs either.
    assert "src/main.zig:orphan" not in out.get("call_graph", {})
    assert "src/main.zig:orphan" not in out.get("reverse_call_graph", {})
