"""S1: the shared reachability filter must keep-all when the ONLY entry points
are synthetic fuzz harnesses.

Under ``--llm-reachability`` the initial parse runs at level ``all`` (scanner.py
forces it), so every parser skips its own filter and the post-LLM re-filter calls
``core.parser_adapter.apply_reachability_filter`` for EVERY language. That shared
filter's keep-all net fired only on a fully-EMPTY seed set (``if not
entry_points``). A rust fuzz-only library seeds exactly one entry point — the
synthetic ``fuzz_target!`` harness (``unit_type='main'`` + ``synthetic_harness``)
— so the net did NOT fire, the BFS pruned to the harness-reachable sliver, and
the un-reached exported public API was silently dropped.

The rust parser's OWN filter already guards this (``parsers/rust/test_pipeline.py``
computes ``real_entry_points`` excluding ``synthetic_harness``), but that filter
never runs on the ``--llm-reachability`` path. This pins the harness-aware keep-all
invariant on the shared core filter.
"""

import importlib.util
import json
import pathlib

_CORE = pathlib.Path(__file__).resolve().parents[1]


def _load_parser_adapter():
    spec = importlib.util.spec_from_file_location(
        "isolated_parser_adapter_s1", _CORE / "core" / "parser_adapter.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _fuzz_only_graph():
    # Only entry point is the synthetic harness; parse/helper are reachable from
    # it, but public_api_a/b are the un-reached EXPORTED surface.
    return {
        "functions": {
            "fuzz/h.rs:fuzz_target": {
                "name": "fuzz_target", "unit_type": "main",
                "synthetic_harness": True, "code": "parse(data)",
            },
            "lib.rs:parse": {"name": "parse", "unit_type": "function", "code": "helper(d)"},
            "lib.rs:helper": {"name": "helper", "unit_type": "function", "code": "d.len()"},
            "lib.rs:public_api_a": {"name": "public_api_a", "unit_type": "function", "code": "1"},
            "lib.rs:public_api_b": {"name": "public_api_b", "unit_type": "function", "code": "2"},
        },
        "call_graph": {
            "fuzz/h.rs:fuzz_target": ["lib.rs:parse"],
            "lib.rs:parse": ["lib.rs:helper"],
        },
        "reverse_call_graph": {
            "lib.rs:parse": ["fuzz/h.rs:fuzz_target"],
            "lib.rs:helper": ["lib.rs:parse"],
        },
    }


def _units():
    # The harness is seed-only (not analyzed as a unit); the 4 real fns are units.
    return [
        {"id": "lib.rs:parse"},
        {"id": "lib.rs:helper"},
        {"id": "lib.rs:public_api_a"},
        {"id": "lib.rs:public_api_b"},
    ]


def test_synthetic_harness_only_seed_keeps_all_units(tmp_path):
    pa = _load_parser_adapter()
    (tmp_path / "call_graph.json").write_text(json.dumps(_fuzz_only_graph()))
    dataset = {"units": _units(), "metadata": {}}

    out = pa.apply_reachability_filter(dataset, str(tmp_path), "reachable")

    kept = {u["id"] for u in out["units"]}
    # RED pre-fix: only {parse, helper} survive; public_api_a/b are dropped.
    assert kept == {
        "lib.rs:parse", "lib.rs:helper",
        "lib.rs:public_api_a", "lib.rs:public_api_b",
    }, (
        "a synthetic-harness-only seed must degrade to keep-all (the un-reached "
        f"exported public API was silently dropped); kept={sorted(kept)}"
    )


def test_mixed_real_plus_harness_still_filters(tmp_path):
    """NEGATIVE CONTROL: a real entry point alongside the harness must filter
    normally — keep-all must NOT fire when a real (non-synthetic) seed exists."""
    pa = _load_parser_adapter()
    graph = _fuzz_only_graph()
    # Add a real `main` (not synthetic) that reaches only parse/helper.
    graph["functions"]["bin.rs:main"] = {
        "name": "main", "unit_type": "main", "code": "parse(d)",
    }
    graph["call_graph"]["bin.rs:main"] = ["lib.rs:parse"]
    (tmp_path / "call_graph.json").write_text(json.dumps(graph))
    dataset = {"units": _units(), "metadata": {}}

    out = pa.apply_reachability_filter(dataset, str(tmp_path), "reachable")
    kept = {u["id"] for u in out["units"]}
    # A real seed exists -> real filtering -> unreached public API is pruned.
    assert "lib.rs:public_api_a" not in kept and "lib.rs:public_api_b" not in kept, (
        "keep-all wrongly fired despite a real (non-synthetic) entry point; "
        f"kept={sorted(kept)}"
    )
