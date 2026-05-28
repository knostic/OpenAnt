"""Empty-seed reachability blackout safety-net.

When EntryPointDetector finds ZERO entry points (the dominant case for a non-web
library/stdlib target — ordinary Python functions are unit_type='function', which
is not seedable), core.parser_adapter.apply_reachability_filter ran the BFS over
an empty seed, kept nothing, and emptied dataset['units'] entirely — reporting
100% reduction as SUCCESS with no error or warning. `--level reachable` thus
produced a silent total blackout.

A zero-entry-point seed must NOT silently drop every unit. The filter degrades to
pass-through (units preserved) and records a loud warning in the filter metadata
so the blackout can never be silent.

(The broader generic-library / public-API seeding heuristic is an architectural
change with an undetermined approach and is deliberately out of scope; this test
pins only the no-silent-blackout invariant.)
"""

import importlib.util
import pathlib

_CORE = pathlib.Path(__file__).resolve().parents[1]


def _load_parser_adapter():
    spec = importlib.util.spec_from_file_location(
        "isolated_parser_adapter", _CORE / "core" / "parser_adapter.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_json(path, obj):
    import json

    path.write_text(json.dumps(obj))


def test_zero_entry_points_does_not_silently_empty_dataset(tmp_path):
    pa = _load_parser_adapter()

    # A library: two ordinary functions, neither a seedable entry point.
    call_graph = {
        "functions": {
            "lib.py:add": {"name": "add", "unit_type": "function", "code": "return a + b"},
            "lib.py:sub": {"name": "sub", "unit_type": "function", "code": "return a - b"},
        },
        "call_graph": {"lib.py:add": ["lib.py:sub"]},
        "reverse_call_graph": {"lib.py:sub": ["lib.py:add"]},
    }
    _write_json(tmp_path / "call_graph.json", call_graph)

    dataset = {
        "units": [
            {"id": "lib.py:add"},
            {"id": "lib.py:sub"},
        ],
        "metadata": {},
    }

    out = pa.apply_reachability_filter(dataset, str(tmp_path), "reachable")

    # The dataset must NOT be silently emptied.
    assert len(out["units"]) == 2, (
        "zero entry points must not drop every unit (silent blackout) — the "
        "filter should degrade to pass-through"
    )

    # The blackout-avoidance must be recorded loudly, not silently.
    meta = out.get("metadata", {}).get("reachability_filter", {})
    assert meta.get("entry_points") == 0
    assert meta.get("warning"), (
        "a zero-entry-point pass-through must record a warning so the degraded "
        "result is never silent"
    )


def test_normal_seed_still_filters(tmp_path):
    """Guard: when there IS an entry point, the filter still prunes unreachable
    units (the safety-net must not disable real filtering)."""
    pa = _load_parser_adapter()

    call_graph = {
        "functions": {
            "app.py:main": {"name": "main", "unit_type": "main", "code": "handler()"},
            "app.py:handler": {"name": "handler", "unit_type": "function", "code": ""},
            "app.py:dead": {"name": "dead", "unit_type": "function", "code": ""},
        },
        "call_graph": {"app.py:main": ["app.py:handler"]},
        "reverse_call_graph": {"app.py:handler": ["app.py:main"]},
    }
    _write_json(tmp_path / "call_graph.json", call_graph)

    dataset = {
        "units": [
            {"id": "app.py:main"},
            {"id": "app.py:handler"},
            {"id": "app.py:dead"},
        ],
        "metadata": {},
    }

    out = pa.apply_reachability_filter(dataset, str(tmp_path), "reachable")
    ids = {u["id"] for u in out["units"]}
    assert ids == {"app.py:main", "app.py:handler"}, (
        "with a real entry point the unreachable 'dead' unit must still be pruned"
    )
    assert not out["metadata"]["reachability_filter"].get("warning")
