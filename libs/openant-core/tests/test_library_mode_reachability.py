"""Library-mode reachability seeding (BUG-005).

A pure library exposes no main/route/CLI entry point, so the structural detector
finds nothing and `apply_reachability_filter` drops EVERY unit — the library
(including any vulnerable sink it contains) is never analysed. Library-mode seeds
the public API surface so the forward BFS pulls in the rest.

These tests pin: (1) the blackout when the mode is OFF, (2) the public API becomes
reachable when ON (and its private callee comes along via the call edge), (3) a
truly-unreferenced private function stays out, and — adversarially — (4) turning
the mode ON for an APP can only ADD reachable units, never remove one (union-only
seed merge), so existing app scans are never degraded.
"""

import json
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

from core.parser_adapter import apply_reachability_filter


def _run(tmp_path, functions, call_graph, *, library_mode, entry_types=None):
    """Write a call_graph.json + dataset and run the filter; return kept unit ids."""
    entry_types = entry_types or {}
    reverse = {}
    for caller, callees in call_graph.items():
        for callee in callees:
            reverse.setdefault(callee, []).append(caller)
    # functions carry name (+ optional unit_type to trip the structural detector)
    fns = {fid: {"name": fid.split(":")[-1].split(".")[-1],
                 "unit_type": entry_types.get(fid, "function")} for fid in functions}
    (tmp_path / "call_graph.json").write_text(json.dumps(
        {"functions": fns, "call_graph": call_graph, "reverse_call_graph": reverse}))
    dataset = {"units": [{"id": fid, "unit_type": entry_types.get(fid, "function")}
                         for fid in functions]}
    out = apply_reachability_filter(dataset, str(tmp_path), "reachable",
                                    library_mode=library_mode)
    return {u["id"] for u in out["units"]}


# library: public_api() -> _sink()  (no structural entry point)
_LIB_FNS = ["lib.py:public_api", "lib.py:_sink"]
_LIB_CG = {"lib.py:public_api": ["lib.py:_sink"]}


def test_library_blackout_when_mode_off(tmp_path):
    """Default (mode off): a pure library is entirely filtered out — the bug."""
    kept = _run(tmp_path, _LIB_FNS, _LIB_CG, library_mode=False)
    assert kept == set(), f"expected blackout (0 reachable) with mode off, got {kept}"


def test_library_public_api_reachable_when_mode_on(tmp_path):
    """Mode on: the public API is seeded, and its private callee comes along."""
    kept = _run(tmp_path, _LIB_FNS, _LIB_CG, library_mode=True)
    assert "lib.py:public_api" in kept, f"public API not seeded: {kept}"
    assert "lib.py:_sink" in kept, f"private callee of the public API not reached: {kept}"


def test_unreferenced_private_stays_out(tmp_path):
    """Precision: a private function nothing calls is NOT seeded (only the public
    surface is) — so library-mode doesn't blanket-seed every unit."""
    fns = _LIB_FNS + ["lib.py:_orphan"]
    kept = _run(tmp_path, fns, _LIB_CG, library_mode=True)
    assert "lib.py:_orphan" not in kept, f"unreferenced private wrongly seeded: {kept}"


# app: main() is a route_handler entry; helper() is its callee; _dead() is unreferenced
_APP_FNS = ["app.py:main", "app.py:helper", "app.py:_dead"]
_APP_CG = {"app.py:main": ["app.py:helper"]}
_APP_ENTRY = {"app.py:main": "route_handler"}


def test_app_baseline_mode_off(tmp_path):
    """App with a real entry point: normal reachable set when mode off."""
    kept = _run(tmp_path, _APP_FNS, _APP_CG, library_mode=False, entry_types=_APP_ENTRY)
    assert kept == {"app.py:main", "app.py:helper"}, f"app baseline changed: {kept}"


def test_app_mode_on_is_additive_only(tmp_path):
    """Adversarial: turning library-mode ON for an app can only ADD reachable units
    (union-only seed merge) — it must never drop one the app scan already had."""
    off = _run(tmp_path, _APP_FNS, _APP_CG, library_mode=False, entry_types=_APP_ENTRY)
    on = _run(tmp_path, _APP_FNS, _APP_CG, library_mode=True, entry_types=_APP_ENTRY)
    assert off <= on, f"library-mode REMOVED app units: off={off} on={on}"
    assert off == {"app.py:main", "app.py:helper"}


def test_parse_repository_wiring(tmp_path):
    """Integration guard: library_mode must flow parse_repository -> _parse_python ->
    apply_reachability_filter. (A unit test on the filter alone missed a wiring bug
    where `_parse_python` referenced library_mode before it was threaded.)"""
    from core.parser_adapter import parse_repository
    repo = tmp_path / "repo"; repo.mkdir()
    (repo / "lib.py").write_text(
        "def public_api(x):\n    return _sink(x)\n\ndef _sink(x):\n    return eval(x)\n")
    import json as _json

    def _kept(library_mode):
        out = tmp_path / f"out_{library_mode}"; out.mkdir()
        parse_repository(repo_path=str(repo), output_dir=str(out), language="python",
                         processing_level="reachable", library_mode=library_mode)
        ds = _json.loads((out / "dataset.json").read_text())
        return {u.get("id") for u in ds.get("units", [])}

    assert _kept(False) == set(), "library should black out with mode off"
    on = _kept(True)
    assert any(i.endswith(":public_api") for i in on), f"public api not analysed: {on}"
    assert any(i.endswith(":_sink") for i in on), f"eval sink not analysed: {on}"
