"""N4 empty-seed keep-all guard for the Swift pipeline (the guard all 6 sibling
parsers ship — PRs 154-159). A library/framework target with no structural entry
point must degrade to keep-all + warn, NEVER a silent 0-unit blackout."""

import importlib.util
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_CORE = _HERE.parents[2]
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_CORE))
from _helpers import build  # noqa: E402


def _load_pipeline():
    spec = importlib.util.spec_from_file_location(
        "swift_pipeline_iso", _CORE / "parsers" / "swift" / "test_pipeline.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_no_entry_points_keeps_all_units(tmp_path):
    # Pure library: ordinary functions, no main / route / @objc / input pattern.
    _, cg = build(tmp_path, {"lib.swift": """
        func a() { b() }
        func b() { c() }
        func c() {}
    """})
    pipeline = _load_pipeline()
    result = pipeline.apply_reachability_filter(cg, str(tmp_path), library_mode=False)
    # N4: with zero seedable entry points, every unit is kept (not a silent blackout).
    assert len(result["functions"]) == len(cg["functions"]) == 3


def test_library_mode_seeds_public_surface(tmp_path):
    _, cg = build(tmp_path, {"lib.swift": """
        public func exposed() { helper() }
        func helper() {}
        func unreached() {}
    """})
    pipeline = _load_pipeline()
    result = pipeline.apply_reachability_filter(cg, str(tmp_path), library_mode=True)
    kept = {fid.split(":", 1)[1] for fid in result["functions"]}
    assert "exposed" in kept and "helper" in kept   # public seed + its callee
    assert "unreached" not in kept                  # not reachable from the public API
