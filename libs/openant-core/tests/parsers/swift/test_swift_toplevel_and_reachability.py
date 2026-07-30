"""Top-level main.swift synthesis (Fable F8) + entry-point seeding / reachability
for a library-heavy target (the security-pcc shape)."""

import importlib.util
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_CORE = _HERE.parents[2]
sys.path.insert(0, str(_HERE))
from _helpers import extract, build  # noqa: E402


def _load(rel, name):
    spec = importlib.util.spec_from_file_location(name, _CORE / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


_EPD = _load("utilities/agentic_enhancer/entry_point_detector.py", "swift_epd_iso2")


def test_toplevel_main_swift_synthesized(tmp_path):
    """main.swift top-level executable code becomes a `main` unit (else the tool's
    real entry + everything it reaches is invisible)."""
    ext = extract(tmp_path, {"main.swift": """
        import Foundation
        let s = start()
        runTool()
    """})
    tops = [f for fid, f in ext["functions"].items() if f["qualified_name"] == "<top-level>"]
    assert tops, "main.swift top-level code must synthesize a unit"
    assert tops[0]["unit_type"] == "main"


def test_non_main_file_no_toplevel_unit(tmp_path):
    """Only main.swift synthesizes a top-level unit (top-level code elsewhere is a
    compile error in a normal target)."""
    ext = extract(tmp_path, {"Other.swift": "func f() { g() }\nfunc g() {}"})
    assert not any(f["qualified_name"] == "<top-level>" for f in ext["functions"].values())


def test_main_seeds_reachability(tmp_path):
    """The synthesized main unit is a structural entry point."""
    ext, _ = build(tmp_path, {"main.swift": "let x = boot()\nfunc boot() {}"})
    detector = _EPD.EntryPointDetector(ext["functions"], {})
    eps = detector.detect_entry_points()
    top = [fid for fid, f in ext["functions"].items() if f["qualified_name"] == "<top-level>"][0]
    assert top in eps


def test_library_mode_seeds_public_api(tmp_path):
    """A pure library (no main/route) is seeded via its public/open API surface;
    internal-only functions are not part of the seed (Fable F6)."""
    ext, _ = build(tmp_path, {"Lib.swift": """
        public struct API {
            public func publicEntry() {}
            func internalHelper() {}
        }
    """})
    funcs = ext["functions"]
    # No structural entry points (no main/route/handler).
    detector = _EPD.EntryPointDetector(funcs, {})
    assert not any(r for r in (detector.detect_entry_points()))
    # Library seeding picks up the public method, not the internal one.
    seeds = _EPD.library_seed_ids(funcs)
    seed_leaves = {s.split(":", 1)[1] for s in seeds}
    assert "API.publicEntry" in seed_leaves
    assert "API.internalHelper" not in seed_leaves


def test_objc_method_seeds_without_public(tmp_path):
    """An @objc method is externally callable via the ObjC runtime even when not
    public → seeded as an entry point (Fable F7)."""
    ext = extract(tmp_path, {"C.swift": """
        class Handler {
            @objc func onEvent() {}
            func plain() {}
        }
    """})
    detector = _EPD.EntryPointDetector(ext["functions"], {})
    eps = detector.detect_entry_points()
    leaves = {fid.split(":", 1)[1] for fid in eps}
    assert "Handler.onEvent" in leaves
    assert "Handler.plain" not in leaves
