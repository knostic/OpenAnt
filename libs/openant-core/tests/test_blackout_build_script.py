"""F18 — a non-runtime `fn main` must not count as a structural entry point.

The Rust extractor classifies `unit_type="main"` for ANY function named `main`
(parsers/rust/function_extractor.py: `if name == "main": return "main"`), with no
file-path check. Several Cargo file kinds carry a `fn main` that is NOT the
crate's deployed runtime user-input entry point:

  * a crate-root `build.rs` (a compile-time build script), and
  * `examples/` and `benches/` targets (auxiliary binaries that CONSUME the
    public API rather than being it).

Each becomes unit_type=main and is counted `structural` by blackout_warning, so a
Rust LIBRARY crate that ships any of them has its library-blackout advisory
silently suppressed. `examples/` is the more common masker than build.rs.

Fix mirrors synthetic_harness: tag `non_runtime_main` on such a main and exclude
it from the structural count, while KEEPING it seeded (over-seeding an entry
point is reachability-safe; only the advisory count changes). The exclusion keys
on the FLAG, never on unit_type — a real `main` (src/main.rs) has no flag and
must stay structural.

Documented residual limits (out of scope, pre-existing): a build script renamed
via Cargo's `build = "custom.rs"` manifest key, and a test-scoped literal
`fn main`, still count structural.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from utilities.agentic_enhancer import blackout_warning, EntryPointDetector  # noqa: E402


# --- blackout_warning half: the non_runtime_main flag must not count structural ---

def test_non_runtime_main_does_not_suppress_warning():
    # Library crate whose ONLY seed is a non-runtime main, 500 -> 20 (96% pruned)
    # — the public API was dropped. Warning MUST fire.
    details = {"b": {"reasons": ["unit_type:main"], "non_runtime_main": True}}
    assert blackout_warning(details, original_count=500, reachable_count=20) is not None


def test_non_runtime_main_plus_incidental_still_warns():
    details = {
        "b": {"reasons": ["unit_type:main"], "non_runtime_main": True},
        "i": {"reasons": ["input_pattern:read"]},
    }
    assert blackout_warning(details, original_count=712, reachable_count=24) is not None


def test_real_main_alongside_non_runtime_still_suppresses():
    # NEGATIVE CONTROL: a genuine src/main.rs main (no flag) IS structural, so a
    # binary crate that also ships a build.rs/examples stays silent.
    details = {
        "b": {"reasons": ["unit_type:main"], "non_runtime_main": True},
        "m": {"reasons": ["unit_type:main"]},
    }
    assert blackout_warning(details, original_count=712, reachable_count=24) is None


# --- detect_entry_points half: tag non_runtime_main from file_path, keep the seed ---

def _det(functions):
    d = EntryPointDetector(functions, call_graph={})
    d.detect_entry_points()
    return d


def _main(fid, file_path):
    return (fid, {"name": "main", "unit_type": "main", "file_path": file_path, "code": ""})


def test_detect_tags_non_runtime_mains():
    cases = dict([
        _main("build.rs:main", "build.rs"),                 # crate-root build script
        _main("crate/build.rs:main", "mycrate/build.rs"),   # workspace member build script
        _main("examples/demo.rs:main", "examples/demo.rs"), # Cargo example target
        _main("benches/bench.rs:main", "benches/bench.rs"), # Cargo bench target
    ])
    d = _det(cases)
    for fid in cases:
        assert d.entry_point_details[fid]["non_runtime_main"] is True, fid
        # Over-seed-safe: still an entry point (seed kept).
        assert fid in d.entry_points, fid


def test_detect_does_not_tag_real_main():
    d = _det(dict([_main("src/main.rs:main", "src/main.rs")]))
    assert d.entry_point_details["src/main.rs:main"].get("non_runtime_main") is False
    assert "src/main.rs:main" in d.entry_points


def test_detect_does_not_tag_src_modules_named_like_targets():
    # A module UNDER src/ named build.rs / in a src/examples subdir is a normal
    # module, NOT a Cargo build script or example target. Must NOT be tagged.
    d = _det(dict([
        _main("src/build.rs:main", "src/build.rs"),
        _main("src/examples/x.rs:main", "src/examples/x.rs"),
    ]))
    assert d.entry_point_details["src/build.rs:main"].get("non_runtime_main") is False
    assert d.entry_point_details["src/examples/x.rs:main"].get("non_runtime_main") is False
