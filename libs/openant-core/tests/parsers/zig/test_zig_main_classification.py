"""Zig `main` classification.

The Zig FunctionExtractor has a dedicated branch for `main` that returned the
generic 'function' unit_type instead of an entry-point type:

    # Main entry point
    if name == "main":
        return "function"

C and Go classify a top-level main as unit_type='main'; Zig folded it into
'function'. With 'main' an ENTRY_POINT_TYPE in the central detector, Zig must emit
'main' so a Zig binary's entry point seeds reachability — otherwise the Zig
classifier is the lone divergent parser and Zig binaries stay blacked out.

function_extractor.py recurs across parser packages, so this module is loaded
under a unique name via importlib to avoid sys.modules collisions with the
C/Python sibling extractors.
"""

import importlib.util
import pathlib

_CORE = pathlib.Path(__file__).resolve().parents[3]
_ZIG_FE = _CORE / "parsers" / "zig" / "function_extractor.py"


def _load_zig_extractor():
    spec = importlib.util.spec_from_file_location("isolated_zig_function_extractor", _ZIG_FE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _classify(name: str) -> str:
    mod = _load_zig_extractor()
    # _classify_function only uses (name, file_path); construct a minimal
    # extractor (scan_results unused by the classifier).
    extractor = mod.FunctionExtractor.__new__(mod.FunctionExtractor)
    return extractor._classify_function(name, "src/main.zig")


def test_zig_main_classified_as_main():
    assert _classify("main") == "main", (
        "Zig must classify a top-level `main` as unit_type='main' (matching C/Go) "
        "so it is recognised as a program entry point"
    )


def test_zig_main_is_distinct_from_plain_function():
    # A regular function still classifies as 'function'; only `main` is special.
    assert _classify("handleRequest") == "function"
    assert _classify("main") != _classify("handleRequest")


def test_zig_other_classifications_unchanged():
    # Guard against over-broadening the fix.
    assert _classify("init") == "constructor"
    assert _classify("create") == "constructor"
    assert _classify("testThing") == "test"
