"""EntryPointDetector cross-language entry-point gaps.

Covers two central-detector faults:

* Program-entry unit_types the parsers actually emit ('main' from C/Go/Zig,
  'http_handler' / 'middleware' from Go) are absent from ENTRY_POINT_TYPES, so a
  native program entry seeds ZERO entry points -> total reachability blackout for
  C/Go/Zig binaries.

* The per-parser reachable path normalizes func metadata under the camelCase key
  'unitType' (c/php/ruby test_pipeline.py:257), but _get_entry_point_reasons reads
  the snake_case 'unit_type' only -> Check-1 (and the module_level Check-4) are
  dead on the real subprocess path even for an entry type that IS in the set.

These assertions are written against the central detector contract, so they hold
regardless of which parser produced the data.
"""

from utilities.agentic_enhancer.entry_point_detector import (
    ENTRY_POINT_TYPES,
    EntryPointDetector,
)


def _detect(func_data: dict, func_id: str = "src/main.c:main"):
    detector = EntryPointDetector({func_id: func_data}, call_graph={})
    return detector.detect_entry_points(), detector


# --- Cluster A: program-entry types missing from the central set ----------

def test_main_unit_type_is_an_entry_point_type():
    """C/Go emit unit_type='main'; Zig (after its classifier fix) does too.
    Without 'main' in ENTRY_POINT_TYPES a native program entry seeds nothing."""
    assert "main" in ENTRY_POINT_TYPES, (
        "'main' must be in ENTRY_POINT_TYPES so a native program entry "
        "(C/Go/Zig main) seeds reachability"
    )


def test_native_main_seeds_an_entry_point():
    eps, _ = _detect(
        {"name": "main", "unit_type": "main", "code": "int main(void){return 0;}"}
    )
    assert "src/main.c:main" in eps, (
        "a function with unit_type='main' must be detected as an entry point"
    )


def test_go_http_handler_and_middleware_are_entry_point_types():
    """The Go parser emits 'http_handler' and 'middleware' (go_parser/types.go
    UnitTypeHTTPHandler / UnitTypeMiddleware) but the detector only knew the
    Python/Express vocabulary -> Go web servers seeded no entry points."""
    assert "http_handler" in ENTRY_POINT_TYPES
    assert "middleware" in ENTRY_POINT_TYPES


# --- Cluster B: camelCase 'unitType' key must also be honoured ------------

def test_unit_type_read_handles_camelcase_unitType_key():
    """The C/PHP/Ruby reachable path writes the camelCase 'unitType' key; the
    detector previously read snake-case 'unit_type' only, so Check-1 was dead on
    that path even for a valid entry type."""
    eps, _ = _detect(
        {"name": "handler", "unitType": "route_handler", "code": ""},
        func_id="app.py:handler",
    )
    assert "app.py:handler" in eps, (
        "an entry unit normalized under the camelCase 'unitType' key must still "
        "be recognised as an entry point"
    )


def test_camelcase_main_is_an_entry_point():
    """End-to-end of Cluster A + B together: a C 'main' normalized to the
    camelCase key must seed reachability."""
    eps, _ = _detect(
        {"name": "main", "unitType": "main", "code": "int main(void){return 0;}"}
    )
    assert "src/main.c:main" in eps


def test_module_level_check4_handles_camelcase_key():
    """Check-4 keys off unit_type=='module_level'; it must also see the
    camelCase 'unitType' so module-level scripts on the camel path still seed."""
    # Use a code pattern that ONLY Check-4 (module_level) matches — the
    # __name__ guard is in MODULE_LEVEL_INPUT_PATTERNS but NOT in
    # USER_INPUT_PATTERNS, so Check-3 cannot mask the result.
    eps, _ = _detect(
        {
            "name": "__module__",
            "unitType": "module_level",
            "code": 'if __name__ == "__main__":\n    run()',
        },
        func_id="script.py:__module__",
    )
    assert "script.py:__module__" in eps
