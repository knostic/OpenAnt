"""Tests for EntryPointDetector — a silent binary `main` (C/Go) classified
unit_type='main' must be seeded as a reachability entry point.

Regression for the gap where `main` was missing from ENTRY_POINT_TYPES: the C
and Go extractors correctly classify a program's `main` function as
unit_type='main', but the detector only honored unit types in
ENTRY_POINT_TYPES. A *silent* main (no user-input pattern, no decorator, not
module_level) therefore produced zero entry-point reasons, was never seeded as
an execution root, and every function it transitively calls was falsely marked
unreachable (reachability blackout on CLI/binary programs).

A program's `main` is an execution root by definition; over-approximating it as
an entry point is safe (a false-unreachable hides exploitable code), and a
library has no `main`, so this does not over-claim.
"""
import sys
from pathlib import Path

# tests/parsers/ -> parents[2] == libs/openant-core (the dir containing utilities/)
_CORE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_CORE_ROOT))

from utilities.agentic_enhancer.entry_point_detector import (  # noqa: E402
    ENTRY_POINT_TYPES,
    EntryPointDetector,
)


def _make_detector(func_id: str, func_data: dict) -> EntryPointDetector:
    return EntryPointDetector({func_id: func_data}, call_graph={})


def test_main_is_in_entry_point_types():
    """`main` must be a recognized entry-point unit type so the reachability
    filter treats a program's execution root as a seed."""
    assert "main" in ENTRY_POINT_TYPES, (
        "'main' must be in ENTRY_POINT_TYPES so a function classified "
        "unit_type='main' is seeded as a reachability entry point"
    )


def test_silent_c_main_is_entry_point():
    """A silent C `main` (no user-input pattern, no decorator) classified
    unit_type='main' must be detected as an entry point."""
    detector = _make_detector(
        "main.c:main",
        {
            "name": "main",
            "unit_type": "main",
            "code": "int main(void) { helper(); return 0; }",
            "decorators": [],
        },
    )
    entry_points = detector.detect_entry_points()
    assert "main.c:main" in entry_points, (
        "silent C main was filtered out — its callees become falsely unreachable"
    )


def test_silent_go_main_is_entry_point():
    """A silent Go `main` classified unit_type='main' must be detected as an
    entry point (language-agnostic: same unit_type, same seeding)."""
    detector = _make_detector(
        "main.go:main",
        {
            "name": "main",
            "unit_type": "main",
            "code": "func main() { helper() }",
            "decorators": [],
        },
    )
    entry_points = detector.detect_entry_points()
    assert "main.go:main" in entry_points, (
        "silent Go main was filtered out — its callees become falsely unreachable"
    )


def test_main_by_name_is_entry_point():
    """Defensive: a function named `main` is seeded as an entry point even if
    the extractor classified its unit_type as something other than 'main'
    (e.g. a generic 'function')."""
    detector = _make_detector(
        "main.c:main",
        {
            "name": "main",
            "unit_type": "function",
            "code": "int main(void) { helper(); return 0; }",
            "decorators": [],
        },
    )
    entry_points = detector.detect_entry_points()
    assert "main.c:main" in entry_points, (
        "a function named main must be seeded as an execution root by name"
    )


def test_non_main_silent_function_is_not_entry_point():
    """True-negative anchor: an ordinary silent helper (no main name, no entry
    unit_type, no input pattern) must NOT be an entry point."""
    detector = _make_detector(
        "main.c:helper",
        {
            "name": "helper",
            "unit_type": "function",
            "code": "void helper(void) { return; }",
            "decorators": [],
        },
    )
    entry_points = detector.detect_entry_points()
    assert "main.c:helper" not in entry_points
