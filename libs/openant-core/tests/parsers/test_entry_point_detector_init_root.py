"""Regression: a Go `func init()` is an auto-run execution root and must be
seeded as a reachability entry point.

Go runs every package-level `init()` automatically at program startup, before
`main` (Go spec: "Package initialization"). The Go extractor classifies it as
unit_type='init' (go_parser/types.go UnitTypeInit). But the detector only
honored unit types in ENTRY_POINT_TYPES, and 'init' was absent, so a silent
`init` (no user-input pattern, not named `main`) produced zero entry-point
reasons and every function it transitively calls was falsely marked unreachable
— a reachability blackout for startup-time code (config loaders, registrations,
side-effecting package init that reaches real sinks).

An auto-run root is an execution root by definition; over-approximating it as an
entry point is reachability-safe (a false-unreachable hides exploitable code),
and a library without `init` does not gain a spurious seed.
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


def test_init_is_in_entry_point_types():
    """'init' must be a recognized entry-point unit type so a function
    classified unit_type='init' is seeded as a reachability root."""
    assert "init" in ENTRY_POINT_TYPES, (
        "'init' must be in ENTRY_POINT_TYPES: Go runs func init() automatically "
        "at startup, so it is an execution root and its callees must be reachable"
    )


def test_silent_go_init_is_entry_point():
    """A silent Go `init` (no user-input pattern, not named main) classified
    unit_type='init' must be detected as an entry point."""
    detector = _make_detector(
        "main.go:init",
        {"name": "init", "unit_type": "init", "code": "func init() { startup() }"},
    )
    entry_points = detector.detect_entry_points()
    assert "main.go:init" in entry_points, (
        "a Go func init() (unit_type='init') must be seeded as an entry point; "
        "it runs automatically at startup"
    )
    reasons = detector.entry_point_details["main.go:init"]["reasons"]
    assert any("init" in r for r in reasons), reasons


def test_init_callees_stay_reachable():
    """The transitive callees of a silent init() must not be falsely pruned."""
    functions = {
        "main.go:init": {"name": "init", "unit_type": "init", "code": "func init() { startup() }"},
        "main.go:startup": {"name": "startup", "unit_type": "function", "code": "func startup() { sink() }"},
        "main.go:sink": {"name": "sink", "unit_type": "function", "code": "func sink() {}"},
    }
    call_graph = {"main.go:init": ["main.go:startup"], "main.go:startup": ["main.go:sink"]}
    seeds = EntryPointDetector(functions, call_graph).detect_entry_points()
    reach = set(seeds)
    stack = list(seeds)
    while stack:
        for callee in call_graph.get(stack.pop(), []):
            if callee not in reach:
                reach.add(callee)
                stack.append(callee)
    assert "main.go:sink" in reach, (
        "sink() runs at startup via init()->startup() but was marked unreachable"
    )
