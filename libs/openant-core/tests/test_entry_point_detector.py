"""Tests for EntryPointDetector — specifically that Express unit types
produced by the JS analyzer are recognised as entry points and therefore
survive the reachability filter.
"""
import pytest

from utilities.agentic_enhancer.entry_point_detector import (
    ENTRY_POINT_TYPES,
    EntryPointDetector,
)


def _make_detector(unit_type: str) -> EntryPointDetector:
    functions = {
        "server.js:fn": {
            "name": "fn",
            "unit_type": unit_type,
            "code": "async (req, res, next) => { next(); }",
        }
    }
    return EntryPointDetector(functions, call_graph={})


def test_route_handler_is_entry_point():
    detector = _make_detector("route_handler")
    entry_points = detector.detect_entry_points()
    assert "server.js:fn" in entry_points


def test_route_middleware_is_entry_point():
    """route_middleware units must be detected as entry points so they are not
    silently dropped by the reachability filter.

    Regression for the gap where `route_middleware` was missing from
    ENTRY_POINT_TYPES: Express anonymous middleware bodies (which receive req
    directly and can be doing anything dangerous) were filtered out before the
    LLM ever saw them.
    """
    assert "route_middleware" in ENTRY_POINT_TYPES, (
        "route_middleware must be in ENTRY_POINT_TYPES so the reachability "
        "filter treats anonymous Express middleware as entry points"
    )

    detector = _make_detector("route_middleware")
    entry_points = detector.detect_entry_points()
    assert "server.js:fn" in entry_points, (
        "route_middleware unit was filtered out — it must survive as an entry point"
    )


def test_unknown_unit_type_is_not_entry_point():
    """A unit with an unrecognised unit_type is not an entry point unless it
    matches a decorator or user-input pattern."""
    detector = _make_detector("utility")
    entry_points = detector.detect_entry_points()
    assert "server.js:fn" not in entry_points
