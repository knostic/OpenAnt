"""Generic dispatch from a TestExecutionPlan's ``result_strategy`` to a
result parser.

JUnit XML is emitted by many ecosystems' test runners (pytest natively;
jest via jest-junit; go test via go-junit-report; mvn/gradle natively;
cargo via cargo2junit) -- one parser serves all of them, so this stays a
small dispatch table rather than a plugin system. TAP (tap_parser.py) is
likewise emitted by many unrelated producers (Node's built-in test
runner, Perl's `prove`, Rust harnesses via a TAP flag, bespoke harnesses)
-- it is a second RESULT FORMAT, not a Node-specific or ecosystem-specific
addition. ``exit_code`` needs no parsing at all: the comparator reads
``TestExecutionResult.exit_code`` directly (see existing_test_regression.py).

Deterministic only. No LLM is ever consulted about whether output "looks
like" a pass or a failure.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


# Bounded, generic diagnostic size -- one failed/errored TEST's message+body,
# not a whole run's output (see existing_test_regression._MAX_EXCERPT_CHARS
# for that, separate, whole-run budget). A single testcase's traceback can be
# arbitrarily long; this keeps a per-test diagnostic small enough to persist
# safely without approaching the whole-run excerpt budget.
_MAX_DIAGNOSTIC_CHARS = 2_000


def _bounded_diagnostic(text: "str | None") -> "str | None":
    """Bound one test's diagnostic text to a small, fixed size. Generic --
    used identically by JUnit (this module) and TAP (tap_parser.py) -- never
    a runner-specific behavior. Returns None for empty/whitespace-only
    input, never an empty string, so callers can use a plain truthiness
    check."""
    if not text:
        return None
    text = text.strip()
    if not text:
        return None
    if len(text) <= _MAX_DIAGNOSTIC_CHARS:
        return text
    omitted = len(text) - _MAX_DIAGNOSTIC_CHARS
    return text[:_MAX_DIAGNOSTIC_CHARS] + f"\n[… {omitted} character(s) truncated …]"


@dataclass
class ParsedTestCounts:
    passed: int
    failed: int
    skipped: int
    errors: int
    failed_test_ids: "list[str]"
    mode: str  # "full" (per-test IDs available) | "counts_only" (aggregate only)
    # Bounded, per-failed-test diagnostic text (test_id -> message/body),
    # populated only where a failed test's own diagnostic is genuinely
    # available (JUnit's <failure>/<error> message/body; TAP's associated
    # YAML diagnostic block -- see tap_parser.py). Empty for "counts_only"
    # mode (no per-test identity to key it by) and for any test this was
    # simply not available for. Never a claim of identity by itself --
    # always keyed by an id already present in failed_test_ids.
    failure_diagnostics: "dict[str, str]" = field(default_factory=dict)


def _int_attr(elem: "ET.Element", name: str) -> int:
    try:
        return int(elem.get(name, "0"))
    except (TypeError, ValueError):
        return 0


def _junit_diagnostic(elem: "ET.Element") -> "str | None":
    """Standard JUnit XML puts a short human-readable summary in a
    failure/error element's own ``message`` attribute and a fuller
    traceback/body in its text content -- both are part of the SAME
    generic JUnit schema every ecosystem's junit-xml writer emits (pytest
    natively; jest via jest-junit; go-junit-report; mvn/gradle; cargo2junit
    -- see this module's own docstring), never a runner-specific
    extension. Combines whichever of the two are present, bounded."""
    message = (elem.get("message") or "").strip()
    body = (elem.text or "").strip()
    parts = [p for p in (message, body) if p]
    return _bounded_diagnostic("\n".join(parts)) if parts else None


def parse_junit_xml(xml_text: "str | None") -> "ParsedTestCounts | None":
    """Parse a JUnit XML report. Returns ``None`` when the text is
    missing, empty, or not parseable as XML, or reports zero tests --
    never raises, never guesses."""
    if not xml_text or not xml_text.strip():
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    testcases = list(root.iter("testcase"))
    if testcases:
        passed = failed = skipped = errors = 0
        failed_ids: "list[str]" = []
        diagnostics: "dict[str, str]" = {}
        for tc in testcases:
            classname = tc.get("classname", "")
            name = tc.get("name", "")
            test_id = f"{classname}::{name}" if classname else name
            failure_elem = tc.find("failure")
            error_elem = tc.find("error")
            if failure_elem is not None:
                failed += 1
                failed_ids.append(test_id)
                diag = _junit_diagnostic(failure_elem)
                if diag:
                    diagnostics[test_id] = diag
            elif error_elem is not None:
                errors += 1
                failed_ids.append(test_id)
                diag = _junit_diagnostic(error_elem)
                if diag:
                    diagnostics[test_id] = diag
            elif tc.find("skipped") is not None:
                skipped += 1
            else:
                passed += 1
        return ParsedTestCounts(
            passed, failed, skipped, errors, failed_ids, mode="full", failure_diagnostics=diagnostics,
        )

    # No <testcase> elements. Fall back to suite-level aggregate counts if
    # present -- never invent individual test names in this branch.
    suites = list(root.iter("testsuite"))
    if suites:
        tests = sum(_int_attr(s, "tests") for s in suites)
        failures = sum(_int_attr(s, "failures") for s in suites)
        errors = sum(_int_attr(s, "errors") for s in suites)
        skipped = sum(_int_attr(s, "skipped") for s in suites)
        if tests > 0:
            passed = max(tests - failures - errors - skipped, 0)
            return ParsedTestCounts(passed, failures, skipped, errors, failed_test_ids=[], mode="counts_only")

    return None


def _parse_tap(text: "str | None") -> "ParsedTestCounts | None":
    from .tap_parser import parse_tap  # local import -- avoid a cycle at module load
    return parse_tap(text)


_PARSERS = {"junit": parse_junit_xml, "tap": _parse_tap}


def parse_result(result_strategy: str, raw_text: "str | None") -> "ParsedTestCounts | None":
    parser = _PARSERS.get(result_strategy)
    if parser is None:
        return None
    return parser(raw_text)
