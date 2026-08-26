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
from dataclasses import dataclass


@dataclass
class ParsedTestCounts:
    passed: int
    failed: int
    skipped: int
    errors: int
    failed_test_ids: "list[str]"
    mode: str  # "full" (per-test IDs available) | "counts_only" (aggregate only)


def _int_attr(elem: "ET.Element", name: str) -> int:
    try:
        return int(elem.get(name, "0"))
    except (TypeError, ValueError):
        return 0


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
        for tc in testcases:
            classname = tc.get("classname", "")
            name = tc.get("name", "")
            test_id = f"{classname}::{name}" if classname else name
            if tc.find("failure") is not None:
                failed += 1
                failed_ids.append(test_id)
            elif tc.find("error") is not None:
                errors += 1
                failed_ids.append(test_id)
            elif tc.find("skipped") is not None:
                skipped += 1
            else:
                passed += 1
        return ParsedTestCounts(passed, failed, skipped, errors, failed_ids, mode="full")

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
