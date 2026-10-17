"""Tests for the generic result-strategy parser dispatch."""

from __future__ import annotations

from utilities.autopatcher.result_parsers import parse_junit_xml, parse_result


def _junit(passed=0, failed_ids=(), errors=0, skipped=0):
    testcases = []
    for tid in failed_ids:
        classname, _, name = tid.rpartition("::")
        testcases.append(f'<testcase classname="{classname}" name="{name}"><failure>boom</failure></testcase>')
    for i in range(passed):
        testcases.append(f'<testcase classname="tests.test_mod" name="test_pass_{i}"/>')
    for i in range(skipped):
        testcases.append(f'<testcase classname="tests.test_mod" name="test_skip_{i}"><skipped/></testcase>')
    for i in range(errors):
        testcases.append(f'<testcase classname="tests.test_mod" name="test_err_{i}"><error>boom</error></testcase>')
    body = "".join(testcases)
    total = passed + len(failed_ids) + errors + skipped
    return (
        f'<testsuites><testsuite name="pytest" tests="{total}" '
        f'failures="{len(failed_ids)}" errors="{errors}" skipped="{skipped}">{body}</testsuite></testsuites>'
    )


class TestParseJunitXml:
    def test_none_or_empty_returns_none(self):
        assert parse_junit_xml(None) is None
        assert parse_junit_xml("") is None
        assert parse_junit_xml("   ") is None

    def test_malformed_xml_returns_none(self):
        assert parse_junit_xml("<not><valid") is None

    def test_full_parse_with_failures_errors_skipped(self):
        xml = _junit(passed=2, failed_ids=["tests.test_mod::test_fail"], errors=1, skipped=1)
        parsed = parse_junit_xml(xml)
        assert parsed is not None
        assert parsed.mode == "full"
        assert parsed.passed == 2
        assert parsed.failed == 1
        assert parsed.errors == 1
        assert parsed.skipped == 1
        assert parsed.failed_test_ids == ["tests.test_mod::test_fail", "tests.test_mod::test_err_0"]

    def test_counts_only_fallback_when_no_testcases(self):
        xml = '<testsuites><testsuite name="pytest" tests="5" failures="2" errors="0" skipped="0"></testsuite></testsuites>'
        parsed = parse_junit_xml(xml)
        assert parsed is not None
        assert parsed.mode == "counts_only"
        assert parsed.passed == 3
        assert parsed.failed == 2
        assert parsed.failed_test_ids == []

    def test_zero_tests_suite_returns_none(self):
        xml = '<testsuites><testsuite name="pytest" tests="0"></testsuite></testsuites>'
        assert parse_junit_xml(xml) is None


class TestFailureDiagnostics:
    """Bounded, per-failed-test diagnostic text preserved from JUnit's own
    <failure>/<error> message attribute + body -- generic JUnit schema,
    never runner-specific."""

    def test_failure_message_and_body_are_combined(self):
        xml = (
            '<testsuites><testsuite name="pytest" tests="1" failures="1">'
            '<testcase classname="tests.test_mod" name="test_fail">'
            '<failure message="assert 1 == 2">Traceback (most recent call last):\n'
            '    assert 1 == 2\nAssertionError</failure>'
            '</testcase></testsuite></testsuites>'
        )
        parsed = parse_junit_xml(xml)
        assert parsed is not None
        diag = parsed.failure_diagnostics["tests.test_mod::test_fail"]
        assert "assert 1 == 2" in diag
        assert "AssertionError" in diag

    def test_error_element_diagnostic_is_preserved(self):
        xml = (
            '<testsuites><testsuite name="pytest" tests="1" errors="1">'
            '<testcase classname="tests.test_mod" name="test_err">'
            '<error message="ImportError: no module named foo">boom</error>'
            '</testcase></testsuite></testsuites>'
        )
        parsed = parse_junit_xml(xml)
        assert parsed is not None
        assert "ImportError" in parsed.failure_diagnostics["tests.test_mod::test_err"]

    def test_diagnostic_is_bounded(self):
        huge = "x" * 50_000
        xml = (
            '<testsuites><testsuite name="pytest" tests="1" failures="1">'
            '<testcase classname="tests.test_mod" name="test_fail">'
            f'<failure>{huge}</failure>'
            '</testcase></testsuite></testsuites>'
        )
        parsed = parse_junit_xml(xml)
        assert parsed is not None
        diag = parsed.failure_diagnostics["tests.test_mod::test_fail"]
        assert len(diag) < 3_000
        assert "truncated" in diag

    def test_passing_tests_get_no_diagnostic(self):
        xml = _junit(passed=2, failed_ids=["tests.test_mod::test_fail"])
        parsed = parse_junit_xml(xml)
        assert parsed is not None
        assert set(parsed.failure_diagnostics.keys()) == {"tests.test_mod::test_fail"}
        assert "tests.test_mod::test_pass_0" not in parsed.failure_diagnostics
        assert "tests.test_mod::test_pass_1" not in parsed.failure_diagnostics

    def test_counts_only_mode_has_no_diagnostics(self):
        xml = '<testsuites><testsuite name="pytest" tests="5" failures="2" errors="0" skipped="0"></testsuite></testsuites>'
        parsed = parse_junit_xml(xml)
        assert parsed is not None
        assert parsed.mode == "counts_only"
        assert parsed.failure_diagnostics == {}

    def test_no_failure_element_body_or_message_yields_no_diagnostic_entry(self):
        xml = (
            '<testsuites><testsuite name="pytest" tests="1" failures="1">'
            '<testcase classname="tests.test_mod" name="test_fail"><failure/></testcase>'
            '</testsuite></testsuites>'
        )
        parsed = parse_junit_xml(xml)
        assert parsed is not None
        assert parsed.failed_test_ids == ["tests.test_mod::test_fail"]
        assert "tests.test_mod::test_fail" not in parsed.failure_diagnostics


class TestParseResultDispatch:
    def test_junit_dispatches_to_junit_parser(self):
        xml = _junit(passed=3)
        result = parse_result("junit", xml)
        assert result is not None
        assert result.passed == 3

    def test_exit_code_strategy_has_no_parser(self):
        """exit_code needs no parsing at all -- the comparator reads
        TestExecutionResult.exit_code directly."""
        assert parse_result("exit_code", "anything") is None

    def test_unknown_strategy_returns_none(self):
        assert parse_result("xunit", "1..1\nok 1") is None

    def test_tap_dispatches_to_tap_parser(self):
        result = parse_result("tap", "1..1\nok 1")
        assert result is not None
        assert result.passed == 1
