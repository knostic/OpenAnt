"""Tests for Existing Test Comparison's comparison algorithm,
orchestration (Test Plan Discovery -> validation -> executor selection ->
baseline/patched execution -> comparison), and report/signal rendering.

Docker and the LLM are never actually invoked here -- `discover_test_plan`
and the selected executor's `.run()` are mocked at the
existing_test_regression module boundary throughout.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest import mock

import pytest

import utilities.autopatcher.existing_test_regression as etr
import utilities.autopatcher.test_executors as test_executors_mod
from utilities.autopatcher.test_execution_models import (
    ExecutorPreflightResult,
    TestExecutionPlan,
    TestExecutionResult,
)


def _preflight_ok() -> ExecutorPreflightResult:
    return ExecutorPreflightResult(ready=True, reason=None, status="OK")


def _unready_executor(reason: str, status: str = "DAEMON_UNREACHABLE") -> mock.MagicMock:
    """A MagicMock standing in for select_executor("docker")'s return
    value, with .preflight() reporting not-ready. .run() is deliberately
    left unconfigured -- these tests assert it's never called."""
    executor = mock.MagicMock()
    executor.preflight.return_value = ExecutorPreflightResult(ready=False, reason=reason, status=status)
    return executor


def _ready_executor() -> mock.MagicMock:
    executor = mock.MagicMock()
    executor.preflight.return_value = _preflight_ok()
    return executor


def _plan(**overrides) -> TestExecutionPlan:
    base = dict(
        setup_commands=(), test_command=("python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"),
        result_strategy="junit", result_output_path="/tmp/openant-result.xml",
        runtime_family="python", runtime_version_hint="3.11",
        evidence=("pyproject.toml",), reasoning_summary="pytest configured via pyproject.toml.",
        confidence="high", source="llm",
    )
    base.update(overrides)
    return TestExecutionPlan(**base)


_EXIT_CODE_PLAN = _plan(test_command=("make", "test"), result_strategy="exit_code", result_output_path=None)
_TAP_PLAN = _plan(
    test_command=("node", "--test"), result_strategy="tap", result_output_path=None,
    runtime_family="node", evidence=("package.json",),
)


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


def _tap(passed=0, failed_ids=(), skipped=0):
    """Build flat TAP text for `passed` anonymous passes plus one
    "not ok - <id>" line per entry in `failed_ids` -- enough for
    _to_test_run_result/compare_runs integration tests; the TAP parser's
    own mechanics (nesting, directives, malformed/truncated input) are
    covered exhaustively in test_tap_parser.py."""
    lines = ["TAP version 13"]
    n = 0
    for _ in range(passed):
        n += 1
        lines.append(f"ok {n} - pass_{n}")
    for tid in failed_ids:
        n += 1
        lines.append(f"not ok {n} - {tid}")
    for _ in range(skipped):
        n += 1
        lines.append(f"ok {n} - skip_{n} # SKIP")
    lines.append(f"1..{n}")
    return "\n".join(lines) + "\n"


def _exec_result(result_output=None, exit_code=0, timed_out=False, setup_failed=False,
                  setup_error="", stdout="", stderr="", duration=1.0):
    return TestExecutionResult(
        ran=not timed_out and not setup_failed, exit_code=exit_code, timed_out=timed_out,
        setup_failed=setup_failed, setup_error=setup_error, stdout=stdout, stderr=stderr,
        result_output=result_output, duration_seconds=duration, executor="docker",
    )


def _make_git_repo(root: Path) -> Path:
    subprocess.run(["git", "init"], cwd=root, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=root, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=root, capture_output=True)
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (root / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=root, capture_output=True, check=True)
    return root


_SOME_PATCH = """\
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
 def add(a, b):
+    # comment
     return a + b
"""

_DUMMY_LLM = object()  # never actually used -- discover_test_plan is mocked in every orchestration test


# ---------------------------------------------------------------------------
# Comparison algorithm
# ---------------------------------------------------------------------------

def _run(passed, failed_ids=(), errors=0, skipped=0, level="OK", exit_code=None):
    if exit_code is None:
        exit_code = 1 if (failed_ids or errors) else 0
    return etr.TestRunResult(
        command=("python", "-m", "pytest"), status="COMPLETED", exit_code=exit_code,
        duration_seconds=1.0, passed=passed, failed=len(failed_ids), skipped=skipped, errors=errors,
        failed_test_ids=list(failed_ids), stdout_excerpt="", stderr_excerpt="",
        timed_out=False, evidence_level=level,
    )


def _exit_only(exit_code):
    return etr.TestRunResult(
        command=("make", "test"), status="COMPLETED", exit_code=exit_code, duration_seconds=1.0,
        passed=None, failed=None, skipped=None, errors=None, failed_test_ids=None,
        stdout_excerpt="", stderr_excerpt="", timed_out=False, evidence_level="EXIT_CODE_ONLY",
    )


class TestCompareRunsFullIdLevel:
    def test_pass_pass_is_pass(self):
        r = etr.compare_runs(("cmd",), _run(428), _run(428))
        assert r.status == etr.STATUS_PASS
        assert r.newly_failing_tests == []

    def test_same_failures_both_sides_is_pre_existing_only(self):
        b = _run(100, failed_ids=["t::a", "t::b"])
        p = _run(100, failed_ids=["t::a", "t::b"])
        r = etr.compare_runs(("cmd",), b, p)
        assert r.status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY
        assert r.newly_failing_tests == []
        assert sorted(r.pre_existing_failures) == ["t::a", "t::b"]

    def test_new_failure_is_new_failures_detected(self):
        b = _run(102)
        p = _run(101, failed_ids=["t::new_fail"])
        r = etr.compare_runs(("cmd",), b, p)
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == ["t::new_fail"]

    def test_pre_existing_failure_fixed_is_not_a_new_failure(self):
        b = _run(100, failed_ids=["t::a", "t::b"])
        p = _run(101, failed_ids=["t::a"])
        r = etr.compare_runs(("cmd",), b, p)
        assert r.status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY
        assert r.newly_failing_tests == []
        assert r.newly_passing_tests == ["t::b"]

    def test_all_failures_fixed_is_pass(self):
        b = _run(100, failed_ids=["t::a"])
        p = _run(101)
        r = etr.compare_runs(("cmd",), b, p)
        assert r.status == etr.STATUS_PASS

    def test_baseline_does_not_need_to_be_green(self):
        b = _run(50, failed_ids=["t::a", "t::b", "t::c"])
        p = _run(52, failed_ids=["t::a"])
        r = etr.compare_runs(("cmd",), b, p)
        assert r.status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY


class TestCompareRunsCountOnlyFallback:
    def test_count_increase_is_new_failures_without_named_tests(self):
        b = _run(100, level="COUNTS_ONLY"); b.failed = 0
        p = _run(98, level="COUNTS_ONLY"); p.failed = 2
        r = etr.compare_runs(("cmd",), b, p)
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == []
        assert "could not be identified" in r.reason

    def test_no_increase_is_pre_existing(self):
        b = _run(100, level="COUNTS_ONLY"); b.failed = 2
        p = _run(100, level="COUNTS_ONLY"); p.failed = 2
        r = etr.compare_runs(("cmd",), b, p)
        assert r.status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY

    def test_weaker_side_governs_mixed_ok_and_counts_only(self):
        """If baseline has full IDs but patched only has counts, the
        comparison must use the WEAKER (count-only) mode for both, never
        a partial ID-level claim."""
        b = _run(100, failed_ids=["t::a"], level="OK")
        p = _run(99, level="COUNTS_ONLY"); p.failed = 1
        r = etr.compare_runs(("cmd",), b, p)
        assert r.status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY
        assert r.newly_failing_tests == []  # never asserted at ID level


class TestCompareRunsExitCodeOnly:
    """The approved exit-code-only truth table."""

    def test_zero_zero_is_pass(self):
        r = etr.compare_runs(("make", "test"), _exit_only(0), _exit_only(0))
        assert r.status == etr.STATUS_PASS

    def test_zero_nonzero_is_new_failures_detected_low_detail(self):
        r = etr.compare_runs(("make", "test"), _exit_only(0), _exit_only(1))
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert "exit-code" in r.reason.lower()
        assert "not available" in r.reason or "no individual" in r.reason.lower() or "not available" in r.reason.lower()

    def test_nonzero_nonzero_is_not_verified(self):
        r = etr.compare_runs(("make", "test"), _exit_only(1), _exit_only(1))
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "cannot distinguish" in r.reason

    def test_nonzero_zero_is_pass(self):
        r = etr.compare_runs(("make", "test"), _exit_only(1), _exit_only(0))
        assert r.status == etr.STATUS_PASS

    def test_junit_declared_but_unparseable_falls_back_to_exit_code(self):
        """result_strategy 'junit' with unparseable output must still use
        exit-code-only comparison rather than giving up entirely."""
        raw = _exec_result(result_output="not xml", exit_code=1)
        run_result = etr._to_test_run_result(_plan(), raw)
        assert run_result.evidence_level == "EXIT_CODE_ONLY"
        assert run_result.status == "COMPLETED"

    def test_tap_declared_but_unparseable_falls_back_to_exit_code(self):
        """Same conservative fallback as junit -- malformed/unparseable
        TAP (tap_parser.parse_tap returning None) must still use
        exit-code-only comparison rather than giving up entirely."""
        raw = _exec_result(stdout="not TAP at all\n", exit_code=1)
        run_result = etr._to_test_run_result(_TAP_PLAN, raw)
        assert run_result.evidence_level == "EXIT_CODE_ONLY"
        assert run_result.status == "COMPLETED"


class TestClassificationUnaffectedByEvidenceReshaping:
    """Evidence-handling changes (untruncated TAP source, head+tail
    excerpts) must never change classification. exit_code-only,
    both-sides-nonzero stays exactly the same conservative NOT_VERIFIED,
    regardless of how large the underlying captured output was."""

    def test_exit_code_only_both_nonzero_with_large_output_stays_not_verified(self):
        huge_stdout = "line of test output\n" * 50_000  # well past _MAX_EXCERPT_CHARS
        baseline = etr._to_test_run_result(_EXIT_CODE_PLAN, _exec_result(stdout=huge_stdout, exit_code=1))
        patched = etr._to_test_run_result(_EXIT_CODE_PLAN, _exec_result(stdout=huge_stdout, exit_code=1))
        result = etr.compare_runs(_EXIT_CODE_PLAN.test_command, baseline, patched)
        assert result.status == etr.STATUS_NOT_VERIFIED
        assert "cannot distinguish" in result.reason


# ---------------------------------------------------------------------------
# Runner-summary counts -- deterministic aggregate-count fallback for the
# wrapper-command class (no structured junit/tap report available at all).
# See existing_test_regression.py's own section docstring for the
# empirical validation (real urllib3 capture) and adversarial cases this
# was tested against.
# ---------------------------------------------------------------------------

class TestExtractSummaryPairs:
    """_extract_summary_pairs / _is_plausible_summary -- the line-level
    acceptance rules, tested in isolation before any integration."""

    def test_pytest_shaped_line_accepted(self):
        pairs = etr._extract_summary_pairs("103 failed, 1639 passed, 563 skipped, 163 warnings in 65.69s")
        assert pairs == {"FAILED": 103, "PASSED": 1639, "SKIPPED": 563}
        assert etr._is_plausible_summary(pairs)

    def test_rust_shaped_line_accepted(self):
        pairs = etr._extract_summary_pairs("test result: FAILED. 10 passed; 1 failed; 2 ignored")
        assert pairs == {"PASSED": 10, "FAILED": 1, "SKIPPED": 2}
        assert etr._is_plausible_summary(pairs)

    def test_failed_error_passed_counts_remain_separate(self):
        """pytest's own 'N failed, M error, K passed' shape -- FAILED and
        ERRORED must never be merged into one bucket (an earlier version
        of this parser did, and it broke Maven's real, legitimately
        separate 'Failures: N, Errors: M' convention)."""
        pairs = etr._extract_summary_pairs("1 failed, 1 error, 8 passed in 0.12s")
        assert pairs == {"FAILED": 1, "ERRORED": 1, "PASSED": 8}

    def test_warning_prose_with_two_failure_words_is_rejected(self):
        """Real adversarial case found during investigation: an unrelated
        warning mentioning two failure-domain words together must not
        pass, because it has no resolution-side (passed/total) count at
        all -- exactly what distinguishes incidental prose from an actual
        test-run summary."""
        pairs = etr._extract_summary_pairs("WARNING: upstream reported 3 errors, 4 failures in the last hour")
        assert pairs == {"ERRORED": 3, "FAILED": 4}
        assert not etr._is_plausible_summary(pairs)

    def test_progress_line_rejected(self):
        pairs = etr._extract_summary_pairs("test_x FAILED [47%]")
        assert not etr._is_plausible_summary(pairs)

    def test_exception_text_rejected(self):
        pairs = etr._extract_summary_pairs(
            "Failed to establish a new connection: [Errno 111] Connection refused"
        )
        assert not etr._is_plausible_summary(pairs)

    def test_timing_percentage_line_rejected(self):
        pairs = etr._extract_summary_pairs(
            "5.02s call test/contrib/test_pyopenssl.py::TestSocketSSL::test_x [47%]"
        )
        assert not etr._is_plausible_summary(pairs)

    def test_conflicting_counts_for_same_bucket_rejects_the_line(self):
        assert etr._extract_summary_pairs("3 failed and separately 5 failed were reported") is None

    def test_maven_tests_run_phrasing_is_explicitly_not_supported(self):
        """Documents the known, deliberate gap from the investigation:
        Maven/Surefire's real 'Tests run: N' phrasing has an intervening
        word between the label and its colon, which this generic,
        adjacency-only parser does not tolerate -- accepting it would
        mean special-casing that exact phrase. FAILED/ERRORED/SKIPPED
        still parse; TOTAL does not, and with no PASSED present either,
        the line correctly fails the resolution-side requirement."""
        pairs = etr._extract_summary_pairs("Tests run: 100, Failures: 3, Errors: 2, Skipped: 4")
        assert pairs == {"FAILED": 3, "ERRORED": 2, "SKIPPED": 4}
        assert not etr._is_plausible_summary(pairs)


class TestFindRunnerSummary:
    """_find_runner_summary -- the bounded-tail scan and multi-candidate
    fail-closed behavior."""

    def test_zero_candidates_returns_none(self):
        stdout = "\n".join(f"line {i} with no outcome words" for i in range(50))
        assert etr._find_runner_summary(stdout) is None

    def test_more_than_one_plausible_candidate_returns_none(self):
        """Synthetic multi-session capture -- two independently-valid
        summary lines in one stream (e.g. a wrapper that merges multiple
        interpreter sessions into one stdout) must never be resolved by
        picking one or aggregating them."""
        stdout = (
            "==== 12 failed, 400 passed, 10 skipped in 40.11s ====\n"
            "==== 10 failed, 402 passed, 10 skipped in 39.02s ====\n"
        )
        assert etr._find_runner_summary(stdout) is None

    def test_exactly_one_candidate_is_returned(self):
        stdout = "noise\nmore noise\n==== 103 failed, 1639 passed, 563 skipped in 65.69s ====\n"
        assert etr._find_runner_summary(stdout) == {"FAILED": 103, "PASSED": 1639, "SKIPPED": 563}

    def test_real_urllib3_baseline_and_patched_captures(self):
        """Direct regression anchor for the real CVE-2023-43804 probe this
        mechanism was built to improve: the true captured stdout (~1.1M
        chars) from both sides, reproduced verbatim (trimmed to the
        relevant tail here) -- must recover the exact validated delta."""
        baseline_tail = (
            "FAILED test/with_dummyserver/test_socketlevel.py::TestHeaders::test_request_host_header_ignores_fqdn_dot\n"
            "==== 103 failed, 1639 passed, 563 skipped, 163 warnings in 65.69s (0:01:05) ====\n"
            "__OPENANT_RESULT_START__\n__OPENANT_RESULT_END__\n"
        )
        patched_tail = (
            "FAILED test/with_dummyserver/test_socketlevel.py::TestHeaders::test_request_host_header_ignores_fqdn_dot\n"
            "==== 104 failed, 1638 passed, 563 skipped, 163 warnings in 65.44s (0:01:05) ====\n"
            "__OPENANT_RESULT_START__\n__OPENANT_RESULT_END__\n"
        )
        assert etr._find_runner_summary(baseline_tail) == {"FAILED": 103, "PASSED": 1639, "SKIPPED": 563}
        assert etr._find_runner_summary(patched_tail) == {"FAILED": 104, "PASSED": 1638, "SKIPPED": 563}


class TestRunnerSummaryCountsIntegration:
    """End-to-end: _to_test_run_result -> compare_runs, exercised through
    an exit_code plan the same way production reaches this fallback."""

    _SUMMARY_PLAN = _EXIT_CODE_PLAN  # result_strategy="exit_code" -- no structured evidence declared

    def _run_result(self, stdout: str, exit_code: int = 1):
        return etr._to_test_run_result(self._SUMMARY_PLAN, _exec_result(stdout=stdout, exit_code=exit_code))

    def test_zero_candidates_stays_exit_code_only(self):
        r = self._run_result("no outcome words here at all\n")
        assert r.evidence_level == "EXIT_CODE_ONLY"
        assert r.failed is None and r.passed is None

    def test_accepted_summary_populates_runner_summary_counts(self):
        r = self._run_result("==== 103 failed, 1639 passed, 563 skipped in 65.69s ====\n")
        assert r.evidence_level == "RUNNER_SUMMARY_COUNTS"
        assert r.failed == 103 and r.passed == 1639 and r.skipped == 563
        assert r.failed_test_ids is None  # never claims identities at this tier

    def test_junit_structured_evidence_still_takes_precedence(self):
        """A plan declaring junit, with genuinely parseable junit output,
        must reach OK/COUNTS_ONLY -- the runner-summary fallback is
        integrated strictly AFTER structured parsing fails, never before,
        even if the raw stdout ALSO happens to contain a summary-shaped
        line."""
        raw = _exec_result(
            result_output=_junit(passed=5, failed_ids=["t::a"]),
            stdout="==== 1 failed, 5 passed in 1.0s ====\n",
            exit_code=1,
        )
        result = etr._to_test_run_result(_plan(), raw)
        assert result.evidence_level == "OK"
        assert result.failed_test_ids == ["t::a"]

    def test_adverse_delta_produces_new_failures_detected_with_hedged_reason(self):
        baseline = self._run_result("==== 103 failed, 1639 passed, 563 skipped in 65.69s ====\n")
        patched = self._run_result("==== 104 failed, 1638 passed, 563 skipped in 65.44s ====\n")
        result = etr.compare_runs(self._SUMMARY_PLAN.test_command, baseline, patched)
        assert result.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert result.newly_failing_tests == []  # exact identity remains UNKNOWN at this tier
        assert "could not be identified" in result.reason
        assert "runner-summary" in result.reason
        assert "not structured per-test output" in result.reason
        # must never imply causal proof
        assert "introduced" not in result.reason.lower()

    def test_mismatched_bucket_sets_fall_back_to_exit_code_comparison(self):
        """Baseline's summary omits 'skipped' entirely (some runners drop
        a zero-count category); patched's includes it. Different
        populated-bucket shapes must never be treated as comparable."""
        baseline = self._run_result("==== 3 failed, 100 passed in 1.0s ====\n")
        patched = self._run_result("==== 3 failed, 100 passed, 2 skipped in 1.0s ====\n")
        result = etr.compare_runs(self._SUMMARY_PLAN.test_command, baseline, patched)
        # falls back to plain exit-code comparison -- both sides exited
        # non-zero here, so this is the conservative NOT_VERIFIED path.
        assert result.status == etr.STATUS_NOT_VERIFIED
        assert "cannot distinguish" in result.reason

    def test_report_states_aggregate_evidence_and_unavailable_identity(self):
        baseline = self._run_result("==== 103 failed, 1639 passed, 563 skipped in 65.69s ====\n")
        patched = self._run_result("==== 104 failed, 1638 passed, 563 skipped in 65.44s ====\n")
        result = etr.compare_runs(self._SUMMARY_PLAN.test_command, baseline, patched)
        out = etr.render_existing_test_comparison(result)
        assert "worse aggregate results" in out.lower()
        assert "could not be identified" in out
        assert "runner-summary" in out

    def test_existing_counts_only_report_also_discloses_its_caveat(self):
        """The pre-existing report gap this change also closes: a
        COUNTS_ONLY-tier NEW_FAILURES_DETECTED result (suite-level-only
        junit parse -- no per-test IDs) must ALSO clearly state that
        exact test identities are unavailable in the rendered report, not
        just the bare status headline."""
        baseline = _run(100, level="COUNTS_ONLY")
        baseline.failed = 0
        patched = _run(98, level="COUNTS_ONLY")
        patched.failed = 2
        result = etr.compare_runs(("cmd",), baseline, patched)
        assert result.status == etr.STATUS_NEW_FAILURES_DETECTED
        out = etr.render_existing_test_comparison(result)
        assert "could not be identified" in out
        assert "structured per-test IDs were unavailable" in out


# ---------------------------------------------------------------------------
# _to_test_run_result
# ---------------------------------------------------------------------------

class TestToTestRunResult:
    def test_junit_full_parse(self):
        raw = _exec_result(result_output=_junit(passed=5, failed_ids=["t::a"]))
        result = etr._to_test_run_result(_plan(), raw)
        assert result.evidence_level == "OK"
        assert result.passed == 5
        assert result.failed_test_ids == ["t::a"]

    def test_exit_code_strategy_never_attempts_junit_parse(self):
        raw = _exec_result(result_output=None, exit_code=0)
        result = etr._to_test_run_result(_EXIT_CODE_PLAN, raw)
        assert result.evidence_level == "EXIT_CODE_ONLY"
        assert result.exit_code == 0

    def test_setup_failed(self):
        raw = _exec_result(setup_failed=True, setup_error="pip install failed")
        result = etr._to_test_run_result(_plan(), raw)
        assert result.status == "SETUP_FAILED"
        assert result.evidence_level == "UNAVAILABLE"

    def test_timed_out(self):
        raw = _exec_result(timed_out=True)
        result = etr._to_test_run_result(_plan(), raw)
        assert result.status == "TIMED_OUT"

    def test_no_exit_code_and_no_junit_is_unparseable(self):
        raw = TestExecutionResult(
            ran=True, exit_code=None, timed_out=False, setup_failed=False, setup_error="",
            stdout="", stderr="", result_output=None, duration_seconds=1.0, executor="docker",
        )
        result = etr._to_test_run_result(_EXIT_CODE_PLAN, raw)
        assert result.status == "UNPARSEABLE"
        assert result.evidence_level == "UNAVAILABLE"


class TestTapToTestRunResult:
    """tap reads its structured result from the test command's own
    captured stdout (never result_output_path -- see
    test_plan_validation.py) and feeds the SAME normalized
    ParsedTestCounts shape junit does into TestRunResult -- no separate
    comparison path."""

    def test_tap_full_parse_from_stdout(self):
        raw = _exec_result(stdout=_tap(passed=5, failed_ids=["a"]), exit_code=1)
        result = etr._to_test_run_result(_TAP_PLAN, raw)
        assert result.evidence_level == "OK"
        assert result.passed == 5
        assert result.failed_test_ids == ["a"]

    def test_tap_never_reads_result_output_path_field(self):
        """Confirms the source really is raw.stdout, not
        raw.result_output (which stays None for a tap plan -- see
        test_plan_validation.TestTapResultStrategy)."""
        raw = _exec_result(result_output=_junit(passed=99), stdout=_tap(passed=2), exit_code=0)
        result = etr._to_test_run_result(_TAP_PLAN, raw)
        assert result.passed == 2  # from stdout's TAP, not result_output's (irrelevant) JUnit

    def test_tap_parses_correctly_when_real_content_sits_far_past_the_excerpt_bound(self):
        """Regression guard for the general failure class this module's
        own docstring update documents: TAP structured parsing reads
        raw.stdout directly (_structured_source_text), which must be the
        FULL captured stream, never something already bounded by
        _excerpt -- that bound is applied separately, only when building
        the report-facing TestRunResult.stdout_excerpt, never to the text
        a structured-result parser reads. Pads the stream with plain
        (safely-ignored, per tap_parser's own docstring) comment lines
        well past _MAX_EXCERPT_CHARS before the real TAP content, and
        confirms full-fidelity parsing still succeeds. No assumption
        about any specific tool -- pure TAP-format padding."""
        padding = "# padding\n" * (etr._MAX_EXCERPT_CHARS // 10 + 50)
        tap_text = padding + _tap(passed=5, failed_ids=["real_failure_past_the_bound"])
        assert len(tap_text) > etr._MAX_EXCERPT_CHARS
        raw = _exec_result(stdout=tap_text, exit_code=1)
        result = etr._to_test_run_result(_TAP_PLAN, raw)
        assert result.evidence_level == "OK"
        assert result.passed == 5
        assert result.failed_test_ids == ["real_failure_past_the_bound"]

    def test_tap_with_no_exit_code_and_unparseable_stdout_is_unparseable(self):
        raw = TestExecutionResult(
            ran=True, exit_code=None, timed_out=False, setup_failed=False, setup_error="",
            stdout="not TAP at all\n", stderr="", result_output=None, duration_seconds=1.0, executor="docker",
        )
        result = etr._to_test_run_result(_TAP_PLAN, raw)
        assert result.status == "UNPARSEABLE"
        assert result.evidence_level == "UNAVAILABLE"

    def test_tap_and_junit_use_the_same_comparator_no_separate_tap_path(self):
        """Structural guard: existing_test_regression.py must not define
        a second, TAP-specific comparison function -- compare_runs is the
        only comparator, reused as-is."""
        import inspect
        source = inspect.getsource(etr)
        assert "def compare_tap" not in source
        assert source.count("def compare_runs") == 1


class TestTapEndToEndComparison:
    """The same baseline-vs-patched diff semantics JUnit already proves
    (TestCompareRunsFullIdLevel above), sourced through TAP-shaped stdout
    end to end via _to_test_run_result -- proving the SAME generic
    compare_runs handles both formats identically."""

    def _tap_run(self, stdout, exit_code=0):
        raw = _exec_result(stdout=stdout, exit_code=exit_code)
        return etr._to_test_run_result(_TAP_PLAN, raw)

    def test_same_failure_both_sides_is_pre_existing_only(self):
        baseline = self._tap_run(_tap(passed=2, failed_ids=["flaky"]), exit_code=1)
        patched = self._tap_run(_tap(passed=2, failed_ids=["flaky"]), exit_code=1)
        r = etr.compare_runs(_TAP_PLAN.test_command, baseline, patched)
        assert r.status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY
        assert r.newly_failing_tests == []
        assert r.pre_existing_failures == ["flaky"]

    def test_failure_only_in_patched_is_new_failure(self):
        baseline = self._tap_run(_tap(passed=3), exit_code=0)
        patched = self._tap_run(_tap(passed=2, failed_ids=["new_break"]), exit_code=1)
        r = etr.compare_runs(_TAP_PLAN.test_command, baseline, patched)
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == ["new_break"]

    def test_failure_only_in_baseline_is_newly_passing(self):
        baseline = self._tap_run(_tap(passed=2, failed_ids=["old_break"]), exit_code=1)
        patched = self._tap_run(_tap(passed=3), exit_code=0)
        r = etr.compare_runs(_TAP_PLAN.test_command, baseline, patched)
        assert r.status == etr.STATUS_PASS
        assert r.newly_passing_tests == ["old_break"]

    def test_both_exit_nonzero_but_tap_distinguishes_pre_existing_from_new(self):
        """The exact minimist-shaped product scenario this feature
        targets: both sides exit non-zero, but structured per-test TAP
        evidence still lets the comparator tell a pre-existing failure
        apart from a new one, rather than collapsing to NOT_VERIFIED the
        way bare exit_code would (see TestCompareRunsExitCodeOnly)."""
        baseline = self._tap_run(_tap(passed=5, failed_ids=["old"]), exit_code=1)
        patched = self._tap_run(_tap(passed=4, failed_ids=["old", "new"]), exit_code=1)
        r = etr.compare_runs(_TAP_PLAN.test_command, baseline, patched)
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == ["new"]
        assert r.pre_existing_failures == ["old"]


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

class TestEvaluateExistingTestComparison:
    def test_no_plan_discovered_is_not_verified(self, tmp_path: Path):
        with mock.patch.object(etr, "discover_test_plan", return_value=None) as m_discover, \
             mock.patch.object(etr, "select_executor", return_value=_ready_executor()):
            r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "no reliable test execution plan" in r.reason
        m_discover.assert_called_once()

    def test_unsupported_runtime_is_not_verified(self, tmp_path: Path):
        ready = _ready_executor()
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan(runtime_family="rust")), \
             mock.patch.object(etr, "select_executor", return_value=ready):
            r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "runtime not supported" in r.reason
        # Preflight (readiness) is checked once, but no actual test
        # execution happens for a runtime we don't support.
        ready.run.assert_not_called()

    def test_docker_unavailable_is_not_verified_and_never_falls_back(self, tmp_path: Path):
        unready = _unready_executor(
            reason="the Docker daemon is not reachable (...). Start Docker and rerun with --compare-existing-tests.",
        )
        with mock.patch.object(etr, "discover_test_plan") as m_discover, \
             mock.patch.object(etr, "select_executor", return_value=unready):
            r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "Docker daemon is not reachable" in r.reason
        assert "did not start" in r.reason
        m_discover.assert_not_called()
        unready.run.assert_not_called()

    def test_baseline_timeout_skips_patched_side(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.return_value = _exec_result(timed_out=True)
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            r = etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert executor.run.call_count == 1  # patched side never attempted
        assert r.baseline.status == "TIMED_OUT"
        assert r.patched is None

    def test_patched_timeout_is_test_execution_error_not_new_failures(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(result_output=_junit(passed=10)),
            _exec_result(timed_out=True),
        ]
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            r = etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_TEST_EXECUTION_ERROR
        assert r.status != etr.STATUS_NEW_FAILURES_DETECTED
        assert "timed out" in r.reason

    def test_baseline_setup_failure_is_not_verified(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.return_value = _exec_result(setup_failed=True, setup_error="no matching distribution")
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            r = etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "environment could not be established" in r.reason

    def test_patched_setup_failure_after_good_baseline_is_test_execution_error(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(result_output=_junit(passed=10)),
            _exec_result(setup_failed=True, setup_error="patched build broke"),
        ]
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            r = etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_TEST_EXECUTION_ERROR

    def test_patch_apply_failure_is_test_execution_error(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        bad_patch = "--- a/does_not_exist.py\n+++ b/does_not_exist.py\n@@ -1,1 +1,1 @@\n-x\n+y\n"
        executor = _ready_executor()
        executor.run.return_value = _exec_result(result_output=_junit(passed=10))
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            r = etr.evaluate_existing_test_comparison(repo, bad_patch, _DUMMY_LLM)
        assert r.status == etr.STATUS_TEST_EXECUTION_ERROR
        assert r.patched is None
        assert executor.run.call_count == 1  # only baseline ever executed

    def test_end_to_end_new_failures_detected(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(result_output=_junit(passed=10)),
            _exec_result(result_output=_junit(passed=9, failed_ids=["tests.test_mod::test_new"])),
        ]
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            r = etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == ["tests.test_mod::test_new"]

    def test_original_repository_untouched(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        original_content = (repo / "app.py").read_text(encoding="utf-8")
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(result_output=_junit(passed=5)),
            _exec_result(result_output=_junit(passed=5)),
        ]
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)
        assert (repo / "app.py").read_text(encoding="utf-8") == original_content
        assert not (repo / "Dockerfile").exists()

    def test_workspaces_cleaned_up(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        seen_paths = []

        def _capture(plan, workspace_root, **kw):
            seen_paths.append(Path(workspace_root))
            assert Path(workspace_root).exists()
            return _exec_result(result_output=_junit(passed=5))

        executor = _ready_executor()
        executor.run.side_effect = _capture
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)

        assert len(seen_paths) == 2
        assert seen_paths[0] != seen_paths[1]
        for p in seen_paths:
            assert not p.exists()

    def test_unexpected_exception_degrades_to_test_execution_error(self, tmp_path: Path):
        with mock.patch.object(etr, "discover_test_plan", side_effect=RuntimeError("boom")), \
             mock.patch.object(etr, "select_executor", return_value=_ready_executor()):
            r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_TEST_EXECUTION_ERROR
        assert "boom" in r.reason


class TestSamePlanInvariant:
    """Discovery happens exactly once; the identical plan object is used
    for both the baseline and patched runs."""

    def test_discovery_called_exactly_once(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.return_value = _exec_result(result_output=_junit(passed=5))
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()) as m_discover, \
             mock.patch.object(etr, "select_executor", return_value=executor):
            etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)
        assert m_discover.call_count == 1

    def test_same_plan_object_passed_to_both_executor_calls(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        seen_plans = []

        def _capture(plan, workspace_root, **kw):
            seen_plans.append(plan)
            return _exec_result(result_output=_junit(passed=5))

        fixed_plan = _plan()
        executor = _ready_executor()
        executor.run.side_effect = _capture
        with mock.patch.object(etr, "discover_test_plan", return_value=fixed_plan), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)

        assert len(seen_plans) == 2
        assert seen_plans[0] is fixed_plan
        assert seen_plans[1] is fixed_plan

    def test_discovery_runs_before_patch_is_applied(self, tmp_path: Path):
        """discover_test_plan must be called against the ORIGINAL repo,
        before either workspace (baseline or patched) is created."""
        repo = _make_git_repo(tmp_path)
        call_order = []

        def _discover(root, llm):
            call_order.append("discover")
            return _plan()

        def _run(plan, workspace_root, **kw):
            call_order.append("execute")
            return _exec_result(result_output=_junit(passed=5))

        executor = _ready_executor()
        executor.run.side_effect = _run
        with mock.patch.object(etr, "discover_test_plan", side_effect=_discover), \
             mock.patch.object(etr, "select_executor", return_value=executor):
            etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)

        assert call_order == ["discover", "execute", "execute"]


class TestWritableWorkspaceEndToEnd:
    """Regression coverage for the real urllib3 2.0.5 / CVE-2023-43804
    failure: baseline and patched both failed before any test ran because
    `/repo` was read-only inside the container and the repository's own
    test runner (there, `nox -s test`) tried to create a working file
    under the repo root.

    Exercises the REAL DockerTestExecutor (not a MagicMock stand-in)
    through the full evaluate_existing_test_comparison_with_plan
    orchestration -- temporary_repo_copy, apply_patch, executor.run,
    _to_test_run_result, compare_runs -- with only the lowest-level
    `run_docker_command` subprocess call stubbed, exactly like
    test_test_executors.py's own convention; no real Docker daemon is
    ever invoked here.

    The stub simulates the exact EROFS failure a read-only `/repo` would
    produce, so this test is tied to actual behavior, not just flag
    absence: it would fail the same way the real run did if `--read-only`
    (or an equivalent restriction) were ever reintroduced. The
    test_command is a generic shell write, never nox/pytest-specific.

    Isolation properties this does NOT re-test (already covered above by
    TestEvaluateExistingTestComparison / TestSamePlanInvariant): no host
    bind mounts, original repository left untouched, baseline/patched
    workspace independence, workspace cleanup.
    """

    _WRITE_PLAN = _plan(
        setup_commands=(), test_command=("sh", "-c", "echo state > repo_local_marker && exit 0"),
        result_strategy="exit_code", result_output_path=None,
    )

    @staticmethod
    def _readonly_aware_stub(cmd, timeout, cwd=None):
        if cmd[:2] == ["docker", "build"]:
            return ("built", "", 0, False)
        assert cmd[:2] == ["docker", "run"]
        if "--read-only" in cmd:
            return ("", "OSError: [Errno 30] Read-only file system: '/repo/repo_local_marker'", 1, False)
        return ("", "", 0, False)

    def test_baseline_and_patched_both_succeed_when_test_command_writes_into_repo(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        real_executor = etr.select_executor("docker")  # the real DockerTestExecutor, never mocked
        with mock.patch.object(test_executors_mod, "run_docker_command", side_effect=self._readonly_aware_stub):
            r = etr.evaluate_existing_test_comparison_with_plan(
                repo, _SOME_PATCH, self._WRITE_PLAN, executor=real_executor,
            )
        assert r.status == etr.STATUS_PASS
        assert r.baseline is not None and r.baseline.status == "COMPLETED"
        assert r.patched is not None and r.patched.status == "COMPLETED"


class TestEnvironmentPreflight:
    """Covers the new environment-preflight step, run BEFORE evidence
    acquisition/discover_test_plan/any workspace or Docker work."""

    def test_flag_equivalent_no_patch_is_not_started(self, tmp_path: Path):
        with mock.patch.object(etr, "discover_test_plan") as m_discover:
            r = etr.evaluate_existing_test_comparison(tmp_path, "", _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "did not start" in r.reason
        m_discover.assert_not_called()

    def test_nonexistent_repo_root_is_not_started(self, tmp_path: Path):
        missing = tmp_path / "does-not-exist"
        with mock.patch.object(etr, "discover_test_plan") as m_discover:
            r = etr.evaluate_existing_test_comparison(missing, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "does not exist" in r.reason
        m_discover.assert_not_called()

    def test_docker_cli_missing_is_not_verified_with_precise_reason_and_zero_llm_calls(self, tmp_path: Path):
        unready = _unready_executor(
            reason="docker is not installed (the `docker` command was not found on PATH). "
                   "Install Docker and rerun with --compare-existing-tests.",
            status="CLI_MISSING",
        )
        with mock.patch.object(etr, "discover_test_plan") as m_discover, \
             mock.patch.object(etr, "select_executor", return_value=unready), \
             mock.patch.object(etr, "temporary_repo_copy") as m_workspace:
            r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "docker is not installed" in r.reason
        # Zero evidence acquisition (folded into discover_test_plan, which
        # is never called), zero disposable workspace creation, zero
        # Docker build/run (executor.run is never called either).
        assert "did not start" in r.reason
        m_discover.assert_not_called()
        m_workspace.assert_not_called()
        unready.run.assert_not_called()

    def test_docker_daemon_unavailable_is_not_verified_with_daemon_specific_reason(self, tmp_path: Path):
        unready = _unready_executor(
            reason="the Docker daemon is not reachable (Cannot connect to the Docker daemon). "
                   "Start Docker and rerun with --compare-existing-tests.",
            status="DAEMON_UNREACHABLE",
        )
        with mock.patch.object(etr, "discover_test_plan") as m_discover, \
             mock.patch.object(etr, "select_executor", return_value=unready):
            r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "Docker daemon is not reachable" in r.reason
        m_discover.assert_not_called()

    def test_docker_preflight_timeout_is_not_verified_with_bounded_reason(self, tmp_path: Path):
        unready = _unready_executor(
            reason="the Docker readiness check (`docker info`) timed out after 5s. "
                   "Check that Docker is responsive and rerun with --compare-existing-tests.",
            status="TIMEOUT",
        )
        with mock.patch.object(etr, "discover_test_plan") as m_discover, \
             mock.patch.object(etr, "select_executor", return_value=unready):
            r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "timed out" in r.reason
        assert len(r.reason) < 500  # bounded, not a raw stack trace
        m_discover.assert_not_called()

    def test_docker_preflight_unexpected_error_is_not_verified(self, tmp_path: Path):
        unready = _unready_executor(
            reason="the Docker readiness check failed unexpectedly (OSError: boom).",
            status="ERROR",
        )
        with mock.patch.object(etr, "discover_test_plan") as m_discover, \
             mock.patch.object(etr, "select_executor", return_value=unready):
            r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "failed unexpectedly" in r.reason
        m_discover.assert_not_called()

    def test_preflight_success_proceeds_to_discovery_exactly_once(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.return_value = _exec_result(result_output=_junit(passed=5))
        with mock.patch.object(etr, "discover_test_plan", return_value=_plan()) as m_discover, \
             mock.patch.object(etr, "select_executor", return_value=executor):
            r = etr.evaluate_existing_test_comparison(repo, _SOME_PATCH, _DUMMY_LLM)
        m_discover.assert_called_once()
        executor.preflight.assert_called_once()
        assert r.status in (etr.STATUS_PASS, etr.STATUS_PRE_EXISTING_FAILURES_ONLY)

    def test_preflight_uses_the_real_canonical_docker_check_end_to_end(self, tmp_path: Path):
        """No mocking of select_executor/preflight at all -- exercises the
        REAL DockerTestExecutor.preflight() -> docker_isolation.
        docker_preflight() chain, proving the wiring (not just the mocked
        contract) works, and that discover_test_plan is never reached
        when the real environment's Docker isn't ready."""
        from utilities.docker_isolation import DockerPreflightResult

        with mock.patch("utilities.docker_isolation.docker_preflight") as m_preflight, \
             mock.patch.object(etr, "discover_test_plan") as m_discover:
            m_preflight.return_value = DockerPreflightResult(
                ready=False, status="DAEMON_UNREACHABLE", reason="the Docker daemon is not reachable (boom).",
            )
            r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "Docker daemon is not reachable" in r.reason
        m_discover.assert_not_called()

    def test_no_repository_specific_runtime_checked_on_host(self, tmp_path: Path):
        """Preflight must not require python/npm/go to be installed on
        the host -- tests run inside Docker. Confirmed structurally: the
        module never imports/calls anything that probes for a host
        language toolchain."""
        import inspect
        source = inspect.getsource(etr)
        for tool in ("shutil.which(\"python", "shutil.which(\"node", "shutil.which(\"go",
                     "shutil.which(\"npm", "which python", "which node"):
            assert tool not in source

    def test_recommendation_neutral_across_all_preflight_failure_reasons(self, tmp_path: Path):
        """Every preflight failure produces a plain NOT_VERIFIED
        ExistingTestComparisonResult -- the same shape/status vocabulary
        already proven neutral to Recommendation Policy elsewhere (see
        test_trust_package.py's decision-unaffected test); nothing about
        a preflight failure introduces a new status value or field."""
        for status, reason in [
            ("CLI_MISSING", "docker is not installed."),
            ("DAEMON_UNREACHABLE", "the Docker daemon is not reachable."),
            ("DAEMON_UNUSABLE", "the Docker daemon is reachable but reported errors."),
            ("TIMEOUT", "the Docker readiness check timed out."),
            ("ERROR", "the Docker readiness check failed unexpectedly."),
        ]:
            unready = _unready_executor(reason=reason, status=status)
            with mock.patch.object(etr, "select_executor", return_value=unready):
                r = etr.evaluate_existing_test_comparison(tmp_path, _SOME_PATCH, _DUMMY_LLM)
            assert r.status == etr.STATUS_NOT_VERIFIED
            assert set(vars(r).keys()) == {
                "status", "command", "baseline", "patched", "newly_failing_tests",
                "pre_existing_failures", "newly_passing_tests", "reason", "plan",
            }


# ---------------------------------------------------------------------------
# Bounding
# ---------------------------------------------------------------------------

class TestExcerptBounding:
    """_excerpt() is the ONE place captured stdout/stderr gets bounded
    (test_executors.py itself no longer truncates -- see its own
    docstring) -- generic head+tail shaping, no assumption about ANY
    tool's output format."""

    def test_short_text_untouched(self):
        assert etr._excerpt("hello") == "hello"

    def test_text_at_exact_limit_untouched(self):
        text = "x" * etr._MAX_EXCERPT_CHARS
        assert etr._excerpt(text) == text

    def test_long_text_keeps_head_and_tail_and_omits_middle(self):
        head_marker, tail_marker, middle_marker = "HEAD_START", "TAIL_END", "MIDDLE_SHOULD_BE_OMITTED"
        text = (
            head_marker + ("a" * etr._MAX_EXCERPT_CHARS)
            + middle_marker
            + ("b" * etr._MAX_EXCERPT_CHARS) + tail_marker
        )
        out = etr._excerpt(text)
        assert out.startswith(head_marker)
        assert out.endswith(tail_marker)
        assert middle_marker not in out
        assert "omitted" in out
        # Bounded: total size stays close to the fixed budget (plus small,
        # fixed marker overhead) regardless of how large the input was.
        assert len(out) <= etr._MAX_EXCERPT_CHARS + 100


# ---------------------------------------------------------------------------
# Trust signal shape
# ---------------------------------------------------------------------------

class TestClassifySignal:
    def test_none_result_is_not_verified(self):
        sig = etr.classify_existing_test_comparison_signal(None)
        assert sig["value"] == etr.STATUS_NOT_VERIFIED
        assert "not requested" in sig["notes"]

    def test_every_status_produces_a_valid_signal_shape(self):
        for status in (
            etr.STATUS_PASS, etr.STATUS_NEW_FAILURES_DETECTED,
            etr.STATUS_PRE_EXISTING_FAILURES_ONLY, etr.STATUS_NOT_VERIFIED,
            etr.STATUS_TEST_EXECUTION_ERROR,
        ):
            result = etr.ExistingTestComparisonResult(
                status=status, command=("cmd",), baseline=None, patched=None, reason="r",
            )
            sig = etr.classify_existing_test_comparison_signal(result)
            assert set(sig.keys()) == {"value", "label", "notes"}
            assert sig["value"] == status
            assert sig["notes"] == "r"


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

class TestRenderExistingTestComparison:
    def test_not_requested(self):
        out = etr.render_existing_test_comparison(None)
        assert "## Existing Test Comparison" in out
        assert "Not requested" in out

    def test_pass(self):
        b = _run(428, failed_ids=["t::a", "t::b"])
        p = _run(428, failed_ids=["t::a", "t::b"])
        r = etr.compare_runs(("cmd",), b, p)
        out = etr.render_existing_test_comparison(r)
        assert "No new failures" in out
        assert "428 passed, 2 failed" in out

    def test_new_failures_lists_newly_failing_bounded(self):
        b = _run(430)
        many_new = [f"t::test_{i}" for i in range(30)]
        p = _run(400, failed_ids=many_new)
        r = etr.compare_runs(("cmd",), b, p)
        out = etr.render_existing_test_comparison(r)
        assert "new failures after the candidate patch" in out
        assert "existing tests that passed on the baseline" in out
        assert out.count("t::test_") <= 20
        assert "more" in out

    def test_not_verified_renders_reason(self):
        r = etr.not_verified_result("Docker is not available")
        out = etr.render_existing_test_comparison(r)
        assert "Not verified" in out
        assert "Docker is not available" in out

    def test_test_execution_error_renders_reason(self):
        r = etr.ExistingTestComparisonResult(
            status=etr.STATUS_TEST_EXECUTION_ERROR, command=("cmd",), baseline=None, patched=None,
            reason="patch did not apply",
        )
        out = etr.render_existing_test_comparison(r)
        assert "Execution error" in out
        assert "patch did not apply" in out

    def test_never_dumps_raw_stdout(self):
        b = _run(1)
        b.stdout_excerpt = "SECRET_RAW_TEST_LOG_LINE"
        p = _run(1)
        r = etr.compare_runs(("cmd",), b, p)
        out = etr.render_existing_test_comparison(r)
        assert "SECRET_RAW_TEST_LOG_LINE" not in out

    def test_exit_code_only_summary_line(self):
        r = etr.compare_runs(("make", "test"), _exit_only(0), _exit_only(0))
        out = etr.render_existing_test_comparison(r)
        assert "exit code" in out.lower()

    def test_provenance_line_present_when_plan_available(self):
        r = etr.compare_runs(("cmd",), _run(5), _run(5))
        r.plan = _plan()
        out = etr.render_existing_test_comparison(r)
        assert "Test plan: discovered from repository evidence" in out
        assert "Execution: Docker" in out


class TestFactualWordingNotRegression:
    """Semantic-cleanup regression guard (in the ordinary
    software-testing sense of that phrase, not this feature's own
    verdict): the report must speak only in terms of factual "new
    failure" deltas, never claim/imply "regression", and must explain
    what a new failure means without judging it."""

    def test_new_failures_wording_says_new_failure_not_regression(self):
        b = _run(430)
        p = _run(400, failed_ids=["t::test_new"])
        r = etr.compare_runs(("cmd",), b, p)
        out = etr.render_existing_test_comparison(r)
        assert "new failure" in out.lower()
        assert "regression" not in out.lower()

    def test_singular_new_failure_wording_is_grammatical(self):
        b = _run(430)
        p = _run(429, failed_ids=["t::test_new"])
        r = etr.compare_runs(("cmd",), b, p)
        out = etr.render_existing_test_comparison(r)
        assert "1 new failure after the candidate patch" in out
        assert "1 existing test that passed on the baseline failed after applying the candidate patch" in out

    def test_plural_new_failures_wording_is_grammatical(self):
        b = _run(430)
        p = _run(428, failed_ids=["t::a", "t::b"])
        r = etr.compare_runs(("cmd",), b, p)
        out = etr.render_existing_test_comparison(r)
        assert "2 new failures after the candidate patch" in out
        assert "2 existing tests that passed on the baseline failed after applying the candidate patch" in out

    def test_section_explains_what_a_new_failure_means_without_judging_it(self):
        """The explanatory sentence must always be present (it's part of
        the section's static intro), regardless of outcome, and must not
        say the change is "bad" or "wrong" -- only that OpenAnt does not
        determine whether it's intended."""
        out = etr.render_existing_test_comparison(None)
        assert (
            "a test that passed on the baseline failed after the patch" in out
            and "does not determine whether that behavior change is intended" in out
        )

    def test_pre_existing_failures_wording_is_explicit_and_factual(self):
        b = _run(100, failed_ids=["t::a", "t::b"])
        p = _run(100, failed_ids=["t::a", "t::b"])
        r = etr.compare_runs(("cmd",), b, p)
        out = etr.render_existing_test_comparison(r)
        assert "Pre-existing failures: 2" in out
        assert (
            "already present on the baseline" in out
            and "cannot be attributed to the candidate patch" in out
        )

    def test_no_result_status_value_contains_the_word_regression(self):
        for status in (
            etr.STATUS_PASS, etr.STATUS_NEW_FAILURES_DETECTED,
            etr.STATUS_PRE_EXISTING_FAILURES_ONLY, etr.STATUS_NOT_VERIFIED,
            etr.STATUS_TEST_EXECUTION_ERROR,
        ):
            assert "regression" not in status.lower()

    def test_trust_signal_label_says_new_failures_not_regression(self):
        result = etr.ExistingTestComparisonResult(
            status=etr.STATUS_NEW_FAILURES_DETECTED, command=("cmd",),
            baseline=None, patched=None, reason="2 test(s) newly failing after the patch.",
        )
        sig = etr.classify_existing_test_comparison_signal(result)
        assert "regression" not in sig["label"].lower()
        assert "new failure" in sig["label"].lower() or "new failures" in sig["label"].lower()
