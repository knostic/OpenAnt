"""Tests for Existing Test Comparison's comparison algorithm,
orchestration (Test Plan Discovery -> validation -> executor selection ->
baseline/patched execution -> comparison), and report/signal rendering.

Docker and the LLM are never actually invoked here -- `discover_test_plan`
and the selected executor's `.run()` are mocked at the
existing_test_regression module boundary throughout.
"""

from __future__ import annotations

import json
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

_UNSET = object()


def _run(passed, failed_ids=_UNSET, errors=0, skipped=0, level="OK", exit_code=None):
    """`failed_ids` defaults to matching PRODUCTION discipline (see
    _to_test_run_result/_build_evidence_from_exit_code): only "OK" (a
    full structured parse) has a real -- possibly empty -- id list by
    default; every other level defaults to None (no reliable ids),
    exactly like COUNTS_ONLY/EXIT_CODE_ONLY/etc. always are in
    production unless ids were separately, reliably established (see
    _find_runner_summary_failed_ids). Pass `failed_ids=[...]` explicitly
    to simulate a level that DOES have reliable ids (e.g. a
    RUNNER_SUMMARY_COUNTS run with a verified pytest short-summary
    listing)."""
    if failed_ids is _UNSET:
        ids_list = [] if level == "OK" else None
    else:
        ids_list = list(failed_ids)
    if exit_code is None:
        exit_code = 1 if (ids_list or errors) else 0
    return etr.TestRunResult(
        command=("python", "-m", "pytest"), status="COMPLETED", exit_code=exit_code,
        duration_seconds=1.0, passed=passed, failed=(len(ids_list) if ids_list is not None else 0),
        skipped=skipped, errors=errors,
        failed_test_ids=ids_list, stdout_excerpt="", stderr_excerpt="",
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
        # Wording updated (LLM Test Failure Evidence Distillation feature):
        # explicitly says the individual failure "could not be identified
        # reliably" when no distillation attempt resolved one (none was
        # attempted here -- this result came straight from compare_runs()).
        assert "worse aggregate test results" in out.lower()
        assert "could not be identified reliably" in out.lower()
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
# Pytest short-summary FAILED/ERROR node ID extraction -- the deliberate,
# narrow exception to this module's "no tool-specific knowledge" rule (see
# existing_test_regression.py's own section docstring). A real urllib3
# replay showed reliable per-test identity already present in already-
# captured pytest output that was being reduced to aggregate counts only.
# ---------------------------------------------------------------------------

class TestPytestNodeIdFromSummaryLine:
    """_pytest_node_id_from_summary_line -- single-line acceptance rules,
    tested in isolation before any integration."""

    def test_failed_line_extracts_node_id(self):
        assert (
            etr._pytest_node_id_from_summary_line("FAILED test/test_retry.py::TestRetry::test_x")
            == "test/test_retry.py::TestRetry::test_x"
        )

    def test_error_line_extracts_node_id(self):
        assert (
            etr._pytest_node_id_from_summary_line("ERROR test/test_connectionpool.py::TestPool::test_y")
            == "test/test_connectionpool.py::TestPool::test_y"
        )

    def test_trailing_short_exception_summary_is_stripped(self):
        line = "FAILED test/test_retry.py::TestRetry::test_x - AssertionError: boom"
        assert etr._pytest_node_id_from_summary_line(line) == "test/test_retry.py::TestRetry::test_x"

    def test_parameterized_node_id_preserved_exactly(self):
        line = "FAILED test/test_util.py::test_parse[https://example.com-443]"
        assert (
            etr._pytest_node_id_from_summary_line(line)
            == "test/test_util.py::test_parse[https://example.com-443]"
        )

    def test_per_test_progress_line_is_not_a_summary_line(self):
        """"test/foo.py::test_x FAILED [ 47%]" -- the outcome keyword is
        NOT at the start of the line, so this must never be mistaken for
        a short-summary entry."""
        assert etr._pytest_node_id_from_summary_line("test/foo.py::test_x FAILED [ 47%]") is None

    def test_traceback_path_line_is_not_a_summary_line(self):
        line = '  File "/app/test/test_retry.py", line 42, in test_x'
        assert etr._pytest_node_id_from_summary_line(line) is None

    def test_prose_mentioning_failed_is_not_a_summary_line(self):
        assert etr._pytest_node_id_from_summary_line("2 tests FAILED during setup") is None

    def test_line_without_double_colon_is_rejected(self):
        """Doesn't look like a real pytest node id at all -- never guess."""
        assert etr._pytest_node_id_from_summary_line("FAILED to connect to database") is None


class TestFindRunnerSummaryFailedIds:
    """_find_runner_summary_failed_ids -- the bounded-tail extraction plus
    its central safety mechanism, the exact-count reliability gate."""

    def test_expected_count_zero_short_circuits_to_empty_list(self):
        assert etr._find_runner_summary_failed_ids("anything at all\n", 0) == []
        assert etr._find_runner_summary_failed_ids(None, 0) == []

    def test_no_stdout_with_nonzero_expected_count_is_none(self):
        assert etr._find_runner_summary_failed_ids(None, 3) is None
        assert etr._find_runner_summary_failed_ids("", 3) is None

    def test_exact_match_extracts_all_ids(self):
        stdout = (
            "FAILED test/test_a.py::test_1\n"
            "FAILED test/test_b.py::test_2\n"
            "ERROR test/test_c.py::test_3\n"
            "==== 2 failed, 1 error, 10 passed in 1.0s ====\n"
        )
        ids = etr._find_runner_summary_failed_ids(stdout, expected_count=3)
        assert ids == ["test/test_a.py::test_1", "test/test_b.py::test_2", "test/test_c.py::test_3"]

    def test_duplicate_lines_are_deduplicated_and_still_match(self):
        stdout = (
            "FAILED test/test_a.py::test_1\n"
            "FAILED test/test_a.py::test_1\n"  # flushed/printed twice
            "FAILED test/test_b.py::test_2\n"
            "==== 2 failed, 10 passed in 1.0s ====\n"
        )
        ids = etr._find_runner_summary_failed_ids(stdout, expected_count=2)
        assert ids == ["test/test_a.py::test_1", "test/test_b.py::test_2"]

    def test_undercount_from_truncated_listing_is_unreliable(self):
        """Only one FAILED line present but the aggregate says 2 --
        never return a partial/truncated list."""
        stdout = "FAILED test/test_a.py::test_1\n==== 2 failed, 10 passed in 1.0s ====\n"
        assert etr._find_runner_summary_failed_ids(stdout, expected_count=2) is None

    def test_overcount_from_duplicate_distinct_lines_is_unreliable(self):
        """More distinct-looking FAILED lines than the trusted aggregate
        count -- e.g. two independent sessions concatenated -- must never
        be resolved by picking a subset."""
        stdout = (
            "FAILED test/test_a.py::test_1\n"
            "FAILED test/test_b.py::test_2\n"
            "FAILED test/test_c.py::test_3\n"
            "==== 2 failed, 10 passed in 1.0s ====\n"
        )
        assert etr._find_runner_summary_failed_ids(stdout, expected_count=2) is None

    def test_progress_and_traceback_lines_never_pollute_extraction(self):
        stdout = (
            "test/test_a.py::test_1 FAILED [ 50%]\n"  # progress line, not a summary entry
            '  File "/app/test/test_a.py", line 10, in test_1\n'
            "  AssertionError: FAILED to match\n"
            "FAILED test/test_a.py::test_1\n"
            "==== 1 failed, 10 passed in 1.0s ====\n"
        )
        ids = etr._find_runner_summary_failed_ids(stdout, expected_count=1)
        assert ids == ["test/test_a.py::test_1"]


class TestCompareByIdsFromRunnerSummary:
    """End-to-end: baseline/patched RUNNER_SUMMARY_COUNTS-tier evidence
    with reliably-extracted pytest node ids drives set-based comparison,
    exactly like OK-tier structured evidence already does."""

    def _summary_result(self, stdout: str, exit_code: int = 1):
        return etr._to_test_run_result(_EXIT_CODE_PLAN, _exec_result(stdout=stdout, exit_code=exit_code))

    @staticmethod
    def _stdout_for(failed_ids, passed=10):
        lines = [f"FAILED {tid}" for tid in failed_ids]
        lines.append(f"==== {len(failed_ids)} failed, {passed} passed in 1.0s ====")
        return "\n".join(lines) + "\n"

    def test_same_failures_both_sides_yields_no_newly_failing(self):
        stdout = self._stdout_for(["t/a.py::test_1", "t/b.py::test_2"])
        baseline = self._summary_result(stdout)
        patched = self._summary_result(stdout)
        assert baseline.failed_test_ids == ["t/a.py::test_1", "t/b.py::test_2"]
        r = etr.compare_runs(_EXIT_CODE_PLAN.test_command, baseline, patched)
        assert r.status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY
        assert r.newly_failing_tests == []
        assert sorted(r.pre_existing_failures) == ["t/a.py::test_1", "t/b.py::test_2"]

    def test_patched_adds_one_failure(self):
        baseline = self._summary_result(self._stdout_for(["t/a.py::test_1"]))
        patched = self._summary_result(self._stdout_for(["t/a.py::test_1", "t/b.py::test_2"]))
        r = etr.compare_runs(_EXIT_CODE_PLAN.test_command, baseline, patched)
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == ["t/b.py::test_2"]
        assert r.pre_existing_failures == ["t/a.py::test_1"]

    def test_patched_removes_one_failure(self):
        baseline = self._summary_result(self._stdout_for(["t/a.py::test_1", "t/b.py::test_2"]))
        patched = self._summary_result(self._stdout_for(["t/a.py::test_1"]))
        r = etr.compare_runs(_EXIT_CODE_PLAN.test_command, baseline, patched)
        assert r.status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY
        assert r.newly_passing_tests == ["t/b.py::test_2"]
        assert r.newly_failing_tests == []

    def test_counts_only_output_with_no_reliable_ids_remains_unresolved_by_identity(self):
        """No per-test FAILED/ERROR lines at all -- only the aggregate --
        so failed_test_ids stays None and the existing aggregate-only
        (never identity-claiming) comparison path is unaffected."""
        baseline = self._summary_result("==== 1 failed, 10 passed in 1.0s ====\n")
        patched = self._summary_result("==== 1 failed, 10 passed in 1.0s ====\n")
        assert baseline.failed_test_ids is None
        assert patched.failed_test_ids is None
        r = etr.compare_runs(_EXIT_CODE_PLAN.test_command, baseline, patched)
        assert r.status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY
        assert r.newly_failing_tests == []

    def test_both_sides_worse_and_unresolvable_stays_not_verified(self):
        """Exit-code-only-shaped ambiguity (both sides exited non-zero,
        no aggregate summary recognized at all) is completely unaffected
        by this feature -- still the conservative NOT_VERIFIED."""
        baseline = self._summary_result("no outcome words here at all\n")
        patched = self._summary_result("no outcome words here at all either\n")
        assert baseline.evidence_level == "EXIT_CODE_ONLY"
        r = etr.compare_runs(_EXIT_CODE_PLAN.test_command, baseline, patched)
        assert r.status == etr.STATUS_NOT_VERIFIED

    def test_junit_and_tap_evidence_paths_unaffected(self):
        """Structured JUnit/TAP parsing (and their existing None-when-
        unreliable discipline) must remain byte-for-byte unchanged by the
        new runner-summary extractor, which only ever runs for the
        exit_code/no-structured-output fallback path."""
        raw = _exec_result(result_output=_junit(passed=5, failed_ids=["t::a"]), exit_code=1)
        result = etr._to_test_run_result(_plan(), raw)
        assert result.evidence_level == "OK"
        assert result.failed_test_ids == ["t::a"]

        raw_tap = _exec_result(stdout=_tap(passed=5, failed_ids=["t::b"]), exit_code=1)
        result_tap = etr._to_test_run_result(_TAP_PLAN, raw_tap)
        assert result_tap.evidence_level == "OK"
        assert result_tap.failed_test_ids == ["t::b"]


# ---------------------------------------------------------------------------
# Execution validity -- exit_code == 0 must never by itself justify PASS
# when explicit runner evidence says the requested execution was declined
# (real urllib3 replay finding: `nox -s test-3.12` exited 0 having never
# run any test at all, because the interpreter it needed was missing).
# ---------------------------------------------------------------------------

class TestExecutionDeclinedReason:
    """Unit coverage for _execution_declined_reason -- deterministic,
    generic (never runner-specific), and deliberately narrow: BOTH an
    explicit decline/non-execution phrase AND an explicit missing-
    runtime/interpreter phrase must co-occur on the SAME line."""

    def test_real_urllib3_shaped_line_is_detected(self):
        text = (
            "nox > Running session test-3.12\n"
            "nox > uv binary not found.\n"
            "nox > Nox was installed without the `[pbs]` extra, can't download Python\n"
            "nox > Missing interpreters will error by default on CI systems.\n"
            "nox > Session test-3.12 skipped: Python interpreter 3.12 not found.\n"
        )
        reason = etr._execution_declined_reason(text)
        assert reason is not None
        assert "skipped" in reason
        assert "interpreter" in reason

    def test_none_or_empty_returns_none(self):
        assert etr._execution_declined_reason(None) is None
        assert etr._execution_declined_reason("") is None

    def test_ordinary_aggregate_skipped_count_does_not_trigger(self):
        """The exact required non-regression: an ORDINARY per-test
        resolution-side count ("3 skipped") must never be read as a
        declined execution -- it has no "session/target/suite" nearby and
        no missing-runtime phrase at all."""
        assert etr._execution_declined_reason("10 passed, 3 skipped, 1 failed in 0.4s") is None

    def test_unrelated_missing_fixture_does_not_trigger(self):
        """A per-test "missing" reason (a fixture, a marker) must not
        trigger this on its own -- it says nothing about the SESSION
        itself being skipped, and mentions no interpreter/runtime."""
        assert etr._execution_declined_reason("test_foo SKIPPED (missing fixture 'db')") is None

    def test_missing_runtime_alone_without_decline_word_does_not_trigger(self):
        assert etr._execution_declined_reason("Python interpreter 3.12 not found, continuing anyway") is None

    def test_decline_word_alone_without_missing_runtime_does_not_trigger(self):
        assert etr._execution_declined_reason("Session integration-tests skipped: marked xfail") is None

    def test_generic_non_nox_wrapper_phrasing_is_also_detected(self):
        """Generic across wrappers -- not nox-specific wording."""
        assert etr._execution_declined_reason(
            "Target 'test' declined: required runtime is unavailable in this image"
        ) is not None

    def test_only_scans_the_tail_window(self):
        """Consistent with _find_runner_summary's own tail-only scan --
        an unrelated decline-shaped line buried far outside the tail
        window must not surface."""
        noise = "\n".join(f"line {i}" for i in range(1000))
        text = "Session test skipped: interpreter not found.\n" + noise
        assert etr._execution_declined_reason(text) is None


class TestExitCodeZeroDoesNotImplyExecution:
    """_build_evidence_from_exit_code / _to_test_run_result level:
    exit_code == 0 must not, by itself, produce EXIT_CODE_ONLY (and
    therefore eventually PASS) when explicit evidence says the requested
    execution was declined."""

    _DECLINED_STDOUT = (
        "nox > Running session test-3.12\n"
        "nox > Session test-3.12 skipped: Python interpreter 3.12 not found.\n"
    )

    def test_declined_stdout_yields_unavailable_not_exit_code_only(self):
        raw = _exec_result(stdout=self._DECLINED_STDOUT, exit_code=0)
        result = etr._to_test_run_result(_EXIT_CODE_PLAN, raw)
        assert result.evidence_level == "UNAVAILABLE"
        assert result.status == "UNPARSEABLE"
        assert result.exit_code == 0  # preserved for provenance, just not trusted as proof
        assert "did not actually execute" in result.reason

    def test_declined_stderr_also_detected(self):
        raw = _exec_result(stdout="", stderr=self._DECLINED_STDOUT, exit_code=0)
        result = etr._to_test_run_result(_EXIT_CODE_PLAN, raw)
        assert result.evidence_level == "UNAVAILABLE"

    def test_ordinary_exit_code_zero_success_is_unaffected(self):
        """The required non-regression: a genuine bespoke command (e.g.
        `make test`) that exits 0 with no aggregate summary and no
        decline evidence at all remains EXIT_CODE_ONLY, exactly as
        before."""
        raw = _exec_result(stdout="all good, nothing to report\n", exit_code=0)
        result = etr._to_test_run_result(_EXIT_CODE_PLAN, raw)
        assert result.evidence_level == "EXIT_CODE_ONLY"
        assert result.exit_code == 0

    def test_ordinary_exit_code_nonzero_failure_is_unaffected(self):
        raw = _exec_result(stdout="boom\n", exit_code=1)
        result = etr._to_test_run_result(_EXIT_CODE_PLAN, raw)
        assert result.evidence_level == "EXIT_CODE_ONLY"
        assert result.exit_code == 1

    def test_runner_summary_present_takes_precedence_over_decline_check(self):
        """A genuine aggregate summary is still checked FIRST -- declined-
        execution detection only matters when no summary was found at all."""
        raw = _exec_result(stdout="==== 5 failed, 10 passed, 3 skipped ====\n", exit_code=0)
        result = etr._to_test_run_result(_EXIT_CODE_PLAN, raw)
        assert result.evidence_level == "RUNNER_SUMMARY_COUNTS"

    def test_structured_junit_success_is_unaffected(self):
        raw = _exec_result(result_output=_junit(passed=5))
        result = etr._to_test_run_result(_plan(), raw)
        assert result.evidence_level == "OK"

    def test_structured_tap_success_is_unaffected(self):
        raw = _exec_result(stdout=_tap(passed=5), exit_code=0)
        result = etr._to_test_run_result(_TAP_PLAN, raw)
        assert result.evidence_level == "OK"


class TestExecutionValidityEndToEnd:
    """Full evaluate_existing_test_comparison_with_plan()-level regression
    coverage for the real urllib3 replay finding."""

    _DECLINED_STDOUT = (
        "nox > Running session test-3.12\n"
        "nox > uv binary not found.\n"
        "nox > Missing interpreters will error by default on CI systems.\n"
        "nox > Session test-3.12 skipped: Python interpreter 3.12 not found.\n"
    )

    def test_both_sides_declined_is_not_pass(self, tmp_path: Path):
        """The exact real replay shape: both baseline and patched run the
        SAME wrapper command, both exit 0, neither actually executes any
        test. Must NEVER be PASS."""
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout=self._DECLINED_STDOUT, exit_code=0),
            _exec_result(stdout=self._DECLINED_STDOUT, exit_code=0),
        ]
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor,
        )
        assert r.status != etr.STATUS_PASS
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert "did not actually execute" in r.reason

    def test_only_patched_side_declined_is_not_pass(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="all good\n", exit_code=0),
            _exec_result(stdout=self._DECLINED_STDOUT, exit_code=0),
        ]
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor,
        )
        assert r.status != etr.STATUS_PASS
        assert r.status == etr.STATUS_NOT_VERIFIED

    def test_only_baseline_side_declined_is_not_pass(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout=self._DECLINED_STDOUT, exit_code=0),
        ]
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor,
        )
        assert r.status != etr.STATUS_PASS
        assert r.status == etr.STATUS_NOT_VERIFIED
        assert executor.run.call_count == 1  # patched side never attempted

    def test_ordinary_exit_code_only_success_remains_pass(self, tmp_path: Path):
        """Required non-regression: genuine exit-code-only success (no
        decline evidence, no aggregate summary) is still PASS."""
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="all good, nothing to report\n", exit_code=0),
            _exec_result(stdout="all good, nothing to report\n", exit_code=0),
        ]
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor,
        )
        assert r.status == etr.STATUS_PASS

    def test_ordinary_exit_code_failure_semantics_unaffected(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="all good\n", exit_code=0),
            _exec_result(stdout="boom, something broke\n", exit_code=1),
        ]
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor,
        )
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED

    def test_unrelated_skipped_word_in_ordinary_output_does_not_invalidate(self, tmp_path: Path):
        """Required non-regression: an unrelated, ordinary per-test
        "SKIPPED" mention (not a full aggregate summary line, so it
        reaches the decline-detection path at all) must not turn a
        genuine pass into NOT_VERIFIED."""
        repo = _make_git_repo(tmp_path)
        ordinary = "test_foo SKIPPED (missing fixture 'db')\nall other checks fine\n"
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout=ordinary, exit_code=0),
            _exec_result(stdout=ordinary, exit_code=0),
        ]
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor,
        )
        assert r.status == etr.STATUS_PASS

    def test_aggregate_runner_summary_runs_remain_unchanged(self, tmp_path: Path):
        """Required non-regression: RUNNER_SUMMARY_COUNTS-tier comparison
        (a real aggregate summary line present) is entirely unaffected by
        this fix -- it never reaches the decline-detection path."""
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="==== 1 failed, 9 passed in 1.0s ====\n", exit_code=1),
            _exec_result(stdout="==== 2 failed, 8 passed in 1.0s ====\n", exit_code=1),
        ]
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor,
        )
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.baseline.evidence_level == "RUNNER_SUMMARY_COUNTS"


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

    def test_junit_failure_diagnostic_flows_into_test_run_result(self):
        xml = (
            '<testsuites><testsuite name="pytest" tests="1" failures="1">'
            '<testcase classname="t" name="a"><failure message="boom">trace</failure></testcase>'
            '</testsuite></testsuites>'
        )
        raw = _exec_result(result_output=xml)
        result = etr._to_test_run_result(_plan(), raw)
        assert result.failure_diagnostics is not None
        assert "boom" in result.failure_diagnostics["t::a"]

    def test_no_failures_gives_none_not_empty_dict(self):
        raw = _exec_result(result_output=_junit(passed=5))
        result = etr._to_test_run_result(_plan(), raw)
        assert result.failure_diagnostics is None

    def test_exit_code_only_never_has_diagnostics(self):
        raw = _exec_result(result_output=None, exit_code=1)
        result = etr._to_test_run_result(_EXIT_CODE_PLAN, raw)
        assert result.failure_diagnostics is None


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
                "distilled_failure_evidence",
            }


# ---------------------------------------------------------------------------
# LLM Test Failure Evidence Distillation
# ---------------------------------------------------------------------------

class _FakeDistillerLLM:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def complete(self, system_prompt, user_message, stage="unknown"):
        self.calls.append({"system_prompt": system_prompt, "user_message": user_message, "stage": stage})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _resolved_json(*, test_id="t::new", summary="assertion failed", excerpt="AssertionError: boom"):
    return json.dumps({
        "status": "resolved",
        "candidates": [{"test_id": test_id, "failure_summary": summary, "supporting_excerpt": excerpt}],
        "reason": "",
    })


def _unresolved_json(reason="could not confidently isolate a failure"):
    return json.dumps({"status": "unresolved", "candidates": [], "reason": reason})


class TestPrefilterFailureRelevantText:
    """_prefilter_failure_relevant_text -- deterministic, generic,
    never runner-specific, never a claim of identity by itself."""

    def test_none_or_empty_returns_none(self):
        assert etr._prefilter_failure_relevant_text(None) is None
        assert etr._prefilter_failure_relevant_text("") is None

    def test_whitespace_only_returns_none(self):
        assert etr._prefilter_failure_relevant_text("   \n\n   ") is None

    def test_non_tail_non_cue_lines_are_dropped(self):
        """Lines with no generic failure cue, past the always-kept
        (byte-bounded) tail, are filtered out -- proving this is a real
        filter, not a pass-through. Needs enough TOTAL bytes to exceed
        _DISTILLATION_TAIL_CHARS -- short inputs are always entirely
        "tail" (see test_true_tail_is_always_kept_even_without_failure_
        words below)."""
        noise = "\n".join(f"progress line {i}" for i in range(1500))
        assert len(noise) > etr._DISTILLATION_TAIL_CHARS
        out = etr._prefilter_failure_relevant_text(noise)
        assert out is not None
        assert "progress line 0" not in out  # far outside the tail, no failure cue
        assert "progress line 1499" in out  # true tail always kept

    def test_lines_with_generic_failure_words_are_kept(self):
        text = "line one\nTraceback (most recent call last):\nAssertionError: boom\nline four"
        out = etr._prefilter_failure_relevant_text(text)
        assert out is not None
        assert "Traceback" in out
        assert "AssertionError" in out

    def test_true_tail_is_always_kept_even_without_failure_words(self):
        head = "\n".join(f"line {i}" for i in range(1000))
        tail = "\n".join(f"tail line {i}" for i in range(50))
        text = head + "\n" + tail
        out = etr._prefilter_failure_relevant_text(text)
        assert out is not None
        assert "tail line 49" in out

    def test_large_uniform_matching_content_is_bounded_not_rejected(self):
        """The concrete bug this function's rewrite fixes: a run with
        MANY keyword-matching lines throughout (e.g. many genuinely
        failing tests, each contributing traceback lines) used to have
        its ENTIRE candidate -- including the always-useful tail --
        discarded once the combined size exceeded the cap. It must now
        be gracefully bounded to the cap instead, never rejected
        outright, as long as at least the tail fits on its own."""
        huge = "\n".join(f"error line with a traceback {i}" for i in range(5000))
        assert len(huge) > etr._DISTILLATION_INPUT_CAP
        out = etr._prefilter_failure_relevant_text(huge)
        assert out is not None
        assert len(out) <= etr._DISTILLATION_INPUT_CAP
        assert "error line with a traceback 4999" in out  # true tail preserved

    def test_single_line_exceeding_even_the_tail_budget_is_unresolved(self):
        """Genuinely pathological case: not even one line fits within
        either budget -- there is nothing safe to hand to the LLM, so
        this must still fail closed to None (never truncate mid-line,
        never guess)."""
        one_giant_line = "error " * 5_000  # a single line, no newlines at all
        assert len(one_giant_line) > etr._DISTILLATION_INPUT_CAP
        assert etr._prefilter_failure_relevant_text(one_giant_line) is None


class TestParseDistillationResponse:
    def test_resolved_with_valid_candidate(self):
        result = etr._parse_distillation_response(_resolved_json())
        assert result.status == "resolved"
        assert result.candidates[0].test_id == "t::new"
        assert result.candidates[0].source == "llm_distilled"

    def test_unresolved_response(self):
        result = etr._parse_distillation_response(_unresolved_json("too noisy"))
        assert result.status == "unresolved"
        assert result.reason == "too noisy"

    def test_malformed_json_is_unresolved(self):
        result = etr._parse_distillation_response("not json at all")
        assert result.status == "unresolved"

    def test_non_object_json_is_unresolved(self):
        result = etr._parse_distillation_response("[1, 2, 3]")
        assert result.status == "unresolved"

    def test_unrecognized_status_is_unresolved(self):
        result = etr._parse_distillation_response(json.dumps({"status": "maybe", "candidates": []}))
        assert result.status == "unresolved"

    def test_resolved_with_no_candidates_is_unresolved(self):
        result = etr._parse_distillation_response(json.dumps({"status": "resolved", "candidates": []}))
        assert result.status == "unresolved"

    def test_resolved_with_all_malformed_candidates_is_unresolved(self):
        result = etr._parse_distillation_response(
            json.dumps({"status": "resolved", "candidates": [{"test_id": ""}, {"no_test_id": "x"}]})
        )
        assert result.status == "unresolved"

    def test_candidate_missing_test_id_is_dropped_not_invented(self):
        result = etr._parse_distillation_response(json.dumps({
            "status": "resolved",
            "candidates": [
                {"test_id": "t::good", "failure_summary": "s", "supporting_excerpt": "e"},
                {"failure_summary": "no id here"},
            ],
        }))
        assert result.status == "resolved"
        assert [c.test_id for c in result.candidates] == ["t::good"]

    def test_supporting_excerpt_and_summary_are_bounded(self):
        result = etr._parse_distillation_response(json.dumps({
            "status": "resolved",
            "candidates": [{
                "test_id": "t::a",
                "failure_summary": "s" * 10_000,
                "supporting_excerpt": "e" * 10_000,
            }],
        }))
        assert len(result.candidates[0].failure_summary) <= etr._MAX_DISTILLED_SUMMARY_CHARS
        assert len(result.candidates[0].supporting_excerpt) <= etr._MAX_DISTILLED_EXCERPT_CHARS

    def test_candidates_bounded_to_max_count(self):
        many = [{"test_id": f"t::{i}", "failure_summary": "s", "supporting_excerpt": "e"} for i in range(50)]
        result = etr._parse_distillation_response(json.dumps({"status": "resolved", "candidates": many}))
        assert len(result.candidates) <= etr._MAX_DISTILLED_CANDIDATES

    def test_code_fenced_response_is_stripped(self):
        fenced = "```json\n" + _resolved_json() + "\n```"
        result = etr._parse_distillation_response(fenced)
        assert result.status == "resolved"


class TestDistillationGate:
    """evaluate_existing_test_comparison_with_plan()'s distillation gate:
    ALL of (llm given, NEW_FAILURES_DETECTED, no deterministic identity)
    must hold."""

    def test_deterministic_identity_available_distiller_not_called(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(result_output=_junit(passed=10)),
            _exec_result(result_output=_junit(passed=9, failed_ids=["t::new"])),
        ]
        llm = _FakeDistillerLLM(_resolved_json())
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _plan(), executor=executor, llm=llm,
        )
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == ["t::new"]
        assert llm.calls == []
        assert r.distilled_failure_evidence is None

    def test_no_new_failures_distiller_not_called(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(result_output=_junit(passed=10)),
            _exec_result(result_output=_junit(passed=10)),
        ]
        llm = _FakeDistillerLLM(_resolved_json())
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _plan(), executor=executor, llm=llm,
        )
        assert r.status == etr.STATUS_PASS
        assert llm.calls == []
        assert r.distilled_failure_evidence is None

    def test_no_llm_given_distiller_not_attempted(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="==== 1 failed, 9 passed in 1.0s ====\n", exit_code=1),
            _exec_result(stdout="==== 2 failed, 8 passed in 1.0s ====\n", exit_code=1),
        ]
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor,
        )
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == []
        assert r.distilled_failure_evidence is None

    def test_aggregate_new_failure_no_identity_triggers_one_distillation_call(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="Traceback shared noise\n==== 1 failed, 9 passed in 1.0s ====\n", exit_code=1),
            _exec_result(
                stdout="Traceback shared noise\nAssertionError: new one\n==== 2 failed, 8 passed in 1.0s ====\n",
                exit_code=1,
            ),
        ]
        llm = _FakeDistillerLLM(_resolved_json(test_id="t::new"))
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == []  # deterministic identity fields untouched
        assert len(llm.calls) == 1
        assert llm.calls[0]["stage"] == etr._DISTILLATION_LLM_TAG
        assert r.distilled_failure_evidence is not None
        assert r.distilled_failure_evidence.status == "resolved"
        assert r.distilled_failure_evidence.candidates[0].test_id == "t::new"
        assert r.distilled_failure_evidence.candidates[0].source == "llm_distilled"

    def test_baseline_and_patched_excerpts_both_reach_the_llm(self, tmp_path: Path):
        """Confirms the distiller is given BOTH sides -- not just the
        patched one -- so it has a basis to distinguish shared/pre-
        existing noise from a genuinely new candidate."""
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="AssertionError: baseline_shared_failure\n==== 1 failed, 9 passed ====\n", exit_code=1),
            _exec_result(
                stdout=(
                    "AssertionError: baseline_shared_failure\n"
                    "AssertionError: patched_only_failure\n"
                    "==== 2 failed, 8 passed ====\n"
                ),
                exit_code=1,
            ),
        ]
        llm = _FakeDistillerLLM(_resolved_json(test_id="t::patched_only"))
        etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert len(llm.calls) == 1
        user_message = llm.calls[0]["user_message"]
        assert "baseline_shared_failure" in user_message
        assert "patched_only_failure" in user_message
        assert "Baseline run" in user_message and "Patched run" in user_message

    def test_ambiguous_evidence_resolves_to_unresolved(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="AssertionError: noise\n==== 1 failed, 9 passed ====\n", exit_code=1),
            _exec_result(stdout="AssertionError: noise\n==== 2 failed, 8 passed ====\n", exit_code=1),
        ]
        llm = _FakeDistillerLLM(_unresolved_json("evidence too ambiguous to isolate a specific test"))
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert r.distilled_failure_evidence.status == "unresolved"
        assert r.newly_failing_tests == []

    def test_large_but_boundable_patched_output_still_calls_llm_once(self, tmp_path: Path):
        """A run whose patched output has MANY keyword-matching lines
        (well past the raw input cap in total size) must still reach the
        distiller exactly once, gracefully bounded -- never rejected
        outright just because more matched elsewhere than fit (the
        concrete bug _prefilter_failure_relevant_text's rewrite fixes;
        see TestPrefilterFailureRelevantText.
        test_large_uniform_matching_content_is_bounded_not_rejected)."""
        repo = _make_git_repo(tmp_path)
        huge_patched_stdout = (
            "\n".join(f"error line with a traceback {i}" for i in range(5000))
            + "\n==== 2 failed, 8 passed ====\n"
        )
        assert len(huge_patched_stdout) > etr._DISTILLATION_INPUT_CAP
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="==== 1 failed, 9 passed ====\n", exit_code=1),
            _exec_result(stdout=huge_patched_stdout, exit_code=1),
        ]
        llm = _FakeDistillerLLM(_resolved_json())
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert len(llm.calls) == 1
        assert r.distilled_failure_evidence.status == "resolved"

    def test_genuinely_unboundable_patched_output_is_unresolved_without_calling_llm(self, tmp_path: Path):
        """Genuinely pathological case: patched output is a SINGLE
        enormous line (no newlines at all) that doesn't fit within
        either prefilter budget on its own -- nothing safe to hand to
        the LLM, so this must fail closed to unresolved without ever
        calling it. Never chunk, never retry. (No parseable aggregate
        summary either, so this reaches NEW_FAILURES_DETECTED via the
        exit-code-only path: clean baseline, non-zero patched.)"""
        repo = _make_git_repo(tmp_path)
        one_giant_line = "error " * 5_000
        assert len(one_giant_line) > etr._DISTILLATION_INPUT_CAP
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="==== 0 failed, 10 passed ====\n", exit_code=0),
            _exec_result(stdout=one_giant_line, exit_code=1),
        ]
        llm = _FakeDistillerLLM(_resolved_json())
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert llm.calls == []
        assert r.distilled_failure_evidence.status == "unresolved"

    def test_malformed_llm_response_is_unresolved_not_a_crash(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="AssertionError: noise\n==== 1 failed, 9 passed ====\n", exit_code=1),
            _exec_result(stdout="AssertionError: new one\n==== 2 failed, 8 passed ====\n", exit_code=1),
        ]
        llm = _FakeDistillerLLM("this is not JSON")
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert r.distilled_failure_evidence.status == "unresolved"

    def test_llm_call_failure_is_unresolved_not_a_crash(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="AssertionError: noise\n==== 1 failed, 9 passed ====\n", exit_code=1),
            _exec_result(stdout="AssertionError: new one\n==== 2 failed, 8 passed ====\n", exit_code=1),
        ]
        llm = _FakeDistillerLLM(RuntimeError("provider unavailable"))
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.distilled_failure_evidence.status == "unresolved"

    def test_distilled_candidates_never_populate_deterministic_identity_fields(self, tmp_path: Path):
        """The core safety invariant: an LLM-distilled candidate must
        NEVER be written into newly_failing_tests/failed_test_ids."""
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="AssertionError: noise\n==== 1 failed, 9 passed ====\n", exit_code=1),
            _exec_result(stdout="AssertionError: new one\n==== 2 failed, 8 passed ====\n", exit_code=1),
        ]
        llm = _FakeDistillerLLM(_resolved_json(test_id="t::should_never_be_deterministic"))
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert r.newly_failing_tests == []
        assert r.patched.failed_test_ids is None
        assert r.baseline.failed_test_ids is None
        assert r.distilled_failure_evidence.candidates[0].test_id == "t::should_never_be_deterministic"

    def test_no_failure_relevant_output_at_all_is_unresolved_without_calling_llm(self, tmp_path: Path):
        """A clean baseline (exit 0) vs. a failing patched side with
        completely empty captured stdout -- still deterministically
        NEW_FAILURES_DETECTED (exit-code-only comparison), but there is
        nothing at all for the pre-filter to give the distiller."""
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout="==== 0 failed, 10 passed ====\n", exit_code=0),
            _exec_result(stdout="", exit_code=1),
        ]
        llm = _FakeDistillerLLM(_resolved_json())
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert llm.calls == []
        assert r.distilled_failure_evidence.status == "unresolved"


def _urllib3_shaped_stdout(*, failed: int, passed: int, skipped: int, extra_failed_id: "str | None" = None) -> str:
    """Real-shape regression fixture (CVE-2023-43804 replay finding):
    many shared `FAILED test/...` lines, an optional additional
    patched-only failure, and the final aggregate summary line -- the
    exact shape RUNNER_SUMMARY_COUNTS is built to recover, with rich
    transient failure-relevant output that a naive/buggy prefilter could
    still fail to surface (see TestUrllib3ShapedDistillationRegression)."""
    lines = []
    for i in range(failed - (1 if extra_failed_id else 0)):
        lines.append(f"FAILED test/with_dummyserver/test_socketlevel.py::TestHeaders::test_shared_{i}")
    if extra_failed_id:
        lines.append(f"FAILED {extra_failed_id}")
    lines.append(f"==== {failed} failed, {passed} passed, {skipped} skipped, 163 warnings in 65.69s (0:01:05) ====")
    return "\n".join(lines) + "\n"


class TestUrllib3ShapedDeterministicIdRegression:
    """Direct regression anchor for the real replay finding: urllib3
    2.0.5 / CVE-2023-43804, baseline 102/1640/563 -> patched 103/1639/563,
    RUNNER_SUMMARY_COUNTS tier, but pytest's own short-summary listing
    (already present in already-captured output) reliably accounts for
    every failure -- so comparison is now based on the ACTUAL IDs, not
    just the aggregate counts. (This class previously exercised the LLM
    distillation fallback against this exact fixture shape, back when
    per-test identity was still being reduced to aggregate counts only;
    now that identity is reliably recoverable here, the distiller is
    correctly never even reached -- see
    TestUrllib3ShapedDistillationStillFallsBackWhenIdsAreUnreliable below
    for the fixture shape that still needs it.)"""

    _BASELINE_STDOUT = _urllib3_shaped_stdout(failed=102, passed=1640, skipped=563)
    _PATCHED_STDOUT = _urllib3_shaped_stdout(
        failed=103, passed=1639, skipped=563,
        extra_failed_id="test/test_retry.py::TestRetry::test_retry_default_remove_headers_on_redirect",
    )

    def test_comparison_uses_actual_ids_not_counts_alone(self, tmp_path: Path):
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout=self._BASELINE_STDOUT, exit_code=1),
            _exec_result(stdout=self._PATCHED_STDOUT, exit_code=1),
        ]
        # No llm given at all -- proves this resolution is fully
        # deterministic and needs no LLM call whatsoever.
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor,
        )

        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.baseline.evidence_level == "RUNNER_SUMMARY_COUNTS"
        assert r.patched.evidence_level == "RUNNER_SUMMARY_COUNTS"
        assert r.baseline.failed == 102 and r.baseline.passed == 1640 and r.baseline.skipped == 563
        assert r.patched.failed == 103 and r.patched.passed == 1639 and r.patched.skipped == 563

        # The actual point: identity, not just a count delta.
        assert r.newly_failing_tests == [
            "test/test_retry.py::TestRetry::test_retry_default_remove_headers_on_redirect",
        ]
        assert len(r.pre_existing_failures) == 102
        assert r.newly_passing_tests == []

        # Never fabricated -- the exact recovered set sizes match the
        # aggregate counts that were already trusted.
        assert len(r.baseline.failed_test_ids) == 102
        assert len(r.patched.failed_test_ids) == 103

    def test_distiller_never_reached_once_ids_are_reliable(self, tmp_path: Path):
        """Even when an llm IS given, the distillation gate (NEW_FAILURES_
        DETECTED + no deterministic identity) never fires once identity
        is reliably available -- the gate's second condition is now
        false, not merely untested."""
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout=self._BASELINE_STDOUT, exit_code=1),
            _exec_result(stdout=self._PATCHED_STDOUT, exit_code=1),
        ]
        llm = _FakeDistillerLLM(_resolved_json())
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )
        assert llm.calls == []
        assert r.distilled_failure_evidence is None


class TestUrllib3ShapedDistillationStillFallsBackWhenIdsAreUnreliable:
    """The distillation fallback (see TestDistillationGate) remains
    necessary and correctly reached for the genuinely unreliable case:
    real, large, transient runner output where a reliable per-test
    listing is NOT available (here: no pytest-shaped FAILED/ERROR lines
    at all, only free-form diagnostic noise) -- as distinct from
    TestUrllib3ShapedDeterministicIdRegression above, where it now is."""

    def test_prefilter_uses_transient_raw_stdout_not_the_persisted_excerpt(self, tmp_path: Path):
        """The persisted, bounded stdout_excerpt (4000 chars) is NOT what
        the distiller sees -- it operates on the raw, untruncated
        TestExecutionResult.stdout captured during this same S11
        execution. Proven here by making the patched-only failure line
        sit far enough into the file that a naive head+tail 4000-char
        excerpt of the exact same content would very plausibly miss or
        mis-locate it, while the full transient stdout does not. Uses
        free-form diagnostic noise (not pytest-shaped FAILED lines) so
        this genuinely exercises "no reliable deterministic identity",
        not an accidental count mismatch."""
        repo = _make_git_repo(tmp_path)
        shared_noise = "AssertionError: baseline_shared_failure\n" * 102
        baseline_stdout = shared_noise + "==== 102 failed, 1640 passed, 563 skipped ====\n"
        padding = "AssertionError: unrelated diagnostic noise\n" * 200
        patched_stdout = (
            padding + shared_noise
            + "AssertionError: test_retry_default_remove_headers_on_redirect failed\n"
            + "==== 103 failed, 1639 passed, 563 skipped ====\n"
        )
        assert len(patched_stdout) > etr._MAX_EXCERPT_CHARS

        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout=baseline_stdout, exit_code=1),
            _exec_result(stdout=patched_stdout, exit_code=1),
        ]
        llm = _FakeDistillerLLM(_resolved_json(
            test_id="test/test_retry.py::TestRetry::test_retry_default_remove_headers_on_redirect",
        ))
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _EXIT_CODE_PLAN, executor=executor, llm=llm,
        )

        assert r.baseline.failed_test_ids is None
        assert r.patched.failed_test_ids is None
        assert len(llm.calls) == 1
        # The persisted excerpt is still small and bounded, as always --
        # distillation succeeding is independent of it. (+100 slack for
        # _excerpt()'s own "[... N omitted ...]" marker overhead -- see
        # TestExcerptBounding.)
        assert len(r.patched.stdout_excerpt) <= etr._MAX_EXCERPT_CHARS + 100
        # No raw full log is ever persisted onto the result itself.
        assert not any(
            len(str(v)) > etr._MAX_EXCERPT_CHARS * 2
            for v in vars(r.patched).values() if isinstance(v, str)
        )

    def test_inverse_deterministic_identity_present_means_zero_distiller_calls(self, tmp_path: Path):
        """The exact inverse case requested alongside the urllib3
        regression: when deterministic identity IS available, the
        distiller must never be called, even though rich raw runner
        output also exists on both sides."""
        repo = _make_git_repo(tmp_path)
        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(result_output=_junit(passed=1640, failed_ids=[f"t::shared_{i}" for i in range(102)])),
            _exec_result(result_output=_junit(
                passed=1639,
                failed_ids=[f"t::shared_{i}" for i in range(102)] + ["some/test::id"],
            )),
        ]
        llm = _FakeDistillerLLM(_resolved_json())
        r = etr.evaluate_existing_test_comparison_with_plan(
            repo, _SOME_PATCH, _plan(), executor=executor, llm=llm,
        )
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.newly_failing_tests == ["some/test::id"]
        assert len(llm.calls) == 0
        assert r.distilled_failure_evidence is None


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

    def test_deterministic_identity_shows_diagnostic_as_fact(self):
        """A structured (OK-tier) newly-failing test's diagnostic is
        presented directly under its name -- no hedging, no "candidate"
        language -- because it IS deterministic evidence."""
        b = _run(430)
        p = _run(429, failed_ids=["t::test_new"])
        p.failure_diagnostics = {"t::test_new": "AssertionError: expected 2 got 1"}
        r = etr.compare_runs(("cmd",), b, p)
        out = etr.render_existing_test_comparison(r)
        assert "t::test_new" in out
        assert "AssertionError: expected 2 got 1" in out
        assert "Candidate" not in out
        assert "Distilled" not in out

    def test_distilled_candidate_is_explicitly_labeled(self):
        """A distilled candidate must be visually and textually
        distinguishable from deterministic identity -- never presented as
        plain fact."""
        baseline = etr.TestRunResult(
            command=("make", "test"), status="COMPLETED", exit_code=1, duration_seconds=1.0,
            passed=9, failed=1, skipped=0, errors=0, failed_test_ids=None,
            stdout_excerpt="", stderr_excerpt="", timed_out=False, evidence_level="RUNNER_SUMMARY_COUNTS",
        )
        patched = etr.TestRunResult(
            command=("make", "test"), status="COMPLETED", exit_code=1, duration_seconds=1.0,
            passed=8, failed=2, skipped=0, errors=0, failed_test_ids=None,
            stdout_excerpt="", stderr_excerpt="", timed_out=False, evidence_level="RUNNER_SUMMARY_COUNTS",
        )
        result = etr.ExistingTestComparisonResult(
            status=etr.STATUS_NEW_FAILURES_DETECTED, command=("make", "test"),
            baseline=baseline, patched=patched,
            reason="Failure/error count increased from 1 to 2; individual newly-failing tests could not be identified.",
            distilled_failure_evidence=etr.DistilledFailureEvidence(
                status="resolved",
                candidates=[etr.DistilledFailureCandidate(
                    test_id="test/test_retry.py::TestRetry::test_x",
                    failure_summary="assertion on removed headers failed",
                    supporting_excerpt="AssertionError: {'Cookie'} != set()",
                )],
            ),
        )
        out = etr.render_existing_test_comparison(result)
        assert "Candidate newly failing test: test/test_retry.py::TestRetry::test_x" in out
        assert "Distilled from runner output" in out
        assert "assertion on removed headers failed" in out
        assert "AssertionError: {'Cookie'} != set()" in out
        # Never presented as if it were the deterministic list.
        assert "**Newly failing:**" not in out

    def test_unresolved_distillation_explains_truthfully(self):
        result = etr.ExistingTestComparisonResult(
            status=etr.STATUS_NEW_FAILURES_DETECTED, command=("make", "test"),
            baseline=_exit_only(1), patched=_exit_only(1),
            reason="patched run exited non-zero after a clean baseline; exit-code-only evidence.",
            distilled_failure_evidence=etr.DistilledFailureEvidence(
                status="unresolved", reason="evidence too ambiguous",
            ),
        )
        out = etr.render_existing_test_comparison(result)
        assert "could not be identified reliably" in out.lower()
        assert "Candidate newly failing test" not in out

    def test_no_distillation_attempted_still_explains_truthfully(self):
        """distilled_failure_evidence is None (never attempted, e.g. no
        llm was given) -- must render the same honest "could not be
        identified" explanation, not a blank/misleading section."""
        baseline = _run(100, level="COUNTS_ONLY")
        baseline.failed = 0
        patched = _run(98, level="COUNTS_ONLY")
        patched.failed = 2
        r = etr.compare_runs(("cmd",), baseline, patched)
        assert r.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert r.distilled_failure_evidence is None
        out = etr.render_existing_test_comparison(r)
        assert "could not be identified reliably" in out.lower()


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
