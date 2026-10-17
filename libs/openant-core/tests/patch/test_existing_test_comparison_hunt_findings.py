"""PR #763 HUNT N11/N12: Existing Test Comparison without per-test identities.

N11: an aggregate-only JUnit report (`<testsuite failures="N">`, no
`<testcase>` children) parses to `failed_test_ids == []`, and identity
comparison read two empty sets as "no failures" -> PASS for 1 -> 2 failures.
N12: equal failure counts were reported as PRE_EXISTING_FAILURES_ONLY although
one test may have been fixed and a different one broken.
"""

from types import SimpleNamespace

import pytest

from utilities.autopatcher import existing_test_regression as etr

_PLAN = SimpleNamespace(test_command=("runner",), result_strategy="junit")


def _junit(failed: int, *, detailed: bool = False, names=None, exit_code=None):
    names = names or [f"t{i}" for i in range(failed)]
    cases = "".join(f'<testcase name="{n}"><failure/></testcase>' for n in names) if detailed else ""
    xml = f'<testsuite tests="5" failures="{failed}" errors="0">{cases}</testsuite>'
    raw = SimpleNamespace(setup_failed=False, timed_out=False, exit_code=int(failed > 0) if exit_code is None else exit_code,
                          duration_seconds=1, stdout="", stderr="", result_output=xml)
    return etr._to_test_run_result(_PLAN, raw)


def _summary(failed: int, out: str):
    return etr.TestRunResult(command=("npm", "test"), status="COMPLETED", exit_code=1, duration_seconds=1.0,
                             passed=9, failed=failed, skipped=None, errors=None, failed_test_ids=None,
                             stdout_excerpt=out, stderr_excerpt="", timed_out=False,
                             evidence_level="RUNNER_SUMMARY_COUNTS")


class TestN11AggregateOnlyJunit:
    @pytest.mark.parametrize("before,after", [(1, 2), (2, 3), (0, 3)])
    def test_increase_is_detected(self, before, after):
        result = etr.compare_runs(_PLAN.test_command, _junit(before), _junit(after))
        assert result.status == etr.STATUS_NEW_FAILURES_DETECTED

    def test_equal_counts_are_never_pass(self):
        result = etr.compare_runs(_PLAN.test_command, _junit(1), _junit(1))
        assert result.status == etr.STATUS_NOT_VERIFIED

    def test_detailed_reports_still_compare_by_identity(self):
        result = etr.compare_runs(_PLAN.test_command, _junit(2, detailed=True), _junit(3, detailed=True))
        assert result.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert result.newly_failing_tests == ["t2"]

    def test_clean_runs_still_pass(self):
        assert etr.compare_runs(_PLAN.test_command, _junit(0), _junit(0)).status == etr.STATUS_PASS


class TestN12EqualCountSubstitution:
    def test_swapped_failure_is_not_pre_existing(self):
        b = _summary(1, "FAIL  test/security.test.js > rejects ../ traversal\nTests: 1 failed, 9 passed, 10 total\n")
        p = _summary(1, "FAIL  test/upload.test.js > accepts nested dirs\nTests: 1 failed, 9 passed, 10 total\n")
        result = etr.compare_runs(("npm", "test"), b, p)
        assert result.status == etr.STATUS_NOT_VERIFIED
        assert etr.classify_existing_test_comparison_signal(result)["value"] == "NOT_VERIFIED"

    def test_fewer_failures_without_identities_is_not_pre_existing(self):
        b, p = _summary(2, "Tests: 2 failed, 8 passed\n"), _summary(1, "Tests: 1 failed, 9 passed\n")
        assert etr.compare_runs(("npm", "test"), b, p).status == etr.STATUS_NOT_VERIFIED

    def test_all_failures_fixed_is_still_pass(self):
        b, p = _summary(2, "Tests: 2 failed, 8 passed\n"), _summary(0, "Tests: 10 passed\n")
        assert etr.compare_runs(("npm", "test"), b, p).status == etr.STATUS_PASS

    def test_identities_still_prove_pre_existing(self):
        b = _junit(1, detailed=True, names=["security"])
        p = _junit(1, detailed=True, names=["security"])
        assert etr.compare_runs(_PLAN.test_command, b, p).status == etr.STATUS_PRE_EXISTING_FAILURES_ONLY

    def test_identities_still_expose_a_swap(self):
        b = _junit(1, detailed=True, names=["security"])
        p = _junit(1, detailed=True, names=["upload"])
        result = etr.compare_runs(_PLAN.test_command, b, p)
        assert result.status == etr.STATUS_NEW_FAILURES_DETECTED and result.newly_failing_tests == ["upload"]
