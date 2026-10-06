"""Regression tests: missing, malformed, failed or unresolved evidence must
never become positive evidence merely because a stage failed to produce a
usable answer.

Each class reproduces one defect found in the PR #763 review and pins the
fail-closed behavior, plus the matching genuine-negative case so the failure
state stays distinguishable from a real clean result.
"""

from __future__ import annotations

from pathlib import Path

from utilities.autopatcher.finding_calibration import _parse_response
from utilities.autopatcher.pipeline import (
    _build_known_findings,
    _classify_challenger,
    _reconcile_verification_status_with_calibration,
)


def _challenger(verification_status, still_vulnerable, edge_cases=None, potential_issues=None):
    return {
        "verification_status": verification_status,
        "still_vulnerable": still_vulnerable,
        "edge_cases": edge_cases or [],
        "potential_issues": potential_issues or [],
        "summary": "",
    }


# ---------------------------------------------------------------------------
# 1. Finding Calibration parse failure = no calibration, never "examined and
#    clean" (recommendation-policy.md: "A missing calibration counts as a
#    defect"; "an uncalibrated validation_gap finding blocks").
# ---------------------------------------------------------------------------

_VALIDATION_GAP = "Cannot verify that the sanitizer is applied on the async code path"
_CONFIRMED_DEFECT = "`validate_path` can be bypassed using symlinked upload directories"

_CLEAN_BLOCK = (
    "1. Claims:\n"
    "   - The evidence directly establishes the claim.\n"
    "   Unresolved: none\n"
    "   Remediation impact: validation_only\n"
    "   Group: Observed\n"
    "   Reworded: text.\n"
)


class TestCalibrationParseFailureIsNotCalibration:
    def test_unparseable_response_is_marked_failed(self):
        [entry] = _parse_response("garbage", [_VALIDATION_GAP])
        assert entry["calibration_failed"] is True

    def test_unparseable_unresolved_field_is_marked_failed(self):
        resp = _CLEAN_BLOCK.replace("Unresolved: none", "Unresolved: ;")
        [entry] = _parse_response(resp, [_VALIDATION_GAP])
        assert entry["calibration_failed"] is True

    def test_genuine_clean_calibration_is_not_marked_failed(self):
        [entry] = _parse_response(_CLEAN_BLOCK, [_VALIDATION_GAP])
        assert entry["calibration_failed"] is False
        assert entry["unresolved_dependencies"] == []
        assert entry["remediation_impact"] == "validation_only"

    def test_failed_calibration_keeps_validation_gap_blocking(self):
        classified = _classify_challenger(_challenger("VERIFIED_FIXED", False, potential_issues=[_VALIDATION_GAP]))
        assert classified["validation_gap_count"] > 0
        failed = _parse_response("garbage", [_VALIDATION_GAP])
        result = _reconcile_verification_status_with_calibration(classified, failed)
        # Identical to "calibration never ran" -- never cleared.
        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert result["still_vulnerable"] is True
        assert result == _reconcile_verification_status_with_calibration(classified, None)

    def test_genuine_clean_calibration_still_clears_validation_gap(self):
        classified = _classify_challenger(_challenger("VERIFIED_FIXED", False, potential_issues=[_VALIDATION_GAP]))
        clean = _parse_response(_CLEAN_BLOCK, [_VALIDATION_GAP])
        result = _reconcile_verification_status_with_calibration(classified, clean)
        assert result["verification_status"] == "VERIFIED_FIXED"

    def test_legacy_failure_shape_without_marker_is_still_failed(self):
        """Artifacts persisted before the explicit marker existed: the parser
        only ever produced unresolved=[] with impact "unclear" on failure (a
        clean "Unresolved: none" is always normalized to validation_only)."""
        classified = _classify_challenger(_challenger("VERIFIED_FIXED", False, potential_issues=[_VALIDATION_GAP]))
        legacy = [{
            "original": _VALIDATION_GAP, "group": "hypothesis", "reworded": _VALIDATION_GAP,
            "unresolved_dependencies": [], "remediation_impact": "unclear",
        }]
        result = _reconcile_verification_status_with_calibration(classified, legacy)
        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"

    def test_failed_calibration_keeps_confirmed_defect_counted(self):
        classified = _classify_challenger(_challenger("VERIFIED_FIXED", False, edge_cases=[_CONFIRMED_DEFECT]))
        assert any(f["category"] == "confirmed_defect" for f in classified["classified_edge_cases"])
        failed = _parse_response("garbage", [_CONFIRMED_DEFECT])
        known = _build_known_findings(classified, failed)
        assert _CONFIRMED_DEFECT in known["potential_remaining_risks"]
        assert known == _build_known_findings(classified, None)


# ---------------------------------------------------------------------------
# 2. A truncated or aborted TAP stream is a parse failure, never "no failures".
# ---------------------------------------------------------------------------

from utilities.autopatcher.tap_parser import parse_tap  # noqa: E402


class TestTruncatedTapIsNotParsed:
    def test_bail_out_is_a_parse_failure(self):
        text = "TAP version 13\n1..10\nok 1 - a\nok 2 - b\nBail out! Segmentation fault\n"
        assert parse_tap(text) is None

    def test_bail_out_without_plan_is_a_parse_failure(self):
        assert parse_tap("TAP version 13\nok 1 - a\nBail out!\n") is None

    def test_plan_larger_than_results_is_a_parse_failure(self):
        assert parse_tap("TAP version 13\n1..10\nok 1 - a\nok 2 - b\nok 3 - c\n") is None

    def test_plan_smaller_than_results_is_a_parse_failure(self):
        assert parse_tap("TAP version 13\n1..1\nok 1 - a\nok 2 - b\n") is None

    def test_two_top_level_plans_are_a_parse_failure(self):
        assert parse_tap("TAP version 13\n1..1\nok 1 - a\n1..1\n") is None

    def test_complete_stream_with_trailing_plan_still_parses(self):
        parsed = parse_tap("TAP version 13\nok 1 - a\nnot ok 2 - b\n1..2\n")
        assert parsed is not None and parsed.passed == 1 and parsed.failed_test_ids == ["b"]

    def test_subtest_counts_as_one_planned_point(self):
        text = (
            "TAP version 13\n"
            "# Subtest: group\n"
            "    ok 1 - x\n"
            "    not ok 2 - y\n"
            "    1..2\n"
            "not ok 1 - group\n"
            "ok 2 - solo\n"
            "1..2\n"
        )
        parsed = parse_tap(text)
        assert parsed is not None
        assert parsed.failed_test_ids == ["group > y"]
        assert parsed.passed == 2

    def test_skip_all_plan_is_recognised_as_a_plan(self):
        """`1..0 # SKIP reason` is TAP's "nothing ran" plan -- it parses to
        zero tests (item 4 decides what zero tests means), it is not
        silently ignored as stray output."""
        parsed = parse_tap("TAP version 13\n1..0 # SKIP no tests on this platform\n")
        assert parsed is not None
        assert parsed.passed == parsed.failed == parsed.skipped == 0


# ---------------------------------------------------------------------------
# 2-4. Existing Test Comparison: an aborted run, a worsened exit code, or a
#      run that executed nothing is never "no new failures".
# ---------------------------------------------------------------------------

from utilities.autopatcher import existing_test_regression as etr  # noqa: E402
from utilities.autopatcher.test_execution_models import TestExecutionPlan, TestExecutionResult  # noqa: E402

_TAP_PLAN = TestExecutionPlan(
    setup_commands=(), test_command=("node", "--test"), result_strategy="tap", result_output_path=None,
    runtime_family="node", runtime_version_hint=None, evidence=("package.json",), reasoning_summary="t", confidence="high",
)
_JUNIT_PLAN = TestExecutionPlan(
    setup_commands=(), test_command=("pytest", "--junitxml=r.xml"), result_strategy="junit",
    result_output_path="r.xml", runtime_family="python", runtime_version_hint=None, evidence=("pytest.ini",), reasoning_summary="t", confidence="high",
)
_EXIT_PLAN = TestExecutionPlan(
    setup_commands=(), test_command=("make", "test"), result_strategy="exit_code", result_output_path=None,
    runtime_family="python", runtime_version_hint=None, evidence=("Makefile",), reasoning_summary="t", confidence="high",
)

_TEN_PASSING_TAP = "TAP version 13\n" + "".join(f"ok {i} - t{i}\n" for i in range(1, 11)) + "1..10\n"
_JUNIT_ZERO = '<testsuites><testsuite name="pytest" tests="0" failures="0" errors="0" skipped="0"></testsuite></testsuites>'
_JUNIT_TWO_PASS = (
    '<testsuites><testsuite name="pytest" tests="2" failures="0" errors="0" skipped="0">'
    '<testcase classname="t" name="a"/><testcase classname="t" name="b"/></testsuite></testsuites>'
)


def _raw(*, stdout="", result_output=None, exit_code=0):
    return TestExecutionResult(
        ran=True, exit_code=exit_code, timed_out=False, setup_failed=False, setup_error="",
        stdout=stdout, stderr="", result_output=result_output, duration_seconds=1.0, executor="docker",
    )


def _compare(plan, baseline_raw, patched_raw):
    baseline = etr._to_test_run_result(plan, baseline_raw)
    patched = etr._to_test_run_result(plan, patched_raw)
    return baseline, patched, etr.compare_runs(plan.test_command, baseline, patched)


class TestAbortedTapRunIsNeverPass:
    def test_bail_out_with_exit_zero_is_not_laundered_into_exit_code_pass(self):
        aborted = "TAP version 13\n1..10\nok 1 - t1\nok 2 - t2\nBail out! worker crashed\n"
        _, patched, result = _compare(_TAP_PLAN, _raw(stdout=_TEN_PASSING_TAP), _raw(stdout=aborted, exit_code=0))
        assert patched.evidence_level == "UNAVAILABLE"
        assert "abort" in patched.reason.lower() or "incomplete" in patched.reason.lower()
        assert result.status != etr.STATUS_PASS

    def test_unfulfilled_plan_with_exit_zero_is_not_pass(self):
        cut = "TAP version 13\n1..10\nok 1 - t1\nok 2 - t2\n"
        _, patched, result = _compare(_TAP_PLAN, _raw(stdout=_TEN_PASSING_TAP), _raw(stdout=cut, exit_code=0))
        assert patched.evidence_level == "UNAVAILABLE"
        assert result.status != etr.STATUS_PASS

    def test_unrecognisable_tap_keeps_the_documented_exit_code_fallback(self):
        """Garbage that is not TAP at all says nothing about the run, so the
        existing (weaker, labelled) exit-code fallback still applies."""
        patched = etr._to_test_run_result(_TAP_PLAN, _raw(stdout="segfault in libfoo\n", exit_code=0))
        assert patched.evidence_level == "EXIT_CODE_ONLY"


class TestWorsenedExitCodeIsNeverIgnored:
    def test_ids_show_no_new_failure_but_patched_exit_nonzero(self):
        _, _, result = _compare(_TAP_PLAN, _raw(stdout=_TEN_PASSING_TAP, exit_code=0),
                                _raw(stdout=_TEN_PASSING_TAP, exit_code=1))
        assert result.status == etr.STATUS_NOT_VERIFIED
        assert "exit" in result.reason.lower()

    def test_counts_show_no_new_failure_but_patched_exit_nonzero(self):
        _, _, result = _compare(_JUNIT_PLAN, _raw(result_output=_JUNIT_TWO_PASS, exit_code=0),
                                _raw(result_output=_JUNIT_TWO_PASS, exit_code=2))
        assert result.status == etr.STATUS_NOT_VERIFIED

    def test_genuine_clean_runs_still_pass(self):
        _, _, result = _compare(_TAP_PLAN, _raw(stdout=_TEN_PASSING_TAP), _raw(stdout=_TEN_PASSING_TAP))
        assert result.status == etr.STATUS_PASS

    def test_real_new_failure_with_nonzero_exit_is_still_new_failures(self):
        failing = _TEN_PASSING_TAP.replace("ok 3 - t3", "not ok 3 - t3")
        _, _, result = _compare(_TAP_PLAN, _raw(stdout=_TEN_PASSING_TAP), _raw(stdout=failing, exit_code=1))
        assert result.status == etr.STATUS_NEW_FAILURES_DETECTED
        assert result.newly_failing_tests == ["t3"]


class TestZeroTestsIsNotSuccessfulEvidence:
    def test_tap_skip_all_plan_is_not_pass(self):
        skip_all = "TAP version 13\n1..0 # SKIP nothing to run\n"
        _, _, result = _compare(_TAP_PLAN, _raw(stdout=skip_all), _raw(stdout=skip_all))
        assert result.status != etr.STATUS_PASS

    def test_structured_zero_tests_is_reported_as_zero_tests_not_exit_code(self):
        run = etr._to_test_run_result(_JUNIT_PLAN, _raw(result_output=_JUNIT_ZERO))
        assert run.evidence_level == "UNAVAILABLE"
        assert "zero tests" in run.reason.lower()

    def test_runner_summary_with_zero_tests_is_not_pass(self):
        summary = "collected 0 items\n\n===== 0 passed, 0 failed in 0.01s =====\n"
        baseline, patched, result = _compare(_EXIT_PLAN, _raw(stdout=summary), _raw(stdout=summary))
        assert baseline.evidence_level == "RUNNER_SUMMARY_COUNTS"
        assert result.status == etr.STATUS_NOT_VERIFIED
        assert "zero tests" in result.reason.lower()


# ---------------------------------------------------------------------------
# 5. An exception inside a trust-critical gate never lets the run proceed as
#    though the gate had passed.
# ---------------------------------------------------------------------------

from unittest import mock  # noqa: E402

from utilities.autopatcher import pipeline as pipeline_mod  # noqa: E402
from utilities.autopatcher import remediation_planner as rp_mod  # noqa: E402
from utilities.autopatcher.remediation_planner import RemediationPlanResult  # noqa: E402
from utilities.autopatcher.remediation_verifier import VerifierResult  # noqa: E402

_VULN_TEXT = "# Test vulnerability\n\nSome description of a vulnerability for testing.\n"


def _grounded_plan(tmp_path, narrower):
    target = tmp_path / "target.py"
    if not target.exists():
        target.write_text("def foo():\n    pass\n", encoding="utf-8")
    return RemediationPlanResult(
        rendered="## Target Discovery Plan\n", target_files=["target.py"], target_symbols=["target.py:foo"],
        security_invariant="the unsafe condition must not occur", remediation_mechanism="the broad mechanism",
        narrower_alternative_decision=None, narrower_alternative_considered=narrower,
        required_edits=["edit one"], approaches_to_avoid=[], explicit_unknowns=[],
        additional_evidence_required="explicit_false",
    )


def _verdict(status, contradiction=None):
    return VerifierResult(
        status=status, reason="because", contradiction=contradiction, failure_kind=None, evaluated=True,
        counterexample_reaches_unsafe_state=None, authoritative_remediation_matches_selected_alternative=None,
    )


class TestPlanVerificationExceptionFailsClosed:
    def _run(self, tmp_path, *, crash_verifier=False, crash_v2_adoption=False):
        plan_v1 = _grounded_plan(tmp_path, "rejected narrower mechanism because X")
        plan_v2 = _grounded_plan(tmp_path, "rejected narrower mechanism because Y (revised)")
        real_build = rp_mod.build_planner_evidence_with_budget

        def _build(plan, *a, **kw):
            if crash_v2_adoption and plan is plan_v2:
                raise RuntimeError("v2 evidence rebuild exploded")
            return real_build(plan, *a, **kw)

        patches = [
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_plan",
                       side_effect=[plan_v1, plan_v2]),
            mock.patch("utilities.autopatcher.remediation_verifier.verify_planner_claim",
                       side_effect=[_verdict("CONTRADICTED", "finding one"), _verdict("SUPPORTED")]),
            mock.patch("utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                       side_effect=_build),
        ]
        if crash_verifier:
            patches.append(mock.patch.object(pipeline_mod, "_run_planner_claim_verification",
                                             side_effect=RuntimeError("verifier exploded")))
        with mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy") as spy_strategy, \
                mock.patch("utilities.autopatcher.pipeline.generate_patch_raw") as spy_patch_gen:
            for p in patches:
                p.start()
            try:
                report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
            finally:
                for p in reversed(patches):
                    p.stop()
        return report, spy_strategy, spy_patch_gen

    def test_crash_while_adopting_authoritative_v2_skips_strategy_and_patch(self, tmp_path):
        report, spy_strategy, spy_patch_gen = self._run(tmp_path, crash_v2_adoption=True)
        spy_strategy.assert_not_called()
        spy_patch_gen.assert_not_called()
        assert "NO PATCH PRODUCED" in report
        assert "Planner Claim Verifier" in report

    def test_crash_inside_verification_skips_strategy_and_patch(self, tmp_path):
        report, spy_strategy, spy_patch_gen = self._run(tmp_path, crash_verifier=True)
        spy_strategy.assert_not_called()
        spy_patch_gen.assert_not_called()
        assert "NO PATCH PRODUCED" in report


from tests.patch.test_evidence_gap_strategy_fallback import (  # noqa: E402
    _VULN_TEXT as _GAP_VULN_TEXT,
    _evidence_result,
    _plan,
    _strategy,
)


class TestEditReadinessExceptionFailsClosed:
    def _run(self, tmp_path, slice_side_effect):
        strategy = _strategy(evaluated=True, target_files=["target.py"], target_symbols=["Target"])
        with (
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_plan",
                       return_value=_plan(target_files=["target.py"], target_symbols=["Target"])),
            mock.patch("utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                       return_value=_evidence_result("evidence", ["target.py:Target"])),
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                       return_value=strategy),
            mock.patch("utilities.autopatcher.remediation_planner.build_final_target_slice",
                       side_effect=slice_side_effect) as mock_slice,
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw") as spy_patch_gen,
        ):
            report = pipeline_mod.run(vulnerability_text=_GAP_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        return report, mock_slice, spy_patch_gen

    def test_crash_while_checking_readiness_never_reaches_patch_generation(self, tmp_path):
        report, mock_slice, spy_patch_gen = self._run(tmp_path, RuntimeError("slice builder exploded"))
        mock_slice.assert_called()  # the readiness gate really was reached, and crashed
        spy_patch_gen.assert_not_called()
        assert "NO PATCH PRODUCED" in report


# ---------------------------------------------------------------------------
# 6. Cross-section dedup never discards the stronger of two duplicates.
# ---------------------------------------------------------------------------

from utilities.autopatcher.pipeline import _classify_finding, _dedupe_challenger_findings  # noqa: E402

_DEFECT = "`validate_path` can be bypassed using symlinked upload directories"
_LONGER_RISK = "`validate_path` handling of symlinked upload directories using mounts needs review"


class TestDedupKeepsTheStrongerFinding:
    def test_fixture_is_a_real_duplicate_pair_of_different_strength(self):
        assert _classify_finding(_DEFECT) == "confirmed_defect"
        assert _classify_finding(_LONGER_RISK) == "plausible_risk"
        assert len(_LONGER_RISK) > len(_DEFECT)
        _, _, record = _dedupe_challenger_findings([_DEFECT], [_LONGER_RISK])
        assert len(record) == 1  # they ARE treated as duplicates

    def test_confirmed_defect_survives_a_longer_weaker_duplicate(self):
        edge, potential, record = _dedupe_challenger_findings([_DEFECT], [_LONGER_RISK])
        assert edge == [_DEFECT] and potential == []
        assert record[0]["kept_text"] == _DEFECT and record[0]["dropped_text"] == _LONGER_RISK

    def test_same_holds_with_sections_swapped(self):
        edge, potential, _ = _dedupe_challenger_findings([_LONGER_RISK], [_DEFECT])
        assert edge == [] and potential == [_DEFECT]

    def test_defect_still_counts_after_classification(self):
        classified = _classify_challenger(_challenger("VERIFIED_FIXED", False, edge_cases=[_DEFECT],
                                                      potential_issues=[_LONGER_RISK]))
        assert any(f["category"] == "confirmed_defect"
                   for f in classified["classified_edge_cases"] + classified["classified_potential_issues"])

    def test_equal_strength_duplicates_keep_the_longer_text_as_before(self):
        short = "`validate_path` handling of symlinked upload directories needs review"
        edge, potential, _ = _dedupe_challenger_findings([short], [_LONGER_RISK])
        assert _classify_finding(short) == _classify_finding(_LONGER_RISK)
        assert edge == [] and potential == [_LONGER_RISK]


# ---------------------------------------------------------------------------
# 7. The Existing Test Amendment scope gate sees every file a diff touches.
# ---------------------------------------------------------------------------

from utilities.autopatcher.existing_test_amendment import _validate_amendment_diff  # noqa: E402

_GROUNDED = {"tests/test_a.py"}
_PROD = {"src/app.py"}
_EDIT_A = (
    "diff --git a/tests/test_a.py b/tests/test_a.py\n"
    "--- a/tests/test_a.py\n"
    "+++ b/tests/test_a.py\n"
    "@@ -1,2 +1,2 @@\n"
    " def test_x():\n"
    "-    assert old()\n"
    "+    assert new()\n"
)


class TestAmendmentScopeSeesEverySection:
    def test_in_scope_edit_is_still_accepted(self):
        assert _validate_amendment_diff(_EDIT_A, _PROD, _GROUNDED) is None

    def test_pure_rename_of_out_of_scope_file_is_rejected(self):
        diff = _EDIT_A + (
            "diff --git a/tests/test_b.py b/tests/test_b_disabled.py\n"
            "similarity index 100%\n"
            "rename from tests/test_b.py\n"
            "rename to tests/test_b_disabled.py\n"
        )
        assert _validate_amendment_diff(diff, _PROD, _GROUNDED) is not None

    def test_mode_only_change_is_rejected(self):
        diff = _EDIT_A + (
            "diff --git a/tests/conftest.py b/tests/conftest.py\n"
            "old mode 100644\n"
            "new mode 100755\n"
        )
        assert _validate_amendment_diff(diff, _PROD, _GROUNDED) is not None

    def test_deletion_is_rejected(self):
        diff = _EDIT_A + (
            "diff --git a/tests/test_b.py b/tests/test_b.py\n"
            "deleted file mode 100644\n"
            "--- a/tests/test_b.py\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-def test_b(): pass\n"
        )
        assert _validate_amendment_diff(diff, _PROD, _GROUNDED) is not None

    def test_binary_section_is_rejected(self):
        diff = _EDIT_A + (
            "diff --git a/tests/data.bin b/tests/data.bin\n"
            "Binary files a/tests/data.bin and b/tests/data.bin differ\n"
        )
        assert _validate_amendment_diff(diff, _PROD, _GROUNDED) is not None


# ---------------------------------------------------------------------------
# 8. A Challenger result without an explicit still_vulnerable=False is never
#    read as "fixed".
# ---------------------------------------------------------------------------

from utilities.autopatcher.pipeline import PipelineResult, _build_report, _compute_trust_signals  # noqa: E402


def _report_for(tmp_path, challenger):
    return _build_report(PipelineResult(
        vulnerability_text="# Test vulnerability\n\nSome description.",
        patch="--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n def foo():\n-    return 1\n+    return 2\n",
        review="**Explanation:**\nok\n\n**Affected areas:**\n- mod.py\n\n**Validation notes:**\n- ok\n",
        score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
        challenger=challenger,
        impact={"impact_level": "low", "changed_files": [], "affected_files": [], "impact_summary": "",
                "recommendations": [], "usage_matches": []},
        hygiene=[],
        applicability={"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""},
        behavior=None, repo_root=tmp_path, detected_language="python",
    ))


class TestMissingStillVulnerableIsNotSafe:
    _VERIFIED = {"verification_status": "VERIFIED_FIXED", "edge_cases": [], "potential_issues": [], "summary": ""}

    def test_control_explicit_false_reaches_deploy_after_validation(self, tmp_path):
        report = _report_for(tmp_path, {**self._VERIFIED, "still_vulnerable": False})
        assert "Deploy After Validation" in report

    def test_missing_key_never_reaches_deploy_after_validation(self, tmp_path):
        report = _report_for(tmp_path, dict(self._VERIFIED))
        assert "Deploy After Validation" not in report

    def test_missing_key_signals_match_explicit_true(self):
        missing = _classify_challenger(dict(self._VERIFIED))
        explicit = _classify_challenger({**self._VERIFIED, "still_vulnerable": True})
        assert _compute_trust_signals([], {"applicable": True}, missing, "None", "low") == \
            _compute_trust_signals([], {"applicable": True}, explicit, "None", "low")


# ---------------------------------------------------------------------------
# Stage 2 / A. A citation must be long enough to identify evidence: a 1-2
#    character "quote" occurs in almost any corpus and proves nothing.
# ---------------------------------------------------------------------------

from utilities.autopatcher.patch_challenger import _point_citation_valid, challenge_patch  # noqa: E402
from utilities.autopatcher.pipeline import _challenger_provenance_context  # noqa: E402

_C_VULN = "# Path traversal in read_file\n\nread_file joins user input onto BASE without validation."
_C_PATCH = ("--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,5 @@\n def read_file(name):\n"
            "+    if '..' in name:\n+        raise ValueError('bad')\n     return open(BASE + name).read()\n")
_C_CODE = ("#### Target definition: `read_file` (mod.py)\n\n```python\ndef read_file(name):\n"
           "    return open(BASE + name).read()\n```")
_REAL_QUOTES = ("if '..' in name:", "return open(BASE + name).read()", "if '..' in name:", "raise ValueError('bad')")


def _concern_response(guard, operation, default_state, effect):
    block = (
        "1. Role: primary\n"
        "   Description: traversal path after patch\n"
        "   Operation present in evidence: present\n"
        f"   Operation provenance: {operation}\n"
        "   Preceding guard: present\n"
        f"   Guard provenance: {guard}\n"
        "   Function provenance: none\n"
        "   Guard default state: condition_true_under_default\n"
        f"   Guard default state provenance: {default_state}\n"
        "   Guard effect: prevents_operation\n"
        f"   Guard effect provenance: {effect}\n"
        "   Reentry state propagation: not_applicable\n"
        "   Reentry provenance: none\n"
        "   Requires explicit non-default action: false\n"
        "   Override provenance: none\n"
        "   Contract addresses override: not_applicable\n"
        "   Scope provenance: none\n"
    )
    return (f"Verification status: VERIFIED_FIXED\n\nConcerns:\n{block}\nEdge cases:\n- none\n\n"
            "Potential issues:\n- none\n\nSummary:\n- none\n")


class _FixedLLM:
    def __init__(self, text):
        self.text = text

    def complete(self, system_prompt, user_message, stage="unknown"):
        return self.text


def _challenge(quotes):
    provenance = _challenger_provenance_context([_C_CODE], _C_CODE)
    return challenge_patch(_C_VULN, _C_PATCH, _FixedLLM(_concern_response(*quotes)),
                           code_context=_C_CODE, provenance_context=provenance)


class TestCitationsMustIdentifyEvidence:
    def test_single_char_citations_never_verify(self, tmp_path):
        out = _challenge(("d", "r", "e", "a"))  # every letter occurs somewhere in the corpus
        assert out["verification_status"] != "VERIFIED_FIXED"
        assert out["concerns"][0]["consequence"] == "UNRESOLVED"
        assert "Deploy After Validation" not in _report_for(tmp_path, out)

    def test_full_line_citations_still_verify(self, tmp_path):
        out = _challenge(_REAL_QUOTES)
        assert out["verification_status"] == "VERIFIED_FIXED"
        assert "Deploy After Validation" in _report_for(tmp_path, out)

    def test_two_char_keyword_is_not_a_citation(self):
        assert _point_citation_valid("if", "if x:\n    pass") is False

    def test_whitespace_padded_short_quote_is_not_a_citation(self):
        assert _point_citation_valid(" d ", "def read_file(name):") is False
        assert _point_citation_valid("`a b`", "a b c") is False  # 2 non-whitespace chars

    def test_three_char_identifier_is_still_a_citation(self):
        assert _point_citation_valid("ctx", "def run(ctx):") is True


# ---------------------------------------------------------------------------
# Stage 2 / B. A target is "covered" only once its own source block was
#    actually rendered into the Final-Target Slice.
# ---------------------------------------------------------------------------

from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer  # noqa: E402
from utilities.agentic_enhancer.repository_index import RepositoryIndex  # noqa: E402
from utilities.autopatcher.candidate_enrichment import InvestigationContext  # noqa: E402

_METHOD_TARGET = "pkg/mod.py:Cls.meth"


def _large_method_fixture(tmp_path):
    body = ["    def meth(self, x):"]
    body += [f"        y{i} = x + {i}  # filler line number {i} padding padding padding" for i in range(80)]
    body += ["        return x"]
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("class Cls:\n" + "\n".join(body) + "\n", encoding="utf-8")
    functions = {_METHOD_TARGET: {
        "name": "meth", "className": "Cls", "code": "\n".join(body), "startLine": 2, "endLine": len(body) + 1,
        "unitType": "method", "filePath": "pkg/mod.py",
    }}
    context = InvestigationContext(
        index=RepositoryIndex({"functions": functions}, repo_path=str(tmp_path)), call_graph={},
        reverse_call_graph={}, reachability=ReachabilityAnalyzer(functions, {}, set()), constants={},
    )
    strategy = rp_mod.RemediationStrategyResult(
        rendered="x", target_files=["pkg/mod.py"], target_symbols=[_METHOD_TARGET], warnings=[],
        extended_mechanism="Fix meth", required_edits=[], evaluated=True,
    )
    return strategy, context


def _slice_and_readiness(tmp_path, max_chars):
    strategy, context = _large_method_fixture(tmp_path)
    result = rp_mod.build_final_target_slice(strategy, tmp_path, context, max_chars=max_chars)
    readiness = rp_mod.check_edit_readiness(rp_mod.build_intended_edits(strategy, result), result)
    return result, readiness


class TestTargetCoveredOnlyWhenRendered:
    def test_control_fully_renderable_target_is_covered_and_ready(self, tmp_path):
        result, readiness = _slice_and_readiness(tmp_path, 100_000)
        assert _METHOD_TARGET in result.covered_target_symbols
        assert "Target definition" in result.rendered and "return x" in result.rendered
        assert readiness.edit_source_ready is True

    def test_target_whose_source_did_not_fit_is_not_covered(self, tmp_path):
        result, readiness = _slice_and_readiness(tmp_path, 3_000)
        assert "return x" not in result.rendered  # the method body was never rendered...
        assert _METHOD_TARGET not in result.covered_target_symbols  # ...so it is not covered
        assert result.coverage_complete is False
        assert result.edit_target_budget_exhausted is True
        assert readiness.edit_source_ready is False

    def test_nothing_rendered_reports_uncovered(self, tmp_path):
        result, readiness = _slice_and_readiness(tmp_path, 1_000)
        assert _METHOD_TARGET in result.uncovered_target_symbols
        assert readiness.edit_source_ready is False

    def test_slice2_retry_does_not_mark_ready_without_source(self, tmp_path):
        strategy, context = _large_method_fixture(tmp_path)
        initial = rp_mod.build_final_target_slice(strategy, tmp_path, context, max_chars=1_000)
        intended = rp_mod.build_intended_edits(strategy, initial)
        acquisition = rp_mod.run_deterministic_acquisition(
            strategy, tmp_path, context, initial, rp_mod.check_edit_readiness(intended, initial),
        )
        final = acquisition.slice_result
        ready = rp_mod.check_edit_readiness(intended, final).edit_source_ready
        assert ready == ("return x" in final.rendered)  # ready if, and only if, the source is there


# ---------------------------------------------------------------------------
# Stage 2 / C. A class-qualified constant target verifies only against that
#    class's constant -- never another class's, never a module-level one.
# ---------------------------------------------------------------------------

def _const(name, class_name, line):
    qualified = f"{class_name}.{name}" if class_name else name
    return qualified, {"qualified_name": qualified, "class_name": class_name, "line": line, "end_line": line}


def _constants_context(tmp_path, files):
    """`files`: {path: [(name, class_name, line), ...]} -- the shape
    candidate_enrichment._extract_literal_constants produces."""
    constants = {}
    for path, entries in files.items():
        (tmp_path / path).write_text("\n" * 10, encoding="utf-8")
        constants[path] = dict(_const(*e) for e in entries)
    return InvestigationContext(
        index=RepositoryIndex({"functions": {}}, repo_path=str(tmp_path)), call_graph={},
        reverse_call_graph={}, reachability=ReachabilityAnalyzer({}, {}, set()), constants=constants,
    )


def _resolve(tmp_path, context, raw):
    return rp_mod._resolve_symbol_details(raw, tmp_path, context)


class TestQualifiedConstantMatchesItsOwnClass:
    def test_qualified_constant_rejects_other_class(self, tmp_path):
        ctx = _constants_context(tmp_path, {"a.py": [("DEFAULT", "Other", 2)]})
        assert _resolve(tmp_path, ctx, "Retry.DEFAULT") is None
        assert rp_mod._resolve_guided_symbol("Retry.DEFAULT", None, tmp_path, ctx)[0] is None

    def test_qualified_constant_prefers_matching_class_across_files(self, tmp_path):
        ctx = _constants_context(tmp_path, {"a.py": [("DEFAULT", "Other", 2)], "b.py": [("DEFAULT", "Retry", 3)]})
        match = _resolve(tmp_path, ctx, "Retry.DEFAULT")
        assert match is not None and match.file == "b.py" and match.line == 3

    def test_qualified_constant_same_file_picks_correct_class(self, tmp_path):
        ctx = _constants_context(tmp_path, {"c.py": [("DEFAULT", "A", 2), ("DEFAULT", "B", 6)]})
        match = _resolve(tmp_path, ctx, "c.py:B.DEFAULT")
        assert match is not None and match.line == 6

    def test_qualified_proposal_does_not_match_module_level_constant(self, tmp_path):
        ctx = _constants_context(tmp_path, {"m.py": [("DEFAULT", None, 1)]})
        assert _resolve(tmp_path, ctx, "Retry.DEFAULT") is None

    def test_guided_ambiguity_counts_only_matching_class(self, tmp_path):
        ctx = _constants_context(tmp_path, {"a.py": [("DEFAULT", "Other", 2)], "b.py": [("DEFAULT", "Retry", 3)]})
        match, reason = rp_mod._resolve_guided_symbol("Retry.DEFAULT", None, tmp_path, ctx)
        assert reason is None and match.file == "b.py"

    # -- controls: behavior that must not change --

    def test_correctly_qualified_constant_still_verifies(self, tmp_path):
        ctx = _constants_context(tmp_path, {"a.py": [("DEFAULT", "Other", 2)]})
        match = _resolve(tmp_path, ctx, "Other.DEFAULT")
        assert match is not None and match.file == "a.py"

    def test_module_constant_unqualified_still_verifies(self, tmp_path):
        ctx = _constants_context(tmp_path, {"m.py": [("DEFAULT", None, 1)]})
        match = _resolve(tmp_path, ctx, "m.py:DEFAULT")
        assert match is not None and match.file == "m.py"

    def test_bare_name_still_matches_class_constant(self, tmp_path):
        ctx = _constants_context(tmp_path, {"a.py": [("DEFAULT", "Other", 2)]})
        match = _resolve(tmp_path, ctx, "DEFAULT")
        assert match is not None and match.file == "a.py"

    def test_strategy_verification_fallback_does_not_reaccept_wrong_class(self, tmp_path):
        """The verified-files text fallback (Strategy verification path) must
        not re-accept the qualified target once the table lookup refused it."""
        ctx = _constants_context(tmp_path, {"a.py": [("DEFAULT", "Other", 2)]})
        (tmp_path / "a.py").write_text("class Other:\n    DEFAULT = 1\n", encoding="utf-8")
        assert rp_mod._resolve_symbol_details("Retry.DEFAULT", tmp_path, ctx, verified_files=["a.py"]) is None
        assert rp_mod._resolve_symbol_details("Other.DEFAULT", tmp_path, ctx, verified_files=["a.py"]) is not None


# ---------------------------------------------------------------------------
# Stage 2 / D. An untrusted repository's symlinks never expose host files:
#    not via the workspace copy, not via executor writes, not via evidence
#    sent to the LLM.
# ---------------------------------------------------------------------------

import os  # noqa: E402
import sys  # noqa: E402

import pytest  # noqa: E402

from utilities.autopatcher.patch_workspace import temporary_repo_copy  # noqa: E402
from utilities.autopatcher.test_evidence_acquisition import gather_test_plan_evidence  # noqa: E402

_posix_symlinks = pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
_SECRET = "FAKE_HOST_SECRET=hunter2"


def _host_and_repo(tmp_path):
    host = tmp_path / "host"
    host.mkdir()
    (host / "secret.txt").write_text(_SECRET + "\n", encoding="utf-8")
    (host / "keys").mkdir()
    (host / "keys" / "id_fake").write_text("FAKE_PRIVATE_KEY\n", encoding="utf-8")
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    return host, repo


def _all_text(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if not os.path.islink(p):
                out.append(Path(p).read_text(encoding="utf-8", errors="replace"))
    return "\n".join(out)


@_posix_symlinks
class TestWorkspaceCopyNeverDereferencesEscapingLinks:
    def test_absolute_symlink_outside_repo_is_dropped(self, tmp_path):
        host, repo = _host_and_repo(tmp_path)
        os.symlink(host / "secret.txt", repo / "leak.txt")
        with temporary_repo_copy(repo) as ws:
            assert not os.path.lexists(ws / "leak.txt")
            assert _SECRET not in _all_text(ws)

    def test_relative_escape_symlink_is_dropped(self, tmp_path):
        _, repo = _host_and_repo(tmp_path)
        os.symlink("../../host/secret.txt", repo / "src" / "leak.txt")  # repo/src -> tmp_path/host
        os.symlink("../host/secret.txt", repo / "leak2.txt")  # repo -> tmp_path/host
        with temporary_repo_copy(repo) as ws:
            assert not os.path.lexists(ws / "src" / "leak.txt")
            assert not os.path.lexists(ws / "leak2.txt")
            assert _SECRET not in _all_text(ws)

    def test_directory_symlink_outside_repo_is_dropped(self, tmp_path):
        host, repo = _host_and_repo(tmp_path)
        os.symlink(host / "keys", repo / "leakdir")
        with temporary_repo_copy(repo) as ws:
            assert not os.path.lexists(ws / "leakdir")
            assert "FAKE_PRIVATE_KEY" not in _all_text(ws)

    def test_dangling_symlink_does_not_raise(self, tmp_path):
        _, repo = _host_and_repo(tmp_path)
        os.symlink(repo / "does-not-exist", repo / "dangling")
        with temporary_repo_copy(repo) as ws:
            assert (ws / "src" / "app.py").is_file()

    def test_link_target_is_never_read_during_copy(self, tmp_path):
        """A link to a FIFO would block forever if the copy read the target."""
        _, repo = _host_and_repo(tmp_path)
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        os.symlink(fifo, repo / "pipe_link")
        with temporary_repo_copy(repo) as ws:
            assert not os.path.lexists(ws / "pipe_link")

    # -- controls --

    def test_in_repo_relative_symlink_is_preserved_as_a_link(self, tmp_path):
        _, repo = _host_and_repo(tmp_path)
        os.symlink("src/app.py", repo / "inrepo_link.py")
        with temporary_repo_copy(repo) as ws:
            link = ws / "inrepo_link.py"
            assert link.is_symlink()
            assert link.read_text(encoding="utf-8") == "print('hi')\n"

    def test_normal_files_copied_unchanged(self, tmp_path):
        _, repo = _host_and_repo(tmp_path)
        with temporary_repo_copy(repo) as ws:
            assert (ws / "src" / "app.py").read_bytes() == (repo / "src" / "app.py").read_bytes()
            assert (ws / ".git" / "HEAD").is_file()


@_posix_symlinks
class TestExecutorWritesNeverFollowSymlinks:
    def test_stage_build_context_does_not_write_through_symlink(self, tmp_path):
        from utilities.autopatcher import test_executors as executors_mod

        victim = tmp_path / "victim.txt"
        victim.write_text("ORIGINAL HOST CONTENT\n", encoding="utf-8")
        ws = tmp_path / "ws"
        ws.mkdir()
        for name in ("Dockerfile", ".dockerignore", ".openant_run_test.sh"):
            os.symlink(victim, ws / name)
        executors_mod._stage_build_context(ws, _TAP_PLAN, "node:20-slim")
        assert victim.read_text(encoding="utf-8") == "ORIGINAL HOST CONTENT\n"
        for name in ("Dockerfile", ".dockerignore", ".openant_run_test.sh"):
            assert not (ws / name).is_symlink() and (ws / name).is_file()
        assert "FROM" in (ws / "Dockerfile").read_text(encoding="utf-8")


@_posix_symlinks
class TestEvidenceReadsStayInsideTheRepository:
    def test_symlinked_config_readme_ci_and_github_dir_never_reach_the_prompt(self, tmp_path):
        host, repo = _host_and_repo(tmp_path)
        (host / "readme.md").write_text("# Testing\n\nREADME_HOST_SECRET\n", encoding="utf-8")
        (host / "pkg.json").write_text('{"scripts": {"test": "PKG_HOST_SECRET"}}', encoding="utf-8")
        (host / "gh" / "workflows").mkdir(parents=True)
        (host / "gh" / "workflows" / "ci.yml").write_text("run: pytest CI_HOST_SECRET\n", encoding="utf-8")
        os.symlink(host / "secret.txt", repo / "requirements.txt")
        os.symlink(host / "readme.md", repo / "README.md")
        os.symlink(host / "pkg.json", repo / "package.json")
        os.symlink(host / "gh", repo / ".github")  # a linked parent directory, not a linked file
        os.symlink(host / "keys", repo / "linked_dir")
        text = gather_test_plan_evidence(repo).to_prompt_text()
        for marker in (_SECRET, "README_HOST_SECRET", "PKG_HOST_SECRET", "CI_HOST_SECRET", "id_fake"):
            assert marker not in text

    def test_in_repo_symlinked_readme_is_still_read(self, tmp_path):
        _, repo = _host_and_repo(tmp_path)
        (repo / "docs").mkdir()
        (repo / "docs" / "README.md").write_text("# Testing\n\nrun pytest IN_REPO_MARKER\n", encoding="utf-8")
        os.symlink("docs/README.md", repo / "README.md")
        assert "IN_REPO_MARKER" in gather_test_plan_evidence(repo).to_prompt_text()


# ---------------------------------------------------------------------------
# Stage 2 / E. A multi-file git-format patch is not corrupted by hunk repair:
#    a "diff --git" line ends the current hunk, it is never a body line.
# ---------------------------------------------------------------------------

import subprocess  # noqa: E402

from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers  # noqa: E402
from utilities.autopatcher.generated_patch_processing import process_generated_patch  # noqa: E402

_GIT_TWO_FILES = (
    "diff --git a/a.py b/a.py\nindex 1111111..2222222 100644\n--- a/a.py\n+++ b/a.py\n"
    "@@ -1,2 +1,2 @@\n-x = 1\n+x = 10\n y = 2\n"
    "diff --git a/b.py b/b.py\nindex 3333333..4444444 100644\n--- a/b.py\n+++ b/b.py\n"
    "@@ -1,2 +1,2 @@\n-p = 1\n+p = 10\n q = 2\n"
)
_PLAIN_TWO_FILES = "".join(
    line + "\n" for line in _GIT_TWO_FILES.splitlines() if not line.startswith(("diff --git", "index "))
)
_GIT_ONE_FILE = _GIT_TWO_FILES.split("diff --git a/b.py")[0]


def _two_file_repo(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("p = 1\nq = 2\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    return tmp_path


class TestMultiFileGitFormatRepair:
    def test_repair_keeps_counts_and_never_absorbs_the_next_header(self, tmp_path):
        repaired, meta = repair_hunk_headers(_GIT_TWO_FILES, repo_root=_two_file_repo(tmp_path))
        assert meta.hunks_rewritten == 0
        assert repaired.count("@@ -1,2 +1,2 @@") == 2
        first_hunk = repaired.split("@@ -1,2 +1,2 @@", 1)[1].split("--- a/b.py", 1)[0]
        assert "diff --git" not in first_hunk and "index 3333333" not in first_hunk

    def test_multi_file_git_format_patch_is_applicable(self, tmp_path):
        repo = _two_file_repo(tmp_path)
        result = process_generated_patch("```diff\n" + _GIT_TWO_FILES + "```", repo, allow_context_reconstruction=True)
        assert result.applicability_result.get("applicable") is True

    def test_new_file_section_after_a_hunk_still_applies(self, tmp_path):
        repo = _two_file_repo(tmp_path)
        patch = _GIT_ONE_FILE + (
            "diff --git a/c.py b/c.py\nnew file mode 100644\nindex 0000000..5555555\n"
            "--- /dev/null\n+++ b/c.py\n@@ -0,0 +1 @@\n+z = 1\n"
        )
        result = process_generated_patch("```diff\n" + patch + "```", repo, allow_context_reconstruction=True)
        assert result.applicability_result.get("applicable") is True

    # -- controls --

    def test_plain_multi_file_output_is_unchanged(self, tmp_path):
        repaired, meta = repair_hunk_headers(_PLAIN_TWO_FILES, repo_root=_two_file_repo(tmp_path))
        assert repaired == _PLAIN_TWO_FILES and meta.hunks_rewritten == 0

    def test_single_file_git_format_is_unchanged(self, tmp_path):
        repaired, meta = repair_hunk_headers(_GIT_ONE_FILE, repo_root=_two_file_repo(tmp_path))
        assert repaired == _GIT_ONE_FILE and meta.hunks_rewritten == 0

    def test_repair_is_idempotent(self, tmp_path):
        repo = _two_file_repo(tmp_path)
        once, _ = repair_hunk_headers(_GIT_TWO_FILES, repo_root=repo)
        twice, meta = repair_hunk_headers(once, repo_root=repo)
        assert twice == once and meta.hunks_rewritten == 0


# ---------------------------------------------------------------------------
# Memo 1. Patch Target Conformance that crashes before completing never lets
#    an unchecked (or known non-conforming) patch continue.
# ---------------------------------------------------------------------------

from tests.patch.test_post_patch_recovery import TestSlice4PipelineIntegration as _Slice4  # noqa: E402

_CONFORMING = "--- a/mod.py\n+++ b/mod.py\n@@ -1,1 +1,1 @@\n-CONST_A = 1\n+CONST_A = 2\n"
_NONCONFORMING = "--- a/other.py\n+++ b/other.py\n@@ -1,1 +1,1 @@\n-X = 1\n+X = 2\n"


def _slice4_run(tmp_path, bad_patch, good_patch, **kwargs):
    result, _stages, _patches, _gen, _review, mock_challenge = _Slice4()._run(tmp_path, bad_patch, good_patch, **kwargs)
    return result, mock_challenge


class TestConformanceCrashWithdrawsThePatch:
    def test_control_conforming_patch_continues(self, tmp_path):
        result, mock_challenge = _slice4_run(tmp_path, _CONFORMING, _CONFORMING)
        assert result.patch.strip()
        assert result.patch_target_conformance.all_conformant is True
        assert mock_challenge.called

    def test_crash_in_conformance_check_withdraws_patch(self, tmp_path):
        with mock.patch("utilities.autopatcher.remediation_planner.check_patch_target_conformance",
                        side_effect=RuntimeError("conformance exploded")):
            result, mock_challenge = _slice4_run(tmp_path, _CONFORMING, _CONFORMING)
        assert not result.patch.strip()
        assert "Patch Target Conformance" in (result.applicability or {}).get("skipped_reason", "")
        assert not mock_challenge.called

    def test_crash_during_recovery_after_nonconformance_withdraws_patch(self, tmp_path):
        with mock.patch("utilities.autopatcher.remediation_planner.recover_post_patch_source",
                        side_effect=RuntimeError("recovery exploded")):
            result, mock_challenge = _slice4_run(tmp_path, _NONCONFORMING, _CONFORMING,
                                                 planning_target_files=["mod.py", "other.py"])
        assert "other.py" not in result.patch
        assert not result.patch.strip()
        assert "Patch Target Conformance" in (result.applicability or {}).get("skipped_reason", "")
        assert not mock_challenge.called


# ---------------------------------------------------------------------------
# Memo 2. A Final Strategy that was INVOKED but failed (raised, or returned
#    no usable result) never lets Patch Generation run without the gates
#    Strategy establishes. "Not invoked" keeps the State A contract.
# ---------------------------------------------------------------------------


class TestInvokedStrategyFailureFailsClosed:
    def _run(self, tmp_path, *, strategy_side_effect, evidence="evidence"):
        with (
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_plan",
                       return_value=_plan(target_files=["target.py"], target_symbols=["Target"])),
            mock.patch("utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
                       return_value=_evidence_result(evidence, ["target.py:Target"] if evidence else [])),
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                       side_effect=strategy_side_effect) as spy_strategy,
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw") as spy_patch_gen,
        ):
            report = pipeline_mod.run(vulnerability_text=_GAP_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        return report, spy_strategy, spy_patch_gen

    def test_strategy_crash_skips_patch_generation(self, tmp_path):
        report, spy_strategy, spy_patch_gen = self._run(tmp_path, strategy_side_effect=RuntimeError("strategy exploded"))
        spy_strategy.assert_called_once()
        spy_patch_gen.assert_not_called()
        assert "NO PATCH PRODUCED" in report
        assert "Final Remediation Strategy" in report

    def test_strategy_llm_returning_garbage_skips_patch_generation(self, tmp_path):
        """The real generate_remediation_strategy swallows an unparseable
        response into an unevaluated result -- invoked and failed."""
        real = rp_mod.generate_remediation_strategy

        def _garbage(vulnerability_text, llm, *args, **kwargs):
            return real(vulnerability_text, _FixedLLM("this is not json"), *args, **kwargs)

        report, spy_strategy, spy_patch_gen = self._run(tmp_path, strategy_side_effect=_garbage)
        spy_strategy.assert_called_once()
        spy_patch_gen.assert_not_called()
        assert "NO PATCH PRODUCED" in report
        assert "Final Remediation Strategy" in report

    def test_control_not_invoked_strategy_keeps_state_a(self):
        """No Planner evidence -> Strategy never invoked -> no failure reason,
        and the guided stage leaves Patch Generation unaffected (State A)."""
        assert pipeline_mod._strategy_invocation_failure("", rp_mod._EMPTY_STRATEGY_RESULT) is None
        assert pipeline_mod._strategy_invocation_failure("   ", None) is None
        result = pipeline_mod._run_guided_context_acquisition(
            vulnerability_text="v", llm=None, repo_root=None, budget_controller=None,
            _strategy_result=rp_mod._EMPTY_STRATEGY_RESULT, _plan_result=None, _investigation_context=None,
        )
        assert result["_skip_patch_generation"] is False

    def test_invoked_failure_is_distinguished_from_success(self):
        assert pipeline_mod._strategy_invocation_failure("evidence", rp_mod._EMPTY_STRATEGY_RESULT) is not None
        assert pipeline_mod._strategy_invocation_failure("evidence", None) is not None
        evaluated = _strategy(evaluated=True, target_files=["target.py"])
        assert pipeline_mod._strategy_invocation_failure("evidence", evaluated) is None

    def test_guided_stage_honors_a_recorded_failure(self):
        result = pipeline_mod._run_guided_context_acquisition(
            vulnerability_text="v", llm=None, repo_root=None, budget_controller=None,
            _strategy_result=rp_mod._EMPTY_STRATEGY_RESULT, _plan_result=None, _investigation_context=None,
            _strategy_failure_reason="Final Remediation Strategy was invoked but failed",
        )
        assert result["_skip_patch_generation"] is True
        assert "Final Remediation Strategy" in result["_skip_patch_generation_reason"]


# ---------------------------------------------------------------------------
# Memo 3. Only a TAP stream with a valid top-level plan is positive test
#    evidence; a planless stream never yields PASS.
# ---------------------------------------------------------------------------

from utilities.autopatcher.tap_parser import tap_stream_incomplete  # noqa: E402

_PLANLESS_ALL_OK = "TAP version 13\nok 1 - a\nok 2 - b\n"
_NODE_TEST_STYLE = (
    "TAP version 13\n"
    "# Subtest: math\n"
    "    ok 1 - adds\n"
    "    ok 2 - subtracts\n"
    "    1..2\n"
    "ok 1 - math\n"
    "  ---\n"
    "  duration_ms: 1.2\n"
    "  ...\n"
    "1..1\n"
    "# tests 2\n"
    "# pass 2\n"
)


class TestPlanlessTapIsNotPositiveEvidence:
    def test_planless_stream_is_incomplete(self):
        assert parse_tap(_PLANLESS_ALL_OK) is None
        assert tap_stream_incomplete(_PLANLESS_ALL_OK) is True

    def test_planless_clean_runs_are_not_pass(self):
        _, patched, result = _compare(_TAP_PLAN, _raw(stdout=_PLANLESS_ALL_OK), _raw(stdout=_PLANLESS_ALL_OK))
        assert patched.evidence_level == "UNAVAILABLE"
        assert result.status != etr.STATUS_PASS

    def test_both_runs_crashing_without_a_plan_is_not_pass(self):
        """Baseline and patched both die part-way (non-zero exit, no plan):
        the exit-code check cannot fire, and the streams show no failure."""
        b = "TAP version 13\nok 1 - a\nok 2 - b\nok 3 - c\n"
        p = "TAP version 13\nok 1 - a\n"
        _, _, result = _compare(_TAP_PLAN, _raw(stdout=b, exit_code=1), _raw(stdout=p, exit_code=1))
        assert result.status != etr.STATUS_PASS

    # -- controls: mainstream TAP keeps working --

    def test_plan_first_and_plan_last_streams_still_parse(self):
        assert parse_tap("TAP version 13\n1..2\nok 1 - a\nok 2 - b\n").passed == 2
        assert parse_tap("TAP version 13\nok 1 - a\nok 2 - b\n1..2\n").passed == 2

    def test_node_test_runner_shape_still_parses_and_passes(self):
        parsed = parse_tap(_NODE_TEST_STYLE)
        assert parsed is not None and parsed.passed == 2 and parsed.failed_test_ids == []
        _, _, result = _compare(_TAP_PLAN, _raw(stdout=_NODE_TEST_STYLE), _raw(stdout=_NODE_TEST_STYLE))
        assert result.status == etr.STATUS_PASS

    def test_non_tap_output_keeps_the_documented_exit_code_fallback(self):
        assert tap_stream_incomplete("segfault in libfoo\n") is False


# ---------------------------------------------------------------------------
# Planning failure. A Planning stage that RAISES never lets Patch Generation
#    proceed -- the same planning_ungrounded outcome an empty/ungrounded plan
#    already gets.
# ---------------------------------------------------------------------------


class TestPlanningFailureFailsClosed:
    def _run(self, tmp_path, *, plan=None, plan_side_effect=None, evidence_side_effect=None):
        plan_patch = (mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_plan",
                                 side_effect=plan_side_effect) if plan_side_effect is not None else
                      mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_plan",
                                 return_value=plan))
        evidence_patch = mock.patch(
            "utilities.autopatcher.remediation_planner.build_planner_evidence_with_budget",
            **({"side_effect": evidence_side_effect} if evidence_side_effect is not None
               else {"return_value": _evidence_result("evidence", ["target.py:Target"])}),
        )
        with plan_patch, evidence_patch, \
                mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                           return_value=_strategy(evaluated=True, target_files=["target.py"],
                                                  target_symbols=["Target"])) as spy_strategy, \
                mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value="") as spy_patch_gen:
            report = pipeline_mod.run(vulnerability_text=_GAP_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        return report, spy_strategy, spy_patch_gen

    def test_planner_raising_never_reaches_patch_generation(self, tmp_path):
        report, spy_strategy, spy_patch_gen = self._run(tmp_path, plan_side_effect=RuntimeError("planner exploded"))
        spy_strategy.assert_not_called()
        spy_patch_gen.assert_not_called()
        assert "NO PATCH PRODUCED" in report
        assert "could not be grounded" in report

    def test_planner_evidence_raising_never_reaches_patch_generation(self, tmp_path):
        report, spy_strategy, spy_patch_gen = self._run(
            tmp_path, plan=_plan(target_files=["target.py"], target_symbols=["Target"]),
            evidence_side_effect=RuntimeError("evidence exploded"),
        )
        spy_strategy.assert_not_called()
        spy_patch_gen.assert_not_called()
        assert "NO PATCH PRODUCED" in report
        assert "could not be grounded" in report

    # -- controls --

    def test_control_grounded_plan_still_reaches_strategy(self, tmp_path):
        _report, spy_strategy, _spy_patch_gen = self._run(
            tmp_path, plan=_plan(target_files=["target.py"], target_symbols=["Target"]),
        )
        spy_strategy.assert_called()

    def test_control_empty_plan_keeps_its_existing_skip(self, tmp_path):
        report, spy_strategy, spy_patch_gen = self._run(tmp_path, plan=rp_mod._EMPTY_PLAN_RESULT)
        spy_strategy.assert_not_called()
        spy_patch_gen.assert_not_called()
        assert "could not be grounded" in report
