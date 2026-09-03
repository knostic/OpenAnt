"""Tests for Existing Test Amendment -- the bounded S11 feedback mechanism
(existing_test_amendment.py): deterministic node-id-to-file grounding, the
tightened LLM judgment contract (AMENDMENT_JUSTIFIED/NO_AMENDMENT_JUSTIFIED),
deterministic scope/disjointness/applicability validation, and the shared
bounded rerun orchestrator both pipeline.py and replay_engine.py call.

Docker is never invoked here -- the orchestrator's own two
evaluate_existing_test_comparison_with_plan() calls go through the SAME
executor-mocking pattern test_existing_test_regression.py uses.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

import utilities.autopatcher.existing_test_amendment as eta
from utilities.autopatcher.existing_test_regression import (
    STATUS_NEW_FAILURES_DETECTED,
    STATUS_NOT_VERIFIED,
    STATUS_PASS,
    STATUS_PRE_EXISTING_FAILURES_ONLY,
    ExistingTestComparisonResult,
    TestRunResult,
)
from utilities.autopatcher.test_execution_models import TestExecutionPlan, TestExecutionResult

_PROD_PATCH = """\
--- a/src/util.py
+++ b/src/util.py
@@ -1,2 +1,3 @@
 def util():
+    # security fix
     return 1
"""

_SECURITY_INVARIANT = "a cross-origin redirect must not forward the Cookie header"


def _make_git_repo(root: Path, test_file="test/test_retry.py", test_source="def test_x():\n    assert True\n"):
    subprocess.run(["git", "init"], cwd=root, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=root, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=root, capture_output=True)
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "util.py").write_text("def util():\n    return 1\n", encoding="utf-8")
    test_path = root / test_file
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_text(test_source, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=root, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=root, capture_output=True, check=True)
    return root


class _FakeLLM:
    def __init__(self, response: str):
        self.response = response
        self.calls: "list[dict]" = []

    def complete(self, system_prompt, user_message, stage="unknown"):
        self.calls.append({"stage": stage, "system_prompt": system_prompt, "user_message": user_message})
        return self.response


def _amendment_json(*, diff=None, decision="AMENDMENT_JUSTIFIED", reason="contradiction found"):
    body = {"decision": decision, "reason": reason}
    if diff is not None:
        body["diff"] = diff
    return json.dumps(body)


_VALID_TEST_DIFF = """\
--- a/test/test_retry.py
+++ b/test/test_retry.py
@@ -1,2 +1,2 @@
 def test_x():
-    assert True
+    assert False
"""


# ---------------------------------------------------------------------------
# Grounding
# ---------------------------------------------------------------------------

class TestGroundNodeIdToFile:
    def test_valid_pytest_node_id_grounds(self, tmp_path):
        _make_git_repo(tmp_path)
        assert eta._ground_node_id_to_file("test/test_retry.py::TestRetry::test_x", tmp_path) == "test/test_retry.py"

    def test_no_double_colon_is_not_grounded(self, tmp_path):
        _make_git_repo(tmp_path)
        assert eta._ground_node_id_to_file("not_a_node_id", tmp_path) is None

    def test_nonexistent_file_is_not_grounded(self, tmp_path):
        _make_git_repo(tmp_path)
        assert eta._ground_node_id_to_file("test/does_not_exist.py::test_x", tmp_path) is None

    def test_path_traversal_is_rejected(self, tmp_path):
        _make_git_repo(tmp_path)
        assert eta._ground_node_id_to_file("../../etc/passwd::test_x", tmp_path) is None

    def test_absolute_path_prefix_is_rejected(self, tmp_path):
        _make_git_repo(tmp_path)
        assert eta._ground_node_id_to_file("/etc/passwd::test_x", tmp_path) is None

    def test_non_string_input_is_not_grounded(self, tmp_path):
        _make_git_repo(tmp_path)
        assert eta._ground_node_id_to_file(None, tmp_path) is None


class TestGroundNewlyFailingTests:
    def test_mixed_groundable_and_ungroundable(self, tmp_path):
        _make_git_repo(tmp_path)
        grounded, ungrounded = eta.ground_newly_failing_tests(
            ["test/test_retry.py::TestRetry::test_x", "some_opaque_id_123"], tmp_path,
        )
        assert grounded == {"test/test_retry.py::TestRetry::test_x": "test/test_retry.py"}
        assert ungrounded == ["some_opaque_id_123"]

    def test_all_ungroundable(self, tmp_path):
        _make_git_repo(tmp_path)
        grounded, ungrounded = eta.ground_newly_failing_tests(["opaque_1", "opaque_2"], tmp_path)
        assert grounded == {}
        assert ungrounded == ["opaque_1", "opaque_2"]


# ---------------------------------------------------------------------------
# Response parsing -- the tightened AMENDMENT_JUSTIFIED/NO_AMENDMENT_JUSTIFIED contract
# ---------------------------------------------------------------------------

class TestParseAmendmentResponse:
    def test_amendment_justified_with_diff(self):
        decision, reason, diff = eta._parse_amendment_response(_amendment_json(diff=_VALID_TEST_DIFF))
        assert decision == "AMENDMENT_JUSTIFIED"
        assert diff == _VALID_TEST_DIFF.strip() + "\n"  # trailing newline restored, see _parse_amendment_response

    def test_no_amendment_justified(self):
        decision, reason, diff = eta._parse_amendment_response(
            _amendment_json(decision="NO_AMENDMENT_JUSTIFIED", reason="no direct contradiction")
        )
        assert decision == "NO_AMENDMENT_JUSTIFIED"
        assert diff is None
        assert reason == "no direct contradiction"

    def test_amendment_justified_without_diff_is_unresolved(self):
        decision, reason, diff = eta._parse_amendment_response(
            json.dumps({"decision": "AMENDMENT_JUSTIFIED", "reason": "r"})
        )
        assert decision == "unresolved"
        assert diff is None

    def test_malformed_json_is_unresolved(self):
        decision, reason, diff = eta._parse_amendment_response("not json at all")
        assert decision == "unresolved"

    def test_unrecognized_decision_is_unresolved(self):
        decision, reason, diff = eta._parse_amendment_response(
            json.dumps({"decision": "MAYBE", "reason": "r"})
        )
        assert decision == "unresolved"

    def test_prose_wrapped_in_fence_is_stripped(self):
        fenced = "```json\n" + _amendment_json(diff=_VALID_TEST_DIFF) + "\n```"
        decision, reason, diff = eta._parse_amendment_response(fenced)
        assert decision == "AMENDMENT_JUSTIFIED"
        assert diff == _VALID_TEST_DIFF.strip() + "\n"  # trailing newline restored, see _parse_amendment_response


# ---------------------------------------------------------------------------
# Deterministic scope/disjointness validation -- constraint 4: original
# production patch preserved exactly; amendment files subset of grounded
# newly-failing test files; disjoint from production patch's own files.
# ---------------------------------------------------------------------------

class TestValidateAmendmentDiff:
    def test_valid_disjoint_subset_diff_passes(self):
        error = eta._validate_amendment_diff(
            _VALID_TEST_DIFF, original_patch_files={"src/util.py"}, grounded_files={"test/test_retry.py"},
        )
        assert error is None

    def test_diff_touching_production_file_is_rejected(self):
        bad_diff = _VALID_TEST_DIFF.replace("test/test_retry.py", "src/util.py")
        error = eta._validate_amendment_diff(
            bad_diff, original_patch_files={"src/util.py"}, grounded_files={"src/util.py"},
        )
        assert error is not None
        assert "already present in the production patch" in error

    def test_diff_touching_ungrounded_file_is_rejected(self):
        bad_diff = _VALID_TEST_DIFF.replace("test/test_retry.py", "test/test_unrelated.py")
        error = eta._validate_amendment_diff(
            bad_diff, original_patch_files={"src/util.py"}, grounded_files={"test/test_retry.py"},
        )
        assert error is not None
        assert "outside the grounded" in error

    def test_diff_with_no_recognizable_files_is_rejected(self):
        error = eta._validate_amendment_diff(
            "not a diff at all", original_patch_files={"src/util.py"}, grounded_files={"test/test_retry.py"},
        )
        assert error is not None

    def test_diff_touching_multiple_files_one_ungrounded_is_rejected(self):
        multi = _VALID_TEST_DIFF + "\n" + _VALID_TEST_DIFF.replace("test/test_retry.py", "test/test_other.py")
        error = eta._validate_amendment_diff(
            multi, original_patch_files={"src/util.py"}, grounded_files={"test/test_retry.py"},
        )
        assert error is not None


# ---------------------------------------------------------------------------
# attempt_existing_test_amendment -- the full gate + LLM call + validation
# ---------------------------------------------------------------------------

class TestAttemptExistingTestAmendment:
    def test_not_attempted_without_security_invariant(self, tmp_path):
        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=tmp_path, patch=_PROD_PATCH,
            newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
            security_invariant=None, llm=llm,
        )
        assert outcome.status == "not_attempted"
        assert llm.calls == []

    def test_not_attempted_with_no_newly_failing_tests(self, tmp_path):
        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=tmp_path, patch=_PROD_PATCH, newly_failing_tests=[],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "not_attempted"
        assert llm.calls == []

    def test_not_attempted_when_nothing_grounds(self, tmp_path):
        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=tmp_path, patch=_PROD_PATCH, newly_failing_tests=["opaque_id_with_no_colon"],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "not_attempted"
        assert outcome.ungrounded_ids == ("opaque_id_with_no_colon",)
        assert llm.calls == []

    def test_full_success_path_is_amended(self, tmp_path):
        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        with mock.patch.object(
            eta, "check_applicability", return_value={"applicable": True, "stderr": "", "error": None},
        ):
            outcome = eta.attempt_existing_test_amendment(
                repo_root=tmp_path, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert outcome.status == "amended"
        assert len(llm.calls) == 1
        assert llm.calls[0]["stage"] == "existing_test_amendment"
        assert _PROD_PATCH.strip() in outcome.amended_patch
        assert "test/test_retry.py" in outcome.amended_patch

    def test_absence_of_failure_diagnostics_does_not_block_amendment(self, tmp_path):
        """Constraint 1: failure_diagnostics is optional, additive evidence
        only -- its absence (the real urllib3 case: deterministic ids
        available, diagnostics null) must never by itself prevent an
        otherwise-justified amendment."""
        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        with mock.patch.object(
            eta, "check_applicability", return_value={"applicable": True, "stderr": "", "error": None},
        ):
            outcome = eta.attempt_existing_test_amendment(
                repo_root=tmp_path, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, failure_diagnostics=None, llm=llm,
            )
        assert outcome.status == "amended"

    def test_no_amendment_justified_produces_no_diff(self, tmp_path):
        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(decision="NO_AMENDMENT_JUSTIFIED", reason="no contradiction found"))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=tmp_path, patch=_PROD_PATCH,
            newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "no_amendment_justified"
        assert outcome.amended_patch is None

    def test_diff_touching_production_file_is_rejected_end_to_end(self, tmp_path):
        _make_git_repo(tmp_path)
        bad_diff = _VALID_TEST_DIFF.replace("test/test_retry.py", "src/util.py")
        llm = _FakeLLM(_amendment_json(diff=bad_diff))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=tmp_path, patch=_PROD_PATCH,
            newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "rejected_invalid_scope"
        assert outcome.amended_patch is None

    def test_inapplicable_amended_patch_is_rejected(self, tmp_path):
        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        with mock.patch.object(
            eta, "check_applicability", return_value={"applicable": False, "stderr": "patch does not apply", "error": None},
        ):
            outcome = eta.attempt_existing_test_amendment(
                repo_root=tmp_path, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert outcome.status == "rejected_inapplicable"
        assert outcome.amended_patch is None

    def test_llm_failure_degrades_to_unresolved(self, tmp_path):
        _make_git_repo(tmp_path)

        class _BrokenLLM:
            def complete(self, *a, **kw):
                raise RuntimeError("provider unavailable")

        outcome = eta.attempt_existing_test_amendment(
            repo_root=tmp_path, patch=_PROD_PATCH,
            newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
            security_invariant=_SECURITY_INVARIANT, llm=_BrokenLLM(),
        )
        assert outcome.status == "unresolved"


# ---------------------------------------------------------------------------
# evaluate_existing_test_comparison_with_amendment -- the bounded rerun
# orchestrator's own gate/accept/reject logic, isolated from Docker via
# mocking evaluate_existing_test_comparison_with_plan directly.
# ---------------------------------------------------------------------------

_A_PLAN = TestExecutionPlan(
    setup_commands=(), test_command=("python", "-m", "pytest"),
    result_strategy="exit_code", result_output_path=None,
    runtime_family="python", runtime_version_hint=None,
    evidence=(), reasoning_summary="r", confidence="high",
)


def _result(status, **kw):
    return ExistingTestComparisonResult(status=status, command=_A_PLAN.test_command, baseline=None, patched=None, reason="r", **kw)


class TestEvaluateExistingTestComparisonWithAmendment:
    def test_pass_never_attempts_amendment(self, tmp_path):
        with mock.patch.object(eta, "evaluate_existing_test_comparison_with_plan", return_value=_result(STATUS_PASS)):
            outcome = eta.evaluate_existing_test_comparison_with_amendment(
                tmp_path, _PROD_PATCH, _A_PLAN, security_invariant=_SECURITY_INVARIANT, llm=_FakeLLM("unused"),
            )
        assert outcome.accepted is False
        assert outcome.amendment.status == "not_attempted"
        assert outcome.patch == _PROD_PATCH
        assert outcome.result.status == STATUS_PASS

    def test_no_llm_never_attempts_amendment(self, tmp_path):
        r1 = _result(STATUS_NEW_FAILURES_DETECTED, newly_failing_tests=["test/test_retry.py::TestRetry::test_x"])
        with mock.patch.object(eta, "evaluate_existing_test_comparison_with_plan", return_value=r1):
            outcome = eta.evaluate_existing_test_comparison_with_amendment(
                tmp_path, _PROD_PATCH, _A_PLAN, security_invariant=_SECURITY_INVARIANT, llm=None,
            )
        assert outcome.accepted is False
        assert outcome.amendment.status == "not_attempted"

    def test_accepted_when_rerun_is_pre_existing_only(self, tmp_path):
        _make_git_repo(tmp_path)
        r1 = _result(STATUS_NEW_FAILURES_DETECTED, newly_failing_tests=["test/test_retry.py::TestRetry::test_x"])
        r2 = _result(STATUS_PRE_EXISTING_FAILURES_ONLY)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        with (
            mock.patch.object(eta, "evaluate_existing_test_comparison_with_plan", side_effect=[r1, r2]),
            mock.patch.object(eta, "check_applicability", return_value={"applicable": True, "stderr": "", "error": None}),
        ):
            outcome = eta.evaluate_existing_test_comparison_with_amendment(
                tmp_path, _PROD_PATCH, _A_PLAN, security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert outcome.accepted is True
        assert outcome.result is r2
        assert outcome.patch != _PROD_PATCH
        assert outcome.pre_amendment_result is r1

    def test_rejected_when_rerun_still_shows_newly_failing(self, tmp_path):
        """Exactly one attempt: rerun still failing rejects the amendment
        outright and restores the ORIGINAL patch/result -- no retry."""
        _make_git_repo(tmp_path)
        r1 = _result(STATUS_NEW_FAILURES_DETECTED, newly_failing_tests=["test/test_retry.py::TestRetry::test_x"])
        r2 = _result(STATUS_NEW_FAILURES_DETECTED, newly_failing_tests=["test/test_retry.py::TestRetry::test_x"])
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        with (
            mock.patch.object(eta, "evaluate_existing_test_comparison_with_plan", side_effect=[r1, r2]),
            mock.patch.object(eta, "check_applicability", return_value={"applicable": True, "stderr": "", "error": None}),
        ):
            outcome = eta.evaluate_existing_test_comparison_with_amendment(
                tmp_path, _PROD_PATCH, _A_PLAN, security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert outcome.accepted is False
        assert outcome.patch == _PROD_PATCH
        assert outcome.result is r1
        # Exactly one amendment call, exactly two comparator calls -- no retry loop.
        assert len(llm.calls) == 1

    def test_no_amendment_justified_leaves_r1_canonical(self, tmp_path):
        _make_git_repo(tmp_path)
        r1 = _result(STATUS_NEW_FAILURES_DETECTED, newly_failing_tests=["test/test_retry.py::TestRetry::test_x"])
        llm = _FakeLLM(_amendment_json(decision="NO_AMENDMENT_JUSTIFIED", reason="no contradiction"))
        with mock.patch.object(eta, "evaluate_existing_test_comparison_with_plan", return_value=r1) as mock_eval:
            outcome = eta.evaluate_existing_test_comparison_with_amendment(
                tmp_path, _PROD_PATCH, _A_PLAN, security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert outcome.accepted is False
        assert outcome.result is r1
        assert outcome.patch == _PROD_PATCH
        assert mock_eval.call_count == 1  # never reran -- no amendment was produced to rerun with


# ---------------------------------------------------------------------------
# Full urllib3-shaped acceptance scenario -- end to end through the REAL
# evaluate_existing_test_comparison_with_plan (Docker mocked via the same
# executor-mocking pattern test_existing_test_regression.py uses), proving
# the mechanism works generically (never urllib3-special-cased): a
# production patch changes behavior, one existing test asserts the old
# behavior, the amendment is proposed/validated/applied, and the rerun
# shows the target test now passing while 102 unrelated pre-existing
# failures remain classified as pre-existing.
# ---------------------------------------------------------------------------

def _exec_result(exit_code=0, stdout="", timed_out=False, setup_failed=False):
    return TestExecutionResult(
        ran=not timed_out and not setup_failed, exit_code=exit_code, timed_out=timed_out,
        setup_failed=setup_failed, setup_error="", stdout=stdout, stderr="",
        result_output=None, duration_seconds=1.0, executor="docker",
    )


def _ready_executor():
    executor = mock.MagicMock()
    executor.preflight.return_value = mock.MagicMock(ready=True, reason=None, status="OK")
    return executor


def _urllib3_shaped_stdout(*, failed, passed, extra_failed_id=None):
    lines = [f"FAILED test/with_dummyserver/test_socketlevel.py::TestHeaders::test_shared_{i}" for i in range(102)]
    if extra_failed_id:
        lines.append(f"FAILED {extra_failed_id}")
    lines.append(f"==== {failed} failed, {passed} passed, 563 skipped in 65.0s ====")
    return "\n".join(lines) + "\n"


class TestUrllib3ShapedAmendmentAcceptanceScenario:
    def test_stale_test_amendment_accepted_pre_existing_failures_preserved(self, tmp_path):
        repo = _make_git_repo(
            tmp_path, test_file="test/test_retry.py",
            test_source="class TestRetry:\n    def test_retry_default_remove_headers_on_redirect(self):\n        assert True\n",
        )
        _EXIT_CODE_PLAN = TestExecutionPlan(
            setup_commands=(), test_command=("nox", "-s", "test"), result_strategy="exit_code",
            result_output_path=None, runtime_family="python", runtime_version_hint=None,
            evidence=("noxfile.py",), reasoning_summary="r", confidence="medium",
        )
        target_id = "test/test_retry.py::TestRetry::test_retry_default_remove_headers_on_redirect"
        baseline_stdout = _urllib3_shaped_stdout(failed=102, passed=1640)
        patched_stdout_r1 = _urllib3_shaped_stdout(failed=103, passed=1639, extra_failed_id=target_id)
        # R2 (post-amendment): the target test no longer fails; the same
        # 102 unrelated pre-existing failures remain.
        patched_stdout_r2 = _urllib3_shaped_stdout(failed=102, passed=1640)

        executor = _ready_executor()
        executor.run.side_effect = [
            _exec_result(stdout=baseline_stdout, exit_code=1),   # R1 baseline
            _exec_result(stdout=patched_stdout_r1, exit_code=1),  # R1 patched
            _exec_result(stdout=baseline_stdout, exit_code=1),   # R2 baseline (rerun, unchanged by design)
            _exec_result(stdout=patched_stdout_r2, exit_code=1),  # R2 patched
        ]

        amendment_diff = (
            "--- a/test/test_retry.py\n"
            "+++ b/test/test_retry.py\n"
            "@@ -1,3 +1,3 @@\n"
            " class TestRetry:\n"
            "     def test_retry_default_remove_headers_on_redirect(self):\n"
            "-        assert True\n"
            "+        assert True  # Cookie now intentionally forwarded per security_invariant\n"
        )
        llm = _FakeLLM(_amendment_json(diff=amendment_diff, reason=f"contradicts: {_SECURITY_INVARIANT}"))

        with mock.patch.object(
            eta, "check_applicability", return_value={"applicable": True, "stderr": "", "error": None},
        ):
            outcome = eta.evaluate_existing_test_comparison_with_amendment(
                repo, _PROD_PATCH, _EXIT_CODE_PLAN,
                security_invariant=_SECURITY_INVARIANT, executor=executor, llm=llm,
            )

        # A: original candidate changes production behavior -- given (_PROD_PATCH).
        # B/C: S11 detected the stale test and the amendment mechanism recognized it.
        assert len(llm.calls) == 1
        assert llm.calls[0]["stage"] == "existing_test_amendment"
        # D: candidate patch amended to include the test update.
        assert outcome.amendment.status == "amended"
        assert "test/test_retry.py" in outcome.amendment.amended_patch
        assert _PROD_PATCH.strip() in outcome.amendment.amended_patch
        # E/F: rerun shows the target test no longer newly failing.
        assert outcome.accepted is True
        assert outcome.result.status == STATUS_PRE_EXISTING_FAILURES_ONLY
        assert outcome.result.newly_failing_tests == []
        # G: the 102 unrelated pre-existing failures remain classified as pre-existing.
        assert len(outcome.result.pre_existing_failures) == 102
        assert target_id not in outcome.result.pre_existing_failures
        # H: amended patch is now authoritative.
        assert outcome.patch == outcome.amendment.amended_patch
        assert outcome.pre_amendment_result.status == STATUS_NEW_FAILURES_DETECTED
        assert outcome.pre_amendment_result.newly_failing_tests == [target_id]


# ---------------------------------------------------------------------------
# Pre-scope / post-scope validation gate (mandatory correction: scope MUST
# be validated before any repository-aware repair/relocation ever runs).
# ---------------------------------------------------------------------------

class TestPreScopeValidationBeforeRepair:
    """The shared generated-diff processor (repair_hunk_headers/content
    relocation) must never even be invoked for a response that is already,
    deterministically, out of scope -- proven by spying on
    generated_patch_processing.process_generated_patch directly (the
    lazily-imported, real call site), not merely by checking the final
    outcome."""

    def test_out_of_scope_file_rejected_before_shared_processor_runs(self, tmp_path):
        _make_git_repo(tmp_path)
        bad_diff = _VALID_TEST_DIFF.replace("test/test_retry.py", "test/test_unrelated.py")
        llm = _FakeLLM(_amendment_json(diff=bad_diff))
        with mock.patch(
            "utilities.autopatcher.generated_patch_processing.process_generated_patch"
        ) as mock_process:
            outcome = eta.attempt_existing_test_amendment(
                repo_root=tmp_path, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert outcome.status == "rejected_invalid_scope"
        assert "pre-repair" in outcome.reason
        mock_process.assert_not_called()

    def test_production_file_overlap_rejected_before_shared_processor_runs(self, tmp_path):
        _make_git_repo(tmp_path)
        bad_diff = _VALID_TEST_DIFF.replace("test/test_retry.py", "src/util.py")
        llm = _FakeLLM(_amendment_json(diff=bad_diff))
        with mock.patch(
            "utilities.autopatcher.generated_patch_processing.process_generated_patch"
        ) as mock_process:
            outcome = eta.attempt_existing_test_amendment(
                repo_root=tmp_path, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert outcome.status == "rejected_invalid_scope"
        assert "pre-repair" in outcome.reason
        mock_process.assert_not_called()

    def test_path_traversal_rejected_before_shared_processor_runs(self, tmp_path):
        _make_git_repo(tmp_path)
        traversal_diff = "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1,1 +1,1 @@\n-a\n+b\n"
        llm = _FakeLLM(_amendment_json(diff=traversal_diff))
        with mock.patch(
            "utilities.autopatcher.generated_patch_processing.process_generated_patch"
        ) as mock_process:
            outcome = eta.attempt_existing_test_amendment(
                repo_root=tmp_path, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert outcome.status == "rejected_invalid_scope"
        assert "unsafe" in outcome.reason
        mock_process.assert_not_called()

    def test_in_scope_diff_does_reach_shared_processor(self, tmp_path):
        """Sanity converse: a genuinely in-scope diff DOES reach the
        shared processor -- proves the pre-scope gate isn't simply
        rejecting everything."""
        import utilities.autopatcher.generated_patch_processing as gpp

        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        with mock.patch(
            "utilities.autopatcher.generated_patch_processing.process_generated_patch",
            wraps=gpp.process_generated_patch,
        ) as mock_process:
            eta.attempt_existing_test_amendment(
                repo_root=tmp_path, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        mock_process.assert_called_once()


class TestPostScopeValidation:
    def test_processor_widening_scope_is_rejected(self, tmp_path):
        """Defense in depth: even though repair_hunk_headers's own
        contract already guarantees it never widens/moves a file's
        hunks to a different file, this is verified independently here,
        never merely assumed -- simulated via a stand-in ProcessedPatch
        whose patch text widens the file set beyond what pre-scope
        validated."""
        from utilities.autopatcher.diff_hunk_repair import RepairResult
        from utilities.autopatcher.generated_patch_processing import ProcessedPatch

        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        widened = _VALID_TEST_DIFF + "\n" + _VALID_TEST_DIFF.replace("test/test_retry.py", "test/test_other.py")
        fake_processed = ProcessedPatch(
            patch=widened, repair_result=RepairResult(), hygiene_findings=[],
            applicability_result={"applicable": True, "stderr": "", "error": None},
        )
        with mock.patch(
            "utilities.autopatcher.generated_patch_processing.process_generated_patch",
            return_value=fake_processed,
        ) as mock_process:
            outcome = eta.attempt_existing_test_amendment(
                repo_root=tmp_path, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert mock_process.called
        assert outcome.status == "rejected_invalid_scope"
        assert "post-repair" in outcome.reason


# ---------------------------------------------------------------------------
# Real hunk-repair/relocation/reconstruction machinery, reused (never
# reimplemented), exercised end to end through
# attempt_existing_test_amendment -- fixture SHAPES reused directly from
# test_context_reconstruction.py's own proven urllib3/thin-context/
# ambiguous cases (adapted to a test-file amendment target instead of
# retry.py itself), never re-deriving the underlying mechanism's own
# exhaustive coverage.
# ---------------------------------------------------------------------------

def _urllib3_shaped_test_source() -> str:
    """Same shape as test_context_reconstruction.py's _urllib3_retry_py:
    the real target line sits at 1-indexed line 188, deep enough that a
    hunk claiming line 187 is a realistic 'drifted by one' defect, not an
    artificially tiny fixture."""
    lines = [f"# filler line {i}\n" for i in range(1, 187)]
    lines.append("\n")  # line 187
    lines.append("    def test_retry_default_remove_headers_on_redirect(self):\n")  # 188
    lines.append('        assert DEFAULT_REMOVE_HEADERS_ON_REDIRECT == frozenset(["Authorization"])\n')  # 189
    lines.append("\n")  # 190
    return "".join(lines)


# The exact real urllib3 CVE-2023-43804 malformed shape (claimed old/new
# count of 3 for a body that is actually 2/2, at a start line drifted by
# one from the content's real position) -- see test_context_reconstruction.
# py's _URLLIB3_MALFORMED, reused here verbatim except for the file path.
_MALFORMED_AMENDMENT_DIFF = (
    "--- a/test/test_retry.py\n"
    "+++ b/test/test_retry.py\n"
    "@@ -187,3 +187,3 @@\n"
    "     def test_retry_default_remove_headers_on_redirect(self):\n"
    '-        assert DEFAULT_REMOVE_HEADERS_ON_REDIRECT == frozenset(["Authorization"])\n'
    '+        assert DEFAULT_REMOVE_HEADERS_ON_REDIRECT == frozenset(["Cookie", "Authorization"])\n'
)


class TestUrllib3ShapedMalformedHunkHeaderRepaired:
    """The real urllib3-shaped defect (this feature's own motivating
    replay failure): a mechanically wrong hunk header AND a drifted old-
    side position, both in the SAME hunk -- repaired and reconstructed by
    the shared primitive, never a local implementation in
    existing_test_amendment.py."""

    def test_malformed_amendment_is_mechanically_repaired_and_amended(self, tmp_path):
        repo = _make_git_repo(tmp_path, test_file="test/test_retry.py", test_source=_urllib3_shaped_test_source())
        llm = _FakeLLM(_amendment_json(diff=_MALFORMED_AMENDMENT_DIFF))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=repo, patch=_PROD_PATCH,
            newly_failing_tests=["test/test_retry.py::TestRetry::test_retry_default_remove_headers_on_redirect"],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "amended"
        assert outcome.amended_patch is not None
        # The LLM's original, mechanically wrong header must be gone --
        # replaced by whatever the shared primitive's repair/relocation/
        # (possibly further) context-reconstruction settled on. The exact
        # resulting header depends on how much surrounding context this
        # specific fixture also needed beyond relocation alone (that
        # downstream behavior already has its own exhaustive coverage in
        # test_context_reconstruction.py) -- this test's own job is only
        # to prove the malformed header never survives, and the correct
        # semantic change lands.
        assert "@@ -187,3 +187,3 @@" not in outcome.amended_patch
        assert 'assert DEFAULT_REMOVE_HEADERS_ON_REDIRECT == frozenset(["Cookie", "Authorization"])' in outcome.amended_patch


class TestStaleLineCoordinateRelocatesThroughSharedMachinery:
    """Isolates PURE content relocation (correct hunk counts from the
    start; only the claimed position is wrong) from the header-count
    defect above -- same isolation strategy as test_context_reconstruction.
    py's own TestThinContextOnly class."""

    def _repo(self, tmp_path):
        lines = [f"filler_{i}\n" for i in range(1, 11)]  # lines 1-10
        lines += ["context_before\n", "target_value = 1\n", "context_after\n"]  # 11,12,13
        lines += [f"filler_{i}\n" for i in range(14, 20)]
        return _make_git_repo(tmp_path, test_file="test/test_reloc.py", test_source="".join(lines))

    def test_drifted_position_relocates_and_amends(self, tmp_path):
        repo = self._repo(tmp_path)
        # Correct counts (3 old, 3 new) but a wrong claimed start (5, real
        # content is at 11) -- isolates relocation from count repair.
        diff = (
            "--- a/test/test_reloc.py\n+++ b/test/test_reloc.py\n@@ -5,3 +5,3 @@\n"
            " context_before\n-target_value = 1\n+target_value = 2\n context_after\n"
        )
        llm = _FakeLLM(_amendment_json(diff=diff))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=repo, patch=_PROD_PATCH, newly_failing_tests=["test/test_reloc.py::test_target"],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "amended"
        assert "@@ -11,3 +11,3 @@" in outcome.amended_patch  # relocated from the claimed 5 to the real 11
        assert "@@ -5,3 +5,3 @@" not in outcome.amended_patch


class TestContextStarvedAmendmentUsesExistingReconstruction:
    """Isolates context-thinness ALONE -- same fixture shape as
    test_context_reconstruction.py's TestThinContextOnly: correct position
    and counts from the start, only missing trailing context."""

    def _repo(self, tmp_path):
        lines = [f"line {i}\n" for i in range(1, 60)]
        lines[29] = "target_value = 1\n"  # 1-indexed line 30
        return _make_git_repo(tmp_path, test_file="test/test_thin.py", test_source="".join(lines))

    def test_one_sided_context_is_reconstructed_and_amends(self, tmp_path):
        repo = self._repo(tmp_path)
        diff = (
            "--- a/test/test_thin.py\n+++ b/test/test_thin.py\n@@ -29,2 +29,2 @@\n"
            " line 29\n-target_value = 1\n+target_value = 2\n"
        )
        llm = _FakeLLM(_amendment_json(diff=diff))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=repo, patch=_PROD_PATCH, newly_failing_tests=["test/test_thin.py::test_target"],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "amended"
        # Reconstruction adds trailing context -- the amended patch's hunk
        # body is now longer than the LLM's original one-sided version.
        assert "target_value = 2" in outcome.amended_patch


class TestAmbiguousRelocationFailsClosed:
    """Same fixture shape as test_context_reconstruction.py's
    TestAmbiguousMatch: the old-side content occurs twice in the file, so
    neither relocation nor context reconstruction may safely resolve it --
    the amendment must fail closed (rejected_inapplicable), never guess."""

    def _repo(self, tmp_path):
        block = ["context\n", "dup_line\n"]
        lines = block + [f"filler{i}\n" for i in range(1, 10)] + block
        return _make_git_repo(tmp_path, test_file="test/test_ambig.py", test_source="".join(lines))

    def test_ambiguous_anchor_fails_closed(self, tmp_path):
        repo = self._repo(tmp_path)
        diff = "--- a/test/test_ambig.py\n+++ b/test/test_ambig.py\n@@ -1,2 +1,2 @@\n context\n-dup_line\n+new_line\n"
        llm = _FakeLLM(_amendment_json(diff=diff))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=repo, patch=_PROD_PATCH, newly_failing_tests=["test/test_ambig.py::test_target"],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "rejected_inapplicable"
        assert outcome.amended_patch is None


# ---------------------------------------------------------------------------
# Fence-safe composition (mandatory correction: the persisted S6 patch is
# markdown-fenced; naive concatenation leaves a stray fence line embedded
# mid-string, invisible to check_applicability's own edge-only stripping).
# ---------------------------------------------------------------------------

_PROD_PATCH_FENCED = "```diff\n" + _PROD_PATCH.rstrip("\n") + "\n```"


class TestFenceSafeComposition:
    def test_compose_amended_patch_strips_both_sides(self):
        combined = eta._compose_amended_patch(_PROD_PATCH_FENCED, _VALID_TEST_DIFF)
        assert "```" not in combined
        assert combined.count("--- a/") == 2

    def test_compose_amended_patch_is_noop_safe_on_unfenced_input(self):
        combined = eta._compose_amended_patch(_PROD_PATCH, _VALID_TEST_DIFF)
        assert "```" not in combined
        assert combined.count("--- a/") == 2

    def test_fenced_production_plus_raw_amendment_amends_end_to_end(self, tmp_path):
        """The real production shape: patch_generator.classify_patch_
        response always wraps a valid response in a ```diff fence -- so
        the FENCED shape, not the unfenced test constant, is what
        production actually threads through this path."""
        repo = _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=repo, patch=_PROD_PATCH_FENCED,
            newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "amended"
        assert "```" not in outcome.amended_patch
        assert outcome.amended_patch.count("--- a/") == 2
        assert "src/util.py" in outcome.amended_patch
        assert "test/test_retry.py" in outcome.amended_patch


# ---------------------------------------------------------------------------
# Production patch semantic preservation (mandatory correction: NOT byte-
# for-byte string equality of the whole patch -- semantic_delta equality
# of the production files specifically, fence removal being the one
# allowed difference).
# ---------------------------------------------------------------------------

class TestProductionSemanticDeltaPreserved:
    def test_preserved_when_composition_only_strips_fences(self):
        combined = eta._compose_amended_patch(_PROD_PATCH_FENCED, _VALID_TEST_DIFF)
        assert eta._production_patch_semantic_delta_preserved(_PROD_PATCH_FENCED, combined, {"src/util.py"})

    def test_not_preserved_if_production_hunk_were_altered(self):
        """Defensive/negative case: if the production portion of the
        combined patch were ever altered (simulated directly here, not via
        any real code path -- no code path in this module is ever
        supposed to reach this), the check must correctly detect it."""
        combined = eta._compose_amended_patch(_PROD_PATCH_FENCED, _VALID_TEST_DIFF)
        tampered = combined.replace("# security fix", "# a different comment")
        assert not eta._production_patch_semantic_delta_preserved(_PROD_PATCH_FENCED, tampered, {"src/util.py"})

    def test_end_to_end_amendment_preserves_production_semantic_delta(self, tmp_path):
        from utilities.autopatcher.diff_parsing import semantic_delta

        repo = _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        outcome = eta.attempt_existing_test_amendment(
            repo_root=repo, patch=_PROD_PATCH_FENCED,
            newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
            security_invariant=_SECURITY_INVARIANT, llm=llm,
        )
        assert outcome.status == "amended"
        original_delta = semantic_delta(_PROD_PATCH)
        combined_delta = semantic_delta(outcome.amended_patch)
        assert combined_delta["src/util.py"] == original_delta["src/util.py"]


# ---------------------------------------------------------------------------
# Structural proof: no local hunk/header/relocation reimplementation in
# this module (the whole point of the shared-primitive extraction).
# ---------------------------------------------------------------------------

class TestNoLocalPatchProcessingReimplementation:
    def test_source_contains_no_hunk_header_regex_or_relocation_logic(self):
        import pathlib
        src = pathlib.Path(eta.__file__).read_text(encoding="utf-8")
        # These are diff_hunk_repair.py/content_relocation.py's own,
        # single-owner implementation signatures -- their presence here
        # would mean a second, independent copy of the same mechanism.
        forbidden = [
            "@@ -", "find_unique_occurrence(", "normalize_diff_line(",
            "_HUNK_RE", "hunks_relocated =",
        ]
        for term in forbidden:
            assert term not in src, f"{term!r} found in existing_test_amendment.py -- local reimplementation?"

    def test_amendment_call_reaches_the_real_shared_processor(self, tmp_path):
        """Spy (not a stub) on the real process_generated_patch -- proves
        this module calls through to it rather than around it."""
        import utilities.autopatcher.generated_patch_processing as gpp

        _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        with mock.patch(
            "utilities.autopatcher.generated_patch_processing.process_generated_patch",
            side_effect=gpp.process_generated_patch,
        ) as spy:
            outcome = eta.attempt_existing_test_amendment(
                repo_root=tmp_path, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        spy.assert_called_once()
        assert spy.call_args.kwargs.get("allow_context_reconstruction") is True
        assert outcome.status == "amended"


# ---------------------------------------------------------------------------
# Hygiene findings are observability only -- never a new rejection policy.
# ---------------------------------------------------------------------------

class TestHygieneFindingsNeverGateAcceptance:
    def test_hygiene_findings_present_but_amendment_still_accepted(self, tmp_path):
        """check_patch's own findings (e.g. an empty-hunk warning on some
        unrelated shape) must never, by themselves, turn an otherwise-
        applicable amendment into a rejection -- mechanical applicability
        remains the sole gate."""
        repo = _make_git_repo(tmp_path)
        llm = _FakeLLM(_amendment_json(diff=_VALID_TEST_DIFF))
        with mock.patch(
            "utilities.autopatcher.patch_hygiene.check_patch",
            return_value=[{"severity": "warning", "check": "empty_hunk", "detail": "synthetic finding"}],
        ):
            outcome = eta.attempt_existing_test_amendment(
                repo_root=repo, patch=_PROD_PATCH,
                newly_failing_tests=["test/test_retry.py::TestRetry::test_x"],
                security_invariant=_SECURITY_INVARIANT, llm=llm,
            )
        assert outcome.status == "amended"
        assert len(outcome.hygiene_findings) == 1
