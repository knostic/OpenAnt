"""Tests for the production CLI's (openant/cli.py cmd_patch) handling of
core.patch.TestComparisonEnvironmentError.

The generic `except Exception as e: _output_json(error(str(e))); return 2`
in cmd_patch already existed before this feature -- these tests confirm
it already gives acceptable UX for this specific exception on the actual
``--json`` contract (stdout: exactly one clean JSON envelope, no
traceback inside it, non-zero exit), so no dedicated catch was added
there.

Scope note: ``core.step_report.step_context`` (wrapping every
``openant patch`` invocation, not something this feature owns or should
modify) prints a traceback to STDERR for ANY exception from ANY step,
before re-raising -- this is pre-existing, universal behavior for every
`openant patch` failure mode (a plain FileNotFoundError gets the same
treatment), not something introduced by or specific to this feature.
Fixing that would mean changing shared, cross-command infrastructure,
which is out of scope here -- the tests below therefore assert on STDOUT
(the actual `--json` machine-readable contract), not stderr.
"""

from __future__ import annotations

import json
import types
from unittest import mock

import pytest

from core.patch import TestComparisonEnvironmentError
from openant.cli import cmd_patch


def _args(**overrides):
    base = dict(
        pipeline_output=None,
        finding_id=None,
        cve="CVE-2021-12345",
        repo_root="/tmp/some-repo",
        output=None,
        context_budget_policy=None,
        max_context_budget_windows=None,
        compare_existing_tests=True,
    )
    base.update(overrides)
    return types.SimpleNamespace(**base)


class TestCliTestComparisonEnvironmentErrorUX:
    def test_non_zero_exit_and_no_traceback_in_the_json_envelope(self, tmp_path, capsys):
        output_dir = tmp_path / "out"
        with mock.patch(
            "core.patch.run_patch_cve",
            side_effect=TestComparisonEnvironmentError(
                "--compare-existing-tests requires Docker, but the `docker` command was not found. "
                "Install/start Docker and rerun."
            ),
        ):
            exit_code = cmd_patch(_args(output=str(output_dir)))

        assert exit_code == 2
        captured = capsys.readouterr()
        # The --json contract (stdout) is what callers/scripts actually
        # consume -- it must be exactly one clean JSON object, never a
        # traceback. See module docstring for why stderr is out of scope.
        assert "Traceback (most recent call last)" not in captured.out
        json.loads(captured.out)  # raises if stdout isn't valid, single JSON

    def test_error_envelope_contains_concise_actionable_message(self, tmp_path, capsys):
        output_dir = tmp_path / "out"
        message = (
            "--compare-existing-tests requires Docker, but the `docker` command was not found. "
            "Install/start Docker and rerun."
        )
        with mock.patch("core.patch.run_patch_cve", side_effect=TestComparisonEnvironmentError(message)):
            cmd_patch(_args(output=str(output_dir)))

        captured = capsys.readouterr()
        envelope = json.loads(captured.out)
        assert envelope["status"] == "error"
        assert envelope["errors"] == [message]

    def test_daemon_unavailable_message_distinguishable(self, tmp_path, capsys):
        output_dir = tmp_path / "out"
        message = "--compare-existing-tests requires Docker, but the Docker daemon is not reachable (boom)."
        with mock.patch("core.patch.run_patch_cve", side_effect=TestComparisonEnvironmentError(message)):
            cmd_patch(_args(output=str(output_dir)))

        envelope = json.loads(capsys.readouterr().out)
        assert "daemon is not reachable" in envelope["errors"][0]

    def test_json_output_stays_valid_json_envelope(self, tmp_path, capsys):
        """--json / envelope behavior is preserved -- stdout is always
        exactly one parseable JSON object, whether the run succeeded or
        hit this prerequisite failure."""
        output_dir = tmp_path / "out"
        with mock.patch(
            "core.patch.run_patch_cve", side_effect=TestComparisonEnvironmentError("docker is not installed."),
        ):
            cmd_patch(_args(output=str(output_dir)))

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)  # raises if not valid JSON
        assert set(parsed.keys()) == {"status", "data", "errors"}

    def test_unexpected_exception_also_produces_no_traceback_same_envelope_shape(self, tmp_path, capsys):
        """The generic except Exception handler is unchanged either way
        -- both an expected prerequisite failure and an unexpected bug
        get the same clean envelope at the CLI layer (this is existing,
        pre-existing behavior for this entry point, confirmed here for
        contrast with run_traced.py, which treats the two differently)."""
        output_dir = tmp_path / "out"
        with mock.patch("core.patch.run_patch_cve", side_effect=RuntimeError("some other bug")):
            exit_code = cmd_patch(_args(output=str(output_dir)))

        assert exit_code == 2
        envelope = json.loads(capsys.readouterr().out)
        assert envelope["errors"] == ["some other bug"]


class TestCliFlagNeutralTerminology:
    """The `openant patch` CLI surface for this feature uses the neutral,
    factual name/flag chosen for this semantic cleanup -- never
    "regression" wording, and the old pre-release flag name is not kept
    as a backward-compatible alias (this feature was never released, so
    there is no compatibility obligation -- see existing_test_regression.
    py's module docstring)."""

    def test_compare_existing_tests_flag_is_registered(self):
        from openant.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["patch", "--cve", "X", "--repo-root", "/tmp", "--compare-existing-tests"])
        assert args.compare_existing_tests is True

    def test_old_check_regressions_flag_no_longer_exists(self):
        from openant.cli import build_parser

        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["patch", "--cve", "X", "--repo-root", "/tmp", "--check-regressions"])

    def test_help_text_for_the_flag_contains_no_regression_wording(self):
        from openant.cli import build_parser

        parser = build_parser()
        help_text = parser.format_help()
        # format_help() on the top-level parser doesn't expand subcommand
        # help; fetch the patch subparser's own help text directly.
        patch_parser = next(
            action.choices["patch"]
            for action in parser._subparsers._group_actions
            if hasattr(action, "choices") and "patch" in action.choices
        )
        patch_help = patch_parser.format_help()
        assert "--compare-existing-tests" in patch_help
        assert "regression" not in patch_help.lower()
        assert help_text or True  # top-level parser also constructed without error
