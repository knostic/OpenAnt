"""Tests for patch_applicability.check_applicability."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"

_FENCED_DIFF = """\
```diff
--- a/auth.py
+++ b/auth.py
@@ -1,2 +1,2 @@
 def authenticate(u, p):
-    return True
+    return check_credentials(u, p)
```"""

_INNER_DIFF = """\
--- a/auth.py
+++ b/auth.py
@@ -1,2 +1,2 @@
 def authenticate(u, p):
-    return True
+    return check_credentials(u, p)
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_git_repo(tmp_path: Path) -> Path:
    """Init a minimal git repo with one committed file."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, capture_output=True)
    (tmp_path / "auth.py").write_text(
        "def authenticate(u, p):\n    return True\n", encoding="utf-8"
    )
    subprocess.run(["git", "add", "auth.py"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    return tmp_path


def _mock_git_run(returncode: int, stderr: str = ""):
    cm = mock.MagicMock()
    cm.returncode = returncode
    cm.stderr = stderr
    return cm


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

class TestSkipConditions:
    def test_no_repo_root_skipped(self):
        from utilities.autopatcher.patch_applicability import check_applicability
        r = check_applicability(_FENCED_DIFF, None)
        assert r["skipped"] is True
        assert r["applicable"] is None
        assert "no repo_root" in r["skipped_reason"]

    def test_not_git_repo_skipped(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        r = check_applicability(_FENCED_DIFF, tmp_path)
        assert r["skipped"] is True
        assert "git" in r["skipped_reason"].lower()

    def test_empty_patch_skipped(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        r = check_applicability("", tmp_path)
        assert r["skipped"] is True
        assert "empty" in r["skipped_reason"].lower()

    def test_fences_only_skipped(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        r = check_applicability("```diff\n```", tmp_path)
        assert r["skipped"] is True

    def test_git_not_found_skipped(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        side_effect=FileNotFoundError):
            r = check_applicability(_FENCED_DIFF, tmp_path)
        assert r["skipped"] is True
        assert "git" in r["skipped_reason"].lower()
        assert r["error"] is None


# ---------------------------------------------------------------------------
# Error state (not skipped)
# ---------------------------------------------------------------------------

class TestErrorState:
    def test_timeout_is_error_not_skip(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        with mock.patch(
            "utilities.autopatcher.patch_applicability.run_utf8",
            side_effect=subprocess.TimeoutExpired("git", 10),
        ):
            r = check_applicability(_FENCED_DIFF, tmp_path)
        assert r["skipped"] is False
        assert r["applicable"] is None
        assert r["error"] is not None
        assert "timed out" in r["error"].lower()

    def test_unexpected_exception_is_error_not_skip(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        with mock.patch(
            "utilities.autopatcher.patch_applicability.run_utf8",
            side_effect=RuntimeError("something broke"),
        ):
            r = check_applicability(_FENCED_DIFF, tmp_path)
        assert r["skipped"] is False
        assert r["error"] is not None
        assert r["applicable"] is None


# ---------------------------------------------------------------------------
# Success / failure from git (mocked)
# ---------------------------------------------------------------------------

class TestApplicabilityResult:
    def test_applicable_true_on_returncode_0(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        return_value=_mock_git_run(0)):
            r = check_applicability(_FENCED_DIFF, tmp_path)
        assert r["applicable"] is True
        assert r["skipped"] is False
        assert r["error"] is None
        assert r["exit_code"] == 0

    def test_applicable_false_on_nonzero_returncode(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        return_value=_mock_git_run(1, "error: auth.py: does not exist in index")):
            r = check_applicability(_FENCED_DIFF, tmp_path)
        assert r["applicable"] is False
        assert r["exit_code"] == 1
        assert "does not exist" in r["stderr"]

    def test_fences_stripped_before_passing_to_git(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        captured = []
        def _capture(cmd, **kwargs):
            captured.append(kwargs.get("input", ""))
            return _mock_git_run(0)
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8", side_effect=_capture):
            check_applicability(_FENCED_DIFF, tmp_path)
        assert captured
        assert "```diff" not in captured[0]
        assert "```" not in captured[0].strip().splitlines()[-1]

    def test_plain_diff_no_fences_also_accepted(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        return_value=_mock_git_run(0)) as m:
            check_applicability(_INNER_DIFF, tmp_path)
        assert m.called


# ---------------------------------------------------------------------------
# stderr truncation
# ---------------------------------------------------------------------------

class TestStderrTruncation:
    def test_truncated_at_20_lines(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        long_stderr = "\n".join(f"error line {i}" for i in range(50))
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        return_value=_mock_git_run(1, long_stderr)):
            r = check_applicability(_FENCED_DIFF, tmp_path)
        lines = r["stderr"].splitlines()
        assert len(lines) <= 21   # 20 data + 1 truncation marker
        assert "truncated" in r["stderr"].lower()

    def test_truncated_at_2000_chars(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        long_stderr = "x" * 3000
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        return_value=_mock_git_run(1, long_stderr)):
            r = check_applicability(_FENCED_DIFF, tmp_path)
        assert len(r["stderr"]) <= 2_100   # 2000 + marker

    def test_short_stderr_not_truncated(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        (tmp_path / ".git").mkdir()
        stderr = "error: auth.py: patch does not apply"
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        return_value=_mock_git_run(1, stderr)):
            r = check_applicability(_FENCED_DIFF, tmp_path)
        assert r["stderr"] == stderr


# ---------------------------------------------------------------------------
# Integration: real git (skipped if git unavailable)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not shutil.which("git"), reason="git not available")
class TestRealGitApply:
    def test_correct_patch_applies(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        _make_git_repo(tmp_path)
        patch = (
            "```diff\n"
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def authenticate(u, p):\n"
            "-    return True\n"
            "+    return check_credentials(u, p)\n"
            "```"
        )
        r = check_applicability(patch, tmp_path)
        assert r["skipped"] is False
        assert r["applicable"] is True
        assert r["error"] is None

    def test_nonexistent_file_fails(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        _make_git_repo(tmp_path)
        patch = (
            "```diff\n"
            "--- a/nonexistent.py\n"
            "+++ b/nonexistent.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old_line()\n"
            "+new_line()\n"
            "```"
        )
        r = check_applicability(patch, tmp_path)
        assert r["skipped"] is False
        assert r["applicable"] is False
        assert r["stderr"]   # git names the problem

    def test_wrong_context_fails(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        _make_git_repo(tmp_path)
        # The file has "def authenticate" but the patch removes "def wrong_name"
        patch = (
            "```diff\n"
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-def wrong_name(u, p):\n"
            "+def authenticate(u, p):\n"
            "     return True\n"
            "```"
        )
        r = check_applicability(patch, tmp_path)
        assert r["skipped"] is False
        assert r["applicable"] is False


# ---------------------------------------------------------------------------
# apply_patch: skip/error conditions (mirrors check_applicability's, minus
# the "skipped" flag — apply_patch just reports applied=False + error)
# ---------------------------------------------------------------------------

class TestApplyPatchSkipConditions:
    def test_no_workspace_root(self):
        from utilities.autopatcher.patch_applicability import apply_patch
        r = apply_patch(_FENCED_DIFF, None)
        assert r.applied is False
        assert "no workspace_root" in r.error
        assert r.error_kind == "invalid_input"

    def test_not_git_repo(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch
        r = apply_patch(_FENCED_DIFF, tmp_path)
        assert r.applied is False
        assert "git" in r.error.lower()
        assert r.error_kind == "not_git_repository"

    def test_empty_patch(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch
        (tmp_path / ".git").mkdir()
        r = apply_patch("", tmp_path)
        assert r.applied is False
        assert "empty" in r.error.lower()
        assert r.error_kind == "invalid_input"

    def test_git_not_found(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch
        (tmp_path / ".git").mkdir()
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        side_effect=FileNotFoundError):
            r = apply_patch(_FENCED_DIFF, tmp_path)
        assert r.applied is False
        assert "git" in r.error.lower()
        assert r.error_kind == "git_not_found"


class TestApplyPatchErrorState:
    def test_timeout(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch
        (tmp_path / ".git").mkdir()
        with mock.patch(
            "utilities.autopatcher.patch_applicability.run_utf8",
            side_effect=subprocess.TimeoutExpired("git", 10),
        ):
            r = apply_patch(_FENCED_DIFF, tmp_path)
        assert r.applied is False
        assert "timed out" in r.error.lower()
        assert r.error_kind == "timeout"

    def test_unexpected_exception(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch
        (tmp_path / ".git").mkdir()
        with mock.patch(
            "utilities.autopatcher.patch_applicability.run_utf8",
            side_effect=RuntimeError("something broke"),
        ):
            r = apply_patch(_FENCED_DIFF, tmp_path)
        assert r.applied is False
        assert r.error is not None
        assert r.error_kind == "unexpected_error"


class TestApplyPatchResult:
    def test_applied_true_on_returncode_0(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch
        (tmp_path / ".git").mkdir()
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        return_value=_mock_git_run(0)):
            r = apply_patch(_FENCED_DIFF, tmp_path)
        assert r.applied is True
        assert r.error is None
        assert r.error_kind is None
        assert r.exit_code == 0

    def test_applied_false_on_nonzero_returncode(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch
        (tmp_path / ".git").mkdir()
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        return_value=_mock_git_run(1, "error: auth.py: does not exist in index")):
            r = apply_patch(_FENCED_DIFF, tmp_path)
        assert r.applied is False
        assert r.exit_code == 1
        assert r.error_kind == "apply_rejected"
        assert "does not exist" in r.stderr

    def test_no_check_flag_passed_to_git(self, tmp_path):
        """apply_patch must NOT pass --check — it mutates the tree."""
        from utilities.autopatcher.patch_applicability import apply_patch
        (tmp_path / ".git").mkdir()
        captured = []
        def _capture(cmd, **kwargs):
            captured.append(cmd)
            return _mock_git_run(0)
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8", side_effect=_capture):
            apply_patch(_FENCED_DIFF, tmp_path)
        assert captured
        assert "--check" not in captured[0]

    def test_result_is_frozen_dataclass(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch, PatchApplicationResult
        (tmp_path / ".git").mkdir()
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8",
                        return_value=_mock_git_run(0)):
            r = apply_patch(_FENCED_DIFF, tmp_path)
        assert isinstance(r, PatchApplicationResult)
        with pytest.raises(Exception):  # dataclasses.FrozenInstanceError
            r.applied = False


# ---------------------------------------------------------------------------
# apply_patch: real git, mutating a disposable copy (never repo_root itself)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not shutil.which("git"), reason="git not available")
class TestRealGitApplyPatch:
    def test_correct_patch_applies_and_mutates_file(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch
        _make_git_repo(tmp_path)
        patch = (
            "```diff\n"
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def authenticate(u, p):\n"
            "-    return True\n"
            "+    return check_credentials(u, p)\n"
            "```"
        )
        r = apply_patch(patch, tmp_path)
        assert r.applied is True
        assert r.error is None
        assert r.error_kind is None
        assert "check_credentials" in (tmp_path / "auth.py").read_text(encoding="utf-8")

    def test_bad_patch_does_not_apply_and_leaves_file_untouched(self, tmp_path):
        from utilities.autopatcher.patch_applicability import apply_patch
        _make_git_repo(tmp_path)
        original = (tmp_path / "auth.py").read_text(encoding="utf-8")
        patch = (
            "```diff\n"
            "--- a/nonexistent.py\n"
            "+++ b/nonexistent.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old_line()\n"
            "+new_line()\n"
            "```"
        )
        r = apply_patch(patch, tmp_path)
        assert r.applied is False
        assert r.error_kind == "apply_rejected"
        assert (tmp_path / "auth.py").read_text(encoding="utf-8") == original

    def test_compose_with_temporary_repo_copy_never_touches_real_repo(self, tmp_path):
        """The intended composition: copy, then apply to the copy only."""
        from utilities.autopatcher.patch_applicability import apply_patch
        from utilities.autopatcher.patch_workspace import temporary_repo_copy
        real_repo = _make_git_repo(tmp_path)
        original = (real_repo / "auth.py").read_text(encoding="utf-8")
        patch = (
            "```diff\n"
            "--- a/auth.py\n"
            "+++ b/auth.py\n"
            "@@ -1,2 +1,2 @@\n"
            " def authenticate(u, p):\n"
            "-    return True\n"
            "+    return check_credentials(u, p)\n"
            "```"
        )
        with temporary_repo_copy(real_repo) as workspace_root:
            r = apply_patch(patch, workspace_root)
            assert r.applied is True
            assert "check_credentials" in (workspace_root / "auth.py").read_text(encoding="utf-8")
            # Real repo must be untouched while the copy is mutated.
            assert (real_repo / "auth.py").read_text(encoding="utf-8") == original
        # And still untouched after the workspace is torn down.
        assert (real_repo / "auth.py").read_text(encoding="utf-8") == original


# ---------------------------------------------------------------------------
# Pipeline-level: section renders correctly
# ---------------------------------------------------------------------------

class TestFenceStrippingPreservesTrailingBlankContext:
    """Regression coverage for the byte-preserving _strip_fences fix.

    Historical bug: splitlines() + "\\n".join(...) followed by .strip()
    silently deleted a trailing single-space context line, turning a valid
    hunk into one whose body no longer matched its @@ header's declared
    count — surfacing as `git apply`'s generic "corrupt patch at line N"
    instead of the real applicability result.
    """

    def _repo_with_blank_line_before_brace(self, tmp_path: Path) -> Path:
        """A hermetic git repo whose file has a real blank line before `}`."""
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, capture_output=True)
        (tmp_path / "redirect.c").write_text(
            "int follow(int x) {\n"
            "  do_thing(x);\n"
            "\n"
            "  return 0;\n"
            "}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "add", "redirect.c"], cwd=tmp_path, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)
        return tmp_path

    def _fenced_patch_with_trailing_blank_context(self) -> str:
        """Fenced diff whose final hunk's last line is a single-space context
        line (representing the real blank line before `}` in redirect.c)."""
        body = (
            "--- a/redirect.c\n"
            "+++ b/redirect.c\n"
            "@@ -1,5 +1,8 @@\n"
            " int follow(int x) {\n"
            "   do_thing(x);\n"
            "+  if(x) {\n"
            "+    clear_creds(x);\n"
            "+  }\n"
            " \n"
            "   return 0;\n"
            " }\n"
        )
        # No trailing newline after the closing fence, matching how
        # patch_generator._extract_diff_block assembles the string.
        return "```diff\n" + body + "```"

    def test_strip_fences_supports_tilde_closing_fence(self):
        """~~~ is accepted as a closing fence, mirroring
        diff_hunk_repair._strip_md_fences's same ("```", "~~~") check."""
        from utilities.autopatcher.patch_applicability import _strip_fences
        patch = "```diff\n--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-a\n+b\n~~~"
        stripped = _strip_fences(patch)
        assert "~~~" not in stripped
        assert "```" not in stripped
        assert stripped == "--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-a\n+b\n"

    def test_strip_fences_preserves_trailing_backtick_context_line(self):
        """F-38 regression: a legitimate context line whose content is ```
        must not be mistaken for the LLM's own wrapper fence and stripped,
        even when the patch has no surrounding ``` wrapper at all."""
        from utilities.autopatcher.patch_applicability import _strip_fences
        patch = (
            "--- a/x\n"
            "+++ b/x\n"
            "@@ -1,2 +1,2 @@\n"
            "-a\n"
            "+b\n"
            " ```\n"
        )
        stripped = _strip_fences(patch)
        assert stripped.splitlines(keepends=True)[-1] == " ```\n"

    def test_strip_fences_preserves_single_space_last_line(self):
        from utilities.autopatcher.patch_applicability import _strip_fences
        patch = self._fenced_patch_with_trailing_blank_context()
        stripped = _strip_fences(patch)
        lines = stripped.splitlines(keepends=True)
        # The blank context line (single space) two lines before the final
        # ' }\n' context line must survive untouched, not be deleted.
        assert lines[-3] == " \n"
        assert lines[-2] == "   return 0;\n"
        assert lines[-1] == " }\n"

    @pytest.mark.skipif(not shutil.which("git"), reason="git not available")
    def test_no_longer_reported_as_corrupt(self, tmp_path):
        from utilities.autopatcher.patch_applicability import check_applicability
        self._repo_with_blank_line_before_brace(tmp_path)
        patch = self._fenced_patch_with_trailing_blank_context()
        r = check_applicability(patch, tmp_path)
        assert "corrupt patch" not in (r["stderr"] or "").lower()

    @pytest.mark.skipif(not shutil.which("git"), reason="git not available")
    def test_well_formed_patch_with_trailing_blank_context_applies(self, tmp_path):
        """The patch above is genuinely well-formed against redirect.c — with
        the fence-stripping bug fixed it must apply cleanly, not merely
        avoid the word 'corrupt'."""
        from utilities.autopatcher.patch_applicability import check_applicability
        self._repo_with_blank_line_before_brace(tmp_path)
        patch = self._fenced_patch_with_trailing_blank_context()
        r = check_applicability(patch, tmp_path)
        assert r["applicable"] is True, r["stderr"]

    @pytest.mark.skipif(not shutil.which("git"), reason="git not available")
    def test_genuine_context_mismatch_still_fails_normally(self, tmp_path):
        """A real context mismatch (not a fence-stripping artifact) must
        still be reported as a normal, non-corrupt applicability failure."""
        from utilities.autopatcher.patch_applicability import check_applicability
        self._repo_with_blank_line_before_brace(tmp_path)
        bad_patch = (
            "```diff\n"
            "--- a/redirect.c\n"
            "+++ b/redirect.c\n"
            "@@ -1,5 +1,8 @@\n"
            " int follow(int x) {\n"
            "   do_thing_that_does_not_exist(x);\n"
            "+  if(x) {\n"
            "+    clear_creds(x);\n"
            "+  }\n"
            " \n"
            "   return 0;\n"
            " }\n"
            "```"
        )
        r = check_applicability(bad_patch, tmp_path)
        assert r["applicable"] is False
        assert "corrupt patch" not in (r["stderr"] or "").lower()
        assert r["stderr"]  # git still names the problem


class TestPipelineApplicabilitySection:
    def test_section_present_in_report(self):
        from utilities.autopatcher.pipeline import run
        vuln_text = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")
        report = run(vulnerability_text=vuln_text, api_key="")
        assert "## Patch Applicability" in report

    def test_skipped_when_no_repo_root(self):
        from utilities.autopatcher.pipeline import run
        vuln_text = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")
        report = run(vulnerability_text=vuln_text, api_key="", repo_root=None)
        start = report.find("## Patch Applicability")
        end = report.find("---", start + 1)
        section = report[start:end]
        assert "Skipped" in section

    def test_hygiene_before_applicability(self):
        from utilities.autopatcher.pipeline import run
        vuln_text = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")
        report = run(vulnerability_text=vuln_text, api_key="")
        idx_hygiene = report.find("## Patch Hygiene")
        idx_applicability = report.find("## Patch Applicability")
        assert idx_hygiene < idx_applicability
