"""Tests for applicability-aware retry logic in pipeline.py."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_PIP_STDERR = (
    "error: patch failed: src/pip/_internal/download.py:1\n"
    "error: src/pip/_internal/download.py: patch does not apply\n"
)

_CORRUPT_STDERR = "error: corrupt patch at line 7\n"

_PIP_DIFF_ORIG = """\
```diff
--- a/src/pip/_internal/download.py
+++ b/src/pip/_internal/download.py
@@ -1,3 +1,4 @@
 from __future__ import absolute_import
+# security fix
 import os
```"""

_PIP_DIFF_RETRY = """\
```diff
--- a/src/pip/_internal/download.py
+++ b/src/pip/_internal/download.py
@@ -1,3 +1,4 @@
 import os
+# security fix
 import sys
```"""

_CLEAN_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -1,2 +1,3 @@
 def retry():
+    # security fix
     pass
```"""


# ---------------------------------------------------------------------------
# _extract_failed_file
# ---------------------------------------------------------------------------

class TestExtractFailedFile:
    def test_patch_failed_format(self):
        from utilities.autopatcher.pipeline import _extract_failed_file
        result = _extract_failed_file(_PIP_STDERR)
        assert result == "src/pip/_internal/download.py"

    def test_does_not_apply_format(self):
        from utilities.autopatcher.pipeline import _extract_failed_file
        stderr = "error: some/path/file.py: patch does not apply\n"
        assert _extract_failed_file(stderr) == "some/path/file.py"

    def test_corrupt_patch_returns_none(self):
        from utilities.autopatcher.pipeline import _extract_failed_file
        assert _extract_failed_file(_CORRUPT_STDERR) is None

    def test_empty_stderr_returns_none(self):
        from utilities.autopatcher.pipeline import _extract_failed_file
        assert _extract_failed_file("") is None

    def test_none_stderr_returns_none(self):
        from utilities.autopatcher.pipeline import _extract_failed_file
        assert _extract_failed_file(None) is None

    def test_patch_failed_takes_priority_over_does_not_apply(self):
        from utilities.autopatcher.pipeline import _extract_failed_file
        # Both formats present — patch failed is matched first
        result = _extract_failed_file(_PIP_STDERR)
        assert result == "src/pip/_internal/download.py"


# ---------------------------------------------------------------------------
# _extract_patch_target
# ---------------------------------------------------------------------------

class TestExtractPatchTarget:
    def test_fenced_diff_returns_target(self):
        from utilities.autopatcher.pipeline import _extract_patch_target
        result = _extract_patch_target(_PIP_DIFF_ORIG)
        assert result == "src/pip/_internal/download.py"

    def test_unfenced_diff_returns_target(self):
        from utilities.autopatcher.pipeline import _extract_patch_target
        unfenced = (
            "--- a/src/foo.py\n"
            "+++ b/src/foo.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        assert _extract_patch_target(unfenced) == "src/foo.py"

    def test_no_plus_plus_line_returns_none(self):
        from utilities.autopatcher.pipeline import _extract_patch_target
        assert _extract_patch_target("no diff here") is None

    def test_empty_patch_returns_none(self):
        from utilities.autopatcher.pipeline import _extract_patch_target
        assert _extract_patch_target("") is None


# ---------------------------------------------------------------------------
# _build_retry_hint
# ---------------------------------------------------------------------------

class TestBuildRetryHint:
    def test_contains_failed_file(self):
        from utilities.autopatcher.pipeline import _build_retry_hint
        hint = _build_retry_hint(_PIP_STDERR, "src/pip/_internal/download.py")
        assert "src/pip/_internal/download.py" in hint

    def test_contains_stderr_excerpt(self):
        from utilities.autopatcher.pipeline import _build_retry_hint
        hint = _build_retry_hint(_PIP_STDERR, "some/file.py")
        assert "error: patch failed" in hint

    def test_instructs_not_to_use_training_memory(self):
        from utilities.autopatcher.pipeline import _build_retry_hint
        hint = _build_retry_hint(_PIP_STDERR, "some/file.py")
        assert "training" in hint.lower() or "ground truth" in hint.lower()

    def test_stderr_truncated_to_limit(self):
        from utilities.autopatcher.pipeline import _build_retry_hint, _RETRY_STDERR_LINES
        many_lines = "\n".join(f"line {i}" for i in range(50))
        hint = _build_retry_hint(many_lines, "f.py")
        # Only first _RETRY_STDERR_LINES lines should appear
        assert f"line {_RETRY_STDERR_LINES}" not in hint
        assert "line 0" in hint


# ---------------------------------------------------------------------------
# Retry NOT triggered
# ---------------------------------------------------------------------------

class TestRetryNotTriggered:
    """Retry must NOT run when applicable=True, applicable=None, or no repo_root."""

    def _run_with_mock(self, applicability_return, repo_root=None, vuln="test vuln"):
        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
            mock.patch("utilities.autopatcher.pipeline.generate_patch", return_value=_CLEAN_DIFF) as mock_gen,
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability", return_value=applicability_return),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        ):
            mock_llm_cls.return_value = mock.MagicMock()
            from utilities.autopatcher.pipeline import run
            run(vuln, api_key="", repo_root=repo_root)
            return mock_gen.call_count

    def test_no_retry_when_applicable_true(self, tmp_path):
        call_count = self._run_with_mock(
            {"applicable": True, "skipped": False, "stderr": "", "exit_code": 0,
             "skipped_reason": None, "error": None},
            repo_root=str(tmp_path),
        )
        assert call_count == 1

    def test_no_retry_when_applicable_none(self, tmp_path):
        call_count = self._run_with_mock(
            {"applicable": None, "skipped": True, "stderr": "", "exit_code": None,
             "skipped_reason": "no repo_root", "error": None},
            repo_root=str(tmp_path),
        )
        assert call_count == 1

    def test_no_retry_when_no_repo_root(self):
        call_count = self._run_with_mock(
            {"applicable": False, "skipped": False, "stderr": _PIP_STDERR,
             "exit_code": 1, "skipped_reason": None, "error": None},
            repo_root=None,
        )
        assert call_count == 1


# ---------------------------------------------------------------------------
# Retry triggered — success and failure outcomes
# ---------------------------------------------------------------------------

class TestRetryTriggered:
    """applicable=False + repo_root → retry must be attempted."""

    def _setup_mocks(
        self,
        tmp_path: Path,
        retry_applicable: bool,
        failed_file: str = "src/pip/_internal/download.py",
    ):
        """Return a context-manager tuple for the common retry scenario."""
        # Write the file the retry will read
        target = tmp_path / failed_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("import os\nimport sys\n", encoding="utf-8")

        first_app = {
            "applicable": False, "skipped": False, "stderr": _PIP_STDERR,
            "exit_code": 1, "skipped_reason": None, "error": None,
        }
        retry_app = {
            "applicable": retry_applicable, "skipped": False, "stderr": "",
            "exit_code": 0 if retry_applicable else 1,
            "skipped_reason": None, "error": None,
        }
        return first_app, retry_app

    def test_retry_calls_generate_patch_twice(self, tmp_path):
        first_app, retry_app = self._setup_mocks(tmp_path, retry_applicable=True)
        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       side_effect=[_PIP_DIFF_ORIG, _PIP_DIFF_RETRY]) as mock_gen,
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       side_effect=[first_app, retry_app]),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        ):
            mock_llm_cls.return_value = mock.MagicMock()
            from utilities.autopatcher.pipeline import run
            run("pip vuln", api_key="", repo_root=str(tmp_path))
            assert mock_gen.call_count == 2

    def test_retry_call_includes_retry_hint(self, tmp_path):
        first_app, retry_app = self._setup_mocks(tmp_path, retry_applicable=True)
        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient"),
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       side_effect=[_PIP_DIFF_ORIG, _PIP_DIFF_RETRY]) as mock_gen,
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       side_effect=[first_app, retry_app]),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        ):
            from utilities.autopatcher.pipeline import run
            run("pip vuln", api_key="", repo_root=str(tmp_path))
            _args, kwargs = mock_gen.call_args_list[1]
            assert kwargs.get("retry_hint") or (len(_args) > 3 and _args[3])


# ---------------------------------------------------------------------------
# Retry outcomes — patch and metadata
# ---------------------------------------------------------------------------

class TestRetryOutcomes:
    def _run_retry_scenario(self, tmp_path, retry_applicable):
        failed_file = "src/pip/_internal/download.py"
        target = tmp_path / failed_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("import os\nimport sys\n", encoding="utf-8")

        first_app = {
            "applicable": False, "skipped": False, "stderr": _PIP_STDERR,
            "exit_code": 1, "skipped_reason": None, "error": None,
        }
        retry_app = {
            "applicable": retry_applicable, "skipped": False, "stderr": "",
            "exit_code": 0 if retry_applicable else 1,
            "skipped_reason": None, "error": None,
        }

        captured_result = {}

        original_build_report = None
        import utilities.autopatcher.pipeline as _pipeline_mod
        original_build_report = _pipeline_mod._build_report

        def capture_result(r):
            captured_result["result"] = r
            return original_build_report(r)

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient"),
            mock.patch("utilities.autopatcher.pipeline.generate_patch",
                       side_effect=[_PIP_DIFF_ORIG, _PIP_DIFF_RETRY]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       side_effect=[first_app, retry_app]),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.pipeline._build_report", side_effect=capture_result),
        ):
            from utilities.autopatcher.pipeline import run
            run("pip vuln", api_key="", repo_root=str(tmp_path))

        return captured_result["result"]

    def test_retry_succeeded_uses_retry_patch(self, tmp_path):
        result = self._run_retry_scenario(tmp_path, retry_applicable=True)
        assert result.retry_succeeded is True
        # diff_hunk_repair rewrites @@ counts, so compare content not exact string
        assert "import sys" in result.patch
        assert result.patch != result.original_patch

    def test_retry_failed_keeps_original_patch(self, tmp_path):
        result = self._run_retry_scenario(tmp_path, retry_applicable=False)
        assert result.retry_succeeded is False
        # patch must equal original_patch (both go through hunk repair, so compare relative identity)
        assert result.patch == result.original_patch

    def test_retry_failed_keeps_original_applicability(self, tmp_path):
        result = self._run_retry_scenario(tmp_path, retry_applicable=False)
        assert result.applicability["applicable"] is False

    def test_retry_patch_stored_in_metadata_on_failure(self, tmp_path):
        result = self._run_retry_scenario(tmp_path, retry_applicable=False)
        # retry_patch is stored even on failure (for inspection)
        assert result.retry_patch is not None
        assert "import sys" in result.retry_patch

    def test_original_patch_preserved_in_metadata_on_success(self, tmp_path):
        result = self._run_retry_scenario(tmp_path, retry_applicable=True)
        # original_patch must contain the original content (from __future__ not in retry)
        assert "from __future__" in result.original_patch

    def test_original_patch_preserved_in_metadata_on_failure(self, tmp_path):
        result = self._run_retry_scenario(tmp_path, retry_applicable=False)
        assert "from __future__" in result.original_patch


# ---------------------------------------------------------------------------
# Retry metadata fields
# ---------------------------------------------------------------------------

class TestRetryMetadata:
    def _run_no_retry(self, tmp_path):
        app = {
            "applicable": True, "skipped": False, "stderr": "",
            "exit_code": 0, "skipped_reason": None, "error": None,
        }
        captured_result = {}
        import utilities.autopatcher.pipeline as _pipeline_mod
        original_build_report = _pipeline_mod._build_report

        def capture(r):
            captured_result["result"] = r
            return original_build_report(r)

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient"),
            mock.patch("utilities.autopatcher.pipeline.generate_patch", return_value=_CLEAN_DIFF),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability", return_value=app),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.pipeline._build_report", side_effect=capture),
        ):
            from utilities.autopatcher.pipeline import run
            run("test vuln", api_key="", repo_root=str(tmp_path))
        return captured_result["result"]

    def test_no_retry_metadata_defaults(self, tmp_path):
        result = self._run_no_retry(tmp_path)
        assert result.retry_attempted is False
        assert result.retry_succeeded is False
        assert result.retry_patch is None
        assert result.retry_failed_file is None
        assert result.retry_error_before is None

    def test_original_patch_matches_patch_when_no_retry(self, tmp_path):
        result = self._run_no_retry(tmp_path)
        assert result.original_patch == result.patch


# ---------------------------------------------------------------------------
# _render_retry_notice — isolated unit tests (mirrors
# tests/test_pipeline_repair.py::TestRenderRepairNotice)
# ---------------------------------------------------------------------------

class TestRenderRetryNotice:
    def _make_result(self, **kwargs):
        from utilities.autopatcher.pipeline import PipelineResult
        defaults = dict(
            vulnerability_text="v", patch="p", review="r",
            score_text="Confidence score: 0.8", challenger={},
        )
        defaults.update(kwargs)
        return PipelineResult(**defaults)

    def test_no_notice_when_not_attempted(self):
        from utilities.autopatcher.pipeline import _render_retry_notice
        r = self._make_result(retry_attempted=False)
        assert _render_retry_notice(r) == ""

    def test_success_notice_content(self):
        from utilities.autopatcher.pipeline import _render_retry_notice
        r = self._make_result(retry_attempted=True, retry_succeeded=True)
        notice = _render_retry_notice(r)
        assert "Applicability-aware retry" in notice
        assert "Initial patch did not apply." in notice
        assert "Applicability-aware retry was attempted." in notice
        assert "Retry succeeded" in notice
        assert "Retry failed" not in notice

    def test_failure_notice_content(self):
        from utilities.autopatcher.pipeline import _render_retry_notice
        r = self._make_result(retry_attempted=True, retry_succeeded=False)
        notice = _render_retry_notice(r)
        assert "Applicability-aware retry" in notice
        assert "Initial patch did not apply." in notice
        assert "Applicability-aware retry was attempted." in notice
        assert "Retry failed to produce an applicable patch." in notice
        assert "Retry succeeded" not in notice


# ---------------------------------------------------------------------------
# Retry notice — end-to-end wiring into the rendered report
# ---------------------------------------------------------------------------

class TestRetryNoticeInReport:
    """Proves the notice is actually wired into _build_report's output, in
    the right place, and has zero footprint when no retry occurred."""

    def _run_and_capture_report(self, tmp_path, *, trigger_retry: bool, retry_applicable=None):
        if trigger_retry:
            failed_file = "src/pip/_internal/download.py"
            target = tmp_path / failed_file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("import os\nimport sys\n", encoding="utf-8")

            first_app = {
                "applicable": False, "skipped": False, "stderr": _PIP_STDERR,
                "exit_code": 1, "skipped_reason": None, "error": None,
            }
            retry_app = {
                "applicable": retry_applicable, "skipped": False, "stderr": "",
                "exit_code": 0 if retry_applicable else 1,
                "skipped_reason": None, "error": None,
            }
            gen_side_effect = [_PIP_DIFF_ORIG, _PIP_DIFF_RETRY]
            app_side_effect = [first_app, retry_app]
        else:
            clean_app = {
                "applicable": True, "skipped": False, "stderr": "",
                "exit_code": 0, "skipped_reason": None, "error": None,
            }
            gen_side_effect = [_CLEAN_DIFF]
            app_side_effect = [clean_app]

        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient"),
            mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=gen_side_effect),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability", side_effect=app_side_effect),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value={}),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="score: 7"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        ):
            from utilities.autopatcher.pipeline import run
            report = run("pip vuln", api_key="", repo_root=str(tmp_path))
        return report

    def test_no_notice_in_report_when_no_retry_occurred(self, tmp_path):
        report = self._run_and_capture_report(tmp_path, trigger_retry=False)
        assert "Applicability-aware retry" not in report

    def test_notice_appears_in_report_on_retry_success(self, tmp_path):
        report = self._run_and_capture_report(tmp_path, trigger_retry=True, retry_applicable=True)
        assert "Applicability-aware retry" in report
        assert "Retry succeeded" in report

    def test_notice_appears_in_report_on_retry_failure(self, tmp_path):
        report = self._run_and_capture_report(tmp_path, trigger_retry=True, retry_applicable=False)
        assert "Applicability-aware retry" in report
        assert "Retry failed to produce an applicable patch." in report

    def test_notice_positioned_after_patch_applicability(self, tmp_path):
        """Patch Applicability and the retry notice were promoted out of
        Appendices (second reviewer-experience pass) to sit directly after
        Proposed patch, before Trust Signals — Appendices now comes well
        after both."""
        report = self._run_and_capture_report(tmp_path, trigger_retry=True, retry_applicable=False)
        applicability_idx = report.index("## Patch Applicability")
        notice_idx = report.index("Applicability-aware retry")
        trust_idx = report.index("## Trust Signals")
        appendices_idx = report.index("## Appendices")
        assert applicability_idx < notice_idx < trust_idx < appendices_idx
