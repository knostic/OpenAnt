"""Unit tests for patch_generator._extract_diff_block and generate_patch."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_CLEAN_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```"""

_PROSE_PREAMBLE = """\
The vulnerability is in retry.py. Here is the minimal fix:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```

Let me know if you need a more defensive approach."""

_TWO_ALTERNATIVES = """\
Option A — minimal fix:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
```

Option B — more defensive:

```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization", "X-Csrf-Token"])
```"""

_MULTI_FILE_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
--- a/src/urllib3/connectionpool.py
+++ b/src/urllib3/connectionpool.py
@@ -1,3 +1,4 @@
+# Cookie stripping is handled via DEFAULT_REMOVE_HEADERS_ON_REDIRECT.
```"""

_PATCH_TAG = """\
```patch
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,1 +1,1 @@
-old_line()
+new_line()
```"""

_UDIFF_TAG = """\
```udiff
--- a/src/utils.py
+++ b/src/utils.py
@@ -1,1 +1,1 @@
-old_line()
+new_line()
```"""

_NO_DIFF_BLOCK = "The vulnerability requires manual intervention. No automated patch is possible."

_WINDOWS_ENDINGS = "```diff\r\n--- a/foo.py\r\n+++ b/foo.py\r\n@@ -1 +1 @@\r\n-old\r\n+new\r\n```"


# ---------------------------------------------------------------------------
# Tests for _extract_diff_block
# ---------------------------------------------------------------------------

class TestExtractDiffBlock:
    def test_clean_diff_preserved(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_CLEAN_DIFF)
        assert result.startswith("```diff\n")
        assert result.strip().endswith("```")
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in result

    def test_prose_preamble_stripped(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_PROSE_PREAMBLE)
        assert result.startswith("```diff\n")
        assert "The vulnerability" not in result
        assert "Let me know" not in result
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in result

    def test_prose_postamble_stripped(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_PROSE_PREAMBLE)
        assert "Let me know" not in result

    def test_first_of_two_alternatives_returned(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_TWO_ALTERNATIVES)
        assert result.count("```diff") == 1
        assert "Option A" not in result
        assert "Option B" not in result
        assert "X-Csrf-Token" not in result
        assert '"Cookie", "Authorization"' in result

    def test_multi_file_diff_preserved(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_MULTI_FILE_DIFF)
        assert "retry.py" in result
        assert "connectionpool.py" in result

    def test_patch_tag_normalised_to_diff(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_PATCH_TAG)
        assert result.startswith("```diff\n")
        assert "+new_line()" in result

    def test_udiff_tag_normalised_to_diff(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_UDIFF_TAG)
        assert result.startswith("```diff\n")
        assert "+new_line()" in result

    def test_no_fenced_block_returns_raw_stripped(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_NO_DIFF_BLOCK)
        assert result == _NO_DIFF_BLOCK.strip()

    def test_empty_string_returns_empty(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        assert _extract_diff_block("") == ""

    def test_windows_line_endings_accepted(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        result = _extract_diff_block(_WINDOWS_ENDINGS)
        assert result.startswith("```diff\n")
        assert "+new" in result

    def test_output_always_starts_with_diff_fence(self):
        from utilities.autopatcher.patch_generator import _extract_diff_block
        for raw in (_CLEAN_DIFF, _PROSE_PREAMBLE, _TWO_ALTERNATIVES, _PATCH_TAG):
            result = _extract_diff_block(raw)
            assert result.startswith("```diff\n"), f"Failed for input starting: {raw[:40]!r}"


# ---------------------------------------------------------------------------
# Integration: generate_patch extracts clean output from messy LLM response
# ---------------------------------------------------------------------------

class TestGeneratePatchExtraction:
    def test_extracts_diff_from_messy_response(self):
        from utilities.autopatcher.patch_generator import generate_patch
        messy = (
            "I'll fix this by adding Cookie to the frozenset:\n\n"
            "```diff\n"
            "--- a/src/urllib3/util/retry.py\n"
            "+++ b/src/urllib3/util/retry.py\n"
            "@@ -187,7 +187,7 @@\n"
            '-    DEFAULT_REMOVE = frozenset(["Authorization"])\n'
            '+    DEFAULT_REMOVE = frozenset(["Cookie", "Authorization"])\n'
            "```\n\n"
            "Alternatively you could also strip X-Csrf-Token."
        )
        llm = mock.MagicMock()
        llm.complete.return_value = messy
        result = generate_patch("some vuln", llm)
        assert result.startswith("```diff\n")
        assert "Alternatively" not in result
        assert result.count("```diff") == 1

    def test_fallback_when_no_fenced_block(self):
        from utilities.autopatcher.patch_generator import generate_patch
        plain = "No automated patch available for this vulnerability."
        llm = mock.MagicMock()
        llm.complete.return_value = plain
        result = generate_patch("some vuln", llm)
        assert result == plain.strip()


# ---------------------------------------------------------------------------
# AUTOPATCHER_DEBUG prompt dump
# ---------------------------------------------------------------------------

class TestDebugDump:
    def test_debug_file_written_when_env_set(self, tmp_path, monkeypatch):
        from utilities.autopatcher.patch_generator import generate_patch

        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        # Redirect debug output to tmp_path
        monkeypatch.chdir(tmp_path)

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch("SQL injection in auth.py", llm, code_context="def auth(): pass")

        debug_dir = tmp_path / "reports" / "debug"
        assert debug_dir.exists(), "reports/debug/ must be created"
        files = list(debug_dir.glob("prompt_*.txt"))
        assert len(files) == 1, f"Expected one debug file, found {files}"
        content = files[0].read_text()
        assert "SQL injection" in content
        assert "def auth(): pass" in content

    def test_no_debug_file_when_env_unset(self, tmp_path, monkeypatch):
        from utilities.autopatcher.patch_generator import generate_patch

        monkeypatch.delenv("AUTOPATCHER_DEBUG", raising=False)
        monkeypatch.chdir(tmp_path)

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch("some vuln", llm)

        debug_dir = tmp_path / "reports" / "debug"
        assert not debug_dir.exists(), "No debug directory should be created without the env var"

    def test_debug_file_does_not_contain_api_key(self, tmp_path, monkeypatch):
        from utilities.autopatcher.patch_generator import generate_patch

        monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
        monkeypatch.chdir(tmp_path)

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch("vuln text", llm, code_context="some code")

        debug_dir = tmp_path / "reports" / "debug"
        files = list(debug_dir.glob("prompt_*.txt"))
        assert files
        content = files[0].read_text()
        # user_message contains only vuln text + code context, never the API key
        assert "sk-" not in content
        assert "OPENAI_API_KEY" not in content


# ---------------------------------------------------------------------------
# retry_hint parameter
# ---------------------------------------------------------------------------

class TestRetryHint:
    def test_retry_hint_appended_to_user_message(self):
        from utilities.autopatcher.patch_generator import generate_patch

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch(
            "some vuln",
            llm,
            code_context="def foo(): pass",
            retry_hint="Please fix the context lines.",
        )

        _system, user_message = llm.complete.call_args[0]
        assert "## Retry instruction" in user_message
        assert "Please fix the context lines." in user_message

    def test_no_retry_section_when_hint_empty(self):
        from utilities.autopatcher.patch_generator import generate_patch

        llm = mock.MagicMock()
        llm.complete.return_value = "```diff\n--- a/f.py\n+++ b/f.py\n```"

        generate_patch("some vuln", llm, code_context="def foo(): pass")

        _system, user_message = llm.complete.call_args[0]
        assert "## Retry instruction" not in user_message
