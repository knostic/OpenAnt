"""Unit tests for patch_hygiene.check_patch and its three sub-checks."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Fixtures — raw diff strings (without fences, as _parse_file_patches sees them)
# ---------------------------------------------------------------------------

_CLEAN_PATCH = """\
--- a/app/auth.py
+++ b/app/auth.py
@@ -42,7 +42,7 @@
 def authenticate(username: str, password: str) -> bool:
-    query = f"SELECT * FROM users WHERE username='{username}'"
+    query = "SELECT * FROM users WHERE username=?"
     cursor = db.execute(query)
     return cursor.fetchone() is not None
"""

_EMPTY_HUNK = """\
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
--- a/src/urllib3/_collections.py
+++ b/src/urllib3/_collections.py
@@ -1,3 +1,3 @@
     # no actual changes here
"""

_DUPLICATE_CONST = """\
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,8 +187,9 @@
     DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
"""

_CORRECT_CONST_REPLACEMENT = """\
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,7 +187,7 @@
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
"""

_UNUSED_IMPORT = """\
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -1,5 +1,6 @@
+import re
 class Retry:
-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
"""

_USED_IMPORT = """\
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -1,5 +1,7 @@
+import re
+PATTERN = re.compile(r'https?://')
 class Retry:
-    OLD_VAL = "x"
+    NEW_VAL = "y"
"""

_NEW_FILE_WITH_CONST = """\
--- /dev/null
+++ b/src/urllib3/util/headers.py
@@ -0,0 +1,3 @@
+SENSITIVE_HEADERS = frozenset(["Cookie", "Authorization"])
+
+def strip_sensitive(headers): pass
"""

# A genuinely new constant added to an existing file — no other line in the
# diff (added, removed, or unchanged context) mentions this name at all.
_NEW_CONSTANT_EXISTING_FILE = """\
--- a/app/config.py
+++ b/app/config.py
@@ -10,6 +10,7 @@
 import os

 TIMEOUT = 30
+MAX_REQUEST_BYTES = 1048576

 def load():
     pass
"""

# Simulates the dirty urllib3 output we observed in the live run
_URLLIB3_DIRTY = """\
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -187,8 +187,9 @@
     DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])
+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])
--- a/src/urllib3/_collections.py
+++ b/src/urllib3/_collections.py
@@ -1,3 +1,3 @@
     # unchanged
--- a/src/urllib3/connectionpool.py
+++ b/src/urllib3/connectionpool.py
@@ -1,4 +1,5 @@
+import re
 class HTTPConnectionPool:
     pass
"""

# The mock patch used throughout existing tests — should be clean
_MOCK_PATCH_INNER = """\
--- a/app/auth.py
+++ b/app/auth.py
@@ -42,7 +42,7 @@
 def authenticate(username: str, password: str) -> bool:
-    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
+    query = "SELECT * FROM users WHERE username=? AND password=?"
     cursor = db.execute(query)
+    # Use parameterized queries to prevent SQL injection
     return cursor.fetchone() is not None
"""


# ---------------------------------------------------------------------------
# check_patch — public API
# ---------------------------------------------------------------------------

class TestCheckPatchSafety:
    def test_empty_string_returns_empty(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        assert check_patch("") == []

    def test_none_like_string_returns_empty(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        assert check_patch("   ") == []

    def test_fenced_block_accepted(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        fenced = "```diff\n" + _CLEAN_PATCH + "\n```"
        result = check_patch(fenced)
        assert isinstance(result, list)

    def test_clean_patch_no_findings(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        assert check_patch(_CLEAN_PATCH) == []

    def test_mock_patch_no_findings(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        assert check_patch(_MOCK_PATCH_INNER) == []


# ---------------------------------------------------------------------------
# Check A — empty / no-op hunks
# ---------------------------------------------------------------------------

class TestEmptyHunkCheck:
    def test_empty_hunk_detected(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_EMPTY_HUNK)
        empty = [f for f in findings if f["check"] == "empty_hunk"]
        assert len(empty) == 1
        assert "_collections.py" in empty[0]["detail"]
        assert empty[0]["severity"] == "HIGH"

    def test_file_with_changes_not_flagged(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_EMPTY_HUNK)
        empty = [f for f in findings if f["check"] == "empty_hunk"]
        details = " ".join(f["detail"] for f in empty)
        assert "retry.py" not in details

    def test_multiple_empty_hunks_all_detected(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_URLLIB3_DIRTY)
        empty = [f for f in findings if f["check"] == "empty_hunk"]
        filenames = " ".join(f["detail"] for f in empty)
        assert "_collections.py" in filenames


# ---------------------------------------------------------------------------
# Check B — duplicate assignment
# ---------------------------------------------------------------------------

class TestDuplicateAssignmentCheck:
    def test_duplicate_constant_detected(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_DUPLICATE_CONST)
        dups = [f for f in findings if f["check"] == "duplicate_assignment"]
        assert len(dups) == 1
        assert "DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in dups[0]["detail"]
        assert dups[0]["severity"] == "MEDIUM"

    def test_duplicate_detail_only_states_what_is_visible(self):
        # The wording must not claim file-wide duplication, execution order,
        # runtime shadowing, or that the patch is ineffective — only that
        # both lines are visible in the diff and warrant a human look.
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_DUPLICATE_CONST)
        dups = [f for f in findings if f["check"] == "duplicate_assignment"]
        detail = dups[0]["detail"].lower()
        assert "verify manually" in detail or "verify" in detail
        assert "likely duplicates it" not in detail

    def test_correct_replacement_not_flagged(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_CORRECT_CONST_REPLACEMENT)
        dups = [f for f in findings if f["check"] == "duplicate_assignment"]
        assert dups == []

    def test_new_file_constant_not_flagged(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_NEW_FILE_WITH_CONST)
        dups = [f for f in findings if f["check"] == "duplicate_assignment"]
        assert dups == [], "new-file constants should not be flagged as duplicates"

    def test_new_constant_in_existing_file_not_flagged(self):
        # Regression for F-25: a genuinely new constant added to an existing
        # file must not be flagged just because the file already has other
        # constants — the name must co-occur as unchanged context to trigger.
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_NEW_CONSTANT_EXISTING_FILE)
        dups = [f for f in findings if f["check"] == "duplicate_assignment"]
        assert dups == [], "a genuinely new constant should not be flagged as a duplicate"

    def test_dirty_urllib3_flags_duplicate(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_URLLIB3_DIRTY)
        dups = [f for f in findings if f["check"] == "duplicate_assignment"]
        assert any("DEFAULT_REMOVE_HEADERS_ON_REDIRECT" in f["detail"] for f in dups)
        assert all(f["severity"] == "MEDIUM" for f in dups)


# ---------------------------------------------------------------------------
# Check C — unused imports
# ---------------------------------------------------------------------------

class TestUnusedImportCheck:
    def test_unused_import_detected(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_UNUSED_IMPORT)
        imps = [f for f in findings if f["check"] == "unused_import"]
        assert len(imps) == 1
        assert "re" in imps[0]["detail"]
        assert imps[0]["severity"] == "MEDIUM"

    def test_used_import_not_flagged(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_USED_IMPORT)
        imps = [f for f in findings if f["check"] == "unused_import"]
        assert imps == []

    def test_dirty_urllib3_flags_unused_re_import(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_URLLIB3_DIRTY)
        imps = [f for f in findings if f["check"] == "unused_import"]
        assert any("re" in f["detail"] for f in imps)


# ---------------------------------------------------------------------------
# Composite: dirty patch triggers all three checks
# ---------------------------------------------------------------------------

class TestDirtyPatch:
    def test_all_three_checks_fire_on_dirty_urllib3_patch(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        findings = check_patch(_URLLIB3_DIRTY)
        checks_found = {f["check"] for f in findings}
        assert "empty_hunk" in checks_found
        assert "duplicate_assignment" in checks_found
        assert "unused_import" in checks_found

    def test_finding_structure_valid(self):
        from utilities.autopatcher.patch_hygiene import check_patch
        for finding in check_patch(_URLLIB3_DIRTY):
            assert "severity" in finding
            assert finding["severity"] in ("HIGH", "MEDIUM")
            assert "check" in finding
            assert "detail" in finding
            assert isinstance(finding["detail"], str) and finding["detail"]


# ---------------------------------------------------------------------------
# Pipeline-level: hygiene section appears in report
# ---------------------------------------------------------------------------

class TestPipelineHygieneSection:
    def test_hygiene_section_present_in_report(self):
        from utilities.autopatcher.pipeline import run
        EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"
        vuln_text = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")
        report = run(vulnerability_text=vuln_text, api_key="")
        assert "## Patch Hygiene" in report

    def test_clean_mock_patch_shows_no_issues(self):
        from utilities.autopatcher.pipeline import run
        EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"
        vuln_text = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")
        report = run(vulnerability_text=vuln_text, api_key="")
        start = report.find("## Patch Hygiene")
        end = report.find("---", start)
        section = report[start:end]
        assert "No obvious hygiene issues detected." in section
