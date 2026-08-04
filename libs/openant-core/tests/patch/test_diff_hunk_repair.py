"""Tests for diff_hunk_repair.repair_hunk_headers.

Covers:
  - Minimist-exact corrupt header regression (primary case)
  - Already-correct patch is returned unchanged (no-op guarantee)
  - Multi-hunk with net-positive first hunk: offset propagation
  - Multi-hunk where both count AND offset are wrong (cascaded error)
  - Hunk suffix text preserved verbatim
  - No-newline marker excluded from counts
  - Count-omitted single-line form normalized to explicit count
  - Multi-file: file_delta resets between files
  - Multi-file: hunk-body content resembling a "--- "/"+++ " header must not
    be misparsed as one (F-36, F-41, F-45)
  - Non-diff / empty input passthrough
  - New-file hunk (--- /dev/null) handled
  - RepairResult metadata reflects actual changes
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


from utilities.autopatcher.diff_hunk_repair import repair_hunk_headers, RepairResult


# ---------------------------------------------------------------------------
# Fixtures / shared patch strings
# ---------------------------------------------------------------------------

# Exact minimist patch from the evaluation run — corrupt hunk headers.
# Hunk 1: claims old=7/new=9 (net +2). Actual body: old=8/new=8 (net 0).
# Hunk 2: claims old_start=79/new_start=81. Correct: 79/79 (delta carried wrong).
_MINIMIST_CORRUPT = """\
--- a/index.js
+++ b/index.js
@@ -69,7 +69,9 @@
     function setKey (obj, keys, value) {
         var o = obj;
         for (var i = 0; i < keys.length-1; i++) {
             var key = keys[i];
-            if (key === '__proto__') return;
+            if (key === '__proto__' || key === 'constructor' || key === 'prototype') return;
             if (o[key] === undefined) o[key] = {};
             if (o[key] === Object.prototype || o[key] === Number.prototype
                 || o[key] === String.prototype) o[key] = {};
@@ -79,7 +81,7 @@

         var key = keys[keys.length - 1];
-        if (key === '__proto__') return;
+        if (key === '__proto__' || key === 'constructor' || key === 'prototype') return;
         if (o === Object.prototype || o === Number.prototype
             || o === String.prototype) o = {};
         if (o === Array.prototype) o = [];
"""

# A correctly formed patch — headers must survive unchanged.
# Hunk adds 1 line (net +1): old=4 context+1 removed=5, new=4 context+2 added=6.
_CORRECT_PATCH = """\
--- a/example.py
+++ b/example.py
@@ -10,5 +10,6 @@
 def foo():
     a = 1
     b = 2
-    return a
+    c = a + b
+    return c

"""


# ---------------------------------------------------------------------------
# Primary regression: minimist corrupt headers
# ---------------------------------------------------------------------------

class TestMinimistCorruptHeaders:
    def test_first_hunk_old_count_corrected(self):
        repaired, _ = repair_hunk_headers(_MINIMIST_CORRUPT)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert hunk_lines[0].startswith("@@ -69,8 +69,8 @@"), (
            f"Expected @@ -69,8 +69,8 @@, got: {hunk_lines[0]}"
        )

    def test_second_hunk_new_start_corrected(self):
        repaired, _ = repair_hunk_headers(_MINIMIST_CORRUPT)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        # file_delta after hunk1 = 0 (net zero), so new_start = 79 + 0 = 79
        assert hunk_lines[1].startswith("@@ -79,6 +79,6 @@"), (
            f"Expected @@ -79,6 +79,6 @@, got: {hunk_lines[1]}"
        )

    def test_body_content_unchanged(self):
        repaired, _ = repair_hunk_headers(_MINIMIST_CORRUPT)
        orig_body = [l for l in _MINIMIST_CORRUPT.splitlines() if not l.startswith("@@")]
        repr_body = [l for l in repaired.splitlines() if not l.startswith("@@")]
        assert orig_body == repr_body

    def test_metadata_reports_two_hunks_rewritten(self):
        _, meta = repair_hunk_headers(_MINIMIST_CORRUPT)
        assert meta.normalization_applied is True
        assert meta.hunks_rewritten == 2
        assert meta.files_rewritten == 1


# ---------------------------------------------------------------------------
# No-op guarantee: already-correct patch must be returned byte-for-byte
# ---------------------------------------------------------------------------

class TestNoOpGuarantee:
    def test_correct_patch_is_unchanged(self):
        repaired, meta = repair_hunk_headers(_CORRECT_PATCH)
        assert repaired == _CORRECT_PATCH

    def test_correct_patch_metadata_zero(self):
        _, meta = repair_hunk_headers(_CORRECT_PATCH)
        assert meta.normalization_applied is False
        assert meta.hunks_rewritten == 0
        assert meta.files_rewritten == 0


# ---------------------------------------------------------------------------
# Multi-hunk: net-positive first hunk propagates offset to second hunk
# ---------------------------------------------------------------------------

class TestOffsetPropagation:
    def test_net_positive_first_hunk_shifts_second_hunk_new_start(self):
        # Hunk 1 adds 2 lines (net +2). Hunk 2's new_start must shift by +2.
        patch = (
            "--- a/foo.py\n"
            "+++ b/foo.py\n"
            "@@ -1,3 +1,5 @@\n"  # correct: old=3, new=5 (net +2)
            " line1\n"
            "+added1\n"
            "+added2\n"
            " line2\n"
            " line3\n"
            "@@ -10,3 +12,3 @@\n"  # correct: old_start=10, new_start=12 (+2 from prior)
            " lineA\n"
            " lineB\n"
            " lineC\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        assert meta.normalization_applied is False, (
            "Patch with correct headers must not be modified"
        )

    def test_wrong_second_hunk_offset_is_corrected(self):
        # Hunk 1 is correct (net +2). Hunk 2 has wrong new_start (still +10 not +12).
        patch = (
            "--- a/foo.py\n"
            "+++ b/foo.py\n"
            "@@ -1,3 +1,5 @@\n"
            " line1\n"
            "+added1\n"
            "+added2\n"
            " line2\n"
            " line3\n"
            "@@ -10,3 +10,3 @@\n"  # wrong: new_start should be 12 (10+2)
            " lineA\n"
            " lineB\n"
            " lineC\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert hunk_lines[1].startswith("@@ -10,3 +12,3 @@"), (
            f"Expected @@ -10,3 +12,3 @@, got: {hunk_lines[1]}"
        )
        assert meta.hunks_rewritten == 1


# ---------------------------------------------------------------------------
# Hunk suffix text preserved verbatim
# ---------------------------------------------------------------------------

class TestSuffixPreserved:
    def test_function_name_suffix_preserved(self):
        patch = (
            "--- a/index.js\n"
            "+++ b/index.js\n"
            "@@ -69,7 +69,9 @@ function setKey\n"
            "     function setKey (obj, keys, value) {\n"
            "         var o = obj;\n"
            "         for (var i = 0; i < keys.length-1; i++) {\n"
            "             var key = keys[i];\n"
            "-            if (key === '__proto__') return;\n"
            "+            if (key === '__proto__' || key === 'constructor') return;\n"
            "             if (o[key] === undefined) o[key] = {};\n"
            "             if (o[key] === Object.prototype || o[key] === Number.prototype\n"
            "                 || o[key] === String.prototype) o[key] = {};\n"
        )
        repaired, _ = repair_hunk_headers(patch)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert hunk_lines[0].endswith("@@ function setKey"), (
            f"Suffix not preserved: {hunk_lines[0]!r}"
        )


# ---------------------------------------------------------------------------
# No-newline marker excluded from counts
# ---------------------------------------------------------------------------

class TestNoNewlineMarker:
    def test_no_newline_marker_not_counted(self):
        # 1 context + 1 removed + 1 added + marker = old=2, new=2
        patch = (
            "--- a/file.py\n"
            "+++ b/file.py\n"
            "@@ -5,99 +5,99 @@\n"    # intentionally wrong counts
            " context\n"
            "-old line\n"
            "+new line\n"
            "\\ No newline at end of file\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert hunk_lines[0].startswith("@@ -5,2 +5,2 @@"), (
            f"Got: {hunk_lines[0]}"
        )
        assert meta.hunks_rewritten == 1


# ---------------------------------------------------------------------------
# Count-omitted single-line form: @@ -5 +5 @@ → @@ -5,1 +5,1 @@
# ---------------------------------------------------------------------------

class TestCountOmittedForm:
    def test_omitted_count_normalized_to_explicit(self):
        patch = (
            "--- a/x.py\n"
            "+++ b/x.py\n"
            "@@ -5 +5 @@\n"   # count omitted — means 1
            "-old\n"
            "+new\n"
        )
        repaired, _ = repair_hunk_headers(patch)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert hunk_lines[0].startswith("@@ -5,1 +5,1 @@"), (
            f"Got: {hunk_lines[0]}"
        )


# ---------------------------------------------------------------------------
# Multi-file: file_delta resets between files
# ---------------------------------------------------------------------------

class TestMultiFileDeltaReset:
    def test_delta_does_not_leak_across_files(self):
        # File 1: net +1. File 2's hunk new_start must NOT be shifted by +1.
        patch = (
            "--- a/file1.py\n"
            "+++ b/file1.py\n"
            "@@ -1,2 +1,3 @@\n"   # correct: old=2, new=3, net+1
            " context\n"
            "-removed\n"
            "+added1\n"
            "+added2\n"
            "--- a/file2.py\n"
            "+++ b/file2.py\n"
            "@@ -10,3 +10,3 @@\n"  # correct: new_start=10, not 11
            " a\n"
            " b\n"
            " c\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        assert meta.normalization_applied is False, (
            "Correct headers across two files must not be modified"
        )

    def test_wrong_count_in_second_file_corrected_without_delta_from_first(self):
        # File 1: net +1 (correct). File 2: wrong counts, but no delta from file 1.
        patch = (
            "--- a/file1.py\n"
            "+++ b/file1.py\n"
            "@@ -1,2 +1,3 @@\n"
            " context\n"
            "-removed\n"
            "+added1\n"
            "+added2\n"
            "--- a/file2.py\n"
            "+++ b/file2.py\n"
            "@@ -10,99 +10,99 @@\n"  # wrong counts; no delta from file1
            " a\n"
            " b\n"
            " c\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert hunk_lines[1].startswith("@@ -10,3 +10,3 @@"), (
            f"Got: {hunk_lines[1]}"
        )
        assert meta.hunks_rewritten == 1
        assert meta.files_rewritten == 1

    def test_body_content_resembling_header_does_not_corrupt_second_file(self):
        """F-36 regression: an added line whose own text starts with "++ "
        (raw line "+++ ...") must not be mistaken for a real "+++ " file
        header — doing so would corrupt file_delta/current_file bookkeeping
        and cascade into file2's header being rewritten incorrectly."""
        patch = (
            "--- a/file1.py\n"
            "+++ b/file1.py\n"
            "@@ -1,3 +1,4 @@\n"
            " def f():\n"
            "-    old = 1\n"
            "+++ marker line inside file1's hunk\n"
            "+    new = 2\n"
            "--- a/file2.py\n"
            "+++ b/file2.py\n"
            "@@ -10,3 +10,3 @@\n"
            " a\n"
            " b\n"
            " c\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert len(hunk_lines) == 2, f"Expected 2 hunk headers, got: {hunk_lines}"
        assert hunk_lines[1].startswith("@@ -10,3 +10,3 @@"), (
            f"file2's correct header was corrupted: {hunk_lines[1]}"
        )


# ---------------------------------------------------------------------------
# Hunk-body content that resembles a file header ("--- "/"+++ " prefix)
# ---------------------------------------------------------------------------

class TestHunkBodyContentResemblingFileHeader:
    def test_plus_plus_plus_body_content_not_treated_as_header(self):
        """F-41 regression: a removed/added line whose own text starts with
        "++ " produces the raw line "+++ ...", indistinguishable from a real
        file header by a naive startswith check. It must stay inside the
        hunk body, not be hoisted in front of the (possibly rewritten) hunk
        header."""
        patch = (
            "--- a/example.py\n"
            "+++ b/example.py\n"
            "@@ -1,3 +1,4 @@\n"
            " def f():\n"
            "-    old = 1\n"
            "+++ this added line of code starts with plus plus plus\n"
            "+    new = 2\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        lines = repaired.splitlines(keepends=True)
        idx_marker = next(
            i for i, l in enumerate(lines) if l.startswith("+++ this added line")
        )
        idx_header = next(i for i, l in enumerate(lines) if l.startswith("@@ "))
        assert idx_marker > idx_header, (
            "The '+++ ' body line was hoisted before the hunk header"
        )
        assert meta.files_rewritten <= 1

    def test_dash_dash_dash_body_content_not_treated_as_header(self):
        """F-45 regression: same as above, for a removed line whose own text
        starts with "-- " (raw line "--- ...")."""
        patch = (
            "--- a/example.py\n"
            "+++ b/example.py\n"
            "@@ -1,3 +1,3 @@\n"
            " def f():\n"
            "--- this removed line of code starts with dash dash dash\n"
            "+    return new\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        lines = repaired.splitlines(keepends=True)
        idx_marker = next(
            i for i, l in enumerate(lines) if l.startswith("--- this removed line")
        )
        idx_header = next(i for i, l in enumerate(lines) if l.startswith("@@ "))
        assert idx_marker > idx_header, (
            "The '--- ' body line was hoisted before the hunk header"
        )
        assert meta.files_rewritten <= 1


# ---------------------------------------------------------------------------
# Non-diff / empty input passthrough
# ---------------------------------------------------------------------------

class TestPassthrough:
    def test_empty_string(self):
        repaired, meta = repair_hunk_headers("")
        assert repaired == ""
        assert meta.normalization_applied is False

    def test_whitespace_only(self):
        repaired, meta = repair_hunk_headers("   \n  \n")
        assert meta.normalization_applied is False

    def test_non_diff_content(self):
        text = "# just a comment\nnot a diff at all\n"
        repaired, meta = repair_hunk_headers(text)
        assert repaired == text
        assert meta.normalization_applied is False

    def test_never_raises_on_garbage(self):
        for garbage in ["@@@@", "@@ broken @@\n+line", "---\n+++\n@@bad"]:
            repaired, meta = repair_hunk_headers(garbage)
            assert isinstance(repaired, str)
            assert isinstance(meta, RepairResult)


# ---------------------------------------------------------------------------
# New-file hunk (--- /dev/null)
# ---------------------------------------------------------------------------

class TestNewFileHunk:
    def test_new_file_hunk_counts_only_added_lines(self):
        patch = (
            "--- /dev/null\n"
            "+++ b/newfile.py\n"
            "@@ -0,0 +1,99 @@\n"   # wrong new count
            "+line1\n"
            "+line2\n"
            "+line3\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        # old=0 (no context, no removed), new=3
        assert hunk_lines[0].startswith("@@ -0,0 +1,3 @@"), (
            f"Got: {hunk_lines[0]}"
        )
        assert meta.hunks_rewritten == 1


# ---------------------------------------------------------------------------
# Fenced patches: ``` must not be absorbed into hunk body
# ---------------------------------------------------------------------------

# Regression patch: LLM-generated fenced diff with inverted +/- order and
# wrong hunk header counts — the exact pattern seen in the minimist v2 eval.
# Before the fix, the closing ``` was absorbed into hunk-2's body, inflating
# its count by 1 so that the "repaired" header still said @@ -81,8 +81,8 @@
# (matching the over-counted body), causing git apply to fail with
# "corrupt patch at line 21" even after repair reported "2 hunks fixed".
_FENCED_MINIMIST_V2 = """\
```diff
--- a/index.js
+++ b/index.js
@@ -69,6 +69,8 @@
     function setKey (obj, keys, value) {
         var o = obj;
         for (var i = 0; i < keys.length-1; i++) {
             var key = keys[i];
+            if (key === 'constructor' || key === '__proto__') return;
-            if (key === '__proto__') return;
             if (o[key] === undefined) o[key] = {};
             if (o[key] === Object.prototype || o[key] === Number.prototype
@@ -81,6 +81,6 @@
         }

         var key = keys[keys.length - 1];
+        if (key === 'constructor' || key === '__proto__') return;
-        if (key === '__proto__') return;
         if (o === Object.prototype || o === Number.prototype
             || o === String.prototype) o = {};
         if (o === Array.prototype) o = [];
```"""

def _make_minimist_fixture(tmp_path: Path) -> Path:
    """Init a minimal git repo whose index.js matches, line-for-line, what
    _FENCED_MINIMIST_V2's hunk headers target (lines 69-75 and 81-87) — so
    the repaired patch can be checked against a real `git apply` without
    depending on an externally-managed minimist checkout.
    """
    lines = [f"// filler line {i}" for i in range(1, 69)]
    lines += [
        "    function setKey (obj, keys, value) {",
        "        var o = obj;",
        "        for (var i = 0; i < keys.length-1; i++) {",
        "            var key = keys[i];",
        "            if (key === '__proto__') return;",
        "            if (o[key] === undefined) o[key] = {};",
        "            if (o[key] === Object.prototype || o[key] === Number.prototype",
    ]
    lines += [f"// filler line {i}" for i in range(76, 81)]
    lines += [
        "        }",
        "",
        "        var key = keys[keys.length - 1];",
        "        if (key === '__proto__') return;",
        "        if (o === Object.prototype || o === Number.prototype",
        "            || o === String.prototype) o = {};",
        "        if (o === Array.prototype) o = [];",
    ]
    index_js = "\n".join(lines) + "\n"

    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, capture_output=True)
    (tmp_path / "index.js").write_text(index_js, encoding="utf-8")
    subprocess.run(["git", "add", "index.js"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    return tmp_path


class TestFencedPatch:
    def test_both_hunk_headers_corrected(self):
        repaired, meta = repair_hunk_headers(_FENCED_MINIMIST_V2)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert hunk_lines[0].startswith("@@ -69,7 +69,7 @@"), hunk_lines[0]
        assert hunk_lines[1].startswith("@@ -81,7 +81,7 @@"), hunk_lines[1]

    def test_metadata_two_hunks_rewritten(self):
        _, meta = repair_hunk_headers(_FENCED_MINIMIST_V2)
        assert meta.hunks_rewritten == 2
        assert meta.files_rewritten == 1

    def test_closing_fence_not_counted_as_context(self):
        """``` must not inflate hunk-2 counts — old bug produced @@ -81,8 +81,8 @@."""
        repaired, _ = repair_hunk_headers(_FENCED_MINIMIST_V2)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert not hunk_lines[1].startswith("@@ -81,8"), (
            f"Closing fence was counted as context: {hunk_lines[1]}"
        )

    def test_fences_preserved_in_output(self):
        repaired, _ = repair_hunk_headers(_FENCED_MINIMIST_V2)
        lines = repaired.splitlines()
        assert lines[0].startswith("```"), "Opening fence should be preserved"
        assert lines[-1].strip() == "```", "Closing fence should be preserved"

    def test_context_line_of_triple_backticks_survives_unfenced_patch(self):
        """F-38 regression: a legitimate context line whose content is ```
        (e.g. an unchanged closing Markdown code fence) must not be mistaken
        for the LLM's own wrapper fence and stripped, even when the patch
        has no surrounding ``` wrapper at all."""
        patch = (
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1,3 +1,3 @@\n"
            " intro\n"
            "-old code\n"
            "+new code\n"
            " ```\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        assert repaired.splitlines(keepends=True)[-1] == " ```\n", (
            "Legitimate context line of ``` was stripped as a fake wrapper fence"
        )
        assert meta.normalization_applied is False

    def test_correct_fenced_patch_is_noop(self):
        """A fenced patch with already-correct headers must not be modified."""
        fenced_correct = (
            "```diff\n"
            "--- a/example.py\n"
            "+++ b/example.py\n"
            "@@ -10,5 +10,6 @@\n"
            " def foo():\n"
            "     a = 1\n"
            "     b = 2\n"
            "-    return a\n"
            "+    c = a + b\n"
            "+    return c\n"
            "\n"
            "```"
        )
        repaired, meta = repair_hunk_headers(fenced_correct)
        assert meta.normalization_applied is False
        assert repaired == fenced_correct

    def test_repaired_patch_applies_cleanly(self, tmp_path):
        """End-to-end: repaired fenced patch must pass git apply --check."""
        import re as _re
        repo = _make_minimist_fixture(tmp_path)
        repaired, _ = repair_hunk_headers(_FENCED_MINIMIST_V2)
        # Strip fences the same way patch_applicability does
        lines = repaired.splitlines()
        if lines and _re.match(r"^```", lines[0]):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
        result = subprocess.run(
            ["git", "apply", "--check", "--whitespace=nowarn", "-"],
            input=stripped + "\n",
            cwd=str(repo),
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"git apply failed: {result.stderr.strip()}"


# ---------------------------------------------------------------------------
# Structural rebuild: repeated / interleaved file-header sections
# ---------------------------------------------------------------------------

def _make_three_file_fixture(tmp_path: Path) -> Path:
    """A real git repo whose three files' line content matches, line for
    line, the hunk anchors used by the tests below (lines 100/150 in
    connectionpool.py, line 50 in retry.py, line 10 in poolmanager.py)."""
    cp_lines = [f"// filler {i}\n" for i in range(1, 250)]
    cp_lines[99] = "context_line\n"
    cp_lines[100] = "old_line\n"
    cp_lines[149] = "context2\n"
    cp_lines[150] = "old2\n"
    retry_lines = [f"// r{i}\n" for i in range(1, 100)]
    retry_lines[49] = "r_context\n"
    retry_lines[50] = "r_old\n"
    pool_lines = [f"// p{i}\n" for i in range(1, 30)]
    pool_lines[9] = "p_context\n"
    pool_lines[10] = "p_old\n"

    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, capture_output=True)
    (tmp_path / "src" / "urllib3" / "util").mkdir(parents=True)
    (tmp_path / "src" / "urllib3" / "connectionpool.py").write_text("".join(cp_lines), encoding="utf-8")
    (tmp_path / "src" / "urllib3" / "util" / "retry.py").write_text("".join(retry_lines), encoding="utf-8")
    (tmp_path / "src" / "urllib3" / "poolmanager.py").write_text("".join(pool_lines), encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)
    return tmp_path


def _git_apply_check(repo: Path, patch_text: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "apply", "--check", "--whitespace=nowarn", "-"],
        input=patch_text, cwd=str(repo), capture_output=True, text=True,
    )


class TestOneFile:
    def test_single_file_single_hunk_unaffected_by_grouping(self):
        patch = (
            "--- a/x.py\n+++ b/x.py\n"
            "@@ -1,2 +1,3 @@\n context\n-old\n+new1\n+new2\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        assert repaired == "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,3 @@\n context\n-old\n+new1\n+new2\n"
        assert meta.files_rewritten == 0  # counts were already correct


class TestTwoFiles:
    def test_two_distinct_files_correct_headers_are_noop(self):
        patch = (
            "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
            "--- a/b.py\n+++ b/b.py\n@@ -5,1 +5,1 @@\n-x\n+y\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        assert repaired == patch
        assert meta.normalization_applied is False


class TestThreeFiles:
    def test_three_files_order_and_counts_preserved(self, tmp_path):
        repo = _make_three_file_fixture(tmp_path)
        # Each hunk carries a trailing context line (matching the fixture's
        # stable filler content) in addition to the leading one -- git apply
        # rejects a hunk with context on only one side (verified directly
        # against real git apply, independent of this repair code).
        malformed = (
            "--- a/src/urllib3/connectionpool.py\n+++ b/src/urllib3/connectionpool.py\n"
            "@@ -100,99 +100,99 @@\n context_line\n-old_line\n+new_line\n // filler 102\n"
            "--- a/src/urllib3/util/retry.py\n+++ b/src/urllib3/util/retry.py\n"
            "@@ -50,99 +50,99 @@\n r_context\n-r_old\n+r_new\n // r52\n"
            "--- a/src/urllib3/poolmanager.py\n+++ b/src/urllib3/poolmanager.py\n"
            "@@ -10,99 +10,99 @@\n p_context\n-p_old\n+p_new\n // p12\n"
        )
        repaired, meta = repair_hunk_headers(malformed)
        headers = [l for l in repaired.splitlines() if l.startswith("---") or l.startswith("+++")]
        assert headers == [
            "--- a/src/urllib3/connectionpool.py", "+++ b/src/urllib3/connectionpool.py",
            "--- a/src/urllib3/util/retry.py", "+++ b/src/urllib3/util/retry.py",
            "--- a/src/urllib3/poolmanager.py", "+++ b/src/urllib3/poolmanager.py",
        ]
        assert meta.files_rewritten == 3
        assert meta.hunks_rewritten == 3
        result = _git_apply_check(repo, repaired)
        assert result.returncode == 0, result.stderr


class TestRepeatedFileHeaders:
    def test_same_file_repeated_immediately_consolidates_with_correct_delta(self):
        # Same file, two back-to-back sections (not interleaved with
        # another file) -- hunk2's new_start must reflect hunk1's net
        # delta (+1), not reset to hunk1's own old_start.
        patch = (
            "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new1\n+new2\n"
            "--- a/x.py\n+++ b/x.py\n@@ -10,2 +10,2 @@\n c2\n-old2\n+new3\n"
        )
        repaired, meta = repair_hunk_headers(patch)
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        assert len(hunk_lines) == 2
        assert hunk_lines[0] == "@@ -1,2 +1,3 @@"
        assert hunk_lines[1] == "@@ -10,2 +11,2 @@"  # 10 + delta(+1) = 11
        # exactly one header pair in the output -- consolidated, not duplicated
        assert repaired.count("--- a/x.py") == 1
        assert repaired.count("+++ b/x.py") == 1
        assert meta.normalization_applied is True

    def test_repeated_header_order_and_dedup(self, tmp_path):
        repo = _make_three_file_fixture(tmp_path)
        malformed = (
            "--- a/src/urllib3/connectionpool.py\n+++ b/src/urllib3/connectionpool.py\n"
            "@@ -100,3 +100,4 @@\n context_line\n-old_line\n+new1\n+new2\n // filler 102\n"
            "--- a/src/urllib3/connectionpool.py\n+++ b/src/urllib3/connectionpool.py\n"
            "@@ -150,3 +150,3 @@\n context2\n-old2\n+new2b\n // filler 152\n"
        )
        repaired, meta = repair_hunk_headers(malformed)
        assert repaired.count("--- a/src/urllib3/connectionpool.py") == 1
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        # hunk1: old=3 (context_line + removed + trailing filler), new=4
        #   (context_line + new1 + new2 + trailing filler) -> delta +1.
        # hunk2: new_start = 150 + delta(1) = 151.
        assert hunk_lines == ["@@ -100,3 +100,4 @@", "@@ -150,3 +151,3 @@"]
        result = _git_apply_check(repo, repaired)
        assert result.returncode == 0, result.stderr


class TestInterleavedFileHeaders:
    def test_file_split_by_another_files_section_is_reunified(self, tmp_path):
        repo = _make_three_file_fixture(tmp_path)
        # connectionpool.py's two hunks are split apart by retry.py's
        # section in between -- exactly the urllib3-trace shape.
        malformed = (
            "--- a/src/urllib3/connectionpool.py\n+++ b/src/urllib3/connectionpool.py\n"
            "@@ -100,99 +100,99 @@\n context_line\n-old_line\n+new1\n+new2\n // filler 102\n"
            "--- a/src/urllib3/util/retry.py\n+++ b/src/urllib3/util/retry.py\n"
            "@@ -50,99 +50,99 @@\n r_context\n-r_old\n+r_new\n // r52\n"
            "--- a/src/urllib3/connectionpool.py\n+++ b/src/urllib3/connectionpool.py\n"
            "@@ -150,99 +150,99 @@\n context2\n-old2\n+new2b\n // filler 152\n"
        )
        # Raw form is what real LLM output looked like -- must be rejected
        # as corrupt/malformed by git before repair (sanity check that this
        # fixture actually reproduces the failure mode, not just a strawman).
        raw_check = _git_apply_check(repo, malformed)
        assert raw_check.returncode != 0
        assert "corrupt patch" in raw_check.stderr

        repaired, meta = repair_hunk_headers(malformed)

        # File order = first-appearance order; connectionpool.py's hunks
        # reunified under ONE header pair, in original relative order;
        # retry.py's section follows, unaffected.
        assert repaired.count("--- a/src/urllib3/connectionpool.py") == 1
        assert repaired.count("--- a/src/urllib3/util/retry.py") == 1
        cp_idx = repaired.index("src/urllib3/connectionpool.py")
        retry_idx = repaired.index("src/urllib3/util/retry.py")
        assert cp_idx < retry_idx
        hunk_lines = [l for l in repaired.splitlines() if l.startswith("@@")]
        # connectionpool.py's two hunks, in original order (hunk1 delta +1
        # propagates into hunk2's new_start = 150+1 = 151), THEN retry.py's
        # one hunk (its own delta series, unaffected by connectionpool.py's).
        assert hunk_lines == ["@@ -100,3 +100,4 @@", "@@ -150,3 +151,3 @@", "@@ -50,3 +50,3 @@"]
        assert meta.normalization_applied is True
        assert meta.files_rewritten == 2

        result = _git_apply_check(repo, repaired)
        assert result.returncode == 0, result.stderr


class TestAlreadyValidMultiFileDiff:
    def test_already_valid_three_file_diff_is_untouched(self, tmp_path):
        repo = _make_three_file_fixture(tmp_path)
        valid = (
            "--- a/src/urllib3/connectionpool.py\n+++ b/src/urllib3/connectionpool.py\n"
            "@@ -100,3 +100,4 @@\n context_line\n-old_line\n+new1\n+new2\n // filler 102\n"
            "--- a/src/urllib3/util/retry.py\n+++ b/src/urllib3/util/retry.py\n"
            "@@ -50,3 +50,3 @@\n r_context\n-r_old\n+r_new\n // r52\n"
            "--- a/src/urllib3/poolmanager.py\n+++ b/src/urllib3/poolmanager.py\n"
            "@@ -10,3 +10,3 @@\n p_context\n-p_old\n+p_new\n // p12\n"
        )
        repaired, meta = repair_hunk_headers(valid)
        assert repaired == valid
        assert meta.normalization_applied is False
        result = _git_apply_check(repo, valid)
        assert result.returncode == 0, result.stderr


class TestUrllib3TraceReproduction:
    """The exact malformation this task was written to fix: the model's
    diff for connectionpool.py appears complete, but a second file's
    header (retry.py) is interleaved before connectionpool.py's remaining
    hunk -- reproduced with the exact filenames from the real trace."""

    def test_urllib3_trace_shaped_diff_is_corrupt_before_repair_and_clean_after(self, tmp_path):
        repo = _make_three_file_fixture(tmp_path)
        malformed = (
            "--- a/src/urllib3/connectionpool.py\n"
            "+++ b/src/urllib3/connectionpool.py\n"
            "@@ -100,99 +100,99 @@\n"
            " context_line\n"
            "-old_line\n"
            "+new1\n"
            " // filler 102\n"
            "--- a/src/urllib3/util/retry.py\n"
            "+++ b/src/urllib3/util/retry.py\n"
            "@@ -50,99 +50,99 @@\n"
            " r_context\n"
            "-r_old\n"
            "+r_new\n"
            " // r52\n"
            "--- a/src/urllib3/connectionpool.py\n"
            "+++ b/src/urllib3/connectionpool.py\n"
            "@@ -150,99 +150,99 @@\n"
            " context2\n"
            "-old2\n"
            "+new2b\n"
            " // filler 152\n"
        )
        before = _git_apply_check(repo, malformed)
        assert before.returncode != 0
        assert "corrupt patch" in before.stderr

        repaired, meta = repair_hunk_headers(malformed)
        after = _git_apply_check(repo, repaired)
        assert after.returncode == 0, after.stderr
        assert "corrupt" not in (after.stderr or "")
