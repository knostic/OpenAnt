"""Tests for diff_hunk_repair.reconstruct_hunk_context.

This is the deterministic fix for a distinct failure mode from either
existing mechanism in diff_hunk_repair.py: a hunk can be arithmetically
correct (repair_hunk_headers's count repair) AND positionally correct
(content relocation) and STILL fail real `git apply --check` because its
body itself carries too little surrounding context. Every fixture below
proves real, unmocked `git apply --check` behavior first (establishing the
actual failure, not an assumed one), then proves reconstruction recovers it.

Covers:
  - Exact urllib3 CVE-2023-43804 trace shape (the regression this feature
    was built for): raw fails, repair-alone still fails, reconstruction
    succeeds, semantic delta preserved.
  - Thin-context-only: correct position/counts from the start (never
    touches relocation/count-repair) — proves this is not accidentally
    dependent on either existing mechanism's own corruption case.
  - Ambiguous old-side match: refuses, unchanged.
  - Multi-hunk same file: one hunk expanded, the sibling left byte-for-byte
    untouched.
  - Multi-file: only the file that needs it is touched.
  - Pure insertion / no old-side anchors: fails closed (via a targeted
    check_applicability mock — real `git apply --check` accepts an
    insertion-only hunk regardless of position, so there is no way to make
    one genuinely fail standalone with a real repo; this isolates the
    no-anchors fail-closed branch directly).
  - Neighboring hunks with insufficient headroom: expansion is capped so
    two hunks' added context can never overlap.
  - `\\ No newline at end of file`: trailing expansion is never attempted
    past the marker.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from utilities.autopatcher.diff_hunk_repair import (
    ContextExpansionResult,
    reconstruct_hunk_context,
    repair_hunk_headers,
)
from utilities.autopatcher.diff_parsing import semantic_delta
from utilities.autopatcher.patch_applicability import check_applicability


def _make_repo(tmp_path: Path, files: dict) -> Path:
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, capture_output=True)
    for relpath, content in files.items():
        path = tmp_path / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, capture_output=True, check=True)
    return tmp_path


def _git_apply_check(repo: Path, patch_text: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "apply", "--check", "--whitespace=nowarn", "-"],
        input=patch_text, cwd=str(repo), capture_output=True, text=True,
    )


# ---------------------------------------------------------------------------
# 1. Exact urllib3 CVE-2023-43804 trace shape
# ---------------------------------------------------------------------------

def _urllib3_retry_py() -> str:
    lines = [f"# filler line {i}\n" for i in range(1, 187)]
    lines.append("\n")  # line 187
    lines.append("    #: Default headers to be used for ``remove_headers_on_redirect``\n")  # 188
    lines.append('    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])\n')  # 189
    lines.append("\n")  # 190
    lines.append("    #: Default maximum backoff time.\n")  # 191
    lines.append("    DEFAULT_BACKOFF_MAX = 120\n")  # 192
    return "".join(lines)


# The exact malformed shape from the real trace: claimed old/new count of 3
# for a body that is actually 2 old-side/2 new-side lines, at a start line
# (187) drifted from the content's real position (188).
_URLLIB3_MALFORMED = (
    "--- a/src/urllib3/util/retry.py\n"
    "+++ b/src/urllib3/util/retry.py\n"
    "@@ -187,3 +187,3 @@\n"
    "     #: Default headers to be used for ``remove_headers_on_redirect``\n"
    '-    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Authorization"])\n'
    '+    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(["Cookie", "Authorization"])\n'
)


class TestUrllib3TraceRegression:
    def test_raw_malformed_patch_fails_real_git_apply(self, tmp_path):
        repo = _make_repo(tmp_path, {"src/urllib3/util/retry.py": _urllib3_retry_py()})
        result = _git_apply_check(repo, _URLLIB3_MALFORMED)
        assert result.returncode != 0

    def test_existing_repair_alone_still_fails_applicability(self, tmp_path):
        """Characterizes the existing (pre-reconstruction) behavior: count
        repair + content relocation both succeed, and the result is STILL
        not applicable. This is the exact gap reconstruct_hunk_context
        exists to close — must be proven, not assumed."""
        repo = _make_repo(tmp_path, {"src/urllib3/util/retry.py": _urllib3_retry_py()})
        repaired, meta = repair_hunk_headers(_URLLIB3_MALFORMED, repo_root=repo)

        # Count repair: body is 1 context + 1 removed + 1 added -> old=2, new=2.
        hunk_line = next(l for l in repaired.splitlines() if l.startswith("@@"))
        assert hunk_line.startswith("@@ -188,2 +188,2 @@"), hunk_line
        # Relocation: found the unique real position (188), corrected from 187.
        assert meta.hunks_relocated == 1
        assert meta.relocations[0].relocation_reason == "unique_match"
        assert meta.relocations[0].original_hunk_start == 187
        assert meta.relocations[0].relocated_hunk_start == 188

        result = check_applicability(repaired, repo)
        assert result["applicable"] is False, (
            "This characterizes the actual gap: a correctly-repaired-and-"
            "relocated hunk can still fail git apply --check due to "
            "insufficient surrounding context."
        )

    def test_reconstruction_succeeds_where_repair_alone_does_not(self, tmp_path):
        repo = _make_repo(tmp_path, {"src/urllib3/util/retry.py": _urllib3_retry_py()})
        repaired, _ = repair_hunk_headers(_URLLIB3_MALFORMED, repo_root=repo)

        reconstructed, expansion = reconstruct_hunk_context(repaired, repo)

        assert expansion.succeeded is True
        assert expansion.hunks_expanded == 1
        result = check_applicability(reconstructed, repo)
        assert result["applicable"] is True, result["stderr"]

    def test_semantic_delta_unchanged(self, tmp_path):
        repo = _make_repo(tmp_path, {"src/urllib3/util/retry.py": _urllib3_retry_py()})
        repaired, _ = repair_hunk_headers(_URLLIB3_MALFORMED, repo_root=repo)
        reconstructed, expansion = reconstruct_hunk_context(repaired, repo)
        assert expansion.succeeded is True
        assert semantic_delta(_URLLIB3_MALFORMED) == semantic_delta(reconstructed)

    def test_added_context_is_verbatim_repository_content(self, tmp_path):
        repo = _make_repo(tmp_path, {"src/urllib3/util/retry.py": _urllib3_retry_py()})
        repaired, _ = repair_hunk_headers(_URLLIB3_MALFORMED, repo_root=repo)
        reconstructed, expansion = reconstruct_hunk_context(repaired, repo)
        assert expansion.succeeded is True
        real_lines = _urllib3_retry_py().splitlines()
        context_lines = [
            l[1:] for l in reconstructed.splitlines()
            if l.startswith(" ") and not l.startswith("@@")
        ]
        for line in context_lines:
            assert line in real_lines


# ---------------------------------------------------------------------------
# 2. Thin-context-only: correct position/counts from the start
# ---------------------------------------------------------------------------

class TestThinContextOnly:
    """Proves reconstruction fires on context-thinness ALONE — the header
    here is never touched by repair_hunk_headers (position and counts are
    already exactly correct), isolating this from the urllib3 fixture's
    count/position corruption."""

    def _repo(self, tmp_path):
        lines = [f"line {i}\n" for i in range(1, 60)]
        lines[29] = "target_value = 1\n"  # 1-indexed line 30
        return _make_repo(tmp_path, {"f.py": "".join(lines)})

    def _one_sided_patch(self) -> str:
        # Correct start (29) and correct counts (2,2) for a 1-context+1-
        # removed+1-added body -- only WRONG in that it has no trailing
        # context, which real git apply requires even at an otherwise
        # exactly-correct position (verified directly below).
        return (
            "--- a/f.py\n+++ b/f.py\n@@ -29,2 +29,2 @@\n"
            " line 29\n-target_value = 1\n+target_value = 2\n"
        )

    def test_repair_hunk_headers_is_a_noop_here(self, tmp_path):
        """Sanity check that this fixture isolates context-thinness: header
        repair must report nothing to fix."""
        repo = self._repo(tmp_path)
        _, meta = repair_hunk_headers(self._one_sided_patch(), repo_root=repo)
        assert meta.normalization_applied is False
        assert meta.hunks_relocated == 0

    def test_one_sided_context_fails_real_git_apply(self, tmp_path):
        repo = self._repo(tmp_path)
        result = _git_apply_check(repo, self._one_sided_patch())
        assert result.returncode != 0

    def test_reconstruction_adds_trailing_context_and_applies(self, tmp_path):
        repo = self._repo(tmp_path)
        reconstructed, expansion = reconstruct_hunk_context(self._one_sided_patch(), repo)
        assert expansion.succeeded is True
        assert expansion.hunks_expanded == 1
        result = check_applicability(reconstructed, repo)
        assert result["applicable"] is True, result["stderr"]

    def test_semantic_delta_unchanged(self, tmp_path):
        repo = self._repo(tmp_path)
        original = self._one_sided_patch()
        reconstructed, expansion = reconstruct_hunk_context(original, repo)
        assert expansion.succeeded is True
        assert semantic_delta(original) == semantic_delta(reconstructed)


# ---------------------------------------------------------------------------
# 3. Ambiguous old-side match -- refuses, unchanged
# ---------------------------------------------------------------------------

class TestAmbiguousMatch:
    def test_reconstruction_refuses_on_ambiguous_anchor(self, tmp_path):
        # The old-side content (context + removed) occurs twice in the file.
        block = ["context\n", "dup_line\n"]
        lines = block + [f"filler{i}\n" for i in range(1, 10)] + block
        repo = _make_repo(tmp_path, {"f.py": "".join(lines)})
        # Deliberately no trailing context -- this hunk is also context-
        # starved, so reconstruction WOULD attempt it if the match weren't
        # ambiguous.
        patch = (
            "--- a/f.py\n+++ b/f.py\n@@ -1,2 +1,2 @@\n"
            " context\n-dup_line\n+new_line\n"
        )
        result = _git_apply_check(repo, patch)
        assert result.returncode != 0  # sanity: this really is failing standalone

        reconstructed, expansion = reconstruct_hunk_context(patch, repo)
        assert expansion.succeeded is False
        assert expansion.skipped_reason == "anchor_ambiguous"
        assert reconstructed == patch  # completely unchanged


# ---------------------------------------------------------------------------
# 4. Multi-hunk, same file: one needs expansion, one does not
# ---------------------------------------------------------------------------

class TestMultiHunkSameFile:
    def _repo(self, tmp_path):
        lines = [f"line {i}\n" for i in range(1, 100)]
        lines[9] = "alpha_value = 1\n"     # 1-indexed line 10 -- gets thin-context hunk
        lines[69] = "beta_before\n"        # line 70
        lines[70] = "beta_value = 1\n"     # line 71
        lines[71] = "beta_after\n"         # line 72
        return _make_repo(tmp_path, {"f.py": "".join(lines)})

    def _patch(self) -> str:
        starved_hunk = (
            "@@ -9,2 +9,2 @@\n"
            " line 9\n-alpha_value = 1\n+alpha_value = 2\n"
        )
        sufficient_hunk = (
            "@@ -70,3 +70,3 @@\n"
            " beta_before\n-beta_value = 1\n+beta_value = 2\n beta_after\n"
        )
        return "--- a/f.py\n+++ b/f.py\n" + starved_hunk + sufficient_hunk

    def test_whole_patch_fails_before_reconstruction(self, tmp_path):
        repo = self._repo(tmp_path)
        result = _git_apply_check(repo, self._patch())
        assert result.returncode != 0

    def test_sufficient_hunk_already_applies_standalone(self, tmp_path):
        """Sanity check for the fixture itself: the second hunk alone must
        already be applicable, isolating the first hunk as the sole cause
        of the whole-patch failure."""
        repo = self._repo(tmp_path)
        sufficient_only = (
            "--- a/f.py\n+++ b/f.py\n"
            "@@ -70,3 +70,3 @@\n"
            " beta_before\n-beta_value = 1\n+beta_value = 2\n beta_after\n"
        )
        result = check_applicability(sufficient_only, repo)
        assert result["applicable"] is True

    def test_reconstruction_succeeds_and_leaves_sufficient_hunk_untouched(self, tmp_path):
        repo = self._repo(tmp_path)
        original = self._patch()
        reconstructed, expansion = reconstruct_hunk_context(original, repo)

        assert expansion.succeeded is True
        assert expansion.hunks_expanded == 1
        assert expansion.hunks_unchanged == 1

        # The already-sufficient hunk's header+body bytes are byte-for-byte
        # identical in the output.
        sufficient_hunk_text = (
            "@@ -70,3 +70,3 @@\n"
            " beta_before\n-beta_value = 1\n+beta_value = 2\n beta_after\n"
        )
        assert sufficient_hunk_text in reconstructed

        result = check_applicability(reconstructed, repo)
        assert result["applicable"] is True, result["stderr"]

    def test_semantic_delta_unchanged(self, tmp_path):
        repo = self._repo(tmp_path)
        original = self._patch()
        reconstructed, expansion = reconstruct_hunk_context(original, repo)
        assert expansion.succeeded is True
        assert semantic_delta(original) == semantic_delta(reconstructed)


# ---------------------------------------------------------------------------
# 5. Multi-file: only one file needs reconstruction
# ---------------------------------------------------------------------------

class TestMultiFile:
    def _repo(self, tmp_path):
        a_lines = [f"a{i}\n" for i in range(1, 60)]
        a_lines[29] = "a_target = 1\n"  # line 30 -- context-starved hunk
        b_lines = [f"b{i}\n" for i in range(1, 60)]
        b_lines[29] = "b_before\n"
        b_lines[30] = "b_target = 1\n"
        b_lines[31] = "b_after\n"
        return _make_repo(tmp_path, {"a.py": "".join(a_lines), "b.py": "".join(b_lines)})

    def _patch(self) -> str:
        a_section = (
            "--- a/a.py\n+++ b/a.py\n@@ -29,2 +29,2 @@\n"
            " a29\n-a_target = 1\n+a_target = 2\n"
        )
        b_section = (
            "--- a/b.py\n+++ b/b.py\n@@ -30,3 +30,3 @@\n"
            " b_before\n-b_target = 1\n+b_target = 2\n b_after\n"
        )
        return a_section + b_section

    def test_reconstruction_touches_only_the_needed_file(self, tmp_path):
        repo = self._repo(tmp_path)
        original = self._patch()
        b_section_text = (
            "--- a/b.py\n+++ b/b.py\n@@ -30,3 +30,3 @@\n"
            " b_before\n-b_target = 1\n+b_target = 2\n b_after\n"
        )

        reconstructed, expansion = reconstruct_hunk_context(original, repo)

        assert expansion.succeeded is True
        assert expansion.hunks_expanded == 1
        assert expansion.hunks_unchanged == 1
        # b.py's entire section is untouched, byte-for-byte.
        assert b_section_text in reconstructed
        # a.py's header pair is preserved; only its hunk body/header changed.
        assert "--- a/a.py\n+++ b/a.py\n" in reconstructed

        result = check_applicability(reconstructed, repo)
        assert result["applicable"] is True, result["stderr"]

    def test_semantic_delta_unchanged(self, tmp_path):
        repo = self._repo(tmp_path)
        original = self._patch()
        reconstructed, expansion = reconstruct_hunk_context(original, repo)
        assert expansion.succeeded is True
        assert semantic_delta(original) == semantic_delta(reconstructed)


# ---------------------------------------------------------------------------
# 6. Pure insertion / no old-side anchors -- explicit fail-closed
#
# Real `git apply --check` accepts a zero-context insertion-only hunk at
# essentially any in-bounds position (there is no old-side content to
# verify it against) -- verified directly, empirically, before writing this
# test: there is no way to make a real insertion-only hunk genuinely fail
# `check_applicability` standalone. This test therefore isolates the
# no-old-side-anchors fail-closed branch directly, via a targeted mock of
# patch_applicability.check_applicability (reconstruct_hunk_context imports
# it lazily at call time, specifically so a mock like this one is picked up
# correctly) -- the same technique test_pipeline_retry.py already uses
# throughout to control applicability outcomes deterministically. No LLM,
# no network.
# ---------------------------------------------------------------------------

class TestPureInsertionNoAnchor:
    def test_fails_closed_when_a_context_starved_hunk_has_no_anchors(self, tmp_path):
        lines = [f"line {i}\n" for i in range(1, 30)]
        repo = _make_repo(tmp_path, {"f.py": "".join(lines)})
        # A pure-insertion hunk (old_count == 0, old_start != 0) has no
        # ' '/'-' body lines at all -- old_side_anchors() is empty.
        patch = "--- a/f.py\n+++ b/f.py\n@@ -10,0 +11,2 @@\n+inserted1\n+inserted2\n"

        with mock.patch(
            "utilities.autopatcher.patch_applicability.check_applicability",
            return_value={"applicable": False, "skipped": False, "stderr": "forced for test",
                          "exit_code": 1, "skipped_reason": None, "error": None},
        ):
            reconstructed, expansion = reconstruct_hunk_context(patch, repo)

        assert expansion.succeeded is False
        assert expansion.skipped_reason == "no_old_side_anchors"
        assert reconstructed == patch


# ---------------------------------------------------------------------------
# 7. Neighboring hunks / insufficient headroom -- never overlap
# ---------------------------------------------------------------------------

class TestNeighboringHunksHeadroom:
    def test_expansion_never_overlaps_a_close_neighboring_hunk(self, tmp_path):
        # Two single-line changes only 3 lines apart (positions 10 and 14)
        # -- a naive fixed 3-line-each-side expansion would have them
        # overlap and corrupt each other's context. Verified directly
        # (independent of this test) that the outcome is deterministic: the
        # 3-line gap between the two hunks' core ranges splits floor(3/2)=1
        # to each side, so hunk 1 gets 3 lines leading (bounded only by the
        # file start) + 1 line trailing, and hunk 2 gets 1 line leading + 3
        # lines trailing (bounded only by the file end) -- never both
        # sides hitting the 3-line cap toward each other.
        lines = [f"line {i}\n" for i in range(1, 30)]
        lines[9] = "first_target = 1\n"   # line 10
        lines[13] = "second_target = 1\n"  # line 14
        repo = _make_repo(tmp_path, {"f.py": "".join(lines)})
        patch = (
            "--- a/f.py\n+++ b/f.py\n"
            "@@ -10,1 +10,1 @@\n-first_target = 1\n+first_target = 2\n"
            "@@ -14,1 +14,1 @@\n-second_target = 1\n+second_target = 2\n"
        )
        result = _git_apply_check(repo, patch)
        assert result.returncode != 0  # sanity: really does fail as-is

        reconstructed, expansion = reconstruct_hunk_context(patch, repo)

        assert expansion.succeeded is True
        assert expansion.hunks_expanded == 2

        hunk_headers = [l for l in reconstructed.splitlines() if l.startswith("@@")]
        assert hunk_headers == ["@@ -7,5 +7,5 @@", "@@ -13,5 +13,5 @@"], hunk_headers

        # Explicit non-overlap proof, independent of the exact header
        # strings above: derive each hunk's covered old-side line range and
        # assert they are disjoint.
        def _old_range(header):
            m = re.match(r"@@ -(\d+),(\d+) ", header)
            start, count = int(m.group(1)), int(m.group(2))
            return start, start + count - 1

        (start1, end1), (start2, end2) = _old_range(hunk_headers[0]), _old_range(hunk_headers[1])
        assert end1 < start2, f"hunks overlap: [{start1},{end1}] vs [{start2},{end2}]"

        result = check_applicability(reconstructed, repo)
        assert result["applicable"] is True, result["stderr"]
        assert semantic_delta(patch) == semantic_delta(reconstructed)


# ---------------------------------------------------------------------------
# 8. `\ No newline at end of file` -- never append context past the marker
# ---------------------------------------------------------------------------

class TestNoNewlineMarkerBoundary:
    def test_trailing_expansion_never_appends_past_the_marker(self, tmp_path):
        lines = [f"line {i}\n" for i in range(1, 30)]
        # The file's true last line has no trailing newline.
        content = "".join(lines) + "last_line_no_newline"
        repo = _make_repo(tmp_path, {"g.py": content})

        # Correct position/counts, only leading context, hunk ends in the
        # no-newline marker -- there is no real trailing content to add.
        patch = (
            "--- a/g.py\n+++ b/g.py\n@@ -29,2 +29,2 @@\n"
            " line 29\n-last_line_no_newline\n+last_line_changed_no_newline\n"
            "\\ No newline at end of file\n"
        )
        result = _git_apply_check(repo, patch)
        assert result.returncode != 0  # sanity: fails as-is (verified empirically)

        reconstructed, expansion = reconstruct_hunk_context(patch, repo)

        # Deterministic outcome, verified directly: there is no real
        # trailing content available past the marker (it's the file's true
        # last line), and leading-only context is never sufficient on its
        # own -- even at the 3-line cap -- so this shape is unfixable and
        # must fail closed with the original patch completely unchanged.
        assert expansion.succeeded is False
        assert expansion.skipped_reason == "hunk_still_not_applicable_after_expansion"
        assert reconstructed == patch

        # Meaningful (non-tautological) invariant: if the marker appears at
        # all, it must be the LAST line -- nothing may follow it.
        lines_out = reconstructed.splitlines(keepends=True)
        for i, l in enumerate(lines_out):
            if l.rstrip("\n") == "\\ No newline at end of file":
                assert i == len(lines_out) - 1, (
                    "No content may follow the no-newline marker"
                )


# ---------------------------------------------------------------------------
# 9. Production semantic-delta safety gate -- tests the gate itself, not
# just that semantic_delta happens to agree on successful fixtures.
# ---------------------------------------------------------------------------

class TestSemanticDeltaSafetyGate:
    def test_refuses_reconstruction_when_semantic_delta_mismatches(self, tmp_path):
        """Forces semantic_delta(clean) != semantic_delta(reconstructed) via
        a targeted mock of the exact function reconstruct_hunk_context
        calls (imported lazily, same technique as check_applicability
        elsewhere in this file) and proves the production fail-closed
        branch itself fires -- not merely that the two happen to agree in
        the ordinary case."""
        lines = [f"line {i}\n" for i in range(1, 60)]
        lines[29] = "target_value = 1\n"  # 1-indexed line 30
        repo = _make_repo(tmp_path, {"f.py": "".join(lines)})
        # This exact fixture (correct position/counts, one-sided context)
        # is proven to reconstruct successfully in TestThinContextOnly --
        # the mock below is the ONLY reason it's refused here.
        patch = (
            "--- a/f.py\n+++ b/f.py\n@@ -29,2 +29,2 @@\n"
            " line 29\n-target_value = 1\n+target_value = 2\n"
        )

        with mock.patch(
            "utilities.autopatcher.diff_parsing.semantic_delta",
            side_effect=[
                {"f.py": (["+target_value = 2"], ["-target_value = 1"])},
                {"f.py": (["+SOMETHING_ELSE"], ["-target_value = 1"])},
            ],
        ):
            reconstructed, expansion = reconstruct_hunk_context(patch, repo)

        assert expansion.succeeded is False
        assert expansion.skipped_reason == "semantic_delta_mismatch"
        assert reconstructed == patch  # never adopted -- exact original returned


# ---------------------------------------------------------------------------
# 10. File-deletion patches ("+++ /dev/null") -- explicit fail-closed
#
# semantic_delta cannot see a deletion section's removed lines at all
# (diff_parsing.parse_diff never recognises "+++ /dev/null" as a file
# header -- see diff_hunk_repair.py's module comment), so reconstruction
# refuses the whole attempt atomically before ever inspecting a hunk -- it
# does not rely on semantic_delta to detect this case.
# ---------------------------------------------------------------------------

class TestFileDeletionUnsupported:
    def test_file_deletion_hunk_refuses_reconstruction(self, tmp_path):
        repo = _make_repo(tmp_path, {"old.py": "line1\nline2\n"})
        # A real file-deletion diff shape, with wrong counts -- would
        # otherwise be a genuine reconstruction candidate if file-deletion
        # sections weren't explicitly rejected first.
        patch = "--- a/old.py\n+++ /dev/null\n@@ -1,99 +0,0 @@\n-line1\n-line2\n"

        reconstructed, expansion = reconstruct_hunk_context(patch, repo)

        assert expansion.succeeded is False
        assert expansion.skipped_reason == "unsupported_file_deletion"
        assert reconstructed == patch  # byte-for-byte identical to input

    def test_file_deletion_section_blocks_reconstruction_of_other_files_too(self, tmp_path):
        """Atomicity: a deletion section anywhere in the patch must refuse
        the WHOLE attempt, even when a different file in the same patch
        would otherwise be successfully reconstructed on its own."""
        a_lines = [f"a{i}\n" for i in range(1, 60)]
        a_lines[29] = "a_target = 1\n"  # line 30 -- genuinely context-starved
        repo = _make_repo(tmp_path, {
            "a.py": "".join(a_lines),
            "old.py": "line1\nline2\n",
        })
        a_section = (
            "--- a/a.py\n+++ b/a.py\n@@ -29,2 +29,2 @@\n"
            " a29\n-a_target = 1\n+a_target = 2\n"
        )
        deletion_section = "--- a/old.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-line1\n-line2\n"
        patch = a_section + deletion_section

        reconstructed, expansion = reconstruct_hunk_context(patch, repo)

        assert expansion.succeeded is False
        assert expansion.skipped_reason == "unsupported_file_deletion"
        assert reconstructed == patch
        assert expansion.hunks_expanded == 0
