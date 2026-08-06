"""Tests for relocation_telemetry.build_relocation_telemetry / summarize.

Covers the four outcomes this telemetry exists to distinguish:
  1. git would already have accepted the patch unaided
  2. Candidate 1 actually rescued applicability
  3. Candidate 1 did nothing (still accepted, or still rejected, either way)
  4. Candidate 1 couldn't relocate safely (still rejected after relocation)

Also confirms it never raises, never mutates the target repo, and returns
None when there's nothing meaningful to measure.
"""

from __future__ import annotations

import subprocess

import pytest

from utilities.autopatcher.relocation_telemetry import (
    HunkRelocationTelemetry,
    RelocationTelemetry,
    build_relocation_telemetry,
    summarize,
)


def _make_git_repo(tmp_path, files: dict):
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


class TestBuildRelocationTelemetryEdgeCases:
    def test_none_for_empty_patch(self, tmp_path):
        assert build_relocation_telemetry("", tmp_path) is None
        assert build_relocation_telemetry("   \n", tmp_path) is None

    def test_none_for_missing_repo_root(self):
        patch = "--- a/f.py\n+++ b/f.py\n@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n"
        assert build_relocation_telemetry(patch, None) is None
        assert build_relocation_telemetry(patch, "") is None

    def test_never_raises_on_garbage_patch(self, tmp_path):
        _make_git_repo(tmp_path, {"f.py": "x\n"})
        result = build_relocation_telemetry("@@@@ not a diff", tmp_path)
        # Either None or a well-formed result -- must not raise either way.
        assert result is None or isinstance(result, RelocationTelemetry)


class TestOutcomeClassification:
    def test_rescued_by_relocation(self, tmp_path):
        """Position drift that git's own search can't recover unaided
        (claim=1, real content far into the file) -- before=False,
        after=True."""
        lines = [f"line{i}\n" for i in range(1, 50)]
        lines[29] = "context_before\n"
        lines[30] = "old_value = 1\n"
        lines[31] = "context_after\n"
        repo = _make_git_repo(tmp_path, {"mod.py": "".join(lines)})
        patch = (
            "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
            " context_before\n-old_value = 1\n+old_value = 2\n context_after\n"
        )
        telemetry = build_relocation_telemetry(patch, repo)
        assert telemetry is not None
        assert telemetry.git_apply_before_relocation is False
        assert telemetry.git_apply_after_relocation is True
        assert len(telemetry.hunks) == 1
        assert telemetry.hunks[0].relocation_performed is True
        assert telemetry.hunks[0].relocation_reason == "unique_match"
        assert "RESCUED" in summarize(telemetry)

    def test_git_already_accepted_unaided(self, tmp_path):
        """A hunk whose claimed position is already correct: git accepts
        it either way -- relocation performs no correction.

        Note: `git apply` requires context on both sides of a change, not
        only the leading side (verified directly; same precedent as
        test_diff_hunk_repair.py's _make_three_file_fixture) -- lines[2]
        supplies that trailing context line.
        """
        lines = [f"line{i}\n" for i in range(1, 10)]
        lines[0] = "ctx\n"
        lines[1] = "old\n"
        repo = _make_git_repo(tmp_path, {"f.py": "".join(lines)})
        patch = "--- a/f.py\n+++ b/f.py\n@@ -1,3 +1,3 @@\n ctx\n-old\n+new\n line3\n"
        telemetry = build_relocation_telemetry(patch, repo)
        assert telemetry is not None
        assert telemetry.git_apply_before_relocation is True
        assert telemetry.git_apply_after_relocation is True
        assert telemetry.hunks[0].relocation_performed is False
        assert "already accepted" in summarize(telemetry)

    def test_ambiguous_content_git_still_applies_unaided_but_we_decline_to_guess(self, tmp_path):
        """Ambiguous content is a real, distinct empirical finding, not a
        hypothetical: since both occurrences are byte-identical, `git
        apply`'s own internal search succeeds by picking ONE of them
        (verified directly) without ever checking uniqueness -- it is not
        "still rejected", it is "already accepted, unvalidated". Our
        relocation correctly reports "ambiguous" and performs no
        correction (does not claim to know which occurrence is meant),
        but that caution costs nothing here precisely because git was
        going to apply somewhere regardless of what we did.

        Both occurrences of the block share the SAME trailing line
        ("trailer") -- both to satisfy git's both-sides-context
        requirement (see note above) and to keep the 3-line anchor
        genuinely ambiguous across both occurrences.
        """
        block = ["context\n", "dup_line\n", "trailer\n"]
        lines = block + [f"filler{i}\n" for i in range(1, 10)] + block
        repo = _make_git_repo(tmp_path, {"f.py": "".join(lines)})
        patch = (
            "--- a/f.py\n+++ b/f.py\n@@ -99,3 +99,3 @@\n"
            " context\n-dup_line\n+new_line\n trailer\n"
        )
        telemetry = build_relocation_telemetry(patch, repo)
        assert telemetry is not None
        assert telemetry.git_apply_before_relocation is True
        assert telemetry.git_apply_after_relocation is True
        assert telemetry.hunks[0].relocation_reason == "ambiguous"
        assert telemetry.hunks[0].relocation_performed is False
        assert "already accepted" in summarize(telemetry)

    def test_still_rejected_both_before_and_after_content_absent(self, tmp_path):
        """Content genuinely absent from the file (not merely
        mispositioned) -- neither git's own search nor our relocation can
        do anything with it; the patch is rejected before AND after.
        This is the "Candidate 1 couldn't relocate safely" outcome."""
        repo = _make_git_repo(tmp_path, {"f.py": "totally unrelated content\n" * 5})
        patch = (
            "--- a/f.py\n+++ b/f.py\n@@ -42,2 +42,2 @@\n"
            " nonexistent_context\n-nonexistent_old\n+new_value\n"
        )
        telemetry = build_relocation_telemetry(patch, repo)
        assert telemetry is not None
        assert telemetry.git_apply_before_relocation is False
        assert telemetry.git_apply_after_relocation is False
        assert telemetry.hunks[0].relocation_reason == "no_match"
        assert telemetry.hunks[0].relocation_performed is False
        assert "still rejected" in summarize(telemetry)

class TestSummarizeNone:
    def test_summarize_none_does_not_raise(self):
        assert "unavailable" in summarize(None)


class TestToDict:
    def test_to_dict_is_json_shaped(self, tmp_path):
        lines = [f"line{i}\n" for i in range(1, 10)]
        lines[0] = "ctx\n"
        lines[1] = "old\n"
        repo = _make_git_repo(tmp_path, {"f.py": "".join(lines)})
        patch = "--- a/f.py\n+++ b/f.py\n@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n"
        telemetry = build_relocation_telemetry(patch, repo)
        d = telemetry.to_dict()
        assert set(d.keys()) == {
            "git_apply_before_relocation", "git_apply_after_relocation", "hunks",
            "source_verification",
        }
        assert isinstance(d["hunks"], list)
        assert isinstance(d["hunks"][0], dict)
        assert d["hunks"][0]["file"] == "f.py"
        assert d["source_verification"]["value"] == "Confirmed"


class TestSourceVerificationField:
    """Evidence Sufficiency Gate (Phase 1) exposure through telemetry --
    see source_verification.py. This is observability only: nothing here
    asserts any effect on git_apply_before/after_relocation or on the
    hunk-level fields, which are computed independently."""

    def test_confirmed_when_unique_match(self, tmp_path):
        lines = [f"line{i}\n" for i in range(1, 10)]
        lines[0] = "ctx\n"
        lines[1] = "old\n"
        repo = _make_git_repo(tmp_path, {"f.py": "".join(lines)})
        patch = "--- a/f.py\n+++ b/f.py\n@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n"
        telemetry = build_relocation_telemetry(patch, repo)
        assert telemetry.source_verification["value"] == "Confirmed"

    def test_unverified_when_no_match(self, tmp_path):
        repo = _make_git_repo(tmp_path, {"f.py": "totally unrelated content\n" * 5})
        patch = (
            "--- a/f.py\n+++ b/f.py\n@@ -42,2 +42,2 @@\n"
            " nonexistent_context\n-nonexistent_old\n+new_value\n"
        )
        telemetry = build_relocation_telemetry(patch, repo)
        assert telemetry.source_verification["value"] == "Unverified"

    def test_summarize_includes_source_verification(self, tmp_path):
        repo = _make_git_repo(tmp_path, {"f.py": "totally unrelated content\n" * 5})
        patch = (
            "--- a/f.py\n+++ b/f.py\n@@ -42,2 +42,2 @@\n"
            " nonexistent_context\n-nonexistent_old\n+new_value\n"
        )
        telemetry = build_relocation_telemetry(patch, repo)
        assert "source verification: Unverified" in summarize(telemetry)


class TestNoMutation:
    def test_does_not_mutate_repo_files(self, tmp_path):
        """check_applicability is --check-only; build_relocation_telemetry
        must never leave the target repo dirty."""
        lines = [f"line{i}\n" for i in range(1, 10)]
        lines[0] = "ctx\n"
        lines[1] = "old\n"
        repo = _make_git_repo(tmp_path, {"f.py": "".join(lines)})
        original = (repo / "f.py").read_text()
        patch = "--- a/f.py\n+++ b/f.py\n@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n"
        build_relocation_telemetry(patch, repo)
        assert (repo / "f.py").read_text() == original
        status = subprocess.run(
            ["git", "status", "--short"], cwd=repo, capture_output=True, text=True
        )
        assert status.stdout.strip() == ""
