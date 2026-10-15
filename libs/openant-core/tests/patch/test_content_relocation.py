"""Unit tests for content_relocation.py's pure text-matching primitives.

End-to-end relocation behavior (wired into repair_hunk_headers) is covered
by tests/patch/test_diff_hunk_repair.py's TestContentRelocation. These tests
isolate the primitives themselves.
"""

from __future__ import annotations

from utilities.autopatcher.content_relocation import (
    find_unique_occurrence,
    locate_occurrence,
    normalize_diff_line,
    normalize_file_line,
    old_side_anchors,
)


class TestNormalizeDiffLine:
    def test_strips_context_marker_and_whitespace(self):
        assert normalize_diff_line("   foo()  \n") == "foo()"

    def test_strips_removed_marker(self):
        assert normalize_diff_line("-old = 1\n") == "old = 1"

    def test_strips_added_marker(self):
        assert normalize_diff_line("+new = 1\n") == "new = 1"

    def test_empty_line_is_safe(self):
        assert normalize_diff_line("\n") == ""


class TestNormalizeFileLine:
    def test_strips_whitespace_only(self):
        assert normalize_file_line("    indented = 1\n") == "indented = 1"

    def test_does_not_strip_leading_dash_content(self):
        """Unlike normalize_diff_line, a raw file line has no marker to
        remove -- a real '--' SQL/Lua comment or '- ' YAML/Markdown list
        item must survive intact."""
        assert normalize_file_line("-- a real sql comment\n") == "-- a real sql comment"
        assert normalize_file_line("- list item\n") == "- list item"

    def test_does_not_strip_leading_plus_content(self):
        assert normalize_file_line("+1 unary literal\n") == "+1 unary literal"


class TestOldSideAnchors:
    def test_keeps_context_and_removed_drops_added(self):
        hunk = [" context\n", "-removed\n", "+added\n"]
        assert old_side_anchors(hunk) == ["context", "removed"]

    def test_excludes_no_newline_marker(self):
        hunk = [" context\n", "-old\n", "+new\n", "\\ No newline at end of file\n"]
        assert old_side_anchors(hunk) == ["context", "old"]

    def test_pure_insertion_hunk_has_no_anchors(self):
        hunk = ["+new1\n", "+new2\n"]
        assert old_side_anchors(hunk) == []


class TestFindUniqueOccurrence:
    def test_finds_unique_exact_match(self):
        file_lines = ["a", "b", "context", "old", "c"]
        assert find_unique_occurrence(["context", "old"], file_lines) == 2

    def test_returns_none_for_no_match(self):
        file_lines = ["a", "b", "c"]
        assert find_unique_occurrence(["nope"], file_lines) is None

    def test_returns_none_for_ambiguous_match(self):
        file_lines = ["x", "y", "x", "y"]
        assert find_unique_occurrence(["x", "y"], file_lines) is None

    def test_returns_none_for_empty_anchors(self):
        assert find_unique_occurrence([], ["a", "b"]) is None

    def test_returns_none_when_anchors_longer_than_file(self):
        assert find_unique_occurrence(["a", "b", "c"], ["a", "b"]) is None

    def test_matches_are_whitespace_normalized(self):
        file_lines = ["    indented_context", "  old_value  "]
        assert find_unique_occurrence(["indented_context", "old_value"], file_lines) == 0

    def test_single_line_anchor_at_start_and_end(self):
        file_lines = ["only_line"]
        assert find_unique_occurrence(["only_line"], file_lines) == 0


class TestLocateOccurrence:
    """locate_occurrence is telemetry-only classification -- these tests
    confirm it agrees with find_unique_occurrence's position on every case
    (same underlying matching), while additionally reporting why."""

    def test_agrees_with_find_unique_occurrence_on_unique_match(self):
        file_lines = ["a", "b", "context", "old", "c"]
        anchors = ["context", "old"]
        pos, reason = locate_occurrence(anchors, file_lines)
        assert pos == find_unique_occurrence(anchors, file_lines) == 2
        assert reason == "unique_match"

    def test_reports_ambiguous_distinctly_from_no_match(self):
        file_lines = ["x", "y", "x", "y"]
        pos, reason = locate_occurrence(["x", "y"], file_lines)
        assert pos is None
        assert reason == "ambiguous"
        assert find_unique_occurrence(["x", "y"], file_lines) is None

    def test_reports_no_match_when_absent(self):
        file_lines = ["a", "b", "c"]
        pos, reason = locate_occurrence(["nope"], file_lines)
        assert pos is None
        assert reason == "no_match"
        assert find_unique_occurrence(["nope"], file_lines) is None

    def test_empty_anchors_reports_no_match(self):
        pos, reason = locate_occurrence([], ["a", "b"])
        assert pos is None
        assert reason == "no_match"

    def test_anchors_longer_than_file_reports_no_match(self):
        pos, reason = locate_occurrence(["a", "b", "c"], ["a", "b"])
        assert pos is None
        assert reason == "no_match"
