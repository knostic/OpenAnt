"""Threshold matrix for language selection policy.

The load-bearing property here is rule 4: the dominant language is always
selected, so a selection can never come back empty for a repo that has any
supported source. That is what makes multi-language scanning strictly a
superset of the old single-language behaviour.
"""

import pytest

from core.language_selection import (
    DEFAULT_MIN_FILES,
    DEFAULT_MIN_SHARE,
    UnknownLanguageError,
    select_languages,
)


class TestThresholds:
    def test_language_above_both_thresholds_is_selected(self):
        sel = select_languages({"python": 100, "go": 50})
        assert sel.selected == ["python", "go"]
        assert sel.excluded == {}

    def test_language_below_absolute_floor_is_excluded(self):
        # go has 2 files; floor is max(5, ceil(0.02*102)) = 5.
        sel = select_languages({"python": 100, "go": 2})
        assert sel.selected == ["python"]
        assert "go" in sel.excluded
        assert "below threshold" in sel.excluded["go"]

    def test_language_below_share_floor_is_excluded(self):
        # The plan's worked case: 2 files out of ~5000.
        # threshold = max(5, ceil(0.02*5002)) = 101.
        sel = select_languages({"python": 5000, "zig": 2})
        assert sel.selected == ["python"]
        assert "zig" in sel.excluded
        assert "0.04%" in sel.excluded["zig"]
        assert "101" in sel.excluded["zig"]

    def test_language_clearing_floor_but_not_share_is_excluded(self):
        # go has 10 files (> min_files=5) but 10/5010 = 0.2% < 2%.
        sel = select_languages({"python": 5000, "go": 10})
        assert sel.selected == ["python"]
        assert "go" in sel.excluded

    def test_exact_threshold_is_inclusive(self):
        # total=105, threshold = max(5, ceil(2.1)) = 5. go has exactly 5.
        sel = select_languages({"python": 100, "go": 5})
        assert sel.selected == ["python", "go"]

    def test_custom_thresholds_are_honoured(self):
        sel = select_languages({"python": 100, "go": 2}, min_files=1, min_share=0.0)
        assert sel.selected == ["python", "go"]

    def test_defaults_are_what_the_module_documents(self):
        assert DEFAULT_MIN_FILES == 5
        assert DEFAULT_MIN_SHARE == 0.02


class TestDominantAlwaysSelected:
    """Rule 4 — the guarantee that selection is never empty."""

    def test_tiny_repo_still_scans(self):
        """A 3-file repo is below min_files, but must still be scanned."""
        sel = select_languages({"python": 3})
        assert sel.selected == ["python"]
        assert sel.primary == "python"

    def test_single_file_repo_still_scans(self):
        sel = select_languages({"zig": 1})
        assert sel.selected == ["zig"]

    def test_selection_is_never_empty(self):
        for counts in ({"python": 1}, {"go": 2, "c": 1}, {"php": 4, "ruby": 4}):
            assert select_languages(counts).selected, f"empty selection for {counts}"


class TestPrimary:
    def test_primary_is_the_dominant_language(self):
        assert select_languages({"python": 10, "go": 3}).primary == "python"

    def test_primary_ties_break_alphabetically(self):
        """Deterministic, and matches the Go side's Ranked()."""
        assert select_languages({"python": 5, "javascript": 5}).primary == "javascript"
        assert select_languages({"zig": 7, "c": 7}).primary == "c"

    def test_primary_is_always_in_selected(self):
        sel = select_languages({"python": 5000, "zig": 2})
        assert sel.primary in sel.selected


class TestExplicitInclude:
    def test_include_bypasses_thresholds(self):
        """A language the policy would drop is parsed when named explicitly."""
        sel = select_languages({"python": 5000, "zig": 2}, include=["python", "zig"])
        assert sel.selected == ["python", "zig"]

    def test_include_can_narrow_below_the_dominant(self):
        """Explicit request wins even over rule 4 — the user named the set."""
        sel = select_languages({"python": 100, "go": 50}, include=["go"])
        assert sel.selected == ["go"]
        assert sel.primary == "go", "primary must name a language actually parsed"
        assert "python" in sel.excluded

    def test_include_is_case_and_whitespace_insensitive(self):
        sel = select_languages({"python": 10, "go": 5}, include=[" Python ", "GO"])
        assert sel.selected == ["python", "go"]

    def test_include_preserves_detection_order_not_argument_order(self):
        sel = select_languages({"python": 100, "go": 50}, include=["go", "python"])
        assert sel.selected == ["python", "go"]

    def test_unknown_language_raises_and_lists_supported(self):
        with pytest.raises(UnknownLanguageError) as exc:
            select_languages({"python": 10}, include=["python", "cobol"])
        assert "cobol" in str(exc.value)
        assert "python" in str(exc.value)

    def test_requested_but_absent_language_is_recorded_not_parsed(self):
        """Asking for Go in a repo with no Go must not spawn a Go parse."""
        sel = select_languages({"python": 10}, include=["python", "go"])
        assert sel.selected == ["python"]
        assert "no source files found" in sel.excluded["go"]


class TestAllLanguages:
    def test_selects_everything_detected(self):
        sel = select_languages({"python": 5000, "zig": 2, "go": 1}, all_languages=True)
        assert sel.selected == ["python", "zig", "go"]
        assert sel.excluded == {}

    def test_ordered_by_descending_count(self):
        sel = select_languages({"go": 1, "python": 9, "c": 5}, all_languages=True)
        assert sel.selected == ["python", "c", "go"]


class TestErrors:
    def test_empty_counts_raises(self):
        with pytest.raises(ValueError, match="No languages detected"):
            select_languages({})


class TestSelectionShape:
    def test_counts_are_carried_through_including_excluded(self):
        sel = select_languages({"python": 5000, "zig": 2})
        assert sel.counts == {"python": 5000, "zig": 2}

    def test_is_multi_flag(self):
        assert not select_languages({"python": 10}).is_multi
        assert select_languages({"python": 10, "go": 10}).is_multi

    def test_caller_supplied_unordered_counts_are_re_sorted(self):
        """Do not depend on the caller having preserved detection order."""
        sel = select_languages({"go": 1, "python": 100}, all_languages=True)
        assert sel.primary == "python"
        assert sel.selected == ["python", "go"]
