"""Unit tests for source_verification.classify_source_verification.

Evidence Sufficiency Gate (Phase 1) -- a deterministic Trust Signal derived
purely from diff_hunk_repair.HunkRelocationRecord-shaped data. These tests
exercise the classification logic in isolation, without going through the
real repair pass or git.
"""

from __future__ import annotations

from dataclasses import dataclass

from utilities.autopatcher.source_verification import classify_source_verification


@dataclass
class _Record:
    """Minimal stand-in for diff_hunk_repair.HunkRelocationRecord --
    classify_source_verification only reads .file/.relocation_reason/
    .relocation_attempted by attribute, so a plain matching-shape object
    is enough and keeps this test independent of diff_hunk_repair."""
    file: str
    relocation_reason: str
    relocation_attempted: bool = True


def _unique(file="f.py"):
    return _Record(file=file, relocation_reason="unique_match")


def _ambiguous(file="f.py"):
    return _Record(file=file, relocation_reason="ambiguous")


def _no_match(file="f.py"):
    return _Record(file=file, relocation_reason="no_match")


def _skipped(file="f.py"):
    return _Record(file=file, relocation_reason="skipped", relocation_attempted=False)


class TestConfirmed:
    def test_single_unique_match(self):
        sig = classify_source_verification([_unique()])
        assert sig["value"] == "Confirmed"
        assert "1 hunk(s)" in sig["notes"]

    def test_multiple_unique_matches_across_files(self):
        sig = classify_source_verification([_unique("a.py"), _unique("b.py")])
        assert sig["value"] == "Confirmed"


class TestNotVerified:
    def test_empty_list(self):
        sig = classify_source_verification([])
        assert sig["value"] == "Not Verified"

    def test_none_input(self):
        sig = classify_source_verification(None)
        assert sig["value"] == "Not Verified"

    def test_all_skipped(self):
        sig = classify_source_verification([_skipped(), _skipped()])
        assert sig["value"] == "Not Verified"

    def test_never_raises_on_malformed_input(self):
        # Objects missing the expected attributes must degrade to
        # "Not Verified", never crash.
        sig = classify_source_verification([object(), 42, "not a record"])
        assert sig["value"] == "Not Verified"


class TestPositionUnconfirmed:
    def test_single_ambiguous(self):
        sig = classify_source_verification([_ambiguous()])
        assert sig["value"] == "Position Unconfirmed"

    def test_ambiguous_alongside_unique_match(self):
        """A real, uniquely-matched hunk elsewhere in the same patch must
        not soften an ambiguous hunk's classification -- worst case wins."""
        sig = classify_source_verification([_unique(), _ambiguous()])
        assert sig["value"] == "Position Unconfirmed"


class TestUnverified:
    def test_single_no_match(self):
        sig = classify_source_verification([_no_match()])
        assert sig["value"] == "Unverified"

    def test_no_match_takes_priority_over_ambiguous(self):
        sig = classify_source_verification([_ambiguous(), _no_match()])
        assert sig["value"] == "Unverified"

    def test_no_match_takes_priority_over_unique_match(self):
        """The real urllib3 case: some hunks may match cleanly while
        others are outright hallucinated -- the patch as a whole must be
        flagged, not averaged away."""
        sig = classify_source_verification([_unique(), _unique(), _no_match()])
        assert sig["value"] == "Unverified"

    def test_notes_list_affected_files(self):
        sig = classify_source_verification([_no_match("src/urllib3/util/retry.py")])
        assert "src/urllib3/util/retry.py" in sig["notes"]

    def test_notes_truncate_many_files(self):
        records = [_no_match(f"file{i}.py") for i in range(5)]
        sig = classify_source_verification(records)
        assert "more" in sig["notes"]


class TestShape:
    def test_returns_value_label_notes_keys(self):
        sig = classify_source_verification([_unique()])
        assert set(sig.keys()) == {"value", "label", "notes"}

    def test_label_includes_value(self):
        sig = classify_source_verification([_no_match()])
        assert "Unverified" in sig["label"]
