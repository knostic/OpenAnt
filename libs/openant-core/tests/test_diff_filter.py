"""Tests for core.diff_filter.apply_diff_filter."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

# Make `core` importable when running this file directly.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.diff_filter import (  # noqa: E402
    SCOPE_CALLERS,
    SCOPE_CHANGED_FILES,
    SCOPE_CHANGED_FUNCTIONS,
    apply_diff_filter,
    load_manifest,
)


def _unit(uid: str, file: str, start: int, end: int, calls: list | None = None) -> dict:
    return {
        "id": uid,
        "code": {
            "primary_origin": {
                "file_path": file,
                "start_line": start,
                "end_line": end,
            },
        },
        "metadata": {"direct_calls": calls or []},
    }


class ChangedFilesScope(unittest.TestCase):
    def test_selects_everything_in_changed_files(self):
        units = [
            _unit("a.py:f1", "a.py", 1, 10),
            _unit("a.py:f2", "a.py", 20, 30),
            _unit("b.py:f3", "b.py", 1, 5),  # b.py not in changed_files
        ]
        manifest = {
            "scope": SCOPE_CHANGED_FILES,
            "changed_files": ["a.py"],
            "hunks": None,
        }
        stats = apply_diff_filter(units, manifest)
        self.assertTrue(units[0]["diff_selected"])
        self.assertTrue(units[1]["diff_selected"])
        self.assertFalse(units[2]["diff_selected"])
        self.assertEqual(stats.total, 3)
        self.assertEqual(stats.selected, 2)


class ChangedFunctionsScope(unittest.TestCase):
    def test_selects_on_line_overlap(self):
        units = [
            _unit("a.py:touched", "a.py", 40, 80),    # overlaps 42..78
            _unit("a.py:untouched", "a.py", 100, 120),
            _unit("a.py:edge", "a.py", 78, 90),       # touches end of hunk at 78
            _unit("b.py:other", "b.py", 1, 5),
        ]
        manifest = {
            "scope": SCOPE_CHANGED_FUNCTIONS,
            "changed_files": ["a.py"],
            "hunks": {"a.py": [[42, 78]]},
        }
        apply_diff_filter(units, manifest)
        self.assertTrue(units[0]["diff_selected"])
        self.assertFalse(units[1]["diff_selected"])
        self.assertTrue(units[2]["diff_selected"])
        self.assertFalse(units[3]["diff_selected"])

    def test_no_line_info_falls_back_to_file_match_and_counts_stat(self):
        unit = {
            "id": "a.py:no_lines",
            "code": {"primary_origin": {"file_path": "a.py"}},
            "metadata": {"direct_calls": []},
        }
        manifest = {
            "scope": SCOPE_CHANGED_FUNCTIONS,
            "changed_files": ["a.py"],
            "hunks": {"a.py": [[1, 5]]},
        }
        stats = apply_diff_filter([unit], manifest)
        self.assertTrue(unit["diff_selected"])
        self.assertEqual(stats.fallback_file_match, 1)

    def test_strips_leading_dotslash(self):
        units = [_unit("./a.py:f", "./a.py", 1, 10)]
        manifest = {
            "scope": SCOPE_CHANGED_FUNCTIONS,
            "changed_files": ["a.py"],
            "hunks": {"a.py": [[1, 10]]},
        }
        apply_diff_filter(units, manifest)
        self.assertTrue(units[0]["diff_selected"])


class CallersScope(unittest.TestCase):
    def test_one_hop_caller_is_selected_two_hop_is_not(self):
        # Chain: A -> B -> C. Only C overlaps a hunk.
        a = _unit("a.py:A", "a.py", 1, 5, calls=["a.py:B"])
        b = _unit("a.py:B", "a.py", 10, 15, calls=["a.py:C"])
        c = _unit("a.py:C", "a.py", 100, 110, calls=[])
        units = [a, b, c]
        manifest = {
            "scope": SCOPE_CALLERS,
            "changed_files": ["a.py"],
            "hunks": {"a.py": [[100, 110]]},
        }
        stats = apply_diff_filter(units, manifest)
        self.assertTrue(c["diff_selected"], "C is in the hunk")
        self.assertTrue(b["diff_selected"], "B calls C directly (1 hop)")
        self.assertFalse(a["diff_selected"], "A only reaches C via B (2 hops)")
        self.assertEqual(stats.callers_added, 1)

    def test_unit_without_direct_calls_is_not_selected(self):
        a = _unit("a.py:A", "a.py", 1, 5)  # no calls metadata
        c = _unit("a.py:C", "a.py", 100, 110)
        units = [a, c]
        manifest = {
            "scope": SCOPE_CALLERS,
            "changed_files": ["a.py"],
            "hunks": {"a.py": [[100, 110]]},
        }
        apply_diff_filter(units, manifest)
        self.assertFalse(a["diff_selected"])
        self.assertTrue(c["diff_selected"])

    def test_camelcase_directCalls_alias(self):
        changed = _unit("a.py:C", "a.py", 100, 110)
        caller = {
            "id": "a.py:A",
            "code": {"primary_origin": {"file_path": "a.py", "start_line": 1, "end_line": 5}},
            "metadata": {"directCalls": ["a.py:C"]},  # camelCase
        }
        units = [caller, changed]
        manifest = {
            "scope": SCOPE_CALLERS,
            "changed_files": ["a.py"],
            "hunks": {"a.py": [[100, 110]]},
        }
        apply_diff_filter(units, manifest)
        self.assertTrue(caller["diff_selected"])


class FilePathResolution(unittest.TestCase):
    def test_falls_back_to_unit_id_when_primary_origin_missing(self):
        unit = {
            "id": "handlers/auth.py:login",
            "metadata": {"direct_calls": []},
        }
        manifest = {
            "scope": SCOPE_CHANGED_FILES,
            "changed_files": ["handlers/auth.py"],
            "hunks": None,
        }
        apply_diff_filter([unit], manifest)
        self.assertTrue(unit["diff_selected"])


class ManifestLoader(unittest.TestCase):
    def test_rejects_bad_scope(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"scope": "bogus", "changed_files": []}, f)
            path = f.name
        try:
            with self.assertRaises(ValueError):
                load_manifest(path)
        finally:
            os.unlink(path)

    def test_round_trip(self):
        m = {
            "base_ref": "origin/main",
            "base_sha": "abc",
            "head_sha": "def",
            "scope": SCOPE_CHANGED_FUNCTIONS,
            "pr_number": 0,
            "changed_files": ["a.py"],
            "hunks": {"a.py": [[1, 10]]},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(m, f)
            path = f.name
        try:
            got = load_manifest(path)
            self.assertEqual(got["scope"], SCOPE_CHANGED_FUNCTIONS)
            self.assertEqual(got["changed_files"], ["a.py"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
