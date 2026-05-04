"""Tests for application_context.json auto-discovery in the Python CLI.

These tests exercise the `_find_app_context` helper used by `analyze` and
`verify` to locate `application_context.json` automatically when
`--app-context` is not passed.
"""
import json
from pathlib import Path

from openant.cli import _find_app_context


def _write_dummy_context(path: Path) -> None:
    path.write_text(json.dumps({
        "application_type": "web_app",
        "purpose": "test",
        "confidence": "high",
        "source": "test",
    }))


class TestFindAppContext:
    def test_returns_none_when_no_dirs(self):
        assert _find_app_context() is None

    def test_returns_none_when_dirs_empty(self):
        assert _find_app_context("", None) is None

    def test_returns_none_when_no_file_present(self, tmp_path):
        d1 = tmp_path / "out"
        d1.mkdir()
        d2 = tmp_path / "repo"
        d2.mkdir()
        assert _find_app_context(str(d1), str(d2)) is None

    def test_finds_in_first_dir(self, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        ctx_path = out_dir / "application_context.json"
        _write_dummy_context(ctx_path)

        result = _find_app_context(str(out_dir), str(tmp_path / "repo"))
        assert result == str(ctx_path)

    def test_finds_in_second_dir_when_first_missing(self, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        ctx_path = repo_dir / "application_context.json"
        _write_dummy_context(ctx_path)

        result = _find_app_context(str(out_dir), str(repo_dir))
        assert result == str(ctx_path)

    def test_first_match_wins(self, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        first = out_dir / "application_context.json"
        second = repo_dir / "application_context.json"
        _write_dummy_context(first)
        _write_dummy_context(second)

        result = _find_app_context(str(out_dir), str(repo_dir))
        assert result == str(first)

    def test_skips_falsy_dirs(self, tmp_path):
        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        ctx_path = repo_dir / "application_context.json"
        _write_dummy_context(ctx_path)

        # First two are falsy (empty / None) — should be skipped without error
        result = _find_app_context("", None, str(repo_dir))
        assert result == str(ctx_path)

    def test_ignores_directory_named_application_context_json(self, tmp_path):
        """A *directory* with the magic name should not be treated as a hit."""
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        # Create a directory (not file) with the target name
        (out_dir / "application_context.json").mkdir()

        assert _find_app_context(str(out_dir)) is None
