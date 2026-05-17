"""Tests for the `--fresh` flag plumbing in core.parser_adapter.parse_repository.

These tests stub out the language-specific parsers so we can verify the
pre-parse cleanup behavior of `fresh=True` in isolation, without relying
on the real Python/JS/Go parsers.
"""
import json
import os
from pathlib import Path

import pytest

from core import parser_adapter
from core.schemas import ParseResult


def _make_stub_parser(record):
    """Build a fake `_parse_python` that records what it sees on disk.

    The stub captures whether `dataset.json` exists in `output_dir` at the
    time it is invoked, then writes a fresh dataset itself so the rest of
    `parse_repository` has something to work with.
    """
    def _stub(repo_path, output_dir, processing_level, skip_tests=True, name=None):
        dataset_path = os.path.join(output_dir, "dataset.json")
        record["dataset_existed_when_parser_ran"] = os.path.exists(dataset_path)
        # Mimic real parser output
        with open(dataset_path, "w") as f:
            json.dump({"units": [{"id": "u1", "code": "def f(): pass"}]}, f)
        return ParseResult(
            dataset_path=dataset_path,
            analyzer_output_path=None,
            units_count=1,
            language="python",
            processing_level=processing_level,
        )
    return _stub


class TestParseFreshFlag:
    def test_fresh_true_deletes_existing_dataset_before_parser_runs(
        self, tmp_path, monkeypatch
    ):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        existing = output_dir / "dataset.json"
        existing.write_text(json.dumps({"units": [{"id": "stale"}]}))

        record = {}
        monkeypatch.setattr(parser_adapter, "_parse_python", _make_stub_parser(record))

        parser_adapter.parse_repository(
            repo_path=str(tmp_path),  # repo path not actually used by stub
            output_dir=str(output_dir),
            language="python",
            processing_level="all",
            fresh=True,
        )

        # The pre-existing dataset.json must be gone by the time the
        # parser runs, proving --fresh removed it before dispatch.
        assert record["dataset_existed_when_parser_ran"] is False

    def test_fresh_false_leaves_existing_dataset_in_place(
        self, tmp_path, monkeypatch
    ):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        existing = output_dir / "dataset.json"
        existing.write_text(json.dumps({"units": [{"id": "stale"}]}))

        record = {}
        monkeypatch.setattr(parser_adapter, "_parse_python", _make_stub_parser(record))

        parser_adapter.parse_repository(
            repo_path=str(tmp_path),
            output_dir=str(output_dir),
            language="python",
            processing_level="all",
            fresh=False,
        )

        # Without --fresh the existing dataset must still be present when
        # the parser is invoked (so the parser can decide whether to
        # incrementally reuse it).
        assert record["dataset_existed_when_parser_ran"] is True

    def test_fresh_default_is_false(self, tmp_path, monkeypatch):
        """`fresh` must default to False so existing scans aren't wiped."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        existing = output_dir / "dataset.json"
        existing.write_text(json.dumps({"units": [{"id": "stale"}]}))

        record = {}
        monkeypatch.setattr(parser_adapter, "_parse_python", _make_stub_parser(record))

        # Note: no `fresh=` kwarg.
        parser_adapter.parse_repository(
            repo_path=str(tmp_path),
            output_dir=str(output_dir),
            language="python",
            processing_level="all",
        )

        assert record["dataset_existed_when_parser_ran"] is True

    def test_fresh_true_with_no_existing_dataset_is_noop(
        self, tmp_path, monkeypatch
    ):
        """Passing --fresh when no dataset.json exists must not error."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        # Note: no pre-existing dataset.json

        record = {}
        monkeypatch.setattr(parser_adapter, "_parse_python", _make_stub_parser(record))

        result = parser_adapter.parse_repository(
            repo_path=str(tmp_path),
            output_dir=str(output_dir),
            language="python",
            processing_level="all",
            fresh=True,
        )

        # The parser still runs and produces a dataset
        assert Path(result.dataset_path).exists()
        assert record["dataset_existed_when_parser_ran"] is False

    def test_fresh_creates_output_dir_if_missing(
        self, tmp_path, monkeypatch
    ):
        """`fresh=True` must not crash when output_dir doesn't yet exist."""
        output_dir = tmp_path / "does_not_exist_yet"

        record = {}
        monkeypatch.setattr(parser_adapter, "_parse_python", _make_stub_parser(record))

        result = parser_adapter.parse_repository(
            repo_path=str(tmp_path),
            output_dir=str(output_dir),
            language="python",
            processing_level="all",
            fresh=True,
        )

        assert output_dir.exists()
        assert Path(result.dataset_path).exists()

    def test_fresh_and_diff_manifest_compose_correctly(
        self, tmp_path, monkeypatch
    ):
        """--fresh cleans up before the parser runs even when --diff-manifest is also set."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        existing = output_dir / "dataset.json"
        existing.write_text(json.dumps({"units": [{"id": "stale"}]}))

        record = {}
        monkeypatch.setattr(parser_adapter, "_parse_python", _make_stub_parser(record))
        # Stub the diff filter so the test doesn't need a real manifest format.
        monkeypatch.setattr(parser_adapter, "_maybe_apply_diff_filter", lambda *a, **kw: None)

        manifest_path = tmp_path / "diff_manifest.json"
        manifest_path.write_text(json.dumps({}))

        parser_adapter.parse_repository(
            repo_path=str(tmp_path),
            output_dir=str(output_dir),
            language="python",
            processing_level="all",
            fresh=True,
            diff_manifest=str(manifest_path),
        )

        # --fresh must delete dataset.json before the parser runs even when
        # --diff-manifest is also provided; the two flags must not interfere.
        assert record["dataset_existed_when_parser_ran"] is False
