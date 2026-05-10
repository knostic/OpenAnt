"""Tests for core/parser_adapter.py — language detection and Python parsing."""
import os
from pathlib import Path

import pytest

from core.parser_adapter import detect_language, parse_repository
from utilities.file_io import read_json


class TestDetectLanguage:
    def test_python_repo(self, sample_python_repo):
        assert detect_language(sample_python_repo) == "python"

    def test_empty_dir_raises(self, tmp_path):
        with pytest.raises(ValueError, match="No supported source files"):
            detect_language(str(tmp_path))

    def test_javascript_repo(self, tmp_path):
        (tmp_path / "index.js").write_text("console.log('hi');")
        (tmp_path / "utils.js").write_text("export function foo() {}")
        assert detect_language(str(tmp_path)) == "javascript"

    def test_mixed_repo_picks_majority(self, tmp_path):
        # 3 Python files, 1 JS file — should pick Python
        for name in ["a.py", "b.py", "c.py"]:
            (tmp_path / name).write_text("pass")
        (tmp_path / "d.js").write_text("//js")
        assert detect_language(str(tmp_path)) == "python"

    def test_ignores_node_modules(self, tmp_path):
        (tmp_path / "app.py").write_text("pass")
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("//js")
        (nm / "util.js").write_text("//js")
        (nm / "helper.js").write_text("//js")
        assert detect_language(str(tmp_path)) == "python"

    def test_ignores_venv(self, tmp_path):
        (tmp_path / "app.go").write_text("package main")
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        for i in range(10):
            (venv / f"mod{i}.py").write_text("pass")
        assert detect_language(str(tmp_path)) == "go"


class TestParseRepositoryPython:
    def test_parses_sample_repo(self, sample_python_repo, tmp_output_dir):
        result = parse_repository(
            repo_path=sample_python_repo,
            output_dir=tmp_output_dir,
            language="python",
            processing_level="all",
        )
        assert result.language == "python"
        assert result.units_count > 0
        assert Path(result.dataset_path).exists()

    def test_dataset_json_valid(self, sample_python_repo, tmp_output_dir):
        result = parse_repository(
            repo_path=sample_python_repo,
            output_dir=tmp_output_dir,
            language="python",
            processing_level="all",
        )
        dataset = read_json(result.dataset_path)
        assert "units" in dataset
        assert len(dataset["units"]) > 0

    def test_units_have_required_fields(self, sample_python_repo, tmp_output_dir):
        result = parse_repository(
            repo_path=sample_python_repo,
            output_dir=tmp_output_dir,
            language="python",
            processing_level="all",
        )
        dataset = read_json(result.dataset_path)
        for unit in dataset["units"]:
            assert "id" in unit
            assert "code" in unit

    def test_auto_detect_language(self, sample_python_repo, tmp_output_dir):
        result = parse_repository(
            repo_path=sample_python_repo,
            output_dir=tmp_output_dir,
            language="auto",
            processing_level="all",
        )
        assert result.language == "python"

    def test_analyzer_output_generated(self, sample_python_repo, tmp_output_dir):
        result = parse_repository(
            repo_path=sample_python_repo,
            output_dir=tmp_output_dir,
            language="python",
            processing_level="all",
        )
        assert result.analyzer_output_path is not None
        assert Path(result.analyzer_output_path).exists()
        data = read_json(result.analyzer_output_path)
        assert "functions" in data
