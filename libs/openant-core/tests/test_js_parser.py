"""Tests for the JavaScript parser pipeline.

Requires Node.js and npm dependencies installed:
  cd parsers/javascript && npm install
"""
import json
import subprocess
import shutil
import sys
from pathlib import Path

import pytest

PARSERS_JS_DIR = Path(__file__).parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

# Skip all tests if node or npm deps aren't available
pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def run_node(script_name, *args):
    """Run a Node.js script from the JS parsers directory."""
    cmd = ["node", str(PARSERS_JS_DIR / script_name)] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result


class TestRepositoryScanner:
    def test_scans_js_repo(self, sample_js_repo, tmp_path):
        output = tmp_path / "scan_results.json"
        result = run_node("repository_scanner.js", sample_js_repo, "--output", str(output))
        assert result.returncode == 0
        assert output.exists()

        data = json.loads(output.read_text())
        assert data["statistics"]["totalFiles"] == 3

    def test_finds_js_files(self, sample_js_repo, tmp_path):
        output = tmp_path / "scan_results.json"
        run_node("repository_scanner.js", sample_js_repo, "--output", str(output))
        data = json.loads(output.read_text())

        paths = [f["path"] for f in data["files"]]
        assert any("app.js" in p for p in paths)
        assert any("db.js" in p for p in paths)
        assert any("utils.js" in p for p in paths)

    def test_skip_tests_flag(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "index.js").write_text("module.exports = {};")
        test_dir = repo / "__tests__"
        test_dir.mkdir()
        (test_dir / "index.test.js").write_text("test('foo', () => {});")

        output = tmp_path / "scan.json"
        run_node("repository_scanner.js", str(repo), "--output", str(output), "--skip-tests")
        data = json.loads(output.read_text())

        paths = [f["path"] for f in data["files"]]
        assert any("index.js" in p for p in paths)
        assert not any("test" in p.lower() for p in paths)


class TestTypeScriptAnalyzer:
    # Known issue: ts-morph fails to resolve files with backslash paths on Windows
    _windows_path_xfail = pytest.mark.xfail(
        sys.platform == "win32",
        reason="ts-morph path resolution issue with Windows backslash paths",
        strict=False,
    )

    def test_analyzes_files(self, sample_js_repo, tmp_path):
        # First scan to get file list
        scan_output = tmp_path / "scan.json"
        run_node("repository_scanner.js", sample_js_repo, "--output", str(scan_output))
        scan_data = json.loads(scan_output.read_text())

        # Write file list
        file_list = tmp_path / "files.txt"
        file_list.write_text("\n".join(f["path"] for f in scan_data["files"]))

        # Run analyzer
        analyzer_output = tmp_path / "analyzer_output.json"
        result = run_node(
            "typescript_analyzer.js",
            sample_js_repo,
            "--files-from", str(file_list),
            "--output", str(analyzer_output),
        )
        assert result.returncode == 0
        assert analyzer_output.exists()

    @_windows_path_xfail
    def test_extracts_functions(self, sample_js_repo, tmp_path):
        scan_output = tmp_path / "scan.json"
        run_node("repository_scanner.js", sample_js_repo, "--output", str(scan_output))
        scan_data = json.loads(scan_output.read_text())

        file_list = tmp_path / "files.txt"
        file_list.write_text("\n".join(f["path"] for f in scan_data["files"]))

        analyzer_output = tmp_path / "analyzer_output.json"
        run_node(
            "typescript_analyzer.js",
            sample_js_repo,
            "--files-from", str(file_list),
            "--output", str(analyzer_output),
        )
        data = json.loads(analyzer_output.read_text())

        assert "functions" in data
        func_names = [f.get("name", "") for f in data["functions"].values()]
        assert "getUser" in func_names
        assert "createUser" in func_names
        assert "getConnection" in func_names

    def test_builds_call_graph(self, sample_js_repo, tmp_path):
        scan_output = tmp_path / "scan.json"
        run_node("repository_scanner.js", sample_js_repo, "--output", str(scan_output))
        scan_data = json.loads(scan_output.read_text())

        file_list = tmp_path / "files.txt"
        file_list.write_text("\n".join(f["path"] for f in scan_data["files"]))

        analyzer_output = tmp_path / "analyzer_output.json"
        run_node(
            "typescript_analyzer.js",
            sample_js_repo,
            "--files-from", str(file_list),
            "--output", str(analyzer_output),
        )
        data = json.loads(analyzer_output.read_text())

        assert "callGraph" in data
        # Call graph keys should match extracted functions
        assert len(data["callGraph"]) == len(data["functions"])


class TestUnitGenerator:
    @pytest.fixture
    def analyzer_output(self, sample_js_repo, tmp_path):
        scan_output = tmp_path / "scan.json"
        run_node("repository_scanner.js", sample_js_repo, "--output", str(scan_output))
        scan_data = json.loads(scan_output.read_text())

        file_list = tmp_path / "files.txt"
        file_list.write_text("\n".join(f["path"] for f in scan_data["files"]))

        output = tmp_path / "analyzer_output.json"
        run_node(
            "typescript_analyzer.js",
            sample_js_repo,
            "--files-from", str(file_list),
            "--output", str(output),
        )
        return str(output)

    def test_generates_dataset(self, analyzer_output, tmp_path):
        dataset_output = tmp_path / "dataset.json"
        result = run_node(
            "unit_generator.js",
            analyzer_output,
            "--output", str(dataset_output),
        )
        assert result.returncode == 0
        assert Path(dataset_output).exists()

        data = json.loads(Path(dataset_output).read_text())
        assert "units" in data
        assert len(data["units"]) > 0

    def test_units_have_required_fields(self, analyzer_output, tmp_path):
        dataset_output = tmp_path / "dataset.json"
        run_node(
            "unit_generator.js",
            analyzer_output,
            "--output", str(dataset_output),
        )
        data = json.loads(Path(dataset_output).read_text())

        for unit in data["units"]:
            assert "id" in unit
            assert "code" in unit


class TestFullPipeline:
    """End-to-end test through parser_adapter."""

    # Known issue: test_pipeline.py uses Unicode checkmarks that fail on Windows cp1252
    _windows_unicode_xfail = pytest.mark.xfail(
        sys.platform == "win32",
        reason="JS test_pipeline.py Unicode chars fail on Windows cp1252 encoding",
        strict=False,
    )

    @_windows_unicode_xfail
    def test_parse_js_repo(self, sample_js_repo, tmp_output_dir):
        from core.parser_adapter import parse_repository

        result = parse_repository(
            repo_path=sample_js_repo,
            output_dir=tmp_output_dir,
            language="javascript",
            processing_level="all",
        )
        assert result.language == "javascript"
        assert result.units_count > 0
        assert Path(result.dataset_path).exists()
        assert result.analyzer_output_path is not None
        assert Path(result.analyzer_output_path).exists()

    @_windows_unicode_xfail
    def test_auto_detects_javascript(self, sample_js_repo, tmp_output_dir):
        from core.parser_adapter import parse_repository

        result = parse_repository(
            repo_path=sample_js_repo,
            output_dir=tmp_output_dir,
            language="auto",
            processing_level="all",
        )
        assert result.language == "javascript"
