"""Tests that each parser writes call_graph.json to the output directory.

The call_graph.json file is required by apply_reachability_filter (and the
post-LLM re-filter path) so it must be present regardless of processing_level,
including when --llm-reachability causes a parse with processing_level="all".

Structure expected by apply_reachability_filter:
    {
        "functions": {<id>: {<metadata>}, ...},
        "call_graph": {<id>: [<callee_id>, ...], ...},
        "reverse_call_graph": {<id>: [<caller_id>, ...], ...},
    }

Parser availability gates (identical to patterns used in test_js_parser.py):
- Python: always available
- JavaScript: requires Node.js + parsers/javascript/node_modules
- Go: requires parsers/go/go_parser/go_parser binary
- C: requires tree_sitter_c Python package
- Ruby: requires tree_sitter_ruby Python package
- PHP: requires tree_sitter_php Python package
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

from core.parser_adapter import apply_reachability_filter, parse_repository

TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
PARSERS_DIR = Path(__file__).parent.parent / "parsers"

# ---------------------------------------------------------------------------
# Availability checks (used by skipif marks)
# ---------------------------------------------------------------------------

def _node_available() -> bool:
    return bool(shutil.which("node")) and (PARSERS_DIR / "javascript" / "node_modules").exists()

def _go_parser_available() -> bool:
    go_dir = PARSERS_DIR / "go" / "go_parser"
    # Check both Unix and Windows binary names.
    candidates = [go_dir / "go_parser", go_dir / "go_parser.exe"]
    binary = next((p for p in candidates if p.exists() and p.stat().st_size > 0), None)
    if binary is None:
        return False
    import subprocess
    try:
        subprocess.run([str(binary), "--help"], capture_output=True, timeout=5)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False

def _ts_c_available() -> bool:
    try:
        import tree_sitter_c  # noqa: F401
        return True
    except ImportError:
        return False

def _ts_ruby_available() -> bool:
    try:
        import tree_sitter_ruby  # noqa: F401
        return True
    except ImportError:
        return False

def _ts_php_available() -> bool:
    try:
        import tree_sitter_php  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = {"functions", "call_graph", "reverse_call_graph"}


def _assert_call_graph_valid(output_dir: str) -> dict:
    """Load call_graph.json from output_dir and assert it has the right shape."""
    cg_path = Path(output_dir) / "call_graph.json"
    assert cg_path.exists(), f"call_graph.json not found in {output_dir}"
    with open(cg_path) as f:
        data = json.load(f)
    assert _REQUIRED_KEYS <= data.keys(), (
        f"call_graph.json missing keys: {_REQUIRED_KEYS - data.keys()}"
    )
    assert isinstance(data["functions"], dict)
    assert isinstance(data["call_graph"], dict)
    assert isinstance(data["reverse_call_graph"], dict)
    return data


# ---------------------------------------------------------------------------
# apply_reachability_filter unit tests (always run — no external deps)
# ---------------------------------------------------------------------------


class TestApplyReachabilityFilterPublicAPI:
    """apply_reachability_filter is the consumer of call_graph.json.
    These tests verify it works correctly with a synthetic fixture."""

    def _make_call_graph_json(self, tmp_path: Path) -> None:
        """Write a minimal call_graph.json that apply_reachability_filter can parse.

        route_handler uses the ``@app.route`` decorator pattern that
        EntryPointDetector recognises, making it a structural entry point.
        """
        cg = {
            "functions": {
                "app.py:route_handler": {
                    "name": "route_handler",
                    "filePath": "app.py",
                    "unitType": "function",
                    "isExported": False,
                    "decorators": ["@app.route('/foo')"],
                },
                "app.py:helper": {
                    "name": "helper",
                    "filePath": "app.py",
                    "unitType": "function",
                    "isExported": False,
                    "decorators": [],
                },
                "app.py:orphan": {
                    "name": "orphan",
                    "filePath": "app.py",
                    "unitType": "function",
                    "isExported": False,
                    "decorators": [],
                },
            },
            "call_graph": {
                "app.py:route_handler": ["app.py:helper"],
            },
            "reverse_call_graph": {
                "app.py:helper": ["app.py:route_handler"],
            },
        }
        (tmp_path / "call_graph.json").write_text(json.dumps(cg))

    def _make_dataset(self, unit_ids: list[str]) -> dict:
        return {
            "units": [
                {"id": uid, "code": {"primary_code": "pass"}, "unit_type": "function"}
                for uid in unit_ids
            ]
        }

    def test_filters_to_reachable_units(self, tmp_path):
        self._make_call_graph_json(tmp_path)
        dataset = self._make_dataset(
            ["app.py:route_handler", "app.py:helper", "app.py:orphan"]
        )
        result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
        unit_ids = {u["id"] for u in result["units"]}
        assert "app.py:route_handler" in unit_ids
        assert "app.py:helper" in unit_ids
        assert "app.py:orphan" not in unit_ids

    def test_extra_entry_points_expand_reachable_set(self, tmp_path):
        self._make_call_graph_json(tmp_path)
        dataset = self._make_dataset(
            ["app.py:route_handler", "app.py:helper", "app.py:orphan"]
        )
        # Promote orphan as an extra entry point (simulating LLM signal).
        result = apply_reachability_filter(
            dataset, str(tmp_path), "reachable",
            extra_entry_points={"app.py:orphan"},
        )
        unit_ids = {u["id"] for u in result["units"]}
        assert "app.py:orphan" in unit_ids

    def test_is_entry_point_set_on_structural_entry_points(self, tmp_path):
        self._make_call_graph_json(tmp_path)
        dataset = self._make_dataset(["app.py:route_handler", "app.py:helper"])
        result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
        by_id = {u["id"]: u for u in result["units"]}
        assert by_id["app.py:route_handler"]["is_entry_point"] is True
        assert by_id["app.py:helper"]["is_entry_point"] is False

    def test_llm_promoted_is_entry_point_preserved(self, tmp_path):
        self._make_call_graph_json(tmp_path)
        dataset = self._make_dataset(["app.py:route_handler", "app.py:helper"])
        # Pre-set is_entry_point=True on helper (simulating LLM promotion).
        dataset["units"][1]["is_entry_point"] = True
        result = apply_reachability_filter(
            dataset, str(tmp_path), "reachable",
            extra_entry_points={"app.py:helper"},
        )
        by_id = {u["id"]: u for u in result["units"]}
        assert by_id["app.py:helper"]["is_entry_point"] is True

    def test_missing_call_graph_returns_dataset_unchanged(self, tmp_path):
        dataset = self._make_dataset(["app.py:route_handler"])
        result = apply_reachability_filter(dataset, str(tmp_path), "reachable")
        assert len(result["units"]) == 1


# ---------------------------------------------------------------------------
# Python parser — always runs
# ---------------------------------------------------------------------------


class TestPythonCallGraphOutput:
    def test_call_graph_json_written(self, sample_python_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_python_repo,
            output_dir=tmp_output_dir,
            language="python",
            processing_level="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_python_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_python_repo,
            output_dir=tmp_output_dir,
            language="python",
            processing_level="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)


# ---------------------------------------------------------------------------
# JavaScript parser
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _node_available(), reason="Node.js or JS parser npm deps not available")
class TestJavaScriptCallGraphOutput:
    def test_call_graph_json_written(self, sample_js_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_js_repo,
            output_dir=tmp_output_dir,
            language="javascript",
            processing_level="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_js_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_js_repo,
            output_dir=tmp_output_dir,
            language="javascript",
            processing_level="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)


# ---------------------------------------------------------------------------
# Go parser
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_go_repo(tmp_path):
    """Minimal Go repository fixture."""
    repo = tmp_path / "go_repo"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/myapp\n\ngo 1.21\n")
    (repo / "main.go").write_text(
        'package main\n\nimport "fmt"\n\n'
        "func main() {\n\tgreet()\n}\n\n"
        'func greet() {\n\tfmt.Println("hello")\n}\n'
    )
    return str(repo)


@pytest.mark.skipif(not _go_parser_available(), reason="go_parser binary not available")
class TestGoCallGraphOutput:
    def test_call_graph_json_written(self, sample_go_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_go_repo,
            output_dir=tmp_output_dir,
            language="go",
            processing_level="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_go_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_go_repo,
            output_dir=tmp_output_dir,
            language="go",
            processing_level="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)


# ---------------------------------------------------------------------------
# C parser
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_c_repo(tmp_path):
    """Minimal C repository fixture."""
    repo = tmp_path / "c_repo"
    repo.mkdir()
    (repo / "main.c").write_text(
        "#include <stdio.h>\n\nvoid greet() {\n    printf(\"hello\\n\");\n}\n\n"
        "int main() {\n    greet();\n    return 0;\n}\n"
    )
    return str(repo)


@pytest.mark.skipif(not _ts_c_available(), reason="tree_sitter_c not installed")
class TestCCallGraphOutput:
    def test_call_graph_json_written(self, sample_c_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_c_repo,
            output_dir=tmp_output_dir,
            language="c",
            processing_level="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_c_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_c_repo,
            output_dir=tmp_output_dir,
            language="c",
            processing_level="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)


# ---------------------------------------------------------------------------
# Ruby parser
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_ruby_repo(tmp_path):
    """Minimal Ruby repository fixture."""
    repo = tmp_path / "ruby_repo"
    repo.mkdir()
    (repo / "app.rb").write_text(
        "def greet\n  puts 'hello'\nend\n\ndef main\n  greet\nend\n"
    )
    return str(repo)


@pytest.mark.skipif(not _ts_ruby_available(), reason="tree_sitter_ruby not installed")
class TestRubyCallGraphOutput:
    def test_call_graph_json_written(self, sample_ruby_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_ruby_repo,
            output_dir=tmp_output_dir,
            language="ruby",
            processing_level="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_ruby_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_ruby_repo,
            output_dir=tmp_output_dir,
            language="ruby",
            processing_level="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)


# ---------------------------------------------------------------------------
# PHP parser
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_php_repo(tmp_path):
    """Minimal PHP repository fixture."""
    repo = tmp_path / "php_repo"
    repo.mkdir()
    (repo / "index.php").write_text(
        "<?php\nfunction greet() {\n    echo 'hello';\n}\n\n"
        "function main() {\n    greet();\n}\n"
    )
    return str(repo)


@pytest.mark.skipif(not _ts_php_available(), reason="tree_sitter_php not installed")
class TestPHPCallGraphOutput:
    def test_call_graph_json_written(self, sample_php_repo, tmp_output_dir):
        parse_repository(
            repo_path=sample_php_repo,
            output_dir=tmp_output_dir,
            language="php",
            processing_level="all",
        )
        _assert_call_graph_valid(tmp_output_dir)

    def test_call_graph_json_written_with_reachable_level(
        self, sample_php_repo, tmp_output_dir
    ):
        parse_repository(
            repo_path=sample_php_repo,
            output_dir=tmp_output_dir,
            language="php",
            processing_level="reachable",
        )
        _assert_call_graph_valid(tmp_output_dir)
