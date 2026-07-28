"""Tests for Phase D repo-wide sink extraction.

Tests: extract_repo_sinks, _find_enclosing_def, _build_sink_table, and
the integration path through build_vulnerability_pattern_context.

All file-system tests use pytest's tmp_path fixture — no real repos needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


from utilities.autopatcher.vulnerability_patterns import (
    _build_sink_table,
    _find_enclosing_def,
    build_vulnerability_pattern_context,
    extract_repo_sinks,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# _find_enclosing_def
# ---------------------------------------------------------------------------


class TestFindEnclosingDef:
    def test_finds_simple_def(self):
        lines = [
            "def my_function(self, x):",
            "    os.system(x)",
        ]
        assert _find_enclosing_def(lines, 1) == "my_function"

    def test_finds_async_def(self):
        lines = [
            "async def async_func(self):",
            "    await do_thing()",
            "    os.system('x')",
        ]
        assert _find_enclosing_def(lines, 2) == "async_func"

    def test_returns_none_when_no_def_above(self):
        lines = [
            "import os",
            "os.system('cmd')",
        ]
        assert _find_enclosing_def(lines, 1) is None

    def test_finds_nearest_not_outer(self):
        # Should return inner, not outer
        lines = [
            "def outer(self):",
            "    x = 1",
            "    def inner(y):",
            "        os.system(y)",
        ]
        assert _find_enclosing_def(lines, 3) == "inner"

    def test_sink_on_def_line_itself(self):
        lines = [
            "def risky(self, shell=True):",
        ]
        assert _find_enclosing_def(lines, 0) == "risky"

    def test_indented_method_inside_class(self):
        lines = [
            "class Foo:",
            "    def method(self):",
            "        os.system('x')",
        ]
        assert _find_enclosing_def(lines, 2) == "method"

    def test_empty_lines_list(self):
        assert _find_enclosing_def([], 0) is None

    def test_walks_past_blank_lines(self):
        lines = [
            "def handler(self):",
            "",
            "    x = 1",
            "    os.system(x)",
        ]
        assert _find_enclosing_def(lines, 3) == "handler"


# ---------------------------------------------------------------------------
# extract_repo_sinks
# ---------------------------------------------------------------------------


class TestExtractRepoSinks:
    def test_multi_file_coverage(self, tmp_path):
        write(tmp_path / "a.py", "def func_a(cmd):\n    os.system(cmd)\n")
        write(tmp_path / "b.py", "def func_b(cmd):\n    x = cmd; os.system(x)\n")
        write(tmp_path / "c.py", "def func_c(cmd):\n    subprocess.call(cmd, shell=True)\n")
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        methods = {s["method"] for s in sinks}
        assert "func_a" in methods
        assert "func_b" in methods
        assert "func_c" in methods

    def test_enclosing_method_detected(self, tmp_path):
        write(tmp_path / "app.py", (
            "def safe_func(x):\n"
            "    return x\n"
            "\n"
            "def danger_func(path):\n"
            "    full = os.path.normpath(path)\n"
            "    return full\n"
        ))
        sinks = extract_repo_sinks(tmp_path, "PATH_TRAVERSAL")
        assert len(sinks) == 1
        assert sinks[0]["method"] == "danger_func"

    def test_deduplication_keeps_first_occurrence(self, tmp_path):
        write(tmp_path / "app.py", (
            "def multi_sink(a, b):\n"
            "    x = os.path.normpath(a)\n"
            "    y = os.path.normpath(b)\n"
            "    return x, y\n"
        ))
        sinks = extract_repo_sinks(tmp_path, "PATH_TRAVERSAL")
        assert len(sinks) == 1
        assert sinks[0]["method"] == "multi_sink"
        assert sinks[0]["line"] == 2  # first occurrence, 1-indexed

    def test_no_sinks_returns_empty(self, tmp_path):
        write(tmp_path / "clean.py", (
            "from pathlib import Path\n"
            "\n"
            "def safe(path, base):\n"
            "    return Path(path).resolve().is_relative_to(Path(base).resolve())\n"
        ))
        assert extract_repo_sinks(tmp_path, "PATH_TRAVERSAL") == []

    def test_comment_lines_skipped(self, tmp_path):
        write(tmp_path / "commented.py", (
            "def func(x):\n"
            "    # old: os.path.normpath(x)\n"
            "    return x\n"
        ))
        assert extract_repo_sinks(tmp_path, "PATH_TRAVERSAL") == []

    def test_test_files_by_name_skipped(self, tmp_path):
        write(tmp_path / "test_app.py", "def test_f(cmd):\n    os.system(cmd)\n")
        write(tmp_path / "app.py", "def safe(x):\n    return x\n")
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        assert all(s["file"] != "test_app.py" for s in sinks)

    def test_tests_subdir_skipped(self, tmp_path):
        write(tmp_path / "tests" / "test_foo.py", "def test_x():\n    os.system('x')\n")
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        assert sinks == []

    def test_module_level_sink_has_none_method(self, tmp_path):
        write(tmp_path / "script.py", "os.system('cmd')\n")
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        assert len(sinks) == 1
        assert sinks[0]["method"] is None

    def test_results_sorted_by_file_then_line(self, tmp_path):
        write(tmp_path / "z_file.py", "def zzz(x):\n    os.system(x)\n")
        write(tmp_path / "a_file.py", "def aaa(x):\n    os.system(x)\n")
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        files = [s["file"] for s in sinks]
        assert files == sorted(files)

    def test_unknown_vuln_class_returns_empty(self, tmp_path):
        write(tmp_path / "app.py", "def f(x):\n    os.system(x)\n")
        assert extract_repo_sinks(tmp_path, "SQL_INJECTION") == []

    def test_none_repo_root_returns_empty(self):
        assert extract_repo_sinks(None, "COMMAND_INJECTION") == []

    def test_capped_at_max_rows(self, tmp_path):
        for i in range(25):
            write(tmp_path / f"mod{i:02d}.py", f"def func_{i}(x):\n    os.system(x)\n")
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        assert len(sinks) <= 20

    def test_line_number_is_1_indexed(self, tmp_path):
        write(tmp_path / "app.py", (
            "def func(x):\n"
            "    safe()\n"
            "    os.system(x)\n"
        ))
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        assert sinks[0]["line"] == 3

    def test_snippet_stripped(self, tmp_path):
        write(tmp_path / "app.py", "def func(x):\n    os.system(x)\n")
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        assert sinks[0]["snippet"] == "os.system(x)"

    def test_path_traversal_normpath_detected(self, tmp_path):
        write(tmp_path / "server.py", (
            "def serve(self, path):\n"
            "    full = os.path.normpath(self.root + path)\n"
            "    return open(full).read()\n"
        ))
        sinks = extract_repo_sinks(tmp_path, "PATH_TRAVERSAL")
        assert len(sinks) == 1
        assert sinks[0]["method"] == "serve"

    def test_path_traversal_string_concat_detected(self, tmp_path):
        write(tmp_path / "fs.py", (
            "def get_file(self, name):\n"
            "    path = self.root + name\n"
            "    return open(path).read()\n"
        ))
        sinks = extract_repo_sinks(tmp_path, "PATH_TRAVERSAL")
        assert any(s["method"] == "get_file" for s in sinks)

    def test_path_traversal_os_path_join_not_detected(self, tmp_path):
        # os.path.join is excluded from repo_sink_patterns to avoid noise
        write(tmp_path / "utils.py", (
            "def build_path(base, name):\n"
            "    return os.path.join(base, name)\n"
        ))
        sinks = extract_repo_sinks(tmp_path, "PATH_TRAVERSAL")
        assert sinks == []

    def test_ignored_dirs_skipped(self, tmp_path):
        write(tmp_path / ".venv" / "lib" / "bad.py", "os.system('x')\n")
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        assert all(".venv" not in s["file"] for s in sinks)

    def test_snippet_truncated_at_80_chars(self, tmp_path):
        long_line = "    os.system(" + "x" * 100 + ")"
        write(tmp_path / "app.py", f"def f(x):\n{long_line}\n")
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        assert len(sinks[0]["snippet"]) <= 80

    def test_multiple_methods_in_one_file(self, tmp_path):
        write(tmp_path / "multi.py", (
            "def method_a(self, cmd):\n"
            "    os.system(cmd)\n"
            "\n"
            "def method_b(self, cmd):\n"
            "    os.system(cmd + ' extra')\n"
        ))
        sinks = extract_repo_sinks(tmp_path, "COMMAND_INJECTION")
        methods = {s["method"] for s in sinks}
        assert "method_a" in methods
        assert "method_b" in methods


# ---------------------------------------------------------------------------
# _build_sink_table
# ---------------------------------------------------------------------------


class TestBuildSinkTable:
    def test_empty_input_has_headers_only(self):
        table = _build_sink_table([])
        assert "| File |" in table
        assert "| Line |" in table
        assert "| Method |" in table
        assert "| Dangerous call |" in table
        assert len(table.splitlines()) == 2  # header + separator

    def test_row_content_present(self):
        sinks = [{"file": "app/cmd.py", "line": 42, "method": "execute", "snippet": "os.system(cmd)"}]
        table = _build_sink_table(sinks)
        assert "app/cmd.py" in table
        assert "42" in table
        assert "execute" in table
        assert "os.system(cmd)" in table

    def test_none_method_shown_as_module(self):
        sinks = [{"file": "script.py", "line": 1, "method": None, "snippet": "os.system('x')"}]
        table = _build_sink_table(sinks)
        assert "<module>" in table

    def test_pipe_in_snippet_escaped(self):
        sinks = [{"file": "f.py", "line": 1, "method": "fn", "snippet": "a | b"}]
        table = _build_sink_table(sinks)
        assert "a \\| b" in table

    def test_multiple_rows(self):
        sinks = [
            {"file": "a.py", "line": 10, "method": "foo", "snippet": "os.system(x)"},
            {"file": "b.py", "line": 20, "method": "bar", "snippet": "os.system(y)"},
        ]
        table = _build_sink_table(sinks)
        lines = table.splitlines()
        # header + separator + 2 rows = 4 lines
        assert len(lines) == 4
        assert "foo" in table
        assert "bar" in table


# ---------------------------------------------------------------------------
# Integration: build_vulnerability_pattern_context
# ---------------------------------------------------------------------------


class TestBuildContextWithRepoSinks:
    def test_table_included_when_sinks_found(self, tmp_path):
        write(tmp_path / "app.py", "def handler(cmd):\n    os.system(cmd)\n")
        result = build_vulnerability_pattern_context(
            "OS command injection CWE-78", "", repo_root=tmp_path
        )
        assert "Dangerous operation locations" in result
        assert "handler" in result

    def test_table_absent_when_no_sinks(self, tmp_path):
        write(tmp_path / "app.py", "def safe(x):\n    return x\n")
        result = build_vulnerability_pattern_context(
            "OS command injection CWE-78", "", repo_root=tmp_path
        )
        assert "Dangerous operation locations" not in result

    def test_table_absent_when_no_repo_root(self):
        result = build_vulnerability_pattern_context(
            "OS command injection CWE-78", "", repo_root=None
        )
        assert "Dangerous operation locations" not in result

    def test_line_number_in_output(self, tmp_path):
        write(tmp_path / "app.py", (
            "def func(x):\n"
            "    safe()\n"
            "    os.system(x)\n"
        ))
        result = build_vulnerability_pattern_context(
            "OS command injection CWE-78", "", repo_root=tmp_path
        )
        assert "| 3 |" in result  # 1-indexed line 3

    def test_both_context_checklist_and_repo_table_present(self, tmp_path):
        # code_context method needs >= _MIN_METHOD_BODY_LINES (3) lines to
        # appear in the context-level sink checklist.
        code_ctx = (
            "def context_method(x):\n"
            "    y = x\n"
            "    os.system(y)\n"
        )
        write(tmp_path / "app.py", "def repo_method(x):\n    os.system(x)\n")
        result = build_vulnerability_pattern_context(
            "OS command injection CWE-78", code_ctx, repo_root=tmp_path
        )
        assert "context_method" in result  # from context-level scan
        assert "Dangerous operation locations" in result  # repo table
        assert "repo_method" in result  # from repo scan

    def test_path_traversal_repo_table_present(self, tmp_path):
        write(tmp_path / "server.py", (
            "def serve(self, path):\n"
            "    full = os.path.normpath(self.root + path)\n"
            "    return open(full).read()\n"
        ))
        result = build_vulnerability_pattern_context(
            "path traversal CWE-22", "", repo_root=tmp_path
        )
        assert "Dangerous operation locations" in result
        assert "serve" in result
