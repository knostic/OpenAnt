"""Regression tests for detect_entry_points unanchored-substring path-exclusion.

Two sites exclude files via `token in str(absolute_path)` —
  Python branch (application_context.py:290): tokens incl 'test','tests','venv'
  JS branch     (application_context.py:310): tokens incl 'dist','build'
So a path SEGMENT (or a PARENT dir) merely CONTAINING a token wrongly skips a real entry point.
Vividly, pytest's own tmp_path contains 'test', so PRE-FIX every fixture below is excluded.
Fix: match on relative-path COMPONENTS + anchored test-file detection.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from context.application_context import detect_entry_points  # noqa: E402

FASTAPI = "from fastapi import FastAPI\napp = FastAPI()\n"
EXPRESS = "const express = require('express')\nconst app = express()\n"


def _w(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_substring_false_positive_python(tmp_path):
    # 'protest_api.py' contains 'test' as a substring but is a real FastAPI entry point.
    _w(tmp_path / "protest_api.py", FASTAPI)
    out = detect_entry_points(tmp_path)
    assert "protest_api.py" in out, f"real entry point wrongly excluded by 'test' substring: {out!r}"


def test_parent_path_token_does_not_kill_all(tmp_path):
    # repo under a parent dir named 'latest' (contains 'test') — pre-fix excludes EVERY file.
    repo = tmp_path / "latest" / "app"
    _w(repo / "server.py", FASTAPI)
    out = detect_entry_points(repo)
    assert "server.py" in out, f"parent-path token wrongly excluded all files: {out!r}"


def test_js_substring_false_positive(tmp_path):
    # 'redistribute.js' contains 'dist' as a substring but is a real express entry point.
    _w(tmp_path / "redistribute.js", EXPRESS)
    out = detect_entry_points(tmp_path)
    assert "redistribute.js" in out, f"real JS entry point wrongly excluded by 'dist' substring: {out!r}"


def test_genuine_exclusions_preserved(tmp_path):
    # post-fix: a clean entry point IS detected; a real tests/ file and node_modules stay excluded.
    _w(tmp_path / "real_app.py", FASTAPI)
    _w(tmp_path / "tests" / "test_real.py", FASTAPI)
    _w(tmp_path / "node_modules" / "pkg" / "mod.py", FASTAPI)
    out = detect_entry_points(tmp_path)
    assert "real_app.py" in out, f"clean entry point should be detected: {out!r}"
    assert "test_real.py" not in out, f"genuine test file should stay excluded: {out!r}"
    assert "mod.py" not in out, f"node_modules should stay excluded: {out!r}"
