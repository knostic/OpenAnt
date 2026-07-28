"""Tests for src/language_support.py — dominant-language detection used to
gate Python-only deterministic signals on non-Python repositories."""

from __future__ import annotations

import sys
from pathlib import Path


from utilities.autopatcher.language_support import detect_language, is_python_repo


def write(path: Path, content: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_detects_python_repo(tmp_path: Path):
    write(tmp_path / "src" / "foo.py", "def foo():\n    pass\n")
    write(tmp_path / "tests" / "test_foo.py", "def test_foo():\n    pass\n")

    assert detect_language(tmp_path) == "python"
    assert is_python_repo(tmp_path) is True


def test_detects_c_repo(tmp_path: Path):
    write(tmp_path / "lib" / "http.c", "int Curl_follow(void) { return 0; }\n")
    write(tmp_path / "lib" / "http.h", "int Curl_follow(void);\n")

    assert detect_language(tmp_path) == "c"
    assert is_python_repo(tmp_path) is False


def test_detects_javascript_repo(tmp_path: Path):
    write(tmp_path / "index.js", "module.exports = function() {};\n")
    write(tmp_path / "lib" / "parse.js", "function parse() {}\n")

    assert detect_language(tmp_path) == "javascript"
    assert is_python_repo(tmp_path) is False


def test_mixed_repo_uses_dominant_extension(tmp_path: Path):
    # A handful of stray .py maintenance scripts must not flip a C repo to "python".
    write(tmp_path / "lib" / "a.c", "int a(void) { return 0; }\n")
    write(tmp_path / "lib" / "b.c", "int b(void) { return 0; }\n")
    write(tmp_path / "lib" / "c.c", "int c(void) { return 0; }\n")
    write(tmp_path / "scripts" / "release.py", "print('release')\n")

    assert detect_language(tmp_path) == "c"


def test_empty_repo_is_unknown(tmp_path: Path):
    assert detect_language(tmp_path) == "unknown"
    assert is_python_repo(tmp_path) is False


def test_missing_repo_root_is_unknown():
    assert detect_language(None) == "unknown"
    assert detect_language(Path("/definitely/does/not/exist/xyz")) == "unknown"


def test_ignored_dirs_excluded_from_detection(tmp_path: Path):
    write(tmp_path / "lib" / "a.c", "int a(void) { return 0; }\n")
    write(
        tmp_path / ".venv" / "lib" / "python3.14" / "site-packages" / "pkg" / "mod.py",
        "x = 1\n",
    )

    assert detect_language(tmp_path) == "c"
