"""Tests for utilities.file_io UTF-8 helpers and a regression scan."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CORE_ROOT))

from utilities.file_io import open_utf8, read_json, run_utf8, write_json  # noqa: E402


NON_ASCII = "héllo 日本語 — café"


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------

def test_open_utf8_round_trip(tmp_path: Path):
    p = tmp_path / "x.txt"
    with open_utf8(p, "w") as f:
        f.write(NON_ASCII)
    with open_utf8(p) as f:
        assert f.read() == NON_ASCII


def test_open_utf8_passes_through_binary_mode(tmp_path: Path):
    """Binary mode should not get encoding= injected."""
    p = tmp_path / "raw.bin"
    payload = NON_ASCII.encode("utf-8")
    with open_utf8(p, "wb") as f:
        f.write(payload)
    with open_utf8(p, "rb") as f:
        assert f.read() == payload


def test_open_utf8_caller_encoding_wins(tmp_path: Path):
    """If caller explicitly passes encoding=, helper must not override it."""
    p = tmp_path / "y.txt"
    p.write_bytes("café".encode("latin-1"))
    with open_utf8(p, encoding="latin-1") as f:
        assert f.read() == "café"


def test_read_json_round_trip(tmp_path: Path):
    p = tmp_path / "data.json"
    obj = {"greeting": NON_ASCII, "list": ["a", NON_ASCII, "b"]}
    write_json(p, obj)
    assert read_json(p) == obj


def test_write_json_uses_utf8(tmp_path: Path):
    """write_json must encode non-ASCII as UTF-8 bytes (not cp1252)."""
    p = tmp_path / "data.json"
    write_json(p, {"k": NON_ASCII})
    raw = p.read_bytes()
    # The non-ASCII characters should appear as their UTF-8 encoding (or as
    # JSON-escaped \uXXXX sequences — both are valid; the key is that the
    # file does not contain a cp1252-encoded ?-replacement).
    decoded = raw.decode("utf-8")
    parsed = json.loads(decoded)
    assert parsed["k"] == NON_ASCII


def test_write_json_default_indent(tmp_path: Path):
    """write_json should pretty-print by default for human readability."""
    p = tmp_path / "data.json"
    write_json(p, {"a": 1, "b": 2})
    text = p.read_text(encoding="utf-8")
    # Indented output spans multiple lines.
    assert "\n" in text


# ---------------------------------------------------------------------------
# run_utf8 subprocess test
# ---------------------------------------------------------------------------

def test_run_utf8_captures_non_ascii_text():
    """run_utf8 with text=True must decode UTF-8 stdout without raising on cp1252."""
    code = (
        "import sys; "
        "sys.stdout.buffer.write('"
        + NON_ASCII
        + "'.encode('utf-8'))"
    )
    result = run_utf8(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout == NON_ASCII


def test_run_utf8_universal_newlines_alias(tmp_path: Path):
    """universal_newlines=True is an alias for text=True; must also get UTF-8."""
    code = (
        "import sys; "
        "sys.stdout.buffer.write('"
        + NON_ASCII
        + "'.encode('utf-8'))"
    )
    result = run_utf8(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout == NON_ASCII


def test_run_utf8_invalid_bytes_replaced_not_raised():
    """errors='replace' default means invalid bytes don't raise."""
    code = (
        "import sys; "
        "sys.stdout.buffer.write(b'good\\x9d_bad')"
    )
    result = run_utf8(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    # Invalid byte 0x9d is replaced by U+FFFD rather than raising.
    assert "good" in result.stdout
    assert "bad" in result.stdout


def test_run_utf8_caller_can_override_errors_default_strict():
    """Without text=True, run_utf8 should not inject errors='replace'.

    Confirms that the encoding/errors injection only fires for text-mode
    captures, leaving binary subprocess invocations untouched.
    """
    result = run_utf8(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\x9d')"],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert result.stdout == b"\x9d"


def test_run_utf8_does_not_override_explicit_encoding():
    """If caller passes encoding= explicitly, run_utf8 must not overwrite it."""
    result = run_utf8(
        [sys.executable, "-c", "print('caf\\xe9')"],
        capture_output=True,
        text=True,
        encoding="latin-1",
        timeout=30,
    )
    assert result.returncode == 0
    assert "café" in result.stdout


# ---------------------------------------------------------------------------
# Regression scan: no bare open() calls reappear in non-test code
# ---------------------------------------------------------------------------

def _iter_python_sources(root: Path):
    for p in root.rglob("*.py"):
        rel = p.relative_to(root).as_posix()
        if rel.startswith("tests/"):
            continue
        if rel == "utilities/file_io.py":
            continue
        # Skip vendored/build artifacts
        if any(part in {".venv", "venv", "build", "dist", "__pycache__"} for part in p.parts):
            continue
        yield p


_OPEN_CALL_RE = re.compile(r"(?<![A-Za-z0-9_.])open\s*\(")


def _strip_strings_and_comments(text: str) -> str:
    """Replace string literals and comments with spaces so identifier matches inside
    docstrings/comments don't trigger the regression check."""
    out = []
    i = 0
    n = len(text)
    in_str = None
    triple = False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\" and not triple:
                out.append("  ")
                i += 2
                continue
            if triple and text[i:i + 3] == in_str:
                out.append("   ")
                in_str = None
                triple = False
                i += 3
                continue
            if not triple and c == in_str:
                in_str = None
                out.append(" ")
                i += 1
                continue
            if not triple and c == "\n":
                in_str = None
                out.append("\n")
                i += 1
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if c == "#":
            nl = text.find("\n", i)
            if nl == -1:
                out.append(" " * (n - i))
                break
            out.append(" " * (nl - i))
            i = nl
            continue
        if text[i:i + 3] in ('"""', "'''"):
            in_str = text[i:i + 3]
            triple = True
            out.append("   ")
            i += 3
            continue
        if c in ("'", '"'):
            in_str = c
            out.append(" ")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _has_encoding(call_args: str) -> bool:
    return re.search(r"\bencoding\s*=", call_args) is not None


def _has_binary_mode(call_args: str) -> bool:
    return re.search(r"""(['"])([rwax+]*b[rwax+]*)\1""", call_args) is not None


def test_no_bare_open_in_non_test_code():
    """Regression: every text-mode `open(` call in non-test code must specify
    encoding=, otherwise Windows defaults to cp1252 and crashes on non-ASCII
    source code.
    """
    offenders: list[str] = []
    for path in _iter_python_sources(CORE_ROOT):
        text = path.read_text(encoding="utf-8")
        scrubbed = _strip_strings_and_comments(text)
        for m in _OPEN_CALL_RE.finditer(scrubbed):
            # Find matching close paren in the SCRUBBED text (parens preserved).
            i = m.end()
            depth = 1
            while i < len(scrubbed) and depth:
                ch = scrubbed[i]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                i += 1
            if depth != 0:
                continue
            args = text[m.end():i - 1]
            if _has_binary_mode(args) or _has_encoding(args):
                continue
            line = text[:m.start()].count("\n") + 1
            rel = path.relative_to(CORE_ROOT).as_posix()
            offenders.append(f"{rel}:{line}: {text.splitlines()[line - 1].strip()}")

    assert not offenders, (
        "Found bare open() calls without encoding= in non-test code. "
        "Use utilities.file_io.open_utf8 / read_json / write_json or pass "
        "encoding='utf-8' explicitly:\n  " + "\n  ".join(offenders)
    )
