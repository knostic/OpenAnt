"""Centralized file I/O and subprocess helpers for Windows UTF-8 compatibility.

On Windows, Python's default encoding is often ``cp1252`` (charmap), which
cannot decode common UTF-8 sequences found in source code.  These thin
wrappers ensure that every file open and subprocess call uses UTF-8
explicitly, preventing ``'charmap' codec can't decode byte ...`` errors.
"""

import json
import os
import subprocess
from typing import Any, Union

# Accept str, Path, or any os.PathLike
PathLike = Union[str, os.PathLike]


def open_utf8(path: PathLike, mode: str = "r", **kwargs):
    """Open a file with UTF-8 encoding by default.

    Drop-in replacement for ``open()`` that sets ``encoding='utf-8'`` unless
    the caller explicitly provides a different encoding or opens in binary
    mode.
    """
    if "b" not in mode and "encoding" not in kwargs:
        kwargs["encoding"] = "utf-8"
    return open(path, mode, **kwargs)


def read_json(path: PathLike) -> Any:
    """Read and parse a JSON file using UTF-8 encoding."""
    with open_utf8(path, "r") as f:
        return json.load(f)


def write_json(path: PathLike, data: Any, **kwargs) -> None:
    """Write data as JSON to a file using UTF-8 encoding."""
    kwargs.setdefault("indent", 2)
    with open_utf8(path, "w") as f:
        json.dump(data, f, **kwargs)


def run_utf8(*args, **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess with UTF-8 encoding for text mode.

    Wrapper around ``subprocess.run`` that sets ``encoding='utf-8'`` and
    ``errors='replace'`` when ``text=True`` (or its alias
    ``universal_newlines=True``) is passed, preventing charmap decode errors
    on Windows.

    Note: ``errors='replace'`` substitutes U+FFFD for invalid bytes in
    stdout/stderr rather than raising. This is intentional - subprocess
    output is used for status display and diagnostics, not for security
    analysis (parser results are read from JSON files separately).
    Callers can override with ``errors='strict'`` if needed.
    """
    if kwargs.get("text") or kwargs.get("universal_newlines"):
        kwargs.setdefault("encoding", "utf-8")
        kwargs.setdefault("errors", "replace")
    return subprocess.run(*args, **kwargs)
