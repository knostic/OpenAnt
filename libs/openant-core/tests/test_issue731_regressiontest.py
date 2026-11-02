"""Regression tests for OpenAnt issue #731."""

import os
import subprocess
import sys
import tracemalloc

from pathlib import Path

import pytest

from utilities.agentic_enhancer.repository_index import RepositoryIndex


@pytest.fixture
def index(tmp_path):
    # Create a RepositoryIndex for a temporary repository.
    return RepositoryIndex({"functions": {}}, repo_path=str(tmp_path))


def test_inclusive_line_ranges(index, tmp_path):
    # Verify that requested lines are 1-indexed and inclusive.
    (tmp_path / "sample.py").write_text(
        "first\nsecond\nthird\nfourth\n",
        encoding="utf-8",
    )

    assert index.read_file_section("sample.py", 2, 3) == "second\nthird\n"
    assert index.read_file_section("sample.py", 1, 1) == "first\n"
    assert index.read_file_section("sample.py", 4, 4) == "fourth\n"
    assert index.read_file_section("sample.py", 10, 20) == ""


def test_missing_and_traversal(index):
    # Preserve original behavior for missing and invalid paths.
    assert index.read_file_section("missing.py", 1, 2) is None
    assert index.read_file_section("../secret.txt", 1, 2) is None
    assert index.read_file_section("/etc/hosts", 1, 2) is None


def test_large_file_memory(index, tmp_path):
    # Ensure a small section doesn't require loading the whole file.
    file = tmp_path / "large.py"

    with file.open("w", encoding="utf-8") as handle:
        for i in range(200_000):
            handle.write(f"line {i}: " + "x" * 40 + "\n")

    tracemalloc.start()
    try:
        result = index.read_file_section("large.py", 1, 2)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert result is not None
    assert len(result.splitlines()) == 2
    assert peak < 1024 * 1024


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"),
    reason="FIFO unavailable on this platform",
)
def test_fifo_does_not_hang(tmp_path):
    # Use a separate process so a blocking read cannot hang pytest.
    fifo = tmp_path / "pipe.py"
    os.mkfifo(fifo)

    script = """
import sys
from utilities.agentic_enhancer.repository_index import RepositoryIndex

directory = sys.argv[1]
index = RepositoryIndex({"functions": {}}, repo_path=directory)
result = index.read_file_section("pipe.py", 1, 5)

assert result is None
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert completed.returncode == 0, completed.stderr


def test_oversized_line(index, tmp_path):
    # A single enormous line should be rejected.
    (tmp_path / "huge.py").write_bytes(
        b"x" * (1024 * 1024 + 10)
    )

    assert index.read_file_section("huge.py", 1, 1) is None


def test_symlink_rejected(index, tmp_path):
    # Symlinks should not be followed.
    target = tmp_path / "target.py"
    target.write_text("secret\n", encoding="utf-8")

    link = tmp_path / "link.py"
    link.symlink_to(target)

    assert index.read_file_section("link.py", 1, 1) is None


def test_whole_file_read(index, tmp_path):
    # Preserve the autopatcher's whole-file reading behavior.
    content = "print('hello world')\n" * 20_000
    (tmp_path / "source.py").write_text(
        content,
        encoding="utf-8",
    )

    assert index.read_file_section("source.py", 1, 10**9) == content
