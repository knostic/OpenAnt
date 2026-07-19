"""Regression test: RepositoryScanner must not infinitely recurse on a
directory symlink loop.

Before the fix, scan_directory() used ``entry.is_dir()`` (which *follows*
symlinks) and recursed with no cycle guard, so a symlink pointing back at an
ancestor directory produced unbounded recursion (RecursionError / duplicate
scanning). This test builds a symlink loop and asserts scan() terminates with a
bounded, duplicate-free result.
"""
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))


def _load_scanner():
    path = _CORE_ROOT / "parsers" / "ruby" / "repository_scanner.py"
    spec = importlib.util.spec_from_file_location("rs_ruby_symlink_cycle", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.RepositoryScanner


SCANNER = _load_scanner()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unsupported")
def test_symlink_loop_terminates_without_recursion_error(tmp_path):
    repo = tmp_path / "repo"
    sub = repo / "app"
    sub.mkdir(parents=True)
    (sub / "widget.rb").write_text("puts 'hi'\n")

    # A directory symlink pointing back at the repo root -> infinite loop
    # unless the scanner tracks visited directories.
    try:
        os.symlink(repo, sub / "loop", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create directory symlink on this platform")

    scanner = SCANNER(str(repo))
    result = scanner.scan()  # buggy code raises RecursionError here

    paths = [f["path"] for f in result["files"]]
    # The single real source file must be found exactly once (no duplicates
    # from re-entering the repo through the symlink loop).
    assert sum(1 for p in paths if Path(p).name == "widget.rb") == 1, paths
