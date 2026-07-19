"""Regression lock: one pathological Ruby file must not abort the whole repo's extraction.

PR #136 added a per-file loop guard (`_process_file_guarded`) to the PYTHON extractor only.
The Ruby extractor's caller loops (`extract_from_scan`, `extract_all`) still called
`self.process_file(file_path)` directly, so a single file raising a non-parse error (e.g. a
`RecursionError` from a deeply-nested tree, or any bug in the extraction body) propagated out of
the file loop and aborted the entire parse, losing ALL units collected so far. The fix mirrors
Python/Zig/Go: wrap each file in `_process_file_guarded`.

These tests drive the real extractor entry points, not hand-constructed dicts.
"""
import os
import tempfile
from pathlib import Path

from parsers.ruby.function_extractor import FunctionExtractor


def _repo(files: dict) -> str:
    d = Path(os.path.realpath(tempfile.mkdtemp()))  # macOS /var -> /private/var so repo_path.resolve() matches
    for name, src in files.items():
        (d / name).write_text(src)
    return str(d)


def _wrap_boom(ex: FunctionExtractor, bad_name: str) -> None:
    """Simulate a REAL mid-extraction crash: raise INSIDE the extraction body
    (`_extract_functions_from_tree`), AFTER the point where the old buggy ordering had
    already incremented files_processed. This is what distinguishes the fix: with the
    increment moved to the END of process_file, a file crashing here is counted once as an
    error and never as processed. Patching process_file itself (raising before the increment)
    would be FALSE-GREEN — it never exercises the increment ordering."""
    orig = ex._extract_functions_from_tree

    def boom(*args, **kwargs):
        if any(bad_name in str(a) for a in args):
            raise RecursionError("simulated deep extraction recursion")
        return orig(*args, **kwargs)

    ex._extract_functions_from_tree = boom


def test_pathological_file_does_not_abort_extract_from_scan():
    repo = _repo({"good.rb": "def alpha\n  1\nend\n", "bad.rb": "def beta\n  2\nend\n"})
    ex = FunctionExtractor(repo)
    _wrap_boom(ex, "bad.rb")
    res = ex.extract_from_scan({"files": [{"path": "good.rb"}, {"path": "bad.rb"}]})
    assert "good.rb:alpha" in res["functions"], "good file's units lost — a bad file aborted the parse"
    assert res["statistics"]["files_with_errors"] >= 1


def test_pathological_file_does_not_abort_extract_all():
    repo = _repo({"good.rb": "def alpha\n  1\nend\n", "bad.rb": "def beta\n  2\nend\n"})
    ex = FunctionExtractor(repo)
    _wrap_boom(ex, "bad.rb")
    res = ex.extract_all(["good.rb", "bad.rb"])
    assert "good.rb:alpha" in res["functions"], "post-parse crash in one file aborted the batch"
    assert res["statistics"]["files_with_errors"] >= 1


def test_stats_not_double_counted():
    repo = _repo({"good.rb": "def alpha\n  1\nend\n", "bad.rb": "def beta\n  2\nend\n"})
    ex = FunctionExtractor(repo)
    _wrap_boom(ex, "bad.rb")
    st = ex.extract_all(["good.rb", "bad.rb"])["statistics"]
    assert st["files_processed"] == 1, "a crashed file must not be counted as processed"
    assert st["files_with_errors"] == 1
