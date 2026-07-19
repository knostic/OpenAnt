"""Regression lock: one pathological C/C++ file must not abort the whole repo's extraction.

PR #136 added a per-file loop guard (`_process_file_guarded`) to the PYTHON extractor only.
The C extractor's caller loops (`extract_from_scan`, `extract_all`) still called
`self.process_file(file_path)` directly, so a single file raising a non-parse error propagated
out of the file loop and aborted the entire parse, losing ALL units collected so far. The fix
mirrors Python/Zig/Go: wrap each file in `_process_file_guarded`.

NOTE: requires the optional `tree_sitter_c` dependency; skipped where it is not installed.
"""
import os
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_c")

from parsers.c.function_extractor import FunctionExtractor  # noqa: E402


def _repo(files: dict) -> str:
    d = Path(os.path.realpath(tempfile.mkdtemp()))  # macOS /var -> /private/var so repo_path.resolve() matches
    for name, src in files.items():
        (d / name).write_text(src)
    return str(d)


def _wrap_boom(ex: FunctionExtractor, bad_name: str) -> None:
    """Simulate a REAL mid-extraction crash: raise INSIDE the extraction body
    (`_extract_functions_from_tree`), AFTER the point where the old buggy ordering had
    already incremented files_processed. Patching process_file itself (raising before the
    increment) would be FALSE-GREEN — it never exercises the increment ordering."""
    orig = ex._extract_functions_from_tree

    def boom(*args, **kwargs):
        if any(bad_name in str(a) for a in args):
            raise RecursionError("simulated deep extraction recursion")
        return orig(*args, **kwargs)

    ex._extract_functions_from_tree = boom


_GOOD = "int alpha(void) { return 1; }\n"
_BAD = "int beta(void) { return 2; }\n"


def test_pathological_file_does_not_abort_extract_from_scan():
    repo = _repo({"good.c": _GOOD, "bad.c": _BAD})
    ex = FunctionExtractor(repo)
    _wrap_boom(ex, "bad.c")
    res = ex.extract_from_scan({"files": [{"path": "good.c"}, {"path": "bad.c"}]})
    assert "good.c:alpha" in res["functions"], "good file's units lost — a bad file aborted the parse"
    assert res["statistics"]["files_with_errors"] >= 1


def test_pathological_file_does_not_abort_extract_all():
    repo = _repo({"good.c": _GOOD, "bad.c": _BAD})
    ex = FunctionExtractor(repo)
    _wrap_boom(ex, "bad.c")
    res = ex.extract_all(["good.c", "bad.c"])
    assert "good.c:alpha" in res["functions"], "post-parse crash in one file aborted the batch"
    assert res["statistics"]["files_with_errors"] >= 1


def test_stats_not_double_counted():
    repo = _repo({"good.c": _GOOD, "bad.c": _BAD})
    ex = FunctionExtractor(repo)
    _wrap_boom(ex, "bad.c")
    st = ex.extract_all(["good.c", "bad.c"])["statistics"]
    assert st["files_processed"] == 1, "a crashed file must not be counted as processed"
    assert st["files_with_errors"] == 1
