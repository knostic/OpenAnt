"""Regression locks: one pathological Python file must not abort the whole repo's extraction.

Before the fix, `FunctionExtractor.process_file` guarded only `ast.parse` (`except SyntaxError`),
while the extraction body and both caller loops (`extract_from_scan`, `extract_all`) were
unguarded. A single file raising a non-SyntaxError (e.g. `RecursionError` from a deeply-nested
source, or any error in the tree walk) propagated out of the file loop and aborted the entire
parse, losing ALL units collected so far. The fix adds a per-file guard at the loop
(`_process_file_guarded`), mirroring the Zig/Go parsers.

These tests drive the real extractor entry points (extract_from_scan = the production path used
by parse_repository, and extract_all), not hand-constructed dicts.
"""
import tempfile
from pathlib import Path

from parsers.python.function_extractor import FunctionExtractor


def _repo(files: dict) -> str:
    d = Path(tempfile.mkdtemp())
    for name, src in files.items():
        (d / name).write_text(src)
    return str(d)


# A file whose parse overflows CPython's stack inside ast.parse -> RecursionError.
#
# This was `"x = a" + ".b" * 60000`, a deeply-nested attribute chain. CPython 3.14's
# PEG parser handles left-recursive attribute chains iteratively, so that input now
# parses cleanly and the fixture stopped being pathological — the two tests below
# failed, and a third (test_pathological_file_does_not_abort_extract_all) began
# passing vacuously, isolating an error that no longer occurred.
#
# The production guard was never at fault: _process_file_guarded still works, as
# test_post_parse_extraction_error_is_isolated demonstrates by injecting the error
# rather than relying on this fixture. So the fix belongs here, not in the parser.
#
# A long binary-operator chain still recurses in 3.14.
_STACK_BLOWER = "x = " + "1+" * 100000 + "1\n"


def test_pathological_file_does_not_abort_extract_from_scan():
    repo = _repo({"good.py": "def alpha(x):\n    return x + 1\n", "bad.py": _STACK_BLOWER})
    ex = FunctionExtractor(repo)
    res = ex.extract_from_scan({"files": [{"path": "good.py"}, {"path": "bad.py"}]})
    assert "good.py:alpha" in res["functions"], "good file's units lost — a bad file aborted the parse"
    assert res["statistics"]["files_with_errors"] >= 1


def test_pathological_file_does_not_abort_extract_all():
    repo = _repo({"good.py": "def beta(a, b):\n    return a + b\n", "bad.py": _STACK_BLOWER})
    res = FunctionExtractor(repo).extract_all(["good.py", "bad.py"])
    assert "good.py:beta" in res["functions"]


def test_post_parse_extraction_error_is_isolated():
    """A crash AFTER ast.parse (in the tree walk) must also be isolated — the guard is at the
    loop, not just around ast.parse, so it covers the extraction body too."""
    repo = _repo({
        "good.py": "def gamma():\n    return 3\n",
        "boom.py": "def trigger_boom():\n    return 1\n",
    })
    ex = FunctionExtractor(repo)
    orig = ex.process_function

    def boom(node, *a, **k):
        if getattr(node, "name", "") == "trigger_boom":
            raise RecursionError("simulated deep extraction recursion")
        return orig(node, *a, **k)

    ex.process_function = boom
    res = ex.extract_from_scan({"files": [{"path": "good.py"}, {"path": "boom.py"}]})
    assert "good.py:gamma" in res["functions"], "post-parse crash in one file aborted the batch"
    assert res["statistics"]["files_with_errors"] >= 1


def test_stats_not_double_counted():
    repo = _repo({
        "g1.py": "def a():\n    return 1\n",
        "g2.py": "def b():\n    return 2\n",
        "bad.py": _STACK_BLOWER,
    })
    st = FunctionExtractor(repo).extract_all(["g1.py", "g2.py", "bad.py"])["statistics"]
    assert st["files_processed"] == 2, "a crashed file must not be counted as processed"
    assert st["files_with_errors"] == 1
