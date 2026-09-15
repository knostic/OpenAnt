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
    # Whether _STACK_BLOWER actually crashes is platform-dependent on 3.14+ (deep
    # binary-op chains overflow the C stack on macos/windows but parse cleanly on
    # ubuntu's larger stacks). Assert the accounting invariant instead of the
    # crash itself: every file lands in exactly one bucket. Crash-recording is
    # still covered deterministically by test_post_parse_extraction_error_is_isolated,
    # which injects the error rather than relying on this fixture.
    st = res["statistics"]
    assert st["files_processed"] + st["files_with_errors"] == 2


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
    # Bucket assignment, not just accounting: the crashed file must land in
    # files_with_errors AND must not be counted as processed (a mislabeling
    # regression keeps the sum invariant but reports the wrong bucket).
    assert res["statistics"]["files_processed"] == 1


def test_extract_all_crash_is_isolated_and_bucketed():
    """extract_all's per-file guard, exercised deterministically. The fixture-based
    extract_all test above is vacuous on platforms where _STACK_BLOWER parses
    cleanly (ubuntu on 3.14+), so without this companion no test would cover
    extract_all's crash-isolation path there. Mirrors the Ruby extractor's
    injected-crash template."""
    repo = _repo({"good.py": "def eps():\n    return 6\n", "boom.py": "def trigger_boom():\n    return 1\n"})
    ex = FunctionExtractor(repo)
    orig = ex.process_function

    def boom(node, *a, **k):
        if getattr(node, "name", "") == "trigger_boom":
            raise RecursionError("simulated deep extraction recursion")
        return orig(node, *a, **k)

    ex.process_function = boom
    res = ex.extract_all(["good.py", "boom.py"])
    assert "good.py:eps" in res["functions"], "post-parse crash in one file aborted extract_all"
    st = res["statistics"]
    assert st["files_with_errors"] == 1, f"crash not recorded: {st}"
    assert st["files_processed"] == 1, f"crashed file mislabeled as processed: {st}"


def test_parse_stage_crash_is_isolated_and_bucketed():
    """A crash INSIDE ast.parse (RecursionError from deep nesting) must be isolated
    like a post-parse crash, recorded in files_with_errors, and never counted as
    processed. Deterministic — the crash is injected, unlike _STACK_BLOWER, whose
    crash occurrence is platform/stack-size dependent on 3.14+."""
    import parsers.python.function_extractor as fe_mod

    repo = _repo({"good.py": "def delta():\n    return 4\n", "deep.py": "def d():\n    return 5\n"})
    ex = FunctionExtractor(repo)
    orig_parse = fe_mod.ast.parse

    def parse_boom(source, *a, **k):
        if "return 5" in source:
            raise RecursionError("simulated parse-stage stack overflow")
        return orig_parse(source, *a, **k)

    fe_mod.ast.parse = parse_boom
    try:
        res = ex.extract_from_scan({"files": [{"path": "good.py"}, {"path": "deep.py"}]})
    finally:
        fe_mod.ast.parse = orig_parse
    assert "good.py:delta" in res["functions"], "parse-stage crash aborted the batch"
    st = res["statistics"]
    assert st["files_with_errors"] == 1, f"parse-stage crash not recorded: {st}"
    assert st["files_processed"] == 1, f"crashed file mislabeled as processed: {st}"


def test_stats_not_double_counted():
    repo = _repo({
        "g1.py": "def a():\n    return 1\n",
        "g2.py": "def b():\n    return 2\n",
        "bad.py": _STACK_BLOWER,
    })
    # Same platform-dependence as above: on interpreters where the fixture parses
    # cleanly, the file is (correctly) counted as processed; where it crashes it
    # is counted once as an error and never as processed. Either way no file is
    # counted twice, so the buckets must sum to the file count.
    st = FunctionExtractor(repo).extract_all(["g1.py", "g2.py", "bad.py"])["statistics"]
    assert st["files_processed"] + st["files_with_errors"] == 3, "a file was counted twice (or lost)"
