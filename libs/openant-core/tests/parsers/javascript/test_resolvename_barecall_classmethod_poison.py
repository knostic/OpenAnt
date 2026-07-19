"""Regression: a bare call inside a class method must resolve to a same-named
free FUNCTION, not to a same-named sibling class METHOD.

A bare `run()` (no `this.`/receiver) can only target a free function in scope;
a sibling method requires a receiver. The same-file resolver scanned exact and
member ('Class.run') matches in one pass, so declaration order let the method
poison the edge (FAM-A misdirection).
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def _analyze(repo_path, file_path):
    cmd = ["node", str(PARSERS_JS_DIR / "typescript_analyzer.js"), str(repo_path), str(file_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, f"analyzer failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    return json.loads(result.stdout)


def _analyze_multi(repo_path, *file_paths):
    cmd = ["node", str(PARSERS_JS_DIR / "typescript_analyzer.js"), str(repo_path)]
    cmd += [str(p) for p in file_paths]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, f"analyzer failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    return json.loads(result.stdout)


def test_barecall_not_poisoned_by_sibling_method_crossfile(tmp_path):
    """The live manifestation: the free function lives in another file, so the
    same-file sibling method is the only same-name unit in the caller's file.

    A bare `run()` must resolve to the cross-file free function, NOT the
    same-file `Runner.run` sibling method it can never actually invoke.
    """
    repo = tmp_path / "poison"
    repo.mkdir()
    a = repo / "a.js"
    b = repo / "b.js"
    a.write_text(
        "class Runner {\n"
        "  start() { return run(); }\n"   # bare call
        "  run() { return 1; }\n"          # sibling method -> the poison
        "}\n"
    )
    b.write_text("function run() { return 2; }\n")  # free function -> correct target

    out = _analyze_multi(repo, a, b)
    targets = out["call_graph"].get("a.js:Runner.start", [])
    assert "a.js:Runner.run" not in targets, f"bare run() poisoned to sibling method; got {targets}"
    assert "b.js:run" in targets, f"bare run() must resolve to cross-file free function; got {targets}"


def test_member_call_still_resolves_sibling_method(tmp_path):
    """Guardrail: a receiver call `this.run()` must STILL reach the same-file
    sibling method (the member path is only gated, not removed).

    A same-name free FUNCTION coexists in the SAME file. This exercises the
    1a/1b ordering: the exact 1a match would grab the free `run()` first, so the
    resolver must run the member-suffix (1b) match BEFORE 1a for receiver calls.
    Without the coexisting free function this test is false-green (nothing forces
    1b to precede 1a)."""
    repo = tmp_path / "member"
    repo.mkdir()
    fp = repo / "file.js"
    fp.write_text(
        "function run() { return 9; }\n"          # coexisting free function (1a bait)
        "class Runner {\n"
        "  start() { return this.run(); }\n"       # receiver call -> must hit method
        "  run() { return 1; }\n"                  # sibling method -> correct target
        "}\n"
    )
    out = _analyze(repo, fp)
    targets = out["call_graph"].get("file.js:Runner.start", [])
    assert "file.js:Runner.run" in targets, f"this.run() must reach sibling method; got {targets}"
    assert "file.js:run" not in targets, (
        f"this.run() must NOT resolve to coexisting free function; got {targets}"
    )
