"""Regression tests for the C parser include-map non-deterministic
basename/suffix match.

CallGraphBuilder consumes a plain extractor_output dict, so these drive it directly
(no repo fixture or extractor run needed). It does build a tree-sitter C Parser at
init, so the module skips where tree_sitter_c is unavailable, like the other C tests.
Two compounding faults:

  Fault 1 (construction over-match): include_map was filled by
    `other_file.endswith(inc) or other_file.endswith('/' + inc)` — the bare
    `endswith(inc)` disjunct matches any path whose tail is the token even across
    a non-'/' boundary (include "x.h" wrongly matches "src/prefix-x.h").

  Fault 2 (consumption non-determinism): _resolve_call iterated the *unordered*
    include_map set and returned the first base_name==call_name match, so with two
    same-basename headers in different dirs each defining f(), the winner depended
    on set iteration order -> flipped across PYTHONHASHSEED.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

CORE = Path(__file__).resolve().parents[3]  # libs/openant-core (test is at tests/parsers/c/)
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

pytest.importorskip("tree_sitter_c")  # CallGraphBuilder builds a tree-sitter C Parser at init

from parsers.c.call_graph_builder import CallGraphBuilder  # noqa: E402


def _extractor_output():
    # foo/x.h and bar/x.h both define f() (same basename header, different dirs).
    # src/prefix-x.h ends with the token "x.h" but NOT with "/x.h" -> must NOT match.
    return {
        "functions": {
            "F_foo": {"name": "f", "file_path": "foo/x.h", "code": "void f(void){}"},
            "F_bar": {"name": "f", "file_path": "bar/x.h", "code": "void f(void){}"},
            "F_prefix": {"name": "g", "file_path": "src/prefix-x.h", "code": "void g(void){}"},
            "F_main": {"name": "main", "file_path": "main.c", "code": "int main(void){ f(); return 0; }"},
        },
        "includes": {"main.c": ["x.h"]},
    }


def test_include_map_no_basename_overmatch():
    """Fault 1: include 'x.h' matches foo/x.h + bar/x.h (path-component boundary)
    but must NOT match src/prefix-x.h (bare-suffix tail match = false positive)."""
    b = CallGraphBuilder(_extractor_output())
    b._build_indexes()
    inc = b.include_map.get("main.c", set())
    assert "foo/x.h" in inc and "bar/x.h" in inc, f"legit same-basename headers must match: {sorted(inc)}"
    assert "src/prefix-x.h" not in inc, f"over-match: include 'x.h' wrongly matched 'src/prefix-x.h': {sorted(inc)}"


_DRIVER = (
    "import sys; sys.path.insert(0, %r);"
    "from parsers.c.call_graph_builder import CallGraphBuilder;"
    "b = CallGraphBuilder(%r); b._build_indexes();"
    "print(b._resolve_call('f', 'main.c'))"
)


def test_include_resolution_deterministic_across_hashseeds():
    """Fault 2: with two same-basename headers each defining f(), _resolve_call must be
    deterministic across PYTHONHASHSEED (set-iteration order must not pick the winner)
    and must select the lexicographically-first file's func (stable tiebreak)."""
    eo = _extractor_output()
    results = []
    for seed in range(10):
        env = dict(os.environ, PYTHONHASHSEED=str(seed))
        out = subprocess.run(
            [sys.executable, "-c", _DRIVER % (str(CORE), eo)],
            capture_output=True, text=True, env=env, cwd=str(CORE),
        )
        assert out.returncode == 0, f"driver failed (seed={seed}): {out.stderr}"
        results.append(out.stdout.strip())
    assert len(set(results)) == 1, f"non-deterministic resolution across PYTHONHASHSEED: {sorted(set(results))}"
    # stable tiebreak = lexicographically-first file: 'bar/x.h' < 'foo/x.h' -> F_bar
    assert results[0] == "F_bar", f"expected stable lexicographic winner F_bar, got {results[0]!r}"
