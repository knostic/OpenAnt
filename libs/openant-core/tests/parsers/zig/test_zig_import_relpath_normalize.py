"""Regression test: Zig @import relative paths must be normalized before
matching the stored (repo-relative) file key.

BUG (zig-import-relpath-no-normalize-edge-drop): the call-graph builder matches
an `@import("...")` path string verbatim against candidate file keys. When the
import uses a relative path with `../` or `./` (as any cross-directory Zig
import does), the raw string never equals the repo-relative candidate key, so
the import fails to disambiguate an otherwise-ambiguous bare-name call and the
cross-file edge is DROPPED.

Reproduced through the REAL extractor -> builder pipeline over a multi-file,
multi-directory repo.
"""

import os
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.zig.function_extractor import FunctionExtractor
from parsers.zig.call_graph_builder import CallGraphBuilder


def _run_multifile(files: dict) -> dict:
    """files: {repo_relative_path: source}. Runs extractor -> builder."""
    workdir = tempfile.mkdtemp()
    for rel, src in files.items():
        full = os.path.join(workdir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fh:
            fh.write(src)
    scan_results = {"files": [{"path": p} for p in files]}
    extractor_output = FunctionExtractor(workdir, scan_results).extract()
    return CallGraphBuilder(extractor_output).build()


def test_relative_import_with_dotdot_resolves_cross_file_edge():
    """`a/main.zig` importing `../b/helper.zig` must link to b's `helpFn`,
    not be dropped as ambiguous against an unrelated same-named `helpFn`.

    A second, unrelated `c/other.zig:helpFn` makes the bare name ambiguous, so
    the edge survives ONLY if the `../b/helper.zig` import is normalized to the
    repo-relative key `b/helper.zig` and used to disambiguate.
    """
    files = {
        "a/main.zig": (
            "const helper = @import(\"../b/helper.zig\");\n"
            "fn f() void { helper.helpFn(); }\n"
        ),
        "b/helper.zig": "fn helpFn() void {}\n",
        "c/other.zig": "fn helpFn() void {}\n",
    }
    cg = _run_multifile(files)["call_graph"]
    edges = cg.get("a/main.zig:f", [])
    assert "b/helper.zig:helpFn" in edges, (
        "Expected f -> b/helper.zig:helpFn edge via normalized ../ import, "
        f"got call_graph[a/main.zig:f]={edges}"
    )
    assert "c/other.zig:helpFn" not in edges, (
        f"Should NOT over-connect to unrelated helpFn, got {edges}"
    )
