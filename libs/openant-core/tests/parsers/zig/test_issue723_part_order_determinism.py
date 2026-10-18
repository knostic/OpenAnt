"""T1 round-2 N3: the zig dependency-part order must not depend on the
PYTHONHASHSEED (set iteration). Swift sorted for exactly this reason; the
sort landed with the #723 remediation. The witness generates the same
3-dependency unit in FOUR subprocesses at fixed seeds and asserts the
outputs are byte-identical (the unsorted base fails with ~99.92% per run:
all four seeds would need the same chance order of a 3-element set)."""
from __future__ import annotations

import pathlib
import subprocess
import sys

from parsers.zig.unit_generator import UnitGenerator as ZigUnitGenerator

WORKER = r'''
import importlib, pathlib, sys
d = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(d))
sys.path.insert(0, str(d / "tests" / "parsers" / "zig"))
ug = importlib.import_module("parsers.zig.unit_generator")
cg_src = {
  "functions": {
    "A.zig:t": {"name": "t", "unit_type": "function", "file_path": "A.zig", "start_line": 1, "end_line": 1, "code": "pub fn t() { a(); b(); c(); }"},
    "A.zig:a": {"name": "a", "unit_type": "function", "file_path": "A.zig", "start_line": 2, "end_line": 2, "code": "fn a() { var x: u32 = 1; }"},
    "A.zig:b": {"name": "b", "unit_type": "function", "file_path": "A.zig", "start_line": 3, "end_line": 3, "code": "fn b() { var y: u32 = 2; }"},
    "A.zig:c": {"name": "c", "unit_type": "function", "file_path": "A.zig", "start_line": 4, "end_line": 4, "code": "fn c() { var z: u32 = 3; }"},
  },
  "call_graph": {"A.zig:t": ["A.zig:a", "A.zig:b", "A.zig:c"]},
  "reverse_call_graph": {"A.zig:a": ["A.zig:t"], "A.zig:b": ["A.zig:t"], "A.zig:c": ["A.zig:t"]},
  "statistics": {"total_edges": 3},
}
cg = cg_src
ds, _ = ug.UnitGenerator(cg, str(d)).generate(name="r")
u = [x for x in ds["units"] if ":t" in x["id"]][0]
sys.stdout.write(u["code"]["primary_code"])
'''


def _unit_at_seed(tree: str, seed: str) -> str:
    r = subprocess.run(
        [sys.executable, "-c", WORKER, tree],
        capture_output=True, text=True,
        env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin:/opt/homebrew/bin"},
    )
    assert r.returncode == 0, r.stderr[-200:]
    return r.stdout


def test_the_dependency_part_order_is_hash_seed_invariant():
    """Same corpus, four fixed seeds — the emitted unit must be identical."""
    assert ZigUnitGenerator.FILE_BOUNDARY == "\n\n// ========== File Boundary ==========\n\n", (
        "the generator under test is the production one")
    tree = str(pathlib.Path(__file__).resolve().parents[3])  # the core root
    outs = [_unit_at_seed(tree, seed) for seed in ("1", "2", "3", "4")]
    assert len(set(outs)) == 1, (
        "the dependency-part order varies with PYTHONHASHSEED — the dataset "
        "is non-deterministic (#723, T1 round-2 N3); the four seeded runs "
        "produced %d distinct outputs" % len(set(outs))
    )
