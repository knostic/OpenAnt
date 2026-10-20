"""T1 round-2 N3: the rust dependency-part order must not depend on the
PYTHONHASHSEED (set iteration). Swift sorted for exactly this reason; the
sort landed with the #723 remediation. The witness generates the same
3-dependency unit in FOUR subprocesses at fixed seeds and asserts the
outputs are byte-identical (the unsorted base fails with ~99.92% per run:
all four seeds would need the same chance order of a 3-element set)."""
from __future__ import annotations

import pathlib
import subprocess
import sys

from parsers.rust.unit_generator import UnitGenerator as RustUnitGenerator

WORKER = r'''
import importlib, pathlib, sys, tempfile
core = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(core))
sys.path.insert(0, str(core / "tests" / "parsers" / "rust"))
h = importlib.import_module("_rust_helpers")
ug = importlib.import_module("parsers.rust.unit_generator")
corpus = {"A.rs": "pub fn t() { a(); b(); c(); }\nfn a(){ let x=1; }\nfn b(){ let y=2; }\nfn c(){ let z=3; }\n"}
# build in a THROWAWAY dir (T1 round-3 F-A): never write the corpus into
# the source tree, never scan the whole core tree
work = pathlib.Path(tempfile.mkdtemp(prefix="det723_"))
try:
    _, cg = h.build(work, corpus)
    ds, _ = ug.UnitGenerator(cg, str(work)).generate(name="r")
finally:
    import shutil; shutil.rmtree(work, ignore_errors=True)
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
    assert RustUnitGenerator.FILE_BOUNDARY == "\n\n// ========== File Boundary ==========\n\n", (
        "the generator under test is the production one")
    tree = str(pathlib.Path(__file__).resolve().parents[3])  # the core root (imported FROM, never written to)
    outs = [_unit_at_seed(tree, seed) for seed in ("1", "2", "3", "4")]
    assert len(set(outs)) == 1, (
        "the dependency-part order varies with PYTHONHASHSEED — the dataset "
        "is non-deterministic (#723, T1 round-2 N3); the four seeded runs "
        "produced %d distinct outputs" % len(set(outs))
    )
