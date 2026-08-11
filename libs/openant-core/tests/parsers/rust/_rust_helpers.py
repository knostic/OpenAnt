"""Shared loaders for the Rust-parser tests.

The parser stage modules share bare names across languages
(`function_extractor.py`, `call_graph_builder.py`, ...). Load the Rust ones by
file path under unique module names so they never collide with the sibling
C/Zig/Swift extractors in ``sys.modules`` (same isolation pattern the Swift/Zig
tests use). Not collected by pytest (no ``test_`` prefix).
"""

import importlib
import pathlib
import sys

_CORE = pathlib.Path(__file__).resolve().parents[3]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

# Import the stage modules as a PACKAGE (`parsers.rust.*`), not by bare file
# path: the Rust call_graph_builder does an intra-package relative import
# (`from .function_extractor import _bare_type_name`) for its type inference,
# which only resolves with package context. The qualified names are unique, so
# they never collide with the sibling-language stage modules in sys.modules —
# the same isolation the swift/zig file-path loaders get, achieved via the
# package namespace instead. (Swift's loader can use bare paths only because its
# CGB has no cross-module import.)
RepositoryScanner = importlib.import_module("parsers.rust.repository_scanner").RepositoryScanner
FunctionExtractor = importlib.import_module("parsers.rust.function_extractor").FunctionExtractor
CallGraphBuilder = importlib.import_module("parsers.rust.call_graph_builder").CallGraphBuilder
UnitGenerator = importlib.import_module("parsers.rust.unit_generator").UnitGenerator


def extract(tmp_path, files: dict, skip_tests: bool = True) -> dict:
    """Write ``files`` (relpath -> source) under tmp_path, run scanner+extractor."""
    for name, src in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src)
    scan = RepositoryScanner(str(tmp_path), skip_tests=skip_tests).scan()
    return FunctionExtractor(str(tmp_path), scan).extract()


def build(tmp_path, files: dict, skip_tests: bool = True):
    """Full extract -> call graph. Returns (extractor_output, callgraph_output)."""
    ext = extract(tmp_path, files, skip_tests=skip_tests)
    cg = CallGraphBuilder(ext).build()
    return ext, cg


def leaf(func_id: str) -> str:
    """Drop the ``file:`` prefix from a func_id for readable assertions."""
    return func_id.split(":", 1)[1] if ":" in func_id else func_id


def edges(cg: dict):
    """Set of (caller_leaf, callee_leaf) edges."""
    out = set()
    for caller, callees in cg["call_graph"].items():
        for c in callees:
            out.add((leaf(caller), leaf(c)))
    return out
