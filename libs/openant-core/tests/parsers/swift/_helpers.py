"""Shared loaders for the Swift-parser tests.

The parser stage modules share bare names across languages
(`function_extractor.py`, `call_graph_builder.py`, ...). Load the Swift ones by
file path under unique module names so they never collide with the sibling
C/Zig/Python extractors in ``sys.modules`` (same isolation pattern the Zig tests
use). Not collected by pytest (no ``test_`` prefix)."""

import importlib.util
import pathlib

_CORE = pathlib.Path(__file__).resolve().parents[3]


def _load(relpath: str, uniqname: str):
    spec = importlib.util.spec_from_file_location(uniqname, _CORE / relpath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RepositoryScanner = _load("parsers/swift/repository_scanner.py", "swift_scanner_iso").RepositoryScanner
FunctionExtractor = _load("parsers/swift/function_extractor.py", "swift_fe_iso").FunctionExtractor
CallGraphBuilder = _load("parsers/swift/call_graph_builder.py", "swift_cgb_iso").CallGraphBuilder
UnitGenerator = _load("parsers/swift/unit_generator.py", "swift_ug_iso").UnitGenerator


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
