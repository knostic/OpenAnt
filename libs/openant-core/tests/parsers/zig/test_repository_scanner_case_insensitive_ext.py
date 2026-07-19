"""Regression test: the Zig RepositoryScanner must match the .zig extension
case-insensitively.

Bug: repository_scanner.py used ``filename.endswith(".zig")`` (case-sensitive),
so a file named ``Main.ZIG`` (uppercase extension) was silently skipped from the
scan and never analysed.
"""
import importlib.util
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))


def _load_scanner():
    path = _CORE_ROOT / "parsers" / "zig" / "repository_scanner.py"
    spec = importlib.util.spec_from_file_location("rs_zig_case_insensitive", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.RepositoryScanner


SCANNER = _load_scanner()


def _scanned_paths(repo: Path):
    results = SCANNER(str(repo)).scan()
    return {f["path"] for f in results["files"]}


def test_uppercase_zig_extension_is_scanned():
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / "lower.zig").write_text("const x = 1;")
        (repo / "Main.ZIG").write_text("const y = 2;")
        (repo / "Mixed.Zig").write_text("const z = 3;")
        paths = _scanned_paths(repo)
    assert "lower.zig" in paths
    assert "Main.ZIG" in paths
    assert "Mixed.Zig" in paths


def test_non_zig_extension_still_skipped():
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / "readme.md").write_text("hi")
        (repo / "code.zig").write_text("const x = 1;")
        paths = _scanned_paths(repo)
    assert "code.zig" in paths
    assert "readme.md" not in paths
