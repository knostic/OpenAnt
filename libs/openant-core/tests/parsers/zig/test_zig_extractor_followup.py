"""Regression tests for the Zig function/struct extractor.

Pinned against the actual tree-sitter-zig 1.1.2 grammar (the AST node-type
names below were confirmed by parsing sample Zig with the live grammar):

  - struct FIELDS (`container_field` nodes) must not be emitted as function
    units, and struct extraction must actually run. The extractor previously
    gated struct handling on grammar node types `VarDecl` / `container_decl` /
    `ContainerDecl` that the real 1.1.2 grammar never emits (it emits
    `variable_declaration` / `struct_declaration`), so struct extraction was
    dead code (0 classes) and the field/method paths were unreachable.

  - a struct method must appear exactly once, qualified as `<Struct>.<method>`,
    not duplicated as a bare top-level function. `_extract_struct_methods`
    emitted the qualified entry, then the unconditional child recursion in
    `_walk_node` re-descended into the same struct body and re-emitted the
    method bare because `current_struct` was never threaded through.

  - `tree_sitter_zig` was imported hard at module top level and called at
    class-body time, so a clean environment without the grammar package raised
    ImportError on import. The parser must degrade gracefully (importable; a
    clear error only when actually used).

The basename `function_extractor.py` recurs across parser packages
(c/cpp/php/python/ruby/zig), so this module is loaded under a unique name via
importlib to avoid any sys.modules cache collision.
"""

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))

# tree-sitter-zig is required to exercise the extractor; skip cleanly if absent.
ts_zig = pytest.importorskip("tree_sitter_zig")

_EXTRACTOR_PATH = _CORE_ROOT / "parsers" / "zig" / "function_extractor.py"


def _load_extractor_module():
    """Load parsers/zig/function_extractor.py under a unique module name."""
    spec = importlib.util.spec_from_file_location(
        "zig_function_extractor_isolated", _EXTRACTOR_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _extract(source: str) -> dict:
    """Run FunctionExtractor over a single in-memory main.zig file."""
    module = _load_extractor_module()
    repo = tempfile.mkdtemp()
    (Path(repo) / "main.zig").write_text(source)
    extractor = module.FunctionExtractor(repo, {"files": [{"path": "main.zig"}]})
    return extractor.extract()


# A struct with two fields and two methods, plus a free function.
_SAMPLE = """const std = @import("std");

const Point = struct {
    x: i32,
    y: i32,

    pub fn init(x: i32, y: i32) Point {
        return Point{ .x = x, .y = y };
    }

    pub fn distance(self: Point) i32 {
        return self.x + self.y;
    }
};

fn helper(n: i32) i32 {
    return n * 2;
}
"""


def test_struct_field_is_not_a_function():
    """`container_field` struct fields must never become function units."""
    result = _extract(_SAMPLE)
    func_names = {info["name"] for info in result["functions"].values()}
    assert "x" not in func_names, f"struct field 'x' emitted as a function: {func_names}"
    assert "y" not in func_names, f"struct field 'y' emitted as a function: {func_names}"


def test_struct_is_extracted_as_a_class():
    """The struct must be extracted as a class (grammar-drift had killed this)."""
    result = _extract(_SAMPLE)
    class_names = {info["name"] for info in result["classes"].values()}
    assert "Point" in class_names, (
        f"struct 'Point' was not extracted as a class; classes={class_names}. "
        "Struct handling is gated on grammar node types the 1.1.2 grammar "
        "does not emit (VarDecl/container_decl)."
    )


def test_only_real_methods_extracted_and_qualified_once():
    """Each method appears exactly once, qualified as Point.<name>; no bare dup."""
    result = _extract(_SAMPLE)
    funcs = result["functions"]
    qualified = [info["qualified_name"] for info in funcs.values()]

    # The two methods must be present, qualified, exactly once each.
    assert qualified.count("Point.init") == 1, f"Point.init not uniquely qualified: {qualified}"
    assert qualified.count("Point.distance") == 1, (
        f"Point.distance not uniquely qualified: {qualified}"
    )

    # No bare duplicate of a method that also exists qualified.
    assert "init" not in qualified, f"method 'init' emitted bare (duplicate): {qualified}"
    assert "distance" not in qualified, (
        f"method 'distance' emitted bare (duplicate): {qualified}"
    )

    # The return-type identifier of init ('Point') must not be captured as a function name.
    assert "Point" not in qualified, (
        f"return-type identifier 'Point' captured as a function name: {qualified}"
    )

    # The free function is still extracted, bare.
    assert qualified.count("helper") == 1, f"free function 'helper' missing: {qualified}"


def test_nested_struct_and_import_not_dropped():
    """De-duplicating methods must not drop nested declarations.

    A naive fix that simply stops recursing into a struct body to avoid the
    bare-duplicate emission would also lose nested structs, their methods, and
    nested @import calls. The correct fix threads the struct context through
    recursion (same func_id => natural de-dup), so everything below is kept.
    """
    source = (
        "const Outer = struct {\n"
        '    const builtin = @import("builtin");\n'
        "\n"
        "    const Inner = struct {\n"
        "        pub fn innerFn() void {}\n"
        "    };\n"
        "\n"
        "    pub fn outerFn() void {}\n"
        "};\n"
    )
    result = _extract(source)
    qualified = [info["qualified_name"] for info in result["functions"].values()]
    class_names = {info["name"] for info in result["classes"].values()}

    assert "Outer.outerFn" in qualified, qualified
    assert "Inner.innerFn" in qualified, qualified
    assert "Outer" in class_names, class_names
    assert "Inner" in class_names, class_names
    assert "builtin" in result["imports"]["main.zig"], result["imports"]


def test_methods_marked_as_methods_with_class_name():
    """Qualified methods carry unit_type=method and class_name=Point."""
    result = _extract(_SAMPLE)
    methods = {
        info["qualified_name"]: info
        for info in result["functions"].values()
        if info["qualified_name"].startswith("Point.")
    }
    assert set(methods) == {"Point.init", "Point.distance"}, sorted(methods)
    for info in methods.values():
        assert info["unit_type"] == "method", info
        assert info["class_name"] == "Point", info


def test_module_imports_without_grammar_package(monkeypatch):
    """The parser module must import even when tree_sitter_zig is absent.

    Simulate a clean environment by hiding `tree_sitter_zig` from import, then
    load the module fresh. A hard top-level import + class-body call raises
    ImportError here; a graceful (lazy/guarded) parser imports fine and only
    fails when the grammar is actually needed.
    """
    # Drop any cached copies so the fresh import re-evaluates the import machinery.
    for name in list(sys.modules):
        if name == "tree_sitter_zig" or name.startswith("tree_sitter_zig."):
            monkeypatch.delitem(sys.modules, name, raising=False)
        if name.startswith("zig_function_extractor_isolated"):
            monkeypatch.delitem(sys.modules, name, raising=False)

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def _blocked_import(name, *args, **kwargs):
        if name == "tree_sitter_zig" or name.startswith("tree_sitter_zig."):
            raise ImportError("No module named 'tree_sitter_zig' (simulated clean env)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _blocked_import)

    spec = importlib.util.spec_from_file_location(
        "zig_function_extractor_isolated_nodep", _EXTRACTOR_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        # Must not raise: importing the parser cannot require the grammar package.
        spec.loader.exec_module(module)
    except ImportError as exc:  # pragma: no cover - this is the failure we pin against
        pytest.fail(
            "Zig parser module raised ImportError on import when tree_sitter_zig "
            f"is absent (no graceful degradation): {exc}"
        )
    finally:
        sys.modules.pop(spec.name, None)


def test_pyproject_declares_tree_sitter_zig():
    """The zig grammar must be declared as a dependency (it is imported)."""
    pyproject = (_CORE_ROOT / "pyproject.toml").read_text()
    requirements = (_CORE_ROOT / "requirements.txt").read_text()
    assert "tree-sitter-zig" in pyproject, (
        "tree-sitter-zig imported by parsers/zig but missing from pyproject.toml dependencies"
    )
    assert "tree-sitter-zig" in requirements, (
        "tree-sitter-zig imported by parsers/zig but missing from requirements.txt"
    )
