"""Regression tests for the Zig FunctionExtractor (u14).

Three confirmed extraction/metadata bugs, each reproduced through the REAL
extractor (FunctionExtractor.extract()) on a temp .zig file, asserting on the
emitted `functions` map.

- [BUG 16] fn-name extraction: a free fn whose return type is a bare named
           identifier (`fn makeWidget(v: i32) Widget { ... }`) is recorded
           under the RETURN-TYPE name (`Widget`) because the identifier loop
           overwrites `name` with the second `identifier` child (the return
           type). The real fn name must be the FIRST identifier.
- [BUG 26] test classification: `pub fn testConnection() bool {}` is wrongly
           classified `test` because `_classify_function` matches the
           `startswith("test")` prefix. A plain function named testXxx is a
           regular function, not a zig `test "..." {}` block.
- [BUG 37] struct/enum container methods: methods inside a
           `const Foo = struct { fn method() ... };` container are never
           extracted, because the walker keys on node types tree-sitter-zig
           never emits (`VarDecl`/`container_decl`). The real types are
           `variable_declaration` and `struct_declaration` / `enum_declaration`
           / `union_declaration` / `opaque_declaration`.
"""

import os
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.zig.function_extractor import FunctionExtractor


def _extract(src: str) -> dict:
    """Run the real extractor on a single zig source file; return extract() output."""
    workdir = tempfile.mkdtemp()
    file_path = os.path.join(workdir, "m.zig")
    with open(file_path, "w") as fh:
        fh.write(src)
    scan_results = {"files": [{"path": "m.zig"}]}
    return FunctionExtractor(workdir, scan_results).extract()


# ---------------------------------------------------------------------------
# [BUG 16] fn name must be the first identifier, not the return-type identifier
# ---------------------------------------------------------------------------

def test_bug16_named_return_type_does_not_shadow_fn_name():
    """`fn makeWidget(v: i32) Widget {}` must be recorded as makeWidget, not Widget."""
    src = (
        "const Widget = struct { x: i32 };\n\n"
        "pub fn makeWidget(v: i32) Widget {\n"
        "    return Widget{ .x = v };\n"
        "}\n"
    )
    out = _extract(src)
    funcs = out["functions"]
    assert "m.zig:makeWidget" in funcs, (
        f"makeWidget missing; functions keys = {sorted(funcs)}"
    )
    assert funcs["m.zig:makeWidget"]["name"] == "makeWidget"
    # The return-type identifier must NOT have become a phantom function.
    assert "m.zig:Widget" not in funcs, (
        f"return-type Widget leaked as a function; keys = {sorted(funcs)}"
    )


def test_bug16_generic_named_return_type_build_T():
    """Re-confirm the general case: `fn build() T` records build, not T."""
    src = "fn build() T {\n    return undefined;\n}\n"
    out = _extract(src)
    funcs = out["functions"]
    assert "m.zig:build" in funcs, f"build missing; keys = {sorted(funcs)}"
    assert funcs["m.zig:build"]["name"] == "build"
    assert "m.zig:T" not in funcs


# ---------------------------------------------------------------------------
# [BUG 26] a plain fn named testXxx must classify as 'function', not 'test'
# ---------------------------------------------------------------------------

def test_bug26_fn_named_testconnection_is_function_not_test():
    """`pub fn testConnection() bool {}` must have unit_type 'function'."""
    src = "pub fn testConnection() bool {\n    return true;\n}\n"
    out = _extract(src)
    funcs = out["functions"]
    assert "m.zig:testConnection" in funcs, f"keys = {sorted(funcs)}"
    assert funcs["m.zig:testConnection"]["unit_type"] == "function", (
        f"testConnection wrongly classified: "
        f"{funcs['m.zig:testConnection']['unit_type']!r}"
    )


# ---------------------------------------------------------------------------
# [BUG 37] container methods (struct/enum/union/opaque) must be extracted
#          under the qualified Container.method name.
# ---------------------------------------------------------------------------

def test_bug37_struct_method_qualified_name_extracted():
    """`const Foo = struct { fn method() ... };` must yield Foo.method."""
    src = (
        "pub fn ordinary() void {}\n\n"
        "const Foo = struct {\n"
        "    pub fn method(self: Foo) void {}\n"
        "};\n"
    )
    out = _extract(src)
    funcs = out["functions"]
    assert "m.zig:Foo.method" in funcs, (
        f"Foo.method missing; keys = {sorted(funcs)}"
    )
    info = funcs["m.zig:Foo.method"]
    assert info["qualified_name"] == "Foo.method"
    assert info["class_name"] == "Foo"
    assert info["unit_type"] == "method"
    # The struct itself should be recorded as a class.
    assert "m.zig:Foo" in out["classes"], f"classes = {sorted(out['classes'])}"


def test_bug37_enum_method_extracted():
    """`const E = enum { a, fn em() ... };` must yield E.em."""
    src = "const E = enum {\n    a,\n    pub fn em() void {}\n};\n"
    out = _extract(src)
    funcs = out["functions"]
    assert "m.zig:E.em" in funcs, f"keys = {sorted(funcs)}"
    assert funcs["m.zig:E.em"]["class_name"] == "E"


def test_bug37_union_method_extracted():
    """`const U = union(enum) { a: u8, fn um() ... };` must yield U.um."""
    src = "const U = union(enum) {\n    a: u8,\n    pub fn um() void {}\n};\n"
    out = _extract(src)
    funcs = out["functions"]
    assert "m.zig:U.um" in funcs, f"keys = {sorted(funcs)}"
    assert funcs["m.zig:U.um"]["class_name"] == "U"


def test_bug37_opaque_method_extracted():
    """`const O = opaque { fn om() ... };` must yield O.om."""
    src = "const O = opaque {\n    pub fn om() void {}\n};\n"
    out = _extract(src)
    funcs = out["functions"]
    assert "m.zig:O.om" in funcs, f"keys = {sorted(funcs)}"
    assert funcs["m.zig:O.om"]["class_name"] == "O"
