"""Regression test for the Zig generic-container method-attribution bug.

Zig's idiomatic generic container is a type-returning function:
    pub fn List(comptime T: type) type { return struct { pub fn push(...) ... }; }
The returned struct is anonymous in the AST (a `struct_declaration` reached via
`return_expression`), NOT a `const Name = struct {...}` (`variable_declaration`).
The walker only threaded struct context for the variable_declaration form, so methods
inside a type-returning container were emitted as bare top-level functions with
class_name=None — and two distinct containers' same-named methods collided on one id.

Driven through the REAL extractor (FunctionExtractor.extract()) on a temp .zig file.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.zig.function_extractor import FunctionExtractor


def _extract(src: str) -> dict:
    workdir = tempfile.mkdtemp()
    with open(os.path.join(workdir, "m.zig"), "w") as fh:
        fh.write(src)
    return FunctionExtractor(workdir, {"files": [{"path": "m.zig"}]}).extract()


def _zig_parser_is_grammar_aligned() -> bool:
    """Probe the PREREQUISITE behavior (not this fix's): does a *named* struct's method
    extract as Container.method? That capability is provided by the tree-sitter-zig
    grammar-alignment work (>=1.1.2 node names struct_declaration/variable_declaration;
    PRs 87/110, commit 322920e), independent of the generic-container fix under test.
    On a base whose parser still matches stale node names (VarDecl/container_decl), no
    struct methods extract at all, so these tests cannot pass for reasons unrelated to
    the fix."""
    probe = "const _Probe = struct {\n    pub fn _m(self: _Probe) void { _ = self; }\n};\n"
    return "m.zig:_Probe._m" in _extract(probe)["functions"]


# Skip (not fail) with an explanatory message when run on a base that lacks the
# grammar-alignment prerequisite — so a human or agent running this on raw master sees
# *why* instead of a cryptic assertion failure. Supported base: staging/parser-fix-stack,
# which carries upstream PR #110 (Zig parser realignment) AND the tree-sitter-zig>=1.1.2
# grammar pin. This is NOT landable on master standalone.
pytestmark = pytest.mark.skipif(
    not _zig_parser_is_grammar_aligned(),
    reason=(
        "Zig parser not grammar-aligned (needs tree-sitter-zig>=1.1.2 node names "
        "struct_declaration/variable_declaration, from upstream PR #110 + the grammar "
        "pin). On such a base no struct methods extract, so the generic-container fix "
        "cannot pass. Supported base: staging/parser-fix-stack — not landable on master."
    ),
)


def test_generic_container_method_qualified_to_container():
    src = (
        "pub fn List(comptime T: type) type {\n"
        "    return struct {\n"
        "        pub fn push(self: *@This(), x: T) void { _ = self; _ = x; }\n"
        "    };\n"
        "}\n"
        "fn ordinary() void {}\n"
    )
    out = _extract(src)
    funcs = out["functions"]
    assert "m.zig:List.push" in funcs, f"List.push missing; keys = {sorted(funcs)}"
    info = funcs["m.zig:List.push"]
    assert info["class_name"] == "List"
    assert info["qualified_name"] == "List.push"
    assert info["unit_type"] == "method"
    # The method must NOT leak as a bare top-level function.
    assert "m.zig:push" not in funcs, f"unqualified push leaked: {sorted(funcs)}"
    # The plain function is unaffected.
    assert "m.zig:ordinary" in funcs, sorted(funcs)


def test_two_generic_containers_methods_no_collision():
    src = (
        "pub fn List(comptime T: type) type {\n"
        "    return struct { pub fn len(self: *@This()) usize { _ = self; return 0; } };\n"
        "}\n"
        "pub fn Ring(comptime T: type) type {\n"
        "    return struct { pub fn len(self: *@This()) usize { _ = self; return 1; } };\n"
        "}\n"
    )
    funcs = _extract(src)["functions"]
    assert "m.zig:List.len" in funcs, f"keys = {sorted(funcs)}"
    assert "m.zig:Ring.len" in funcs, f"silent collision/data-loss; keys = {sorted(funcs)}"
