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

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.zig.function_extractor import FunctionExtractor


def _extract(src: str) -> dict:
    workdir = tempfile.mkdtemp()
    with open(os.path.join(workdir, "m.zig"), "w") as fh:
        fh.write(src)
    return FunctionExtractor(workdir, {"files": [{"path": "m.zig"}]}).extract()


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
