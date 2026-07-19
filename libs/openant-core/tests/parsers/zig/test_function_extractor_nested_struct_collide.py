"""Regression test: nested-struct methods must not collide on func_id.

The walker threads a single struct name as the qualifier for a method's func_id
(`file:Struct.method`). For a struct nested inside another struct the context was
REPLACED rather than NESTED, so only the innermost struct name survived. Two
different outer structs that each contain an inner struct of the same name with a
same-named method therefore produced the SAME func_id
(`file:Inner.method`) — last-write-wins silently dropped all but the last.

Anchor: parsers/zig/function_extractor.py:133 (functions[func_id] = func_info).

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
from parsers.zig.call_graph_builder import CallGraphBuilder


def _extract(src: str) -> dict:
    workdir = tempfile.mkdtemp()
    with open(os.path.join(workdir, "m.zig"), "w") as fh:
        fh.write(src)
    return FunctionExtractor(workdir, {"files": [{"path": "m.zig"}]}).extract()


def _pipeline(src: str) -> dict:
    """Real extractor -> builder pipeline on a single zig source file."""
    workdir = tempfile.mkdtemp()
    with open(os.path.join(workdir, "m.zig"), "w") as fh:
        fh.write(src)
    out = FunctionExtractor(workdir, {"files": [{"path": "m.zig"}]}).extract()
    return CallGraphBuilder(out).build()


def _zig_parser_is_grammar_aligned() -> bool:
    """Prerequisite probe: does a *named* struct's method extract as Container.method?
    Provided by the tree-sitter-zig>=1.1.2 grammar alignment; independent of this fix.
    On a stale-grammar base no struct methods extract at all."""
    probe = "const _Probe = struct {\n    pub fn _m(self: _Probe) void { _ = self; }\n};\n"
    return "m.zig:_Probe._m" in _extract(probe)["functions"]


pytestmark = pytest.mark.skipif(
    not _zig_parser_is_grammar_aligned(),
    reason=(
        "Zig parser not grammar-aligned (needs tree-sitter-zig>=1.1.2). On such a base "
        "no struct methods extract, so this nesting fix cannot be exercised."
    ),
)


def test_nested_struct_same_named_methods_do_not_collide():
    src = (
        "const Http = struct {\n"
        "    const Message = struct {\n"
        "        pub fn parse(self: Message) void { _ = self; }\n"
        "    };\n"
        "};\n"
        "const Ftp = struct {\n"
        "    const Message = struct {\n"
        "        pub fn parse(self: Message) void { _ = self; }\n"
        "    };\n"
        "};\n"
    )
    funcs = _extract(src)["functions"]
    # Both parse methods must survive with fully-qualified, distinct func_ids.
    assert "m.zig:Http.Message.parse" in funcs, f"keys = {sorted(funcs)}"
    assert "m.zig:Ftp.Message.parse" in funcs, f"keys = {sorted(funcs)}"
    assert funcs["m.zig:Http.Message.parse"]["qualified_name"] == "Http.Message.parse"
    assert funcs["m.zig:Ftp.Message.parse"]["qualified_name"] == "Ftp.Message.parse"
    # The un-nested (last-write-wins) key must NOT be the only survivor.
    assert len([k for k in funcs if k.endswith("Message.parse")]) == 2, sorted(funcs)


def test_generic_container_nested_in_struct_does_not_collide():
    # Zig generic-container idiom (type-returning fn) nested inside two structs.
    src = (
        "const A = struct {\n"
        "    pub fn Iter() type { return struct { pub fn next() void {} }; }\n"
        "};\n"
        "const B = struct {\n"
        "    pub fn Iter() type { return struct { pub fn next() void {} }; }\n"
        "};\n"
    )
    funcs = _extract(src)["functions"]
    assert "m.zig:A.Iter.next" in funcs, f"keys = {sorted(funcs)}"
    assert "m.zig:B.Iter.next" in funcs, f"keys = {sorted(funcs)}"


def test_nested_struct_class_name_stays_bare_leaf_for_receiver_resolution():
    """The storage KEY carries the full nested scope, but class_name stays the BARE
    leaf so the receiver resolver still matches an in-scope `var x = Inner{}` type.

    This asserts BOTH halves of the decoupling:
      (a) two Outer/Ftp each with a same-named Inner.method do NOT collide -- they
          keep two distinct, fully-qualified func_ids; AND
      (b) a plain single Outer{Inner{...}} with `var x = Inner{}; x.method()` STILL
          resolves the caller -> Inner.method edge. Making class_name dotted
          (Outer.Inner) to fix (a) broke (b): _resolve_typed_member matches
          class_name against the bare receiver type "Inner", so a dotted class_name
          found no match and dropped the edge. This is the regression this closes.
    """
    # (a) collision-free storage keys with a bare class_name leaf.
    collide_src = (
        "const Http = struct {\n"
        "    const Inner = struct {\n"
        "        pub fn method(self: Inner) void { _ = self; }\n"
        "    };\n"
        "};\n"
        "const Ftp = struct {\n"
        "    const Inner = struct {\n"
        "        pub fn method(self: Inner) void { _ = self; }\n"
        "    };\n"
        "};\n"
    )
    funcs = _extract(collide_src)["functions"]
    distinct = [k for k in funcs if k.endswith("Inner.method")]
    assert sorted(distinct) == ["m.zig:Ftp.Inner.method", "m.zig:Http.Inner.method"], distinct
    # class_name is the bare leaf ("Inner"), not the dotted path ("Http.Inner").
    assert funcs["m.zig:Http.Inner.method"]["class_name"] == "Inner", funcs["m.zig:Http.Inner.method"]
    assert funcs["m.zig:Ftp.Inner.method"]["class_name"] == "Inner", funcs["m.zig:Ftp.Inner.method"]

    # (b) regression: a bare-name receiver on a nested struct still resolves the edge.
    edge_src = (
        "const Outer = struct {\n"
        "    const Inner = struct {\n"
        "        pub fn method(self: Inner) void { _ = self; }\n"
        "    };\n"
        "    pub fn use(self: Outer) void {\n"
        "        _ = self;\n"
        "        var x = Inner{};\n"
        "        x.method();\n"
        "    }\n"
        "};\n"
    )
    cg = _pipeline(edge_src)["call_graph"]
    assert "m.zig:Outer.Inner.method" in cg.get("m.zig:Outer.use", []), (
        f"expected use -> Inner.method edge; got call_graph={dict(cg)}"
    )
