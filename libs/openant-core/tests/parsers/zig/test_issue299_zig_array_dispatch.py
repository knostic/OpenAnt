"""Regression tests for issue #299 (Zig member — 2 of 7): the array/subscript
dispatch shape loses call edges.

Zig already resolves the STRUCT-FIELD shape (`const h = T{ .cb = fn }; h.cb()`
via _collect_field_fn_bindings — the closest in-repo template for this fix
family). The ARRAY shape (`const tbl = [_]fn () void{ handlerA, handlerB };
tbl[i]()`) records nothing: the callee is an index_expression, a shape the
callee-type check omits, and file-scope const declarations are invisible to
the per-function alias index (the scope defect the umbrella documents).

Contract locked here:
- a container literal of function references (array form) plus a subscript
  call through it records edges to EVERY referenced function — the caller
  set contains the DISPATCHER specifically (the umbrella's fixture rule);
- file-scope containers are visible to every function in the file (the
  alias index's scope defect fixed for this shape);
- a direct-call CONTROL keeps its edge (null-result meaningfulness) and
  the struct-field shape keeps working (the template must not regress);
- an unknown subscript base abstains — no edge to a same-named function
  (the Go false-edge lesson, applied proactively).
"""

import json
import os
import sys
import tempfile

# #415: two ".." from tests/parsers/<lang> inserted `tests/` — and tests/parsers/
# is a REGULAR package that outranks the source parsers/ namespace, so every
# later in-process parsers.* import in the same pytest batch resolved into the
# TEST directory (the rust collection errors, the zig/php shadow binds). The
# insert only exists so the file runs standalone; it needs the core root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from core.parser_adapter import parse_repository  # noqa: E402


def _cg(files: dict):
    with tempfile.TemporaryDirectory() as _repo, tempfile.TemporaryDirectory() as out:
        repo = os.path.realpath(_repo)
        for rel, content in files.items():
            p = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
        parse_repository(repo, out, language="zig", processing_level="all",
                         skip_tests=True, name="r")
        with open(os.path.join(out, "call_graph.json"), encoding="utf-8") as fh:
            return json.load(fh)


def _edges(cg, caller_suffix):
    keys = [k for k in cg["call_graph"] if k.endswith(caller_suffix)]
    return [e for k in keys for e in cg["call_graph"][k]]


_ARRAY_FIXTURE = {
    "main.zig":
        "const std = @import(\"std\");\n"
        "fn handlerA() void { std.process.exit(1); }\n"
        "fn handlerB() void {}\n"
        "fn directTarget() void {}\n"
        # file-scope container: the common placement
        "const tbl = [_]fn () void{ handlerA, handlerB };\n"
        "pub fn dispatch(i: usize) void {\n"
        "    directTarget();\n"      # CONTROL
        "    tbl[i]();\n"
        "}\n",
}


def test_array_container_dispatch_edges():
    """tbl[i]() through a file-scope array of function references edges to
    every referenced function — the dispatcher specifically."""
    cg = _cg(_ARRAY_FIXTURE)
    edges = _edges(cg, ":dispatch")
    assert any("handlerA" in e for e in edges), edges
    assert any("handlerB" in e for e in edges), edges


def test_direct_call_control_passes():
    cg = _cg(_ARRAY_FIXTURE)
    assert any("directTarget" in e for e in _edges(cg, ":dispatch"))


def test_struct_field_shape_still_resolves():
    """The template must not regress: h.cb() through a struct field-init
    binding still resolves (this is the pre-existing handled shape)."""
    cg = _cg({
        "main.zig":
            "const Handler = struct { callback: *const fn () void };\n"
            "fn sink() void {}\n"
            "pub fn main() void {\n"
            "    const h = Handler{ .callback = sink };\n"
            "    h.callback();\n"
            "}\n",
    })
    assert any("sink" in e for e in _edges(cg, ":main"))


def test_local_array_container_in_function():
    """A container built INSIDE a function body: same dispatch through the
    local name."""
    cg = _cg({
        "main.zig":
            "fn h1() void {}\n"
            "fn h2() void {}\n"
            "pub fn dispatch(i: usize) void {\n"
            "    const t = [_]fn () void{ h1, h2 };\n"
            "    t[i]();\n"
            "}\n",
    })
    edges = _edges(cg, ":dispatch")
    assert any("h1" in e for e in edges), edges
    assert any("h2" in e for e in edges), edges


def test_unknown_subscript_abstains():
    """A subscript over a name with no known function-referencing container
    records nothing — no edge to a same-named function (the Go false-edge
    lesson)."""
    cg = _cg({
        "main.zig":
            # a function sharing the array's name — must NOT receive an edge
            "fn data() void {}\n"
            "pub fn use(i: usize) void {\n"
            "    const data = [_]i32{1, 2, 3};\n"   # NOT a fn container
            "    const x = data[i];\n"
            "    _ = x;\n"
            "}\n",
    })
    assert _edges(cg, ":use") == []



def test_local_shadow_does_not_leak_file_wide():
    """Regression (panel finding): a function-local container shadowing a
    file-scope name must not mutate the file map other functions see —
    the per-function merge must deep-copy, never share set references."""
    cg = _cg({"app.zig": (
        "fn handlerA() void {}\n"
        "fn handlerB() void {}\n"
        "const TABLE = [_]*const fn () void{ handlerA };\n"
        "fn main() void {\n"
        "    const TABLE = [_]*const fn () void{ handlerB };\n"
        "    TABLE[0]();\n"
        "}\n"
        "fn other() void {\n"
        "    TABLE[0]();\n"
        "}\n"
    )})
    main_edges = _edges(cg, ":main")
    other_edges = _edges(cg, ":other")
    assert any("handlerB" in e for e in main_edges), "main's local table dispatches to handlerB"
    assert any("handlerA" in e for e in other_edges), "other still sees the FILE table (handlerA)"
    assert not any("handlerB" in e for e in other_edges), "main's local binding must NOT leak to other"
