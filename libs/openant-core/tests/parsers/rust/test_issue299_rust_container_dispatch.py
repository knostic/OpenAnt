"""Regression tests for issue #299 (Rust member — 7 of 7): container-literal
dispatch loses call edges.

Rust's ``_describe_callee`` handled generic_function / identifier /
field_expression / scoped_identifier — an index_expression callee
(``TBL[i]()``) returned None, so the dispatcher's targets were orphaned.
Per the umbrella's own measurement the subscript-call idiom is RARE in
idiomatic Rust (zero code hits across 2,432 .rs files in 10 projects —
match, dyn Fn, and bound-local lookup all resolve); this member completes
the seven-parser family, fixture-proven, with the pre-registered
expectation gained≈0 on real corpora.

Contract locked here:
- a container of function references (static array literal, the common
  synthetic shape) plus a subscript call records edges to every referenced
  function — the caller set contains the DISPATCHER specifically;
- a direct-call CONTROL keeps its edge;
- an unknown subscript base abstains — no invented edges;
- a let-bound local container works the same.
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
        parse_repository(repo, out, language="rust", processing_level="all",
                         skip_tests=True, name="r")
        with open(os.path.join(out, "call_graph.json")) as fh:
            return json.load(fh)


def _edges(cg, caller_suffix):
    keys = [k for k in cg["call_graph"] if k.endswith(caller_suffix)]
    return [e for k in keys for e in cg["call_graph"][k]]


_FIXTURE = {
    "main.rs":
        "fn handler_a() -> i32 { 1 }\n"
        "fn handler_b() -> i32 { 2 }\n"
        "fn direct_target() -> i32 { 3 }\n"
        "\n"
        "static TBL: [fn() -> i32; 2] = [handler_a, handler_b];\n"
        "\n"
        "fn dispatch(i: usize) -> i32 {\n"
        "    direct_target();\n"          # CONTROL
        "    TBL[i]()\n"
        "}\n",
}


def test_static_container_dispatch_edges():
    cg = _cg(_FIXTURE)
    edges = _edges(cg, ":dispatch")
    assert any("handler_a" in e for e in edges), edges
    assert any("handler_b" in e for e in edges), edges


def test_direct_call_control_passes():
    cg = _cg(_FIXTURE)
    assert any("direct_target" in e for e in _edges(cg, ":dispatch"))


def test_local_let_container_dispatch():
    cg = _cg({
        "main.rs":
            "fn h1() -> i32 { 1 }\n"
            "fn h2() -> i32 { 2 }\n"
            "fn dispatch(i: usize) -> i32 {\n"
            "    let t: [fn() -> i32; 2] = [h1, h2];\n"
            "    t[i]()\n"
            "}\n",
    })
    edges = _edges(cg, ":dispatch")
    assert any("h1" in e for e in edges), edges
    assert any("h2" in e for e in edges), edges


def test_unknown_subscript_abstains():
    cg = _cg({
        "main.rs":
            "fn data() -> i32 { 1 }\n"
            "fn use_(i: usize) -> i32 {\n"
            "    let d = [1, 2, 3];\n"
            "    d[i]()\n"
            "}\n",
    })
    assert _edges(cg, ":use_") == []
