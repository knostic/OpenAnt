"""Regression tests for issue #299 (Swift member — 3 of 7): container-literal
dispatch loses call edges.

Swift drops `tbl[i]()` because the OUTER call node's callee is an INNER
call_expression (the subscript `tbl[i]`), a shape _extract_calls handles only
as simple_identifier or navigation_expression; the inner subscript is skipped
by the explicit `not _is_subscript(node)` guard. The maintainer's corrected
guidance (the original item-4 narrowing is WITHDRAWN — it fabricates edges):
bind container literals in _collect_aliases (array_literal /
dictionary_literal RHS), make file-scope `let` visible (the alias index
parses only each function's own code), and add a subscript-callee case that
resolves through the alias set. The guard itself stays (it excludes genuine
subscript OPERATOR calls) and gains its rationale comment.

Contract locked here:
- an array/dictionary literal of function references plus a subscript call
  records edges to every referenced function — the caller set contains the
  DISPATCHER specifically (the umbrella's fixture rule);
- NO edge to a function that merely shares the container's name (the
  Go/Swift negative the umbrella requires — the alias gate abstains);
- a direct-call CONTROL keeps its edge; a local (in-function) container
  works the same as a file-scope one;
- an unknown subscript base abstains — no invented edges.
"""

import json
import os
import sys
import tempfile

# #415: this header previously inserted `tests/` (two ".." from
# tests/parsers/swift) — and tests/parsers/ is a REGULAR package, so with it
# on sys.path every later in-process `parsers.*` import in the same pytest
# batch resolved into the TEST directory (ModuleNotFoundError: No module
# named 'parsers.swift.repository_scanner'). The insert only exists so the
# file runs standalone; it needs the CORE root, three ".." up.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from core.parser_adapter import parse_repository  # noqa: E402


def _cg(files: dict):
    repo = os.path.realpath(tempfile.mkdtemp())
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
    out = tempfile.mkdtemp()
    parse_repository(repo, out, language="swift", processing_level="all",
                     skip_tests=True, name="r")
    with open(os.path.join(out, "call_graph.json")) as fh:
        return json.load(fh)


def _edges(cg, caller_suffix):
    keys = [k for k in cg["call_graph"] if k.endswith(caller_suffix)]
    return [e for k in keys for e in cg["call_graph"][k]]


_FIXTURE = {
    "main.swift":
        "func handlerA() -> Int { return 1 }\n"
        "func handlerB() -> Int { return 2 }\n"
        "func directTarget() -> Int { return 3 }\n"
        "func tbl() -> Int { return 4 }\n"   # SHADOW: shares the container's name
        "\n"
        "let tbl: [() -> Int] = [handlerA, handlerB]\n"     # file scope
        "let map: [String: () -> Int] = [\"a\": handlerB]\n"  # dictionary literal
        "\n"
        "func dispatch(_ i: Int, _ k: String) -> Int {\n"
        "    let local: [() -> Int] = [handlerA]\n"           # function local
        "    directTarget()\n"                               # CONTROL
        "    return tbl[i]() + map[k]!() + local[i]()\n"
        "}\n",
}


def test_array_container_dispatch_edges():
    cg = _cg(_FIXTURE)
    edges = _edges(cg, ":dispatch")
    assert any("handlerA" in e for e in edges), edges
    assert any("handlerB" in e for e in edges), edges


def test_no_edge_to_same_named_function():
    """The umbrella's Go/Swift negative: the function named `tbl` must NOT
    receive an edge from the subscript dispatch."""
    cg = _cg(_FIXTURE)
    edges = _edges(cg, ":dispatch")
    assert not any(e.endswith(":tbl") for e in edges), edges


def test_direct_call_control_passes():
    cg = _cg(_FIXTURE)
    assert any("directTarget" in e for e in _edges(cg, ":dispatch"))


def test_local_and_dictionary_forms():
    """Both the function-local array and the dictionary-literal container
    dispatch through their names (the three forms behave the same)."""
    cg = _cg(_FIXTURE)
    edges = _edges(cg, ":dispatch")
    assert any("handlerA" in e for e in edges), edges  # local[i]()
    assert any("handlerB" in e for e in edges), edges  # map[k]!()


def test_unknown_subscript_abstains():
    cg = _cg({
        "main.swift":
            "func data() -> Int { return 1 }\n"
            "func use(_ i: Int) -> Int {\n"
            "    let data = [1, 2, 3]\n"   # NOT a function container
            "    return data[i]()\n"
            "}\n",
    })
    assert _edges(cg, ":use") == []
