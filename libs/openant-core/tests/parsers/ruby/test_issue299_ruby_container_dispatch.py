"""Regression tests for issue #299 (Ruby member — 5 of 7): container-literal
dispatch loses call edges.

Ruby's dispatch-table idiom: a CONSTANT assigned a hash/array of
`method(:sym)` objects or symbols — `HANDLERS = { 'a' => method(:handlerA) }`
then `HANDLERS[k].call`, or `SYMS = [:handlerA, :handlerB]` then
`send(SYMS[k])`. The builder resolved `.call` only via LOCAL method-object
bindings (`m = method(:helper)`), so a subscript receiver over a container
resolved nothing and the dispatcher's targets were orphaned.

Contract locked here:
- both container forms dispatch: `HANDLERS[k].call` (method-object values)
  and `send(SYMS[k])` (symbol elements) record edges to every referenced
  function — the caller set contains the DISPATCHER specifically;
- a direct-call CONTROL keeps its edge;
- a local container (lowercase var, assigned in the function) works the
  same as a CONSTANT;
- an unknown subscript base abstains — no invented edges.
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from core.parser_adapter import parse_repository  # noqa: E402


def _cg(files: dict):
    repo = os.path.realpath(tempfile.mkdtemp())
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
    out = tempfile.mkdtemp()
    parse_repository(repo, out, language="ruby", processing_level="all",
                     skip_tests=True, name="r")
    return json.load(open(os.path.join(out, "call_graph.json")))


def _edges(cg, caller_suffix):
    keys = [k for k in cg["call_graph"] if k.endswith(caller_suffix)]
    return [e for k in keys for e in cg["call_graph"][k]]


_FIXTURE = {
    "main.rb":
        "def handlerA; 1; end\n"
        "def handlerB; 2; end\n"
        "def directTarget; 3; end\n"
        "\n"
        "HANDLERS = { 'a' => method(:handlerA), 'b' => method(:handlerB) }\n"
        "SYMS = [:handlerA, :handlerB]\n"
        "\n"
        "def dispatch(k)\n"
        "  directTarget\n"
        "  HANDLERS[k].call\n"
        "  send(SYMS[k])\n"
        "  0\n"
        "end\n",
}


def test_method_object_container_dispatch():
    cg = _cg(_FIXTURE)
    edges = _edges(cg, ":dispatch")
    assert any("handlerA" in e for e in edges), edges
    assert any("handlerB" in e for e in edges), edges


def test_symbol_container_send_dispatch():
    """send(SYMS[k]) through a symbol-element container."""
    cg = _cg({
        "main.rb":
            "def h1; 1; end\n"
            "def h2; 2; end\n"
            "SYMS = [:h1, :h2]\n"
            "def dispatch(k)\n"
            "  send(SYMS[k])\n"
            "  0\n"
            "end\n",
    })
    edges = _edges(cg, ":dispatch")
    assert any("h1" in e for e in edges), edges
    assert any("h2" in e for e in edges), edges


def test_direct_call_control_passes():
    cg = _cg(_FIXTURE)
    assert any("directTarget" in e for e in _edges(cg, ":dispatch"))


def test_local_container_dispatch():
    cg = _cg({
        "main.rb":
            "def h1; 1; end\n"
            "def dispatch(k)\n"
            "  t = { 'x' => method(:h1) }\n"
            "  t[k].call\n"
            "  0\n"
            "end\n",
    })
    assert any("h1" in e for e in _edges(cg, ":dispatch"))


def test_unknown_subscript_abstains():
    cg = _cg({
        "main.rb":
            "def data; 1; end\n"
            "def use(k)\n"
            "  data = [1, 2, 3]\n"
            "  data[k]\n"
            "  0\n"
        "end\n",
    })
    assert _edges(cg, ":use") == []
