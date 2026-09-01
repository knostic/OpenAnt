"""Regression tests for issue #299 (PHP member — 4 of 7): container-literal
dispatch loses call edges.

PHP's dispatch-table idiom holds function NAMES AS STRINGS —
``$handlers = ['a' => 'handlerA', 'b' => 'handlerB']; $handlers[$k]();`` —
and `_resolve_function_call` had no subscript case: the callee is a
`subscript_expression`, so nothing resolved and the dispatcher's targets
were orphaned (pruned with their dispatcher kept — #295's shape). The
in-repo template is `_resolve_variable_function` (a single string-literal
binding `$f = 'helper'; $f()` already resolves): the container is the
array form of that binding.

Contract locked here:
- an array literal of function-name strings plus a subscript call records
  edges to every referenced function — the caller set contains the
  DISPATCHER specifically (the umbrella's fixture rule);
- a direct-call CONTROL keeps its edge;
- a function-local container works the same as a file-scope one (with the
  common `global` import shape);
- an unknown subscript base abstains — no invented edges (the data-array
  negative).
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
    repo = os.path.realpath(tempfile.mkdtemp())
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
    out = tempfile.mkdtemp()
    parse_repository(repo, out, language="php", processing_level="all",
                     skip_tests=True, name="r")
    with open(os.path.join(out, "call_graph.json")) as fh:
        return json.load(fh)


def _edges(cg, caller_suffix):
    keys = [k for k in cg["call_graph"] if k.endswith(caller_suffix)]
    return [e for k in keys for e in cg["call_graph"][k]]


_FIXTURE = {
    "main.php":
        "<?php\n"
        "function handlerA() { return 1; }\n"
        "function handlerB() { return 2; }\n"
        "function directTarget() { return 3; }\n"
        # file-scope container (the common placement)
        "$handlers = ['a' => 'handlerA', 'b' => 'handlerB'];\n"
        "function dispatch($k) {\n"
        "    global $handlers;\n"
        "    directTarget();\n"          # CONTROL
        "    $handlers[$k]();\n"
        "    return 0;\n"
        "}\n",
}


def test_file_scope_container_dispatch_edges():
    cg = _cg(_FIXTURE)
    edges = _edges(cg, ":dispatch")
    assert any("handlerA" in e for e in edges), edges
    assert any("handlerB" in e for e in edges), edges


def test_direct_call_control_passes():
    cg = _cg(_FIXTURE)
    assert any("directTarget" in e for e in _edges(cg, ":dispatch"))


def test_local_container_dispatch():
    """A container built INSIDE the function (no `global` needed): same
    dispatch through the local name."""
    cg = _cg({
        "main.php":
            "<?php\n"
            "function h1() { return 1; }\n"
            "function h2() { return 2; }\n"
            "function dispatch($k) {\n"
            "    $t = ['x' => 'h1', 'y' => 'h2'];\n"
            "    $t[$k]();\n"
            "    return 0;\n"
            "}\n",
    })
    edges = _edges(cg, ":dispatch")
    assert any("h1" in e for e in edges), edges
    assert any("h2" in e for e in edges), edges


def test_list_form_container():
    """The list form (bare string elements, no =>) behaves the same."""
    cg = _cg({
        "main.php":
            "<?php\n"
            "function h1() { return 1; }\n"
            "function dispatch($i) {\n"
            "    $t = ['h1'];\n"
            "    $t[$i]();\n"
            "    return 0;\n"
            "}\n",
    })
    assert any("h1" in e for e in _edges(cg, ":dispatch"))


def test_unknown_subscript_abstains():
    """A subscript over a container with no known-function strings records
    nothing — no invented edges."""
    cg = _cg({
        "main.php":
            "<?php\n"
            "function data() { return 1; }\n"
            "function use_($i) {\n"
            "    $data = ['x', 'y'];\n"
            "    $data[$i]();\n"
            "    return 0;\n"
            "}\n",
    })
    assert _edges(cg, ":use_") == []


def test_dict_key_never_fabricates_edge():
    """Regression (panel finding): the KEY of `'k' => 'fn'` is a label, not a
    callee — a key colliding with a real function must not fabricate an edge."""
    files = {
        "handlers.php": """<?php
function init() { return 1; }
function handlerA() { return 2; }
$TBL = ['init' => 'handlerA'];
function dispatch($mode) { global $TBL; $TBL[$mode](); }
""",
    }
    cg = _cg(files)
    dispatch_edges = _edges(cg, ":dispatch")
    assert any("handlerA" in e for e in dispatch_edges), "value dispatch still works"
    assert not any("init" in e for e in dispatch_edges), "the KEY 'init' must NOT fabricate an edge to function init()"
