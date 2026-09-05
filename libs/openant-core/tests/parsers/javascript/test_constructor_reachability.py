"""Class constructors are units + `new X()` edges reach the constructor body (FN fix).

The constructor was excluded from method enumeration (both the inventory and the
call-graph builder) and `new X()` (a NewExpression) was never captured, so a sink
inside a constructor body was unreachable. Precision: `new X()` resolves to X's
constructor only within the same file; a cross-file `new X()`, `new Map()`, and a
`foo.constructor()` member call all stay indirect (no phantom edge).
"""
import json
import os
import tempfile
from pathlib import Path

from core.parser_adapter import parse_repository


def _cg(files: dict):
    repo = os.path.realpath(tempfile.mkdtemp())
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
    out = tempfile.mkdtemp()
    parse_repository(repo, out, language="javascript", processing_level="all",
                     skip_tests=True, name="r")
    return json.loads((Path(out) / "call_graph.json").read_text(encoding="utf-8"))


def _edges(cg, caller_suffix):
    keys = [k for k in cg["call_graph"] if k.endswith(caller_suffix)]
    return [e for k in keys for e in cg["call_graph"][k]]


def test_constructor_unit_and_body_reachable_via_new():
    cg = _cg({
        "app.js": "class Svc {\n"
                  "  constructor(){ this.danger(); }\n"
                  "  danger(){ return eval(globalThis.x); }\n"
                  "}\n"
                  "function boot(){ new Svc(); }\n",
    })
    assert any(k.endswith(":Svc.constructor") for k in cg["functions"]), (
        f"constructor must be emitted as a unit; funcs={list(cg['functions'])}"
    )
    assert any("Svc.constructor" in e for e in _edges(cg, ":boot")), (
        f"new Svc() must edge to Svc.constructor; boot edges={_edges(cg, ':boot')}"
    )
    assert any("Svc.danger" in e for e in _edges(cg, ":Svc.constructor")), (
        f"constructor body call this.danger() must be an edge; "
        f"ctor edges={_edges(cg, ':Svc.constructor')}"
    )


def test_cross_file_new_stays_indirect():
    # Precision: the qualified `X.constructor` edge name resolves only same-file, so a
    # cross-file new Svc() does NOT connect (no phantom).
    cg = _cg({
        "a.js": "function boot(){ new Svc(); }\n",
        "b.js": "class Svc { constructor(){ this.danger(); } danger(){ return 1; } }\n",
    })
    assert not any("Svc.constructor" in e for e in _edges(cg, "a.js:boot")), (
        f"cross-file new Svc() must stay indirect; got {_edges(cg, 'a.js:boot')}"
    )


def test_new_builtin_and_dot_constructor_no_phantom():
    cg = _cg({
        "app.js": "function boot(){ new Map(); }\n"
                  "function meta(o){ return o.constructor(); }\n",
    })
    assert not any("constructor" in e.lower() for e in _edges(cg, ":boot")), (
        f"new Map() must not create a phantom constructor edge; got {_edges(cg, ':boot')}"
    )
    assert not any("constructor" in e.lower() for e in _edges(cg, ":meta")), (
        f"o.constructor() member call must stay indirect; got {_edges(cg, ':meta')}"
    )
