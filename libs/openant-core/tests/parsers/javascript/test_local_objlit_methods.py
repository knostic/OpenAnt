"""Methods of a var-declared object literal are units (reachability FN fix).

Object-literal methods were mined only via export default / module.exports; a
`const ctrl = { handler(){ sink } }` was never emitted, so a sink inside it was
unreachable. Precision (strengthened guard): an object-literal method is only ever
called through a receiver (`ctrl.handler()`), so a bare same-name call in ANOTHER
file must never resolve to it -- no phantom, whether the object is exported or not.
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


def test_local_objlit_method_emitted_and_body_scanned():
    # Use a user-function sink so the edge appears in the RESOLVED call graph
    # (external/require'd calls do not resolve to a unit).
    cg = _cg({
        "app.js": "const ctrl = { handler(x){ danger(x); } };\n"
                  "function danger(y){ eval(y); }\n"
                  "function boot(){ ctrl.handler(globalThis.x); }\n",
    })
    assert any(k.endswith(":ctrl.handler") for k in cg["functions"]), (
        f"local object-literal method ctrl.handler must be a unit; funcs={list(cg['functions'])}"
    )
    assert any("danger" in e for e in _edges(cg, ":ctrl.handler")), (
        f"ctrl.handler body call danger() must be an edge; got {_edges(cg, ':ctrl.handler')}"
    )
    assert any("ctrl.handler" in e for e in _edges(cg, ":boot")), (
        f"same-file boot()->ctrl.handler() member call must resolve; got {_edges(cg, ':boot')}"
    )


def test_bare_cross_file_call_no_phantom_nonexported():
    cg = _cg({
        "a.js": "const ctrl = { doThing(x){ globalThis.sink(x); } };\n",
        "b.js": "function useIt(){ doThing(); }\n",
    })
    assert not any("ctrl.doThing" in e for e in _edges(cg, "b.js:useIt")), (
        f"bare cross-file doThing() must not resolve to ctrl.doThing; got {_edges(cg, 'b.js:useIt')}"
    )


def test_bare_cross_file_call_no_phantom_EXPORTED():
    # The strengthened guard: even an EXPORTED object literal must not absorb a bare
    # cross-file same-name call (the `&& !isExported` weak guard ships this phantom).
    cg = _cg({
        "api.js": "export const svc = { run(){ return 1; } };\n",
        "consumer.js": "function useIt(){ run(); }\n",
    })
    assert not any("svc.run" in e for e in _edges(cg, "consumer.js:useIt")), (
        f"bare cross-file run() must not resolve to exported svc.run; got {_edges(cg, 'consumer.js:useIt')}"
    )
