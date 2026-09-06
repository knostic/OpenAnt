"""Class-expression get/set accessors are emitted as units (reachability FN fix).

`_extractClassExpressionMethods` iterated only getMethods(), which excludes get/set
accessors, so an accessor of `const X = class { get payload(){...} }` was never emitted
as a unit -> a sink inside it was invisible. The class-declaration path already includes
getGetAccessors()/getSetAccessors().
"""
import json
import os
import tempfile
from pathlib import Path


from core.parser_adapter import parse_repository


def _functions(files: dict):
    with tempfile.TemporaryDirectory() as _repo, tempfile.TemporaryDirectory() as out:
        repo = os.path.realpath(_repo)
        for rel, content in files.items():
            p = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
        parse_repository(repo, out, language="javascript", processing_level="all",
                         skip_tests=True, name="r")
        return json.loads((Path(out) / "call_graph.json").read_text(encoding="utf-8"))["functions"]


def test_class_expression_getter_emitted_as_unit():
    fns = _functions({
        "expr.js": "const { exec } = require('child_process');\n"
                   "const ExprCmd = class {\n"
                   "  get payload(){ exec(globalThis.cmd); return 1; }\n"
                   "  run(){ return this.payload; }\n"
                   "};\n"
                   "module.exports = ExprCmd;\n",
    })
    assert any(k.endswith(":ExprCmd.payload") for k in fns), (
        f"class-expression getter ExprCmd.payload must be emitted as a unit; funcs={list(fns)}"
    )
    # sanity: the exec sink is inside the emitted accessor's code
    key = next((k for k in fns if k.endswith(":ExprCmd.payload")), None)
    assert key and "exec(" in (fns[key].get("code") or ""), (
        f"accessor unit present but its exec sink is missing from its code"
    )
