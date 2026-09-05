"""Arrow/fn-expr const does not overwrite a colliding block function (reachability FN fix).

The arrow/function-expression const emit path wrote this.functions[path:name]
unconditionally (no collision guard), so a module-level `const foo = () => ...`
overwrote (last-wins) a block-scoped `function foo(){...}` sharing the id, dropping
that function and its calls. Other emit paths use a first-wins skip guard.
"""
import json
import os
import tempfile
from pathlib import Path

from core.parser_adapter import parse_repository


def _functions(files: dict):
    repo = os.path.realpath(tempfile.mkdtemp())
    for rel, content in files.items():
        p = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
    out = tempfile.mkdtemp()
    parse_repository(repo, out, language="javascript", processing_level="all",
                     skip_tests=True, name="r")
    return json.loads((Path(out) / "call_graph.json").read_text(encoding="utf-8"))["functions"]


def test_arrow_const_does_not_drop_block_function_sink():
    fns = _functions({
        "app.js": "const express = require('express');\n"
                  "const cp = require('child_process');\n"
                  "const app = express();\n"
                  "const foo = () => 42;\n"
                  "{\n"
                  "  function foo(){ cp.exec(globalThis.cmd); }\n"
                  "  app.post('/run', (req, res) => { foo(); res.end(); });\n"
                  "}\n"
                  "module.exports = app;\n",
    })
    assert any("cp.exec" in (v.get("code") or "") for v in fns.values()), (
        "the block-scoped function foo carrying the cp.exec sink was overwritten by "
        f"the module-level arrow const foo (last-wins); funcs={list(fns)}"
    )
