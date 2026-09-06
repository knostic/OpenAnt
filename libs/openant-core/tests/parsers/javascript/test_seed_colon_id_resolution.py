"""A caller whose id contains colons resolves its calls (reachability FN fix).

_buildResolvedGraphs derived a caller's file via lastIndexOf(':'), but a route-handler
seed id like `app.js:express(GET:/run:4:0)` contains colons in its NAME part, so the
computed file was mangled, same-file resolution missed, and the seed resolved nothing --
dropping the whole reachable subtree behind the route. The file is the part before the
FIRST colon (relative paths contain no colon).
"""
import json
import os
import tempfile
from pathlib import Path

from core.parser_adapter import parse_repository


def _call_graph(files: dict):
    with tempfile.TemporaryDirectory() as _repo, tempfile.TemporaryDirectory() as out:
        repo = os.path.realpath(_repo)
        for rel, content in files.items():
            p = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(content)
        parse_repository(repo, out, language="javascript", processing_level="all",
                         skip_tests=True, name="r")
        return json.loads((Path(out) / "call_graph.json").read_text(encoding="utf-8"))


def test_route_seed_with_colon_id_resolves_callee():
    # Two conditional `handle` defs make the name ambiguous, so the unique-name
    # fallback cannot resolve it -- only same-file resolution (which needs the
    # correctly-computed caller file) can. This is what the colon-mangle breaks.
    cg = _call_graph({
        "app.js": "const express = require('express');\n"
                  "const app = express();\n"
                  "app.get('/run', (req, res) => { handle(req.query.v); res.send('ok'); });\n"
                  "if (process.env.MODE === 'a') { function handle(v){ leak(v); } }\n"
                  "else { function handle(v){ danger(v); } }\n"
                  "function leak(v){ console.log(process.env.SECRET + v); }\n"
                  "function danger(v){ eval(v); }\n"
                  "app.listen(3000);\n",
    })
    graph = cg["call_graph"]
    seeds = [k for k in graph if "express" in k or "/run" in k]
    assert seeds, f"no route-handler seed found; keys={list(graph)}"
    assert any(any("handle" in t for t in graph.get(s, [])) for s in seeds), (
        f"route seed (a colon-containing id) must resolve its handle() call; "
        f"seeds={seeds}, edges={{s: graph.get(s) for s in seeds}}"
    )
