"""Tests for Express anonymous route handler extraction in the JS parser.

These exercise the typescript_analyzer.js + unit_generator.js pipeline by
running the Node.js scripts as subprocesses (mirroring tests/test_js_parser.py).

Skips when Node.js or the parser's npm dependencies aren't installed.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest


PARSERS_JS_DIR = Path(__file__).parent.parent.parent.parent / "parsers" / "javascript"
NODE_MODULES = PARSERS_JS_DIR / "node_modules"

pytestmark = pytest.mark.skipif(
    not shutil.which("node") or not NODE_MODULES.exists(),
    reason="Node.js or JS parser npm dependencies not available",
)


def _run_node(script_name, *args):
    cmd = ["node", str(PARSERS_JS_DIR / script_name)] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def _analyze(repo_path, file_path):
    """Run the analyzer on a single file and return parsed output."""
    result = _run_node("typescript_analyzer.js", str(repo_path), str(file_path))
    assert result.returncode == 0, (
        f"analyzer failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return json.loads(result.stdout)


def _generate_units(analyzer_output_path, dataset_output_path):
    result = _run_node(
        "unit_generator.js",
        str(analyzer_output_path),
        "--output", str(dataset_output_path),
    )
    assert result.returncode == 0, (
        f"unit_generator failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return json.loads(Path(dataset_output_path).read_text())


def _write_fixture(tmp_path: Path, name: str, content: str) -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    file_path = repo / "server.js"
    file_path.write_text(content)
    return file_path


def _express_units(dataset):
    return [u for u in dataset["units"] if "express(" in u["id"]]


def test_anonymous_handler_with_named_middleware(tmp_path):
    """router.post(path, namedMiddleware, async (req, res) => {...})."""
    file_path = _write_fixture(
        tmp_path,
        "anon_with_mw",
        """
const express = require('express');
const router = express.Router();

function authenticateToken(req, res, next) { next(); }

router.post('/orders', authenticateToken, async (req, res) => {
  const { productId, quantity } = req.body;
  res.json({ productId, quantity });
});

module.exports = router;
""",
    )
    repo = file_path.parent
    out = _analyze(repo, file_path)

    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert len(express_funcs) == 1, f"expected 1 anon handler, got {express_funcs}"

    fid, fdata = next(iter(express_funcs.items()))
    assert fdata["unitType"] == "route_handler"
    assert fdata["isEntryPoint"] is True
    meta = fdata["routeMetadata"]
    assert meta["http_method"] == "POST"
    assert meta["http_path"] == "/orders"
    assert meta["named_middleware"] == ["authenticateToken"]

    # Run unit_generator and verify the call-graph edge to authenticateToken.
    analyzer_path = tmp_path / "analyzer.json"
    analyzer_path.write_text(json.dumps(out))
    dataset_path = tmp_path / "dataset.json"
    dataset = _generate_units(analyzer_path, dataset_path)

    handler_unit = next(u for u in dataset["units"] if u["id"] == fid)
    assert handler_unit["unit_type"] == "route_handler"
    assert handler_unit["is_entry_point"] is True
    assert handler_unit["http_method"] == "POST"
    assert handler_unit["http_path"] == "/orders"
    assert handler_unit["route"]["method"] == "POST"
    assert handler_unit["route"]["path"] == "/orders"
    assert handler_unit["route"]["middleware"] == ["authenticateToken"]

    # Call-graph edge: handler -> authenticateToken
    upstream_ids = handler_unit["metadata"]["direct_calls"]
    auth_id = "server.js:authenticateToken"
    assert auth_id in upstream_ids, (
        f"expected handler to call authenticateToken; direct_calls={upstream_ids}"
    )


def test_handler_no_middleware(tmp_path):
    """app.get(path, (req, res) => res.json([])) — no extra edges."""
    file_path = _write_fixture(
        tmp_path,
        "no_mw",
        """
const express = require('express');
const app = express();
app.get('/users', (req, res) => res.json([]));
module.exports = app;
""",
    )
    repo = file_path.parent
    out = _analyze(repo, file_path)
    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert len(express_funcs) == 1
    fid, fdata = next(iter(express_funcs.items()))
    meta = fdata["routeMetadata"]
    assert meta["http_method"] == "GET"
    assert meta["http_path"] == "/users"
    assert meta["named_middleware"] == []
    assert fdata["isEntryPoint"] is True


def test_use_with_multiple_anonymous_callbacks(tmp_path):
    """router.use(path, anonMw1, anonMw2, anonHandler) —
    one route_handler + two route_middleware units."""
    file_path = _write_fixture(
        tmp_path,
        "use_multi",
        """
const express = require('express');
const router = express.Router();

router.use('/api',
  (req, res, next) => { req.start = Date.now(); next(); },
  (req, res, next) => { console.log(req.path); next(); },
  async (req, res, next) => {
    if (!req.headers.authorization) return res.status(401).end();
    next();
  }
);

module.exports = router;
""",
    )
    repo = file_path.parent
    out = _analyze(repo, file_path)
    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert len(express_funcs) == 3, f"expected 3 callbacks, got {list(express_funcs)}"

    by_type = {}
    for fdata in express_funcs.values():
        by_type.setdefault(fdata["unitType"], []).append(fdata)

    assert len(by_type.get("route_handler", [])) == 1
    assert len(by_type.get("route_middleware", [])) == 2

    handler = by_type["route_handler"][0]
    assert handler["isEntryPoint"] is True
    assert handler["routeMetadata"]["http_method"] == "USE"
    assert handler["routeMetadata"]["http_path"] == "/api"

    for mw in by_type["route_middleware"]:
        assert mw["isEntryPoint"] is False or mw.get("isEntryPoint") is None
        assert mw["routeMetadata"]["http_method"] == "USE"
        assert mw["routeMetadata"]["http_path"] == "/api"
        assert mw["routeMetadata"]["callback_index"] < 2


def test_non_express_call_is_skipped(tmp_path):
    """myCache.get('foo', () => {}) must not be claimed as a route."""
    file_path = _write_fixture(
        tmp_path,
        "non_express",
        """
const myCache = makeCache();
myCache.get('foo', () => { return 1; });
const queryBuilder = makeBuilder();
queryBuilder.post('users', () => {});
""",
    )
    repo = file_path.parent
    out = _analyze(repo, file_path)
    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert express_funcs == {}, (
        f"non-Express receivers must not be extracted; got {list(express_funcs)}"
    )


def test_synthetic_handlers_have_call_graph_entries(tmp_path):
    """Synthetic Express handlers must also appear as callGraph keys.

    Regression for the invariant `len(callGraph) == len(functions)` that
    other tests (e.g. test_js_parser.test_builds_call_graph) rely on.
    """
    file_path = _write_fixture(
        tmp_path,
        "callgraph_invariant",
        """
const express = require('express');
const router = express.Router();

function authenticateToken(req, res, next) { next(); }

router.post('/orders', authenticateToken, async (req, res) => {
  const { productId, quantity } = req.body;
  res.json({ productId, quantity });
});

module.exports = router;
""",
    )
    repo = file_path.parent
    out = _analyze(repo, file_path)

    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert len(express_funcs) == 1

    # Every synthetic Express function must have a callGraph entry.
    for fid in express_funcs:
        assert fid in out["callGraph"], (
            f"synthetic function {fid} missing from callGraph; "
            f"callGraph keys={list(out['callGraph'])}"
        )

    # Global invariant: callGraph keys ≡ functions keys.
    assert len(out["callGraph"]) == len(out["functions"]), (
        f"callGraph/functions size mismatch: "
        f"{len(out['callGraph'])} vs {len(out['functions'])}"
    )


def test_typescript_typed_callback(tmp_path):
    """TS callback with type annotations:
    `(req: Request, res: Response, next: NextFunction) => {...}`.

    Type annotations on the parameters and return type must not prevent
    the AST walk from recognising the callback as an ArrowFunction.
    """
    repo = tmp_path / "ts_typed"
    repo.mkdir(parents=True, exist_ok=True)
    file_path = repo / "server.ts"
    file_path.write_text(
        """
import express, { Request, Response, NextFunction } from 'express';
const app = express();

function authenticateToken(req: Request, res: Response, next: NextFunction): void { next(); }

app.post('/orders', authenticateToken, async (req: Request, res: Response): Promise<void> => {
  const { productId, quantity } = req.body;
  res.json({ productId, quantity });
});

export default app;
"""
    )
    out = _analyze(repo, file_path)
    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert len(express_funcs) == 1, (
        f"expected 1 anon TS handler, got {express_funcs}"
    )
    fid, fdata = next(iter(express_funcs.items()))
    assert fdata["unitType"] == "route_handler"
    assert fdata["isEntryPoint"] is True
    meta = fdata["routeMetadata"]
    assert meta["http_method"] == "POST"
    assert meta["http_path"] == "/orders"
    assert meta["named_middleware"] == ["authenticateToken"]


def test_dynamic_path_does_not_crash(tmp_path):
    """`app.get('/' + prefix, handler)` — first arg isn't a string literal.

    The extractor should skip such calls without throwing. We can't
    reliably extract a path from a runtime-built expression.
    """
    file_path = _write_fixture(
        tmp_path,
        "dynamic_path",
        """
const express = require('express');
const app = express();
const prefix = 'foo';
app.get('/' + prefix, (req, res) => res.send('ok'));
module.exports = app;
""",
    )
    repo = file_path.parent
    out = _analyze(repo, file_path)
    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert express_funcs == {}, (
        f"dynamic path should be skipped, got {list(express_funcs)}"
    )


def test_use_no_path_anonymous_middleware(tmp_path):
    """`app.use((req, res, next) => {...})` — middleware with no path.

    The synthetic unit should be emitted with http_path=null and
    http_method='USE'.
    """
    file_path = _write_fixture(
        tmp_path,
        "use_no_path",
        """
const express = require('express');
const app = express();
app.use((req, res, next) => { req.start = Date.now(); next(); });
module.exports = app;
""",
    )
    repo = file_path.parent
    out = _analyze(repo, file_path)
    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert len(express_funcs) == 1, (
        f"expected 1 anon middleware unit, got {list(express_funcs)}"
    )
    fid, fdata = next(iter(express_funcs.items()))
    meta = fdata["routeMetadata"]
    assert meta["http_method"] == "USE"
    assert meta["http_path"] is None


def test_anon_middleware_named_handler_mixed(tmp_path):
    """`app.get(path, anonMw, namedHandler)` — anon middleware before
    named handler. Anon gets a route_middleware unit; the named handler
    is left to the regular extractor (no synthetic unit for it)."""
    file_path = _write_fixture(
        tmp_path,
        "mixed",
        """
const express = require('express');
const app = express();
function namedHandler(req, res) { res.send('ok'); }
app.get('/x', (req, res, next) => { console.log('mw'); next(); }, namedHandler);
module.exports = app;
""",
    )
    repo = file_path.parent
    out = _analyze(repo, file_path)
    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert len(express_funcs) == 1, (
        f"expected 1 anon middleware unit, got {list(express_funcs)}"
    )
    fid, fdata = next(iter(express_funcs.items()))
    assert fdata["unitType"] == "route_middleware"
    # named_middleware should include the namedHandler sibling
    assert fdata["routeMetadata"]["named_middleware"] == ["namedHandler"]
    # namedHandler must still be extracted normally
    assert any(
        f.get("name") == "namedHandler" for f in out["functions"].values()
    )


def test_named_handler_no_anonymous_unit(tmp_path):
    """router.get('/x', namedHandler) — no anon unit synthesised."""
    file_path = _write_fixture(
        tmp_path,
        "named",
        """
const express = require('express');
const router = express.Router();

function namedHandler(req, res) { res.send('ok'); }

router.get('/x', namedHandler);

module.exports = router;
""",
    )
    repo = file_path.parent
    out = _analyze(repo, file_path)
    express_funcs = {k: v for k, v in out["functions"].items() if "express(" in k}
    assert express_funcs == {}, (
        f"named-only callbacks must not synthesise anon units; got {list(express_funcs)}"
    )
    # namedHandler should still be picked up by the regular extractor.
    assert any(
        f.get("name") == "namedHandler" for f in out["functions"].values()
    )
