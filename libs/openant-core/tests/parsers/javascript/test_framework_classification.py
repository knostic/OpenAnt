"""Tests for framework route-handler classification.

Fastify `(request, reply)` handlers must classify as route_handlers, and React
components that happen to take `(request, response)` must NOT be misclassified as
routes.

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


def _analyze(repo_path, file_path):
    cmd = ["node", str(PARSERS_JS_DIR / "typescript_analyzer.js"), str(repo_path), str(file_path)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, (
        f"analyzer failed:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    return json.loads(result.stdout)


def _write(tmp_path, name, content, filename="file.js"):
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    fp = repo / filename
    fp.write_text(content)
    return repo, fp


def test_fastify_request_reply_is_route_handler(tmp_path):
    repo, fp = _write(
        tmp_path,
        "sb6_fastify",
        "function fastifyRoute(request, reply) { reply.send({ ok: true }); }\n",
    )
    out = _analyze(repo, fp)
    fn = out["functions"]["file.js:fastifyRoute"]
    assert fn["unitType"] == "route_handler", (
        f"Fastify (request, reply) handler must classify as route_handler; got {fn['unitType']}"
    )


def test_koa_ctx_is_route_handler(tmp_path):
    repo, fp = _write(
        tmp_path,
        "sb6_koa",
        "function koaRoute(ctx) { ctx.body = 'ok'; }\n",
    )
    out = _analyze(repo, fp)
    fn = out["functions"]["file.js:koaRoute"]
    assert fn["unitType"] == "route_handler", (
        f"Koa (ctx) handler must classify as route_handler; got {fn['unitType']}"
    )


def test_react_component_not_misclassified(tmp_path):
    """A function named like a component taking (request, response) must not be
    treated as an Express route just because of the parameter names."""
    repo, fp = _write(
        tmp_path,
        "sb6_react",
        "function MyComponent(request, response) { return null; }\n",
        filename="file.jsx",
    )
    out = _analyze(repo, fp)
    fn = out["functions"]["file.jsx:MyComponent"]
    assert fn["unitType"] != "route_handler", (
        f"React component taking (request, response) must NOT be a route_handler; got {fn['unitType']}"
    )
