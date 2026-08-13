"""Recall extensions to the custom-router classifier (re-exam 2026-08-14).

Two zero-FP-risk recall gains found by adversarial re-examination (engineer +
Fable + Sol, each re-derived first-hand):
  * B8  — `@<router>.websocket_route(...)` on a custom-named router was missed
          (the verb alternation had `websocket` and `route` but not the
          `websocket_route` method) → a silent reachability FN for WS routes.
  * B-FN-02 — a simple alias `r = <router>` was not propagated, so `@r.get(...)`
          was missed.
Both only ADD `route_handler` for genuine routers (pure recall; the negative
controls below pin that a non-router alias / receiver is NOT promoted). The
flow/scope over-seed FPs (B2/B11) are deliberately NOT "fixed": tightening them
regresses function-scoped custom routers to FN, which is net-harmful for a SAST
reachability tool (missed route >> over-analyzed non-route).
"""
import sys
import tempfile
from pathlib import Path

import pytest

CORE = str(Path(__file__).resolve().parents[3])
if CORE not in sys.path:
    sys.path.insert(0, CORE)
sys.path.insert(0, str(Path(CORE) / "parsers" / "python"))
from parsers.python.function_extractor import FunctionExtractor  # noqa: E402


def _unit_type(src: str, func_name: str) -> str:
    repo = Path(tempfile.mkdtemp()).resolve()
    (repo / "m.py").write_text(src)
    ex = FunctionExtractor(str(repo))
    ex.process_file(repo / "m.py")
    return ex.functions[f"m.py:{func_name}"]["unit_type"]


# ---- B8: websocket_route on a custom-named router --------------------------
@pytest.mark.parametrize("src", [
    "from fastapi import FastAPI\nchat = FastAPI()\n"
    "@chat.websocket_route('/ws')\nasync def handler(websocket): pass\n",
    "from starlette.applications import Starlette\napp2 = Starlette()\n"
    "@app2.websocket_route('/ws')\nasync def handler(websocket): pass\n",
])
def test_custom_router_websocket_route_is_route_handler(src):
    assert _unit_type(src, "handler") == "route_handler"


# ---- B-FN-02: alias of a router variable -----------------------------------
@pytest.mark.parametrize("src", [
    "from fastapi import APIRouter\nbase = APIRouter()\nr = base\n"
    "@r.get('/x')\ndef handler(): pass\n",
    # two-hop alias chain
    "from fastapi import APIRouter\nbase = APIRouter()\nr = base\nq = r\n"
    "@q.post('/x')\ndef handler(): pass\n",
])
def test_router_alias_is_route_handler(src):
    assert _unit_type(src, "handler") == "route_handler"


# ---- negative controls: aliasing must NOT promote a non-router -------------
@pytest.mark.parametrize("src", [
    # alias of a non-router object stays a non-route
    "cache = TTLCache(100)\nc = cache\n@c.get('/k')\ndef helper(): pass\n",
    # websocket_route on a NON-router receiver is not a route
    "cache = TTLCache(100)\n@cache.websocket_route('/k')\ndef helper(): pass\n",
])
def test_alias_and_wsroute_do_not_overmatch_nonrouter(src):
    assert _unit_type(src, "helper") != "route_handler"


# ---- F2 (re-exam round 1): annotated alias must propagate (was FN) ----------
def test_annotated_alias_is_route_handler():
    src = ("from fastapi import APIRouter\nadmin = APIRouter()\n"
           "ws: APIRouter = admin\n@ws.websocket_route('/ws')\nasync def handler(websocket): pass\n")
    assert _unit_type(src, "handler") == "route_handler"


# ---- F3 (re-exam round 1): deep alias chain resolves (edge-map correctness) --
def test_deep_alias_chain_resolves():
    n = 200
    src = ("from fastapi import APIRouter\nadmin = APIRouter()\n"
           + "".join(f"x{i} = x{i-1}\n" for i in range(2, n + 1)).replace("x1", "admin", 1)
           + f"x1 = admin\n@x{n}.get('/deep')\ndef handler(): pass\n")
    assert _unit_type(src, "handler") == "route_handler"


# ---- coverage gaps (test-quality finder): declared ctors + verbs + targets ---
@pytest.mark.parametrize("src", [
    # Flask ctor under a CUSTOM name (only Blueprint/app were exercised before)
    "from flask import Flask\nsrv = Flask(__name__)\n@srv.route('/x')\ndef handler(): pass\n",
    # multi-target assignment a = b = APIRouter()
    "from fastapi import APIRouter\na = b = APIRouter()\n@b.get('/x')\ndef handler(): pass\n",
    # under-sampled verb: delete
    "from fastapi import APIRouter\nadmin = APIRouter()\n@admin.delete('/x')\ndef handler(): pass\n",
    # Starlette custom name, HTTP verb (not just websocket_route)
    "from starlette.applications import Starlette\nsvc = Starlette()\n@svc.get('/x')\ndef handler(): pass\n",
])
def test_declared_ctor_and_verb_coverage(src):
    assert _unit_type(src, "handler") == "route_handler"


# ---- F-R2-1 (re-exam round 2): walrus (NamedExpr) binding forms --------------
@pytest.mark.parametrize("src", [
    # router constructed by a walrus
    "from fastapi import APIRouter\nif (r := APIRouter()):\n    pass\n@r.get('/x')\ndef handler(): pass\n",
    # alias THROUGH a walrus: x = (y := admin) -> both x and y alias admin
    "from fastapi import APIRouter\nadmin = APIRouter()\nx = (y := admin)\n@y.get('/x')\ndef handler(): pass\n",
])
def test_walrus_bound_router_is_route_handler(src):
    assert _unit_type(src, "handler") == "route_handler"


def test_walrus_bound_nonrouter_is_not_route_handler():
    # walrus binding a NON-router must NOT be promoted
    src = "d = (r := dict())\n@r.get('/x')\ndef helper(): pass\n"
    assert _unit_type(src, "helper") != "route_handler"
