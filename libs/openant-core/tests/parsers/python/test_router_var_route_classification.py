"""Custom-named router variables classify as route_handler (FN fix) while
non-router receivers with HTTP-verb-shaped decorators do NOT (over-match guard).

Proposed location: tests/parsers/python/test_router_var_route_classification.py
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

CORE = str(Path(__file__).resolve().parents[3])   # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)
sys.path.insert(0, str(Path(CORE) / "parsers" / "python"))

# OPENANT_FE_MODULE lets the harness point at an alternate copy of the module
# (used only to demonstrate red on the pre-fix broad regex). In-repo the test
# simply imports the real module.
_FE = os.environ.get("OPENANT_FE_MODULE")
if _FE:
    import importlib.util
    spec = importlib.util.spec_from_file_location("fe_under_test", _FE)
    fe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fe)
    FunctionExtractor = fe.FunctionExtractor
else:
    from parsers.python.function_extractor import FunctionExtractor


def _unit_type(src: str, func_name: str) -> str:
    repo = Path(tempfile.mkdtemp()).resolve()
    (repo / "m.py").write_text(src)
    ex = FunctionExtractor(str(repo))
    ex.process_file(repo / "m.py")
    return ex.functions[f"m.py:{func_name}"]["unit_type"]


# ---- FN fix: custom-named router instances ARE routes -----------------------

@pytest.mark.parametrize("src", [
    # the original silent-FN repro
    "from fastapi import APIRouter\nadmin = APIRouter()\n"
    "@admin.post('/grant')\ndef handler(): pass\n",
    # annotated assignment
    "from fastapi import APIRouter\nauth: APIRouter = APIRouter()\n"
    "@auth.get('/login')\ndef handler(): pass\n",
    # custom-named Flask Blueprint via .route
    "from flask import Blueprint\nbilling = Blueprint('b', __name__)\n"
    "@billing.route('/pay', methods=['POST'])\ndef handler(): pass\n",
    # attribute-qualified ctor (aiohttp), custom name
    "from aiohttp import web\ntables = web.RouteTableDef()\n"
    "@tables.get('/x')\ndef handler(request): pass\n",
    # sub-app FastAPI instance under a custom name
    "from fastapi import FastAPI\nservice = FastAPI()\n"
    "@service.put('/v')\ndef handler(): pass\n",
    # import-aliased ctor (`from fastapi import APIRouter as AR`) — alias resolution
    "from fastapi import APIRouter as AR\nadmin = AR()\n"
    "@admin.post('/grant')\ndef handler(): pass\n",
])
def test_custom_router_variable_is_route_handler(src):
    assert _unit_type(src, "handler") == "route_handler"


# ---- over-match guard: verb-shaped decorators on NON-router receivers -------

@pytest.mark.parametrize("src", [
    # cache helper — the @cache.get('/k') over-match repro
    "cache = TTLCache(100)\n@cache.get('/k')\ndef helper(): pass\n",
    # HTTP-client mock/recorder
    "client = Recorder()\n@client.get('https://internal/x')\ndef helper(): pass\n",
    # plugin registry with a .route verb
    "registry = PluginRegistry()\n@registry.route('plugin')\ndef helper(): pass\n",
])
def test_non_router_receiver_is_not_route_handler(src):
    assert _unit_type(src, "helper") != "route_handler"


# ---- isolation: a router name in file A must not qualify file B -------------

def test_router_names_do_not_leak_across_files():
    repo = Path(tempfile.mkdtemp()).resolve()
    (repo / "a.py").write_text(
        "from fastapi import APIRouter\nadmin = APIRouter()\n"
        "@admin.post('/grant')\ndef grant(): pass\n"
    )
    (repo / "b.py").write_text(
        "admin = SomethingElse()\n@admin.post('/n')\ndef notroute(): pass\n"
    )
    ex = FunctionExtractor(str(repo))
    ex.process_file(repo / "a.py")
    ex.process_file(repo / "b.py")
    assert ex.functions["a.py:grant"]["unit_type"] == "route_handler"
    assert ex.functions["b.py:notroute"]["unit_type"] != "route_handler"


# ---- no regression: legacy allowlist receivers still classify ---------------

@pytest.mark.parametrize("src", [
    "@app.route('/x')\ndef handler(): pass\n",
    "@app.get('/x')\ndef handler(): pass\n",
    "from fastapi import APIRouter\nrouter = APIRouter()\n"
    "@router.get('/x')\ndef handler(): pass\n",
    # F4 allowlist names still work WITHOUT a visible assignment
    "@api.get('/x')\ndef handler(): pass\n",
    "@v1.post('/x')\ndef handler(): pass\n",
    "@routes.get('/x')\ndef handler(): pass\n",
])
def test_legacy_route_forms_still_route_handler(src):
    assert _unit_type(src, "handler") == "route_handler"


# ---- #165 conformance: full-pipeline strict-superset seed invariant ---------
#
# PR #165's invariant: an additive route-recognition change must yield
# set(entry_points_patched) >= set(entry_points_pristine), with the delta being
# EXACTLY the intended new seeds. Its own pristine-vs-patched subprocess harness
# (test_F4_entry_root_additive_v3.py::test_strict_superset_and_new_seeds) became
# a permanent skip the day #165 merged — the durable in-repo encoding is
# extensional: run the FULL extractor -> detector pipeline (subprocess, like the
# F4 harness) over a union fixture and assert the complete expected seed set:
#   - #165's pristine spine, INCLUDING its two anti-regression fixtures (a real
#     `@app.route def test_connection()` and a route under `svc/test/`),
#   - #165's own additive seeds,
#   - the router-var fix's new seeds,
# are ALL present, and that non-router verb-decorator decoys plus the CBV helper
# are NEVER seeded. Any future change that drops one of these seeds — the
# failure mode the superset invariant exists to catch — turns this red.
#
# (The literal pristine-vs-patched A/B was run at development time against a
# HEAD-5449b72 worktree: superset held; delta == exactly the 3 new router-var
# seeds; decoys seeded on neither side.)

import json
import subprocess

_PIPELINE_DRIVER = r"""
import json, sys
core, repo = sys.argv[1], sys.argv[2]
sys.path.insert(0, core)
from parsers.python.function_extractor import FunctionExtractor
from utilities.agentic_enhancer.entry_point_detector import EntryPointDetector
res = FunctionExtractor(repo).extract_all()
eps = EntryPointDetector(res["functions"], {}).detect_entry_points()
print(json.dumps(sorted(eps)))
"""

_SUPERSET_FIXTURES = {
    # (#165 anti-regression) real @app.route whose handler is NAMED test_connection
    "app_routes.py": (
        "from flask import Flask\napp = Flask(__name__)\n\n"
        "@app.route('/health')\ndef test_connection():\n    return 'ok'\n"
    ),
    # (#165 anti-regression) real route living UNDER a test/ directory
    "svc/test/handler.py": (
        "from flask import Flask\napp = Flask(__name__)\n\n"
        "@app.route('/svc')\ndef svc_handler():\n    return 'ok'\n"
    ),
    # #165 allowlist receivers (api/v1/router)
    "custom_router.py": (
        "from fastapi import APIRouter\n"
        "router = APIRouter()\napi = APIRouter()\nv1 = APIRouter()\n\n"
        "@router.api_route('/r', methods=['GET'])\ndef router_apiroute():\n    return {}\n\n"
        "@api.get('/a')\ndef api_get_handler():\n    return {}\n\n"
        "@v1.get('/v1')\ndef v1_get_handler():\n    return {}\n"
    ),
    # #165 aiohttp + Starlette + Django-CBV shapes
    "aiohttp_routes.py": (
        "from aiohttp import web\nroutes = web.RouteTableDef()\n\n"
        "@routes.get('/ah')\ndef aiohttp_get_handler(req):\n    return web.Response()\n"
    ),
    "starlette_app.py": (
        "from starlette.applications import Starlette\napp = Starlette()\n\n"
        "@app.websocket_route('/ws')\nasync def ws_handler(websocket):\n"
        "    await websocket.accept()\n"
    ),
    "views.py": (
        "from django.views import View\n\n"
        "def legacy_view(req):\n    return None\n\n"
        "class MyView(View):\n"
        "    def get(self, req):\n        return None\n"
        "    def post(self, req):\n        return None\n"
        "    def get_queryset(self):\n        return []\n"
    ),
    # router-var fix: custom-NAMED router instances (the silent-FN class)
    "named_routers.py": (
        "from fastapi import APIRouter\nfrom flask import Blueprint\n"
        "admin = APIRouter()\nbilling = Blueprint('b', __name__)\n\n"
        "@admin.post('/grant')\ndef grant_handler():\n    return {}\n\n"
        "@billing.route('/pay', methods=['POST'])\ndef pay_handler():\n    return 'ok'\n"
    ),
    "aliased_router.py": (
        "from fastapi import APIRouter as AR\ninternal = AR()\n\n"
        "@internal.get('/i')\ndef internal_handler():\n    return {}\n"
    ),
    # decoys: verb-shaped decorators on NON-router receivers
    "cache_helper.py": (
        "cache = TTLCache(100)\n\n@cache.get('/k')\ndef cache_helper():\n    pass\n"
    ),
    "http_client.py": (
        "client = Recorder()\n\n"
        "@client.get('https://internal/x')\ndef replay_helper():\n    pass\n"
    ),
}

# The superset spine: every seed the pipeline produced BEFORE the router-var fix
# (#165 pristine spine + #165's own additive seeds). Dropping ANY of these
# violates the strict-superset invariant.
_PRE_FIX_SEEDS = {
    "app_routes.py:test_connection",
    "svc/test/handler.py:svc_handler",
    "custom_router.py:router_apiroute",
    "custom_router.py:api_get_handler",
    "custom_router.py:v1_get_handler",
    "aiohttp_routes.py:aiohttp_get_handler",
    "starlette_app.py:ws_handler",
    "views.py:MyView.get",
    "views.py:MyView.post",
    "views.py:legacy_view",
}
# The router-var fix's intended delta — exactly these, nothing else new.
_ROUTER_VAR_SEEDS = {
    "named_routers.py:grant_handler",
    "named_routers.py:pay_handler",
    "aliased_router.py:internal_handler",
}
_NEVER_SEEDED = {
    "views.py:MyView.get_queryset",
    "cache_helper.py:cache_helper",
    "http_client.py:replay_helper",
}


def _run_full_pipeline(repo: Path) -> set:
    proc = subprocess.run(
        [sys.executable, "-c", _PIPELINE_DRIVER, CORE, str(repo)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"pipeline driver failed:\n{proc.stderr}")
    return set(json.loads(proc.stdout.strip().splitlines()[-1]))


def _superset_fixture_repo() -> Path:
    repo = Path(tempfile.mkdtemp(prefix="router_superset_")).resolve()
    for rel, src in _SUPERSET_FIXTURES.items():
        dest = repo / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(src, encoding="utf-8")
    return repo


def test_entry_point_seed_set_is_strict_superset_of_pre_fix_pipeline():
    seeds = _run_full_pipeline(_superset_fixture_repo())

    # Superset: every pre-fix seed (incl. #165's two anti-regression fixtures)
    # survives the router-var change.
    dropped = _PRE_FIX_SEEDS - seeds
    assert not dropped, (
        f"strict-superset violated — pre-fix entry-point seeds dropped: {sorted(dropped)}"
    )

    # Delta: the fix's new seeds are present...
    missing = _ROUTER_VAR_SEEDS - seeds
    assert not missing, f"router-var fix did not seed: {sorted(missing)}"

    # ...and nothing outside the intended sets is seeded from this fixture repo.
    unexpected = seeds - _PRE_FIX_SEEDS - _ROUTER_VAR_SEEDS
    assert not unexpected, f"unintended new seeds (over-seeding): {sorted(unexpected)}"

    # Decoys and the CBV helper are never seeded.
    leaked = _NEVER_SEEDED & seeds
    assert not leaked, f"non-entry-point unit(s) seeded: {sorted(leaked)}"
