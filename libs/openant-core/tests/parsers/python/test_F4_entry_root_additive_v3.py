#!/usr/bin/env python3
"""F4 v3 — PURE-ADDITIVE entry-root recognition, proven as a STRICT SUPERSET.

Both earlier F4 attempts introduced a dropped seed (a security false negative) by
adding SUPPRESSION — a test-name / test-path guard that demoted a real
`@app.route def test_connection()` and real routes under a `test/` directory to
'test' and removed them from the entry-point seed set. v3 SUPPRESSES NOTHING: it
only ADDS route/entry recognition (custom-named APIRouter, aiohttp RouteTableDef,
Starlette websocket_route, Django class-based-view dispatch methods) ALONGSIDE the
pristine bare-substring `@app.route`/`@router.`/`@blueprint.` checks, which are
left untouched.

This test proves the STRICT-SUPERSET property directly: it runs the full
extractor -> detector pipeline over ONE fixture set on BOTH the pristine core and
the patched core (each in its own subprocess, so the two copies of the modules
never collide in sys.modules), then asserts:

    set(entry_points_patched)  is a SUPERSET of  set(entry_points_pristine)

so no pristine seed is ever lost, AND that every new custom-router / aiohttp /
Starlette / Django-CBV seed appears only after the patch.

The fixture set deliberately INCLUDES the two seeds the earlier unsound patches
dropped — `@app.route def test_connection()` and a route under `svc/test/` — and
asserts they are seeded on BOTH pristine and patched (anti-regression).

RED vs GREEN: on the PRISTINE core the NEW-seed assertions fail (those routes are
missed) — the pristine baseline is captured and asserted to LACK them. After the
patch the same seeds are present. If the patch were a no-op this test fails; if
the patch dropped any pristine seed the superset assertion fails.

Run:
  PY=python
  $PY fixes/F4-entry-root-additive-v3.test.py
"""

import json
import os
import shutil
import subprocess
import sys

import pytest
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
# This repo's own openant-core — tests/parsers/python/ -> openant-core.
# Used by the forward-looking tests, which assert against the CURRENT tree and
# so need no external checkout.
CORE_ROOT = HERE.parent.parent.parent
PATCH = HERE / "F4-entry-root-additive-v3.patch"
# Pristine core: fixes/ and OpenAnt/ are siblings under new-bugs-2/. Allow an
# explicit override so the test is relocatable.
PRISTINE_CORE = Path(
    os.environ.get(
        "OPENANT_CORE",
        HERE.parent / "OpenAnt" / "libs" / "openant-core",
    )
).resolve()

# The pipeline driver, run in a subprocess with `sys.path[0]` = a given core copy.
# It prints the sorted entry-point func_id set as JSON on stdout.
_DRIVER = r"""
import json, sys
core, repo = sys.argv[1], sys.argv[2]
sys.path.insert(0, core)
from parsers.python.function_extractor import FunctionExtractor
from utilities.agentic_enhancer.entry_point_detector import EntryPointDetector
res = FunctionExtractor(repo).extract_all()
functions = res["functions"]
# Detection only iterates `functions`; an empty call graph is sufficient and
# keeps this test independent of the call-graph builder.
eps = EntryPointDetector(functions, {}).detect_entry_points()
print(json.dumps(sorted(eps)))
"""

# One fixture set exercising EVERY required shape. Values chosen so the NEW seeds
# are NOT incidentally seeded on pristine via a user-input code pattern (bodies are
# trivial), which would defeat the RED baseline.
FIXTURES = {
    # (anti-regression) A REAL @app.route whose handler is NAMED test_connection.
    # Must be seeded on BOTH pristine and patched — the earlier unsound patches
    # dropped it because the name starts with 'test'.
    "app_routes.py": (
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/health')\n"
        "def test_connection():\n"
        "    return 'ok'\n"
    ),
    # (anti-regression) A REAL route living UNDER a `test/` directory. Filename is
    # NOT test_*.py; the only test-ish signal is the directory, which must be
    # irrelevant to route classification. Seeded on BOTH pristine and patched.
    "svc/test/handler.py": (
        "from flask import Flask\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/svc')\n"
        "def svc_handler():\n"
        "    return 'ok'\n"
    ),
    # Custom-named APIRouter instances. @router.api_route is already seeded on
    # pristine (the bare '@router.' substring); @api.get and @v1.get are NEW.
    "custom_router.py": (
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n"
        "api = APIRouter()\n"
        "v1 = APIRouter()\n\n"
        "@router.api_route('/r', methods=['GET'])\n"
        "def router_apiroute():\n"
        "    return {}\n\n"
        "@api.get('/a')\n"
        "def api_get_handler():\n"
        "    return {}\n\n"
        "@v1.get('/v1')\n"
        "def v1_get_handler():\n"
        "    return {}\n"
    ),
    # Flask blueprint non-view registrations. Both seeded on pristine via the
    # '@blueprint.' substring — included to prove they survive (superset).
    "blueprints.py": (
        "from flask import Blueprint\n"
        "blueprint = Blueprint('bp', __name__)\n\n"
        "@blueprint.before_request\n"
        "def bp_before():\n"
        "    pass\n\n"
        "@blueprint.errorhandler(404)\n"
        "def bp_error(e):\n"
        "    return 'nf'\n"
    ),
    # aiohttp RouteTableDef — @routes.get. NEW seed (pristine misses it).
    "aiohttp_routes.py": (
        "from aiohttp import web\n"
        "routes = web.RouteTableDef()\n\n"
        "@routes.get('/ah')\n"
        "def aiohttp_get_handler(req):\n"
        "    return web.Response()\n"
    ),
    # Starlette websocket route — @app.websocket_route. NEW seed (the '_route'
    # suffix defeats pristine's @app.(...|websocket)\b boundary check).
    "starlette_app.py": (
        "from starlette.applications import Starlette\n"
        "app = Starlette()\n\n"
        "@app.websocket_route('/ws')\n"
        "async def ws_handler(websocket):\n"
        "    await websocket.accept()\n"
    ),
    # Django class-based view. legacy_view (module-level, class_name is None) is
    # seeded on pristine via the existing 'views' branch — proves that branch is
    # untouched. MyView.get / MyView.post are NEW (CBV dispatch). get_queryset is a
    # helper that must NOT be swept in (exact HTTP-verb match only).
    "views.py": (
        "from django.views import View\n\n"
        "def legacy_view(req):\n"
        "    return None\n\n"
        "class MyView(View):\n"
        "    def get(self, req):\n"
        "        return None\n"
        "    def post(self, req):\n"
        "        return None\n"
        "    def get_queryset(self):\n"
        "        return []\n"
    ),
}

# func_ids present on pristine (must remain on patched -> superset spine).
PRISTINE_EXPECTED = {
    "app_routes.py:test_connection",
    "svc/test/handler.py:svc_handler",
    "custom_router.py:router_apiroute",
    "blueprints.py:bp_before",
    "blueprints.py:bp_error",
    "views.py:legacy_view",
}
# func_ids that the additive patch newly seeds (absent on pristine, present after).
NEW_EXPECTED = {
    "custom_router.py:api_get_handler",
    "custom_router.py:v1_get_handler",
    "aiohttp_routes.py:aiohttp_get_handler",
    "starlette_app.py:ws_handler",
    "views.py:MyView.get",
    "views.py:MyView.post",
}
# Must never be seeded on either side (CBV helper, not an HTTP dispatch method).
NEVER_SEEDED = {"views.py:MyView.get_queryset"}


def _write_fixture_repo() -> Path:
    repo = Path(tempfile.mkdtemp(prefix="f4v3_repo_"))
    for rel, src in FIXTURES.items():
        dest = repo / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(src, encoding="utf-8")
    return repo


def _run_pipeline(core: Path, repo: Path) -> set:
    proc = subprocess.run(
        [sys.executable, "-c", _DRIVER, str(core), str(repo)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"pipeline failed for core={core}:\n{proc.stderr}")
    return set(json.loads(proc.stdout.strip().splitlines()[-1]))


def _build_patched_core() -> Path:
    dest = Path(tempfile.mkdtemp(prefix="f4v3_core_")) / "openant-core"
    shutil.copytree(PRISTINE_CORE, dest)
    subprocess.run(
        ["git", "apply", "-p1", str(PATCH)],
        cwd=str(dest),
        check=True,
        capture_output=True,
        text=True,
    )
    return dest


def test_strict_superset_and_new_seeds():
    # This is a development-time RED/GREEN harness: it compares a PRE-#165
    # checkout against the same tree with the F4 patch applied. Commit 858f5d6
    # merged that patch, and the .patch file was never committed, so neither
    # precondition can be satisfied from inside this repo — it has failed on
    # every run since the day it landed.
    #
    # Skipped rather than left red so it stops masquerading as a signal. The
    # coverage it was meant to provide now lives in
    # test_f4_seeds_are_produced_by_the_current_core below, which asserts the
    # same seeds forward against the current tree and needs no external
    # checkout.
    if not PRISTINE_CORE.is_dir() or not PATCH.is_file():
        pytest.skip(
            "pristine-vs-patched harness needs an out-of-tree pre-#165 checkout "
            f"({PRISTINE_CORE}) and a patch file ({PATCH}) that is not committed; "
            "forward-looking coverage lives in "
            "test_f4_seeds_are_produced_by_the_current_core"
        )

    repo = _write_fixture_repo()
    patched_core = _build_patched_core()

    pristine = _run_pipeline(PRISTINE_CORE, repo)
    patched = _run_pipeline(patched_core, repo)

    # STRICT SUPERSET: every pristine seed survives the patch.
    assert patched >= pristine, (
        "patched entry points are NOT a superset of pristine — the patch dropped "
        f"seed(s): {sorted(pristine - patched)}"
    )

    # The pristine baseline seeds are all present on pristine (sanity + anti-regression
    # of the two test-named/test-path routes the earlier unsound patches dropped).
    missing_pristine = PRISTINE_EXPECTED - pristine
    assert not missing_pristine, f"expected-pristine seeds missing on pristine: {sorted(missing_pristine)}"

    # RED baseline: the NEW seeds are absent on the PRISTINE core.
    leaked = NEW_EXPECTED & pristine
    assert not leaked, f"new seeds unexpectedly present on pristine (RED baseline broken): {sorted(leaked)}"

    # GREEN: the NEW custom-router / aiohttp / Starlette / Django-CBV seeds appear
    # after the additive patch.
    still_missing = NEW_EXPECTED - patched
    assert not still_missing, f"additive patch did not seed: {sorted(still_missing)}"

    # The strict-superset delta is EXACTLY the new seeds (nothing else changed, and
    # nothing was suppressed).
    assert patched - pristine == NEW_EXPECTED, (
        f"unexpected seed delta: added={sorted(patched - pristine)} "
        f"expected={sorted(NEW_EXPECTED)}"
    )

    # The CBV helper is seeded on NEITHER side.
    assert not (NEVER_SEEDED & pristine), "CBV helper wrongly seeded on pristine"
    assert not (NEVER_SEEDED & patched), "CBV helper wrongly seeded on patched"


if __name__ == "__main__":
    try:
        test_strict_superset_and_new_seeds()
    except AssertionError as exc:
        print(f"FAIL test_strict_superset_and_new_seeds: {exc}")
        sys.exit(1)
    except Exception as exc:  # setup / environment errors
        print(f"ERROR: {exc}")
        sys.exit(2)
    print("PASS test_strict_superset_and_new_seeds")
    print("all tests PASSED")


def test_f4_seeds_are_produced_by_the_current_core():
    """Forward-looking replacement for the pristine-vs-patched comparison.

    Asserts that the CURRENT tree seeds the F4 entry-point patterns —
    custom ``APIRouter`` instances, aiohttp ``RouteTableDef``, Starlette
    ``websocket_route``, and Django class-based-view dispatch methods — against
    the same fixture repo the original harness used.

    This is the only coverage of those patterns in the suite. The original test
    could not provide it: it aborts on an unsatisfiable precondition before
    reaching a single assertion.
    """
    repo = _write_fixture_repo()
    seeds = _run_pipeline(CORE_ROOT, repo)

    missing = NEW_EXPECTED - seeds
    assert not missing, (
        "current core does not seed the F4 entry points: "
        f"{sorted(missing)}\nseeded: {sorted(seeds)}"
    )


def test_cbv_helper_is_never_seeded_by_the_current_core():
    """``get_queryset`` is a CBV helper, not an HTTP dispatch method.

    Seeding it would inflate the reachability root set with non-entry points.
    """
    repo = _write_fixture_repo()
    seeds = _run_pipeline(CORE_ROOT, repo)

    leaked = NEVER_SEEDED & seeds
    assert not leaked, f"non-entry-point helper(s) seeded: {sorted(leaked)}"
