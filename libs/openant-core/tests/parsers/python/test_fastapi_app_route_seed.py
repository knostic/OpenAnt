"""Bug (N3): FastAPI / Flask-2.0 direct-app verb decorators are never seeded as
reachability entry points, so every handler under `@app.get`/`@app.post`/… is
dropped from a `--level reachable` scan (the default) and silently never analyzed.

Two independent gaps, both fixed and both covered here:

  1. parsers/python/function_extractor.py `classify_function` — the route-handler
     check tested the substring `'@get'`, but `@app.get` does NOT contain `@get`
     (the `@` is bound to `app`). So `@app.get`/`@app.post`/… classified as a
     plain function, not `route_handler`.
  2. utilities/agentic_enhancer/entry_point_detector.py `ENTRY_POINT_DECORATORS`
     — had `@router.<verb>` but no `@app.<verb>`, and `@router.websocket` was
     missing from the router verb set, so the decorator path also missed them.

Because `route_handler` is in `ENTRY_POINT_TYPES` AND the decorator list feeds a
second independent check, the fix seeds these handlers by *both* routes. The
trailing `\b` on each new pattern is the precision guard: it must match
`@app.get(` and a bare `@app.get`, but NOT `@app.getter` / `@app.headers`.

Investigated independent + judge on the real pipeline (editable-installed venv):
extract a real FastAPI module, run the real EntryPointDetector, and assert the
handler is seeded. On master both fix sites are absent, so every positive case
below is a genuine RED→GREEN.
"""
import sys
import tempfile
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.function_extractor import FunctionExtractor
from utilities.agentic_enhancer.entry_point_detector import (
    ENTRY_POINT_TYPES,
    EntryPointDetector,
)

# HTTP verbs the modern direct-app idiom exposes (FastAPI + Flask 2.0).
VERBS = ["get", "post", "put", "delete", "patch", "options", "head", "websocket"]


def _extract(src: str) -> dict:
    """Run the real Python extractor over a one-file repo, return its functions."""
    repo = Path(tempfile.mkdtemp()).resolve()
    (repo / "app.py").write_text(src)
    ex = FunctionExtractor(str(repo))
    ex.process_file(repo / "app.py")
    return ex.functions


def _unit_type_of(functions: dict, name: str) -> str:
    for fd in functions.values():
        if fd.get("name") == name:
            return fd.get("unit_type", "")
    raise AssertionError(f"function {name!r} was not extracted at all: "
                         f"{sorted(fd.get('name') for fd in functions.values())}")


# --------------------------------------------------------------------------- #
# Fix site 1 — classify_function via the REAL extractor (end-to-end classify)  #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("verb", VERBS)
def test_app_verb_decorator_classified_as_route_handler(verb):
    src = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        f'@app.{verb}("/x")\n'
        "def handler():\n"
        "    return run_query(request.args)\n"
    )
    assert _unit_type_of(_extract(src), "handler") == "route_handler"


def test_bare_app_verb_without_parens_classified_as_route_handler():
    # `@app.get` with no call parens still ends on a word boundary → must match.
    src = "app = X()\n@app.get\ndef handler():\n    return 1\n"
    assert _unit_type_of(_extract(src), "handler") == "route_handler"


@pytest.mark.parametrize("decorator", [
    "@app.getter",       # would match a `\b`-less `@app.get` — precision guard
    "@app.headers",      # would match a `\b`-less `@app.head` — precision guard
    "@app.on_event('startup')",
    "@app.middleware('http')",
    "@app.exception_handler(404)",
])
def test_non_route_app_decorators_are_not_route_handlers(decorator):
    src = f"app = X()\n{decorator}\ndef not_a_route():\n    return 1\n"
    assert _unit_type_of(_extract(src), "not_a_route") != "route_handler"


# --------------------------------------------------------------------------- #
# Fix site 2 — ENTRY_POINT_DECORATORS via the REAL EntryPointDetector          #
# (isolated from fix site 1: unit_type is a NON-entry type, so only the        #
#  decorator check can seed the function)                                      #
# --------------------------------------------------------------------------- #

def _detect(decorators: list[str], unit_type: str = "function") -> set:
    functions = {
        "app.py:f": {
            "name": "f",
            "unit_type": unit_type,        # deliberately NOT an entry-point type
            "decorators": decorators,
            "code": "return 1",            # no input pattern → no Check-3 rescue
        }
    }
    return EntryPointDetector(functions, {}).detect_entry_points()


@pytest.mark.parametrize("verb", VERBS)
def test_app_verb_decorator_is_entry_point(verb):
    assert "app.py:f" in _detect([f'@app.{verb}("/x")'])


def test_router_websocket_decorator_is_entry_point():
    # @router.websocket was the verb missing from the router pattern.
    assert "app.py:f" in _detect(['@router.websocket("/ws")'])


@pytest.mark.parametrize("decorator", [
    "@app.getter",              # precision guard: `@app.get` + `\b` must NOT match
    "@app.headers",             # precision guard: `@app.head` + `\b` must NOT match
    "@app.middleware('http')",  # not a verb route (and no pre-existing pattern)
    "@app.exception_handler(404)",
])
def test_non_route_app_decorators_are_not_entry_points(decorator):
    # unit_type is non-entry and code has no input pattern, so if these seed at
    # all it can only be via the decorator over-match we are guarding against.
    # NOTE: @app.on_event is deliberately excluded — it matches the PRE-EXISTING
    # `@app\.on_event` pattern (a real lifecycle entry point), not this N3 fix.
    assert "app.py:f" not in _detect([decorator])


# --------------------------------------------------------------------------- #
# End-to-end — the actual N3 chain: extract → detect → handler is reachable    #
# --------------------------------------------------------------------------- #

def test_fastapi_handler_survives_reachability_seeding_end_to_end():
    src = (
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        '@app.get("/items/{n}")\n'
        "def read_item(n):\n"
        "    return __import__('os').system(n)\n"   # a real sink behind the route
    )
    functions = _extract(src)
    entry_points = EntryPointDetector(functions, {}).detect_entry_points()

    handler_ids = [fid for fid, fd in functions.items()
                   if fd.get("name") == "read_item"]
    assert handler_ids, "handler not extracted"
    assert handler_ids[0] in entry_points, (
        "FastAPI @app.get handler was not seeded as an entry point — it would be "
        "dropped from a --level reachable scan and never analyzed (N3)."
    )
    # Sanity: the classification that drives Check-1 is coherent with the type set.
    assert "route_handler" in ENTRY_POINT_TYPES
