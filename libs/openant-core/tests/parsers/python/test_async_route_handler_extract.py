"""Bug (py-routeparser-async-def-miss): the Python route parser walked the AST
looking only for `ast.FunctionDef`, so `async def` route handlers were never
matched. Modern async web handlers (Flask 2.x `async def`, aiohttp views —
which are async by definition) were therefore dropped as entry points and never
analyzed.

Two same-concern sibling sites are fixed and covered here:
  1. parsers/python/ast_parser.py `_parse_flask_file` (anchor, :289) — the walk
     that discovers Flask route decorators.
  2. parsers/python/ast_parser.py `_get_function_source` (:100) — resolves a
     handler's source by name; used by the aiohttp/django paths whose handlers
     are frequently `async def`.

On HEAD both sites test `isinstance(node, ast.FunctionDef)` only, so every async
case below is a genuine RED -> GREEN.
"""
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.ast_parser import PythonRouteParser


def _parse_flask_repo(src: str) -> list:
    repo = Path(tempfile.mkdtemp()).resolve()
    (repo / "app.py").write_text(src)
    parser = PythonRouteParser(str(repo))
    parser.framework = "flask"
    parser._parse_flask()
    return parser.routes


def test_async_flask_route_handler_is_extracted():
    src = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/async', methods=['GET'])\n"
        "async def async_handler():\n"
        "    return 'ok'\n"
    )
    routes = _parse_flask_repo(src)
    handlers = {r["route"]["handler"] for r in routes}
    assert "async_handler" in handlers, (
        f"async def route handler was not extracted (got {handlers}) — async "
        "Flask handlers are dropped as entry points."
    )


def test_sync_flask_route_handler_still_extracted():
    # Regression guard: the sync path must keep working.
    src = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/sync', methods=['GET'])\n"
        "def sync_handler():\n"
        "    return 'ok'\n"
    )
    handlers = {r["route"]["handler"] for r in _parse_flask_repo(src)}
    assert "sync_handler" in handlers


def test_get_function_source_resolves_async_handler():
    # Sibling site :100 — resolve an `async def` handler's source by name.
    repo = Path(tempfile.mkdtemp()).resolve()
    views = repo / "views.py"
    views.write_text(
        "async def async_view(request):\n"
        "    return web.Response(text='hi')\n"
    )
    parser = PythonRouteParser(str(repo))
    code, start, end = parser._get_function_source(views, "async_view")
    assert "async_view" in code and start > 0, (
        f"_get_function_source failed to locate an async def handler "
        f"(code={code!r}, start={start})"
    )
