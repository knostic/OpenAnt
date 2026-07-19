"""Bug (py-routeparser-async-def-miss, A-class sibling): the route-parser
`def`-only defect had two UNPATCHED clones in the ENRICHER
(parsers/python/dataset_enhancer.py). `PythonDependencyResolver._get_function_source`
walked the AST testing `isinstance(node, ast.FunctionDef)` only, so `async def`
handlers/methods matched nothing and their source was re-dropped even after the
route parser detected them.

Two same-concern sibling sites are covered here:
  1. dataset_enhancer.py :110 — module-level function lookup.
  2. dataset_enhancer.py :126 — class-method lookup.

On HEAD both sites test `ast.FunctionDef` only, so both async cases are a genuine
RED -> GREEN; the sync cases are regression guards.
"""
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.dataset_enhancer import PythonDependencyResolver


def _write(src: str) -> Path:
    repo = Path(tempfile.mkdtemp()).resolve()
    f = repo / "views.py"
    f.write_text(src)
    return f


def test_module_level_async_handler_source_is_enriched():
    # Sibling site :110 — module-level `async def` handler.
    f = _write(
        "async def async_view(request):\n"
        "    return web.Response(text='hi')\n"
    )
    resolver = PythonDependencyResolver(str(f.parent))
    code, start, end = resolver._get_function_source(f, "async_view")
    assert "async_view" in code and start > 0, (
        f"enricher dropped async def handler source (code={code!r}, start={start})"
    )


def test_class_method_async_handler_source_is_enriched():
    # Sibling site :126 — `async def` method inside a class.
    f = _write(
        "class MyView:\n"
        "    async def get(self, request):\n"
        "        return web.Response(text='hi')\n"
    )
    resolver = PythonDependencyResolver(str(f.parent))
    code, start, end = resolver._get_function_source(f, "get")
    assert "async def get" in code and start > 0, (
        f"enricher dropped async def method source (code={code!r}, start={start})"
    )


def test_sync_handler_source_still_enriched():
    # Regression guard: sync path must keep working at both sites.
    f = _write(
        "def sync_view(request):\n"
        "    return 'ok'\n"
        "class MyView:\n"
        "    def get(self, request):\n"
        "        return 'ok'\n"
    )
    resolver = PythonDependencyResolver(str(f.parent))
    fn_code, fn_start, _ = resolver._get_function_source(f, "sync_view")
    m_code, m_start, _ = resolver._get_function_source(f, "get")
    assert "sync_view" in fn_code and fn_start > 0
    assert "def get" in m_code and m_start > 0
