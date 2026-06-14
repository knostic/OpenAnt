"""Canonical per-parser schema completeness: every emitted function unit carries
the schema-contract fields downstream consumers (call graph, unit generator,
entry-point detector, dataset) read. Run across top-level, nested, method,
async, decorated, and block-scoped defs so no emit path drops a field.
"""
import sys
import tempfile
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.python.function_extractor import FunctionExtractor

# Fields every function unit must expose (present-as-key; value may be None/[]).
_REQUIRED_FIELDS = {
    "name", "qualified_name", "file_path", "start_line", "end_line",
    "code", "parameters", "unit_type", "is_async", "decorators",
    "class_name",
}

_FIXTURE = (
    "import functools\n"
    "def top(a, b):\n"
    "    return a + b\n"
    "async def atop():\n"
    "    return 1\n"
    "@functools.cache\n"
    "def decorated():\n"
    "    return 2\n"
    "class C:\n"
    "    def method(self):\n"
    "        def nested():\n"
    "            return 3\n"
    "        return nested()\n"
    "if FLAG:\n"
    "    def block_fn(x):\n"
    "        return x\n"
    "    async def block_async():\n"
    "        return 4\n"
)


def _functions():
    repo = Path(tempfile.mkdtemp()).resolve()
    (repo / "m.py").write_text(_FIXTURE)
    ex = FunctionExtractor(str(repo))
    ex.process_file(repo / "m.py")
    return {k: v for k, v in ex.functions.items() if not k.endswith(":__module__")}


def test_every_function_has_required_schema_fields():
    fns = _functions()
    assert fns, "fixture produced no functions"
    for fid, data in fns.items():
        missing = _REQUIRED_FIELDS - set(data)
        assert not missing, f"{fid} missing schema fields: {sorted(missing)}"


def test_block_scoped_defs_present_and_well_formed():
    names = {k.split(":", 1)[1] for k in _functions()}
    for expected in ("block_fn", "block_async"):
        assert expected in names, f"{expected} not surfaced: {sorted(names)}"


def test_field_value_types():
    for fid, data in _functions().items():
        assert isinstance(data["name"], str) and data["name"], fid
        assert isinstance(data["parameters"], list), fid
        assert isinstance(data["start_line"], int), fid
        assert isinstance(data["is_async"], bool), fid
