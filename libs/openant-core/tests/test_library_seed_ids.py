"""Fix C — shared library_seed_ids: public-API seed set, both key casings.

The subprocess pipelines normalize function records to camelCase (`isExported`)
while the on-disk call_graph and the Python path use snake_case (`is_exported`).
`library_seed_ids` must seed the exported, non-name-private functions under EITHER
casing, defaulting to exported when neither field is present (over-seed, never
under-seed). This is what lets a C/JS/etc. library's public API surface seed the
reachability BFS instead of blacking out.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from utilities.agentic_enhancer import library_seed_ids  # noqa: E402


def test_snake_case_exported_seeded():
    fns = {"f.c:pub": {"name": "pub", "is_exported": True}}
    assert library_seed_ids(fns) == {"f.c:pub"}


def test_snake_case_static_not_seeded():
    fns = {"f.c:priv": {"name": "priv", "is_exported": False}}
    assert library_seed_ids(fns) == set()


def test_camel_case_exported_seeded():
    # JS/normalized-pipeline shape.
    fns = {"f.js:pub": {"name": "pub", "isExported": True}}
    assert library_seed_ids(fns) == {"f.js:pub"}


def test_camel_case_unexported_not_seeded():
    fns = {"f.js:priv": {"name": "priv", "isExported": False}}
    assert library_seed_ids(fns) == set()


def test_missing_field_defaults_exported():
    # Parsers without an export field (python/ruby/php) default to exported.
    fns = {"m.py:helper": {"name": "helper"}}
    assert library_seed_ids(fns) == {"m.py:helper"}


def test_leading_underscore_name_is_private():
    fns = {
        "m.py:_internal": {"name": "_internal"},
        "m.py:public": {"name": "public"},
    }
    assert library_seed_ids(fns) == {"m.py:public"}


def test_name_falls_back_to_func_id_tail():
    # No 'name' field -> derive from the func_id tail, strip a dotted qualifier.
    fns = {"f.c:Mod.run": {"is_exported": True}}
    assert library_seed_ids(fns) == {"f.c:Mod.run"}


def test_exported_but_underscore_still_excluded():
    # Name-private wins even when exported (a public-but-_-prefixed symbol is
    # conventionally internal); over-seeding bias does not override the name rule.
    fns = {"f.c:_x": {"name": "_x", "is_exported": True}}
    assert library_seed_ids(fns) == set()
