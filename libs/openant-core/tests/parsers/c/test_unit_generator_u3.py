"""Regression test for BUG 29 (c schema_field_drift in unit_generator.py).

Bug report (OpenAnt blind mining, 2026-06-04):
    The C function extractor computes and stores `is_inline` for every function
    (function_extractor._process_function_node, func_data['is_inline']), but the
    unit generator's create_unit() never copies it into the assembled unit's
    `metadata` block. Sibling boolean flags `is_static` and `is_exported` ARE
    carried there, so `is_inline` is silently dropped at unit assembly.

Reproduction:
    Source `m.c` = 'inline int add(int a, int b) {\\n    return a + b;\\n}\\n'
    target = m.c:add, check = metadata, expected is_inline == True.

This test drives the REAL extractor to produce func_data, feeds a call-graph-
shaped dict to the REAL UnitGenerator, and asserts the unit exposes is_inline
at the same location as its sibling flags (unit['metadata']).
"""

import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.c.function_extractor import FunctionExtractor
from parsers.c.unit_generator import UnitGenerator


INLINE_SRC = "inline int add(int a, int b) {\n    return a + b;\n}\n"


def _extract_functions(tmp_path: Path) -> dict:
    """Run the real C function extractor on an inline function and return func_data map."""
    src_file = tmp_path / "m.c"
    src_file.write_text(INLINE_SRC)

    extractor = FunctionExtractor(str(tmp_path))
    result = extractor.extract_all(files=["m.c"])
    return result["functions"]


def _call_graph_data(functions: dict, repo: Path) -> dict:
    """Shape the extractor output as call-graph data that UnitGenerator consumes."""
    return {
        "repository": str(repo),
        "functions": functions,
        "call_graph": {},
        "reverse_call_graph": {},
    }


def test_extractor_produces_is_inline(tmp_path):
    """Sanity: the producer actually emits is_inline=True for an inline function."""
    functions = _extract_functions(tmp_path)
    assert "m.c:add" in functions, f"add not extracted; got {list(functions)}"
    assert functions["m.c:add"]["is_inline"] is True


def test_unit_exposes_is_inline(tmp_path):
    """BUG 29: the assembled unit must carry is_inline alongside its sibling flags."""
    functions = _extract_functions(tmp_path)
    gen = UnitGenerator(_call_graph_data(functions, tmp_path))
    unit = gen.create_unit("m.c:add", functions["m.c:add"])

    # Sibling flags live in unit['metadata']; is_inline must too.
    assert "is_inline" in unit["metadata"], (
        "is_inline dropped at unit assembly; "
        f"metadata keys = {sorted(unit['metadata'])}"
    )
    assert unit["metadata"]["is_inline"] is True
