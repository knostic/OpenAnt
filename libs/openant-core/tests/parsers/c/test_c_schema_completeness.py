"""Schema-completeness contract test for the C parser (BUG 29 family guard).

BUG 29 was a *field drift*: the function extractor produced `is_inline` in its
per-function `func_data`, but the unit generator's create_unit() silently
dropped it when assembling the unit's metadata. The root family is
"producer/consumer field-contract not schema-enforced" — a textual, per-field
review misses the next drop. This test makes the contract explicit and
machine-checked.

Design:
    * FIELD_CONTRACT maps each extractor-produced metadata key that the unit
      MUST expose -> the dotted location where create_unit() should place it.
    * A small reusable `get_path(obj, dotted)` walks that location.
    * One parametrized test drives the REAL extractor + REAL UnitGenerator on a
      function exercising every flag (static, inline) and asserts each contracted
      field is present at its location and round-trips the producer's value.

To add a future field to the contract: extend FIELD_CONTRACT. If create_unit()
forgets to carry it, this test fails — no per-field hand audit needed.
"""

import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_CORE_ROOT))

from parsers.c.function_extractor import FunctionExtractor
from parsers.c.unit_generator import UnitGenerator


# Source exercising the contracted flags: `static inline` => is_static=True,
# is_inline=True, is_exported=False, plus return_type/parameters populated.
CONTRACT_SRC = "static inline int add(int a, int b) {\n    return a + b;\n}\n"
TARGET_ID = "m.c:add"

# extractor func_data key -> dotted location in the assembled unit.
# This is the field-contract the consumer (create_unit) must honor.
FIELD_CONTRACT = {
    "is_static": "metadata.is_static",
    "is_exported": "metadata.is_exported",
    "is_inline": "metadata.is_inline",
    "return_type": "metadata.return_type",
    "parameters": "metadata.parameters",
    "unit_type": "unit_type",
    "name": "code.primary_origin.function_name",
    "file_path": "code.primary_origin.file_path",
    "class_name": "code.primary_origin.class_name",
    "start_line": "code.primary_origin.start_line",
    "end_line": "code.primary_origin.end_line",
}

_MISSING = object()


def get_path(obj, dotted):
    """Walk a dotted path through nested dicts; return _MISSING if any hop absent."""
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return _MISSING
        cur = cur[part]
    return cur


@pytest.fixture(scope="module")
def extracted_and_unit(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("c_schema")
    (tmp_path / "m.c").write_text(CONTRACT_SRC)

    extractor = FunctionExtractor(str(tmp_path))
    functions = extractor.extract_all(files=["m.c"])["functions"]
    assert TARGET_ID in functions, f"target not extracted; got {list(functions)}"

    gen = UnitGenerator({
        "repository": str(tmp_path),
        "functions": functions,
        "call_graph": {},
        "reverse_call_graph": {},
    })
    unit = gen.create_unit(TARGET_ID, functions[TARGET_ID])
    return functions[TARGET_ID], unit


# Parallel consumer: generate_analyzer_output() re-emits a camelCase schema.
# It is the SECOND place BUG-29's field could drift; guard it too.
# extractor snake_case key -> analyzer_output camelCase key.
ANALYZER_CONTRACT = {
    "name": "name",
    "unit_type": "unitType",
    "code": "code",
    "file_path": "filePath",
    "start_line": "startLine",
    "end_line": "endLine",
    "is_static": "isStatic",
    "is_exported": "isExported",
    "is_inline": "isInline",
    "return_type": "returnType",
    "parameters": "parameters",
    "class_name": "className",
}


@pytest.mark.parametrize("producer_key,camel_key", sorted(ANALYZER_CONTRACT.items()))
def test_analyzer_output_contract_carried(extracted_and_unit, producer_key, camel_key):
    """generate_analyzer_output() must re-emit every contracted field (camelCase)."""
    func_data, _unit = extracted_and_unit
    gen = UnitGenerator({
        "repository": "",
        "functions": {TARGET_ID: func_data},
        "call_graph": {},
        "reverse_call_graph": {},
    })
    out = gen.generate_analyzer_output()["functions"][TARGET_ID]
    assert camel_key in out, (
        f"field '{producer_key}' dropped from analyzer_output: "
        f"expected camelCase key '{camel_key}'; keys = {sorted(out)}"
    )
    assert out[camel_key] == func_data[producer_key]


@pytest.mark.parametrize("producer_key,unit_location", sorted(FIELD_CONTRACT.items()))
def test_field_contract_carried(extracted_and_unit, producer_key, unit_location):
    """Each extractor-produced field must appear at its contracted unit location."""
    func_data, unit = extracted_and_unit

    assert producer_key in func_data, (
        f"contract assumes extractor produces '{producer_key}', but it did not "
        f"(producer keys = {sorted(func_data)})"
    )

    value = get_path(unit, unit_location)
    assert value is not _MISSING, (
        f"field '{producer_key}' dropped at unit assembly: "
        f"expected at unit location '{unit_location}'"
    )
    assert value == func_data[producer_key], (
        f"field '{producer_key}' did not round-trip: "
        f"producer={func_data[producer_key]!r} unit={value!r}"
    )


def test_drift_prone_keys_stay_in_contract():
    """Self-check: the BUG-29 drift-prone key must remain in both contract maps
    so this suite cannot silently go toothless if someone deletes the entry
    (parity with the PHP schema test). If `is_inline` is dropped from a map, the
    field-drift guard above evaporates -- fail loudly instead."""
    assert "is_inline" in FIELD_CONTRACT, "is_inline dropped from FIELD_CONTRACT -> guard disabled"
    assert ANALYZER_CONTRACT.get("is_inline") == "isInline", "is_inline->isInline dropped from ANALYZER_CONTRACT -> guard disabled"
