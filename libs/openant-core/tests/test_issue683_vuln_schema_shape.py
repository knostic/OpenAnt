"""#683: the corrector's _VULN_SCHEMA shape matches the Stage-1 prompt's schema.

The #623 fix aligned the ENUM (the verdict values); this completes the SHAPE.
A rescued reply could only carry fields the extraction schema asked for —
cwe_id/cwe_name/attack_vector were absent from the schema, so the extraction
LLM was never asked for them, and _normalize_result stamped cwe_id=0.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utilities.json_corrector import _VULN_SCHEMA  # noqa: E402
from core.verdict_taxonomy import STAGE1_PROMPT_FINDINGS  # noqa: E402


def _schema_fields(schema_text):
    """The field names a schema asks for (the top-level quoted keys)."""
    return set(re.findall(r'"(\w+)":', schema_text))


def test_the_prompt_fields_are_all_in_the_schema():
    """THE #683 SHAPE: every field the Stage-1 prompt asks for appears in the
    corrector's schema — the extraction LLM has a slot to preserve them."""
    prompt_fields = {"function_analyzed", "finding", "reasoning", "severity",
                     "attack_vector", "confidence", "cwe_id", "cwe_name"}
    schema_fields = _schema_fields(_VULN_SCHEMA)
    missing = prompt_fields - schema_fields
    assert not missing, (
        f"fields in the Stage-1 prompt but NOT in the corrector schema: "
        f"{sorted(missing)} — a rescued reply can only carry fields the "
        "schema asks for; _normalize_result stamps the gap (CWE-0 "
        "disclosure, empty impact, dedup exempt)"
    )


def test_the_enum_still_aligned():
    """The #623 enum alignment survives: all STAGE1_PROMPT_FINDINGS values
    appear in the schema (in the canonical lowercase form)."""
    for finding in STAGE1_PROMPT_FINDINGS:
        assert f'"{finding}"' in _VULN_SCHEMA, (
            f"the finding value {finding!r} is missing from the schema "
            "— the #623 enum alignment regressed"
        )


def test_the_legacy_nested_shape_is_gone():
    """The legacy vulnerabilities[] nested form (source/sink/flow — fields the
    reporter never reads) is not the schema."""
    assert "vulnerabilities" not in _schema_fields(_VULN_SCHEMA), (
        "the schema still carries the legacy nested vulnerabilities[] form — "
        "the reporter reads the flat fields (cwe_id/attack_vector/impact), "
        "not source/sink/flow"
    )
    for gone in ("source", "sink", "flow"):
        assert gone not in _schema_fields(_VULN_SCHEMA), (
            f"the legacy field {gone!r} is still in the schema — the "
            "reporter never reads it"
        )
