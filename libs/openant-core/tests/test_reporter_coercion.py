"""Tests for ``core.reporter`` defensive string coercion.

Regression coverage for the crash discovered when running OpenAnt with
a non-Anthropic provider (issue #65 follow-up). The analyze prompt's
schema example says ``attack_vector`` is a string, and Claude reliably
honors that — but GPT-4o sometimes returns the same field as a
structured object. The reporter's ``\\n\\n``.join`` then blew up with
``TypeError: sequence item 0: expected str instance, dict found``.

The fix is twofold:

1. Tighten the analyze prompt to explicitly require string types
   (``prompts/vulnerability_analysis.py``).
2. Defensively coerce at every consumption site in ``reporter.py``
   so a stray dict / list doesn't crash report generation.

These tests pin behavior #2: ``_coerce_to_str`` returns sane strings
for every plausible model-returned shape, and ``build_pipeline_output``
no longer crashes when a finding has dict-shaped ``attack_vector``,
list-of-dict ``data_flow``, or dict-shaped ``verification_explanation``.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from core.reporter import _coerce_to_str, build_pipeline_output
from utilities.file_io import write_json


def _run_build(tmp_path: Path, finding: dict) -> dict:
    """Invoke ``build_pipeline_output`` over a minimal one-finding scan.

    Returns the parsed ``pipeline_output.json``. Test wrappers focus on
    the finding's fields without re-stating the scan-context boilerplate.
    """
    results = {
        "dataset": "test",
        "code_by_route": {"app.py:foo": "def foo(): pass"},
        "metrics": {},
        "confirmed_findings": [{
            "route_key": "app.py:foo",
            "unit_id": "app.py:foo",
            "verdict": "VULNERABLE",
            "finding": "vulnerable",
            **finding,
        }],
    }
    results_path = tmp_path / "results.json"
    write_json(results_path, results)

    out_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(results_path),
        output_path=str(out_path),
        language="python",
        repo_name="test/repo",
    )
    return json.loads(out_path.read_text())


# ---------------------------------------------------------------------------
# _coerce_to_str — unit-level
# ---------------------------------------------------------------------------


class TestCoerceToStr:
    def test_string_passes_through_unchanged(self):
        assert _coerce_to_str("plain text") == "plain text"

    def test_none_becomes_empty_string(self):
        assert _coerce_to_str(None) == ""

    def test_dict_becomes_json(self):
        out = _coerce_to_str({"type": "sqli", "description": "query"})
        # Round-trips cleanly as JSON — not a Python repr.
        assert json.loads(out) == {"type": "sqli", "description": "query"}

    def test_list_becomes_json_array(self):
        out = _coerce_to_str(["step1", "step2"])
        assert json.loads(out) == ["step1", "step2"]

    def test_nested_structure(self):
        # GPT-style structured attack_vector — a real shape we saw in
        # the failing scan. Must serialise without crashing.
        nested = {
            "type": "sql_injection",
            "payload": "' OR 1=1--",
            "steps": [
                {"step": 1, "description": "navigate to /login"},
                {"step": 2, "description": "submit payload"},
            ],
        }
        out = _coerce_to_str(nested)
        # Round-trips cleanly.
        assert json.loads(out) == nested

    def test_integer_falls_back_to_str(self):
        # Numbers should still produce a usable string. JSON encodes
        # them as bare numbers, which is fine for downstream display.
        assert _coerce_to_str(42) == "42"
        assert _coerce_to_str(1.5) == "1.5"

    def test_bool_falls_back_to_str(self):
        # JSON encodes booleans as lowercase, which is consistent
        # enough for downstream rendering.
        assert _coerce_to_str(True) == "true"
        assert _coerce_to_str(False) == "false"

    def test_unjsonable_object_uses_str(self):
        # Something json.dumps can't handle — e.g. a complex number.
        # The fallback to str() means the function never raises.
        class _Weird:
            def __str__(self):
                return "weird-repr"

        # complex() isn't JSON-serialisable, so json.dumps raises and the
        # fallback to str() kicks in: str(complex(1, 2)) == "(1+2j)".
        assert _coerce_to_str(complex(1, 2)) == "(1+2j)"
        assert _coerce_to_str(_Weird()) == "weird-repr"


# ---------------------------------------------------------------------------
# build_pipeline_output — integration-level
# ---------------------------------------------------------------------------


class TestBuildPipelineOutputCoercion:
    """Regression: dict-shaped fields must NOT crash build_pipeline_output."""

    def test_dict_attack_vector_does_not_crash(self, tmp_path):
        # Reproduces the original crash. attack_vector is a dict
        # because GPT-4o returned structured data despite the prompt
        # asking for a string.
        out = _run_build(tmp_path, finding={
            "attack_vector": {
                "type": "sql_injection",
                "description": "' OR 1=1--",
            },
        })
        assert len(out["findings"]) == 1
        steps = out["findings"][0]["steps_to_reproduce"] or ""
        assert "sql_injection" in steps, (
            f"dict attack_vector content lost during coercion: {steps!r}"
        )

    def test_list_of_dicts_in_data_flow_does_not_crash(self, tmp_path):
        # data_flow is supposed to be list[str] per the verify schema,
        # but some models return list[dict]. The string-join used to
        # blow up here too.
        out = _run_build(tmp_path, finding={
            "attack_vector": "GET /user?id=' OR 1=1--",
            "exploit_path": {
                "data_flow": [
                    {"step": 1, "where": "request.query.id"},
                    {"step": 2, "where": "db.execute(sql)"},
                ],
            },
        })
        steps = out["findings"][0]["steps_to_reproduce"] or ""
        assert "request.query.id" in steps
        assert "db.execute(sql)" in steps

    def test_dict_verification_explanation_does_not_crash(self, tmp_path):
        out = _run_build(tmp_path, finding={
            "attack_vector": "GET /user?id=evil",
            "verification_explanation": {
                "summary": "exploitable",
                "rationale": "no input validation",
            },
        })
        steps = out["findings"][0]["steps_to_reproduce"] or ""
        assert "no input validation" in steps

    def test_string_fields_unchanged_after_fix(self, tmp_path):
        # Anthropic still returns clean strings; coercion must be
        # a no-op for the common case (no spurious quoting / wrapping).
        out = _run_build(tmp_path, finding={
            "attack_vector": "GET /user?id=' OR 1=1--",
            "exploit_path": {"data_flow": ["request.query.id", "db.execute(sql)"]},
            "verification_explanation": "no input validation",
        })
        steps = out["findings"][0]["steps_to_reproduce"] or ""
        # Plain text, no JSON quote wrapping around the original string.
        assert "GET /user?id=' OR 1=1--" in steps
        assert "Data flow: request.query.id -> db.execute(sql)" in steps
        assert "Verification: no input validation" in steps


class TestBuildPipelineOutputDataFlowContainer:
    """M3: ``data_flow`` is supposed to be ``list[str]`` per the verify
    schema, but a model can violate that and hand back any JSON shape.

    The original guard iterated the container blindly
    (``for step in data_flow``), which:

    * crashes on a scalar (``TypeError: 'int' object is not iterable``),
    * garbles a bare string into char-by-char ``g -> e -> t ...``,
    * silently drops a dict's values (iterating a dict yields keys).

    The fix coerces the *container* first: list/tuple → join coerced
    steps, anything else → coerce the whole value. These tests drive the
    REAL ``build_pipeline_output`` path with each malformed shape and
    assert no crash plus sensible, lossless output.
    """

    def test_scalar_data_flow_does_not_crash(self, tmp_path):
        # Truthy int — the exact schema-violation class that used to
        # raise ``TypeError: 'int' object is not iterable``.
        out = _run_build(tmp_path, finding={
            "attack_vector": "GET /user?id=evil",
            "exploit_path": {"data_flow": 42},
        })
        steps = out["findings"][0]["steps_to_reproduce"] or ""
        # The scalar value is preserved, not dropped.
        assert "Data flow: 42" in steps, (
            f"scalar data_flow lost / crashed: {steps!r}"
        )

    def test_bare_string_data_flow_not_garbled(self, tmp_path):
        # A bare string is iterable, so the old code char-walked it into
        # 'r -> e -> q -> u -> ...'. The container coercion must keep it
        # whole.
        out = _run_build(tmp_path, finding={
            "attack_vector": "GET /user?id=evil",
            "exploit_path": {"data_flow": "request.query.id"},
        })
        steps = out["findings"][0]["steps_to_reproduce"] or ""
        assert "Data flow: request.query.id" in steps, (
            f"bare-string data_flow garbled: {steps!r}"
        )
        # Proof of "not char-by-char": no single-char arrow joins.
        assert "r -> e -> q" not in steps

    def test_dict_data_flow_preserves_data(self, tmp_path):
        # Iterating a dict yields its keys, so the old code dropped the
        # values entirely. Coercing the whole dict to JSON keeps both.
        out = _run_build(tmp_path, finding={
            "attack_vector": "GET /user?id=evil",
            "exploit_path": {"data_flow": {"source": "request.query.id",
                                           "sink": "db.execute(sql)"}},
        })
        steps = out["findings"][0]["steps_to_reproduce"] or ""
        # Both the value(s) survive — not just the keys.
        assert "request.query.id" in steps
        assert "db.execute(sql)" in steps

    def test_none_data_flow_is_skipped(self, tmp_path):
        # Falsy / absent data_flow must be omitted entirely, not render
        # an empty "Data flow: " line.
        out = _run_build(tmp_path, finding={
            "attack_vector": "GET /user?id=evil",
            "exploit_path": {"data_flow": None},
        })
        steps = out["findings"][0]["steps_to_reproduce"] or ""
        assert "Data flow" not in steps
        # The other part still renders, proving we only skipped data_flow.
        assert "GET /user?id=evil" in steps
