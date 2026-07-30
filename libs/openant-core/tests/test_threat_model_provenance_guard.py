"""_finalize()'s non-dict `generated_by` guard (HANDOFF §4 #6: "the non-dict
generated_by guard never runs" — no test exercised the else-branch).

A model can return `generated_by` as a string or list instead of a dict; the naive
`provenance.update(...)` would then raise AttributeError and abort the write. The guard
(context/threat_model_agent.py:332) replaces a non-dict with our own provenance dict.
These pin all three shapes. Fake binding, tmp file — no network, no cost.

RED without the guard: `_finalize` with `generated_by="..."` raises AttributeError
(str has no .update) -> test_string_generated_by_is_coerced would error instead of passing.
"""
from __future__ import annotations

import types

import pytest

from context.threat_model_agent import _finalize
from utilities.file_io import repo_path_state

# Proven-valid schema-v1 payload (mirrors tests/test_threat_model_agent.py::VALID_PAYLOAD).
def _valid_payload() -> dict:
    return {
        "schema": "openant-threat-model",
        "schema_version": 1,
        "classification": "deployment orchestrator",
        "purpose": "Applies manifests to hosts.",
        "components": [{"name": "parser", "paths": ["pkg/"],
                        "component_type": "data parser", "exposure": "internal"}],
        "attacker_profiles": [{"id": "a1", "position": "adjacent", "description": "d",
                               "capabilities": ["c"], "cannot": ["l"],
                               "entry_via": ["src"], "impact": "i"}],
        "input_sources": {"src": {"trust": "semi_trusted", "description": "d"}},
        "vulnerability_criteria": ["crit"],
        "not_a_vulnerability": [],
        "impact_statement": "impact",
    }


_BINDING = types.SimpleNamespace(model="fake-model", provider_name="fake")


def _run(tmp_path, generated_by_value):
    data = _valid_payload()
    if generated_by_value is not _SENTINEL:
        data["generated_by"] = generated_by_value
    target = tmp_path / "OPENANT.THREATMODEL.md"
    _finalize(data, _BINDING, target, repo_path_state(target), explored=True)
    assert target.exists(), "a valid document must be written"
    return data


_SENTINEL = object()


def test_string_generated_by_is_coerced_not_crashed(tmp_path):
    # THE GUARD: a model returning a string must not crash the write.
    data = _run(tmp_path, "the model wrote prose here")
    assert isinstance(data["generated_by"], dict)
    assert data["generated_by"]["model"] == "fake-model"
    assert data["generated_by"]["provider"] == "fake"
    assert data["generated_by"]["survey"] == "repository_exploration"


def test_list_generated_by_is_coerced_not_crashed(tmp_path):
    data = _run(tmp_path, ["a", "list"])
    assert isinstance(data["generated_by"], dict)
    assert data["generated_by"]["model"] == "fake-model"


def test_dict_generated_by_is_preserved_and_stamped(tmp_path):
    # A dict is UPDATED in place (existing keys kept, provenance added) — not replaced.
    data = _run(tmp_path, {"model_note": "keep me"})
    gb = data["generated_by"]
    assert gb["model_note"] == "keep me"          # preserved
    assert gb["model"] == "fake-model"             # stamped
    assert gb["survey"] == "repository_exploration"


def test_missing_generated_by_is_created(tmp_path):
    data = _run(tmp_path, _SENTINEL)               # no generated_by at all
    assert isinstance(data["generated_by"], dict)
    assert data["generated_by"]["provider"] == "fake"


def test_single_shot_survey_label(tmp_path):
    data = _valid_payload()
    data["generated_by"] = "prose"
    target = tmp_path / "OPENANT.THREATMODEL.md"
    _finalize(data, _BINDING, target, repo_path_state(target), explored=False)
    assert data["generated_by"]["survey"] == "single_shot_summary"
