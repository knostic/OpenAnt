"""Negative controls for threat-model validation.

Mutation testing over the existing suite found 18-21 surviving mutants in
``validate_threat_model``: every type check, every empty check, and every nested
missing-field check could be deleted with the suite still green. The cause was that
``test_threat_model_schema.py`` tests exactly one axis thoroughly — deleting a
top-level key from an otherwise-valid model — and never supplies a wrong *type* or a
malformed *nested* object.

That matters more here than in most validators: this file is authored by the scanned
repository, which OpenAnt treats as hostile. A validator whose rejection paths never
execute is not a trust boundary, it is decoration.

Each test below is a negative control: it asserts the validator REJECTS something,
and names the violation, rather than asserting a valid model is accepted.
"""

from __future__ import annotations

import copy

import pytest

from context.threat_model import (
    ThreatModelValidationError,
    validate_threat_model,
    warn_permissive_threat_model,
)

VALID = {
    "schema": "openant-threat-model",
    "schema_version": 1,
    "classification": "deployment-orchestrator",
    "purpose": "reconcile manifests into cluster state",
    "components": [
        {"name": "watcher", "paths": ["src/watch"], "component_type": "manifest watcher",
         "exposure": "remote"},
    ],
    "attacker_profiles": [
        {"id": "committer", "description": "developer with commit access",
         "position": "supply_chain", "capabilities": ["push a manifest"],
         "cannot": ["shell on the orchestrator"], "entry_via": ["manifest_repo"],
         "impact": "arbitrary workload scheduling"},
    ],
    "input_sources": {
        "manifest_repo": {"trust": "semi_trusted", "description": "watched git repo",
                          "handled_by": ["watcher"]},
    },
    "vulnerability_criteria": ["anything a committer can escalate"],
    "not_a_vulnerability": ["misconfiguration by the cluster operator"],
    "impact_statement": "cluster-wide workload compromise",
}


def _reject(model: dict) -> str:
    """Assert the model is rejected; return the joined violations."""
    with pytest.raises(ThreatModelValidationError) as exc:
        validate_threat_model(model)
    return "\n".join(exc.value.violations)


def test_the_valid_baseline_is_actually_valid():
    """Guards every other test in this file.

    If VALID drifts out of validity, each _reject() below passes for the wrong
    reason and the whole file becomes vacuous.
    """
    validate_threat_model(copy.deepcopy(VALID))


# --- type violations, per field ----------------------------------------------


@pytest.mark.parametrize(
    "field,bad",
    [
        ("classification", 42),
        ("classification", ""),
        ("purpose", None),
        ("impact_statement", []),
        ("components", "not a list"),
        ("components", []),
        ("attacker_profiles", {}),
        ("attacker_profiles", []),
        ("input_sources", []),
        ("input_sources", {}),
        ("vulnerability_criteria", "a string not a list"),
        ("not_a_vulnerability", 7),
    ],
)
def test_wrong_type_for_top_level_field_is_rejected(field: str, bad):
    model = copy.deepcopy(VALID)
    model[field] = bad
    assert field.split("[")[0] in _reject(model)


@pytest.mark.parametrize(
    "key,bad",
    [("name", 1), ("name", ""), ("component_type", None), ("paths", "src"),
     ("paths", []), ("exposure", "Remote"), ("exposure", "everywhere")],
)
def test_malformed_component_is_rejected(key: str, bad):
    model = copy.deepcopy(VALID)
    model["components"][0][key] = bad
    assert "components[0]" in _reject(model)


@pytest.mark.parametrize(
    "key,bad",
    [("id", ""), ("description", None), ("impact", 3), ("position", "nearby"),
     ("capabilities", []), ("capabilities", "push"), ("cannot", []),
     ("entry_via", []), ("entry_via", "manifest_repo")],
)
def test_malformed_attacker_profile_is_rejected(key: str, bad):
    model = copy.deepcopy(VALID)
    model["attacker_profiles"][0][key] = bad
    assert "attacker_profiles[0]" in _reject(model)


@pytest.mark.parametrize(
    "key,bad",
    [("trust", "kinda"), ("trust", None), ("description", 5), ("handled_by", "watcher")],
)
def test_malformed_input_source_is_rejected(key: str, bad):
    model = copy.deepcopy(VALID)
    model["input_sources"]["manifest_repo"][key] = bad
    assert "manifest_repo" in _reject(model)


@pytest.mark.parametrize("bad", [None, [], "a string", 42, True])
def test_non_object_model_is_rejected(bad):
    _reject(bad)


@pytest.mark.parametrize("missing", sorted(VALID.keys() - {"schema_version"}))
def test_each_missing_required_field_is_named(missing: str):
    model = copy.deepcopy(VALID)
    del model[missing]
    assert missing in _reject(model)


# --- identity and contradiction ----------------------------------------------


def test_schema_version_true_is_not_version_one():
    """`True == 1` in Python, so a bare membership test accepted `true`.

    The same bool guard was already present on `confidence` and absent here — the
    "wired one branch of two" shape that recurs throughout this codebase.
    """
    model = copy.deepcopy(VALID)
    model["schema_version"] = True
    assert "schema_version" in _reject(model)


def test_duplicate_attacker_profile_ids_are_rejected():
    """Ids name personas in the Stage 2 prompt; duplicates are indistinguishable."""
    model = copy.deepcopy(VALID)
    model["attacker_profiles"].append(copy.deepcopy(model["attacker_profiles"][0]))
    assert "duplicates" in _reject(model)


def test_duplicate_component_names_are_rejected():
    """Duplicates collapse into the name set and weaken the handled_by cross-check."""
    model = copy.deepcopy(VALID)
    model["components"].append(copy.deepcopy(model["components"][0]))
    assert "duplicates" in _reject(model)


def test_contradictory_can_and_cannot_is_rejected():
    """Both lists render verbatim to the verifier, which is then told both.

    `cannot` is what makes a NOT-EXPLOITABLE verdict falsifiable, so a contradiction
    silently decides that verdict in whichever direction the model happens to read.
    """
    model = copy.deepcopy(VALID)
    model["attacker_profiles"][0]["cannot"] = ["push a manifest"]
    assert "both capabilities and cannot" in _reject(model)


def test_empty_input_source_key_is_rejected():
    model = copy.deepcopy(VALID)
    model["input_sources"][""] = {"trust": "trusted", "description": "x",
                                  "handled_by": []}
    assert "non-empty string" in _reject(model)


def test_dangling_cross_references_are_rejected():
    model = copy.deepcopy(VALID)
    model["attacker_profiles"][0]["entry_via"] = ["no_such_source"]
    assert "unknown input source" in _reject(model)

    model = copy.deepcopy(VALID)
    model["input_sources"]["manifest_repo"]["handled_by"] = ["no_such_component"]
    assert "unknown" in _reject(model).lower()


# --- permissive-model warnings (THREAT_MODEL_AUTHORITY_DESIGN.md 2.4) --------


def test_all_trusted_inputs_warns():
    """A repository can whitelist itself without anything being malformed.

    Nothing here is invalid, so validation cannot catch it. The only defence is
    making the suppression visible.
    """
    model = copy.deepcopy(VALID)
    model["input_sources"]["manifest_repo"]["trust"] = "trusted"
    warnings = warn_permissive_threat_model(model)
    assert any("trusted" in w for w in warnings)


def test_no_reachable_attacker_warns():
    model = copy.deepcopy(VALID)
    model["attacker_profiles"][0]["position"] = "local_user"
    warnings = warn_permissive_threat_model(model)
    assert any("remote" in w for w in warnings)


def test_blanket_exclusions_warn():
    model = copy.deepcopy(VALID)
    model["not_a_vulnerability"] = [
        "ALL command injection", "ALL SQL injection", "ALL RCE", "ALL path traversal",
        "ALL SSRF", "ALL deserialization", "ALL XSS", "ALL auth bypass",
    ]
    warnings = warn_permissive_threat_model(model)
    assert any("not_a_vulnerability" in w for w in warnings)


def test_an_honest_model_produces_no_warnings():
    """Negative control for the warnings themselves.

    Without this, a warn() that fired on everything would pass every test above
    while making the signal useless.
    """
    assert warn_permissive_threat_model(copy.deepcopy(VALID)) == []
