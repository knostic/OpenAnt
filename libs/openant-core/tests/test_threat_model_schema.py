"""Stage B1 — threat-model schema, validation, derivation and round-trip.

Covers the exit criteria for the custom threat-model dataclass extension:

* every missing required field is NAMED in the raised error, and several missing
  fields are all reported in one raise (validation collects, it does not fail fast);
* bad enum values for trust / exposure / position;
* ``schema_version: 2`` errors while listing the supported versions;
* dangling ``entry_via`` and ``handled_by`` cross-references are caught;
* MD -> parse -> validate -> context -> save -> load preserves every field;
* ``load_threat_model`` returns None when ABSENT and RAISES when present-but-broken;
* the derived ``application_type`` is free-form ``custom:...`` and does not trip
  ``UnsupportedApplicationTypeError``;
* a prose decoy ```json block without the schema key is skipped.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from context.application_context import (  # noqa: E402
    MANUAL_OVERRIDE_FILES,
    UnsupportedApplicationTypeError,
    load_context,
    save_context,
)
from context.threat_model import (  # noqa: E402
    SCHEMA_NAME,
    SUPPORTED_SCHEMA_VERSIONS,
    THREAT_MODEL_FILENAME,
    ThreatModelValidationError,
    load_threat_model,
    parse_threat_model_md,
    render_threat_model_md,
    slug,
    threat_model_to_context,
    validate_threat_model,
)

TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "context" / "OPENANT_THREATMODEL_TEMPLATE.md"


def valid_model(**overrides) -> dict:
    """A minimal but fully valid schema-v1 threat model."""
    model = {
        "schema": SCHEMA_NAME,
        "schema_version": 1,
        "classification": "GitOps deployment orchestrator",
        "purpose": "Reconciles manifests from a watched git repo into clusters.",
        "components": [
            {
                "name": "manifest-watcher",
                "paths": ["internal/gitwatch/"],
                "component_type": "manifest watcher",
                "exposure": "internal",
            },
            {
                "name": "admission-webhook",
                "paths": ["cmd/webhook/"],
                "component_type": "admission webhook",
                "exposure": "local",
            },
        ],
        "attacker_profiles": [
            {
                "id": "manifest-committer",
                "description": "Developer with commit access to the manifest repo, no shell on the orchestrator",
                "position": "supply_chain",
                "capabilities": ["Commit arbitrary YAML to the watched repo"],
                "cannot": ["Execute shell commands on the orchestrator host"],
                "entry_via": ["git_manifest_repo"],
                "impact": "Arbitrary code execution inside a cluster-admin pod.",
            },
        ],
        "input_sources": {
            "git_manifest_repo": {
                "trust": "untrusted",
                "description": "YAML manifests from the watched repository.",
                "handled_by": ["manifest-watcher"],
            },
            "orchestrator_config": {
                "trust": "trusted",
                "description": "Operator-supplied config, set at deploy time.",
            },
        },
        "vulnerability_criteria": ["Template sandbox escape reachable from a manifest field"],
        "not_a_vulnerability": ["Applying manifests to the cluster - that is the product"],
        "impact_statement": "Full control of every managed cluster.",
    }
    model.update(overrides)
    return model


def violations_of(model) -> list[str]:
    with pytest.raises(ThreatModelValidationError) as exc:
        validate_threat_model(model)
    return exc.value.violations


# --- missing required fields --------------------------------------------------

@pytest.mark.parametrize("field", [
    "schema", "schema_version", "classification", "purpose", "components",
    "attacker_profiles", "input_sources", "vulnerability_criteria",
    "not_a_vulnerability", "impact_statement",
])
def test_each_missing_required_field_is_named(field):
    model = valid_model()
    del model[field]
    assert any(f"missing required field: {field}" in v for v in violations_of(model)), (
        f"{field} was not named in the violations"
    )


def test_multiple_missing_fields_all_reported_at_once():
    model = valid_model()
    for field in ("purpose", "impact_statement", "vulnerability_criteria"):
        del model[field]
    violations = violations_of(model)
    for field in ("purpose", "impact_statement", "vulnerability_criteria"):
        assert any(f"missing required field: {field}" in v for v in violations)
    # Collecting, not fail-fast: all three in one raise.
    assert len([v for v in violations if "missing required field" in v]) == 3


def test_empty_not_a_vulnerability_is_allowed_but_the_key_is_required():
    validate_threat_model(valid_model(not_a_vulnerability=[]))  # must not raise
    model = valid_model()
    del model["not_a_vulnerability"]
    assert any("not_a_vulnerability" in v for v in violations_of(model))


def test_nested_missing_fields_are_named_with_their_path():
    model = valid_model()
    del model["components"][0]["exposure"]
    del model["attacker_profiles"][0]["cannot"]
    violations = violations_of(model)
    assert any("components[0] missing required field: exposure" in v for v in violations)
    assert any("attacker_profiles[0] missing required field: cannot" in v for v in violations)


# --- enums --------------------------------------------------------------------

def test_bad_trust_level_rejected():
    model = valid_model()
    model["input_sources"]["git_manifest_repo"]["trust"] = "kinda_trusted"
    violations = violations_of(model)
    assert any("trust" in v and "kinda_trusted" in v for v in violations)


def test_trust_level_is_accepted_case_insensitively():
    model = valid_model()
    model["input_sources"]["git_manifest_repo"]["trust"] = "UnTrusted"
    validate_threat_model(model)  # must not raise


def test_bad_exposure_rejected():
    model = valid_model()
    model["components"][0]["exposure"] = "public"
    assert any("exposure" in v and "public" in v for v in violations_of(model))


def test_bad_attacker_position_rejected():
    model = valid_model()
    model["attacker_profiles"][0]["position"] = "hacker"
    assert any("position" in v and "hacker" in v for v in violations_of(model))


def test_free_form_component_type_and_classification_are_not_constrained():
    model = valid_model(classification="Wildly Bespoke Thing #7")
    model["components"][0]["component_type"] = "reconciliation loop"
    validate_threat_model(model)  # must not raise


# --- schema / version ---------------------------------------------------------

def test_schema_version_2_errors_listing_supported_versions():
    violations = violations_of(valid_model(schema_version=2))
    matches = [v for v in violations if "schema_version" in v]
    assert matches, "schema_version violation not reported"
    joined = " ".join(matches)
    for supported in SUPPORTED_SCHEMA_VERSIONS:
        assert str(supported) in joined
    assert "supported versions" in joined


def test_wrong_schema_discriminator_rejected():
    assert any("schema" in v for v in violations_of(valid_model(schema="something-else")))


# --- cross-references ---------------------------------------------------------

def test_dangling_entry_via_is_caught():
    model = valid_model()
    model["attacker_profiles"][0]["entry_via"] = ["no_such_source"]
    violations = violations_of(model)
    assert any("entry_via" in v and "no_such_source" in v for v in violations)


def test_dangling_handled_by_is_caught():
    model = valid_model()
    model["input_sources"]["git_manifest_repo"]["handled_by"] = ["ghost-component"]
    violations = violations_of(model)
    assert any("handled_by" in v and "ghost-component" in v for v in violations)


def test_handled_by_is_optional():
    model = valid_model()
    del model["input_sources"]["git_manifest_repo"]["handled_by"]
    validate_threat_model(model)  # must not raise


# --- parsing ------------------------------------------------------------------

def test_decoy_json_block_without_schema_key_is_skipped():
    text = (
        "# Threat Model\n\n"
        "Here is an example of what NOT to write:\n\n"
        "```json\n"
        '{"application_type": "web_app", "purpose": "a decoy"}\n'
        "```\n\n"
        "And here is a second decoy, a fragment:\n\n"
        "```json\n"
        '{"schema": "some-other-schema", "schema_version": 99}\n'
        "```\n\n"
        "## Machine-Readable Threat Model\n\n"
        "```json\n" + json.dumps(valid_model()) + "\n```\n"
    )
    parsed = parse_threat_model_md(text)
    assert parsed["schema"] == SCHEMA_NAME
    assert parsed["classification"] == "GitOps deployment orchestrator"


def test_unparseable_decoy_block_does_not_prevent_finding_the_real_one():
    text = (
        "```json\n{ this is not json at all ,,, }\n```\n\n"
        "```json\n" + json.dumps(valid_model()) + "\n```\n"
    )
    assert parse_threat_model_md(text)["schema"] == SCHEMA_NAME


def test_no_schema_block_raises_and_says_so():
    text = "```json\n{\"application_type\": \"web_app\"}\n```\n"
    with pytest.raises(ThreatModelValidationError) as exc:
        parse_threat_model_md(text)
    assert any(SCHEMA_NAME in v for v in exc.value.violations)


def test_no_json_block_at_all_raises():
    with pytest.raises(ThreatModelValidationError):
        parse_threat_model_md("# Threat Model\n\nJust prose, no fenced block.\n")


def test_shipped_template_parses_and_validates():
    """The template we tell users to copy must itself be a valid schema-v1 document."""
    text = TEMPLATE_PATH.read_text(encoding="utf-8")
    data = parse_threat_model_md(text)
    validate_threat_model(data)
    # A literal ```json sequence in PROSE opens a fence that swallows the document
    # up to the real block's opener. Keep exactly one, so the template stays parseable
    # no matter how the surrounding documentation is edited.
    assert text.count("```json") == 1


def test_template_documents_the_unfenced_known_gap():
    text = TEMPLATE_PATH.read_text(encoding="utf-8")
    assert "KNOWN GAP" in text
    assert "attacker-influenceable" in text
    assert "NOT prompt-injection-fenced" in text
    assert "_fence.py" in text


# --- derivation ---------------------------------------------------------------

def test_application_type_is_free_form_custom_and_does_not_raise():
    ctx = threat_model_to_context(valid_model())
    assert ctx.application_type == "custom:gitops-deployment-orchestrator"
    assert ctx.has_threat_model() is True
    assert ctx.threat_model_version == 1


def test_custom_application_type_would_be_rejected_without_the_threat_model_branch():
    """Guard the escape hatch: the derived type IS unsupported for the legacy path.

    If this ever stops raising, ``application_type`` has drifted back into the enum
    and the free-form guarantee is gone.
    """
    from context.application_context import ApplicationContext
    with pytest.raises(UnsupportedApplicationTypeError):
        ApplicationContext(application_type="custom:gitops-deployment-orchestrator",
                           purpose="x", source="llm")


def test_trust_boundaries_are_derived_from_input_sources():
    ctx = threat_model_to_context(valid_model())
    assert ctx.trust_boundaries == {
        "git_manifest_repo": "untrusted",
        "orchestrator_config": "trusted",
    }


def test_requires_remote_trigger_true_via_untrusted_input_without_a_remote_attacker():
    model = valid_model()
    assert all(p["position"] != "remote" for p in model["attacker_profiles"])
    assert threat_model_to_context(model).requires_remote_trigger is True


def test_requires_remote_trigger_true_via_remote_attacker_without_untrusted_input():
    model = valid_model()
    model["input_sources"]["git_manifest_repo"]["trust"] = "semi_trusted"
    model["attacker_profiles"][0]["position"] = "remote"
    assert threat_model_to_context(model).requires_remote_trigger is True


def test_requires_remote_trigger_false_when_neither_holds():
    model = valid_model()
    model["input_sources"]["git_manifest_repo"]["trust"] = "trusted"
    assert threat_model_to_context(model).requires_remote_trigger is False


def test_legacy_direct_maps_are_carried():
    model = valid_model(
        intended_behaviors=["Applies arbitrary manifests"],
        security_model="Restricted template function map",
        confidence=0.9,
        evidence=["README.md"],
    )
    ctx = threat_model_to_context(model)
    assert ctx.intended_behaviors == ["Applies arbitrary manifests"]
    assert ctx.security_model == "Restricted template function map"
    assert ctx.confidence == 0.9
    assert ctx.evidence == ["README.md"]
    assert ctx.not_a_vulnerability == model["not_a_vulnerability"]


def test_slug_collapses_punctuation():
    assert slug("GitOps  Deployment/Orchestrator!!") == "gitops-deployment-orchestrator"


# --- MANUAL_OVERRIDE_FILES must stay clean ------------------------------------

def test_threat_model_filename_absent_from_manual_override_files():
    """Adding it would make check_manual_override consume it on the BUILT-IN arm too,
    contaminating the A/B comparison the whole design exists to enable."""
    assert THREAT_MODEL_FILENAME not in MANUAL_OVERRIDE_FILES


# --- round trip ---------------------------------------------------------------

def test_full_round_trip_md_parse_validate_context_save_load(tmp_path):
    model = valid_model(
        intended_behaviors=["Applies arbitrary manifests"],
        security_model="Restricted template function map",
        architecture="Long-running controller.",
        confidence=0.9,
        evidence=["README.md describes the reconcile loop"],
        generated_by="manual",
    )
    md = render_threat_model_md(model)

    # Rendered markdown carries the full human skeleton...
    for heading in ("## Purpose", "## Attacker Profiles", "## Input Sources & Trust Levels",
                    "## What IS a Vulnerability", "## What is NOT a Vulnerability",
                    "## Impact", "## Machine-Readable Threat Model"):
        assert heading in md

    # ...emits exactly one fence (a stray ```json in the prose would shadow it)...
    assert md.count("```json") == 1

    # ...and round-trips exactly through the json block.
    reparsed = parse_threat_model_md(md)
    assert reparsed == model
    validate_threat_model(reparsed)

    ctx = threat_model_to_context(reparsed)
    out = tmp_path / "threat_model_context.json"
    save_context(ctx, out)
    loaded = load_context(out)

    assert loaded.threat_model_version == 1
    assert loaded.classification == model["classification"]
    assert loaded.components == model["components"]
    assert loaded.attacker_profiles == model["attacker_profiles"]
    assert loaded.input_sources == model["input_sources"]
    assert loaded.vulnerability_criteria == model["vulnerability_criteria"]
    assert loaded.impact_statement == model["impact_statement"]
    assert loaded.application_type == ctx.application_type
    assert loaded.trust_boundaries == ctx.trust_boundaries
    assert loaded.requires_remote_trigger == ctx.requires_remote_trigger
    assert loaded.not_a_vulnerability == ctx.not_a_vulnerability
    assert loaded.intended_behaviors == ctx.intended_behaviors
    assert loaded.security_model == ctx.security_model
    assert loaded.confidence == ctx.confidence
    assert loaded.evidence == ctx.evidence
    assert loaded.source == "threat_model"
    assert loaded.has_threat_model() is True


# --- load_threat_model: absent vs malformed -----------------------------------

def test_load_threat_model_returns_none_when_absent(tmp_path):
    assert load_threat_model(tmp_path) is None


def test_load_threat_model_reads_a_valid_file(tmp_path):
    (tmp_path / THREAT_MODEL_FILENAME).write_text(
        render_threat_model_md(valid_model()), encoding="utf-8"
    )
    ctx = load_threat_model(tmp_path)
    assert ctx is not None
    assert ctx.has_threat_model() is True


def test_load_threat_model_raises_when_present_but_invalid_json(tmp_path):
    (tmp_path / THREAT_MODEL_FILENAME).write_text(
        "## Machine-Readable Threat Model\n\n```json\n{ nope\n```\n", encoding="utf-8"
    )
    with pytest.raises(ThreatModelValidationError) as exc:
        load_threat_model(tmp_path)
    assert exc.value.path == tmp_path / THREAT_MODEL_FILENAME


def test_load_threat_model_raises_when_present_but_schema_invalid(tmp_path):
    model = valid_model()
    del model["impact_statement"]
    model["attacker_profiles"][0]["entry_via"] = ["nope"]
    (tmp_path / THREAT_MODEL_FILENAME).write_text(
        "```json\n" + json.dumps(model) + "\n```\n", encoding="utf-8"
    )
    with pytest.raises(ThreatModelValidationError) as exc:
        load_threat_model(tmp_path)
    assert any("impact_statement" in v for v in exc.value.violations)
    assert any("entry_via" in v for v in exc.value.violations)
    assert str(tmp_path / THREAT_MODEL_FILENAME) in str(exc.value)


def test_load_threat_model_does_not_swallow_an_empty_file(tmp_path):
    """The inversion of check_manual_override: empty-but-present is an error."""
    (tmp_path / THREAT_MODEL_FILENAME).write_text("", encoding="utf-8")
    with pytest.raises(ThreatModelValidationError):
        load_threat_model(tmp_path)
