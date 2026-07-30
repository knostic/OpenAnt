"""Stage B1 — the threat-model fields must not disturb pre-existing contexts.

``ApplicationContext`` grew seven optional fields for the custom threat-model path.
The whole design rests on those fields being *invisible* to everything written before
they existed: an ``application_context.json`` produced by an older run must still
load, ``source == "merged"`` must still be accepted, and the four-value type
validation must still fire exactly as before for non-threat-model contexts.

If any of this breaks, the A/B comparison between the built-in arm and the
threat-model arm is measuring two different pipelines rather than two different
contexts.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from utilities.file_io import write_json  # noqa: E402

from context.application_context import (  # noqa: E402
    ApplicationContext,
    UnsupportedApplicationTypeError,
    load_context,
    save_context,
)

# Byte-for-byte the shape ``save_context`` produced before the threat-model fields
# were added: no threat_model_version, no classification, no components, etc.
LEGACY_CONTEXT_JSON = {
    "application_type": "cli_tool",
    "purpose": "Command-line tool for managing cloud infrastructure",
    "intended_behaviors": ["Reads and writes local configuration files"],
    "trust_boundaries": {"cli_arguments": "trusted", "config_files": "trusted"},
    "security_model": "API keys stored in environment variables",
    "not_a_vulnerability": ["Path traversal in file operations - user has filesystem access"],
    "requires_remote_trigger": False,
    "confidence": 1.0,
    "evidence": ["Manual configuration"],
    "source": "llm",
}


def _write_legacy(tmp_path, **overrides) -> Path:
    data = {**LEGACY_CONTEXT_JSON, **overrides}
    path = tmp_path / "application_context.json"
    write_json(path, data)
    return path


def test_legacy_json_without_new_keys_still_loads(tmp_path):
    ctx = load_context(_write_legacy(tmp_path))
    assert ctx.application_type == "cli_tool"
    assert ctx.purpose == LEGACY_CONTEXT_JSON["purpose"]
    assert ctx.trust_boundaries == LEGACY_CONTEXT_JSON["trust_boundaries"]
    assert ctx.source == "llm"


def test_legacy_json_defaults_the_threat_model_fields(tmp_path):
    ctx = load_context(_write_legacy(tmp_path))
    assert ctx.threat_model_version is None
    assert ctx.classification is None
    assert ctx.components == []
    assert ctx.attacker_profiles == []
    assert ctx.input_sources == {}
    assert ctx.vulnerability_criteria == []
    assert ctx.impact_statement is None


def test_legacy_json_has_no_threat_model(tmp_path):
    assert load_context(_write_legacy(tmp_path)).has_threat_model() is False


@pytest.mark.parametrize("source", ["llm", "manual", "merged"])
def test_all_legacy_source_values_still_accepted(tmp_path, source):
    ctx = load_context(_write_legacy(tmp_path, source=source))
    assert ctx.source == source


def test_merged_source_accepted_on_direct_construction():
    ctx = ApplicationContext(application_type="web_app", purpose="x", source="merged")
    assert ctx.source == "merged"
    assert ctx.has_threat_model() is False


def test_default_mutable_fields_are_not_shared_between_instances():
    a = ApplicationContext(application_type="library", purpose="a")
    b = ApplicationContext(application_type="library", purpose="b")
    a.components.append("x")
    a.input_sources["k"] = "v"
    a.vulnerability_criteria.append("y")
    a.attacker_profiles.append("z")
    assert b.components == [] and b.input_sources == {}
    assert b.vulnerability_criteria == [] and b.attacker_profiles == []


# --- the legacy validation path is untouched ----------------------------------

def test_unsupported_type_still_raises_for_llm_source():
    with pytest.raises(UnsupportedApplicationTypeError):
        ApplicationContext(application_type="desktop_app", purpose="x", source="llm")


def test_manual_override_bypass_still_works():
    ctx = ApplicationContext(application_type="desktop_app", purpose="x", source="manual")
    assert ctx.application_type == "desktop_app"
    assert ctx.has_threat_model() is False


def test_threat_model_bypass_is_independent_of_the_manual_bypass():
    """A threat-model context skips type validation on its own branch, with source
    'threat_model' — NOT by masquerading as a manual override."""
    ctx = ApplicationContext(
        application_type="custom:gitops-deployment-orchestrator",
        purpose="x",
        source="threat_model",
        threat_model_version=1,
    )
    assert ctx.source == "threat_model"
    assert ctx.has_threat_model() is True


def test_legacy_round_trip_is_unchanged(tmp_path):
    ctx = ApplicationContext(**{k: v for k, v in LEGACY_CONTEXT_JSON.items()})
    out = tmp_path / "ctx.json"
    save_context(ctx, out)
    reloaded = load_context(out)
    for key, value in LEGACY_CONTEXT_JSON.items():
        assert getattr(reloaded, key) == value


def test_unknown_keys_in_saved_json_are_still_dropped(tmp_path):
    path = _write_legacy(tmp_path, hallucinated_key="boom")
    ctx = load_context(path)
    assert not hasattr(ctx, "hallucinated_key")
