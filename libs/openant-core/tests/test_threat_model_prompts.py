"""Prompt construction branches on a custom threat model.

The headline change is the ATTACKER PERSONA. Without a threat model, OpenAnt
hardcodes "You are an attacker on the internet. You have a browser and nothing
else" — which cannot express, say, a developer with commit access to a watched
manifest repo but no shell on the host. A threat model declares its own
attacker profiles, and verification must adopt each in turn.

Every legacy assertion here is deliberate: the no-threat-model path must be
BYTE-IDENTICAL, because `test_threat_model_untrusted_input_gate.py` pins its
wording and because changing it would silently move every existing user's
verdicts.
"""

import pytest

from context.application_context import ApplicationContext
from prompts.vulnerability_analysis import (
    format_app_context_for_prompt,
    get_analysis_prompt,
    get_system_prompt,
)
from prompts.verification_prompts import (
    format_app_context_for_verification,
    get_verification_prompt,
    get_verification_system_prompt,
)

CODE = "def handler(req):\n    return req.args['x']\n"


def legacy_context() -> ApplicationContext:
    return ApplicationContext(
        application_type="cli_tool",
        purpose="A command line tool.",
        intended_behaviors=["Reads files the operator names"],
        trust_boundaries={"cli args": "trusted"},
        not_a_vulnerability=["Path traversal via CLI flags"],
        requires_remote_trigger=False,
    )


def threat_model_context() -> ApplicationContext:
    return ApplicationContext(
        application_type="custom:deployment-orchestrator",
        purpose="Applies git-sourced manifests to hosts over SSH.",
        threat_model_version=1,
        classification="deployment orchestrator",
        components=[
            {"name": "manifest_parser", "paths": ["pkg/manifest/"],
             "component_type": "semi-trusted data parser", "exposure": "internal"},
        ],
        attacker_profiles=[
            {"id": "manifest_author", "position": "adjacent",
             "description": "Developer with commit access to a watched manifest repo, no shell on the orchestrator.",
             "capabilities": ["craft arbitrary manifest YAML"],
             "cannot": ["run commands on the orchestrator", "modify operator config"],
             "entry_via": ["deployment_manifests"],
             "impact": "Escalation from repo-commit to orchestrator RCE."},
            {"id": "remote_unauth", "position": "remote",
             "description": "Anonymous internet user hitting the dashboard.",
             "capabilities": ["send arbitrary HTTP requests"],
             "cannot": ["run CLI commands"],
             "entry_via": ["dashboard_http"],
             "impact": "State tampering."},
        ],
        input_sources={
            "deployment_manifests": {"trust": "semi_trusted", "description": "YAML from git"},
            "dashboard_http": {"trust": "untrusted", "description": "HTTP requests"},
            "operator_config": {"trust": "trusted", "description": "Operator files"},
        },
        vulnerability_criteria=[
            "Manifest content escaping template sandboxing into command execution",
        ],
        impact_statement="Deploy-pipeline RCE across managed hosts.",
        not_a_vulnerability=[f"item {i}" for i in range(8)],   # >5: truncation check
        requires_remote_trigger=True,
    )


class TestLegacyPathUnchanged:
    """Byte-identity guards. These must never need updating."""

    def test_context_block_is_byte_identical(self):
        ctx = legacy_context()
        assert not ctx.has_threat_model()
        out = format_app_context_for_prompt(ctx)
        assert "**Application Type:** cli_tool" in out
        assert "have local access" in out, "legacy suppression sentinel changed"

    def test_verification_block_is_byte_identical(self):
        out = format_app_context_for_verification(legacy_context())
        assert "local filesystem access" in out, "legacy sentinel changed"

    def test_hardcoded_persona_still_used_without_a_threat_model(self):
        out = get_verification_prompt(CODE, "vulnerable", "av", "r",
                                      app_context=legacy_context())
        assert "browser and nothing else" in out

    def test_system_prompts_unchanged(self):
        assert "REMOTE attackers" in get_system_prompt(legacy_context())
        assert get_verification_system_prompt(legacy_context())


class TestAttackerPersonaComesFromTheThreatModel:
    """The headline: declared profiles replace the hardcoded browser attacker."""

    def test_hardcoded_browser_persona_is_gone(self):
        out = get_verification_prompt(CODE, "vulnerable", "av", "r",
                                      app_context=threat_model_context())
        assert "browser and nothing else" not in out, (
            "the hardcoded persona survived — a threat model's attacker "
            "profiles must replace it, not sit alongside it"
        )

    def test_every_profile_appears(self):
        out = get_verification_prompt(CODE, "vulnerable", "av", "r",
                                      app_context=threat_model_context())
        assert "manifest_author" in out
        assert "remote_unauth" in out

    def test_capabilities_and_limits_are_stated(self):
        out = get_verification_prompt(CODE, "vulnerable", "av", "r",
                                      app_context=threat_model_context())
        assert "craft arbitrary manifest YAML" in out
        assert "run commands on the orchestrator" in out, "the CANNOT list is load-bearing"

    def test_non_remote_attacker_is_expressible(self):
        """The whole point: an 'adjacent' attacker the old binary could not express."""
        out = get_verification_prompt(CODE, "vulnerable", "av", "r",
                                      app_context=threat_model_context())
        assert "adjacent" in out.lower()

    def test_the_trailing_cli_tool_line_is_dropped(self):
        """`If this is a CLI tool/library...` contradicts a custom threat model."""
        out = get_verification_prompt(CODE, "vulnerable", "av", "r",
                                      app_context=threat_model_context())
        assert "If this is a CLI tool/library" not in out


class TestThreatModelContextBlock:
    def test_vulnerability_criteria_are_rendered(self):
        out = format_app_context_for_prompt(threat_model_context())
        assert "escaping template sandboxing" in out

    def test_input_sources_grouped_by_trust(self):
        out = format_app_context_for_prompt(threat_model_context())
        for level in ("untrusted", "semi_trusted", "trusted"):
            assert level in out.lower()

    def test_components_and_free_form_types_appear(self):
        out = format_app_context_for_prompt(threat_model_context())
        assert "manifest_parser" in out
        assert "semi-trusted data parser" in out, "free-form component type lost"

    def test_impact_statement_reaches_verification(self):
        out = format_app_context_for_verification(threat_model_context())
        assert "Deploy-pipeline RCE" in out

    def test_not_a_vulnerability_is_not_truncated_at_five(self):
        """Legacy truncates to 5; a custom model's list is authoritative."""
        out = format_app_context_for_verification(threat_model_context())
        for i in range(8):
            assert f"item {i}" in out, f"item {i} truncated away"

    def test_legacy_suppression_block_is_not_emitted(self):
        """Attacker profiles subsume the local/remote binary."""
        out = format_app_context_for_prompt(threat_model_context())
        assert "have local access" not in out


class TestSystemPrompts:
    def test_analysis_system_prompt_defers_to_the_profiles(self):
        out = get_system_prompt(threat_model_context())
        assert "REMOTE attackers" not in out, (
            "the hardcoded 'only remote attackers' rule contradicts a custom "
            "threat model that may declare a local or adjacent attacker"
        )

    def test_verification_system_prompt_mentions_the_threat_model(self):
        out = get_verification_system_prompt(threat_model_context())
        assert "threat model" in out.lower()


class TestNoContextAtAll:
    def test_prompts_still_build_with_no_app_context(self):
        assert get_analysis_prompt(CODE, language="python")
        assert get_verification_prompt(CODE, "vulnerable", "av", "r")
        assert get_system_prompt(None)
        assert get_verification_system_prompt(None)


class TestAnalysisQuestionUsesDeclaredInputSources:
    """The Stage-1 question must reference the threat model's own sources.

    This path had no test, which is how a mis-placed patch (system-prompt text
    landing in the question block) passed the suite and was caught only by a
    linter's undefined-name check.
    """

    def test_question_references_declared_trust_levels(self):
        out = get_analysis_prompt(CODE, language="python",
                                  app_context=threat_model_context())
        assert "declared input source" in out.lower()
        assert "trust level" in out.lower()

    def test_legacy_question_still_used_without_a_threat_model(self):
        out = get_analysis_prompt(CODE, language="python",
                                  app_context=legacy_context())
        assert "they have local access" in out.lower()

    def test_system_prompt_and_question_are_not_swapped(self):
        """Guards the exact mix-up: system-prompt text inside the question."""
        out = get_analysis_prompt(CODE, language="python",
                                  app_context=threat_model_context())
        assert "IMPORTANT: This repository supplies its own threat model" not in out, (
            "system-prompt text leaked into the user prompt's question block"
        )
