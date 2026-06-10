"""Tests for ``utilities.llm.config`` — parsing, migration, serialisation."""

from __future__ import annotations

import pytest

from utilities.llm import (
    PHASES,
    ConfigError,
    LLMConfig,
    PhaseRef,
    ProviderConfig,
    parse_config,
    serialise_config,
)


def _all_phases(provider: str, model: str) -> dict[str, dict]:
    """Build a phase mapping that satisfies the 'every phase listed' rule."""
    return {p: {"provider": provider, "model": model} for p in PHASES}


# ---------------------------------------------------------------------------
# Phase coverage rules
# ---------------------------------------------------------------------------


class TestPhaseCoverage:
    def test_config_missing_a_phase_is_rejected(self):
        phases = _all_phases("anthropic", "claude-opus-4-6")
        del phases["verify"]
        with pytest.raises(ConfigError) as exc:
            parse_config(
                {
                    "$schema_version": 2,
                    "llm_providers": {
                        "anthropic": {"type": "anthropic", "api_key": "sk-x"}
                    },
                    "llm_configs": {"foo": phases},
                }
            )
        assert "missing phases" in str(exc.value)
        assert "verify" in str(exc.value)
        # Helpful pointer to the template config so the user knows how to fix it.
        assert "openant-default" in str(exc.value)

    def test_config_with_extra_phase_is_rejected(self):
        phases = _all_phases("anthropic", "claude-opus-4-6")
        phases["bogus_phase"] = {"provider": "anthropic", "model": "claude-opus-4-6"}
        with pytest.raises(ConfigError) as exc:
            parse_config(
                {
                    "$schema_version": 2,
                    "llm_providers": {
                        "anthropic": {"type": "anthropic", "api_key": "sk-x"}
                    },
                    "llm_configs": {"foo": phases},
                }
            )
        assert "unknown phases" in str(exc.value)
        assert "bogus_phase" in str(exc.value)


# ---------------------------------------------------------------------------
# Provider / phase reference validation
# ---------------------------------------------------------------------------


class TestReferenceValidation:
    def test_unknown_provider_reference_rejected(self):
        with pytest.raises(ConfigError) as exc:
            parse_config(
                {
                    "$schema_version": 2,
                    "llm_providers": {
                        "anthropic": {"type": "anthropic", "api_key": "sk-x"}
                    },
                    "llm_configs": {
                        "foo": _all_phases("ghost-provider", "claude-opus-4-6")
                    },
                }
            )
        assert "ghost-provider" in str(exc.value)
        assert "unknown provider" in str(exc.value)

    def test_missing_provider_type_rejected(self):
        with pytest.raises(ConfigError) as exc:
            parse_config(
                {
                    "$schema_version": 2,
                    "llm_providers": {"anthropic": {"api_key": "sk-x"}},
                }
            )
        assert "type" in str(exc.value).lower()

    def test_anthropic_reference_without_provider_entry_is_allowed(self):
        # A hand-authored v2 config may reference the ``anthropic`` provider
        # on its phases while relying on ``ANTHROPIC_API_KEY`` in the env,
        # with NO ``llm_providers`` entry. ``resolve_provider`` synthesises a
        # credential-less ProviderConfig for that case, so parse must NOT die
        # here (it would break the documented v1 -> v2 upgrade path).
        cf = parse_config(
            {
                "$schema_version": 2,
                # No llm_providers at all.
                "llm_configs": {
                    "mine": _all_phases("anthropic", "claude-opus-4-6")
                },
            }
        )
        assert cf.llm_providers == {}
        assert set(cf.llm_configs["mine"].phases) == set(PHASES)
        assert cf.llm_configs["mine"].phases["analyze"].provider == "anthropic"

    def test_unknown_non_anthropic_provider_still_rejected(self):
        # The ``anthropic`` exemption is scoped to that one name. An unknown
        # non-anthropic provider (here ``ghost``) has no env-key fallback and
        # must still fail at parse.
        with pytest.raises(ConfigError) as exc:
            parse_config(
                {
                    "$schema_version": 2,
                    "llm_configs": {
                        "mine": _all_phases("ghost", "claude-opus-4-6")
                    },
                }
            )
        assert "ghost" in str(exc.value)
        assert "unknown provider" in str(exc.value)


# ---------------------------------------------------------------------------
# openant-default is reserved
# ---------------------------------------------------------------------------


class TestOpenantDefaultReserved:
    def test_user_cannot_redefine_openant_default(self):
        with pytest.raises(ConfigError) as exc:
            parse_config(
                {
                    "$schema_version": 2,
                    "llm_providers": {
                        "anthropic": {"type": "anthropic", "api_key": "sk-x"}
                    },
                    "llm_configs": {
                        "openant-default": _all_phases("anthropic", "claude-opus-4-6")
                    },
                }
            )
        msg = str(exc.value)
        assert "openant-default" in msg
        assert "built-in" in msg
        assert "copy" in msg.lower()  # points the user at the fix


# ---------------------------------------------------------------------------
# v1 -> v2 migration
# ---------------------------------------------------------------------------


class TestMigrationV1toV2:
    def test_legacy_api_key_synthesises_anthropic_provider(self):
        cf = parse_config(
            {
                # v1 file: no $schema_version, top-level api_key.
                "api_key": "sk-legacy",
                "default_model": "opus",
                "active_project": "org/repo",
            }
        )
        assert cf.schema_version == 2
        assert "anthropic" in cf.llm_providers
        assert cf.llm_providers["anthropic"].api_key == "sk-legacy"
        assert cf.llm_providers["anthropic"].type == "anthropic"
        # Legacy fields preserved for downgrade window.
        assert cf.legacy_api_key == "sk-legacy"
        assert cf.legacy_default_model == "opus"
        # Default LLM falls through to the built-in.
        assert cf.default_llm == "openant-default"

    def test_legacy_api_key_does_not_clobber_existing_anthropic_provider(self):
        # User has already migrated by hand and customised the entry
        # (e.g. set a base_url). Migration must leave it alone.
        cf = parse_config(
            {
                "api_key": "sk-legacy",
                "$schema_version": 1,  # still v1, force migration path
                "llm_providers": {
                    "anthropic": {
                        "type": "anthropic",
                        "api_key": "sk-new",
                        "base_url": "https://openrouter.ai/api/v1",
                    }
                },
            }
        )
        assert cf.llm_providers["anthropic"].api_key == "sk-new"
        assert cf.llm_providers["anthropic"].base_url == "https://openrouter.ai/api/v1"

    def test_empty_file_yields_empty_config(self):
        cf = parse_config({})
        assert cf.llm_providers == {}
        assert cf.llm_configs == {}
        assert cf.default_llm == "openant-default"


# ---------------------------------------------------------------------------
# Round-trip parse -> serialise -> parse
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_v2_file_round_trips_cleanly(self):
        original = {
            "$schema_version": 2,
            "default_llm": "foo",
            "active_project": "org/repo",
            "llm_providers": {
                "anthropic": {
                    "type": "anthropic",
                    "api_key": "sk-x",
                },
                "openrouter": {
                    "type": "anthropic",
                    "api_key": "sk-or",
                    "base_url": "https://openrouter.ai/api/v1",
                },
            },
            "llm_configs": {
                "foo": _all_phases("anthropic", "claude-opus-4-6"),
            },
        }
        cf = parse_config(original)
        roundtrip = serialise_config(cf)

        # Drop None-valued optional fields that the serialiser omits.
        assert roundtrip["$schema_version"] == 2
        assert roundtrip["default_llm"] == "foo"
        assert roundtrip["active_project"] == "org/repo"
        assert roundtrip["llm_providers"]["anthropic"] == {
            "type": "anthropic",
            "api_key": "sk-x",
        }
        assert roundtrip["llm_providers"]["openrouter"]["base_url"] == "https://openrouter.ai/api/v1"
        assert roundtrip["llm_configs"]["foo"]["analyze"] == {
            "provider": "anthropic",
            "model": "claude-opus-4-6",
        }


# ---------------------------------------------------------------------------
# LLMConfig dataclass validation
# ---------------------------------------------------------------------------


class TestLLMConfigDataclass:
    def test_direct_construction_with_missing_phase_fails(self):
        # Even building the dataclass by hand (e.g. from a Python
        # script) trips the same validation as parsing the JSON.
        with pytest.raises(ConfigError):
            LLMConfig(
                name="hand-built",
                phases={
                    "analyze": PhaseRef(provider="anthropic", model="m"),
                    # other phases missing
                },
            )

    def test_direct_construction_with_all_phases_succeeds(self):
        cfg = LLMConfig(
            name="hand-built",
            phases={p: PhaseRef(provider="anthropic", model="m") for p in PHASES},
        )
        assert cfg.name == "hand-built"
        assert set(cfg.phases) == set(PHASES)
