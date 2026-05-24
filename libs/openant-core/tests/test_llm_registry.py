"""Tests for the registry — phase resolution, eager instantiation, validation."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from utilities.llm import (
    PHASES,
    ConfigError,
    ConfigFile,
    LLMAdapter,
    LLMAuthError,
    LLMConfig,
    LLMNotFoundError,
    PhaseBinding,
    PhaseRef,
    PhaseRegistry,
    ProviderConfig,
    build_phase_registry,
    empty_config,
    get_builtin_default,
    load_config_file,
    parse_config,
    resolve_llm_config,
    resolve_provider,
    with_llm_config,
    with_provider,
)


def _all_phases_ref(provider: str, model: str) -> dict[str, PhaseRef]:
    return {p: PhaseRef(provider=provider, model=model) for p in PHASES}


# ---------------------------------------------------------------------------
# Fake adapter that the registry tests can stand-in for AnthropicAdapter
# ---------------------------------------------------------------------------


class _FakeAdapter:
    name = "anthropic"
    supports_tools = True

    instances: list["_FakeAdapter"] = []  # class-level so tests can inspect construction count

    def __init__(self, *, api_key=None, base_url=None):
        self.api_key = api_key
        self.base_url = base_url
        self.validate_calls: list[str] = []
        self.complete_calls: list[dict] = []
        type(self).instances.append(self)

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.complete_calls.append({"model": model})
        from utilities.llm import CompletionResult, TextBlock
        return CompletionResult(
            content=[TextBlock("ok")],
            input_tokens=1,
            output_tokens=1,
            stop_reason="end_turn",
        )

    def validate(self, model):
        self.validate_calls.append(model)


class _FakeNoToolAdapter(_FakeAdapter):
    supports_tools = False


@pytest.fixture(autouse=True)
def _reset_fake_adapter():
    _FakeAdapter.instances = []
    yield
    _FakeAdapter.instances = []


# ---------------------------------------------------------------------------
# resolve_llm_config
# ---------------------------------------------------------------------------


class TestResolveLLMConfig:
    def test_default_returns_builtin(self):
        cf = empty_config()
        resolved = resolve_llm_config(cf, None)
        assert resolved is get_builtin_default()

    def test_explicit_openant_default_returns_builtin(self):
        cf = empty_config()
        # User explicitly names openant-default; should still get the
        # built-in, not raise.
        resolved = resolve_llm_config(cf, "openant-default")
        assert resolved is get_builtin_default()

    def test_explicit_name_resolves_to_user_config(self):
        my_config = LLMConfig(name="foo", phases=_all_phases_ref("anthropic", "m"))
        cf = with_llm_config(empty_config(), my_config)
        assert resolve_llm_config(cf, "foo") is my_config

    def test_unknown_name_raises_with_available_list(self):
        my_config = LLMConfig(name="foo", phases=_all_phases_ref("anthropic", "m"))
        cf = with_llm_config(empty_config(), my_config)
        with pytest.raises(ConfigError) as exc:
            resolve_llm_config(cf, "nonexistent")
        msg = str(exc.value)
        assert "nonexistent" in msg
        # Both the builtin and user-defined names should be listed.
        assert "openant-default" in msg
        assert "foo" in msg

    def test_falls_back_to_file_default_llm(self):
        my_config = LLMConfig(name="foo", phases=_all_phases_ref("anthropic", "m"))
        cf = ConfigFile(
            default_llm="foo",
            llm_configs={"foo": my_config},
        )
        # No explicit name → cf.default_llm wins.
        assert resolve_llm_config(cf, None) is my_config


# ---------------------------------------------------------------------------
# resolve_provider
# ---------------------------------------------------------------------------


class TestResolveProvider:
    def test_returns_defined_provider(self):
        provider = ProviderConfig(name="anthropic", type="anthropic", api_key="sk")
        cf = with_provider(empty_config(), provider)
        assert resolve_provider(cf, "anthropic") is provider

    def test_anthropic_fallback_when_not_defined(self):
        # Upgrade-from-v1 path: user has ANTHROPIC_API_KEY in env but
        # nothing in config.json. openant-default still resolves
        # because the registry synthesises a credential-less provider.
        cf = empty_config()
        provider = resolve_provider(cf, "anthropic")
        assert provider.type == "anthropic"
        assert provider.api_key is None  # SDK reads env

    def test_unknown_named_provider_raises(self):
        cf = empty_config()
        with pytest.raises(ConfigError):
            resolve_provider(cf, "some-other-name")


# ---------------------------------------------------------------------------
# build_phase_registry
# ---------------------------------------------------------------------------


class TestBuildPhaseRegistry:
    def _build(self, llm_config: LLMConfig, cf: ConfigFile | None = None) -> PhaseRegistry:
        cf = cf or with_provider(
            empty_config(),
            ProviderConfig(name="anthropic", type="anthropic", api_key="sk"),
        )
        with patch(
            "utilities.llm.registry.get_adapter_class",
            return_value=_FakeAdapter,
        ):
            return build_phase_registry(cf, llm_config)

    def test_eager_instantiation_one_per_provider(self):
        # All six phases share the same provider → one adapter,
        # reused across phases. Not six adapters.
        llm_config = LLMConfig(name="foo", phases=_all_phases_ref("anthropic", "m"))
        registry = self._build(llm_config)
        assert len(_FakeAdapter.instances) == 1

    def test_two_providers_yield_two_adapter_instances(self):
        cf = empty_config()
        cf = with_provider(cf, ProviderConfig(name="anthropic", type="anthropic", api_key="sk-a"))
        cf = with_provider(cf, ProviderConfig(name="openrouter", type="anthropic", api_key="sk-or", base_url="https://or.example/v1"))
        phases = {
            "analyze": PhaseRef(provider="anthropic", model="claude-opus-4-6"),
            "enhance": PhaseRef(provider="openrouter", model="qwen/qwen-3-coder-480b"),
            "verify": PhaseRef(provider="anthropic", model="claude-opus-4-6"),
            "report": PhaseRef(provider="openrouter", model="qwen/qwen-3-coder-480b"),
            "dynamic_test": PhaseRef(provider="openrouter", model="qwen/qwen-3-coder-480b"),
            "llm_reach": PhaseRef(provider="anthropic", model="claude-opus-4-6"),
            "app_context": PhaseRef(provider="openrouter", model="qwen/qwen-3-coder-480b"),
        }
        llm_config = LLMConfig(name="foo", phases=phases)
        registry = self._build(llm_config, cf)
        # Two distinct provider entries → two adapter instances.
        assert len(_FakeAdapter.instances) == 2

    def test_get_returns_binding_with_model_and_provider_name(self):
        llm_config = LLMConfig(
            name="foo",
            phases={
                p: PhaseRef(provider="anthropic", model=f"model-{p}")
                for p in PHASES
            },
        )
        registry = self._build(llm_config)
        binding = registry.get("verify")
        assert binding.phase == "verify"
        assert binding.model == "model-verify"
        assert binding.provider_name == "anthropic"

    def test_get_unknown_phase_raises_keyerror(self):
        llm_config = LLMConfig(name="foo", phases=_all_phases_ref("anthropic", "m"))
        registry = self._build(llm_config)
        with pytest.raises(KeyError) as exc:
            registry.get("not_a_phase")
        # Error message must list the canonical phase set so the
        # caller of get() gets immediate feedback on the typo.
        for p in PHASES:
            assert p in str(exc.value)

    def test_unique_probe_targets_dedups(self):
        # Six phases all using the same provider+model → one probe target.
        llm_config = LLMConfig(
            name="foo",
            phases={p: PhaseRef(provider="anthropic", model="m") for p in PHASES},
        )
        registry = self._build(llm_config)
        assert registry.unique_probe_targets() == [("anthropic", "m")]

    def test_unique_probe_targets_keeps_distinct_models(self):
        # Two providers, three models → three probe targets even
        # though only two adapters are built.
        cf = empty_config()
        cf = with_provider(cf, ProviderConfig(name="a1", type="anthropic", api_key="x"))
        cf = with_provider(cf, ProviderConfig(name="a2", type="anthropic", api_key="y"))
        phases = {
            "analyze": PhaseRef(provider="a1", model="alpha"),
            "enhance": PhaseRef(provider="a1", model="alpha"),  # same: dedup
            "verify": PhaseRef(provider="a1", model="beta"),    # same provider, new model
            "report": PhaseRef(provider="a2", model="gamma"),
            "dynamic_test": PhaseRef(provider="a2", model="gamma"),  # dedup
            "llm_reach": PhaseRef(provider="a2", model="gamma"),
            "app_context": PhaseRef(provider="a2", model="gamma"),   # dedup
        }
        registry = self._build(LLMConfig(name="foo", phases=phases), cf)
        assert registry.unique_probe_targets() == [
            ("a1", "alpha"),
            ("a1", "beta"),
            ("a2", "gamma"),
        ]


# ---------------------------------------------------------------------------
# Tool-support gating
# ---------------------------------------------------------------------------


class TestToolSupportGating:
    def test_verify_on_non_tool_adapter_rejected(self):
        # Adapter advertises supports_tools=False; verify must abort
        # at registry-build time, not at first call.
        cf = with_provider(
            empty_config(),
            ProviderConfig(name="local", type="anthropic", api_key="x"),
        )
        llm_config = LLMConfig(name="foo", phases=_all_phases_ref("local", "m"))
        with patch(
            "utilities.llm.registry.get_adapter_class",
            return_value=_FakeNoToolAdapter,
        ):
            with pytest.raises(ConfigError) as exc:
                build_phase_registry(cf, llm_config)
        msg = str(exc.value)
        # Error must name the phase, the offending provider, and
        # what to do about it.
        assert "verify" in msg or "enhance" in msg
        assert "tool" in msg.lower()
        assert "local" in msg


# ---------------------------------------------------------------------------
# validate() routes through adapters
# ---------------------------------------------------------------------------


class TestRegistryValidate:
    def test_validates_each_unique_pair_once(self):
        llm_config = LLMConfig(
            name="foo",
            phases={p: PhaseRef(provider="anthropic", model="m") for p in PHASES},
        )
        cf = with_provider(
            empty_config(),
            ProviderConfig(name="anthropic", type="anthropic", api_key="x"),
        )
        with patch(
            "utilities.llm.registry.get_adapter_class",
            return_value=_FakeAdapter,
        ):
            registry = build_phase_registry(cf, llm_config)
        registry.validate()
        # Six phases share the same provider+model → exactly one
        # validate() call on the shared adapter instance.
        assert len(_FakeAdapter.instances) == 1
        assert _FakeAdapter.instances[0].validate_calls == ["m"]

    def test_propagates_adapter_validate_errors(self):
        # validate() doesn't swallow LLMError subclasses — the
        # caller (openant init) decides how to surface them.
        class _FailingAdapter(_FakeAdapter):
            def validate(self, model):
                raise LLMAuthError("rejected by upstream")

        llm_config = LLMConfig(name="foo", phases=_all_phases_ref("anthropic", "m"))
        cf = with_provider(
            empty_config(),
            ProviderConfig(name="anthropic", type="anthropic", api_key="x"),
        )
        with patch(
            "utilities.llm.registry.get_adapter_class",
            return_value=_FailingAdapter,
        ):
            registry = build_phase_registry(cf, llm_config)
        with pytest.raises(LLMAuthError):
            registry.validate()


# ---------------------------------------------------------------------------
# load_config_file
# ---------------------------------------------------------------------------


class TestLoadConfigFile:
    def test_missing_file_returns_empty_config(self, tmp_path: Path):
        nonexistent = tmp_path / "nope.json"
        cf = load_config_file(nonexistent)
        assert cf.llm_providers == {}
        assert cf.llm_configs == {}
        # Built-in default still resolves through the registry.
        assert resolve_llm_config(cf, None) is get_builtin_default()

    def test_v1_file_migrates_in_memory(self, tmp_path: Path):
        path = tmp_path / "config.json"
        path.write_text(json.dumps({"api_key": "sk-legacy"}), encoding="utf-8")
        cf = load_config_file(path)
        assert cf.schema_version == 2
        assert cf.llm_providers["anthropic"].api_key == "sk-legacy"

    def test_invalid_json_raises_config_error(self, tmp_path: Path):
        path = tmp_path / "config.json"
        path.write_text("not json {{", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config_file(path)
