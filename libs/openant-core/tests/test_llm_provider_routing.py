"""Tests for the OpenRouter / non-Claude provider routing in llm_client.

Covers issue #9:
    - OPENANT_LLM_BASE_URL / OPENANT_LLM_API_KEY are picked up by every
      Anthropic client construction.
    - --model accepts slash-form IDs verbatim and strips a leading
      "openrouter/" prefix per OpenCode convention.
    - Unknown model IDs default to $0 pricing with a one-time warning.
    - MODEL_PRICING_OVERRIDE merges over the built-in pricing table.
"""
import os

import pytest

from utilities import llm_client
from utilities.llm_client import (
    get_anthropic_client,
    get_pricing,
    resolve_model_id,
    TokenTracker,
)


@pytest.fixture(autouse=True)
def _clear_provider_env(monkeypatch):
    """Strip OpenRouter env vars before each test to keep them isolated."""
    for var in (
        "OPENANT_LLM_BASE_URL",
        "OPENANT_LLM_API_KEY",
        "MODEL_PRICING_OVERRIDE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(llm_client, "_unknown_model_warned", set())
    yield


class TestResolveModelId:
    def test_opus_alias(self):
        assert resolve_model_id("opus") == "claude-opus-4-6"

    def test_sonnet_alias(self):
        assert resolve_model_id("sonnet") == "claude-sonnet-4-20250514"

    def test_explicit_claude_id_passes_through(self):
        assert resolve_model_id("claude-opus-4-6") == "claude-opus-4-6"

    def test_slash_form_passes_through_verbatim(self):
        assert (
            resolve_model_id("qwen/qwen-3-coder-480b") == "qwen/qwen-3-coder-480b"
        )

    def test_openrouter_prefix_stripped(self):
        # OpenCode convention per Didier on issue #9: openrouter/<provider>/<model>
        # collapses to <provider>/<model> for the actual API call.
        assert (
            resolve_model_id("openrouter/moonshotai/kimi-k2")
            == "moonshotai/kimi-k2"
        )

    def test_openrouter_prefix_only_at_start(self):
        # A "/openrouter/..." substring later in the ID is not stripped.
        assert (
            resolve_model_id("acme/openrouter/x") == "acme/openrouter/x"
        )

    def test_empty_string_returns_empty(self):
        assert resolve_model_id("") == ""


class TestGetAnthropicClientEnvWiring:
    def test_no_env_vars_passes_no_overrides(self, monkeypatch):
        captured = {}

        class _Stub:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        monkeypatch.setattr(llm_client.anthropic, "Anthropic", _Stub)
        get_anthropic_client(max_retries=5)

        assert "base_url" not in captured
        assert "api_key" not in captured
        assert captured["max_retries"] == 5

    def test_env_vars_passed_through(self, monkeypatch):
        monkeypatch.setenv(
            "OPENANT_LLM_BASE_URL", "https://openrouter.ai/api/v1"
        )
        monkeypatch.setenv("OPENANT_LLM_API_KEY", "sk-or-v1-test")

        captured = {}

        class _Stub:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        monkeypatch.setattr(llm_client.anthropic, "Anthropic", _Stub)
        get_anthropic_client(max_retries=5)

        assert captured["base_url"] == "https://openrouter.ai/api/v1"
        assert captured["api_key"] == "sk-or-v1-test"
        assert captured["max_retries"] == 5

    def test_explicit_kwargs_win_over_env(self, monkeypatch):
        monkeypatch.setenv(
            "OPENANT_LLM_BASE_URL", "https://openrouter.ai/api/v1"
        )
        monkeypatch.setenv("OPENANT_LLM_API_KEY", "sk-or-v1-env")

        captured = {}

        class _Stub:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        monkeypatch.setattr(llm_client.anthropic, "Anthropic", _Stub)
        get_anthropic_client(api_key="explicit-key", base_url="https://other")

        assert captured["base_url"] == "https://other"
        assert captured["api_key"] == "explicit-key"

    def test_only_base_url_set(self, monkeypatch):
        monkeypatch.setenv(
            "OPENANT_LLM_BASE_URL", "https://openrouter.ai/api/v1"
        )

        captured = {}

        class _Stub:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        monkeypatch.setattr(llm_client.anthropic, "Anthropic", _Stub)
        get_anthropic_client()

        assert captured["base_url"] == "https://openrouter.ai/api/v1"
        assert "api_key" not in captured


class TestGetPricing:
    def test_known_claude_model(self):
        # Sonnet is in the built-in table at $3 input / $15 output per million.
        pricing = get_pricing("claude-sonnet-4-20250514")
        assert pricing == {"input": 3.0, "output": 15.0}

    def test_unknown_model_returns_zero_and_warns_once(self, capsys):
        first = get_pricing("qwen/qwen-3-coder-480b")
        second = get_pricing("qwen/qwen-3-coder-480b")
        assert first == {"input": 0.0, "output": 0.0}
        assert second == {"input": 0.0, "output": 0.0}

        err = capsys.readouterr().err
        # Warning should appear exactly once even though we called twice.
        assert err.count("qwen/qwen-3-coder-480b") == 1

    def test_pricing_override_merges_over_default(self, monkeypatch):
        monkeypatch.setenv(
            "MODEL_PRICING_OVERRIDE",
            '{"qwen/qwen-3-coder-480b": {"input": 0.4, "output": 1.6}}',
        )
        pricing = get_pricing("qwen/qwen-3-coder-480b")
        assert pricing == {"input": 0.4, "output": 1.6}

    def test_pricing_override_can_replace_known_claude_pricing(self, monkeypatch):
        # Power users sometimes want to update Claude pricing without code
        # changes — the override must take precedence over the built-in table.
        monkeypatch.setenv(
            "MODEL_PRICING_OVERRIDE",
            '{"claude-sonnet-4-20250514": {"input": 99.0, "output": 99.0}}',
        )
        pricing = get_pricing("claude-sonnet-4-20250514")
        assert pricing == {"input": 99.0, "output": 99.0}

    def test_invalid_override_json_is_ignored(self, monkeypatch, capsys):
        monkeypatch.setenv("MODEL_PRICING_OVERRIDE", "not json")
        # Falls back to the built-in table without raising.
        pricing = get_pricing("claude-sonnet-4-20250514")
        assert pricing == {"input": 3.0, "output": 15.0}
        assert "MODEL_PRICING_OVERRIDE" in capsys.readouterr().err

    def test_non_object_override_is_ignored(self, monkeypatch, capsys):
        monkeypatch.setenv("MODEL_PRICING_OVERRIDE", "[1, 2, 3]")
        pricing = get_pricing("claude-sonnet-4-20250514")
        assert pricing == {"input": 3.0, "output": 15.0}
        assert "MODEL_PRICING_OVERRIDE" in capsys.readouterr().err


class TestTokenTrackerHonoursOverride:
    def test_override_flows_through_record_call(self, monkeypatch):
        monkeypatch.setenv(
            "MODEL_PRICING_OVERRIDE",
            '{"qwen/qwen-3-coder-480b": {"input": 1.0, "output": 2.0}}',
        )
        tracker = TokenTracker()
        result = tracker.record_call("qwen/qwen-3-coder-480b", 1_000_000, 1_000_000)
        # 1M tokens * $1 input + 1M * $2 output = $3.00
        assert result["cost_usd"] == 3.0
