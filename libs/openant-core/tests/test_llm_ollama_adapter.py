"""Ollama-adapter-specific tests.

The shared contract harness (``test_llm_adapter_contract.py``) covers
behaviors every adapter must satisfy, and the request/response
translation layer is the OpenAI adapter's (reused, covered by
``test_llm_openai_adapter.py``). This file covers the bits that are
specific to Ollama:

* constructor plumbing — default localhost base_url, override,
  placeholder API key (never a real credential, never an env fallback)
* unpulled-model 404 mapped to LLMNotFoundError with an
  ``ollama pull`` hint (live-verified Ollama body)
* server-down connection error mapped to LLMConnectionError with an
  ``ollama serve`` hint
* empty completions (tool-incapable models) raised as LLMResponseError
  via the shared translator's guard — fail loud, never a clean pass
* 429 reports to the global rate limiter

These tests stub the SDK boundary so nothing hits the network.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import openai
import pytest

from utilities.llm import (
    LLMConnectionError,
    LLMNotFoundError,
    LLMRateLimitError,
    LLMResponseError,
    Message,
    TextBlock,
    ToolDef,
)
from utilities.llm.providers.ollama import OllamaAdapter
from utilities.rate_limiter import get_rate_limiter, reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_state():
    reset_rate_limiter()
    yield
    reset_rate_limiter()


def _ok_response(*, text="hi", finish_reason="stop", tool_calls=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content=text, tool_calls=tool_calls),
            finish_reason=finish_reason,
        )],
        usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
    )


def _stub_adapter(side_effect):
    client = MagicMock(spec=openai.OpenAI)
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=side_effect)
    return OllamaAdapter(_client=client), client


def _fake_http_resp(status):
    return httpx.Response(
        status_code=status,
        headers={},
        request=httpx.Request("POST", "http://localhost:11434/v1/chat/completions"),
    )


def _complete(adapter, model="qwen3:14b", tools=None):
    return adapter.complete(
        model=model,
        system=None,
        messages=[Message(role="user", content=[TextBlock("hi")])],
        max_tokens=8,
        tools=tools,
    )


# ---------------------------------------------------------------------------
# Constructor plumbing
# ---------------------------------------------------------------------------


class TestConstructor:
    def _patched(self, monkeypatch):
        captured = {}

        class FakeOpenAI:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.chat = MagicMock()

        monkeypatch.setattr(
            "utilities.llm.providers.ollama.openai.OpenAI", FakeOpenAI
        )
        return captured

    def test_defaults_to_localhost_base_url(self, monkeypatch):
        captured = self._patched(monkeypatch)
        OllamaAdapter()
        assert captured["base_url"] == "http://localhost:11434/v1"

    def test_base_url_override_wins(self, monkeypatch):
        captured = self._patched(monkeypatch)
        OllamaAdapter(base_url="http://192.168.1.50:11434/v1")
        assert captured["base_url"] == "http://192.168.1.50:11434/v1"

    def test_placeholder_key_when_none_given(self, monkeypatch):
        """No key → placeholder bearer, NOT the SDK's OPENAI_API_KEY env
        default and not a crash."""
        captured = self._patched(monkeypatch)
        OllamaAdapter()
        assert captured["api_key"]  # non-empty (SDK requirement)

    def test_no_env_fallback_for_keys(self, monkeypatch):
        """A foreign provider key in the env must NEVER be picked up for
        Ollama — no silent cross-provider credential reuse."""
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-leak")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-leak")
        captured = self._patched(monkeypatch)
        OllamaAdapter()
        assert captured["api_key"] != "sk-or-leak"
        assert captured["api_key"] != "sk-openai-leak"


# ---------------------------------------------------------------------------
# Error mapping deltas
# ---------------------------------------------------------------------------


class TestErrors:
    def test_unpulled_model_404_maps_to_not_found_with_pull_hint(self):
        """Ollama returns 404 'model ... not found, try pulling it first'
        for an unpulled model (live-verified body). It must surface as
        LLMNotFoundError with the `ollama pull` fix in the message."""

        def respond(**kw):
            raise openai.NotFoundError(
                message=(
                    "Error code: 404 - {'error': {'message': "
                    "\"model 'ghost-model' not found, try pulling it first\", "
                    "'code': 404}}"
                ),
                response=_fake_http_resp(404),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMNotFoundError) as exc_info:
            _complete(adapter, model="ghost-model")
        assert "ollama pull" in str(exc_info.value)

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMNotFoundError):
            adapter.validate(model="ghost-model")

    def test_connection_error_gets_serve_hint(self):
        import httpx as _httpx

        def respond(**kw):
            raise openai.APIConnectionError(
                request=_httpx.Request(
                    "POST", "http://localhost:11434/v1/chat/completions"
                )
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMConnectionError) as exc_info:
            _complete(adapter)
        assert "ollama serve" in str(exc_info.value)

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMConnectionError):
            adapter.validate(model="qwen3:14b")

    def test_other_400_is_a_response_error(self):
        def respond(**kw):
            raise openai.BadRequestError(
                message="max_tokens must be positive",
                response=_fake_http_resp(400),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMResponseError):
            _complete(adapter)


# ---------------------------------------------------------------------------
# Empty-completion handling (shared translator guard)
# ---------------------------------------------------------------------------


class TestEmptyCompletionGuard:
    TOOLS = [
        ToolDef(
            name="echo",
            description="Echo input",
            input_schema={"type": "object"},
        )
    ]

    def test_empty_completion_with_tools_raises(self):
        """A tool-incapable model that silently ignores `tools` and returns
        an empty completion must fail loud — via the shared translator's
        empty-completion guard (same path as every OpenAI-wire adapter).
        """
        def respond(**kw):
            return SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content="", tool_calls=None),
                        finish_reason="stop",
                    )
                ],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=0),
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMResponseError) as exc_info:
            _complete(adapter, tools=self.TOOLS)
        assert "empty completion" in str(exc_info.value)

    def test_text_completion_with_tools_still_fine(self):
        """A text-only answer to a tools request is allowed — the
        pipeline handles plain refusals; only EMPTY completions guard."""

        def respond(**kw):
            return _ok_response(text="I cannot use tools.")

        adapter, _ = _stub_adapter(respond)
        result = _complete(adapter, tools=self.TOOLS)
        assert result.content[0].text == "I cannot use tools."

    def test_empty_choices_raise(self):
        def respond(**kw):
            return SimpleNamespace(
                choices=[],
                usage=SimpleNamespace(prompt_tokens=1, completion_tokens=0),
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMResponseError):
            _complete(adapter, tools=self.TOOLS)


# ---------------------------------------------------------------------------
# validate() probe
# ---------------------------------------------------------------------------


class TestValidate:
    def test_validate_probes_one_token(self):
        client = MagicMock(spec=openai.OpenAI)
        client.chat = MagicMock()
        client.chat.completions = MagicMock()
        client.chat.completions.create = MagicMock(return_value=_ok_response())

        adapter = OllamaAdapter(_client=client)
        assert adapter.validate(model="qwen3:14b") is None

        kwargs = client.chat.completions.create.call_args.kwargs
        assert kwargs["model"] == "qwen3:14b"
        assert kwargs["max_tokens"] == 1


# ---------------------------------------------------------------------------
# Rate limiter interaction
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_429_reports_to_global_limiter(self):
        def respond(**kw):
            raise openai.RateLimitError(
                message="too many requests",
                response=_fake_http_resp(429),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMRateLimitError):
            _complete(adapter)
        # The process-global limiter heard about the 429.
        assert get_rate_limiter().is_in_backoff()

    def test_validate_429_does_not_back_off_the_fleet(self):
        def respond(**kw):
            raise openai.RateLimitError(
                message="too many requests",
                response=_fake_http_resp(429),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMRateLimitError):
            adapter.validate(model="qwen3:14b")
        assert not get_rate_limiter().is_in_backoff()
