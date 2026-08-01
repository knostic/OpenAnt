"""OpenRouter-adapter-specific tests.

The shared contract harness (``test_llm_adapter_contract.py``) covers
behaviors every adapter must satisfy, and the request/response
translation layer is the OpenAI adapter's (reused, covered by
``test_llm_openai_adapter.py``). This file covers the bits that are
specific to OpenRouter:

* constructor plumbing — default base_url, override, attribution
  headers, ``OPENROUTER_API_KEY`` env fallback, fail-loud when no key
  can be resolved (never falling through to the SDK's OPENAI_API_KEY)
* vendor/model slugs passed through verbatim; ``openai/o3``-style
  slugs still get ``max_completion_tokens``
* 400 "not a valid model ID" mapped to LLMNotFoundError (live-verified
  OpenRouter behavior — it is NOT a 404)
* 402 insufficient-credits mapped to LLMAuthError with a top-up hint
* 403 moderation-flag mapped to LLMRefusalError; plain 403 stays auth
* mid-generation provider failure (finish_reason == "error") raised as
  LLMResponseError instead of warn-and-normalise
* 429 reports to the global rate limiter; other statuses don't

These tests stub the SDK boundary so nothing hits the network.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import openai
import pytest

from utilities.llm import (
    LLMAuthError,
    LLMNotFoundError,
    LLMRateLimitError,
    LLMRefusalError,
    LLMResponseError,
    Message,
    TextBlock,
)
from utilities.llm.providers.openrouter import OpenRouterAdapter
from utilities.rate_limiter import get_rate_limiter, reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_state():
    reset_rate_limiter()
    yield
    reset_rate_limiter()


def _ok_response(*, text="hi", finish_reason="stop"):
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content=text, tool_calls=None),
            finish_reason=finish_reason,
        )],
        usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
    )


def _stub_adapter(side_effect):
    client = MagicMock(spec=openai.OpenAI)
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=side_effect)
    return OpenRouterAdapter(_client=client), client


def _fake_http_resp(status, *, retry_after=None):
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status,
        headers=headers,
        request=httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions"),
    )


def _complete(adapter, model="anthropic/claude-sonnet-4.6"):
    return adapter.complete(
        model=model,
        system=None,
        messages=[Message(role="user", content=[TextBlock("hi")])],
        max_tokens=8,
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
            "utilities.llm.providers.openrouter.openai.OpenAI", FakeOpenAI
        )
        return captured

    def test_defaults_to_openrouter_base_url(self, monkeypatch):
        captured = self._patched(monkeypatch)
        OpenRouterAdapter(api_key="sk-or-v1-test")
        assert captured["base_url"] == "https://openrouter.ai/api/v1"
        assert captured["api_key"] == "sk-or-v1-test"
        assert captured["max_retries"] == 5

    def test_base_url_override_wins(self, monkeypatch):
        captured = self._patched(monkeypatch)
        OpenRouterAdapter(api_key="sk-or-v1-test", base_url="https://gateway.internal/v1")
        assert captured["base_url"] == "https://gateway.internal/v1"

    def test_attribution_headers_sent(self, monkeypatch):
        captured = self._patched(monkeypatch)
        OpenRouterAdapter(api_key="sk-or-v1-test")
        headers = captured["default_headers"]
        assert headers["HTTP-Referer"] == "https://github.com/knostic/OpenAnt"
        assert headers["X-Title"] == "OpenAnt"

    def test_env_fallback_is_openrouter_api_key(self, monkeypatch):
        captured = self._patched(monkeypatch)
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-from-env")
        # OPENAI_API_KEY must be irrelevant even when present.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-wrong-provider")
        OpenRouterAdapter()
        assert captured["api_key"] == "sk-or-v1-from-env"

    def test_no_key_anywhere_fails_loud(self, monkeypatch):
        """Without an explicit key or OPENROUTER_API_KEY the constructor
        must raise a typed error — NOT construct an SDK client that
        would fall back to OPENAI_API_KEY and quietly send an OpenAI
        key to a third party."""
        self._patched(monkeypatch)
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-should-never-be-used")
        with pytest.raises(LLMAuthError) as exc_info:
            OpenRouterAdapter()
        assert "OPENROUTER_API_KEY" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Model slugs
# ---------------------------------------------------------------------------


class TestModelSlugs:
    def test_slug_passed_verbatim(self):
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        _complete(adapter, model="google/gemini-2.5-flash")
        kwargs = client.chat.completions.create.call_args.kwargs
        assert kwargs["model"] == "google/gemini-2.5-flash"
        assert kwargs["max_tokens"] == 8

    def test_reasoning_slug_gets_max_completion_tokens(self):
        """``_token_param`` strips the vendor prefix, so reasoning
        models routed through OpenRouter must not 400 on max_tokens."""
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        _complete(adapter, model="openai/o3-mini")
        kwargs = client.chat.completions.create.call_args.kwargs
        assert kwargs["max_completion_tokens"] == 8
        assert "max_tokens" not in kwargs

    def test_validate_probes_the_passed_slug(self):
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        adapter.validate(model="anthropic/claude-haiku-4.5")
        kwargs = client.chat.completions.create.call_args.kwargs
        assert kwargs["model"] == "anthropic/claude-haiku-4.5"
        assert kwargs["max_tokens"] == 1


# ---------------------------------------------------------------------------
# OpenRouter-specific error mapping
# ---------------------------------------------------------------------------


class TestErrorMapping:
    def test_invalid_model_400_maps_to_not_found(self):
        """OpenRouter reports an unknown model as 400 'not a valid
        model ID' (live-verified), not 404 — it must still fail like a
        typo'd model so the registry's validate() catches it at init."""

        def respond(**kw):
            raise openai.BadRequestError(
                message=(
                    "Error code: 400 - {'error': {'message': "
                    "'anthropic/claude-no-such-model is not a valid model ID', "
                    "'code': 400}}"
                ),
                response=_fake_http_resp(400),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMNotFoundError) as exc_info:
            _complete(adapter, model="anthropic/claude-no-such-model")
        assert "openrouter.ai/models" in str(exc_info.value)

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMNotFoundError):
            adapter.validate(model="anthropic/claude-no-such-model")

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

    def test_402_maps_to_auth_error_with_credits_hint(self):
        def respond(**kw):
            raise openai.APIStatusError(
                message="Insufficient credits",
                response=_fake_http_resp(402),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMAuthError) as exc_info:
            _complete(adapter)
        assert "credits" in str(exc_info.value)

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMAuthError):
            adapter.validate(model="anthropic/claude-haiku-4.5")

    def test_403_moderation_maps_to_refusal(self):
        """OpenRouter reserves 403 for input moderation; a moderated
        scan prompt must surface as a refusal, not an auth failure."""

        def respond(**kw):
            raise openai.PermissionDeniedError(
                message="Your input was flagged by moderation",
                response=_fake_http_resp(403),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMRefusalError):
            _complete(adapter)

    def test_403_without_moderation_wording_stays_auth(self):
        def respond(**kw):
            raise openai.PermissionDeniedError(
                message="Key disabled by organization policy",
                response=_fake_http_resp(403),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMAuthError):
            _complete(adapter)

    def test_finish_reason_error_raises_response_error(self):
        """A provider failing mid-generation comes back as HTTP 200
        with finish_reason == 'error'; it must raise, never normalise
        to a clean-looking end_turn."""
        adapter, _ = _stub_adapter(
            lambda **kw: _ok_response(text="partial…", finish_reason="error")
        )
        with pytest.raises(LLMResponseError) as exc_info:
            _complete(adapter)
        assert "mid-generation" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Rate-limiter coordination
# ---------------------------------------------------------------------------


class TestRateLimiterCoordination:
    def test_429_reports_to_global_limiter(self):
        def respond(**kw):
            raise openai.RateLimitError(
                message="rate limited",
                response=_fake_http_resp(429, retry_after="3"),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMRateLimitError) as exc_info:
            _complete(adapter)
        assert exc_info.value.retry_after == 3
        assert get_rate_limiter().is_in_backoff()

    def test_validate_429_does_not_back_off_the_fleet(self):
        def respond(**kw):
            raise openai.RateLimitError(
                message="rate limited",
                response=_fake_http_resp(429, retry_after="3"),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMRateLimitError):
            adapter.validate(model="anthropic/claude-haiku-4.5")
        assert not get_rate_limiter().is_in_backoff()

    def test_other_api_status_errors_do_not_trigger_backoff(self):
        def respond(**kw):
            raise openai.APIStatusError(
                message="bad gateway (provider down)",
                response=_fake_http_resp(502),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMResponseError):
            _complete(adapter)
        assert not get_rate_limiter().is_in_backoff()
