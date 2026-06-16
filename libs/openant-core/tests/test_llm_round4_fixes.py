"""Round-4 review fixes for the LLM provider adapters (PR #69).

This file holds the regression tests for the five round-4 findings.
Each finding has a RED test written first (per the project's TDD rule),
then the adapter / helper code is changed to make it pass.

Findings covered:

* R4-1 (HIGH) — Anthropic ``_response_to_unified`` raises
  :class:`LLMResponseError` on an empty/refusal completion instead of
  returning an empty ``end_turn`` (which a security tool would read as
  a clean pass). A tool-use-only response stays valid.
* R4-2 (MED) — A populated refusal / content-filter finish reason
  raises the new :class:`LLMRefusalError` (a subclass of
  :class:`LLMResponseError`) across all three adapters.
* R4-3 (MED) — The Google adapter forwards ``max_retries`` into the SDK
  via ``HttpOptions(retry_options=HttpRetryOptions(attempts=...))``.
* R4-5 (LOW) — Anthropic tolerates a usage-less response (token counts
  fall back to 0 instead of raising ``AttributeError``).
* R4-6 (LOW) — Provider error strings are run through
  :func:`redact_secrets` before being wrapped in an ``LLM*Error`` so a
  leaked key in a 400/401 body doesn't reach logs/reports.

Everything here stubs the SDK boundary; nothing hits the network.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import anthropic
import httpx
import openai
import pytest
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from utilities.llm import (
    LLMResponseError,
    Message,
    TextBlock,
    ToolDef,
)
from utilities.llm.providers.anthropic import AnthropicAdapter
from utilities.llm.providers.google import GoogleAdapter
from utilities.llm.providers.openai import OpenAIAdapter
from utilities.llm_client import reset_warning_state
from utilities.rate_limiter import reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_state():
    # A leaked backoff would make later tests sleep; reset around each test.
    reset_rate_limiter()
    reset_warning_state()
    yield
    reset_rate_limiter()
    reset_warning_state()


def _hi():
    return [Message(role="user", content=[TextBlock("hi")])]


# ---------------------------------------------------------------------------
# Anthropic stubs
# ---------------------------------------------------------------------------


def _anthropic_stub(side_effect):
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages = MagicMock()
    client.messages.create = MagicMock(side_effect=side_effect)
    return AnthropicAdapter(_client=client), client


def _anthropic_response(*, content, stop_reason="end_turn", with_usage=True):
    ns = SimpleNamespace(content=content, stop_reason=stop_reason)
    if with_usage:
        ns.usage = SimpleNamespace(input_tokens=1, output_tokens=1)
    return ns


def _a_text_block(text):
    return SimpleNamespace(type="text", text=text)


def _a_tool_use_block(*, id, name, input):
    return SimpleNamespace(type="tool_use", id=id, name=name, input=input)


def _a_fake_http(status, *, retry_after=None):
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status,
        headers=headers,
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
    )


# ---------------------------------------------------------------------------
# OpenAI stubs
# ---------------------------------------------------------------------------


def _openai_stub(side_effect):
    client = MagicMock(spec=openai.OpenAI)
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=side_effect)
    return OpenAIAdapter(_client=client), client


def _openai_response(*, content, finish_reason, tool_calls=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content=content, tool_calls=tool_calls),
            finish_reason=finish_reason,
        )],
        usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
    )


def _openai_fake_http(status, *, retry_after=None):
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status,
        headers=headers,
        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"),
    )


# ---------------------------------------------------------------------------
# Google stubs
# ---------------------------------------------------------------------------


def _google_stub(side_effect):
    client = MagicMock(spec=genai.Client)
    client.models = MagicMock()
    client.models.generate_content = MagicMock(side_effect=side_effect)
    return GoogleAdapter(_client=client), client


def _google_response(*, parts, finish_reason="STOP"):
    return SimpleNamespace(
        candidates=[SimpleNamespace(
            content=SimpleNamespace(parts=parts),
            finish_reason=finish_reason,
        )],
        usage_metadata=SimpleNamespace(
            prompt_token_count=1, candidates_token_count=1
        ),
    )


def _g_text_part(text):
    return SimpleNamespace(text=text, function_call=None)


def _g_client_error(code, message):
    response_json = {"error": {"code": code, "message": message, "status": ""}}
    resp = httpx.Response(
        status_code=code,
        request=httpx.Request(
            "POST",
            "https://generativelanguage.googleapis.com/v1beta/models/x:generateContent",
        ),
    )
    return genai_errors.ClientError(code, response_json, resp)


# ===========================================================================
# R4-1 — Anthropic empty-content guard
# ===========================================================================


class TestR41AnthropicEmptyContent:
    def test_empty_content_list_raises_response_error(self):
        """``response.content == []`` is a refusal/empty completion. The
        adapter must raise instead of returning an empty end_turn that a
        security tool would read as a clean pass (mirrors OpenAI empty
        ``choices`` / Gemini empty ``candidates``)."""
        adapter, _ = _anthropic_stub(
            lambda **kw: _anthropic_response(content=[], stop_reason="end_turn")
        )
        with pytest.raises(LLMResponseError):
            adapter.complete(model="claude-test", system=None, messages=_hi(), max_tokens=8)

    def test_only_unknown_blocks_dropped_to_empty_raises(self):
        """A response whose only blocks are unknown/dropped kinds collapses
        to an empty content list → must raise (not silently succeed)."""
        adapter, _ = _anthropic_stub(
            lambda **kw: _anthropic_response(
                content=[SimpleNamespace(type="thinking", text="...")],
                stop_reason="end_turn",
            )
        )
        with pytest.raises(LLMResponseError):
            adapter.complete(model="claude-test", system=None, messages=_hi(), max_tokens=8)

    def test_tool_use_only_response_is_valid(self):
        """CRITICAL: a tool-use-only response (no text) is a VALID
        completion and must NOT raise."""
        adapter, _ = _anthropic_stub(
            lambda **kw: _anthropic_response(
                content=[_a_tool_use_block(id="toolu_1", name="echo", input={"x": 1})],
                stop_reason="tool_use",
            )
        )
        result = adapter.complete(
            model="claude-test", system=None, messages=_hi(), max_tokens=8,
            tools=[ToolDef(name="echo", description="x", input_schema={"type": "object"})],
        )
        assert result.stop_reason == "tool_use"
        assert len(result.content) == 1

    def test_text_response_still_works(self):
        adapter, _ = _anthropic_stub(
            lambda **kw: _anthropic_response(content=[_a_text_block("hello")])
        )
        result = adapter.complete(model="claude-test", system=None, messages=_hi(), max_tokens=8)
        assert result.content[0].text == "hello"


# ===========================================================================
# R4-2 — typed refusal error (LLMRefusalError)
# ===========================================================================


class TestR42RefusalError:
    def test_llm_refusal_error_subclasses_response_error(self):
        from utilities.llm import LLMRefusalError
        assert issubclass(LLMRefusalError, LLMResponseError)

    def test_anthropic_refusal_stop_reason_raises_refusal(self):
        """Anthropic ``stop_reason == "refusal"`` → LLMRefusalError, even
        with populated text content (the refusal signal wins)."""
        from utilities.llm import LLMRefusalError
        adapter, _ = _anthropic_stub(
            lambda **kw: _anthropic_response(
                content=[_a_text_block("I can't help with that.")],
                stop_reason="refusal",
            )
        )
        with pytest.raises(LLMRefusalError):
            adapter.complete(model="claude-test", system=None, messages=_hi(), max_tokens=8)

    def test_openai_content_filter_raises_refusal(self):
        from utilities.llm import LLMRefusalError
        adapter, _ = _openai_stub(
            lambda **kw: _openai_response(content="filtered", finish_reason="content_filter")
        )
        with pytest.raises(LLMRefusalError):
            adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8)

    @pytest.mark.parametrize(
        "finish_reason",
        ["SAFETY", "RECITATION", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII"],
    )
    def test_google_safety_finish_raises_refusal(self, finish_reason):
        from utilities.llm import LLMRefusalError
        adapter, _ = _google_stub(
            lambda **kw: _google_response(
                parts=[_g_text_part("partial")], finish_reason=finish_reason
            )
        )
        with pytest.raises(LLMRefusalError):
            adapter.complete(model="gemini-2.5-pro", system=None, messages=_hi(), max_tokens=8)

    def test_refusal_is_caught_by_response_error_handler(self):
        """Existing ``except LLMResponseError`` handlers must still catch
        a refusal (subclass relationship)."""
        adapter, _ = _openai_stub(
            lambda **kw: _openai_response(content="x", finish_reason="content_filter")
        )
        with pytest.raises(LLMResponseError):
            adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8)


# ===========================================================================
# R4-3 — Google max_retries forwarded to the SDK
# ===========================================================================


class TestR43GoogleMaxRetries:
    def test_max_retries_forwarded_as_retry_options(self, monkeypatch):
        captured = {}

        class FakeClient:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.models = MagicMock()

        monkeypatch.setattr(
            "utilities.llm.providers.google.genai.Client", FakeClient
        )
        GoogleAdapter(api_key="k", max_retries=9)
        http_options = captured.get("http_options")
        assert http_options is not None, "max_retries must produce an HttpOptions"
        retry = getattr(http_options, "retry_options", None)
        assert retry is not None, "HttpOptions must carry retry_options"
        # F3 (round-5): SDK ``attempts`` includes the original request, so
        # ``max_retries`` (retries beyond the first) maps to ``+ 1``.
        assert getattr(retry, "attempts", None) == 10

    def test_max_retries_set_even_with_base_url(self, monkeypatch):
        captured = {}

        class FakeClient:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.models = MagicMock()

        monkeypatch.setattr(
            "utilities.llm.providers.google.genai.Client", FakeClient
        )
        GoogleAdapter(api_key="k", base_url="https://proxy.example/v1", max_retries=4)
        http_options = captured["http_options"]
        assert http_options.base_url == "https://proxy.example/v1"
        # F3 (round-5): off-by-one corrected — attempts = max_retries + 1.
        assert http_options.retry_options.attempts == 5


# ===========================================================================
# R4-5 — Anthropic usage-less response tolerated
# ===========================================================================


class TestR45AnthropicUsageGuard:
    def test_missing_usage_attribute_returns_zero_tokens(self):
        adapter, _ = _anthropic_stub(
            lambda **kw: _anthropic_response(
                content=[_a_text_block("hi")], with_usage=False
            )
        )
        result = adapter.complete(model="claude-test", system=None, messages=_hi(), max_tokens=8)
        assert result.input_tokens == 0
        assert result.output_tokens == 0


# ===========================================================================
# R4-6 — error strings redacted
# ===========================================================================


class TestR46RedactSecrets:
    def test_redacts_anthropic_key(self):
        from utilities.llm._redact import redact_secrets
        out = redact_secrets("bad key: sk-ant-api03-AbCdEf123456789ZyXwVu rejected")
        assert "sk-ant-api03-AbCdEf123456789ZyXwVu" not in out
        assert "rejected" in out

    def test_redacts_generic_sk_key(self):
        from utilities.llm._redact import redact_secrets
        out = redact_secrets("token sk-proj-ABCDEFG1234567890hijklmnop here")
        assert "sk-proj-ABCDEFG1234567890hijklmnop" not in out

    def test_redacts_google_aiza_key(self):
        from utilities.llm._redact import redact_secrets
        out = redact_secrets("key=AIzaSyA1234567890_abcDEFghIJklmNOpqrSTuvwx blocked")
        assert "AIzaSyA1234567890_abcDEFghIJklmNOpqrSTuvwx" not in out

    def test_redacts_bearer_token(self):
        from utilities.llm._redact import redact_secrets
        out = redact_secrets("Authorization: Bearer abcdef1234567890ABCDEF token")
        assert "abcdef1234567890ABCDEF" not in out

    def test_redacts_api_key_query_param(self):
        from utilities.llm._redact import redact_secrets
        for prefix in ("api_key=", "apikey=", "key="):
            secret = "supersecretvalue1234567890"
            out = redact_secrets(f"url?{prefix}{secret}&x=1")
            assert secret not in out, prefix

    def test_does_not_over_redact_prose(self):
        from utilities.llm._redact import redact_secrets
        prose = "The model returned a 400 Bad Request: invalid 'messages' field."
        assert redact_secrets(prose) == prose

    def test_anthropic_error_message_is_redacted_end_to_end(self):
        """A fake SDK error whose message embeds a key → the raised
        LLMError message is masked."""
        secret = "sk-ant-api03-LEAKED1234567890abcdefGHIJ"

        def boom(**kw):
            raise anthropic.APIStatusError(
                message=f"400 invalid_request: api key {secret} is bad",
                response=_a_fake_http(400),
                body=None,
            )

        adapter, _ = _anthropic_stub(boom)
        with pytest.raises(LLMResponseError) as exc_info:
            adapter.complete(model="claude-test", system=None, messages=_hi(), max_tokens=8)
        assert secret not in str(exc_info.value)

    def test_openai_error_message_is_redacted_end_to_end(self):
        secret = "sk-proj-LEAKED1234567890abcdefGHIJKL"

        def boom(**kw):
            raise openai.BadRequestError(
                message=f"400: key {secret} rejected",
                response=_openai_fake_http(400),
                body=None,
            )

        adapter, _ = _openai_stub(boom)
        with pytest.raises(LLMResponseError) as exc_info:
            adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8)
        assert secret not in str(exc_info.value)

    def test_google_error_message_is_redacted_end_to_end(self):
        secret = "AIzaSyLEAKED1234567890_abcDEFghIJklmNOpqr"

        def boom(**kw):
            raise _g_client_error(400, f"bad request with key={secret}")

        adapter, _ = _google_stub(boom)
        with pytest.raises(LLMResponseError) as exc_info:
            adapter.complete(model="gemini-2.5-pro", system=None, messages=_hi(), max_tokens=8)
        assert secret not in str(exc_info.value)
