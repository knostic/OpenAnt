"""Anthropic-adapter-specific tests.

The shared contract harness (``test_llm_adapter_contract.py``)
covers behaviors every adapter must satisfy. This file covers
the bits that are specific to the Anthropic adapter:

* request shape sent to the SDK — system prompts, tool definitions,
  content-block translation in both directions
* rate-limiter coordination — 429 and 529 both trigger global backoff
* base_url / api_key plumbing into the SDK constructor
* validate() actually probes the configured model (not a hardcoded one)

These tests stub the SDK boundary so nothing hits the network.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import anthropic
import httpx
import pytest

from utilities.llm import (
    LLMRateLimitError,
    LLMResponseError,
    Message,
    TextBlock,
    ToolDef,
    ToolResultBlock,
    ToolUseBlock,
)
from utilities.llm.providers.anthropic import AnthropicAdapter
from utilities.rate_limiter import get_rate_limiter, reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    reset_rate_limiter()
    yield
    reset_rate_limiter()


def _ok_response(*, text="hi", input_tokens=1, output_tokens=1, stop_reason="end_turn"):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
        stop_reason=stop_reason,
    )


def _stub_adapter(side_effect):
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages = MagicMock()
    client.messages.create = MagicMock(side_effect=side_effect)
    return AnthropicAdapter(_client=client), client


def _fake_http_resp(status, *, retry_after=None):
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status,
        headers=headers,
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
    )


# ---------------------------------------------------------------------------
# Request translation
# ---------------------------------------------------------------------------


class TestRequestTranslation:
    def test_text_only_request(self):
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        adapter.complete(
            model="claude-test",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hello")])],
            max_tokens=64,
        )
        kwargs = client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-test"
        assert kwargs["max_tokens"] == 64
        assert "system" not in kwargs  # omit when None, don't pass system=None
        assert kwargs["messages"] == [
            {"role": "user", "content": [{"type": "text", "text": "hello"}]}
        ]
        assert "tools" not in kwargs

    def test_system_prompt_passed_through(self):
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        adapter.complete(
            model="claude-test",
            system="You are helpful.",
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=8,
        )
        assert client.messages.create.call_args.kwargs["system"] == "You are helpful."

    def test_tool_definitions_serialised(self):
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        adapter.complete(
            model="claude-test",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=8,
            tools=[
                ToolDef(
                    name="search",
                    description="Search the index",
                    input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
                )
            ],
        )
        tools = client.messages.create.call_args.kwargs["tools"]
        assert tools == [
            {
                "name": "search",
                "description": "Search the index",
                "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
            }
        ]

    def test_tool_use_and_result_blocks_round_trip(self):
        """A tool-use loop sends ToolUseBlock + ToolResultBlock back in
        Anthropic's native shape, in order. This is the most subtle bit
        of the translation — a regression here breaks verify / agentic
        enhance silently."""
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        adapter.complete(
            model="claude-test",
            system=None,
            messages=[
                Message(role="user", content=[TextBlock("call echo")]),
                Message(
                    role="assistant",
                    content=[ToolUseBlock(id="toolu_1", name="echo", input={"text": "hi"})],
                ),
                Message(
                    role="user",
                    content=[ToolResultBlock(tool_use_id="toolu_1", content='"hi"')],
                ),
            ],
            max_tokens=8,
            tools=[ToolDef(name="echo", description="echo", input_schema={"type": "object"})],
        )
        messages = client.messages.create.call_args.kwargs["messages"]
        # Assistant turn carries tool_use in native format.
        assert messages[1] == {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "echo",
                    "input": {"text": "hi"},
                }
            ],
        }
        # Following user turn carries tool_result with matching id.
        assert messages[2] == {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": '"hi"',
                }
            ],
        }


# ---------------------------------------------------------------------------
# Response translation
# ---------------------------------------------------------------------------


class TestResponseTranslation:
    def test_unknown_stop_reason_normalised_to_end_turn(self):
        # Future SDK adding a new stop reason must not crash the
        # pipeline. The adapter falls back to "end_turn" defensively.
        adapter, _ = _stub_adapter(
            lambda **kw: _ok_response(stop_reason="future_invention")
        )
        result = adapter.complete(
            model="claude-test",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=8,
        )
        assert result.stop_reason == "end_turn"

    def test_tool_use_block_extracted_from_response(self):
        def respond(**kw):
            return SimpleNamespace(
                content=[
                    SimpleNamespace(
                        type="tool_use",
                        id="toolu_42",
                        name="search",
                        input={"q": "leak"},
                    )
                ],
                usage=SimpleNamespace(input_tokens=5, output_tokens=2),
                stop_reason="tool_use",
            )

        adapter, _ = _stub_adapter(respond)
        result = adapter.complete(
            model="claude-test",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=8,
            tools=[ToolDef(name="search", description="x", input_schema={"type": "object"})],
        )
        assert result.stop_reason == "tool_use"
        assert len(result.content) == 1
        block = result.content[0]
        assert isinstance(block, ToolUseBlock)
        assert block.id == "toolu_42"
        assert block.name == "search"
        assert block.input == {"q": "leak"}

    def test_unknown_block_kind_silently_dropped(self):
        # A future "thinking" block from Anthropic shouldn't crash
        # the pipeline; the adapter drops unknown kinds (with no log)
        # so phases that don't know about them keep working.
        def respond(**kw):
            return SimpleNamespace(
                content=[
                    SimpleNamespace(type="thinking", text="...hidden..."),
                    SimpleNamespace(type="text", text="visible"),
                ],
                usage=SimpleNamespace(input_tokens=1, output_tokens=1),
                stop_reason="end_turn",
            )

        adapter, _ = _stub_adapter(respond)
        result = adapter.complete(
            model="claude-test",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=8,
        )
        assert len(result.content) == 1
        assert isinstance(result.content[0], TextBlock)
        assert result.content[0].text == "visible"

    def test_raw_response_preserved(self):
        sentinel = _ok_response(text="hi")
        adapter, _ = _stub_adapter(lambda **kw: sentinel)
        result = adapter.complete(
            model="claude-test",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=8,
        )
        assert result.raw is sentinel


# ---------------------------------------------------------------------------
# Rate-limiter coordination
# ---------------------------------------------------------------------------


class TestRateLimiterCoordination:
    def test_429_reports_to_global_limiter(self):
        def respond(**kw):
            raise anthropic.RateLimitError(
                message="slow",
                response=_fake_http_resp(429, retry_after="3"),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMRateLimitError):
            adapter.complete(
                model="claude-test",
                system=None,
                messages=[Message(role="user", content=[TextBlock("hi")])],
                max_tokens=8,
            )
        # The singleton should now be in backoff so other workers
        # wait their turn — that's the whole point of routing 429s
        # through ``get_rate_limiter().report_rate_limit()``.
        assert get_rate_limiter().is_in_backoff()

    def test_529_overloaded_maps_to_rate_limit(self):
        # Per the design decision in plan §10, 529 is transient just
        # like 429 and goes through the same rate-limit code path.
        def respond(**kw):
            raise anthropic.APIStatusError(
                message="overloaded",
                response=_fake_http_resp(529, retry_after="5"),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMRateLimitError) as exc_info:
            adapter.complete(
                model="claude-test",
                system=None,
                messages=[Message(role="user", content=[TextBlock("hi")])],
                max_tokens=8,
            )
        assert exc_info.value.retry_after == 5
        assert get_rate_limiter().is_in_backoff()

    def test_other_api_status_errors_are_response_errors(self):
        # 400/422/500 are structural problems, not rate-limit problems.
        def respond(**kw):
            raise anthropic.APIStatusError(
                message="bad request",
                response=_fake_http_resp(400),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMResponseError):
            adapter.complete(
                model="claude-test",
                system=None,
                messages=[Message(role="user", content=[TextBlock("hi")])],
                max_tokens=8,
            )
        # And critically, no rate-limit backoff was triggered.
        assert not get_rate_limiter().is_in_backoff()


# ---------------------------------------------------------------------------
# Constructor plumbing
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_passes_base_url_to_sdk(self, monkeypatch):
        captured = {}

        class FakeAnthropic:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.messages = MagicMock()

        monkeypatch.setattr(
            "utilities.llm.providers.anthropic.anthropic.Anthropic", FakeAnthropic
        )
        AnthropicAdapter(api_key="sk-or-test", base_url="https://openrouter.ai/api/v1")
        assert captured["base_url"] == "https://openrouter.ai/api/v1"
        assert captured["api_key"] == "sk-or-test"
        assert captured["max_retries"] == 5

    def test_omits_api_key_when_none(self, monkeypatch):
        """SDK's own ANTHROPIC_API_KEY env lookup must still work
        when the adapter is built without an explicit key."""
        captured = {}

        class FakeAnthropic:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.messages = MagicMock()

        monkeypatch.setattr(
            "utilities.llm.providers.anthropic.anthropic.Anthropic", FakeAnthropic
        )
        AnthropicAdapter()
        assert "api_key" not in captured
        assert "base_url" not in captured


# ---------------------------------------------------------------------------
# validate()
# ---------------------------------------------------------------------------


class TestValidate:
    def test_validate_probes_the_passed_model(self):
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        adapter.validate(model="claude-haiku-test")
        kwargs = client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-haiku-test"
        assert kwargs["max_tokens"] == 1

    def test_validate_raises_not_found_on_bad_model(self):
        def respond(**kw):
            raise anthropic.NotFoundError(
                message="model not found",
                response=_fake_http_resp(404),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        from utilities.llm import LLMNotFoundError

        with pytest.raises(LLMNotFoundError):
            adapter.validate(model="ghost-model")
