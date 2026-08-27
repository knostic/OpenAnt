"""Scenario factory for the Bedrock adapter contract tests.

Each scenario builds a fake ``anthropic.AnthropicBedrock`` client wired
with the right scripted behavior, then constructs a
:class:`BedrockAdapter` over that fake. Bedrock speaks the same
Messages API through the same ``anthropic`` SDK types and exception
classes as the direct API, so the scripted responses and raised
exceptions mirror the Anthropic factory — only the client spec and the
endpoint URL differ.

See ``tests/test_llm_adapter_contract.py`` for the scenario catalogue.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import anthropic
import httpx2 as httpx

from utilities.llm import LLMAdapter
from utilities.llm.providers.bedrock import BedrockAdapter


_ENDPOINT = "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke"


def _text_block(text: str) -> SimpleNamespace:
    return SimpleNamespace(type="text", text=text)


def _tool_use_block(*, id: str, name: str, input: dict) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=id, name=name, input=input)


def _response(
    *, content: list, input_tokens: int, output_tokens: int, stop_reason: str
) -> SimpleNamespace:
    return SimpleNamespace(
        content=content,
        usage=SimpleNamespace(
            input_tokens=input_tokens, output_tokens=output_tokens
        ),
        stop_reason=stop_reason,
    )


def _fake_httpx_response(status_code: int, *, retry_after: str | None = None) -> httpx.Response:
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status_code,
        headers=headers,
        request=httpx.Request("POST", _ENDPOINT),
    )


def _script_text(call_args: dict) -> SimpleNamespace:
    # The contract test asserts content=="hi there", usage 3/5, end_turn.
    return _response(
        content=[_text_block("hi there")],
        input_tokens=3,
        output_tokens=5,
        stop_reason="end_turn",
    )


def _script_tool_use_round(call_args: dict) -> SimpleNamespace:
    has_assistant = any(m.get("role") == "assistant" for m in call_args["messages"])
    if not has_assistant:
        return _response(
            content=[
                _tool_use_block(
                    id="toolu_test_1",
                    name="echo",
                    input={"text": "hello"},
                )
            ],
            input_tokens=10,
            output_tokens=8,
            stop_reason="tool_use",
        )
    return _response(
        content=[_text_block("echoed: hello")],
        input_tokens=20,
        output_tokens=4,
        stop_reason="end_turn",
    )


def _raise_auth(_call_args: dict):
    raise anthropic.AuthenticationError(
        message="invalid signature",
        response=_fake_httpx_response(401),
        body=None,
    )


def _raise_rate_limit(_call_args: dict):
    # Bedrock throttling (ThrottlingException) surfaces as the SDK's
    # standard 429 RateLimitError.
    raise anthropic.RateLimitError(
        message="too many requests, please wait before trying again",
        response=_fake_httpx_response(429, retry_after="7"),
        body=None,
    )


def _raise_connection(_call_args: dict):
    raise anthropic.APIConnectionError(
        request=httpx.Request("POST", _ENDPOINT),
    )


def _raise_not_found(_call_args: dict):
    raise anthropic.NotFoundError(
        message="model not found: ghost-model",
        response=_fake_httpx_response(404),
        body=None,
    )


_SCENARIO_HANDLERS = {
    "text": _script_text,
    "tool_use_round": _script_tool_use_round,
    "auth_error": _raise_auth,
    "rate_limit": _raise_rate_limit,
    "connection_error": _raise_connection,
    "model_not_found": _raise_not_found,
    "validate_ok": _script_text,        # any valid response satisfies validate
    "validate_auth_fail": _raise_auth,  # validate is a thin wrapper over create
}


def make_adapter(scenario: str) -> LLMAdapter:
    """Build a BedrockAdapter whose SDK is scripted for ``scenario``."""
    if scenario not in _SCENARIO_HANDLERS:
        raise KeyError(f"Unknown scenario: {scenario!r}")

    handler = _SCENARIO_HANDLERS[scenario]

    def side_effect(**kwargs: Any) -> Any:
        return handler(kwargs)

    fake_client = MagicMock(spec=anthropic.AnthropicBedrock)
    fake_client.messages = MagicMock()
    fake_client.messages.create = MagicMock(side_effect=side_effect)

    return BedrockAdapter(_client=fake_client)
