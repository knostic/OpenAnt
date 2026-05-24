"""Scenario factory for the Anthropic adapter contract tests.

Each scenario builds a fake ``anthropic.Anthropic`` client wired with
the right scripted behavior, then constructs an
:class:`AnthropicAdapter` over that fake. The adapter is unaware
it's being tested — all the SDK-boundary mocking happens here.

See ``tests/test_llm_adapter_contract.py`` for the scenario catalogue.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import anthropic
import httpx

from utilities.llm import LLMAdapter
from utilities.llm.providers.anthropic import AnthropicAdapter


# ---------------------------------------------------------------------------
# Helpers for constructing fake SDK response objects
# ---------------------------------------------------------------------------
#
# The anthropic SDK returns Pydantic-style objects with `.type`, `.text`,
# `.usage.input_tokens`, etc. The AnthropicAdapter walks these via getattr,
# so SimpleNamespace is a structurally-compatible stand-in without dragging
# in the SDK's heavy Pydantic models.


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
    """Build a real httpx.Response so SDK error constructors are happy.

    The anthropic SDK's exception classes require an httpx.Response in
    their constructor; faking it with SimpleNamespace works for some
    versions but breaks on others. Building a real one keeps the test
    stable across SDK upgrades.
    """
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status_code,
        headers=headers,
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
    )


# ---------------------------------------------------------------------------
# Per-scenario behaviors scripted onto a fake ``messages.create``
# ---------------------------------------------------------------------------


def _script_text(call_args: dict) -> SimpleNamespace:
    # The contract test asserts content=="hi there", usage 3/5, end_turn.
    return _response(
        content=[_text_block("hi there")],
        input_tokens=3,
        output_tokens=5,
        stop_reason="end_turn",
    )


def _script_tool_use_round(call_args: dict) -> SimpleNamespace:
    """Two-turn round trip: tool_use, then end_turn after tool_result.

    The harness sends the user's "call echo" prompt twice (once
    standalone, once with the assistant + tool_result appended).
    Distinguish the turns by checking whether the messages list
    contains an assistant turn yet.
    """
    has_assistant = any(m.get("role") == "assistant" for m in call_args["messages"])
    if not has_assistant:
        # Turn 1: emit tool_use.
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
    # Turn 2: end_turn with text.
    return _response(
        content=[_text_block("echoed: hello")],
        input_tokens=20,
        output_tokens=4,
        stop_reason="end_turn",
    )


def _raise_auth(_call_args: dict):
    raise anthropic.AuthenticationError(
        message="invalid api key",
        response=_fake_httpx_response(401),
        body=None,
    )


def _raise_rate_limit(_call_args: dict):
    raise anthropic.RateLimitError(
        message="slow down",
        response=_fake_httpx_response(429, retry_after="7"),
        body=None,
    )


def _raise_connection(_call_args: dict):
    # APIConnectionError takes a request, not a response.
    raise anthropic.APIConnectionError(
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
    )


def _raise_not_found(_call_args: dict):
    raise anthropic.NotFoundError(
        message="model not found: ghost-model",
        response=_fake_httpx_response(404),
        body=None,
    )


# ---------------------------------------------------------------------------
# Factory entry point
# ---------------------------------------------------------------------------


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
    """Build an AnthropicAdapter whose SDK is scripted for ``scenario``.

    Each scenario maps to a side-effect that is invoked on every
    ``client.messages.create(**kwargs)`` call. Side effects either
    return a SimpleNamespace shaped like an SDK response, or raise
    one of the SDK's typed exceptions.
    """
    if scenario not in _SCENARIO_HANDLERS:
        raise KeyError(f"Unknown scenario: {scenario!r}")

    handler = _SCENARIO_HANDLERS[scenario]

    def side_effect(**kwargs: Any) -> Any:
        return handler(kwargs)

    fake_client = MagicMock(spec=anthropic.Anthropic)
    fake_client.messages = MagicMock()
    fake_client.messages.create = MagicMock(side_effect=side_effect)

    return AnthropicAdapter(_client=fake_client)
