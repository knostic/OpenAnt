"""Scenario factory for the OpenAI adapter contract tests.

Each scenario builds a fake ``openai.OpenAI`` client wired with the
right scripted behavior, then constructs an :class:`OpenAIAdapter`
over that fake. The adapter is unaware it's being tested — all the
SDK-boundary mocking happens here.

See ``tests/test_llm_adapter_contract.py`` for the scenario catalogue.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import httpx
import openai

from utilities.llm import LLMAdapter
from utilities.llm.providers.openai import OpenAIAdapter


# ---------------------------------------------------------------------------
# Fake response helpers
# ---------------------------------------------------------------------------
#
# The openai SDK returns Pydantic-style objects. The adapter walks them via
# attribute access (``choice.finish_reason``, ``message.content``,
# ``message.tool_calls``, ``usage.prompt_tokens``, …), so SimpleNamespace is
# a structurally-compatible stand-in.


def _message(*, content: str | None, tool_calls: list | None = None) -> SimpleNamespace:
    return SimpleNamespace(content=content, tool_calls=tool_calls)


def _tool_call(*, id: str, name: str, arguments: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=id,
        type="function",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _choice(*, message: SimpleNamespace, finish_reason: str) -> SimpleNamespace:
    return SimpleNamespace(message=message, finish_reason=finish_reason)


def _response(*, choices: list, prompt_tokens: int, completion_tokens: int) -> SimpleNamespace:
    return SimpleNamespace(
        choices=choices,
        usage=SimpleNamespace(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        ),
    )


def _fake_httpx_response(status_code: int, *, retry_after: str | None = None) -> httpx.Response:
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status_code,
        headers=headers,
        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"),
    )


# ---------------------------------------------------------------------------
# Per-scenario behaviors scripted onto a fake ``chat.completions.create``
# ---------------------------------------------------------------------------


def _script_text(call_args: dict) -> SimpleNamespace:
    return _response(
        choices=[_choice(
            message=_message(content="hi there"),
            finish_reason="stop",
        )],
        prompt_tokens=3,
        completion_tokens=5,
    )


def _script_tool_use_round(call_args: dict) -> SimpleNamespace:
    """Two-turn round trip: tool_calls finish, then end_turn after tool result.

    The harness sends the user's "call echo" prompt twice (once
    standalone, once with the assistant + tool_result appended).
    Distinguish the turns by checking whether the messages include
    an assistant turn yet — easier than tracking call counts because
    contract tests can rerun.
    """
    has_assistant = any(m.get("role") == "assistant" for m in call_args["messages"])
    if not has_assistant:
        return _response(
            choices=[_choice(
                message=_message(
                    content=None,
                    tool_calls=[_tool_call(
                        id="call_test_1",
                        name="echo",
                        arguments='{"text": "hello"}',
                    )],
                ),
                finish_reason="tool_calls",
            )],
            prompt_tokens=10,
            completion_tokens=8,
        )
    return _response(
        choices=[_choice(
            message=_message(content="echoed: hello"),
            finish_reason="stop",
        )],
        prompt_tokens=20,
        completion_tokens=4,
    )


def _raise_auth(_call_args: dict):
    raise openai.AuthenticationError(
        message="invalid api key",
        response=_fake_httpx_response(401),
        body=None,
    )


def _raise_rate_limit(_call_args: dict):
    raise openai.RateLimitError(
        message="slow down",
        response=_fake_httpx_response(429, retry_after="7"),
        body=None,
    )


def _raise_connection(_call_args: dict):
    raise openai.APIConnectionError(
        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"),
    )


def _raise_not_found(_call_args: dict):
    raise openai.NotFoundError(
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
    "validate_ok": _script_text,
    "validate_auth_fail": _raise_auth,
}


def make_adapter(scenario: str) -> LLMAdapter:
    """Build an OpenAIAdapter whose SDK is scripted for ``scenario``."""
    if scenario not in _SCENARIO_HANDLERS:
        raise KeyError(f"Unknown scenario: {scenario!r}")

    handler = _SCENARIO_HANDLERS[scenario]

    def side_effect(**kwargs: Any) -> Any:
        return handler(kwargs)

    fake_client = MagicMock(spec=openai.OpenAI)
    fake_client.chat = MagicMock()
    fake_client.chat.completions = MagicMock()
    fake_client.chat.completions.create = MagicMock(side_effect=side_effect)

    return OpenAIAdapter(_client=fake_client)
