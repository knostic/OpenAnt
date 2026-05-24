"""Scenario factory for the Google Gemini adapter contract tests.

Builds a fake ``google.genai.Client`` and constructs a
:class:`GoogleAdapter` over it. The adapter walks the response via
attribute access (``response.candidates[0].content.parts``,
``part.text``, ``part.function_call.name``, etc.), so
``SimpleNamespace`` stand-ins satisfy the contract without dragging in
the SDK's heavier Pydantic models.

See ``tests/test_llm_adapter_contract.py`` for the scenario catalogue.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import httpx
from google import genai
from google.genai import errors as genai_errors

from utilities.llm import LLMAdapter
from utilities.llm.providers.google import GoogleAdapter


# ---------------------------------------------------------------------------
# Fake response helpers
# ---------------------------------------------------------------------------


def _text_part(text: str) -> SimpleNamespace:
    # The adapter checks ``part.function_call is not None`` before
    # ``part.text``, so a text-only part needs function_call=None to
    # avoid being misinterpreted as a tool call.
    return SimpleNamespace(text=text, function_call=None)


def _function_call_part(*, name: str, args: dict, id: str | None = None) -> SimpleNamespace:
    fc = SimpleNamespace(name=name, args=args, id=id)
    return SimpleNamespace(text=None, function_call=fc)


def _content(parts: list) -> SimpleNamespace:
    return SimpleNamespace(parts=parts)


def _candidate(*, parts: list, finish_reason: str = "STOP") -> SimpleNamespace:
    return SimpleNamespace(
        content=_content(parts),
        finish_reason=finish_reason,
    )


def _response(*, candidates: list, prompt_tokens: int, candidate_tokens: int) -> SimpleNamespace:
    return SimpleNamespace(
        candidates=candidates,
        usage_metadata=SimpleNamespace(
            prompt_token_count=prompt_tokens,
            candidates_token_count=candidate_tokens,
        ),
    )


def _fake_httpx_response(status_code: int, *, retry_after: str | None = None) -> httpx.Response:
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status_code,
        headers=headers,
        request=httpx.Request(
            "POST",
            "https://generativelanguage.googleapis.com/v1beta/models/x:generateContent",
        ),
    )


# ---------------------------------------------------------------------------
# genai error construction helpers
# ---------------------------------------------------------------------------
#
# genai.errors.ClientError(code, response_json, response) raises during
# its __init__ if response_json doesn't have an "error" key the SDK can
# unpack. Supply a minimal-but-valid shape so the constructor succeeds
# and the .code attribute we rely on in the adapter is populated.


def _client_error(code: int, message: str, *, retry_after: str | None = None) -> genai_errors.ClientError:
    response_json = {"error": {"code": code, "message": message, "status": ""}}
    resp = _fake_httpx_response(code, retry_after=retry_after)
    return genai_errors.ClientError(code, response_json, resp)


# ---------------------------------------------------------------------------
# Per-scenario behaviors scripted onto a fake ``models.generate_content``
# ---------------------------------------------------------------------------


def _script_text(call_args: dict) -> SimpleNamespace:
    return _response(
        candidates=[_candidate(
            parts=[_text_part("hi there")],
            finish_reason="STOP",
        )],
        prompt_tokens=3,
        candidate_tokens=5,
    )


def _script_tool_use_round(call_args: dict) -> SimpleNamespace:
    """Two-turn round trip: function_call, then text after function_response.

    The harness sends the user's "call echo" prompt twice (once
    standalone, once with the assistant + tool_result appended).
    Distinguish turns by checking whether the contents list contains
    a ``model`` role yet (Gemini's equivalent of "assistant").
    """
    contents = call_args.get("contents", [])
    has_model_turn = any(
        getattr(c, "role", None) == "model" for c in contents
    )
    if not has_model_turn:
        return _response(
            candidates=[_candidate(
                parts=[_function_call_part(
                    name="echo",
                    args={"text": "hello"},
                    id="gemini_test_1",
                )],
                finish_reason="STOP",
            )],
            prompt_tokens=10,
            candidate_tokens=8,
        )
    return _response(
        candidates=[_candidate(
            parts=[_text_part("echoed: hello")],
            finish_reason="STOP",
        )],
        prompt_tokens=20,
        candidate_tokens=4,
    )


def _raise_auth(_call_args: dict):
    raise _client_error(401, "invalid api key")


def _raise_rate_limit(_call_args: dict):
    raise _client_error(429, "slow down", retry_after="7")


def _raise_connection(_call_args: dict):
    raise httpx.ConnectError("DNS lookup failed")


def _raise_not_found(_call_args: dict):
    raise _client_error(404, "model not found")


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
    """Build a GoogleAdapter whose SDK is scripted for ``scenario``."""
    if scenario not in _SCENARIO_HANDLERS:
        raise KeyError(f"Unknown scenario: {scenario!r}")

    handler = _SCENARIO_HANDLERS[scenario]

    def side_effect(**kwargs: Any) -> Any:
        return handler(kwargs)

    fake_client = MagicMock(spec=genai.Client)
    fake_client.models = MagicMock()
    fake_client.models.generate_content = MagicMock(side_effect=side_effect)

    return GoogleAdapter(_client=fake_client)
