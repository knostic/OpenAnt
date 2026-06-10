"""OpenAI-adapter-specific tests (PR #69 fixes H1 + H3 + L2 + L3).

The shared contract harness (``test_llm_adapter_contract.py``) covers
behaviors every adapter must satisfy. This file covers OpenAI specifics:

* H3 — reasoning models (o1/o3/o4) send ``max_completion_tokens``, not
  ``max_tokens``; regular chat models (gpt-4o) keep ``max_tokens``. Also,
  reasoning models reject the ``system`` role, so a system prompt is
  routed to a ``developer``-role message; non-reasoning models keep
  ``system``. o1-mini/o1-preview are dropped entirely (no tool support).
* H1 — a 429 reports to the process-global rate limiter so sibling
  workers back off, and ``complete()`` consults the limiter first.
* L2 — an empty ``choices`` array surfaces ``LLMResponseError`` instead
  of letting an ``IndexError`` escape the taxonomy.
* L3 — the pricing table carries current models so calls don't silently
  report $0.

These stub the SDK boundary so nothing hits the network.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import openai
import pytest

from utilities.llm import LLMRateLimitError, LLMResponseError, Message, TextBlock
from utilities.llm.providers.openai import OpenAIAdapter
from utilities.llm_client import reset_warning_state
from utilities.rate_limiter import get_rate_limiter, reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_state():
    # Once OpenAI wires into the global limiter, a leaked backoff would
    # make later tests sleep ~30s. Reset before and after every test.
    reset_rate_limiter()
    reset_warning_state()
    yield
    reset_rate_limiter()
    reset_warning_state()


def _text_response(*, prompt_tokens=1, completion_tokens=1):
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content="hi", tool_calls=None),
            finish_reason="stop",
        )],
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
    )


def _stub(side_effect):
    client = MagicMock(spec=openai.OpenAI)
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=side_effect)
    return OpenAIAdapter(_client=client), client


def _fake_http(status, *, retry_after=None):
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status,
        headers=headers,
        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"),
    )


def _hi():
    return [Message(role="user", content=[TextBlock("hi")])]


# ---------------------------------------------------------------------------
# H3 — reasoning models need max_completion_tokens
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("model", ["o1", "o3-mini", "o4-mini", "o3", "openai/o1"])
def test_reasoning_model_uses_max_completion_tokens(model):
    adapter, client = _stub(lambda **kw: _text_response())
    adapter.complete(model=model, system=None, messages=_hi(), max_tokens=64)
    kw = client.chat.completions.create.call_args.kwargs
    assert kw.get("max_completion_tokens") == 64
    assert "max_tokens" not in kw, f"{model}: reasoning models reject max_tokens"


@pytest.mark.parametrize("model", ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo"])
def test_chat_model_uses_max_tokens(model):
    adapter, client = _stub(lambda **kw: _text_response())
    adapter.complete(model=model, system=None, messages=_hi(), max_tokens=64)
    kw = client.chat.completions.create.call_args.kwargs
    assert kw.get("max_tokens") == 64
    assert "max_completion_tokens" not in kw


def test_validate_reasoning_model_uses_max_completion_tokens():
    adapter, client = _stub(lambda **kw: _text_response())
    adapter.validate("o3-mini")
    kw = client.chat.completions.create.call_args.kwargs
    assert kw.get("max_completion_tokens") == 1
    assert "max_tokens" not in kw


# ---------------------------------------------------------------------------
# H3 — reasoning models reject the ``system`` role → route to ``developer``
# ---------------------------------------------------------------------------


def _roles(client) -> list[str]:
    """Roles, in order, of the messages sent on the last create() call."""
    kw = client.chat.completions.create.call_args.kwargs
    return [m["role"] for m in kw["messages"]]


@pytest.mark.parametrize("model", ["o1", "o3-mini", "o4-mini", "openai/o1"])
def test_reasoning_model_routes_system_to_developer(model):
    adapter, client = _stub(lambda **kw: _text_response())
    adapter.complete(
        model=model, system="be careful", messages=_hi(), max_tokens=8
    )
    kw = client.chat.completions.create.call_args.kwargs
    roles = [m["role"] for m in kw["messages"]]
    assert "developer" in roles, f"{model}: reasoning models need a developer role"
    assert "system" not in roles, f"{model}: reasoning models reject the system role"
    dev = next(m for m in kw["messages"] if m["role"] == "developer")
    assert dev["content"] == "be careful"


@pytest.mark.parametrize("model", ["gpt-4o", "gpt-4o-mini", "gpt-4.1"])
def test_chat_model_keeps_system_role(model):
    adapter, client = _stub(lambda **kw: _text_response())
    adapter.complete(
        model=model, system="be careful", messages=_hi(), max_tokens=8
    )
    roles = _roles(client)
    assert "system" in roles, f"{model}: non-reasoning models keep the system role"
    assert "developer" not in roles
    kw = client.chat.completions.create.call_args.kwargs
    sysmsg = next(m for m in kw["messages"] if m["role"] == "system")
    assert sysmsg["content"] == "be careful"


def test_dropped_reasoning_models_absent_from_pricing():
    # o1-mini / o1-preview reject the developer role AND lack tool support,
    # so the adapter no longer advertises them (H3).
    assert "o1-mini" not in OpenAIAdapter.pricing
    assert "o1-preview" not in OpenAIAdapter.pricing
    # The reasoning models we DO keep stay priced.
    assert "o1" in OpenAIAdapter.pricing
    assert "o3-mini" in OpenAIAdapter.pricing


# ---------------------------------------------------------------------------
# L2 — empty ``choices`` surfaces LLMResponseError (not a bare IndexError)
# ---------------------------------------------------------------------------


def test_empty_choices_raises_llm_response_error():
    empty = SimpleNamespace(
        choices=[],
        usage=SimpleNamespace(prompt_tokens=1, completion_tokens=0),
    )
    adapter, _ = _stub(lambda **kw: empty)
    with pytest.raises(LLMResponseError):
        adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8)


# ---------------------------------------------------------------------------
# L3 — pricing table carries current models so they don't report $0
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "model", ["gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano", "o3", "o4-mini"]
)
def test_current_models_present_in_pricing(model):
    rates = OpenAIAdapter.pricing.get(model)
    assert rates is not None, f"{model}: must be priced so it doesn't report $0"
    assert rates["input"] > 0 and rates["output"] > 0


# ---------------------------------------------------------------------------
# H1 — rate-limiter coordination
# ---------------------------------------------------------------------------


def test_rate_limit_reports_to_global_limiter():
    def boom(**kw):
        raise openai.RateLimitError(
            message="slow down", response=_fake_http(429, retry_after="7"), body=None
        )

    adapter, _ = _stub(boom)
    limiter = get_rate_limiter()
    assert not limiter.is_in_backoff()
    with pytest.raises(LLMRateLimitError):
        adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8)
    assert limiter.is_in_backoff(), "OpenAI 429 must trigger global backoff (H1)"


def test_complete_consults_limiter_before_request(monkeypatch):
    adapter, _ = _stub(lambda **kw: _text_response())
    seen = {"waited": False}
    limiter = get_rate_limiter()
    monkeypatch.setattr(
        limiter, "wait_if_needed", lambda: (seen.__setitem__("waited", True), 0.0)[1]
    )
    adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8)
    assert seen["waited"], "complete() must call wait_if_needed before the request (H1)"
