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


# ===========================================================================
# Responses API (/v1/responses) — gpt-5+ path
# ===========================================================================

from utilities.llm import LLMRefusalError, ToolDef, ToolResultBlock, ToolUseBlock
from utilities.llm.providers.openai import (
    _use_responses_api,
    _is_reasoning_model,
    _RESPONSES_MIN_OUTPUT_TOKENS,
    _messages_to_responses,
    _tool_to_responses,
)

G5 = "gpt-5.6"


def _resp(*, status="completed", output=None, input_tokens=7, output_tokens=11,
          incomplete_reason=None, error=None):
    return SimpleNamespace(
        status=status,
        output=output or [],
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
        incomplete_details=(SimpleNamespace(reason=incomplete_reason)
                            if incomplete_reason else None),
        error=error,
    )


def _msg_item(*parts):
    return SimpleNamespace(type="message", content=list(parts))


def _text_part(text):
    return SimpleNamespace(type="output_text", text=text)


def _refusal_part(text):
    return SimpleNamespace(type="refusal", refusal=text)


def _fncall(*, call_id, name, arguments):
    return SimpleNamespace(type="function_call", call_id=call_id, name=name, arguments=arguments)


def _reasoning():
    return SimpleNamespace(type="reasoning", encrypted_content="opaque")


def _stub_resp(side_effect, *, use_responses_api=None):
    client = MagicMock(spec=openai.OpenAI)
    client.responses = MagicMock()
    client.responses.create = MagicMock(side_effect=side_effect)
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=AssertionError(
        "chat.completions must NOT be called on the responses path"))
    return OpenAIAdapter(_client=client, use_responses_api=use_responses_api), client


def _tools():
    return [ToolDef(name="echo", description="Echo the text.",
                    input_schema={"type": "object", "properties": {"text": {"type": "string"}},
                                  "required": ["text"]})]


# --- gate --------------------------------------------------------------------

def test_gate_predicates_partition_models():
    assert _use_responses_api("gpt-5.6", None) is True
    assert _use_responses_api("gpt-5", None) is True
    assert _use_responses_api("openai/gpt-6", None) is True
    assert _use_responses_api("gpt-4o", None) is False
    assert _use_responses_api("gpt-4o-mini", None) is False
    assert _use_responses_api("o3", None) is False          # o-series stays on chat
    # ctor override wins either way (base_url proxies)
    assert _use_responses_api("gpt-4o", True) is True
    assert _use_responses_api("gpt-5.6", False) is False


def test_gpt5_chat_variants_stay_off_responses():
    # C1: the non-reasoning chat variants reject the reasoning param; they must NOT be
    # force-routed to /v1/responses (which always sends reasoning -> 400), and must not
    # be classified reasoning (they take max_tokens + system, the plain chat shape).
    for m in ("gpt-5-chat-latest", "gpt-5-chat"):
        assert _use_responses_api(m, None) is False
        assert _is_reasoning_model(m) is False


def test_gpt5_family_boundary_and_whitespace():
    # C3: unrelated numbering (gpt-50) is not the gpt-5..gpt-9 family; ids are whitespace-trimmed.
    assert _use_responses_api("gpt-50", None) is False
    assert _use_responses_api("gpt-5 ", None) is True      # trailing space
    assert _use_responses_api(" gpt-5", None) is True      # leading space
    # real reasoning family still routes to responses and classifies as reasoning
    assert _use_responses_api("gpt-5.6", None) is True
    assert _use_responses_api("gpt-5-mini", None) is True
    assert _is_reasoning_model("gpt-5-mini") is True


def test_gpt5_routes_to_responses_not_chat():
    adapter, client = _stub_resp(lambda **kw: _resp(output=[_msg_item(_text_part("hello"))]))
    r = adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=4096)
    client.responses.create.assert_called_once()
    client.chat.completions.create.assert_not_called()
    assert [b.text for b in r.content] == ["hello"]
    assert r.stop_reason == "end_turn"
    assert (r.input_tokens, r.output_tokens) == (7, 11)     # responses usage fields


def test_gpt4o_stays_on_chat_not_responses():
    client = MagicMock(spec=openai.OpenAI)
    client.chat = MagicMock(); client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=lambda **kw: _text_response())
    client.responses = MagicMock()
    client.responses.create = MagicMock(side_effect=AssertionError("gpt-4o must not use responses"))
    adapter = OpenAIAdapter(_client=client)
    adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8)
    client.responses.create.assert_not_called()


def test_override_forces_responses_for_gpt4o():
    adapter, client = _stub_resp(lambda **kw: _resp(output=[_msg_item(_text_part("ok"))]),
                                 use_responses_api=True)
    adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8)
    client.responses.create.assert_called_once()


# --- request shape -----------------------------------------------------------

def test_request_shape_floor_effort_store_instructions():
    adapter, client = _stub_resp(lambda **kw: _resp(output=[_msg_item(_text_part("x"))]))
    adapter.complete(model=G5, system="be careful", messages=_hi(), max_tokens=4096, tools=_tools())
    kw = client.responses.create.call_args.kwargs
    assert kw["max_output_tokens"] == _RESPONSES_MIN_OUTPUT_TOKENS   # floored up from 4096
    assert kw["reasoning"] == {"effort": "medium"}
    assert kw["store"] is False
    assert kw["instructions"] == "be careful"
    assert kw["tools"][0] == {"type": "function", "name": "echo",
                              "description": "Echo the text.",
                              "parameters": _tools()[0].input_schema, "strict": False}


def test_tools_omitted_when_none():
    # helpers.simple_text calls complete() with no tools; must not send tools=[]
    adapter, client = _stub_resp(lambda **kw: _resp(output=[_msg_item(_text_part("x"))]))
    adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)
    assert "tools" not in client.responses.create.call_args.kwargs


def test_reasoning_effort_configurable():
    adapter, client = _stub_resp(lambda **kw: _resp(output=[_msg_item(_text_part("x"))]))
    adapter._reasoning_effort = "low"
    adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)
    assert client.responses.create.call_args.kwargs["reasoning"] == {"effort": "low"}


# --- tool round-trip (the agentic loop) --------------------------------------

def test_tool_call_parsed_as_tooluseblock():
    adapter, _ = _stub_resp(lambda **kw: _resp(
        output=[_reasoning(), _fncall(call_id="call_1", name="echo", arguments='{"text":"hi"}')]))
    r = adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8, tools=_tools())
    assert r.stop_reason == "tool_use"
    tus = [b for b in r.content if isinstance(b, ToolUseBlock)]
    assert len(tus) == 1 and tus[0].id == "call_1" and tus[0].name == "echo"
    assert tus[0].input == {"text": "hi"}


def test_tool_result_roundtrips_to_function_call_output():
    msgs = [
        Message(role="user", content=[TextBlock("go")]),
        Message(role="assistant", content=[ToolUseBlock(id="call_9", name="echo", input={"text": "hi"})]),
        Message(role="user", content=[ToolResultBlock(tool_use_id="call_9", content="RESULT", name="echo")]),
    ]
    items = _messages_to_responses(msgs)
    # ordering: user text, then assistant function_call, then function_call_output
    fc = [i for i in items if i.get("type") == "function_call"]
    fco = [i for i in items if i.get("type") == "function_call_output"]
    assert fc and fc[0]["call_id"] == "call_9" and fc[0]["arguments"] == '{"text": "hi"}'
    assert fco and fco[0]["call_id"] == "call_9" and fco[0]["output"] == "RESULT"


def test_parallel_tool_calls():
    adapter, _ = _stub_resp(lambda **kw: _resp(output=[
        _fncall(call_id="c1", name="echo", arguments='{"text":"a"}'),
        _fncall(call_id="c2", name="echo", arguments='{"text":"b"}'),
    ]))
    r = adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8, tools=_tools())
    ids = [b.id for b in r.content if isinstance(b, ToolUseBlock)]
    assert ids == ["c1", "c2"]


def test_user_turn_orders_tool_output_before_text():
    msgs = [Message(role="user", content=[
        ToolResultBlock(tool_use_id="c1", content="R"), TextBlock("and now this")])]
    items = _messages_to_responses(msgs)
    assert items[0]["type"] == "function_call_output"
    assert items[1]["role"] == "user"


# --- safety guards (the silent-clean-pass failure modes) ---------------------

def test_refusal_in_message_content_raises():
    adapter, _ = _stub_resp(lambda **kw: _resp(output=[_msg_item(_refusal_part("nope"))]))
    with pytest.raises(LLMRefusalError):
        adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)


def test_content_filter_incomplete_raises_refusal():
    adapter, _ = _stub_resp(lambda **kw: _resp(status="incomplete", incomplete_reason="content_filter",
                                               output=[]))
    with pytest.raises(LLMRefusalError):
        adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)


def test_empty_output_raises_response_error():
    adapter, _ = _stub_resp(lambda **kw: _resp(output=[_reasoning()]))   # reasoning only, no content
    with pytest.raises(LLMResponseError):
        adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)


def test_failed_status_raises_response_error():
    adapter, _ = _stub_resp(lambda **kw: _resp(status="failed",
                                               error=SimpleNamespace(message="boom"), output=[]))
    with pytest.raises(LLMResponseError):
        adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)


def test_incomplete_max_tokens_sets_stop_reason():
    adapter, _ = _stub_resp(lambda **kw: _resp(status="incomplete", incomplete_reason="max_output_tokens",
                                               output=[_msg_item(_text_part("partial"))]))
    r = adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)
    assert r.stop_reason == "max_tokens"


# --- BUG-2: abnormal status / unknown incomplete-reason must NOT read as a clean end_turn ----
# A truncated/abnormal response carrying PARTIAL content must not be laundered into a clean
# stop_reason="end_turn" (a silent false-negative for a SAST tool). It is relabelled "max_tokens"
# (the honest "not a clean finish" signal) and a one-time stderr warning is emitted, mirroring the
# chat path's unknown-finish_reason handling. Empty-content abnormal responses still RAISE.

def test_incomplete_unknown_reason_with_partial_is_not_clean_end_turn():
    # incomplete + reason absent (incomplete_details=None) + partial text
    adapter, _ = _stub_resp(lambda **kw: _resp(status="incomplete", incomplete_reason=None,
                                               output=[_msg_item(_text_part("truncated: no issues fou"))]))
    r = adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)
    assert r.stop_reason != "end_turn"          # must NOT launder to a clean finish
    assert r.stop_reason == "max_tokens"
    assert [b.text for b in r.content] == ["truncated: no issues fou"]   # content preserved


def test_incomplete_other_reason_with_partial_is_not_clean_end_turn():
    adapter, _ = _stub_resp(lambda **kw: _resp(status="incomplete", incomplete_reason="other",
                                               output=[_msg_item(_text_part("partial"))]))
    r = adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)
    assert r.stop_reason == "max_tokens"


def test_unknown_top_level_status_with_partial_is_not_clean_end_turn():
    adapter, _ = _stub_resp(lambda **kw: _resp(status="in_progress",
                                               output=[_msg_item(_text_part("looks clean"))]))
    r = adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)
    assert r.stop_reason != "end_turn"
    assert r.stop_reason == "max_tokens"


def test_bug2_regression_guards_still_hold():
    # (1) completed + text → clean end_turn (unchanged)
    a1, _ = _stub_resp(lambda **kw: _resp(status="completed", output=[_msg_item(_text_part("done"))]))
    assert a1.complete(model=G5, system=None, messages=_hi(), max_tokens=8).stop_reason == "end_turn"
    # (2) incomplete + content_filter → refusal (unchanged)
    a2, _ = _stub_resp(lambda **kw: _resp(status="incomplete", incomplete_reason="content_filter", output=[]))
    with pytest.raises(LLMRefusalError):
        a2.complete(model=G5, system=None, messages=_hi(), max_tokens=8)
    # (3) failed → response error (unchanged)
    a3, _ = _stub_resp(lambda **kw: _resp(status="failed", error=SimpleNamespace(message="boom"), output=[]))
    with pytest.raises(LLMResponseError):
        a3.complete(model=G5, system=None, messages=_hi(), max_tokens=8)
    # (4) incomplete + max_output_tokens + text → max_tokens (unchanged)
    a4, _ = _stub_resp(lambda **kw: _resp(status="incomplete", incomplete_reason="max_output_tokens",
                                          output=[_msg_item(_text_part("partial"))]))
    assert a4.complete(model=G5, system=None, messages=_hi(), max_tokens=8).stop_reason == "max_tokens"
    # (5) abnormal status but EMPTY content → still RAISES (empty-content guard intact)
    a5, _ = _stub_resp(lambda **kw: _resp(status="in_progress", output=[]))
    with pytest.raises(LLMResponseError):
        a5.complete(model=G5, system=None, messages=_hi(), max_tokens=8)


# --- validate gating ---------------------------------------------------------

def test_validate_gpt5_uses_responses_endpoint():
    adapter, client = _stub_resp(lambda **kw: _resp(output=[_msg_item(_text_part("OK"))]))
    adapter.validate(G5)
    client.responses.create.assert_called_once()
    client.chat.completions.create.assert_not_called()
    # BUG-1: the ping exercises the SAME reasoning effort complete() will send,
    # so a model-rejected effort fails fast at init instead of 400-ing every unit.
    assert client.responses.create.call_args.kwargs["reasoning"] == {"effort": "medium"}


def test_validate_gpt5_fails_fast_on_model_rejected_effort():
    # BUG-1: a model that rejects the configured reasoning effort must fail init,
    # not pass validation and then 400 every single unit of the scan.
    def reject_minimal(**kw):
        if kw.get("reasoning", {}).get("effort") == "minimal":
            raise openai.BadRequestError(
                message="Unsupported value: 'minimal' is not supported for this model",
                response=_fake_http(400), body=None)
        return _resp(output=[_msg_item(_text_part("OK"))])
    client = MagicMock(spec=openai.OpenAI)
    client.responses = MagicMock(); client.responses.create = MagicMock(side_effect=reject_minimal)
    client.chat = MagicMock(); client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=AssertionError("must probe responses, not chat"))
    adapter = OpenAIAdapter(_client=client, reasoning_effort="minimal")
    with pytest.raises(LLMResponseError):
        adapter.validate(G5)


def test_validate_gpt4o_uses_chat_endpoint():
    adapter, client = _stub(lambda **kw: _text_response())
    adapter.validate("gpt-4o")
    assert client.chat.completions.create.call_args.kwargs.get("max_tokens") == 1


# --- error taxonomy parity on the responses path -----------------------------

def test_responses_429_reports_to_global_limiter():
    def boom(**kw):
        raise openai.RateLimitError(message="slow", response=_fake_http(429, retry_after="5"), body=None)
    adapter, _ = _stub_resp(boom)
    limiter = get_rate_limiter()
    with pytest.raises(LLMRateLimitError):
        adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=8)
    assert limiter.is_in_backoff(), "responses 429 must trigger global backoff too"


# ---------------------------------------------------------------------------
# Coupling fix: gpt-5+ is reasoning-class, so a gpt-5 forced onto the CHAT
# path (use_responses_api=False, a proxy escape hatch) must still get
# max_completion_tokens + the developer role — not max_tokens + system,
# which 400s a reasoning model. Endpoint choice and token-param/role choice
# must agree. (judge ruling A)
# ---------------------------------------------------------------------------


def _stub_chat_forced(side_effect):
    """A chat-path adapter with use_responses_api=False (forces gpt-5 to chat)."""
    client = MagicMock(spec=openai.OpenAI)
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=side_effect)
    return OpenAIAdapter(_client=client, use_responses_api=False), client


@pytest.mark.parametrize("model", ["gpt-5", "gpt-5.6", "openai/gpt-6"])
def test_gpt5_forced_to_chat_uses_max_completion_tokens(model):
    adapter, client = _stub_chat_forced(lambda **kw: _text_response())
    adapter.complete(model=model, system=None, messages=_hi(), max_tokens=64)
    kw = client.chat.completions.create.call_args.kwargs
    assert kw.get("max_completion_tokens") == 64, f"{model}: gpt-5 on chat needs max_completion_tokens"
    assert "max_tokens" not in kw, f"{model}: gpt-5 rejects max_tokens"


@pytest.mark.parametrize("model", ["gpt-5", "gpt-5.6", "openai/gpt-6"])
def test_gpt5_forced_to_chat_routes_system_to_developer(model):
    adapter, client = _stub_chat_forced(lambda **kw: _text_response())
    adapter.complete(model=model, system="be careful", messages=_hi(), max_tokens=8)
    roles = [m["role"] for m in client.chat.completions.create.call_args.kwargs["messages"]]
    assert "developer" in roles, f"{model}: gpt-5 needs a developer role"
    assert "system" not in roles, f"{model}: gpt-5 rejects the system role"


@pytest.mark.parametrize("model", ["gpt-5", "gpt-6", "gpt-9", "openai/gpt-5.6", "gpt-5.6"])
def test_gpt5_bare_and_prefixed_treated_as_reasoning(model):
    assert _is_reasoning_model(model) is True


@pytest.mark.parametrize("model", ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "gpt-4-turbo"])
def test_gpt4x_still_not_reasoning(model):
    assert _is_reasoning_model(model) is False


def test_gpt5_default_route_still_responses():
    # No override: a gpt-5 still routes to /v1/responses (unchanged by the fix).
    adapter, client = _stub_resp(lambda **kw: _resp(output=[_msg_item(_text_part("ok"))]))
    adapter.complete(model=G5, system=None, messages=_hi(), max_tokens=4096)
    client.responses.create.assert_called_once()
