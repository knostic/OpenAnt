"""Google-adapter-specific tests (PR #69 fixes C1 + H1).

* C1 — Gemini matches a ``function_response`` to its ``function_call``
  by NAME, not id. The pipeline now carries the originating tool's name
  on ``ToolResultBlock.name``; the adapter must send THAT as the
  function_response name, not the synthesised ``gemini_<name>_<idx>`` id.
* H1 — a 429 reports to the process-global rate limiter so sibling
  workers back off.
"""

from __future__ import annotations

import pytest

from utilities.llm import LLMRateLimitError, Message, TextBlock, ToolResultBlock
from utilities.llm.providers.google import _message_to_gemini, _name_for_tool_result
from utilities.llm_client import reset_warning_state
from utilities.rate_limiter import get_rate_limiter, reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_state():
    reset_rate_limiter()
    reset_warning_state()
    yield
    reset_rate_limiter()
    reset_warning_state()


# ---------------------------------------------------------------------------
# C1 — function name survives the round trip
# ---------------------------------------------------------------------------


def test_name_for_tool_result_prefers_name():
    # When the pipeline supplies the originating tool name, use it.
    block = ToolResultBlock(tool_use_id="gemini_search_code_0", name="search_code", content="x")
    assert _name_for_tool_result(block) == "search_code"


def test_name_for_tool_result_falls_back_to_id_when_no_name():
    block = ToolResultBlock(tool_use_id="legacy_id", content="x")
    assert _name_for_tool_result(block) == "legacy_id"


def test_function_response_carries_function_name():
    """The whole point of C1: the function_response Part Gemini receives
    must be named after the original function (``search_code``), not the
    synthesised id (``gemini_search_code_0``) — otherwise Gemini can't
    match the result to its call."""
    msg = Message(
        role="user",
        content=[ToolResultBlock(
            tool_use_id="gemini_search_code_0",
            name="search_code",
            content='{"hits": 1}',
        )],
    )
    content = _message_to_gemini(msg)
    part = content.parts[0]
    assert part.function_response is not None
    assert part.function_response.name == "search_code", (
        "C1: Gemini matches function_response to function_call by NAME; "
        "sending the synthesised id would never match the original call"
    )


# ---------------------------------------------------------------------------
# H1 — rate-limiter coordination
# ---------------------------------------------------------------------------


def test_rate_limit_reports_to_global_limiter():
    from tests._llm_factories.google import make_adapter

    adapter = make_adapter("rate_limit")  # scripted to raise a 429 (retry_after=7)
    limiter = get_rate_limiter()
    assert not limiter.is_in_backoff()
    with pytest.raises(LLMRateLimitError):
        adapter.complete(
            model="gemini-2.5-pro",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hi")])],
            max_tokens=8,
        )
    assert limiter.is_in_backoff(), "Google 429 must trigger global backoff (H1)"


def test_present_candidate_with_empty_parts_raises_not_clean_end_turn():
    # A candidate present with a clean STOP finish but NO usable parts (thinking-only
    # or blank) must raise -- returning an empty end_turn reads as a clean, passing
    # result for a security tool (silent false-negative). Mirrors the no-candidates
    # guard and the Anthropic/OpenAI empty-content guards.
    from types import SimpleNamespace
    from utilities.llm import LLMResponseError
    from utilities.llm.providers.google import _response_to_unified
    cand = SimpleNamespace(finish_reason="STOP", content=SimpleNamespace(parts=[]))
    resp = SimpleNamespace(candidates=[cand], usage_metadata=SimpleNamespace(
        prompt_token_count=1, candidates_token_count=0, total_token_count=1))
    with pytest.raises(LLMResponseError):
        _response_to_unified(resp)


def test_empty_max_tokens_candidate_raises_budget_wording():
    # #569: the budget marker is DETERMINISTIC-CLASS-ONLY — a MAX_TOKENS
    # empty candidate carries "consumed the token budget" (the raised-cap
    # retry class); the other empty shapes must NOT (producer-side pin —
    # the #569 review round: the classifier must not over-match).
    from types import SimpleNamespace
    from utilities.llm import LLMResponseError
    from utilities.llm.providers.google import _response_to_unified
    cand = SimpleNamespace(finish_reason="MAX_TOKENS", content=SimpleNamespace(parts=[]))
    resp = SimpleNamespace(candidates=[cand], usage_metadata=SimpleNamespace(
        prompt_token_count=1, candidates_token_count=0, total_token_count=1))
    with pytest.raises(LLMResponseError, match="consumed the token budget"):
        _response_to_unified(resp)


def test_empty_stop_candidate_has_no_budget_wording():
    # #569 producer-side pin: a filtered/blank empty candidate keeps the
    # #292 same-cap rationale — its raise must NOT carry the marker.
    from types import SimpleNamespace
    from utilities.llm import LLMResponseError
    from utilities.llm.providers.google import _response_to_unified
    cand = SimpleNamespace(finish_reason="STOP", content=SimpleNamespace(parts=[]))
    resp = SimpleNamespace(candidates=[cand], usage_metadata=SimpleNamespace(
        prompt_token_count=1, candidates_token_count=0, total_token_count=1))
    with pytest.raises(LLMResponseError) as ei:
        _response_to_unified(resp)
    assert "consumed the token budget" not in str(ei.value)
    assert "filtered" in str(ei.value)


def test_tool_use_only_candidate_is_valid_not_empty():
    # Control: a function_call part with no text is a VALID response (content
    # non-empty) and must NOT be caught by the empty-content guard.
    from types import SimpleNamespace
    from utilities.llm.providers.google import _response_to_unified
    fc = SimpleNamespace(name="do_it", args={"x": 1}, id="g1")
    part = SimpleNamespace(text=None, function_call=fc)
    cand = SimpleNamespace(finish_reason="STOP", content=SimpleNamespace(parts=[part]))
    resp = SimpleNamespace(candidates=[cand], usage_metadata=SimpleNamespace(
        prompt_token_count=1, candidates_token_count=1, total_token_count=2))
    result = _response_to_unified(resp)
    assert result.content and result.stop_reason == "tool_use"


# ---------------------------------------------------------------------------
# The real-transport guard (#576 review follow-up 4b): the suite's factories
# INJECT httpx errors, so nothing detects a future google-genai default-
# transport flip (the anthropic/openai 3.x SDKs already moved to httpx2; the
# genai sync client subclasses httpx.Client TODAY and references httpx2 in
# the same module — the drift direction is live). These tests drive the
# adapter through the SDK's ACTUAL default transport: a REAL genai.Client
# against an unroutable endpoint, no injected client, no factory stubs. A
# transport flip breaks the exception CLASS IDENTITY — the raised error no
# longer matches the adapter's `except httpx.*` clauses — and these tests
# go RED the day the default transport's error classes diverge.
# ---------------------------------------------------------------------------

def _real_transport_adapter():
    """A GoogleAdapter around a REAL SDK client: hermetic (a dummy key, an
    unroutable endpoint via the SDK's own HttpOptions, zero network beyond
    the refused connection), max_retries=0 so the failure is immediate."""
    from utilities.llm.providers.google import GoogleAdapter
    return GoogleAdapter(api_key="test-key",
                         base_url="http://127.0.0.1:9", max_retries=0)


def test_real_transport_connection_refused_maps_typed():
    """The conn-refused class through the SDK's DEFAULT transport (the #576
    probe shape, made permanent): a real genai.Client raises whatever its
    real transport raises; the adapter must map it to LLMConnectionError.
    RED on a transport flip (the error no longer matches the httpx clauses)."""
    from utilities.llm import Message, TextBlock
    from utilities.llm.adapter import LLMConnectionError
    adapter = _real_transport_adapter()
    with pytest.raises(LLMConnectionError):
        adapter.complete(model="gemini-2.5-pro", system=None,
                         messages=[Message(role="user",
                                           content=[TextBlock("hi")])],
                         max_tokens=8)


def test_real_transport_validate_maps_typed():
    """The same guard on the validate() path (its own except ladder)."""
    from utilities.llm.adapter import LLMConnectionError
    adapter = _real_transport_adapter()
    with pytest.raises(LLMConnectionError):
        adapter.validate(model="gemini-2.5-pro")


def test_real_transport_half_open_connection_maps_typed():
    """The accept-then-close case (the #576 review's second shape): a
    listener that accepts and immediately closes. If the SDK's default
    transport raises a class the adapter's catch list MISSES (e.g.
    httpx.RemoteProtocolError / httpx.ReadError), the error escapes the
    LLMConnectionError mapping — this test goes RED, naming the missing
    clause. Today's conn-refused-only list is asserted live, not assumed."""
    import socket
    import threading
    from utilities.llm import Message, TextBlock
    from utilities.llm.adapter import LLMError

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]

    def accept_and_close():
        for _ in range(8):  # the SDK retries 0; cover races anyway
            try:
                conn, _ = listener.accept()
                conn.close()
            except OSError:
                return

    t = threading.Thread(target=accept_and_close, daemon=True)
    t.start()
    try:
        from utilities.llm.providers.google import GoogleAdapter
        adapter = GoogleAdapter(api_key="test-key",
                                base_url=f"http://127.0.0.1:{port}",
                                max_retries=0)
        try:
            adapter.complete(model="gemini-2.5-pro", system=None,
                             messages=[Message(role="user",
                                               content=[TextBlock("hi")])],
                             max_tokens=8)
        except LLMError:
            pass  # typed mapping held — the guard's pass condition
        # Anything NOT an LLMError escapes untyped: pytest.raises nothing,
        # so the raw exception propagates and THIS test fails with the
        # un-typed error's own traceback — naming exactly which transport
        # class the adapter's catch list is missing.
        finally:
            listener.close()
        t.join(timeout=2)
    finally:
        listener.close()
