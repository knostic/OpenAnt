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
