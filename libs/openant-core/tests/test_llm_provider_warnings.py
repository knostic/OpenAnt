"""One-time-warning behaviors across adapters (PR #69 fixes H5 + M6 + M7).

* H5 — OpenAI: malformed ``tool_call.arguments`` warns once (instead of
  silently becoming ``{}``), then still falls back to ``{}`` so the
  turn proceeds.
* M6 — Anthropic: an unknown response block kind is dropped but warns
  once (instead of vanishing silently).
* M7 — the per-process "warned once" sets are cleared by
  ``reset_global_tracker`` / ``reset_warning_state`` so a fresh scan (or
  the next test) re-warns instead of staying silent forever.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import anthropic
import openai
import pytest

from utilities.llm import Message, TextBlock, ToolDef, ToolUseBlock
from utilities.llm.providers.anthropic import AnthropicAdapter
from utilities.llm.providers.openai import OpenAIAdapter
from utilities.llm_client import reset_global_tracker, reset_warning_state
from utilities.rate_limiter import reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_state():
    reset_rate_limiter()
    reset_warning_state()
    yield
    reset_rate_limiter()
    reset_warning_state()


def _hi():
    return [Message(role="user", content=[TextBlock("hi")])]


# ---------------------------------------------------------------------------
# H5 — OpenAI malformed tool arguments
# ---------------------------------------------------------------------------


def _openai_adapter_returning_tool_args(arguments: str) -> OpenAIAdapter:
    response = SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(
                content=None,
                tool_calls=[SimpleNamespace(
                    id="call_1",
                    type="function",
                    function=SimpleNamespace(name="echo", arguments=arguments),
                )],
            ),
            finish_reason="tool_calls",
        )],
        usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1),
    )
    client = MagicMock(spec=openai.OpenAI)
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(return_value=response)
    return OpenAIAdapter(_client=client)


def test_malformed_tool_json_warns_once_and_falls_back(capsys):
    adapter = _openai_adapter_returning_tool_args('{"oops": ')  # invalid JSON
    tools = [ToolDef(name="echo", description="e", input_schema={"type": "object"})]
    result = adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8, tools=tools)

    tool_uses = [b for b in result.content if isinstance(b, ToolUseBlock)]
    assert len(tool_uses) == 1
    assert tool_uses[0].input == {}, "H5: malformed args still fall back to empty dict"

    err = capsys.readouterr().err
    assert "echo" in err and "json" in err.lower(), "H5: must warn (not swallow silently)"

    # Warn-once: a second identical failure stays quiet.
    adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8, tools=tools)
    assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# M6 — Anthropic unknown block kind
# ---------------------------------------------------------------------------


def _anthropic_adapter_returning_blocks(blocks) -> AnthropicAdapter:
    response = SimpleNamespace(
        content=blocks,
        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
        stop_reason="end_turn",
    )
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages = MagicMock()
    client.messages.create = MagicMock(return_value=response)
    return AnthropicAdapter(_client=client)


def test_unknown_block_kind_dropped_but_warns_once(capsys):
    adapter = _anthropic_adapter_returning_blocks([
        SimpleNamespace(type="thinking", text="internal reasoning"),
        SimpleNamespace(type="text", text="the answer"),
    ])
    result = adapter.complete(model="m", system=None, messages=_hi(), max_tokens=8)

    # Unknown 'thinking' block dropped; the real text survives.
    kinds = [type(b).__name__ for b in result.content]
    assert kinds == ["TextBlock"]
    assert result.content[0].text == "the answer"

    err = capsys.readouterr().err
    assert "thinking" in err, "M6: a dropped unknown block must not be silent"

    adapter.complete(model="m", system=None, messages=_hi(), max_tokens=8)
    assert capsys.readouterr().err == "", "M6: warn-once, not per-call"


# ---------------------------------------------------------------------------
# M7 — reset clears the warn-once memory
# ---------------------------------------------------------------------------


def test_reset_global_tracker_rearms_warnings(capsys):
    """The exact finding: warn sets were NOT reset by reset_global_tracker,
    making 'warned once' order-dependent. Now they are."""
    from utilities.llm.providers.openai import _warn_bad_tool_json

    _warn_bad_tool_json("echo")
    assert "echo" in capsys.readouterr().err
    _warn_bad_tool_json("echo")
    assert capsys.readouterr().err == ""  # already warned this process

    reset_global_tracker()  # M7: must also clear one-time-warning state

    _warn_bad_tool_json("echo")
    assert "echo" in capsys.readouterr().err, "M7: reset_global_tracker must re-arm warnings"


def test_reset_warning_state_clears_all_adapters():
    # Smoke test that the aggregator reaches every adapter's reset hook
    # without raising (lazy, SDK-guarded import path).
    reset_warning_state()
