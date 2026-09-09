"""Tests for issue #564 — the anthropic adapter's empty-completion raise
carries the rejected reply's usage.

The #537 usage carriage existed on the openai sites only; the anthropic
guard raised before reading the usage the successful return reads two
lines below (the same response object) — recording 0/0 for a call the
provider may have billed.
"""
from __future__ import annotations

import pytest

from utilities.llm import LLMResponseError, Message, TextBlock
from utilities.llm.providers.anthropic import AnthropicAdapter


class _Usage:
    def __init__(self, i=11, o=7):
        self.input_tokens = i
        self.output_tokens = o


class _Resp:
    def __init__(self, stop, usage):
        self.stop_reason = stop
        self.content = []
        self.usage = usage


def _make_client(resp):
    """A client whose messages.create returns the canned response."""
    class _messages:
        @staticmethod
        def create(**kw):
            return resp
    return type("C", (), {"messages": _messages})()


def _adapter(resp):
    return AnthropicAdapter(api_key="sk-test", _client=_make_client(resp))


def _msg():
    return [Message(role="user", content=[TextBlock("x")])]


class TestAnthropicUsageCarriage:
    def test_raise_carries_usage(self):
        """THE #564 regression: the error carries the rejected reply's
        tokens (the openai sites' #537 shape)."""
        adapter = _adapter(_Resp("end_turn", _Usage(11, 7)))
        with pytest.raises(LLMResponseError) as ei:
            adapter.complete(model="claude-test", system=None,
                             messages=_msg(), max_tokens=100)
        assert ei.value.input_tokens == 11
        assert ei.value.output_tokens == 7

    def test_no_usage_defaults_zero(self):
        adapter = _adapter(_Resp("end_turn", None))
        with pytest.raises(LLMResponseError) as ei:
            adapter.complete(model="claude-test", system=None,
                             messages=_msg(), max_tokens=100)
        assert ei.value.input_tokens == 0
        assert ei.value.output_tokens == 0

    def test_recorded_before_reraise(self):
        """simple_completion records the rejected call's usage — the
        tracker total carries it (the #537 contract, now on this adapter)."""
        from utilities.llm.helpers import simple_completion
        from utilities.llm import PhaseBinding
        from utilities.llm_client import TokenTracker

        adapter = _adapter(_Resp("end_turn", _Usage(30, 9)))
        tracker = TokenTracker()
        binding = PhaseBinding(phase="p", adapter=adapter, model="claude-test",
                               provider_name="anthropic")
        with pytest.raises(LLMResponseError):
            simple_completion(binding, "hi", tracker=tracker)
        assert tracker.total_input_tokens >= 30
        assert tracker.total_output_tokens >= 9
