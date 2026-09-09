"""Tests for issue #561 — the empty-completion raise's cause clause
branches on the finish reason it already carries.

The chat path's raise interpolates `finish_reason={raw_finish!r}` (#527)
but the cause clause stays constant ("may have been filtered or the
response was malformed") regardless — for `finish_reason='length'` the
reply was not filtered or malformed (the output budget was consumed
before any visible content; the reasoning-model shape #512 root-caused),
and the module's own Responses path already says so ("may have been
truncated (reasoning consumed the budget) or filtered"). The string is
persisted verbatim into verify checkpoints and results_verified.json, so
an operator reading a length-stop row is pointed at moderation/gateway —
the #212 misdirection class.

The fix: the chat adapter branches the clause on the finish reason
(`length` → the budget wording); the anthropic adapter's identical
constant clause branches on `stop_reason == "max_tokens"`.
"""
from __future__ import annotations

import pytest

from utilities.llm import LLMResponseError
from utilities.llm.providers.openai import OpenAIAdapter
from utilities.llm.providers.anthropic import AnthropicAdapter


class _Usage:
    def __init__(self, p=10, c=5):
        self.prompt_tokens = p
        self.completion_tokens = c


class _ChatResp:
    def __init__(self, finish, usage=None):
        self.usage = usage
        self.choices = [type("C", (), {
            "message": type("M", (), {"content": None,
                                      "tool_calls": None})(),
            "finish_reason": finish})()]


class _AnthResp:
    def __init__(self, stop):
        self.stop_reason = stop
        self.content = []


def _openai_client(finish):
    class _C:
        class chat:
            class completions:
                @staticmethod
                def create(**kw):
                    return _ChatResp(finish)
    return _C()


class TestOpenAICauseClause:
    def test_length_stop_names_the_budget(self, monkeypatch):
        """finish_reason='length' → the cause clause names the consumed
        output budget, never 'filtered or malformed'."""
        adapter = OpenAIAdapter(api_key="sk-test",
                                _client=_openai_client("length"))
        from utilities.llm import Message, TextBlock
        with pytest.raises(LLMResponseError) as ei:
            adapter.complete(
                model="gpt-4o-mini", system=None,
                messages=[Message(role="user", content=[TextBlock("x")])],
                max_tokens=100)
        msg = str(ei.value)
        assert "finish_reason='length'" in msg
        assert "output budget was consumed" in msg, msg
        assert "filtered or the response was malformed" not in msg

    def test_stop_stop_keeps_the_filter_wording(self, monkeypatch):
        """finish_reason='stop' with no content → the unknown cause keeps
        the original wording (the honest non-assertion, #212)."""
        adapter = OpenAIAdapter(api_key="sk-test",
                                _client=_openai_client("stop"))
        from utilities.llm import Message, TextBlock
        with pytest.raises(LLMResponseError) as ei:
            adapter.complete(
                model="gpt-4o-mini", system=None,
                messages=[Message(role="user", content=[TextBlock("x")])],
                max_tokens=100)
        msg = str(ei.value)
        assert "finish_reason='stop'" in msg
        assert "filtered or the response was malformed" in msg
        assert "output budget was consumed" not in msg


class TestAnthropicCauseClause:
    def _adapter(self, stop):
        class _Client:
            class messages:
                @staticmethod
                def create(**kw):
                    return _AnthResp(stop)
        return AnthropicAdapter(api_key="sk-test", _client=_Client())

    def test_max_tokens_names_the_budget(self):
        """stop_reason='max_tokens' with no content → the budget wording."""
        with pytest.raises(LLMResponseError) as ei:
            self._adapter("max_tokens").complete(
                model="claude-test", system=None,
                messages=[__import__("utilities.llm", fromlist=["Message"])
                          .Message(role="user", content=[
                              __import__("utilities.llm", fromlist=["TextBlock"])
                              .TextBlock("x")])],
                max_tokens=100)
        msg = str(ei.value)
        assert "stop_reason='max_tokens'" in msg
        assert "output budget was consumed" in msg, msg
        assert "filtered or the response was malformed" not in msg

    def test_end_turn_keeps_the_filter_wording(self):
        with pytest.raises(LLMResponseError) as ei:
            self._adapter("end_turn").complete(
                model="claude-test", system=None,
                messages=[__import__("utilities.llm", fromlist=["Message"])
                          .Message(role="user", content=[
                              __import__("utilities.llm", fromlist=["TextBlock"])
                              .TextBlock("x")])],
                max_tokens=100)
        msg = str(ei.value)
        assert "filtered or the response was malformed" in msg
        assert "output budget was consumed" not in msg


class TestClassifierContract:
    """The refute round's fold: pin the retry/error-info classifiers against
    the NEW budget-wording strings (the contract this diff could have
    broken — previously verified only by inspection)."""

    def test_budget_wording_still_retryable(self):
        """The classifier's STRING branch carries the raw raise text (the
        analyzer path stores str(e)); the dict branch keys on the typed
        empty_completion classification. Both real shapes must keep the
        transient classification under the new budget wording."""
        from utilities.rate_limiter import is_retryable_error

        for msg in (
            "OpenAIAdapter returned an empty completion (no text or tool "
            "calls; finish_reason='length'); the output budget was consumed "
            "before any visible content (reasoning models spend it on "
            "hidden reasoning)",
            "AnthropicAdapter returned no usable content (empty completion; "
            "stop_reason='max_tokens'); the output budget was consumed "
            "before any visible content (reasoning models spend it on "
            "hidden reasoning)",
        ):
            # The string branch (the raw raise text):
            assert is_retryable_error(msg), msg
        # The dict branch (the typed classification, as built by
        # context_enhancer._build_error_info):
        assert is_retryable_error({"type": "empty_completion",
                                   "message": "any wording"}), (
            "the typed empty_completion dict must stay retryable")
