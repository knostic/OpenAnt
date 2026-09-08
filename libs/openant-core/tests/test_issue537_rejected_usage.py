"""Tests for issue #537 — a rejected completion's returned usage is not lost.

The empty-completion raise in providers/openai.py fires BEFORE the usage
read, and simple_completion records usage only after complete() returns —
so a rejected reply's usage is discarded un-read, and a verify conversation
that fails on a later turn loses its earlier turns' accounting on the
exceptional exit.

The fix: LLMResponseError carries the rejected reply's usage (when the
provider supplied it), and helpers.simple_completion records it via
add_prior_usage before re-raising.
"""
from __future__ import annotations

import pytest

from utilities.llm import (
    CompletionResult,
    LLMAuthError,
    LLMResponseError,
    PhaseBinding,
    TextBlock,
)
from utilities.llm_client import TokenTracker


class _Usage:
    def __init__(self, prompt_tokens, completion_tokens):
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class _Resp:
    def __init__(self, usage, finish="stop"):
        self.usage = usage
        self.choices = [type("C", (), {"message": type("M", (), {"content": None}),
                                       "finish_reason": finish})()]


class RejectingAdapter:
    """Mimics the provider contract: the raise path fires INSIDE complete
    (the real openai.py raises before returning) — with the usage attached
    per the #537 fix."""
    name = "openai"
    supports_tools = True

    def __init__(self, usage):
        self._usage = usage
        self.calls = 0

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls += 1
        raise LLMResponseError(
            "openai returned an empty completion",
            input_tokens=getattr(self._usage, "prompt_tokens", 0),
            output_tokens=getattr(self._usage, "completion_tokens", 0))

    def validate(self, model):
        pass


class OkThenRejectAdapter:
    name = "openai"
    supports_tools = True

    def __init__(self, usage):
        self._usage = usage
        self.n = 0

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.n += 1
        if self.n == 1:
            return CompletionResult(
                content=[TextBlock("ok")], input_tokens=10, output_tokens=5,
                stop_reason="end_turn")
        raise LLMResponseError(
            "openai returned an empty completion",
            input_tokens=getattr(self._usage, "prompt_tokens", 0),
            output_tokens=getattr(self._usage, "completion_tokens", 0))

    def validate(self, model):
        pass


def _binding(adapter, model="m"):
    return PhaseBinding(phase="p", adapter=adapter, model=model,
                        provider_name="openai")


class TestRaiseCarriesUsage:
    def test_response_error_carries_usage(self):
        """The rejected reply's usage is ON the error — inspectable by the
        caller's exceptional path."""
        adapter = RejectingAdapter(_Usage(120, 34))
        tracker = TokenTracker()
        with pytest.raises(LLMResponseError) as ei:
            from utilities.llm.helpers import simple_completion
            simple_completion(_binding(adapter), "hi", tracker=tracker)
        err = ei.value
        assert getattr(err, "input_tokens", None) == 120
        assert getattr(err, "output_tokens", None) == 34

    def test_recorded_before_reraise(self):
        """simple_completion records the rejected call's usage via
        add_prior_usage — the tracker total carries it (never $0 for a
        call the provider billed)."""
        adapter = RejectingAdapter(_Usage(120, 34))
        tracker = TokenTracker()
        with pytest.raises(LLMResponseError):
            from utilities.llm.helpers import simple_completion
            simple_completion(_binding(adapter), "hi", tracker=tracker)
        assert tracker.total_input_tokens >= 120
        assert tracker.total_output_tokens >= 34

    def test_ok_then_rejected_keeps_earlier_turn(self):
        """A conversation that succeeds then rejects: the earlier turn's
        usage survives (recorded at its own completion), the rejected
        turn's usage recorded at the raise."""
        adapter = OkThenRejectAdapter(_Usage(77, 21))
        tracker = TokenTracker()
        from utilities.llm.helpers import simple_completion
        simple_completion(_binding(adapter), "first", tracker=tracker)
        with pytest.raises(LLMResponseError):
            simple_completion(_binding(adapter), "second", tracker=tracker)
        # 10+5 from the ok turn; 77+21 from the rejected turn.
        assert tracker.total_input_tokens == 10 + 77
        assert tracker.total_output_tokens == 5 + 21

    def test_auth_error_unchanged(self):
        """LLMAuthError has no usage semantics — nothing to record."""
        class BoomAuth(RejectingAdapter):
            def complete(self, **kw):
                raise LLMAuthError("bad key")

        tracker = TokenTracker()
        with pytest.raises(LLMAuthError):
            from utilities.llm.helpers import simple_completion
            simple_completion(_binding(BoomAuth(None)), "x", tracker=tracker)
        assert tracker.total_input_tokens == 0


class TestRealProviderSite:
    """The real openai.py raise (not the fake-adapter contract): a response
    object with usage but no usable content -> the error carries it."""

    def test_chat_path_empty_completion_carries_usage(self, monkeypatch):
        import utilities.llm.providers.openai as oa

        class _Client:
            class chat:
                class completions:
                    @staticmethod
                    def create(**kw):
                        return _Resp(_Usage(55, 13))

        adapter = oa.OpenAIAdapter(api_key="sk-test",
                                   _client=_Client())
        from utilities.llm import Message, TextBlock
        import pytest as _pytest
        with _pytest.raises(LLMResponseError) as ei:
            adapter.complete(
                model="gpt-4o-mini", system=None,
                messages=[Message(role="user", content=[TextBlock("x")])],
                max_tokens=100)
        assert ei.value.input_tokens == 55
        assert ei.value.output_tokens == 13
