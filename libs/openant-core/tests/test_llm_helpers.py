"""Tests for ``utilities.llm.helpers``."""

from __future__ import annotations

import pytest

from utilities.llm import (
    CompletionResult,
    PhaseBinding,
    TextBlock,
    ToolUseBlock,
    simple_text,
)
from utilities.llm_client import TokenTracker


class _RecordingAdapter:
    """Minimal LLMAdapter stand-in that records calls."""

    name = "anthropic"
    supports_tools = True

    def __init__(self, response: CompletionResult):
        self._response = response
        self.calls: list[dict] = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls.append(
            {
                "model": model,
                "system": system,
                "messages": messages,
                "max_tokens": max_tokens,
                "tools": tools,
            }
        )
        return self._response

    def validate(self, model):
        pass


def _binding(adapter):
    return PhaseBinding(
        phase="analyze",
        adapter=adapter,
        model="claude-test",
        provider_name="anthropic",
    )


class TestSimpleText:
    def test_returns_text_from_response(self):
        adapter = _RecordingAdapter(
            CompletionResult(
                content=[TextBlock("the reply")],
                input_tokens=5,
                output_tokens=3,
                stop_reason="end_turn",
            )
        )
        out = simple_text(_binding(adapter), "the prompt", tracker=TokenTracker())
        assert out == "the reply"

    def test_sends_prompt_as_user_message(self):
        adapter = _RecordingAdapter(
            CompletionResult(content=[TextBlock("x")], input_tokens=1, output_tokens=1, stop_reason="end_turn")
        )
        simple_text(_binding(adapter), "hello world", tracker=TokenTracker())
        call = adapter.calls[0]
        assert len(call["messages"]) == 1
        msg = call["messages"][0]
        assert msg.role == "user"
        assert msg.content[0].text == "hello world"

    def test_uses_binding_model(self):
        adapter = _RecordingAdapter(
            CompletionResult(content=[TextBlock("x")], input_tokens=1, output_tokens=1, stop_reason="end_turn")
        )
        simple_text(_binding(adapter), "prompt", tracker=TokenTracker())
        assert adapter.calls[0]["model"] == "claude-test"

    def test_system_prompt_passed_through(self):
        adapter = _RecordingAdapter(
            CompletionResult(content=[TextBlock("x")], input_tokens=1, output_tokens=1, stop_reason="end_turn")
        )
        simple_text(
            _binding(adapter),
            "p",
            system="You are concise.",
            tracker=TokenTracker(),
        )
        assert adapter.calls[0]["system"] == "You are concise."

    def test_max_tokens_default_and_override(self):
        adapter = _RecordingAdapter(
            CompletionResult(content=[TextBlock("x")], input_tokens=1, output_tokens=1, stop_reason="end_turn")
        )
        simple_text(_binding(adapter), "p", tracker=TokenTracker())
        assert adapter.calls[0]["max_tokens"] == 8192

        simple_text(_binding(adapter), "p", max_tokens=128, tracker=TokenTracker())
        assert adapter.calls[1]["max_tokens"] == 128

    def test_records_tokens_against_tracker(self):
        adapter = _RecordingAdapter(
            CompletionResult(
                content=[TextBlock("x")],
                input_tokens=100,
                output_tokens=50,
                stop_reason="end_turn",
            )
        )
        tracker = TokenTracker()
        simple_text(_binding(adapter), "p", tracker=tracker)
        totals = tracker.get_totals()
        assert totals["total_input_tokens"] == 100
        assert totals["total_output_tokens"] == 50

    def test_records_against_binding_model_not_adapter_default(self):
        # Cost reports must reflect the model actually requested,
        # which for non-default providers may differ from anything
        # the adapter sees as a "default".
        adapter = _RecordingAdapter(
            CompletionResult(
                content=[TextBlock("x")],
                input_tokens=1,
                output_tokens=1,
                stop_reason="end_turn",
            )
        )
        tracker = TokenTracker()
        binding = PhaseBinding(
            phase="enhance",
            adapter=adapter,
            model="custom-model-name",
            provider_name="anthropic",
        )
        simple_text(binding, "p", tracker=tracker)
        summary = tracker.get_summary()
        assert summary["calls"][0]["model"] == "custom-model-name"

    def test_concatenates_multiple_text_blocks(self):
        # If a provider returns multiple text blocks (rare but
        # possible), simple_text joins them with newlines rather
        # than dropping any.
        adapter = _RecordingAdapter(
            CompletionResult(
                content=[TextBlock("first"), TextBlock("second")],
                input_tokens=1,
                output_tokens=1,
                stop_reason="end_turn",
            )
        )
        out = simple_text(_binding(adapter), "p", tracker=TokenTracker())
        assert out == "first\nsecond"

    def test_drops_non_text_blocks(self):
        # If a model returns a tool_use block in a text-only context
        # (model misbehaving — no tools were even passed), simple_text
        # drops it and returns whatever text was alongside.
        adapter = _RecordingAdapter(
            CompletionResult(
                content=[
                    ToolUseBlock(id="t_1", name="echo", input={}),
                    TextBlock("after the tool block"),
                ],
                input_tokens=1,
                output_tokens=1,
                stop_reason="end_turn",
            )
        )
        out = simple_text(_binding(adapter), "p", tracker=TokenTracker())
        assert out == "after the tool block"

    def test_no_tools_passed_to_adapter(self):
        # simple_text is the text-only helper; it must never pass
        # tools, otherwise an unsuspecting caller could trigger
        # tool_use blocks they don't know how to handle.
        adapter = _RecordingAdapter(
            CompletionResult(content=[TextBlock("x")], input_tokens=1, output_tokens=1, stop_reason="end_turn")
        )
        simple_text(_binding(adapter), "p", tracker=TokenTracker())
        assert adapter.calls[0]["tools"] is None
