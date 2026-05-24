"""Sanity tests for the LLM adapter interface module itself.

These tests don't need an adapter implementation — they pin the
shape of the public surface so a future refactor can't silently
drop a class, rename a field, or break the error hierarchy without
the test suite noticing.

The behavioral guarantees adapters must provide live in
``test_llm_adapter_contract.py``.
"""

from __future__ import annotations

import pytest

from utilities.llm import (
    CompletionResult,
    LLMAdapter,
    LLMAuthError,
    LLMConnectionError,
    LLMError,
    LLMNotFoundError,
    LLMRateLimitError,
    LLMResponseError,
    Message,
    TextBlock,
    ToolDef,
    ToolResultBlock,
    ToolUseBlock,
)


class TestContentBlocks:
    """Block types are the contract — adapters MUST emit only these three.

    Tests pin: each block is frozen (mutating a result mid-pipeline
    is a foot-gun), the three kinds are distinct types (so adapters
    can't blur the boundary), and the unified union covers exactly
    those three.
    """

    def test_text_block_is_frozen(self):
        block = TextBlock(text="hi")
        with pytest.raises(Exception):
            block.text = "mutated"  # type: ignore[misc]

    def test_tool_use_block_is_frozen(self):
        block = ToolUseBlock(id="t_1", name="echo", input={"x": 1})
        with pytest.raises(Exception):
            block.name = "renamed"  # type: ignore[misc]

    def test_tool_result_block_is_frozen(self):
        block = ToolResultBlock(tool_use_id="t_1", content="42")
        with pytest.raises(Exception):
            block.content = "47"  # type: ignore[misc]

    def test_three_distinct_block_types(self):
        # If a future change collapses two block types into one,
        # the isinstance checks the pipeline uses become wrong.
        assert TextBlock is not ToolUseBlock
        assert TextBlock is not ToolResultBlock
        assert ToolUseBlock is not ToolResultBlock


class TestMessage:
    def test_message_carries_block_list(self):
        msg = Message(
            role="assistant",
            content=[
                TextBlock("thinking..."),
                ToolUseBlock(id="t_1", name="echo", input={"text": "hi"}),
            ],
        )
        assert msg.role == "assistant"
        assert len(msg.content) == 2

    def test_message_is_frozen(self):
        msg = Message(role="user", content=[TextBlock("hi")])
        with pytest.raises(Exception):
            msg.role = "assistant"  # type: ignore[misc]


class TestToolDef:
    def test_tool_def_carries_schema(self):
        td = ToolDef(
            name="search",
            description="Search the codebase",
            input_schema={
                "type": "object",
                "properties": {"q": {"type": "string"}},
                "required": ["q"],
            },
        )
        assert td.name == "search"
        assert td.input_schema["required"] == ["q"]


class TestCompletionResult:
    def test_completion_result_has_required_fields(self):
        result = CompletionResult(
            content=[TextBlock("done")],
            input_tokens=10,
            output_tokens=5,
            stop_reason="end_turn",
        )
        assert result.input_tokens == 10
        assert result.output_tokens == 5
        assert result.stop_reason == "end_turn"
        # raw defaults to None and stays out of repr so logging
        # adapters don't accidentally dump huge SDK payloads.
        assert result.raw is None
        assert "raw" not in repr(result)

    def test_completion_result_carries_raw_when_supplied(self):
        sentinel = object()
        result = CompletionResult(
            content=[],
            input_tokens=0,
            output_tokens=0,
            stop_reason="end_turn",
            raw=sentinel,
        )
        assert result.raw is sentinel


class TestErrorHierarchy:
    """The retry/backoff logic keys on these classes. Don't reshuffle."""

    @pytest.mark.parametrize(
        "exc_cls",
        [
            LLMAuthError,
            LLMRateLimitError,
            LLMConnectionError,
            LLMNotFoundError,
            LLMResponseError,
        ],
    )
    def test_subclass_of_base(self, exc_cls):
        assert issubclass(exc_cls, LLMError)

    def test_rate_limit_carries_retry_after(self):
        err = LLMRateLimitError("slow down", retry_after=12.5)
        assert err.retry_after == 12.5
        assert "slow down" in str(err)

    def test_rate_limit_retry_after_optional(self):
        err = LLMRateLimitError("slow down")
        assert err.retry_after is None


class TestAdapterProtocol:
    """Pin the protocol shape so adapters can't drift."""

    def test_minimal_dummy_satisfies_protocol(self):
        # A trivial conforming implementation. If this stops being
        # recognised as an LLMAdapter, the protocol's required
        # surface has changed and every existing adapter needs
        # auditing.
        class Dummy:
            name = "dummy"
            supports_tools = False

            def complete(self, *, model, system, messages, max_tokens, tools=None):
                return CompletionResult(
                    content=[TextBlock("ok")],
                    input_tokens=1,
                    output_tokens=1,
                    stop_reason="end_turn",
                )

            def validate(self, model):
                return None

        assert isinstance(Dummy(), LLMAdapter)

    def test_missing_method_fails_protocol_check(self):
        class NoValidate:
            name = "x"
            supports_tools = False

            def complete(self, *, model, system, messages, max_tokens, tools=None):
                return CompletionResult(
                    content=[], input_tokens=0, output_tokens=0, stop_reason="end_turn"
                )

        # Protocol check should fail because validate() is missing.
        assert not isinstance(NoValidate(), LLMAdapter)


class TestProvidersRegistry:
    """The dispatcher in ``providers/__init__.py`` is part of the contract.

    Adding an adapter to the build means editing ``get_adapter_class``
    here AND ``known_provider_types``. These tests catch a missed edit.
    """

    def test_anthropic_is_resolvable(self):
        # The actual class lands in Phase 2; for now we just confirm
        # the dispatcher knows the name. When the class shows up, the
        # contract tests in ``test_llm_adapter_contract.py`` take over.
        from utilities.llm.providers import known_provider_types

        assert "anthropic" in known_provider_types()

    def test_unknown_type_raises_with_helpful_message(self):
        from utilities.llm.providers import get_adapter_class

        with pytest.raises(ValueError) as exc_info:
            get_adapter_class("bogus-provider")
        # Message must point contributors at the recipe doc.
        assert "HOW_TO_ADD_AN_ADAPTER.md" in str(exc_info.value)
