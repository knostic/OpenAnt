"""Contract tests every LLM adapter must satisfy.

This module defines the BAR a provider plugin has to clear to be
considered correct. The tests stub out the provider's SDK boundary
and feed each adapter the same scripted scenarios:

* Plain text completion — token counts and content blocks come back
  right, stop reason is ``end_turn``.
* Tool-use round trip — assistant emits ``ToolUseBlock``, user turn
  carries the matching ``ToolResultBlock``, conversation continues.
  Skipped on adapters with ``supports_tools=False``.
* Auth failure mapping — provider's auth exception → ``LLMAuthError``.
* Rate limit mapping — provider's 429 → ``LLMRateLimitError`` with
  ``retry_after`` populated when the provider supplies it.
* Connection failure mapping → ``LLMConnectionError``.
* Model-not-found mapping → ``LLMNotFoundError``.
* ``validate()`` succeeds against a healthy stub and surfaces the
  right error class against an unhealthy one.
* ``tools=...`` on a non-tool adapter raises ``LLMResponseError``
  rather than silently dropping the tools.

A new adapter wires itself in by adding a row to the ``ADAPTERS``
parametrize fixture, plus providing a small "scenario factory" that
returns a stubbed-SDK-equipped instance for each scenario. The bulk
of the test logic stays here — adapters don't get to redefine what
"correct" means.

These tests never hit the network. They use unittest.mock to stub
each provider's SDK entry point.
"""

from __future__ import annotations

from typing import Callable

import pytest

from utilities.llm import (
    LLMAdapter,
    LLMAuthError,
    LLMConnectionError,
    LLMNotFoundError,
    LLMRateLimitError,
    LLMResponseError,
    Message,
    TextBlock,
    ToolDef,
    ToolResultBlock,
    ToolUseBlock,
)
from utilities.rate_limiter import reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_global_rate_limiter():
    """The Anthropic adapter reports 429/529 to a process-level
    singleton rate limiter that puts ALL future calls into backoff
    for ~30s. Without a reset, the rate-limit scenario in this
    harness leaks 30 seconds of sleep into every subsequent test.
    """
    reset_rate_limiter()
    yield
    reset_rate_limiter()


# ---------------------------------------------------------------------------
# Scenario factories
# ---------------------------------------------------------------------------
#
# Each adapter contributes a small factory module that knows how to:
#   1. Construct an adapter wired to a fake SDK.
#   2. Script the fake SDK for a given scenario name.
#
# The harness below calls the factory once per scenario, then asserts
# on the adapter's behavior. The factory is the ONLY place
# provider-specific knowledge lives in this file.
#
# Factory contract:
#
#   make_adapter(scenario: str) -> LLMAdapter
#
# Scenarios:
#   "text"               — one-shot text response
#   "tool_use_round"     — tool_use → tool_result → end_turn
#   "auth_error"         — first call raises adapter's auth exc
#   "rate_limit"         — first call raises 429-equivalent (retry_after=7)
#   "connection_error"   — first call raises network exc
#   "model_not_found"    — first call raises model-404 exc
#   "validate_ok"        — validate() succeeds
#   "validate_auth_fail" — validate() raises auth
#
# Factories live in ``tests/_llm_factories/<provider>.py`` so they
# can stay near the test module without polluting the production
# package.


def _anthropic_factory():
    from tests._llm_factories.anthropic import make_adapter

    return make_adapter


def _openai_factory():
    from tests._llm_factories.openai import make_adapter

    return make_adapter


def _google_factory():
    from tests._llm_factories.google import make_adapter

    return make_adapter


# Each row: (display_name, scenario_factory_callable)
# Add a row when registering a new adapter.
ADAPTERS: list[tuple[str, Callable[[str], LLMAdapter]]] = [
    ("anthropic", _anthropic_factory()),
    ("openai", _openai_factory()),
    ("google", _google_factory()),
]


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,make", ADAPTERS, ids=[name for name, _ in ADAPTERS])
class TestAdapterContract:
    """Every adapter must satisfy every test in this class."""

    # ---- Surface ----------------------------------------------------------

    def test_satisfies_protocol(self, name, make):
        adapter = make("text")
        assert isinstance(adapter, LLMAdapter), (
            f"{name} must satisfy the LLMAdapter protocol; check class-level "
            f"`name` and `supports_tools` attributes plus complete/validate methods."
        )

    def test_has_name_string(self, name, make):
        adapter = make("text")
        assert isinstance(adapter.name, str) and adapter.name, (
            f"{name}: adapter.name must be a non-empty string"
        )

    def test_supports_tools_is_bool(self, name, make):
        adapter = make("text")
        assert isinstance(adapter.supports_tools, bool), (
            f"{name}: supports_tools must be bool, not derived per-call"
        )

    # ---- Happy path: text completion --------------------------------------

    def test_text_completion(self, name, make):
        adapter = make("text")
        result = adapter.complete(
            model="test-model",
            system=None,
            messages=[Message(role="user", content=[TextBlock("hello")])],
            max_tokens=64,
        )

        # Exactly one text block, with the scripted reply.
        assert len(result.content) == 1
        assert isinstance(result.content[0], TextBlock)
        assert result.content[0].text == "hi there"

        # Token counts surfaced from the stub's usage payload.
        assert result.input_tokens == 3
        assert result.output_tokens == 5

        # Normalised stop reason.
        assert result.stop_reason == "end_turn"

    # ---- Tool use round trip ----------------------------------------------

    def test_tool_use_round_trip(self, name, make):
        adapter = make("tool_use_round")
        if not adapter.supports_tools:
            pytest.skip(f"{name}: supports_tools=False; round trip not applicable")

        tools = [
            ToolDef(
                name="echo",
                description="Echo input",
                input_schema={
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            )
        ]

        # Turn 1: model emits tool_use.
        first = adapter.complete(
            model="test-model",
            system="You are helpful.",
            messages=[Message(role="user", content=[TextBlock("call echo")])],
            max_tokens=64,
            tools=tools,
        )
        assert first.stop_reason == "tool_use"
        tool_uses = [b for b in first.content if isinstance(b, ToolUseBlock)]
        assert len(tool_uses) == 1, (
            f"{name}: expected exactly one ToolUseBlock in the assistant content"
        )
        tu = tool_uses[0]
        assert tu.name == "echo"
        assert tu.input == {"text": "hello"}
        assert isinstance(tu.id, str) and tu.id, (
            f"{name}: ToolUseBlock.id must be a non-empty string"
        )

        # Turn 2: we send tool result, model finishes.
        second = adapter.complete(
            model="test-model",
            system="You are helpful.",
            messages=[
                Message(role="user", content=[TextBlock("call echo")]),
                Message(role="assistant", content=list(first.content)),
                Message(
                    role="user",
                    content=[ToolResultBlock(tool_use_id=tu.id, content='"hello"')],
                ),
            ],
            max_tokens=64,
            tools=tools,
        )
        assert second.stop_reason == "end_turn"
        assert any(isinstance(b, TextBlock) for b in second.content)

    def test_tools_rejected_when_unsupported(self, name, make):
        adapter = make("text")
        if adapter.supports_tools:
            pytest.skip(f"{name}: supports_tools=True; this guard doesn't apply")

        with pytest.raises(LLMResponseError):
            adapter.complete(
                model="test-model",
                system=None,
                messages=[Message(role="user", content=[TextBlock("hi")])],
                max_tokens=64,
                tools=[ToolDef(name="x", description="x", input_schema={"type": "object"})],
            )

    # ---- Error mapping ----------------------------------------------------

    def test_auth_error_mapped(self, name, make):
        adapter = make("auth_error")
        with pytest.raises(LLMAuthError):
            adapter.complete(
                model="test-model",
                system=None,
                messages=[Message(role="user", content=[TextBlock("hi")])],
                max_tokens=8,
            )

    def test_rate_limit_mapped(self, name, make):
        adapter = make("rate_limit")
        with pytest.raises(LLMRateLimitError) as exc_info:
            adapter.complete(
                model="test-model",
                system=None,
                messages=[Message(role="user", content=[TextBlock("hi")])],
                max_tokens=8,
            )
        assert exc_info.value.retry_after == 7

    def test_connection_error_mapped(self, name, make):
        adapter = make("connection_error")
        with pytest.raises(LLMConnectionError):
            adapter.complete(
                model="test-model",
                system=None,
                messages=[Message(role="user", content=[TextBlock("hi")])],
                max_tokens=8,
            )

    def test_model_not_found_mapped(self, name, make):
        adapter = make("model_not_found")
        with pytest.raises(LLMNotFoundError):
            adapter.complete(
                model="ghost-model",
                system=None,
                messages=[Message(role="user", content=[TextBlock("hi")])],
                max_tokens=8,
            )

    # ---- validate() -------------------------------------------------------

    def test_validate_ok(self, name, make):
        adapter = make("validate_ok")
        # Returns None on success; we just want no exception.
        assert adapter.validate(model="test-model") is None

    def test_validate_auth_failure_mapped(self, name, make):
        adapter = make("validate_auth_fail")
        with pytest.raises(LLMAuthError):
            adapter.validate(model="test-model")
