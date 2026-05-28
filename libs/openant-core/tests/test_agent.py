"""Regression tests for the agentic enhancer input budget.

The agentic context enhancer built the LLM conversation with no input
token/char budget: ``primary_code`` was inlined verbatim into the initial
user prompt, and raw, untruncated tool results were appended to ``messages``
every iteration. On a large unit the constructed input grew unbounded across
iterations until it overflowed the model context (400 error), losing the
enhancement.

Operative guard: an INPUT BUDGET applied at the consumption points.
  - ``get_user_prompt`` caps the inlined ``primary_code`` (prompts.py).
  - ``cap_tool_result_content`` caps each serialized tool result before it is
    appended to ``messages`` (agent.py).

These tests exercise the pure, deterministic guard functions (no network).
"""
import json

from utilities.agentic_enhancer.prompts import get_user_prompt
from utilities.agentic_enhancer import agent as agent_mod


def test_primary_code_is_capped_in_user_prompt():
    """A huge primary_code must not be inlined verbatim — the constructed
    prompt must stay bounded (well under any model context budget)."""
    huge_code = "x = 1\n" * 500_000  # ~3 MB of source
    prompt = get_user_prompt(
        unit_id="big.py:huge",
        unit_type="function",
        primary_code=huge_code,
        static_deps=[],
        static_callers=[],
    )
    # The whole prompt (not just the code) must be bounded.
    assert len(prompt) <= agent_mod.MAX_PROMPT_CHARS + 4096, (
        f"prompt length {len(prompt)} exceeds budget "
        f"{agent_mod.MAX_PROMPT_CHARS}; primary_code was not capped"
    )
    # Truncation must be signalled so the model knows content was elided.
    assert "truncated" in prompt.lower()


def test_small_primary_code_is_not_altered():
    """Small code must pass through verbatim (no spurious truncation)."""
    small_code = "def f():\n    return 1\n"
    prompt = get_user_prompt(
        unit_id="small.py:f",
        unit_type="function",
        primary_code=small_code,
        static_deps=[],
        static_callers=[],
    )
    assert small_code in prompt
    assert "... (truncated" not in prompt


def test_tool_result_content_is_capped():
    """A very large tool result must be truncated before being appended to
    the messages list so the constructed input cannot grow unbounded."""
    huge_result = {"found": True, "code": "A" * 1_000_000}
    content = agent_mod.cap_tool_result_content(huge_result)
    assert isinstance(content, str)
    assert len(content) <= agent_mod.MAX_TOOL_RESULT_CHARS + 256, (
        f"tool-result content length {len(content)} exceeds budget "
        f"{agent_mod.MAX_TOOL_RESULT_CHARS}"
    )
    assert "truncated" in content.lower()


def test_small_tool_result_round_trips_as_json():
    """A small tool result must serialize losslessly (parseable JSON)."""
    result = {"found": True, "id": "a.py:f", "code": "def f(): pass"}
    content = agent_mod.cap_tool_result_content(result)
    assert json.loads(content) == result


def test_messages_do_not_grow_unbounded_across_iterations():
    """Simulate the loop's append behaviour: repeatedly appending capped tool
    results keeps total input bounded per iteration (no unbounded growth from
    a single oversized result)."""
    messages = []
    oversized = {"found": True, "code": "Z" * 5_000_000}
    for _ in range(agent_mod.MAX_ITERATIONS):
        content = agent_mod.cap_tool_result_content(oversized)
        messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t", "content": content}
        ]})
    total = sum(len(m["content"][0]["content"]) for m in messages)
    bound = agent_mod.MAX_ITERATIONS * (agent_mod.MAX_TOOL_RESULT_CHARS + 256)
    assert total <= bound, (
        f"accumulated tool-result input {total} exceeds bounded "
        f"expectation {bound}"
    )
