"""Regression tests for issue #291 — verify's tool loop appends raw tool
results with no input cap, while the structurally identical enhance loop
caps both and documents why.

`agentic_enhancer/agent.py` has bounded its conversation input since PR
#133: MAX_PROMPT_CHARS (60k) on inlined primary_code and
cap_tool_result_content (24k) on every serialized tool result, with a
comment naming the failure the caps prevent — "input grew unbounded until
it overflowed the model context (400)". `finding_verifier.py` ran the same
20-iteration tool loop with NEITHER cap: `json.dumps(outcome)` was appended
verbatim every turn, so verify's input grew without bound (on the run that
filed this, incomplete verifications consumed 3.2x the tokens of completed
ones, the largest accumulating 5.8M tokens across 20 turns; the max-iteration
group's median input/turn was 2.2x the completed group's while output/turn
was indistinguishable — the growth is on the input side).

Contract locked here:
- every tool result appended to the verify conversation is bounded by the
  SAME helper and limit the enhance loop uses (cap_tool_result_content /
  MAX_TOOL_RESULT_CHARS), with the truncation marker when it fires;
- the inlined unit code in the initial verify prompt is capped at the
  enhance loop's MAX_PROMPT_CHARS, with the truncation marker;
- a small tool result still round-trips as valid JSON (not gratuitously
  truncated).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

from utilities.agentic_enhancer.agent import MAX_PROMPT_CHARS, MAX_TOOL_RESULT_CHARS
from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.finding_verifier import FindingVerifier
from utilities.llm import PhaseBinding, TextBlock, ToolResultBlock, ToolUseBlock
from utilities.llm.adapter import CompletionResult
from utilities.llm_client import reset_warning_state

STAGE1_FINDING = "vulnerable"


class _RecordingAdapter:
    """Issues one oversized-outcome tool call, then a finish; records every
    conversation it is handed so the test can inspect what was appended."""

    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def __init__(self):
        self.seen_messages = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.seen_messages.append(messages)
        if len(self.seen_messages) == 1:
            return CompletionResult(
                content=[ToolUseBlock(id="t1", name="read_function",
                                      input={"function": "big"})],
                input_tokens=1, output_tokens=1, stop_reason="tool_use",
            )
        return CompletionResult(
            content=[ToolUseBlock(id="t2", name="finish",
                                  input={"agree": True,
                                         "correct_finding": "vulnerable"})],
            input_tokens=1, output_tokens=1, stop_reason="tool_use",
        )


class _HugeOutcomeExecutor:
    """Stands in for the real ToolExecutor: returns a 200k-char payload."""

    def execute(self, tool_name, tool_input):
        return {"content": "A" * 200_000}


def _verify(adapter, code="x = 1", executor=None):
    binding = PhaseBinding(phase="verify", adapter=adapter, model="claude-x",
                           provider_name="anthropic")
    v = FindingVerifier(index=RepositoryIndex({}, repo_path=None),
                        binding=binding)
    if executor is not None:
        v.tool_executor = executor
    return v.verify_result(code=code, finding=STAGE1_FINDING,
                           attack_vector="a", reasoning="r")


def _tool_result_blocks(messages):
    blocks = []
    for m in messages:
        content = m.content if isinstance(m.content, (list, tuple)) else []
        for b in content:
            if isinstance(b, ToolResultBlock) and b.name == "read_function":
                blocks.append(b)
    return blocks


def test_oversized_tool_result_is_capped(tmp_path):
    reset_warning_state()
    adapter = _RecordingAdapter()
    _verify(adapter, executor=_HugeOutcomeExecutor())
    reset_warning_state()
    # the conversation is one growing list (the adapter sees the same
    # object each turn); the tool result is in the last recorded state
    results = _tool_result_blocks(adapter.seen_messages[-1])
    assert len(results) == 1
    content = results[0].content
    assert len(content) <= MAX_TOOL_RESULT_CHARS
    assert content.endswith("\n... (truncated)")


def test_small_tool_result_round_trips_valid_json():
    reset_warning_state()

    class _SmallExecutor:
        def execute(self, tool_name, tool_input):
            return {"content": "small"}

    adapter = _RecordingAdapter()
    _verify(adapter, executor=_SmallExecutor())
    reset_warning_state()
    results = _tool_result_blocks(adapter.seen_messages[-1])
    assert json.loads(results[0].content) == {"content": "small"}


def test_oversized_unit_code_is_capped_in_initial_prompt():
    reset_warning_state()
    adapter = _RecordingAdapter()
    tail = "END_OF_UNIT_MARKER"
    huge = "B" * (MAX_PROMPT_CHARS + 50_000) + tail
    _verify(adapter, code=huge)
    reset_warning_state()
    first_user = adapter.seen_messages[0][0]
    text = "".join(b.text for b in first_user.content
                   if isinstance(b, TextBlock))
    assert len(text) < MAX_PROMPT_CHARS + 10_000
    assert tail not in text                       # the unit was truncated
    assert "\n... (truncated)" in text            # with the explicit marker
