"""C(b): the Stage-2 verifier must not accept a `finish` tool call from a TRUNCATED
turn (stop_reason == "max_tokens") as a completed verdict.

Before this fix the block loop harvested a `finish` ToolUseBlock regardless of
stop_reason, so a `max_tokens`-truncated reply carrying a well-formed
`finish(agree=False, correct_finding="safe")` was parsed as a COMPLETE verdict
(`incomplete=False`) and downgraded a Stage-1 `vulnerable` to `safe` silently — the
verify-stage tail of the same silent-false-negative family the adapter BUG-2/BUG-7
fixes address (the adapter now honestly reports truncation as `max_tokens`; the
verifier must gate on it). Offline stub adapters; no real LLM calls.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.finding_verifier import FindingVerifier, VerificationResult
from utilities.llm import PhaseBinding, ToolUseBlock
from utilities.llm.adapter import CompletionResult
from utilities.llm_client import reset_warning_state

STAGE1_FINDING = "vulnerable"


@pytest.fixture(autouse=True)
def _reset():
    reset_warning_state()
    yield
    reset_warning_state()


def _verify(adapter) -> VerificationResult:
    binding = PhaseBinding(phase="verify", adapter=adapter, model="claude-x", provider_name="anthropic")
    v = FindingVerifier(index=RepositoryIndex({}, repo_path=None), binding=binding)
    return v.verify_result(code="x = 1", finding=STAGE1_FINDING, attack_vector="a", reasoning="r")


class _TruncatedFinishAdapter:
    """A finish(agree=False, safe) call on a turn the model truncated at max_tokens."""
    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return CompletionResult(
            content=[ToolUseBlock(id="t1", name="finish",
                                  input={"agree": False, "correct_finding": "safe"})],
            input_tokens=1, output_tokens=1, stop_reason="max_tokens",
        )


class _CompleteFinishAdapter:
    """Regression guard: a finish on a NORMAL turn (tool_use) is still accepted."""
    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return CompletionResult(
            content=[ToolUseBlock(id="t1", name="finish",
                                  input={"agree": True, "correct_finding": "vulnerable"})],
            input_tokens=1, output_tokens=1, stop_reason="tool_use",
        )


def test_truncated_finish_at_max_tokens_is_incomplete_not_safe():
    r = _verify(_TruncatedFinishAdapter())
    assert r.incomplete is True                     # must NOT be a completed verdict
    assert r.correct_finding == STAGE1_FINDING       # Stage-1 verdict preserved, not "safe"
    assert r.agree is False


def test_complete_finish_still_accepted():
    r = _verify(_CompleteFinishAdapter())
    assert r.incomplete is False                     # a normal finish is still a real verdict
    assert r.agree is True
