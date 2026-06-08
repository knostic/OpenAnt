"""PR #69 round-2 review fixes.

* M-a: Gemini output tokens include `thoughts_token_count` (thinking models).
* M-b: a Gemini prompt-level block (empty candidates) raises instead of
  returning a silent empty `end_turn`.
* M-c: the Stage-2 verifier returns "incomplete" on a truncated response
  (no tool call) instead of looping with an empty user message.

(P1 — the agent file-read path-traversal guard — is a pre-existing fix and
lives in ``test_agent_file_read_security.py``.)
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.finding_verifier import FindingVerifier
from utilities.llm import LLMResponseError, PhaseBinding, TextBlock
from utilities.llm.adapter import CompletionResult
from utilities.llm.providers.google import _response_to_unified
from utilities.llm_client import reset_warning_state


@pytest.fixture(autouse=True)
def _reset():
    reset_warning_state()
    yield
    reset_warning_state()


def _gemini_text_resp(*, candidates_tokens, thoughts_tokens=None):
    usage_kwargs = {"prompt_token_count": 10, "candidates_token_count": candidates_tokens}
    if thoughts_tokens is not None:
        usage_kwargs["thoughts_token_count"] = thoughts_tokens
    return SimpleNamespace(
        candidates=[SimpleNamespace(
            content=SimpleNamespace(parts=[SimpleNamespace(text="hi", function_call=None)]),
            finish_reason="STOP",
        )],
        usage_metadata=SimpleNamespace(**usage_kwargs),
    )


# --- M-a -------------------------------------------------------------------


def test_gemini_output_tokens_include_thoughts():
    result = _response_to_unified(_gemini_text_resp(candidates_tokens=5, thoughts_tokens=7))
    assert result.input_tokens == 10
    assert result.output_tokens == 12  # 5 visible + 7 thinking


def test_gemini_output_tokens_without_thoughts_field():
    # Non-thinking models / responses with no thoughts field still work.
    result = _response_to_unified(_gemini_text_resp(candidates_tokens=3))
    assert result.output_tokens == 3


# --- M-b -------------------------------------------------------------------


def test_gemini_empty_candidates_raises_with_reason():
    resp = SimpleNamespace(
        candidates=[],
        prompt_feedback=SimpleNamespace(block_reason="SAFETY"),
        usage_metadata=SimpleNamespace(prompt_token_count=3, candidates_token_count=0),
    )
    with pytest.raises(LLMResponseError) as exc:
        _response_to_unified(resp)
    assert "SAFETY" in str(exc.value)


def test_gemini_empty_candidates_no_feedback_still_raises():
    with pytest.raises(LLMResponseError):
        _response_to_unified(SimpleNamespace(candidates=[]))


# --- M-c -------------------------------------------------------------------


class _TruncatingAdapter:
    """Returns a text-only response truncated at max_tokens (no tool call)."""

    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def __init__(self):
        self.calls = 0

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls += 1
        return CompletionResult(
            content=[TextBlock("partial reasoning that got cut off")],
            input_tokens=1,
            output_tokens=1,
            stop_reason="max_tokens",
        )


def test_verifier_incomplete_on_truncation_makes_no_extra_call():
    stub = _TruncatingAdapter()
    binding = PhaseBinding(phase="verify", adapter=stub, model="claude-x", provider_name="anthropic")
    verifier = FindingVerifier(index=RepositoryIndex({}, repo_path=None), binding=binding)

    result = verifier.verify_result(code="x = 1", finding="sqli", attack_vector="a", reasoning="r")

    assert stub.calls == 1, "must NOT loop with an empty user message after a truncated response"
    assert "incomplete" in result.explanation.lower()
