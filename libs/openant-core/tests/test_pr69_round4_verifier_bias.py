"""PR #69 round-4, finding R4-7 (HIGH, pre-existing): Stage-2 verifier bias.

The Stage-2 verifier (`utilities/finding_verifier.py`) returned
``agree=True`` (i.e. *agree with Stage 1*) on **every degenerate path**:

  * ``:380`` text response couldn't be parsed   -> "Verification incomplete"
  * ``:448`` model made no tool calls           -> "Verification incomplete (no tool calls)"
  * ``:464`` max iterations reached             -> "Max iterations reached"
  * ``:925`` a ``finish`` call omitting ``agree`` -> ``get("agree", True)``

For a *security* verifier, ``agree=True`` is read downstream as a successful
"Verification agreed" (``finding_verifier.py:644``, ``experiment.py:772``,
``core/verifier.py:204``) — a silent rubber-stamp. A degenerate verify of a
Stage-1 ``vulnerable`` would read as confirmed/agreed with zero analysis.

FAIL-SAFE FIX (user decision): on each degenerate path the verifier must NOT
auto-agree. It must set ``agree=False`` so the result never reads as
"agreed"/clean, while PRESERVING the Stage-1 verdict in ``correct_finding``
(``correct_finding=finding``) so the finding stays SURFACED for human triage
and is never dropped from the report.

  Why preserve the Stage-1 verdict instead of "inconclusive": the downstream
  report filter keys on ``result["finding"]`` (``core/verifier.py:271-274``,
  ``core/reporter.py:253-256``), and the ``agree=False`` consumer overwrites
  ``result["finding"] = verification.correct_finding``
  (``finding_verifier.py:649-651``, ``experiment.py:775-778``). Encoding
  ``correct_finding="inconclusive"`` would set ``result["finding"]`` to
  ``"inconclusive"``, which is NOT in ``("vulnerable","bypassable")`` — the
  finding would VANISH from ``confirmed_findings`` and from the report. Keeping
  ``correct_finding=finding`` keeps a Stage-1 ``vulnerable`` visible.

These tests force each of the four degenerate paths through an offline stub
adapter (no real LLM calls) and assert the fail-safe behavior.
"""

from __future__ import annotations

import pytest

from utilities.agentic_enhancer.repository_index import RepositoryIndex
from utilities.finding_verifier import MAX_ITERATIONS, FindingVerifier
from utilities.llm import PhaseBinding, TextBlock, ToolUseBlock
from utilities.llm.adapter import CompletionResult
from utilities.llm_client import reset_warning_state

# The Stage-1 verdict every test feeds in. It MUST survive a degenerate
# verify (never be silently downgraded to a clean/safe/inconclusive value).
STAGE1_FINDING = "vulnerable"


@pytest.fixture(autouse=True)
def _reset():
    reset_warning_state()
    yield
    reset_warning_state()


def _make_verifier(adapter) -> FindingVerifier:
    binding = PhaseBinding(
        phase="verify", adapter=adapter, model="claude-x", provider_name="anthropic"
    )
    return FindingVerifier(index=RepositoryIndex({}, repo_path=None), binding=binding)


def _verify(adapter):
    return _make_verifier(adapter).verify_result(
        code="x = 1", finding=STAGE1_FINDING, attack_vector="a", reasoning="r"
    )


# --------------------------------------------------------------------------
# Stub adapters — one per degenerate path. All offline; no real API calls.
# --------------------------------------------------------------------------


class _UnparseableTextAdapter:
    """:380 — model ends its turn with text that contains no JSON object."""

    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def __init__(self):
        self.calls = 0

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls += 1
        # No '{' .. '}' anywhere => _try_parse_text_response returns None
        # and stop_reason == "end_turn" => falls through to the :380 path.
        return CompletionResult(
            content=[TextBlock("I am not sure, here is some prose with no json")],
            input_tokens=1,
            output_tokens=1,
            stop_reason="end_turn",
        )


class _NoToolCallsAdapter:
    """:448 — text-only response truncated at max_tokens (no tool call)."""

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


class _MaxIterationsAdapter:
    """:464 — keeps calling a (non-finish) tool forever, never finishes."""

    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def __init__(self):
        self.calls = 0

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls += 1
        # An unknown tool keeps the loop going: ToolExecutor returns
        # {"error": ...} (never raises) and no `finish` is seen, so the
        # while-loop runs MAX_ITERATIONS times then exits at :464.
        return CompletionResult(
            content=[ToolUseBlock(id=f"t{self.calls}", name="search_usages",
                                  input={"function_name": "noop"})],
            input_tokens=1,
            output_tokens=1,
            stop_reason="tool_use",
        )


class _FinishWithoutAgreeAdapter:
    """:925 — a `finish` tool call that OMITS the `agree` field."""

    name = "anthropic"
    supports_tools = True
    pricing = {"claude-x": {"input": 1.0, "output": 1.0}}

    def __init__(self):
        self.calls = 0

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls += 1
        return CompletionResult(
            content=[ToolUseBlock(
                id="finish-1",
                name="finish",
                # NOTE: no "agree" key at all.
                input={"correct_finding": "vulnerable",
                       "explanation": "looks exploitable"},
            )],
            input_tokens=1,
            output_tokens=1,
            stop_reason="tool_use",
        )


# --------------------------------------------------------------------------
# Fail-safe assertions (GREEN target). A degenerate verify must:
#   1. NOT read as "Verification agreed"  -> agree is False
#   2. keep the Stage-1 finding surfaced  -> correct_finding == STAGE1_FINDING
#      (so result["finding"] stays "vulnerable" and is never dropped)
# --------------------------------------------------------------------------


def _assert_failsafe(result):
    assert result.agree is False, (
        "degenerate verify must NOT auto-agree (would read as "
        "'Verification agreed' — a silent rubber-stamp)"
    )
    assert result.correct_finding == STAGE1_FINDING, (
        "degenerate verify must preserve the Stage-1 verdict so the finding "
        "stays surfaced for triage and is never dropped from the report; "
        f"got {result.correct_finding!r}"
    )
    # And never silently downgraded to a clean/safe verdict.
    assert result.correct_finding not in ("safe", "protected"), (
        "degenerate verify must never produce a clean verdict"
    )


def test_failsafe_unparseable_text_does_not_auto_agree():
    """:380 — unparseable end_turn text must not rubber-stamp Stage 1."""
    result = _verify(_UnparseableTextAdapter())
    assert "incomplete" in result.explanation.lower()
    _assert_failsafe(result)


def test_failsafe_no_tool_calls_does_not_auto_agree():
    """:448 — truncated response with no tool call must not rubber-stamp."""
    adapter = _NoToolCallsAdapter()
    result = _verify(adapter)
    assert adapter.calls == 1, "must not loop with an empty user message"
    assert "incomplete" in result.explanation.lower()
    _assert_failsafe(result)


def test_failsafe_max_iterations_does_not_auto_agree():
    """:464 — hitting MAX_ITERATIONS must not rubber-stamp Stage 1."""
    adapter = _MaxIterationsAdapter()
    result = _verify(adapter)
    assert adapter.calls == MAX_ITERATIONS
    assert "max iterations" in result.explanation.lower()
    _assert_failsafe(result)


def test_failsafe_finish_without_agree_defaults_to_disagree():
    """:925 — a `finish` omitting `agree` must default to NOT-agree."""
    result = _verify(_FinishWithoutAgreeAdapter())
    # The model omitted `agree`; fail-safe default must be False, and the
    # model-supplied correct_finding ("vulnerable") is honored (still surfaced).
    assert result.agree is False, (
        "a finish call that omits `agree` must default to False, not True"
    )
    assert result.correct_finding == "vulnerable"
