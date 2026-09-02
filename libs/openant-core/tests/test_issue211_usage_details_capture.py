"""Regression tests for issue #211 — usage-detail capture (accounting fidelity).

The cost meter dropped provider-supplied billing-relevant usage fields on the
floor: no adapter read any reasoning-token or cache-token detail field, and
``TokenTracker.record_call`` had nowhere to put them. A run could under-report
cost against the provider's bill with no way to reconcile from the artifacts
(#211's measurement: ~15% under, concentrated in the reasoning- and
cache-heavy Opus-5 phases; the issue itself frames the mechanisms as leads).

Contract locked here (PASS-THROUGH CAPTURE ONLY):
- adapters copy provider-supplied detail fields into
  ``CompletionResult.usage_details`` VERBATIM — present-only; a field the
  provider did not report is ABSENT from the dict (never a fabricated 0);
- ``record_call`` stores ``usage_details`` verbatim in the call record;
- detail fields NEVER feed the cost formula and are NEVER summed into the
  token totals — the reported cost number is UNCHANGED by this capture
  (whether ``completion_tokens`` already includes reasoning differs by
  provider/route; summing would double-count on including routes — the
  cost-math question stays deferred per the issue's ruling);
- multi-turn loops pass the per-turn detail dicts as a list (verbatim order).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm.adapter import CompletionResult  # noqa: E402
from utilities.llm_client import TokenTracker  # noqa: E402


# ---------------------------------------------------------------------------
# Tracker: verbatim storage, no math
# ---------------------------------------------------------------------------

def test_record_call_stores_usage_details_verbatim():
    t = TokenTracker()
    details = {"reasoning_tokens": 1234, "cached_tokens": 800}
    rec = t.record_call(
        model="claude-opus-5", input_tokens=100, output_tokens=50,
        pricing={"input": 1.0, "output": 2.0}, usage_details=details,
    )
    assert rec["usage_details"] == details, "details must be stored verbatim"
    # Not summed anywhere: totals stay the plain token counts.
    assert t.total_input_tokens == 100
    assert t.total_output_tokens == 50


def test_record_call_usage_details_absent_not_zero():
    t = TokenTracker()
    rec = t.record_call(
        model="claude-opus-5", input_tokens=10, output_tokens=5,
        pricing={"input": 1.0, "output": 2.0},
    )
    assert "usage_details" not in rec or rec["usage_details"] is None, (
        "absent details must not become a fabricated 0-dict"
    )


def test_record_call_details_do_not_change_cost():
    t = TokenTracker()
    base_kwargs = dict(model="claude-opus-5", input_tokens=100, output_tokens=50,
                       pricing={"input": 1.0, "output": 2.0})
    t.record_call(**base_kwargs)
    cost_without = t.total_cost_usd
    t.record_call(**base_kwargs, usage_details={"reasoning_tokens": 999999})
    cost_with = t.total_cost_usd
    assert cost_with == 2 * cost_without, (
        "details must not affect cost math (second call identical except details)"
    )


def test_record_call_accepts_per_turn_list():
    t = TokenTracker()
    turns = [{"reasoning_tokens": 10}, {"reasoning_tokens": 20}, None]
    rec = t.record_call(
        model="claude-opus-5", input_tokens=30, output_tokens=15,
        pricing={"input": 1.0, "output": 2.0}, usage_details=turns,
    )
    assert rec["usage_details"] == turns


# ---------------------------------------------------------------------------
# CompletionResult field
# ---------------------------------------------------------------------------

def test_completion_result_has_usage_details_default_none():
    r = CompletionResult(content=(), input_tokens=1, output_tokens=1,
                         stop_reason="end_turn")
    assert getattr(r, "usage_details", None) is None


# ---------------------------------------------------------------------------
# Adapter extraction: verbatim, present-only
# ---------------------------------------------------------------------------

def _fake_anthropic_usage(**kw):
    return SimpleNamespace(**kw)


def test_anthropic_extracts_cache_fields_verbatim():
    from utilities.llm.providers.anthropic import _extract_usage_details
    usage = _fake_anthropic_usage(
        input_tokens=100, output_tokens=50,
        cache_read_input_tokens=800, cache_creation_input_tokens=120,
    )
    d = _extract_usage_details(usage)
    assert d == {"cache_read_input_tokens": 800,
                 "cache_creation_input_tokens": 120}


def test_anthropic_absent_fields_absent_not_zero():
    from utilities.llm.providers.anthropic import _extract_usage_details
    usage = _fake_anthropic_usage(input_tokens=100, output_tokens=50)
    d = _extract_usage_details(usage)
    assert d is None or d == {}, (
        f"no cache fields supplied → no fabricated zeros (got {d!r})"
    )


def test_openai_chat_extracts_reasoning_and_cache_details():
    from utilities.llm.providers.openai import _extract_usage_details_chat
    usage = SimpleNamespace(
        prompt_tokens=100, completion_tokens=50,
        prompt_tokens_details=SimpleNamespace(
            cached_tokens=64, cache_write_tokens=32),
        completion_tokens_details=SimpleNamespace(reasoning_tokens=512),
    )
    d = _extract_usage_details_chat(usage)
    assert d == {"reasoning_tokens": 512, "cached_tokens": 64,
                 "cache_write_tokens": 32}


def test_openai_chat_absent_details_absent():
    from utilities.llm.providers.openai import _extract_usage_details_chat
    usage = SimpleNamespace(prompt_tokens=100, completion_tokens=50)
    d = _extract_usage_details_chat(usage)
    assert d is None or d == {}


def test_openai_responses_extracts_reasoning_and_cached_tokens():
    """Field names verified against pinned openai SDK 2.37.0 ResponseUsage."""
    from utilities.llm.providers.openai import _extract_usage_details_responses
    usage = SimpleNamespace(
        input_tokens=100, output_tokens=50,
        input_tokens_details=SimpleNamespace(cached_tokens=64),
        output_tokens_details=SimpleNamespace(reasoning_tokens=256),
    )
    d = _extract_usage_details_responses(usage)
    assert d == {"reasoning_tokens": 256, "cached_tokens": 64}


def test_google_extracts_thoughts_and_cached_content():
    from utilities.llm.providers.google import _extract_usage_details
    usage = SimpleNamespace(
        prompt_token_count=100, candidates_token_count=50,
        thoughts_token_count=256, cached_content_token_count=128)
    d = _extract_usage_details(usage)
    assert d == {"thoughts_token_count": 256, "cached_content_token_count": 128}


def test_google_absent_details_absent():
    from utilities.llm.providers.google import _extract_usage_details
    usage = SimpleNamespace(prompt_token_count=100, candidates_token_count=50)
    d = _extract_usage_details(usage)
    assert d is None or d == {}


# ---------------------------------------------------------------------------
# simple_text pass-through
# ---------------------------------------------------------------------------

class _RecordingAdapter:
    name = "fake"
    supports_tools = False
    pricing = {"fake-model": {"input": 1.0, "output": 2.0}}

    def __init__(self, result):
        self._result = result

    def complete(self, **kwargs):
        return self._result


def test_simple_text_passes_usage_details_to_tracker():
    from utilities.llm.helpers import simple_text
    from utilities.llm.adapter import TextBlock
    from utilities.llm.registry import PhaseBinding

    details = {"reasoning_tokens": 42}
    adapter = _RecordingAdapter(CompletionResult(
        content=(TextBlock("ok"),), input_tokens=10, output_tokens=5,
        stop_reason="end_turn", usage_details=details))
    binding = PhaseBinding(phase="analyze", adapter=adapter, model="fake-model",
                           provider_name="fake")
    t = TokenTracker()
    simple_text(binding, "hello", tracker=t)
    assert t.calls[-1]["usage_details"] == details


def test_genuine_zero_survives_not_dropped():
    """A provider-reported 0 must be captured as 0 (absent ≠ zero ≠ dropped-zero)."""
    from utilities.llm.providers.openai import _extract_usage_details_chat
    usage = SimpleNamespace(
        prompt_tokens=100, completion_tokens=50,
        prompt_tokens_details=SimpleNamespace(cached_tokens=0),
        completion_tokens_details=SimpleNamespace(reasoning_tokens=0),
    )
    d = _extract_usage_details_chat(usage)
    assert d == {"reasoning_tokens": 0, "cached_tokens": 0}


def test_merge_usage_carries_details_verbatim():
    from report.generator import _merge_usage
    merged = _merge_usage([
        {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
         "cost_usd": 0.01, "usage_details": {"reasoning_tokens": 3}},
        {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
         "cost_usd": 0.01},
    ])
    assert merged["usage_details"] == [{"reasoning_tokens": 3}]
    assert merged["input_tokens"] == 20  # numerics still merged as before


def test_merge_usage_no_details_no_key():
    from report.generator import _merge_usage
    merged = _merge_usage([
        {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15, "cost_usd": 0.01},
        {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15, "cost_usd": 0.01},
    ])
    assert "usage_details" not in merged


def test_verifier_real_loop_persists_usage_details():
    """Integration: the REAL Stage-2 loop records per-turn details to the
    tracker AND serializes them into the unit's verification record."""
    from utilities.finding_verifier import FindingVerifier
    from utilities.llm.adapter import TextBlock, ToolUseBlock
    from utilities.llm.registry import PhaseBinding
    from utilities.llm_client import TokenTracker

    class _ToolLoopAdapter:
        name = "fake"
        supports_tools = True
        pricing = {"fake-model": {"input": 1.0, "output": 2.0}}

        def __init__(self):
            self.turn = 0

        def complete(self, *, model, max_tokens, system, tools, messages):
            self.turn += 1
            if self.turn == 1:
                # One tool-use turn with details, then a finish turn.
                return CompletionResult(
                    content=(ToolUseBlock(id="t1", name="finish", input={}),),
                    input_tokens=10, output_tokens=5, stop_reason="tool_use",
                    usage_details={"reasoning_tokens": 11})
            return CompletionResult(
                content=(TextBlock("done"),),
                input_tokens=8, output_tokens=4, stop_reason="end_turn")

    tracker = TokenTracker()
    adapter = _ToolLoopAdapter()
    binding = PhaseBinding(phase="verify", adapter=adapter, model="fake-model",
                           provider_name="fake")
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    verifier = FindingVerifier(index=RepositoryIndex({}, repo_path=None),
                               binding=binding, tracker=tracker)
    result = verifier.verify_result(
        code="def f(): ...", finding="vulnerable",
        attack_vector="x", reasoning="r")
    # tracker record carries the per-turn list verbatim
    assert tracker.calls[-1]["usage_details"] == [{"reasoning_tokens": 11}, None]
    # the serialized unit record persists them (the reconcilable artifact)
    d = result.to_dict()
    assert d["usage_details"] == [{"reasoning_tokens": 11}, None]


def test_agent_real_loop_persists_usage_details():
    """Integration: the REAL enhancer loop serializes per-turn details into
    agent_metadata (dataset_enhanced / checkpoints)."""
    from utilities.agentic_enhancer.agent import ContextAgent
    from utilities.llm.adapter import TextBlock, ToolUseBlock
    from utilities.llm.registry import PhaseBinding
    from utilities.llm_client import TokenTracker

    class _ToolLoopAdapter:
        name = "fake"
        supports_tools = True
        pricing = {"fake-model": {"input": 1.0, "output": 2.0}}

        def __init__(self):
            self.turn = 0

        def complete(self, *, model, max_tokens, system, tools, messages):
            self.turn += 1
            if self.turn == 1:
                return CompletionResult(
                    content=(ToolUseBlock(id="t1", name="finish",
                                          input={"security_classification": "exploitable",
                                                 "usage_context": "ctx",
                                                 "include_functions": [],
                                                 "classification_reasoning": "r",
                                                 "confidence": 0.9}),),
                    input_tokens=10, output_tokens=5, stop_reason="tool_use",
                    usage_details={"reasoning_tokens": 9})
            return CompletionResult(
                content=(TextBlock("done"),),
                input_tokens=8, output_tokens=4, stop_reason="end_turn")

    tracker = TokenTracker()
    adapter = _ToolLoopAdapter()
    binding = PhaseBinding(phase="enhance", adapter=adapter, model="fake-model",
                           provider_name="fake")
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    agent = ContextAgent(index=RepositoryIndex({}, repo_path=None),
                         binding=binding, tracker=tracker)
    result = agent.analyze_unit(
        unit_id="a.py:f", unit_type="function",
        primary_code="def f(): ...", static_deps=[], static_callers=[])
    d = result.to_dict()
    # The finish arrives as a tool call in turn 1 → a single recorded turn.
    assert d["agent_metadata"]["usage_details"] == [{"reasoning_tokens": 9}]


# ---------------------------------------------------------------------------
# Round-2 additions: cost-mutation locks (details must NEVER move a cost number)
# ---------------------------------------------------------------------------

def test_extract_usage_cost_immune_to_details():
    """_extract_usage is where detail fields and cost math are adjacent —
    lock that details cannot move the dollar figure (mutation guard)."""
    from report.generator import _extract_usage
    base = _extract_usage(100, 50, "m", pricing={"input": 1.0, "output": 2.0})
    with_details = _extract_usage(
        100, 50, "m", pricing={"input": 1.0, "output": 2.0},
        usage_details={"reasoning_tokens": 10_000_000, "cached_tokens": 10_000_000})
    assert with_details["cost_usd"] == base["cost_usd"], (
        "usage_details must not change cost_usd (the deferred cost-math rule)"
    )
    assert with_details["usage_details"]["reasoning_tokens"] == 10_000_000


def test_reporter_record_usage_forwards_details_to_tracker():
    """core/reporter._record_usage_in_tracker (its except swallows errors)
    must forward usage_details — a dropped kwarg would silently degrade."""
    from core.reporter import _record_usage_in_tracker
    import utilities.llm_client as llm_client

    details = {"reasoning_tokens": 5}
    usage = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
             "cost_usd": 0.01, "usage_details": details}

    class _Adapter:
        pricing = {"m": {"input": 1.0, "output": 2.0}}

    class _B:
        model = "m"
        adapter = _Adapter()

    tracker = llm_client.TokenTracker()
    orig = llm_client.get_global_tracker
    llm_client.get_global_tracker = lambda: tracker
    try:
        _record_usage_in_tracker(usage, _B())
    finally:
        llm_client.get_global_tracker = orig
    assert tracker.calls[-1]["usage_details"] == details


def test_verifier_loop_totals_immune_to_details():
    """The REAL verifier loop: totals/cost must not move when details are
    present (double-count mutation guard at the accumulation site)."""
    from utilities.finding_verifier import FindingVerifier
    from utilities.llm.adapter import TextBlock, ToolUseBlock
    from utilities.llm.registry import PhaseBinding
    from utilities.llm_client import TokenTracker
    from utilities.agentic_enhancer.repository_index import RepositoryIndex

    class _ToolLoopAdapter:
        name = "fake"
        supports_tools = True
        pricing = {"fake-model": {"input": 1.0, "output": 2.0}}

        def __init__(self):
            self.turn = 0

        def complete(self, *, model, max_tokens, system, tools, messages):
            self.turn += 1
            if self.turn == 1:
                return CompletionResult(
                    content=(ToolUseBlock(id="t1", name="finish", input={}),),
                    input_tokens=10, output_tokens=5, stop_reason="tool_use",
                    usage_details={"reasoning_tokens": 10_000_000})
            return CompletionResult(
                content=(TextBlock("done"),),
                input_tokens=8, output_tokens=4, stop_reason="end_turn")

    tracker = TokenTracker()
    binding = PhaseBinding(phase="verify", adapter=_ToolLoopAdapter(),
                           model="fake-model", provider_name="fake")
    verifier = FindingVerifier(index=RepositoryIndex({}, repo_path=None),
                               binding=binding, tracker=tracker)
    result = verifier.verify_result(
        code="def f(): ...", finding="vulnerable",
        attack_vector="x", reasoning="r")
    # Totals = plain token sums only: 10+8 input, 5+4 output — the
    # 10M reasoning tokens in usage_details must NOT appear anywhere.
    assert result.total_tokens == (10 + 8) + (5 + 4)
    assert tracker.total_input_tokens == 18
    assert tracker.total_output_tokens == 9
    assert tracker.calls[-1]["usage_details"] == [{"reasoning_tokens": 10_000_000}, None]
