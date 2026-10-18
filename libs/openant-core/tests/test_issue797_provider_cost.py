"""#797 — the cost meter never reads the provider's own cost.

OpenRouter returns ``usage.cost`` on EVERY response (the issue's executed
probe: gpt-4o-mini → 1.8e-06; claude-sonnet-5.5 → 3e-05; the field arrives
with no extra body, on all three observed routings) — and the response
unifier OpenRouter reuses (``_extract_usage_details_chat``) harvests the
reasoning/cache detail fields and DROPS ``cost``. The tracker's
``record_call`` then prices from the local table (or the #216 loud $0 +
cost_incomplete path for a lookup miss): a 220.5M-token phase shipped as
``$0.00`` under a column headed "Actual" while the authoritative charged
cost sat on the wire, discarded.

The fix (the issue's own shape): PREFER the provider-reported cost where
present, fall back to the local table, keep ``cost_incomplete`` honest for
the residual gap (models that report neither).

Shapes:

  S1 -- the WITNESS (absence-red at base): the falsifier at the adapter
        level — an OpenRouter response carrying ``usage.cost`` must surface
        it on the CompletionResult (``provider_cost_usd``).
  S2 -- the WITNESS (absence-red at base): the tracker's preference
        contract — ``record_call(provider_cost_usd=...)``: the provider
        value is THE cost (no table lookup, no unpriced marker, the record
        carries its source); the provider WINS over a present table rate;
        without a provider cost the two existing paths (the table; the
        #216 loud unpriced path) are byte-identical.
  S3 -- the WITNESS (absence-red at base): the integration — simple_text
        through a fake adapter reporting a provider cost → the meter's
        totals carry it (the $0.00 era ends on this path).
  S4 -- the agentic integration: the agent's per-turn accumulator — each
        turn's provider cost sums; the conversation record carries the sum.
  S5 -- the fallback pins: a response WITHOUT a cost (the OpenAI direct
        path) stays None (the unifier does not fabricate); the #216 loud
        path for a table-miss model WITHOUT a provider cost is unchanged
        (cost_incomplete stays honest for the residual gap).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import TokenTracker, reset_warning_state  # noqa: E402


def _fake_completion(*, prompt_tokens=10, completion_tokens=5,
                     cost=None, content="hi"):
    """A response shaped like the openai SDK's ChatCompletion — the object
    the OpenRouter adapter's ``_response_to_unified`` consumes."""
    usage = SimpleNamespace(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
        completion_tokens_details=SimpleNamespace(reasoning_tokens=1),
        prompt_tokens_details=SimpleNamespace(cached_tokens=2,
                                              cache_write_tokens=0),
    )
    if cost is not None:
        usage.cost = cost
    choice = SimpleNamespace(
        finish_reason="stop",
        message=SimpleNamespace(content=content, tool_calls=None),
    )
    return SimpleNamespace(choices=[choice], usage=usage, id="resp", model="m")


class _Adapter:
    name = "openrouter"
    supports_tools = False
    pricing = {}

    def __init__(self, result=None, response=None):
        self._result = result
        self._response = response

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        if self._response is not None:
            from utilities.llm.providers.openrouter import _response_to_unified
            return _response_to_unified(self._response,
                                        adapter="OpenRouterAdapter")
        return self._result


# ---------------------------------------------------------------------------
# S1 — the falsifier: the adapter surfaces the provider's own cost
# ---------------------------------------------------------------------------
def test_the_openrouter_response_cost_reaches_the_result(monkeypatch):
    """The issue's probe: usage.cost on every OpenRouter response. The
    unifier dropped it; the ADAPTER must surface it as provider_cost_usd
    (present-only) on the result its complete() returns."""
    from utilities.llm.adapter import Message, TextBlock
    from utilities.llm.providers.openrouter import OpenRouterAdapter

    _msg = [Message(role="user", content=(TextBlock(text="hi"),))]

    adapter = OpenRouterAdapter.__new__(OpenRouterAdapter)
    adapter._client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(
            create=lambda **kw: _fake_completion(cost=3e-05))))
    result = adapter.complete(model="anthropic/claude-sonnet-5.5", system=None,
                               messages=_msg, max_tokens=1)
    assert result.input_tokens == 10 and result.output_tokens == 5
    assert result.provider_cost_usd == 3e-05, (
        f"the authoritative charged cost was dropped: {result!r}")

    # present-only: a response WITHOUT a cost stays None (never fabricated)
    adapter2 = OpenRouterAdapter.__new__(OpenRouterAdapter)
    adapter2._client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(
            create=lambda **kw: _fake_completion())))
    result_none = adapter2.complete(model="m", system=None,
                                    messages=_msg, max_tokens=1)
    assert result_none.provider_cost_usd is None, (
        f"a fabricated cost: {result_none!r}")


# ---------------------------------------------------------------------------
# S2 — the tracker's preference contract
# ---------------------------------------------------------------------------
def test_the_tracker_prefers_the_provider_cost():
    """The provider's own number IS the cost: no table lookup, no unpriced
    marker, the record carries its source; the provider WINS over a present
    table rate; the two existing paths are unchanged without it."""
    reset_warning_state()
    t = TokenTracker()

    # the provider cost wins even with NO pricing (the lookup-miss class)
    rec = t.record_call(model="anthropic/claude-sonnet-5.5",
                        input_tokens=100, output_tokens=50,
                        pricing=None, provider_cost_usd=0.0123)
    assert rec["cost_usd"] == 0.0123, rec
    assert rec.get("cost_source") == "provider", rec
    totals = t.get_totals()
    assert totals["total_cost_usd"] == 0.0123, totals
    assert totals.get("cost_incomplete") is not True, totals
    assert totals.get("unpriced_models") != ["anthropic/claude-sonnet-5.5"], totals

    # the provider cost wins OVER a present table rate (the preference)
    t2 = TokenTracker()
    rec2 = t2.record_call(model="m", input_tokens=100, output_tokens=50,
                          pricing={"input": 10.0, "output": 10.0},
                          provider_cost_usd=0.002)
    assert rec2["cost_usd"] == 0.002, rec2
    assert rec2.get("cost_source") == "provider", rec2

    # without a provider cost: the table path byte-identical
    t3 = TokenTracker()
    rec3 = t3.record_call(model="m", input_tokens=100, output_tokens=50,
                          pricing={"input": 1.0, "output": 2.0})
    assert abs(rec3["cost_usd"] - (100 * 1.0 + 50 * 2.0) / 1e6) < 1e-12, rec3
    assert "cost_source" not in rec3, rec3

    # without either: the #216 loud path UNCHANGED (the residual gap honest)
    reset_warning_state()
    t4 = TokenTracker()
    rec4 = t4.record_call(model="unknown/model", input_tokens=10,
                          output_tokens=5, pricing=None)
    assert rec4["cost_usd"] == 0.0, rec4
    totals4 = t4.get_totals()
    assert totals4["cost_incomplete"] is True, totals4
    assert "unknown/model" in totals4["unpriced_models"], totals4
    reset_warning_state()

    # the r1-F3 pin (the DESIGN DECISION, executed): a provider cost with
    # CACHE usage — the provider's number IS the priced total, so the
    # cache-UNPRICED marker is suppressed (the marker lived in the
    # table-priced arm the preference skips); the cache TOKEN line items
    # still record. The control (no provider cost) keeps the marker.
    t5 = TokenTracker()
    rec5 = t5.record_call(model="m", input_tokens=100, output_tokens=50,
                          pricing={"input": 1.0, "output": 2.0},
                          provider_cost_usd=0.005,
                          usage_details={"cache_read_input_tokens": 90})
    assert rec5["cost_usd"] == 0.005 and rec5.get("cost_source") == "provider"
    assert rec5.get("cache_read_tokens") == 90, rec5
    totals5 = t5.get_totals()
    assert totals5.get("cost_incomplete") is not True, totals5
    assert totals5.get("unpriced_cache_models") != ["m"], totals5
    t6 = TokenTracker()
    t6.record_call(model="m", input_tokens=100, output_tokens=50,
                   pricing={"input": 1.0, "output": 2.0},
                   usage_details={"cache_read_input_tokens": 90})
    assert "m" in (t6.get_totals().get("unpriced_cache_models") or []), (
        f"the control lost its cache marker: {t6.get_totals()!r}")
    reset_warning_state()


# ---------------------------------------------------------------------------
# S3 — the integration: simple_text carries the meter's new source
# ---------------------------------------------------------------------------
def test_simple_text_meter_carries_the_provider_cost(monkeypatch):
    """The integration the campaign lacked: the scan's main chat path
    (simple_text) through an adapter reporting the provider cost → the
    meter's totals carry it (cost_incomplete stays ABSENT — the call is
    fully priced by the provider)."""
    reset_warning_state()
    from utilities.llm import PhaseBinding
    from utilities.llm.helpers import simple_text

    from utilities.llm.adapter import TextBlock

    class _Res:
        content = (TextBlock(text="ok"),)
        input_tokens = 100
        output_tokens = 20
        stop_reason = "stop"
        raw = None
        usage_details = {"reasoning_tokens": 1}
        provider_cost_usd = 0.0075

    binding = PhaseBinding(phase="analyze", adapter=_Adapter(result=_Res()),
                           model="anthropic/claude-sonnet-5.5",
                           provider_name="openrouter")
    tracker = TokenTracker()
    out = simple_text(binding, "hi", max_tokens=10, tracker=tracker)
    assert out == "ok"
    totals = tracker.get_totals()
    assert abs(totals["total_cost_usd"] - 0.0075) < 1e-12, totals
    assert totals.get("cost_incomplete") is not True, totals
    reset_warning_state()


# ---------------------------------------------------------------------------
# S4 — the agentic accumulator: per-turn costs sum into the conversation
# ---------------------------------------------------------------------------
def test_the_agent_accumulates_per_turn_provider_costs(monkeypatch, tmp_path):
    """The issue's evidence path WAS agentic (the enhance phase). The
    agent's turn loop must accumulate each turn's provider cost and the
    conversation record must carry the sum."""
    reset_warning_state()
    import utilities.agentic_enhancer.agent as agent_mod
    from utilities.llm import PhaseBinding
    from utilities.llm.adapter import TextBlock, ToolUseBlock

    costs = iter([0.001, 0.002, 0.004])
    calls = [0]

    def _turn():
        calls[0] += 1
        res = SimpleNamespace()
        res.input_tokens = 10
        res.output_tokens = 5
        res.raw = None
        res.usage_details = {"reasoning_tokens": 1}
        res.provider_cost_usd = next(costs)
        if calls[0] < 3:
            # a tool call keeps the loop alive (the finish tool — the
            # agent's own completion contract)
            res.content = (ToolUseBlock(id="t%d" % calls[0], name="finish",
                                        input={"status": "complete"}),)
            res.stop_reason = "tool_use"
        else:
            res.content = (TextBlock(text="analysis"),)
            res.stop_reason = "stop"
        return res

    class _AgentAdapter:
        name = "openrouter"
        supports_tools = True
        pricing = {}

        def complete(self, *, model, system, messages, max_tokens, tools=None):
            return _turn()

    binding = PhaseBinding(phase="enhance",
                           adapter=_AgentAdapter(), model="m",
                           provider_name="openrouter")
    tracker = TokenTracker()

    # the tools must serve the finish call (the real executor against a
    # dummy index; finish is context-free)
    def _fake_execute(self, tool_name, tool_input):
        if tool_name == "finish" and calls[0] < 3:
            # the FIRST two finish calls do NOT complete — the loop keeps
            # running so the accumulator sees all three turns
            return {"status": "incomplete", "result": "keep going"}
        return {"status": "complete", "result": "done"}

    monkeypatch.setattr(agent_mod.ToolExecutor, "execute", _fake_execute)
    try:
        agent_mod.enhance_unit_with_agent(
            {"id": "u:1"}, SimpleNamespace(), binding, tracker=tracker,
            verbose=False)
    except Exception:
        pass  # whichever exit: the conversation record carries the sum
    totals = tracker.get_totals()
    assert totals["total_calls"] >= 1, totals
    assert abs(totals["total_cost_usd"] - 0.007) < 1e-9, (
        f"the per-turn provider costs did not accumulate: {totals!r}")
    reset_warning_state()


# ---------------------------------------------------------------------------
# S5 — the fallback pins (green at base, the mutant-kill guards)
# ---------------------------------------------------------------------------
def test_a_response_without_cost_stays_absent_and_the_loud_path_survives():
    """The two pre-existing contracts: (a) the OpenAI-direct unifier does
    not FABRICATE a cost (None stays None); (b) the #216 loud path for a
    model with neither a table rate nor a provider cost is unchanged —
    cost_incomplete stays honest for the residual gap (the issue's own
    'keep the marker honest' clause)."""
    from utilities.llm.providers.openai import _response_to_unified
    result = _response_to_unified(_fake_completion(),
                                  adapter="OpenAIAdapter")
    assert result.provider_cost_usd is None, (
        f"a fabricated cost: {result!r}")
    reset_warning_state()
    t = TokenTracker()
    rec = t.record_call(model="orphan/model", input_tokens=10,
                        output_tokens=5, pricing=None)
    assert rec["cost_usd"] == 0.0, rec
    assert t.get_totals()["cost_incomplete"] is True
    assert "orphan/model" in t.get_totals()["unpriced_models"]
    reset_warning_state()


# ---------------------------------------------------------------------------
# S6 — the exit-shape witnesses: every record site carries the sum
# ---------------------------------------------------------------------------
def _agent_drive(monkeypatch, turn_fn, *, finish_serves=None):
    """The shared agentic drive: the REAL enhance_unit_with_agent with the
    adapter's complete + the tool executor monkeypatched, returning the
    tracker (the caller asserts the recorded cost)."""
    reset_warning_state()
    import utilities.agentic_enhancer.agent as agent_mod
    from utilities.llm import PhaseBinding

    class _AgentAdapter:
        name = "openrouter"
        supports_tools = True
        pricing = {}

        def complete(self, *, model, system, messages, max_tokens, tools=None):
            return turn_fn()

    def _execute(self, tool_name, tool_input):
        if finish_serves is not None:
            return finish_serves(tool_name, tool_input)
        return {"status": "complete", "result": "done"}

    monkeypatch.setattr(agent_mod.ToolExecutor, "execute", _execute)
    binding = PhaseBinding(phase="enhance", adapter=_AgentAdapter(), model="m",
                           provider_name="openrouter")
    tracker = TokenTracker()
    try:
        agent_mod.enhance_unit_with_agent(
            {"id": "u:1"}, SimpleNamespace(), binding, tracker=tracker,
            verbose=False)
    except Exception:
        pass
    reset_warning_state()
    return tracker


def test_the_error_exit_carries_the_accumulated_cost(monkeypatch):
    """The :386 record site (the tool-loop error path): the adapter raises
    on turn 2 — the error record carries turn 1's accumulated provider
    cost."""
    from utilities.llm.adapter import ToolUseBlock

    state = [0]

    def turn_fn():
        state[0] += 1
        res = SimpleNamespace()
        res.input_tokens = 10
        res.output_tokens = 5
        res.raw = None
        res.usage_details = None
        if state[0] == 1:
            res.content = (ToolUseBlock(id="t1", name="finish",
                                        input={"status": "complete"}),)
            res.stop_reason = "tool_use"
            res.provider_cost_usd = 0.002
            return res
        raise RuntimeError("the second turn exploded")

    t = _agent_drive(monkeypatch, turn_fn,
                     finish_serves=lambda n, i: {"status": "incomplete",
                                                 "result": "keep going"})
    totals = t.get_totals()
    assert abs(totals["total_cost_usd"] - 0.002) < 1e-12, (
        f"the error exit lost the accumulated provider cost: {totals!r}")


def test_the_degenerate_no_finish_exit_carries_the_cost(monkeypatch):
    """The :482 record site (the agent ended without calling finish): a
    text-only turn with stop_reason='stop' — the degenerate record carries
    the turn's provider cost."""
    from utilities.llm.adapter import TextBlock

    def turn_fn():
        res = SimpleNamespace()
        res.content = (TextBlock(text="analysis"),)
        res.input_tokens = 7
        res.output_tokens = 3
        # the degenerate exit's own trigger (agent.py: the end_turn branch)
        res.stop_reason = "end_turn"
        res.raw = None
        res.usage_details = None
        res.provider_cost_usd = 0.004
        return res

    t = _agent_drive(monkeypatch, turn_fn)
    totals = t.get_totals()
    assert abs(totals["total_cost_usd"] - 0.004) < 1e-12, (
        f"the degenerate exit lost the provider cost: {totals!r}")


def test_the_truncated_finish_exit_carries_the_cost(monkeypatch):
    """The :558 record site (the finish call truncated at max_tokens): the
    finish tool completes but the response's stop_reason is max_tokens —
    the truncated record carries the turn's provider cost."""
    from utilities.llm.adapter import ToolUseBlock

    def turn_fn():
        res = SimpleNamespace()
        res.content = (ToolUseBlock(id="t1", name="finish",
                                    input={"status": "complete"}),)
        res.input_tokens = 9
        res.output_tokens = 2
        res.stop_reason = "max_tokens"
        res.raw = None
        res.usage_details = None
        res.provider_cost_usd = 0.005
        return res

    t = _agent_drive(monkeypatch, turn_fn)
    totals = t.get_totals()
    assert abs(totals["total_cost_usd"] - 0.005) < 1e-12, (
        f"the truncated-finish exit lost the provider cost: {totals!r}")


def test_the_normal_finish_exit_carries_the_cost(monkeypatch):
    """The :589 record site (the normal finish flow: the finish tool called
    and the loop's tool_use round completes): a single finish turn — the
    record carries the turn's provider cost."""
    from utilities.llm.adapter import ToolUseBlock

    def turn_fn():
        res = SimpleNamespace()
        res.content = (ToolUseBlock(id="t1", name="finish",
                                    input={"status": "complete"}),)
        res.input_tokens = 4
        res.output_tokens = 1
        res.stop_reason = "tool_use"
        res.raw = None
        res.usage_details = None
        res.provider_cost_usd = 0.006
        return res

    t = _agent_drive(monkeypatch, turn_fn)
    totals = t.get_totals()
    assert abs(totals["total_cost_usd"] - 0.006) < 1e-12, (
        f"the normal-finish exit lost the provider cost: {totals!r}")


# ---------------------------------------------------------------------------
# S6e — the MAX_ITERATIONS exit (the r1-F1 catch: the SIXTH record site)
# ---------------------------------------------------------------------------
def test_the_max_iterations_exit_carries_the_cost(monkeypatch):
    """The r1-F1 catch: a tool-heavy unit that exhausts MAX_ITERATIONS is
    the exit a rich agent run most plausibly takes — the sixth record site
    must thread the accumulated provider cost like every other exit."""
    import utilities.agentic_enhancer.agent as agent_mod
    from utilities.llm.adapter import ToolUseBlock

    turns = [0]

    def turn_fn():
        turns[0] += 1
        res = SimpleNamespace()
        res.content = (ToolUseBlock(id="t%d" % turns[0], name="finish",
                                    input={"status": "complete"}),)
        res.input_tokens = 5
        res.output_tokens = 2
        res.stop_reason = "tool_use"
        res.raw = None
        res.usage_details = None
        res.provider_cost_usd = 0.0005
        return res

    # every finish returns incomplete -> the loop runs to MAX_ITERATIONS
    t = _agent_drive(monkeypatch, turn_fn,
                     finish_serves=lambda n, i: {"status": "incomplete",
                                                "result": "keep going"})
    totals = t.get_totals()
    assert totals["total_calls"] == 1, totals
    assert abs(totals["total_cost_usd"] - 0.0005 * agent_mod.MAX_ITERATIONS) \
        < 1e-9, (
        f"the max-iterations exit lost the accumulated provider cost "
        f"(the r1-F1 class): {totals!r}")


# ---------------------------------------------------------------------------
# S7 — the mixed-conversation fallback (the r1-F4 catch)
# ---------------------------------------------------------------------------
def test_a_rejected_billed_turn_falls_back_not_silent_under_count(monkeypatch):
    """The r1-F4 catch: the raising turn's OWN billed usage has no cost
    channel — threading the accumulated provider cost would label the
    conversation 'provider' while that turn's charge is missing (a silent
    under-count; at base the same shape took the LOUD path). The fallback:
    a billed raising turn sends the conversation back to the table/loud
    path — NOT provider-labelled."""
    from utilities.llm.adapter import ToolUseBlock
    from utilities.llm import LLMResponseError

    state = [0]

    def turn_fn():
        state[0] += 1
        res = SimpleNamespace()
        res.input_tokens = 10
        res.output_tokens = 5
        res.raw = None
        res.usage_details = None
        if state[0] == 1:
            res.content = (ToolUseBlock(id="t1", name="finish",
                                        input={"status": "complete"}),)
            res.stop_reason = "tool_use"
            res.provider_cost_usd = 0.002
            return res
        # the second turn is BILLED and rejected (the #537 class: usage
        # attached to the raise)
        raise LLMResponseError(
            "rejected", input_tokens=1000, output_tokens=500,
            usage_details={"reasoning_tokens": 1})

    t = _agent_drive(monkeypatch, turn_fn,
                     finish_serves=lambda n, i: {"status": "incomplete",
                                                "result": "keep going"})
    totals = t.get_totals()
    rec = t.calls[0]
    # NOT provider-labelled: the raising turn's charge is unknowable, so
    # the conversation must not claim the provider's authoritative total
    assert rec.get("cost_source") != "provider", rec
    assert totals.get("cost_incomplete") is True, (
        f"the mixed conversation read a silent provider label: {rec!r} / "
        f"{totals!r}")
