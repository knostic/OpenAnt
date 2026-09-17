"""Regression tests for issue #609 — the enhancement stage's running
summary and per-unit checkpoints omit unsuccessful-attempt spend.

The agent loop attaches the failed attempt's token counts to the error
path's ``agent_state`` (agent.py's except) and nothing else: no tracker
``record_call`` (the exits record, the raise does not), no summary fold
(``_update_summary`` reads only ``agent_metadata``), no checkpoint usage
block (``_save_unit_checkpoint`` reads only metadata), and the retry wipe
(``unit["agent_context"] = {}``) discards the record entirely. A retried
unit's summary/checkpoint therefore report only the successful attempt's
spend while the provider billed every attempt.

Contract locked here:
- a failed attempt's spend (tokens, priced cost, unpriced markers) reaches
  the tracker (the #616 idiom: record on raise, zero-token guard, the
  rejected reply's tokens folded from LLMResponseError, a None per-turn
  entry for the raising turn);
- the running summary folds the error path's ``agent_state`` usage;
- the per-unit checkpoint usage block is CUMULATIVE across attempts (and
  across runs for a re-attempted errored unit) so a resume does not orphan
  run-1 spend;
- re-error counter behavior is pinned INTENTIONAL (a re-errored retry does
  not re-increment ``errors``; the error-breakdown keeps the original type).

Deliberately NOT covered: raises outside the agent loop's narrow try (tool
result capping, message construction) and KeyboardInterrupt - the same
disclosed residual as #616 (test_issue616_verifier_error_usage.py).
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm.adapter import (  # noqa: E402
    CompletionResult,
    LLMConnectionError,
    LLMRateLimitError,
    LLMResponseError,
    ToolUseBlock,
)
from utilities.llm_client import TokenTracker, reset_warning_state  # noqa: E402


def _read_summary(checkpoint_dir: Path) -> dict:
    return json.loads((Path(checkpoint_dir) / "_summary.json").read_text())


def _read_unit_cp(checkpoint_dir: Path, unit_id: str) -> dict:
    from core.checkpoint import id_keyed_checkpoint_map
    cp_map = id_keyed_checkpoint_map(str(checkpoint_dir))
    return json.loads(Path(cp_map[unit_id]).read_text())


def _cost_eq(a: float, b: float) -> bool:
    return math.isclose(a, b, abs_tol=1e-9)


def _binding(adapter, model="fake-model"):
    from utilities.llm.registry import PhaseBinding
    return PhaseBinding(phase="enhance", adapter=adapter, model=model,
                        provider_name="fake")


def _harness_binding():
    class _Adapter:
        name = "fake"
        supports_tools = True
        pricing = {"fake-model": {"input": 3.0, "output": 15.0}}

    return _binding(_Adapter())


# ---------------------------------------------------------------------------
# A - the agent's error path records the attempt (real ContextAgent)
# ---------------------------------------------------------------------------
class _ScriptedAdapter:
    """Keyword-only complete(); scripts one response per turn then raises."""

    name = "fake"
    supports_tools = True

    def __init__(self, pricing, responses, failure):
        self._pricing = pricing
        self._responses = list(responses)
        self._failure = failure
        self.turn = 0

    @property
    def pricing(self):
        return self._pricing

    def complete(self, *, model, max_tokens, system, tools, messages):
        self.turn += 1
        if self.turn <= len(self._responses):
            return self._responses[self.turn - 1]
        raise self._failure


def _tool_turn(input_tokens, output_tokens):
    return CompletionResult(
        content=(ToolUseBlock(id="t1", name="get_static_dependencies", input={}),),
        input_tokens=input_tokens, output_tokens=output_tokens,
        stop_reason="tool_use", usage_details={"reasoning_tokens": 7})


def _real_agent(adapter):
    from utilities.agentic_enhancer.agent import ContextAgent
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    tracker = TokenTracker()
    agent = ContextAgent(index=RepositoryIndex({}, repo_path=None),
                         binding=_binding(adapter), tracker=tracker)
    return agent, tracker


def test_agent_error_path_records_attempt_spend():
    """A raise after a billed iteration: the completed turns' spend reaches
    the tracker and the error state carries the SAME numbers (cost included)."""
    reset_warning_state()
    adapter = _ScriptedAdapter(
        {"fake-model": {"input": 3.0, "output": 15.0}},
        [_tool_turn(100, 10)],
        LLMConnectionError("transport died"))
    agent, tracker = _real_agent(adapter)
    with pytest.raises(LLMConnectionError) as excinfo:
        agent.analyze_unit(unit_id="a.py:f", unit_type="function",
                           primary_code="def f(): ...",
                           static_deps=[], static_callers=[])
    totals = tracker.get_totals()
    assert totals["total_input_tokens"] == 100
    assert totals["total_output_tokens"] == 10
    assert _cost_eq(totals["total_cost_usd"], 100 / 1e6 * 3.0 + 10 / 1e6 * 15.0)
    # the healthy error path does NOT tick the #605 counter (present-only:
    # the marker appears only when an accounting failure is swallowed)
    assert "accounting_errors" not in totals
    state = excinfo.value.agent_state
    assert state["input_tokens"] == 100
    assert state["output_tokens"] == 10
    assert _cost_eq(state["cost_usd"], 100 / 1e6 * 3.0 + 10 / 1e6 * 15.0)
    # the call record's per-turn list carries ONLY the completed turns -
    # a connection error carries no tokens, so no None entry (the #616
    # convention: the list length equals the turns billed)
    assert tracker.get_summary()["calls"][0]["usage_details"] == [
        {"reasoning_tokens": 7}]
    reset_warning_state()


def test_agent_response_error_tokens_recorded():
    """An LLMResponseError carries the REJECTED reply's usage (#537): the
    raising turn's tokens join the record, not vanish."""
    reset_warning_state()
    adapter = _ScriptedAdapter(
        {"fake-model": {"input": 3.0, "output": 15.0}},
        [_tool_turn(100, 10)],
        LLMResponseError("malformed", input_tokens=50, output_tokens=5))
    agent, tracker = _real_agent(adapter)
    with pytest.raises(LLMResponseError):
        agent.analyze_unit(unit_id="a.py:f", unit_type="function",
                           primary_code="def f(): ...",
                           static_deps=[], static_callers=[])
    totals = tracker.get_totals()
    assert totals["total_input_tokens"] == 150
    assert totals["total_output_tokens"] == 15
    assert _cost_eq(totals["total_cost_usd"], 150 / 1e6 * 3.0 + 15 / 1e6 * 15.0)
    # the raising turn carried tokens -> its per-turn entry is None
    # (the list length equals the turns billed, #616)
    assert tracker.get_summary()["calls"][0]["usage_details"] == [
        {"reasoning_tokens": 7}, None]
    reset_warning_state()


def test_agent_turn1_failure_records_nothing():
    """GREEN (regression lock): a turn-1 connection raise billed nothing -
    the zero-token guard writes NO $0 record and no unpriced marker."""
    reset_warning_state()
    adapter = _ScriptedAdapter(
        {"fake-model": {"input": 3.0, "output": 15.0}},
        [],
        LLMConnectionError("transport died"))
    agent, tracker = _real_agent(adapter)
    with pytest.raises(LLMConnectionError) as excinfo:
        agent.analyze_unit(unit_id="a.py:f", unit_type="function",
                           primary_code="def f(): ...",
                           static_deps=[], static_callers=[])
    assert tracker.get_totals()["total_calls"] == 0
    assert excinfo.value.agent_state["cost_usd"] == 0.0
    assert "unpriced_models" not in excinfo.value.agent_state
    reset_warning_state()


def test_record_failure_preserves_original_exception():
    """GREEN (regression lock for the #609 inner guard): if the accounting
    record itself raises inside the except, the ORIGINAL exception survives
    - its retryability class must not be silently reclassified - and the
    swallowed failure is LOUD in the artifacts (#605: the accounting-error
    counter ticks, never a complete-looking artifact)."""
    from utilities.agentic_enhancer.agent import ContextAgent
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.llm_client import get_global_tracker

    class _PoisonTracker(TokenTracker):
        def record_call(self, **kw):
            raise KeyError("poison pricing dict")

    reset_warning_state()  # zeroes the #605 counter (per-scan lifecycle)
    adapter = _ScriptedAdapter(
        {"fake-model": {"input": 3.0, "output": 15.0}},
        [_tool_turn(100, 10)],
        LLMRateLimitError("rate limited", retry_after=0))
    agent = ContextAgent(index=RepositoryIndex({}, repo_path=None),
                         binding=_binding(adapter), tracker=_PoisonTracker())
    with pytest.raises(LLMRateLimitError):
        agent.analyze_unit(unit_id="a.py:f", unit_type="function",
                           primary_code="def f(): ...",
                           static_deps=[], static_callers=[])
    # #605: the swallowed accounting failure surfaced in get_totals()
    # (present-only key, via the GLOBAL tracker the counter rides on) —
    # exactly once: the reset at the top zeroes the counter and a single
    # guarded record_call attempt is all this run can tick (a double-tick
    # regression must fail here, matching the #605 pins).
    assert get_global_tracker().get_totals()["accounting_errors"] == 1
    reset_warning_state()


# ---------------------------------------------------------------------------
# B/D - the summary and checkpoint carry the attempt (real enhance flow,
# stubbed enhance_unit_with_agent - the #293 harness pattern)
# ---------------------------------------------------------------------------
def _drive(dataset, checkpoint_dir, binding=None, enhance=None, workers=1,
           tracker=None):
    """Drive the REAL enhance_dataset_agentic with a stubbed unit enhancer.

    The real ``enhance_unit_with_agent`` is captured BEFORE the patch and
    restored in ``finally`` (the capture-then-patch discipline; a
    self-referential patch has passed vacuously twice before).
    """
    import utilities.context_enhancer as ce
    real = ce.enhance_unit_with_agent
    if enhance is not None:
        ce.enhance_unit_with_agent = enhance
    try:
        enhancer = ce.ContextEnhancer(binding=binding or _harness_binding(),
                                      tracker=tracker)
        analyzer_out = Path(checkpoint_dir).parent / "a.json"
        analyzer_out.write_text(json.dumps({"results": []}))
        enhancer.enhance_dataset_agentic(
            dataset, analyzer_output_path=str(analyzer_out),
            repo_path=None, workers=workers, checkpoint_path=str(checkpoint_dir))
        return _read_summary(checkpoint_dir)
    finally:
        ce.enhance_unit_with_agent = real


def _fail_with_state(tokens_in, tokens_out, cost):
    # RuntimeError: NON-retryable - a single error event, no re-attempt
    # (the retryable shapes live in _retry_harness).
    def fake(unit, index, binding, tracker, verbose):
        err = RuntimeError("enhance exploded")
        err.agent_state = {"input_tokens": tokens_in, "output_tokens": tokens_out,
                           "cost_usd": cost}
        raise err
    return fake


def test_error_attempt_spend_reaches_summary(tmp_path):
    """B: the running summary folds the error path's agent_state usage -
    tokens, priced cost, and the #216 unpriced marker (present-only)."""
    reset_warning_state()
    def fake(unit, index, binding, tracker, verbose):
        err = RuntimeError("enhance exploded")
        err.agent_state = {"input_tokens": 100, "output_tokens": 10,
                           "cost_usd": 0.03, "unpriced_models": ["fake/x"]}
        raise err
    cp_dir = tmp_path / "cp"
    s = _drive({"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
               cp_dir, enhance=fake)
    assert s["usage"]["input_tokens"] == 100
    assert s["usage"]["output_tokens"] == 10
    assert _cost_eq(s["usage"]["cost_usd"], 0.03)
    assert s["usage"]["cost_incomplete"] is True
    assert s["usage"]["unpriced_models"] == ["fake/x"]
    reset_warning_state()


def test_error_checkpoint_carries_attempt_spend(tmp_path):
    """D: a non-retryable error's checkpoint file carries the attempt's
    usage (read from the error state AT SAVE TIME - the save happens inside
    the worker, before any main-thread fold)."""
    reset_warning_state()
    cp_dir = tmp_path / "cp"
    _drive({"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]},
           cp_dir, enhance=_fail_with_state(100, 10, 0.03))
    cp = _read_unit_cp(cp_dir, "u1")
    assert cp["usage"]["input_tokens"] == 100
    assert cp["usage"]["output_tokens"] == 10
    assert _cost_eq(cp["usage"]["cost_usd"], 0.03)
    reset_warning_state()


def test_parallel_error_checkpoint_carries_attempt_spend(tmp_path):
    """D under parallel workers: the worker-thread save still sees the
    attempt state (prior_spend is written on the main thread only; the
    current attempt's state lives on the unit's error context)."""
    reset_warning_state()
    cp_dir = tmp_path / "cp"
    dataset = {"units": [{"id": f"u{i}", "code": {"primary_code": "x=1"}}
                         for i in range(2)]}
    _drive(dataset, cp_dir, enhance=_fail_with_state(50, 5, 0.01), workers=2)
    for i in range(2):
        cp = _read_unit_cp(cp_dir, f"u{i}")
        assert cp["usage"]["input_tokens"] == 50
        assert _cost_eq(cp["usage"]["cost_usd"], 0.01)
    s = _read_summary(cp_dir)
    assert s["usage"]["input_tokens"] == 100
    reset_warning_state()


# ---------------------------------------------------------------------------
# C/D - the retry path
# ---------------------------------------------------------------------------
def _retry_harness(unit_script, tmp_path, workers=1):
    """unit_script: id -> list of behaviors ('S:<in>:<out>:<cost>' attempt
    state error, or 'M:<in>:<out>:<cost>' success meta). Drives the real
    flow; returns (summary, per-unit checkpoints)."""
    calls = {}

    def fake(unit, index, binding, tracker, verbose):
        uid = unit["id"]
        n = calls.get(uid, 0)
        calls[uid] = n + 1
        step = unit_script[uid][n]
        if step.startswith("S:"):
            _, tin, tout, cost = step.split(":")
            err = LLMRateLimitError("rate limited", retry_after=0)
            err.agent_state = {"input_tokens": int(tin), "output_tokens": int(tout),
                               "cost_usd": float(cost)}
            raise err
        _, tin, tout, cost = step.split(":")
        unit["agent_context"] = {
            "security_classification": "safe",
            "agent_metadata": {"input_tokens": int(tin), "output_tokens": int(tout),
                               "cost_usd": float(cost)},
        }

    s = _drive({"units": [{"id": uid, "code": {"primary_code": "x=1"}}
                          for uid in unit_script]},
               tmp_path / "cp", enhance=fake, workers=workers)
    cps = {uid: _read_unit_cp(tmp_path / "cp", uid) for uid in unit_script}
    return s, cps


def test_retry_success_carries_attempt_plus_meta(tmp_path):
    """C+D: a retry that succeeds - the summary and the OVERWRITTEN
    checkpoint carry attempt + retry meta (the wipe moved the attempt into
    the prior map; the recompute-from-parts save is idempotent)."""
    reset_warning_state()
    s, cps = _retry_harness(
        {"u1": ["S:100:10:0.03", "M:200:20:0.06"]}, tmp_path)
    assert s["usage"]["input_tokens"] == 300
    assert s["usage"]["output_tokens"] == 30
    assert _cost_eq(s["usage"]["cost_usd"], 0.09)
    cp = cps["u1"]
    assert cp["usage"]["input_tokens"] == 300
    assert _cost_eq(cp["usage"]["cost_usd"], 0.09)
    reset_warning_state()


def test_retry_reerror_folds_new_attempt(tmp_path):
    """C: a retry that errors again - the NEW attempt's state folds (the
    prior attempt was folded at its own error event). Counter behavior is
    pinned INTENTIONAL: a re-errored retry does NOT re-increment errors and
    the error breakdown keeps the ORIGINAL type (stale by design)."""
    reset_warning_state()
    s, cps = _retry_harness(
        {"u1": ["S:100:10:0.03", "S:50:5:0.015"]}, tmp_path)
    assert s["usage"]["input_tokens"] == 150
    assert _cost_eq(s["usage"]["cost_usd"], 0.045)
    cp = cps["u1"]
    assert cp["usage"]["input_tokens"] == 150
    assert _cost_eq(cp["usage"]["cost_usd"], 0.045)
    # counters: one error, original breakdown type, no double count
    assert s["errors"] == 1
    assert s["error_breakdown"] == {"rate_limit": 1}
    reset_warning_state()


def test_multiround_accumulation(tmp_path):
    """D across reachable retry rounds: uA recovers in round 1 (keeping the
    round alive for uB); uB fails twice then succeeds in round 2 - its
    checkpoint carries all three attempts' spend."""
    reset_warning_state()
    s, cps = _retry_harness(
        {"uA": ["S:10:1:0.003", "M:20:2:0.006"],
         "uB": ["S:100:10:0.03", "S:50:5:0.015", "M:200:20:0.06"]},
        tmp_path)
    cpB = cps["uB"]
    assert cpB["usage"]["input_tokens"] == 350
    assert _cost_eq(cpB["usage"]["cost_usd"], 0.105)
    # summary: uA(10+20 in) + uB(100+50+200 in)
    assert s["usage"]["input_tokens"] == 380
    assert _cost_eq(s["usage"]["cost_usd"], 0.003 + 0.006 + 0.03 + 0.015 + 0.06)
    reset_warning_state()


# ---------------------------------------------------------------------------
# D-resume - a fresh run over an errored unit's checkpoint
# ---------------------------------------------------------------------------
def test_resume_carries_prior_attempt_spend(tmp_path):
    """Run-1 errors a unit (its checkpoint carries the attempt usage);
    run-2 (fresh enhancer AND fresh tracker) re-attempts and succeeds: the
    summary seeds run-1's spend and adds run-2's; the OVERWRITTEN
    checkpoint carries both; the tracker carries the injected prior.

    Usage-only assertions ON PURPOSE: the bucket counts on this path hit a
    pre-existing seed defect (the restored-errors seed is not decremented
    when the re-attempt succeeds) - disclosed in the PR body, out of scope.
    """
    reset_warning_state()
    import utilities.context_enhancer as ce
    dataset = {"units": [{"id": "u1", "code": {"primary_code": "x=1"}}]}
    cp_dir = tmp_path / "cp"
    analyzer_out = tmp_path / "a.json"
    analyzer_out.write_text(json.dumps({"results": []}))

    real = ce.enhance_unit_with_agent

    # run-1: non-retryable error with attempt state
    def fail_once(unit, index, binding, tracker, verbose):
        err = RuntimeError("enhance exploded")
        err.agent_state = {"input_tokens": 100, "output_tokens": 10,
                           "cost_usd": 0.03}
        raise err
    try:
        ce.enhance_unit_with_agent = fail_once
        e1 = ce.ContextEnhancer(binding=_harness_binding(),
                                tracker=TokenTracker())
        e1.enhance_dataset_agentic(dataset, analyzer_output_path=str(analyzer_out),
                                   repo_path=None, workers=1,
                                   checkpoint_path=str(cp_dir))

        # run-2: fresh enhancer + fresh tracker, succeeds
        def succeed(unit, index, binding, tracker, verbose):
            unit["agent_context"] = {
                "security_classification": "safe",
                "agent_metadata": {"input_tokens": 200, "output_tokens": 20,
                                   "cost_usd": 0.06},
            }
        ce.enhance_unit_with_agent = succeed
        e2 = ce.ContextEnhancer(binding=_harness_binding(),
                                tracker=TokenTracker())
        e2.enhance_dataset_agentic(dataset, analyzer_output_path=str(analyzer_out),
                                   repo_path=None, workers=1,
                                   checkpoint_path=str(cp_dir))
    finally:
        ce.enhance_unit_with_agent = real

    s = _read_summary(cp_dir)
    assert s["usage"]["input_tokens"] == 300
    assert _cost_eq(s["usage"]["cost_usd"], 0.09)
    cp = _read_unit_cp(cp_dir, "u1")
    assert cp["usage"]["input_tokens"] == 300
    assert _cost_eq(cp["usage"]["cost_usd"], 0.09)
    # the tracker leg: the seed injects run-1's spend (the fake records
    # nothing for run-2 - the real-agent record is pinned in the A tests)
    assert e2.tracker.get_totals()["total_input_tokens"] == 100
    assert _cost_eq(e2.tracker.get_totals()["total_cost_usd"], 0.03)
    reset_warning_state()


# ---------------------------------------------------------------------------
# A+E through the real agent - unpriced attempt markers
# ---------------------------------------------------------------------------
def test_unpriced_attempt_markers(tmp_path):
    """A+E, fresh tracker: an attempt on an unpriced model - the record
    takes the #216 loud path; the error state, the summary, and the
    checkpoint all carry the incomplete-cost marker."""
    reset_warning_state()
    import utilities.context_enhancer as ce
    adapter = _ScriptedAdapter(
        {},  # no pricing record for the model
        [_tool_turn(100, 10)],
        LLMConnectionError("transport died"))
    binding = _binding(adapter)
    e1 = ce.ContextEnhancer(binding=binding, tracker=TokenTracker())
    analyzer_out = tmp_path / "a.json"
    analyzer_out.write_text(json.dumps({"results": []}))
    cp_dir = tmp_path / "cp"
    dataset = {"units": [{"id": "u1", "code": {"primary_code": "def f(): ..."},
                         "unit_type": "function"}]}
    e1.enhance_dataset_agentic(dataset, analyzer_output_path=str(analyzer_out),
                               repo_path=None, workers=1,
                               checkpoint_path=str(cp_dir))
    s = _read_summary(cp_dir)
    assert s["usage"]["input_tokens"] == 100
    assert s["usage"]["cost_incomplete"] is True
    assert s["usage"]["unpriced_models"] == ["fake-model"]
    cp = _read_unit_cp(cp_dir, "u1")
    assert cp["usage"]["unpriced_models"] == ["fake-model"]
    # the tracker's loud path fired exactly once for the model
    totals = e1.tracker.get_totals()
    assert totals.get("unpriced_models") == ["fake-model"]
    reset_warning_state()
