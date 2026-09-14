"""#616: the standalone verifier's error path records the conversation's
usage — harvest is no longer the only signal.

``verify_result`` had NO try/except around its conversation loop: when the
direct adapter call raised mid-conversation, the frame-local accumulation
(``total_input_tokens``/``total_output_tokens``/``per_turn_usage_details``)
was never recorded, and ``_verify_one``'s handler harvested a tracker the
conversation never wrote — the errored unit read $0 / 0 tokens while the
provider billed both. The #537/#549 fix landed this exact idiom in
``helpers.simple_completion``; the verifier bypasses the helper, so the
fix lands at the boundary the verifier actually uses.

The contract (the process notes): conversation-level record, exactly-once
(every normal exit returns immediately after its own record_call), the
raising turn's own tokens folded in (they live ONLY on the exception — the
accumulation runs after complete returns), a None per-turn entry for the
raising turn, a zero-token guard (a turn-1 connection failure writes NO
$0 call record), and KeyboardInterrupt propagates uncaught (BaseException
— the :983/:1024 handlers keep their shape). No conversation record is
ever relabeled a request.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm import (  # noqa: E402
    CompletionResult,
    LLMConnectionError,
    LLMRateLimitError,
    LLMResponseError,
    TextBlock,
)


from utilities.llm import ToolUseBlock  # noqa: E402


def _result(in_t=1, out_t=1, stop="end_turn", content=None):
    return CompletionResult(
        content=[TextBlock(content or "ok")], stop_reason=stop,
        input_tokens=in_t, output_tokens=out_t, usage_details=None)


def _tool_turn(in_t=1, out_t=1, name="read_function", inp=None):
    """A non-finish tool-call turn: the loop processes the call and
    CONTINUES (the shape needed to reach a second adapter call)."""
    return CompletionResult(
        content=[ToolUseBlock(id="tu1", name=name,
                              input=inp or {"names": []})],
        stop_reason="tool_use", input_tokens=in_t, output_tokens=out_t,
        usage_details=None)


class _Tracker:
    def __init__(self):
        self.calls = []

    def record_call(self, **kw):
        self.calls.append(kw)

    def start_unit_tracking(self):
        pass

    def get_unit_usage(self):
        t_in = sum(c.get("input_tokens", 0) for c in self.calls)
        t_out = sum(c.get("output_tokens", 0) for c in self.calls)
        return {"input_tokens": t_in, "output_tokens": t_out,
                "total_tokens": t_in + t_out, "cost_usd": 0.0}

    def add_prior_usage(self, *a, **kw):
        pass


class _Pricing:
    pricing = {"m/x": {"input": 2.0, "output": 4.0}}


class _Adapter:
    model = "m/x"

    def __init__(self):
        self.pricing = _Pricing.pricing
        self.script = []  # the canned turns/raises

    def complete(self, **kw):
        act = self.script.pop(0)
        if isinstance(act, BaseException):
            raise act
        return act


def _verifier(adapter):
    from types import SimpleNamespace
    from utilities.finding_verifier import FindingVerifier
    adapter.supports_tools = True
    adapter.name = "stub"
    binding = SimpleNamespace(adapter=adapter, model="m/x", phase="verify")
    return FindingVerifier(SimpleNamespace(), binding, tracker=_Tracker())


def _call(v):
    """verify_result's real signature: (code, finding, attack_vector,
    reasoning) — the minimal drive."""
    return v.verify_result("def f(): pass", "vulnerable", "x", "r")


# ---------------------------------------------------------------------------
# the RED: the mid-conversation raise records before re-raising
# ---------------------------------------------------------------------------

def test_mid_conversation_raise_records_exactly_once():
    """Turn 1 succeeds (100/10); turn 2 raises LLMResponseError with its own
    tokens (50/5). Post-fix: exactly ONE record carrying 150/15 and the
    per-turn list [None, None] — the turn-1 details plus the raising
    turn's None entry. Pristine recorded NOTHING."""
    adapter = _Adapter()
    adapter.script = [
        _tool_turn(in_t=100, out_t=10),
        LLMResponseError("boom", input_tokens=50, output_tokens=5),
    ]
    v = _verifier(adapter)
    try:
        _call(v)
        raise AssertionError("the raise must propagate")
    except LLMResponseError:
        pass
    assert len(v.tracker.calls) == 1, v.tracker.calls
    call = v.tracker.calls[0]
    assert call["input_tokens"] == 150
    assert call["output_tokens"] == 15
    assert call["usage_details"] == [None, None]  # turn 1 + the raising turn
    assert call["model"] == "m/x"


def test_the_raise_still_propagates_for_the_handler():
    """The _verify_one handler's shape is unchanged: the exception
    propagates; the handler catches it and sets result['error']."""
    adapter = _Adapter()
    adapter.script = [LLMResponseError("empty", input_tokens=3)]
    v = _verifier(adapter)
    try:
        _call(v)
        raise AssertionError("must raise")
    except LLMResponseError:
        pass
    # the raising turn's own tokens reached the tracker (3 on the exc)
    assert v.tracker.calls[0]["input_tokens"] == 3


# ---------------------------------------------------------------------------
# the exactly-once negatives
# ---------------------------------------------------------------------------

def test_healthy_conversation_records_exactly_once():
    """The control: a healthy conversation — one record, unchanged
    (the unparseable end_turn takes the degenerate-exit record)."""
    adapter = _Adapter()
    adapter.script = [_result(in_t=10, out_t=2, stop="end_turn",
                              content="All good")]
    v = _verifier(adapter)
    _call(v)
    assert len(v.tracker.calls) == 1
    assert v.tracker.calls[0]["input_tokens"] == 10


def test_turn1_connection_failure_writes_no_record():
    """The zero-token guard: a turn-1 LLMConnectionError (nothing
    accumulated, nothing on the exception) writes NO $0 call record —
    the helpers' guard, mirrored."""
    adapter = _Adapter()
    adapter.script = [LLMConnectionError("connection refused")]
    v = _verifier(adapter)
    try:
        _call(v)
        raise AssertionError("must raise")
    except LLMConnectionError:
        pass
    assert v.tracker.calls == []  # the guard


def test_rate_limit_raise_records_accumulated_only():
    """LLMRateLimitError carries no tokens (only retry_after — the adapter
    handles waits internally, so a raise here is the unrecoverable shape):
    the record carries the accumulated totals, nothing from the exception."""
    adapter = _Adapter()
    adapter.script = [
        _tool_turn(in_t=7, out_t=1),
        LLMRateLimitError("limit", retry_after=30),
    ]
    v = _verifier(adapter)
    try:
        _call(v)
        raise AssertionError("must raise")
    except LLMRateLimitError:
        pass
    assert len(v.tracker.calls) == 1
    assert v.tracker.calls[0]["input_tokens"] == 7


def test_keyboard_interrupt_propagates_unrecorded():
    """BaseException: KeyboardInterrupt never enters the except-Exception
    handler — the :983/:1024 handlers keep their shape."""
    adapter = _Adapter()
    adapter.script = [KeyboardInterrupt()]
    v = _verifier(adapter)
    try:
        _call(v)
        raise AssertionError("must raise")
    except KeyboardInterrupt:
        pass
    assert v.tracker.calls == []


def test_the_conversation_is_never_reabeled_a_request():
    """The unit contract: ONE conversation-level record per errored unit
    (never N per-request records) — the per-turn structure lives in the
    usage_details list, not in the call record count."""
    adapter = _Adapter()
    adapter.script = [
        _tool_turn(in_t=10, out_t=1), _tool_turn(in_t=10, out_t=1),
        LLMResponseError("boom", input_tokens=5, output_tokens=1),
    ]
    v = _verifier(adapter)
    try:
        _call(v)
    except LLMResponseError:
        pass
    assert len(v.tracker.calls) == 1
    assert v.tracker.calls[0]["usage_details"] == [None, None, None]

def test_verify_one_harvests_the_errored_units_real_usage():
    """THE end-to-end receipt: the issue was filed over the HARVEST —
    _verify_one's get_unit_usage() reading $0 for an errored unit. With the
    fix, the errored unit's harvested usage carries the conversation's real
    spend (the checkpoint's usage, the resume sum — all downstream)."""
    adapter = _Adapter()
    adapter.supports_tools = True
    adapter.name = "stub"
    adapter.script = [
        _tool_turn(in_t=80, out_t=8),
        LLMResponseError("boom", input_tokens=20, output_tokens=2),
    ]
    from types import SimpleNamespace
    from utilities.finding_verifier import FindingVerifier
    binding = SimpleNamespace(adapter=adapter, model="m/x", phase="verify")
    v = FindingVerifier(SimpleNamespace(), binding, tracker=_Tracker())
    result = {"route_key": "a.py:f", "finding": "vulnerable",
              "stage1_finding": "vulnerable"}
    route_key, detail, elapsed, worker, usage = v._verify_one(
        result, code_by_route={"a.py:f": "def f(): pass"})
    assert detail == "error"
    assert usage["input_tokens"] == 100  # the harvest: real spend, not $0
    assert usage["total_tokens"] == 110
