"""#625 — the request-side thinking policy: exposed, gated, recorded, and
the dropped blocks counted.

The adapter had no request-side thinking control while the SDK accepts
one, and the response translation dropped unsupported block kinds
(thinking; refusal) with a once-per-kind stderr warning while forwarding
their usage — the delivered content and the billed content could differ
by an invisible amount. This is an ENHANCEMENT with a hard constraint:
the DEFAULT stays byte-identical (the #242 instrument lesson — verdict
behavior is evaluated separately, never mixed with a usage-accounting
change).

Two-sided discipline: the default rows assert BOTH the request's
full-dict equality (no thinking key) AND the unchanged artifacts; the
knob rows assert the request carries the exact dict; the gate rows
assert the loud ConfigError AND the phase-naming message; the count rows
assert the per-kind dict AND its absence when nothing dropped.
"""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

import utilities.llm.providers.anthropic as anth  # noqa: E402
import utilities.llm.registry as registry_mod  # noqa: E402
from unittest.mock import MagicMock  # noqa: E402

import anthropic as _anthropic_sdk  # noqa: E402
from utilities.llm.adapter import (  # noqa: E402
    LLMResponseError, Message, TextBlock, ToolDef)
from utilities.llm.config import (  # noqa: E402
    ConfigError, LLMConfig, PhaseRef, _serialise_config)


def _parse_thinking(config_name, phase, value):
    """Lazy: the symbol is #625's own addition — importing it lazily keeps
    this file COLLECTABLE on the pre-fix base so the RED table is per-test,
    not a collection error (the #623 lesson)."""
    from utilities.llm.config import _parse_thinking as _real  # noqa: PLC0415
    return _real(config_name, phase, value)


_USER_MSG = [Message(role="user", content=[TextBlock(text="hi")])]
_TOOL = [ToolDef(name="t", description="d", input_schema={"type": "object"})]


def _fake_client():
    c = MagicMock(spec=_anthropic_sdk.Anthropic)
    c.messages.create = MagicMock(
        side_effect=lambda **kw: _stub_response([_text_block()]))
    return c


def _adapter(thinking=None, client=None):
    return anth.AnthropicAdapter(
        _client=client or _fake_client(), thinking=thinking)


def _stub_response(blocks, stop="end_turn"):
    return SimpleNamespace(
        content=blocks,
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
        stop_reason=stop,
    )


def _text_block(text="hi"):
    return SimpleNamespace(type="text", text=text)


def _thinking_block():
    return SimpleNamespace(type="thinking", thinking="inner", signature="s")


def _refusal_block():
    return SimpleNamespace(type="refusal", refusal="no")


# --- T1: the default path is byte-identical ------------------------------------

def test_default_request_carries_no_thinking_key():
    a = _adapter()
    a.complete(model="m", system="s", max_tokens=100,
               messages=_USER_MSG)
    kw = a._client.messages.create.call_args.kwargs
    assert "thinking" not in kw, "the default request carries NO thinking key"
    assert kw == {
        "model": "m", "max_tokens": 100,
        "system": "s",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
    }, "the full-dict equality — no junk keys slipped in"


def test_validate_probe_never_carries_thinking():
    """The 1-token startup probe CANNOT satisfy enabled's budget<max_tokens
    constraint (budget >= 1024 vs max_tokens=1) — carrying the policy would
    400 every thinking-configured scan at startup. The probe tests the
    transport; the policy surfaces at the first real call (documented)."""
    a = _adapter(thinking={"type": "adaptive"})
    a.validate(model="m")
    kw = a._client.messages.create.call_args.kwargs
    assert "thinking" not in kw


# --- T2: the three config shapes thread to the request ---------------------------

def test_adaptive_threads():
    a = _adapter(thinking={"type": "adaptive"})
    a.complete(model="m", system=None, max_tokens=100,
               messages=_USER_MSG)
    assert a._client.messages.create.call_args.kwargs["thinking"] == {"type": "adaptive"}


def test_enabled_threads_and_the_budget_preflight_raises():
    """enabled requires budget_tokens >= 1024 AND < the call's max_tokens —
    a budget that cannot fit THIS call fails LOUD before the request is
    paid, never clamped (clamping is a silent instrument change)."""
    a = _adapter(thinking={"type": "enabled", "budget_tokens": 8192})
    msg = _USER_MSG[0]
    try:
        a.complete(model="m", system=None, max_tokens=4096, messages=[msg])
    except LLMResponseError as e:
        assert "budget_tokens" in str(e)
    else:
        raise AssertionError("the pre-flight must fire (8192 >= 4096)")
    a._client.messages.create.assert_not_called()
    # a fitting budget passes through verbatim
    a2 = _adapter(thinking={"type": "enabled", "budget_tokens": 1024})
    a2.complete(model="m", system=None, max_tokens=4096, messages=_USER_MSG)
    assert a2._client.messages.create.call_args.kwargs["thinking"] == {
        "type": "enabled", "budget_tokens": 1024}


def test_explicit_disabled_is_a_distinct_request():
    """{"type": "disabled"} is a DIFFERENT request than the absent key —
    the round trip must preserve the distinction."""
    a = _adapter(thinking={"type": "disabled"})
    a.complete(model="m", system=None, max_tokens=100,
               messages=_USER_MSG)
    assert a._client.messages.create.call_args.kwargs["thinking"] == {"type": "disabled"}


# --- T3: the config parse/serialise -----------------------------------------------

def test_config_parse_validation():
    ok = {"type": "enabled", "budget_tokens": 2048}
    assert _parse_thinking("c", "analyze", ok) == ok
    assert _parse_thinking("c", "analyze", {"type": "adaptive"}) == {"type": "adaptive"}
    assert _parse_thinking("c", "analyze", {"type": "disabled"}) == {"type": "disabled"}
    assert _parse_thinking("c", "analyze", None) is None
    for bad in ({"type": "weird"},
                {"type": "enabled", "budget_tokens": 512},
                {"type": "enabled", "budget_tokens": True},
                {"type": "enabled", "budget_tokens": "x"},
                {"type": "enabled"},  # budget required
                {"type": "adaptive", "extra": 1},
                "adaptive", 42, []):
        try:
            _parse_thinking("c", "analyze", bad)
        except ConfigError:
            pass
        else:
            raise AssertionError(f"must reject {bad!r}")


def test_config_roundtrip_preserves_none_and_disabled():
    cfg = LLMConfig(name="c", phases={
        **{p: PhaseRef(provider="p", model="m") for p in _ALL_PHASES},
        "analyze": PhaseRef(provider="p", model="m",
                            thinking={"type": "disabled"}),
    })
    out = _serialise_config(cfg)
    assert out["analyze"]["thinking"] == {"type": "disabled"}
    assert "thinking" not in out["verify"], "the default serialises absent"
    reparsed = {
        ph: PhaseRef(provider=e["provider"], model=e["model"],
                     thinking=_parse_thinking("c", ph, e.get("thinking")))
        for ph, e in out.items()}
    assert reparsed["verify"].thinking is None
    assert reparsed["analyze"].thinking == {"type": "disabled"}
    assert "thinking" not in out["verify"], "the default serialises absent"


# --- T4: the tool-phase gate --------------------------------------------------------

_ALL_PHASES = ("analyze", "enhance", "verify", "report", "dynamic_test",
               "llm_reach", "app_context")


def _registry_for(phases: dict):
    """The full required phase set with the test's overrides applied."""
    from utilities.llm.config import ConfigFile, ProviderConfig
    cf = ConfigFile(llm_providers={"p": ProviderConfig(
        name="p", type="anthropic", api_key="dummy-key")})
    full = {p: PhaseRef(provider="p", model="m") for p in _ALL_PHASES}
    full.update(phases)
    return registry_mod.build_phase_registry(
        cf, LLMConfig(name="c", phases=full))


def test_tool_phase_gate_fires():
    """The platform REQUIRES thinking blocks echoed back with tool results;
    the loops carry text/tool-use only and the adapter cannot serialise
    thinking — a thinking-configured tool phase hard-fails every multi-turn
    unit at turn 2. Refused at BUILD time, naming the phase."""
    for phase in ("enhance", "verify"):
        try:
            _registry_for({phase: PhaseRef(provider="p", model="m",
                                            thinking={"type": "adaptive"})})
        except ConfigError as e:
            assert phase in str(e) and "tool-calling phase" in str(e)
        else:
            raise AssertionError(f"the gate must fire for {phase}")


def test_explicit_disabled_passes_the_tool_phase_gate():
    """disabled produces NO thinking blocks — nothing to echo; the gate
    (and the adapter backstop) deliberately let it through (the panel
    round's over-fire catch)."""
    r = _registry_for({"verify": PhaseRef(
        provider="p", model="m", thinking={"type": "disabled"})})
    assert r.get("verify").thinking == {"type": "disabled"}


def test_adapter_tool_backstop_fires_before_the_paid_call():
    """The EXHAUSTIVE half: ANY non-disabled thinking policy on a
    tool-carrying call fails loud HERE — covering the phases the
    build-time list cannot name (app_context drives BOTH a single-turn
    path and the threat-model repo-explorer tool loop)."""
    a = _adapter(thinking={"type": "adaptive"})
    try:
        a.complete(model="m", system=None, max_tokens=100,
                   messages=_USER_MSG, tools=_TOOL)
    except LLMResponseError as e:
        assert "tool-carrying call" in str(e)
    else:
        raise AssertionError("the backstop must fire")
    a._client.messages.create.assert_not_called()
    # disabled rides tool calls fine
    a2 = _adapter(thinking={"type": "disabled"})
    a2.complete(model="m", system=None, max_tokens=100,
                messages=_USER_MSG, tools=_TOOL)
    assert a2._client.messages.create.call_args.kwargs["thinking"] == {"type": "disabled"}


def test_budget_bounded_at_parse_time_for_subcall_caps():
    """The phase's binding serves sub-calls at 4096/8192 caps (JSON
    correction, stage-1 consistency) — a budget above the smallest would
    fail those mid-scan (and the consistency pass swallows exceptions
    SILENTLY: a bare except at stage1_consistency.py would disable the
    check without a trace). Bounded at parse time, naming the phase."""
    try:
        _parse_thinking("c", "analyze",
                        {"type": "enabled", "budget_tokens": 8192})
    except ConfigError as e:
        assert "4096" in str(e) and "sub-calls" in str(e)
    else:
        raise AssertionError("the parse-time bound must fire")
    assert _parse_thinking("c", "analyze", {"type": "enabled", "budget_tokens": 2048}) == {"type": "enabled", "budget_tokens": 2048}


def test_single_turn_phase_builds_and_binding_carries_policy():
    r = _registry_for({"analyze": PhaseRef(
        provider="p", model="m", thinking={"type": "adaptive"})})
    b = r.get("analyze")
    assert b.thinking == {"type": "adaptive"}, "the binding carries the policy"


def test_mixed_policies_behind_one_provider_get_distinct_adapters():
    r = _registry_for({
        "analyze": PhaseRef(provider="p", model="m",
                            thinking={"type": "adaptive"}),
        "report": PhaseRef(provider="p", model="m"),
    })
    assert r.get("analyze").adapter is not r.get("report").adapter, (
        "a thinking-configured phase and a default phase behind the same "
        "provider need DIFFERENT request dicts")


# --- T5: the per-kind dropped-block diagnostic -------------------------------------

def test_dropped_blocks_per_kind_on_the_result():
    anth.reset_warnings()
    resp = _stub_response([_thinking_block(), _refusal_block(), _text_block()])
    result = anth._response_to_unified(resp, adapter="AnthropicAdapter")
    assert result.dropped_blocks == {"thinking": 1, "refusal": 1}, (
        "PER-KIND — a routine kind must not bury a dropped refusal")
    assert len(result.content) == 1


def test_dropped_blocks_absent_when_nothing_dropped():
    anth.reset_warnings()
    resp = _stub_response([_text_block()])
    result = anth._response_to_unified(resp, adapter="AnthropicAdapter")
    assert result.dropped_blocks is None, (
        "present-only — the default path stays byte-identical")


def test_the_counter_persists_and_resets():
    anth.reset_warnings()
    anth._count_dropped_block("refusal")
    anth._count_dropped_block("refusal")
    anth._count_dropped_block("thinking")
    assert anth.get_dropped_block_counts() == {"refusal": 2, "thinking": 1}
    anth.reset_warnings()
    assert anth.get_dropped_block_counts() == {}, (
        "the per-scan lifecycle (the #605 counter discipline)")


def test_the_totals_flow_present_only():
    from utilities.llm_client import get_dropped_block_totals
    anth.reset_warnings()
    try:
        assert get_dropped_block_totals() == {}
        anth._count_dropped_block("refusal")
        assert get_dropped_block_totals() == {"refusal": 1}
    finally:
        anth.reset_warnings()


# --- T6: the fingerprint fold (only-when-set) -----------------------------------------

def test_fingerprint_fold_only_when_set():
    from core.backend_identity import fingerprint_for_binding
    from core.analyzer import _analyze_fingerprint

    class _A:
        name = "fake"

        def complete(self, **kw):
            raise AssertionError("not called")
    base = registry_mod.PhaseBinding(phase="analyze", adapter=_A(), model="m",
                        provider_name="p", base_url=None, thinking=None)
    withp = registry_mod.PhaseBinding(phase="analyze", adapter=_A(), model="m",
                          provider_name="p", base_url=None,
                          thinking={"type": "adaptive"})
    texts = ["t1", "t2"]
    d_none = fingerprint_for_binding(base, texts, extra_key=None)
    d_set = fingerprint_for_binding(withp, texts, extra_key={"thinking": dict(withp.thinking)})
    assert d_none["key_digest"] != d_set["key_digest"], (
        "a non-default policy must re-pay")
    # two different policies differ
    other = fingerprint_for_binding(
        withp, texts,
        extra_key={"thinking": {"type": "disabled"}})
    assert other["key_digest"] != d_set["key_digest"]
    # the BEHAVIORAL pin (the #546 shape — the direct call, not a hand-built
    # extra_key): the production fold puts thinking in fp["extra"] only-when-set
    fp_set = _analyze_fingerprint(withp, ctx_sha=None)
    assert fp_set["extra"]["thinking"] == {"type": "adaptive"}, (
        "the analyzer's production fold fires")
    fp_none = _analyze_fingerprint(base, ctx_sha=None)
    assert "thinking" not in fp_none.get("extra", {}), (
        "the None fold leaves the digest unchanged")


def test_binding_default_thinking_is_none():

    class _A:
        name = "fake"
    b = registry_mod.PhaseBinding(phase="analyze", adapter=_A(), model="m",
                     provider_name="p")
    assert b.thinking is None, "the dataclass default — zero re-pay"


# --- T7: the step-report surfaces ------------------------------------------------------

_HERE = Path(__file__).resolve().parents[1]


def test_analyze_step_inputs_gain_policy_present_only():
    """The scanner's analyze step inputs carry the policy only-when-set
    (the default step report stays byte-identical). CWD-anchored (the
    #604 pattern — Path(__file__), never the process CWD)."""
    src = (_HERE / "core" / "scanner.py").read_text()
    assert '"thinking": dict(analyze_binding.thinking)' in src, (
        "the scanner's analyze inputs thread the policy")
    assert 'is not None else {}' in src, "the present-only conditional"


def test_results_json_experiment_gains_policy():
    src = (_HERE / "core" / "analyzer.py").read_text()
    assert '"thinking": dict(binding.thinking)' in src, (
        "the results.json experiment block threads the policy")


