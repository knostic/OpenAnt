"""#626 on the ERROR path — the F-A1 pin (PR #661 dry-hunt, round 2).

#537 says "a rejected call the provider billed must not vanish from
accounting" and ``LLMResponseError`` carries the rejected reply's
input/output tokens to honour it. #626 then made the CACHE fields price at
their own multipliers — but they travel in ``usage_details``, and the
exception had no ``usage_details`` channel. So ``helpers.simple_completion``'s
error ``record_call`` (helpers.py:95-100), the ONLY error-path accounting
site, could forward input/output only and bypassed #626 entirely:

  EXCLUSIVE (anthropic, cache OUTSIDE input_tokens) -> a COST error:
      success $0.070000 vs rejected $0.025000 on identical provider-billed
      traffic (64 % under), ``cost_incomplete: false`` on BOTH — unflagged.

  INCLUSIVE (openai/openrouter, cache INSIDE prompt_tokens) -> the #598
      masquerade shape: the SAME cost figure, but the error path loses
      ``cost_incomplete``, loses the named model and loses both cache line
      items. A plausible figure labelled complete.

The fix threads ``usage_details`` from the raise to the recorder and records
it through the SAME ``record_call``/``price_usage`` path as success — one
formula, never a second (the #598 lesson).
"""
from __future__ import annotations

import pytest

from utilities.llm.adapter import LLMRefusalError, LLMResponseError
from utilities.llm.helpers import simple_completion
from utilities.llm.providers import anthropic as anthropic_mod
from utilities.llm.providers import openai as openai_mod
from utilities.llm.registry import PhaseBinding
from utilities.llm_client import TokenTracker

# The accounting keys this pin compares. Cost + both cache line items + both
# incompleteness kinds: every surface #626 feeds.
_KEYS = ("total_cost_usd", "cost_incomplete", "unpriced_models",
         "unpriced_cache_models", "total_cache_read_tokens",
         "total_cache_write_tokens")


def _totals(tracker):
    tot = tracker.get_totals()
    return {k: tot.get(k) for k in _KEYS}


# --------------------------------------------------------------------------
# the anthropic / EXCLUSIVE shape
# --------------------------------------------------------------------------

class _AnthUsage:
    def __init__(self, inp=2_000, out=600, read=90_000, write=0):
        self.input_tokens = inp
        self.output_tokens = out
        self.cache_read_input_tokens = read
        self.cache_creation_input_tokens = write


class _TextBlockRaw:
    type = "text"
    text = "hello"


def _anth_resp(usage, *, empty):
    class _R:
        content = [] if empty else [_TextBlockRaw()]
        stop_reason = "end_turn"
    r = _R()
    r.usage = usage
    return r


class _AnthAdapter:
    """Drives the REAL ``anthropic._response_to_unified`` — the success
    return (:478-481) and the empty-content raise (:451-455) both read the
    SAME usage object, which is exactly why the detail is already in hand at
    the raise."""

    name = "anthropic"
    supports_tools = True

    def __init__(self, usage, *, empty, pricing):
        self._usage = usage
        self._empty = empty
        self.pricing = pricing

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return anthropic_mod._response_to_unified(
            _anth_resp(self._usage, empty=self._empty))

    def validate(self, model):
        pass


# --------------------------------------------------------------------------
# the openai / openrouter INCLUSIVE shape
# --------------------------------------------------------------------------

class _PTD:
    def __init__(self, cached=90_000):
        self.cached_tokens = cached


class _ChatUsage:
    def __init__(self, prompt=100_000, completion=1_000, cached=90_000):
        self.prompt_tokens = prompt
        self.completion_tokens = completion
        self.prompt_tokens_details = _PTD(cached)
        self.completion_tokens_details = None


def _chat_resp(usage, *, mode):
    """mode: "ok" | "empty" (openai.py:943) | "nochoices" (openai.py:861)."""
    msg = type("M", (), {"content": "hi" if mode == "ok" else None,
                         "tool_calls": None, "refusal": None})()
    choice = type("C", (), {"message": msg, "finish_reason": "stop"})()

    class _R:
        choices = [] if mode == "nochoices" else [choice]
    r = _R()
    r.usage = usage
    return r


class _ChatAdapter:
    name = "openrouter"
    supports_tools = True

    def __init__(self, usage, *, mode, pricing):
        self._usage = usage
        self._mode = mode
        self.pricing = pricing

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        return openai_mod._response_to_unified(
            _chat_resp(self._usage, mode=self._mode),
            adapter="OpenRouterAdapter")

    def validate(self, model):
        pass


def _drive(adapter, model):
    """One completion through the REAL ``simple_completion``; returns the
    accounting totals whichever arm fired."""
    tracker = TokenTracker()
    binding = PhaseBinding(phase="detect", adapter=adapter, model=model,
                           provider_name=adapter.name)
    try:
        simple_completion(binding, "x", tracker=tracker)
    except LLMResponseError:
        pass
    return _totals(tracker)


# a priced-cache entry (the shipped anthropic census shape) and a
# cache-UNPRICED one (the shipped openrouter census shape)
_ANTH_PRICING = {"claude-opus-5": {"input": 5.0, "output": 25.0,
                                   "cache_read": 0.1, "cache_write": 1.25}}
_OR_PRICING = {"anthropic/claude-opus-5": {"input": 5.0, "output": 25.0}}


class TestErrorCarriesTheChannel:
    """The exception must have somewhere to put the detail."""

    def test_llm_response_error_carries_usage_details(self):
        exc = LLMResponseError("x", input_tokens=1, output_tokens=2,
                               usage_details={"cache_read_input_tokens": 7})
        assert exc.usage_details == {"cache_read_input_tokens": 7}

    def test_absent_usage_details_is_none_not_a_fabricated_empty(self):
        # absent != {} : a fabricated empty dict would read as "the provider
        # reported no cache", which is a different claim (#211 verbatim rule).
        assert LLMResponseError("x").usage_details is None

    def test_refusal_subclass_inherits_the_channel(self):
        # every `except LLMResponseError` handler catches refusals too
        # (adapter.py:307-317) — the accounting channel must come with it.
        exc = LLMRefusalError("x", input_tokens=1,
                              usage_details={"cached_tokens": 5})
        assert exc.usage_details == {"cached_tokens": 5}


class TestRealRaiseSitesAttachTheDetail:
    """All three #537 usage-carrying raise sites, at their real code."""

    def test_anthropic_empty_content_site(self):
        with pytest.raises(LLMResponseError) as ei:
            anthropic_mod._response_to_unified(
                _anth_resp(_AnthUsage(), empty=True))
        # byte-identical to what the success sibling would have captured
        assert ei.value.usage_details == anthropic_mod._extract_usage_details(
            _AnthUsage())
        assert ei.value.usage_details["cache_read_input_tokens"] == 90_000

    def test_openai_chat_empty_completion_site(self):
        usage = _ChatUsage()
        with pytest.raises(LLMResponseError) as ei:
            openai_mod._response_to_unified(_chat_resp(usage, mode="empty"))
        assert ei.value.usage_details == \
            openai_mod._extract_usage_details_chat(usage)
        assert ei.value.usage_details["cached_tokens"] == 90_000

    def test_openai_no_choices_site(self):
        usage = _ChatUsage()
        with pytest.raises(LLMResponseError) as ei:
            openai_mod._response_to_unified(_chat_resp(usage,
                                                       mode="nochoices"))
        assert ei.value.usage_details == \
            openai_mod._extract_usage_details_chat(usage)
        assert ei.value.usage_details["cached_tokens"] == 90_000


class TestExclusiveArmIsACostError:
    """anthropic: the cache read sits OUTSIDE input_tokens, so dropping it
    drops real spend — the 64 % under-report."""

    def test_error_path_prices_the_cache_like_the_success_path(self):
        usage = _AnthUsage()
        ok = _drive(_AnthAdapter(usage, empty=False, pricing=_ANTH_PRICING),
                    "claude-opus-5")
        err = _drive(_AnthAdapter(usage, empty=True, pricing=_ANTH_PRICING),
                     "claude-opus-5")
        # the regression figures, pinned to the cent
        assert ok["total_cost_usd"] == pytest.approx(0.070)
        assert err["total_cost_usd"] == pytest.approx(0.070), (
            "the rejected call lost its cache line item: "
            f"{err['total_cost_usd']} vs {ok['total_cost_usd']}")
        # ONE formula: identical traffic -> identical accounting, every key
        assert err == ok

    def test_the_cache_line_item_survives_the_error(self):
        usage = _AnthUsage(read=90_000, write=4_000)
        err = _drive(_AnthAdapter(usage, empty=True, pricing=_ANTH_PRICING),
                     "claude-opus-5")
        assert err["total_cache_read_tokens"] == 90_000
        assert err["total_cache_write_tokens"] == 4_000


class TestInclusiveArmIsTheMasquerade:
    """openrouter/openai: the cost figure is the same either way, but the
    error path dropped the disclosure — a plausible figure labelled
    complete (#598)."""

    @pytest.mark.parametrize("mode", ["empty", "nochoices"])
    def test_error_path_keeps_cost_incomplete_and_names_the_model(self, mode):
        usage = _ChatUsage()
        err = _drive(_ChatAdapter(usage, mode=mode, pricing=_OR_PRICING),
                     "anthropic/claude-opus-5")
        assert err["cost_incomplete"] is True, (
            "a used-but-unpriced cache on a rejected call must still "
            "disclose — this is the #598 masquerade shape")
        assert err["unpriced_cache_models"] == ["anthropic/claude-opus-5"]
        assert err["total_cache_read_tokens"] == 90_000

    def test_full_parity_with_the_success_arm(self):
        usage = _ChatUsage()
        ok = _drive(_ChatAdapter(usage, mode="ok", pricing=_OR_PRICING),
                    "anthropic/claude-opus-5")
        err = _drive(_ChatAdapter(usage, mode="empty", pricing=_OR_PRICING),
                     "anthropic/claude-opus-5")
        assert err == ok


class TestGuardDoesNotSwallowACacheOnlyCall:
    """A full cache hit can leave zero FRESH input tokens while the provider
    still billed the cached read (exclusive shape: the read is not inside
    input_tokens). The `if exc.input_tokens or exc.output_tokens` guard
    would skip the record entirely and the threading would be moot."""

    def test_cache_only_rejected_call_is_still_recorded(self):
        usage = _AnthUsage(inp=0, out=0, read=90_000)
        err = _drive(_AnthAdapter(usage, empty=True, pricing=_ANTH_PRICING),
                     "claude-opus-5")
        assert err["total_cache_read_tokens"] == 90_000
        # 90000/1e6 * 5.0 * 0.1
        assert err["total_cost_usd"] == pytest.approx(0.045)
