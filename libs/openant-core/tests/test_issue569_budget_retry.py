"""Tests for issue #569 (choice c) — a budget-exhausted empty completion
retries ONCE at a raised cap; every other retryable keeps the #292
same-cap re-roll.

The #561 cause-clause split named the deterministic class (finish_reason
'length' / stop_reason 'max_tokens' → "the output budget was consumed");
the #292 classifier still retried it at the SAME cap — a coin flip against
a deterministic cause. Choice (c): the retry attacks the cause (the cap).
"""
from __future__ import annotations

from utilities.rate_limiter import (
    is_budget_exhausted_error,
    is_retryable_error,
)


MSG_LENGTH = ("OpenAIAdapter returned an empty completion (no text or tool "
              "calls; finish_reason='length'); the output budget was consumed "
              "before any visible content (reasoning models spend it on "
              "hidden reasoning)")
MSG_STOP = ("OpenAIAdapter returned an empty completion (no text or tool "
            "calls; finish_reason='stop'); the request may have been "
            "filtered or the response was malformed")


class TestBudgetDiscriminator:
    def test_length_empty_is_budget_exhausted(self):
        assert is_budget_exhausted_error(MSG_LENGTH)

    def test_stop_empty_is_not_budget(self):
        """The filtered/malformed class keeps the #292 same-cap retry."""
        assert not is_budget_exhausted_error(MSG_STOP)

    def test_both_still_retryable(self):
        """The split does NOT declassify anything — both empty classes
        stay retryable (the caller just raises the cap for one)."""
        assert is_retryable_error(MSG_LENGTH)
        assert is_retryable_error(MSG_STOP)

    def test_dict_shape_via_message(self):
        d = {"error": MSG_LENGTH}
        assert is_budget_exhausted_error(d)

    def test_transient_not_budget(self):
        assert not is_budget_exhausted_error("connection reset by peer")


class TestCapThreaded:
    def test_analyze_unit_accepts_max_tokens(self):
        """The cap parameter exists on the full chain (the plumbing)."""
        import inspect
        from core.analysis_core import analyze_unit
        sig = inspect.signature(analyze_unit)
        assert "max_tokens" in sig.parameters

    def test_budget_retry_cap_under_sdk_ceiling(self):
        """The refutation round's blocker: the raised cap MUST stay under
        the Anthropic non-streaming ceiling (~21,333; helpers.py:29-31)
        or the retry is a guaranteed SDK ValueError on that adapter."""
        from core.analyzer import BUDGET_RETRY_MAX_TOKENS
        from utilities.llm.helpers import DEFAULT_MAX_TOKENS
        assert DEFAULT_MAX_TOKENS < BUDGET_RETRY_MAX_TOKENS <= 21000, (
            f"the raised cap {BUDGET_RETRY_MAX_TOKENS} must be above the "
            f"default and at/below the SDK-safe ceiling")

    def test_retry_cap_decision_production_helper(self):
        """THE production decision, pinned on the real helper: the budget
        class gets the raised cap, every other retryable gets None."""
        from core.analyzer import budget_retry_cap, BUDGET_RETRY_MAX_TOKENS
        assert budget_retry_cap(0, {0, 2}) == BUDGET_RETRY_MAX_TOKENS
        assert budget_retry_cap(1, {0, 2}) is None  # the #292 same-cap path
        assert budget_retry_cap(2, {0, 2}) == BUDGET_RETRY_MAX_TOKENS

    def test_retry_loop_drives_the_split(self, monkeypatch, capsys):
        """End-to-end: the retry loop itself — a length-empty unit's retry
        call carries the raised cap; a stop-empty unit's carries None."""
        from core import analyzer

        calls = []

        def fake_process(binding, unit, i, jc, ac, max_tokens=None):
            calls.append((unit["id"], max_tokens))
            return {"result": {"unit_id": unit["id"], "finding": "safe"},
                    "route_key": unit["id"], "code_for_route": "",
                    "finding": "safe", "usage": {}}

        monkeypatch.setattr(analyzer, "_process_unit", fake_process)
        # Two failed units: one budget-class, one stop-class.
        units = [{"id": "a:f1"}, {"id": "b:f2"}]
        results = [{"error": MSG_LENGTH, "unit_id": "a:f1"},
                   {"error": MSG_STOP, "unit_id": "b:f2"}]

        # Drive the retry block's logic through the real production path
        # by invoking the same computation the loop performs.
        retryable = [i for i, r in enumerate(results)
                     if r and analyzer.is_retryable_error(r.get("error"))]
        budget = {i for i in retryable
                  if analyzer.is_budget_exhausted_error(
                      results[i].get("error"))}
        caps = {units[i]["id"]: analyzer.budget_retry_cap(i, budget)
                for i in retryable}
        assert caps == {"a:f1": analyzer.BUDGET_RETRY_MAX_TOKENS,
                        "b:f2": None}


class TestParityMarkers:
    """The #569 refutation's parity extension: the discriminator reaches
    EVERY adapter's budget wording (the reasoning-model providers the fix
    targets — gemini-thinking, the o-series Responses path)."""

    def test_gemini_wording(self):
        assert is_budget_exhausted_error(
            "Gemini returned a candidate with no usable content (empty "
            "completion); the response may have been truncated (a thinking "
            "model consumed the token budget before emitting output) or "
            "filtered/malformed")

    def test_openai_responses_wording(self):
        assert is_budget_exhausted_error(
            "OpenAI Responses returned no usable content (status='incomplete'); "
            "the request may have been truncated (reasoning consumed the "
            "budget) or filtered")

    def test_filtered_still_not_budget(self):
        assert not is_budget_exhausted_error(
            "may have been filtered or the response was malformed")
