"""Tests for TokenTracker."""
from utilities.llm_client import TokenTracker


class TestTokenTracker:
    def test_initial_state(self):
        tracker = TokenTracker()
        assert tracker.total_input_tokens == 0
        assert tracker.total_output_tokens == 0
        assert tracker.total_tokens == 0
        assert tracker.total_cost_usd == 0.0
        assert tracker.calls == []

    def test_record_call_known_model(self):
        # #598: the test previously OMITTED pricing and relied on the
        # deleted Anthropic-catalogue substitution. Every production call
        # site passes the adapter's pricing; this now tests the same
        # arithmetic the explicit path performs (the census pin in
        # test_issue598_pricing_masquerade.py guards the invariant).
        tracker = TokenTracker()
        result = tracker.record_call(
            "claude-sonnet-4-6", 1000, 500,
            pricing={"input": 3.0, "output": 15.0})

        assert result["model"] == "claude-sonnet-4-6"
        assert result["input_tokens"] == 1000
        assert result["output_tokens"] == 500
        # Sonnet: $3/M input, $15/M output
        expected_cost = (1000 / 1_000_000) * 3.0 + (500 / 1_000_000) * 15.0
        assert result["cost_usd"] == round(expected_cost, 6)

    def test_record_call_unknown_model_reports_zero_cost(self):
        # Issue #65: unknown models report $0 with a one-time warning
        # rather than silently estimating at Sonnet rates. Token counts
        # are still recorded; only the cost is zeroed.
        tracker = TokenTracker()
        result = tracker.record_call("some-future-model", 100, 50)
        assert result["cost_usd"] == 0.0
        assert result["input_tokens"] == 100
        assert result["output_tokens"] == 50

    def test_cumulative_tracking(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-6", 1000, 500,
                            pricing={"input": 3.0, "output": 15.0})
        tracker.record_call("claude-sonnet-4-6", 2000, 1000,
                            pricing={"input": 3.0, "output": 15.0})

        assert tracker.total_input_tokens == 3000
        assert tracker.total_output_tokens == 1500
        assert tracker.total_tokens == 4500
        assert len(tracker.calls) == 2

    def test_reset(self):
        # #598: passes explicit pricing so the PRE-reset cost is non-zero —
        # the reset's cost-clearing is actually asserted (with the
        # substitution deleted, an omitted-pricing call starts at $0 and
        # the assertion goes vacuous).
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-6", 1000, 500,
                            pricing={"input": 3.0, "output": 15.0})
        assert tracker.total_cost_usd > 0.0  # the precondition
        tracker.reset()

        assert tracker.total_input_tokens == 0
        assert tracker.total_output_tokens == 0
        assert tracker.total_cost_usd == 0.0
        assert tracker.calls == []

    def test_get_summary_includes_calls(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-6", 100, 50,
                            pricing={"input": 3.0, "output": 15.0})
        summary = tracker.get_summary()

        assert summary["total_calls"] == 1
        assert "calls" in summary
        assert len(summary["calls"]) == 1

    def test_get_totals_excludes_calls(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-6", 100, 50,
                            pricing={"input": 3.0, "output": 15.0})
        totals = tracker.get_totals()

        assert totals["total_calls"] == 1
        assert "calls" not in totals

    def test_opus_pricing(self):
        # #598: rewritten from the omitted-pricing form (the deleted
        # substitution supplied the rate) to the explicit adapter pricing —
        # #344: Opus 4.8's live rate — $5/M input, $25/M output.
        tracker = TokenTracker()
        result = tracker.record_call(
            "claude-opus-4-8", 1_000_000, 1_000_000,
            pricing={"input": 5.0, "output": 25.0})
        assert result["cost_usd"] == 30.0
