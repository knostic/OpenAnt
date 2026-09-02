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
        tracker = TokenTracker()
        result = tracker.record_call("claude-sonnet-4-6", 1000, 500)

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
        tracker.record_call("claude-sonnet-4-6", 1000, 500)
        tracker.record_call("claude-sonnet-4-6", 2000, 1000)

        assert tracker.total_input_tokens == 3000
        assert tracker.total_output_tokens == 1500
        assert tracker.total_tokens == 4500
        assert len(tracker.calls) == 2

    def test_reset(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-6", 1000, 500)
        tracker.reset()

        assert tracker.total_input_tokens == 0
        assert tracker.total_output_tokens == 0
        assert tracker.total_cost_usd == 0.0
        assert tracker.calls == []

    def test_get_summary_includes_calls(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-6", 100, 50)
        summary = tracker.get_summary()

        assert summary["total_calls"] == 1
        assert "calls" in summary
        assert len(summary["calls"]) == 1

    def test_get_totals_excludes_calls(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-6", 100, 50)
        totals = tracker.get_totals()

        assert totals["total_calls"] == 1
        assert "calls" not in totals

    def test_opus_pricing(self):
        tracker = TokenTracker()
        result = tracker.record_call("claude-opus-4-8", 1_000_000, 1_000_000)
        # #344: Opus 4.8's live rate — $5/M input, $25/M output (both Anthropic's
        # pricing page and the OpenRouter catalogue; the prior 15/75 was the
        # retired Opus 4.1-era shipped-table rate).
        assert result["cost_usd"] == 30.0
