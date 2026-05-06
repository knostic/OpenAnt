"""Tests for TokenTracker."""
from utilities.llm_client import TokenTracker, MODEL_PRICING


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
        result = tracker.record_call("claude-sonnet-4-20250514", 1000, 500)

        assert result["model"] == "claude-sonnet-4-20250514"
        assert result["input_tokens"] == 1000
        assert result["output_tokens"] == 500
        # Sonnet: $3/M input, $15/M output
        expected_cost = (1000 / 1_000_000) * 3.0 + (500 / 1_000_000) * 15.0
        assert result["cost_usd"] == round(expected_cost, 6)

    def test_record_call_unknown_model_uses_default(self):
        tracker = TokenTracker()
        result = tracker.record_call("some-future-model", 100, 50)
        default_pricing = MODEL_PRICING["default"]
        expected_cost = (100 / 1_000_000) * default_pricing["input"] + (50 / 1_000_000) * default_pricing["output"]
        assert result["cost_usd"] == round(expected_cost, 6)

    def test_cumulative_tracking(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-20250514", 1000, 500)
        tracker.record_call("claude-sonnet-4-20250514", 2000, 1000)

        assert tracker.total_input_tokens == 3000
        assert tracker.total_output_tokens == 1500
        assert tracker.total_tokens == 4500
        assert len(tracker.calls) == 2

    def test_reset(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-20250514", 1000, 500)
        tracker.reset()

        assert tracker.total_input_tokens == 0
        assert tracker.total_output_tokens == 0
        assert tracker.total_cost_usd == 0.0
        assert tracker.calls == []

    def test_get_summary_includes_calls(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-20250514", 100, 50)
        summary = tracker.get_summary()

        assert summary["total_calls"] == 1
        assert "calls" in summary
        assert len(summary["calls"]) == 1

    def test_get_totals_excludes_calls(self):
        tracker = TokenTracker()
        tracker.record_call("claude-sonnet-4-20250514", 100, 50)
        totals = tracker.get_totals()

        assert totals["total_calls"] == 1
        assert "calls" not in totals

    def test_opus_pricing(self):
        tracker = TokenTracker()
        result = tracker.record_call("claude-opus-4-20250514", 1_000_000, 1_000_000)
        # Opus: $15/M input, $75/M output
        assert result["cost_usd"] == 90.0
