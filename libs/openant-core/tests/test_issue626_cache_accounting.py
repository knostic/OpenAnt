"""Regression tests for issue #626 — the provider-aware cache accounting
prerequisite (Step 0; the cache CONTROL itself ships separately, after).

#626: no phase sends ``cache_control`` today, and the tracker cannot price
cached input — the captured cache fields are stored verbatim (#211) but
never feed the cost formula, and the pricing records carry no cache rates.
Enabling caching before the accounting would silently under-report cost.

Contract pinned here:
- pricing records carry cache multipliers (read / write, as multipliers of
  the base input rate — Anthropic's pricing page: 5-minute write 1.25x,
  cache read 0.1x, and 0.025x read on the Fable 5.1 / Mythos 5.1 records);
- ``pricing_map`` emits them alongside input/output;
- ``record_call`` normalizes the cross-provider cache field shapes
  (anthropic: ``cache_read_input_tokens`` / ``cache_creation_input_tokens``;
  openai/openrouter: ``cached_tokens`` / ``cache_write_tokens``; google:
  ``cached_content_token_count``), prices them at their own rates, and keeps
  them OUT of ``total_input_tokens`` (cached and uncached stay separated);
- a per-turn ``usage_details`` list sums its turns' cache fields;
- cache usage on a record WITHOUT multipliers marks the run
  ``cost_incomplete`` and names the model (``unpriced_cache_models``) —
  never a silent $0 cache;
- the billing-reconciliation surfaces: the call record, ``get_totals`` /
  ``get_summary``, and ``UsageInfo`` carry the cache line items;
- NO cache usage ⇒ NO new keys in the totals (byte-identical shape).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.model_registry import pricing_map  # noqa: E402
from utilities.llm_client import TokenTracker  # noqa: E402


_SONNET_PRICING = pricing_map("anthropic")["claude-sonnet-5"]
_FABLE51_PRICING = pricing_map("anthropic")["claude-fable-5-1"]


def test_records_carry_cache_multipliers():
    # read 0.1x / write 1.25x family-wide; the 5.1 exception reads at 0.025x
    assert _SONNET_PRICING["cache_read"] == 0.1
    assert _SONNET_PRICING["cache_write"] == 1.25
    assert _FABLE51_PRICING["cache_read"] == 0.025
    assert _FABLE51_PRICING["cache_write"] == 1.25


def test_record_without_cache_rates_has_no_multipliers():
    # a non-Claude record (or an unpriced-cache provider) carries none —
    # its cached usage (if any) takes the incomplete path, never $0
    gpt = pricing_map("openai").get("gpt-4o")
    assert gpt is not None and "cache_read" not in gpt


def test_anthropic_shaped_cache_priced_and_separated():
    t = TokenTracker()
    rec = t.record_call(
        model="claude-sonnet-5", input_tokens=10_000, output_tokens=1_000,
        pricing=_SONNET_PRICING,
        usage_details={"cache_read_input_tokens": 100_000,
                       "cache_creation_input_tokens": 50_000})
    # cache cost = 100k * $2 * 0.1 / 1M + 50k * $2 * 1.25 / 1M = $0.02 + $0.125
    assert round(rec["cost_usd"] - (10_000*2 + 1_000*10)/1e6 - 0.145, 9) == 0
    assert rec["cache_read_tokens"] == 100_000
    assert rec["cache_write_tokens"] == 50_000
    # separation: cached tokens never land in the input total
    totals = t.get_totals()
    assert totals["total_input_tokens"] == 10_000
    assert totals["total_cache_read_tokens"] == 100_000
    assert totals["total_cache_write_tokens"] == 50_000
    assert not totals["cost_incomplete"]


def test_openai_and_google_shapes_normalize():
    t = TokenTracker()
    t.record_call(model="m", input_tokens=1, output_tokens=1,
                  pricing=_SONNET_PRICING,
                  usage_details={"cached_tokens": 10})
    t.record_call(model="m", input_tokens=1, output_tokens=1,
                  pricing=_SONNET_PRICING,
                  usage_details={"cached_content_token_count": 7})
    t.record_call(model="m", input_tokens=1, output_tokens=1,
                  pricing=_SONNET_PRICING,
                  usage_details={"cache_write_tokens": 3})
    totals = t.get_totals()
    assert totals["total_cache_read_tokens"] == 17
    assert totals["total_cache_write_tokens"] == 3


def test_per_turn_list_sums_cache():
    t = TokenTracker()
    rec = t.record_call(
        model="claude-sonnet-5", input_tokens=10, output_tokens=10,
        pricing=_SONNET_PRICING, turns=3,
        usage_details=[{"cache_read_input_tokens": 100},
                       {"cache_read_input_tokens": 200},
                       None])
    assert rec["cache_read_tokens"] == 300
    assert t.get_totals()["total_cache_read_tokens"] == 300


def test_cache_without_multipliers_marks_incomplete():
    t = TokenTracker()
    t.record_call(model="gpt-4o", input_tokens=10, output_tokens=10,
                  pricing=pricing_map("openai")["gpt-4o"],
                  usage_details={"cached_tokens": 5_000})
    totals = t.get_totals()
    assert totals["cost_incomplete"]
    assert "gpt-4o" in totals["unpriced_cache_models"]


def test_usageinfo_carries_cache_fields():
    from core.tracking import get_usage
    t = TokenTracker()
    t.record_call(model="claude-sonnet-5", input_tokens=10, output_tokens=10,
                  pricing=_SONNET_PRICING,
                  usage_details={"cache_read_input_tokens": 1_000})
    import utilities.llm_client as lc
    old = lc.get_global_tracker()
    lc._global_tracker = t
    try:
        info = get_usage()
    finally:
        lc._global_tracker = old
    assert info.total_cache_read_tokens == 1_000
    assert not info.cost_incomplete


def test_no_cache_usage_byte_identical_shape():
    t = TokenTracker()
    t.record_call(model="claude-sonnet-5", input_tokens=10, output_tokens=10,
                  pricing=_SONNET_PRICING)
    totals = t.get_totals()
    for k in ("total_cache_read_tokens", "total_cache_write_tokens",
              "unpriced_cache_models"):
        assert k not in totals
    assert "cache_read_tokens" not in t.calls[0]


def test_one_sided_multipliers_do_not_price_the_missing_side():
    """T8 probe (2026-09-21): a record with cache_read but no cache_write
    must not price 50k write tokens at $0.0 with cost_incomplete=False —
    the used-but-unpriced side marks the run incomplete and names the
    model (the promise stated in the PR's own comment)."""
    t = TokenTracker()
    t.record_call(
        model="m", input_tokens=10, output_tokens=10,
        pricing={"input": 2.0, "output": 10.0, "cache_read": 0.1},
        usage_details={"cache_read_input_tokens": 1_000,
                       "cache_creation_input_tokens": 50_000})
    totals = t.get_totals()
    assert "m" in totals["unpriced_cache_models"], (
        "the write side lacks its multiplier — the run must be marked "
        "incomplete, not priced at $0")
    assert totals["cost_incomplete"]
    assert totals["total_cache_write_tokens"] == 50_000
    summary = t.get_summary()
    assert summary.get("total_cache_read_tokens") == 1_000
    assert summary.get("unpriced_cache_models") == ["m"]
