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
    from utilities import llm_client as lc
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


# F661-1 (the PR-MERGE review finding, 2026-09-22): OpenAI/Google input
# counts are INCLUSIVE — prompt_tokens/prompt_token_count already contain
# the cached portion. Pricing input AS-IS plus the cache line items bills
# the cached tokens twice (the executed control: 0.001460 vs the correct
# 0.000560 on the same fake usage). The cached portion must be SUBTRACTED
# from the billed input and priced only at its multiplier.
def test_openai_inclusive_cache_not_double_billed():
    t = TokenTracker()
    rec = t.record_call(
        model="gpt-x", input_tokens=10_000, output_tokens=0,
        pricing={"input": 2.0, "output": 10.0, "cache_read": 0.1},
        usage_details={"cached_tokens": 8_000})
    # correct: uncached 2k*$2 + cached 8k*$2*0.1 = $0.004 + $0.0016
    assert round(rec["cost_usd"], 9) == round((2_000*2 + 8_000*2*0.1)/1e6, 9)


def test_google_inclusive_cache_not_double_billed():
    t = TokenTracker()
    rec = t.record_call(
        model="gemini-x", input_tokens=10_000, output_tokens=0,
        pricing={"input": 2.0, "output": 10.0, "cache_read": 0.25},
        usage_details={"cached_content_token_count": 8_000})
    assert round(rec["cost_usd"], 9) == round((2_000*2 + 8_000*2*0.25)/1e6, 9)


# T1 round-2 (F-A): an UNPRICED inclusive cache must degrade to the
# full-rate upper bound (master's direction), never a $0 under-report —
# the shipped census has no openai/google cache rates, and OpenAI
# auto-caches, so this is the default OpenAI/Google path.
def test_unpriced_inclusive_cache_degrades_to_upper_bound():
    t = TokenTracker()
    rec = t.record_call(
        model="gpt-4o", input_tokens=6_000, output_tokens=500,
        pricing={"input": 2.5, "output": 10.0},   # NO cache multipliers
        usage_details={"cached_tokens": 4_096})
    # the full input at the full rate (the over-estimate, like master) —
    # NOT (6000-4096)*2.5 with the cached 4096 at $0 (the under-report)
    assert round(rec["cost_usd"], 9) == round((6_000*2.5 + 500*10.0)/1e6, 9)
    totals = t.get_totals()
    assert totals["cost_incomplete"]
    assert "gpt-4o" in totals["unpriced_cache_models"]


# the EXCLUSIVE semantics (anthropic) must not regress: input_tokens
# EXCLUDES the cache fields — the current correct math stands.
def test_anthropic_exclusive_cache_still_additive():
    t = TokenTracker()
    rec = t.record_call(
        model="claude-x", input_tokens=2_000, output_tokens=0,
        pricing={"input": 2.0, "output": 10.0, "cache_read": 0.1},
        usage_details={"cache_read_input_tokens": 8_000})
    # input 2k*$2 + cache 8k*$2*0.1 (the fields are DISJOINT from input)
    assert round(rec["cost_usd"], 9) == round((2_000*2 + 8_000*2*0.1)/1e6, 9)


# F661-2 (the PR-MERGE review finding, 2026-09-22): the step report copies
# only unpriced_models from the end snapshot — unpriced_cache_models (the
# snapshot HAS it) is dropped, so a cache-only incompleteness reports
# "at least one model unpriced" with NO model named (#216 broken for the
# cache path).
def test_step_report_carries_unpriced_cache_models(tmp_path):
    from core.step_report import step_context
    from core import step_report as _sr

    # the snapshot shape _snapshot_usage produces for a cache-unpriced run
    _snap = {"input": 100, "output": 10, "total": 110,
             "cost_incomplete": True,
             "unpriced_models": [],
             "cache_read": 5_000,
             "unpriced_cache_models": ["gpt-4o"]}
    _orig = _sr._snapshot_usage
    _sr._snapshot_usage = lambda: (0.001, _snap)
    try:
        with step_context("analyze", str(tmp_path)) as ctx:
            ctx.inputs = {}
        # the report the context wrote must carry the cache-unpriced ids
        import json as _json
        _files = list(tmp_path.glob("*.json"))
        assert _files, "no step report written"
        _rep = _json.loads(_files[0].read_text())
        _tu = _rep.get("token_usage", {})
        assert _tu.get("unpriced_cache_models") == ["gpt-4o"], (
            "the cache-unpriced model is dropped from the step report "
            "(F661-2: #216's name-the-model broken for cache-only incompleteness)")
    finally:
        _sr._snapshot_usage = _orig


# The census pin (the linkage gate's demand): EVERY cache-rated record in
# config/models.json is pinned — reverting any single model's cache rates
# must fail here (the per-model data rows are guarded, not just sonnet's).
def test_every_cache_rated_record_is_pinned():
    import json as _json
    from pathlib import Path
    _cfg = _json.loads(
        (Path(__file__).resolve().parents[3] / "config" / "models.json").read_text())
    _rated = {rec["id"]: rec for rec in _cfg["models"]
              if isinstance(rec, dict) and isinstance(rec.get("cache"), dict)}
    # the EXPECTED set (the census, 2026-09-21): the ten claude-family
    # records. Pinning the set — not iterating whatever is present — is
    # what makes a single record's reversion FAIL here (the linkage
    # demand: each data row is guarded).
    _expected = {
        "claude-fable-5", "claude-fable-5-1", "claude-haiku-4-5-20251001",
        "claude-mythos-5", "claude-mythos-5-1", "claude-opus-4-7",
        "claude-opus-4-8", "claude-opus-5", "claude-sonnet-4-6",
        "claude-sonnet-5",
    }
    assert set(_rated) == _expected, (
        f"the cache-rated census changed: {set(_rated) ^ _expected}")
    for name, rec in _rated.items():
        _c = rec["cache"]
        assert isinstance(_c["read"], (int, float)) and _c["read"] > 0, name
        assert "write" in _c, f"{name}: read without write (the anthropic shape has both)"
        assert isinstance(_c["write"], (int, float)) and _c["write"] > 0, name


# The cache-delta pin (the linkage gate's demand): the step report's
# cache_read delta + the snapshot's line items — reverting the copy loop
# or the snapshot keys must fail here.
def test_step_report_carries_cache_deltas(tmp_path):
    from core.step_report import step_context
    from core import step_report as _sr

    _start_snap = {"input": 0, "output": 0, "total": 0}
    _end_snap = {"input": 100, "output": 10, "total": 110,
                 "cache_read": 5_000, "cache_write": 2_000}
    _orig = _sr._snapshot_usage
    _calls = [0]
    def _fake():
        _calls[0] += 1
        return (0.001, _start_snap) if _calls[0] == 1 else (0.001, _end_snap)
    _sr._snapshot_usage = _fake
    try:
        with step_context("analyze", str(tmp_path)) as ctx:
            ctx.inputs = {}
        import json as _json
        _files = list(tmp_path.glob("*.json"))
        assert _files, "no step report written"
        _tu = _json.loads(_files[0].read_text()).get("token_usage", {})
        assert _tu.get("cache_read") == 5_000, (
            "the step's cache_read delta is dropped (the #626 line item)")
        assert _tu.get("cache_write") == 2_000, (
            "the step's cache_write delta is dropped")
    finally:
        _sr._snapshot_usage = _orig


# The snapshot pin (the linkage demand): the REAL _snapshot_usage carries
# the cache line items from the global tracker — a mock-based test cannot
# see this hunk (the mock replaces the very function under test).
def test_real_snapshot_carries_cache_line_items():
    # drive the GLOBAL TRACKER (get_usage rebuilds UsageInfo from its
    # totals — mutating a UsageInfo copy is invisible to the snapshot)
    from core.step_report import _snapshot_usage
    from core.tracking import reset_tracking
    from utilities.llm_client import get_global_tracker
    reset_tracking()
    t = get_global_tracker()
    _gpt = pricing_map("openai")["gpt-4o"]  # priced, NO cache multipliers
    t.record_call(
        model="gpt-4o", input_tokens=100, output_tokens=10,
        pricing=_gpt,  # the cache-unpriced path: cost_incomplete + the ids
        usage_details={"cached_tokens": 5_000, "cache_write_tokens": 2_000})
    _cost, snap = _snapshot_usage()
    assert snap.get("cache_read") == 5_000, "the snapshot drops cache_read"
    assert snap.get("cache_write") == 2_000, "the snapshot drops cache_write"
    assert snap.get("unpriced_cache_models") == ["gpt-4o"], (
        "the snapshot drops the cache-unpriced ids (F661-2's upstream)")
    assert snap.get("cost_incomplete") is True
    reset_tracking()
