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


# ---------------------------------------------------------------------------
# FIX-1 (defect (e), the merge-blocker): the UsageInfo ENVELOPE must be
# present-only for the cache line items, like every other #626 surface.
#
# The PR's original decision was always-present (the #624 asdict precedent).
# Master has since grown tests/patch/test_run_traced_wrapper.py:304, which
# asserts EXACT dict equality on a no-cache run's usage envelope — so the
# always-present choice is a hard CI failure, and the "byte-identical
# serialization for no-cache runs" promise was false at this one surface.
# The dataclass FIELDS stay (typed consumers keep attribute access and the
# 0/[] defaults); only to_dict() becomes present-only.
def test_usage_info_envelope_byte_identical_without_cache():
    from core.schemas import UsageInfo
    d = UsageInfo(total_calls=1, total_turns=1, total_input_tokens=1_000,
                  total_output_tokens=500, total_tokens=1_500,
                  total_cost_usd=0.0525).to_dict()
    assert set(d) == {
        "total_calls", "total_turns", "total_input_tokens",
        "total_output_tokens", "total_tokens", "total_cost_usd",
        "cost_incomplete", "unpriced_models",
    }, (
        "a no-cache run's UsageInfo envelope must carry exactly the eight "
        "pre-#626 keys — master's test_run_traced_wrapper.py:304 asserts "
        "exact dict equality on this envelope")


def test_usage_info_envelope_carries_cache_when_present():
    from core.schemas import UsageInfo
    d = UsageInfo(total_calls=1, total_input_tokens=1_000,
                  total_cache_read_tokens=4_096,
                  total_cache_write_tokens=1_000,
                  unpriced_cache_models=["gpt-4o"]).to_dict()
    assert d["total_cache_read_tokens"] == 4_096
    assert d["total_cache_write_tokens"] == 1_000
    assert d["unpriced_cache_models"] == ["gpt-4o"]


def test_usage_info_envelope_present_only_per_field():
    """present-only is PER FIELD, not all-or-nothing: a read-only cache run
    must carry cache_read and omit the write key (and vice versa), so the
    envelope never asserts a zero it did not measure."""
    from core.schemas import UsageInfo
    read_only = UsageInfo(total_cache_read_tokens=4_096).to_dict()
    assert read_only["total_cache_read_tokens"] == 4_096
    assert "total_cache_write_tokens" not in read_only
    assert "unpriced_cache_models" not in read_only
    ids_only = UsageInfo(unpriced_cache_models=["gpt-4o"]).to_dict()
    assert ids_only["unpriced_cache_models"] == ["gpt-4o"]
    assert "total_cache_read_tokens" not in ids_only


# ---------------------------------------------------------------------------
# FIX-4A (defects (b) + (b-extra)): the per-unit RELABEL, fixed AT SOURCE.
#
# ``record_call`` added BOTH kinds of incompleteness to the SAME thread-local
# set ``tl.unit_unpriced`` — the #216 pricing-absent kind (llm_client.py:269)
# and the #626 cache-rates-absent kind (:323). Everything reading that set
# therefore relabels a PRICED model as having no pricing record at all:
#   - ``get_unit_usage()`` -> the per-unit checkpoint record -> the resume;
#   - SIX private reads of the thread-local in
#     utilities/agentic_enhancer/agent.py (:350, :447, :524, :556, :600, :635)
#     which bypass get_unit_usage() entirely and persist agent_metadata.
# Splitting the set at the source fixes all seven sources in one file, and
# leaves the 169 lines of existing single-list plumbing CORRECT (a
# cache-unpriced model is simply absent from it) instead of wrong.
_GPT4O_NO_CACHE_RATES = {"input": 2.5, "output": 10.0}


def test_unit_usage_separates_cache_unpriced_from_unpriced():
    t = TokenTracker()
    t.start_unit_tracking()
    t.record_call(model="gpt-4o", input_tokens=6_000, output_tokens=500,
                  pricing=_GPT4O_NO_CACHE_RATES,
                  usage_details={"cached_tokens": 4_096})
    u = t.get_unit_usage()
    # present-only (the pre-existing get_unit_usage discipline — the key was
    # never emitted empty): the pricing-unpriced kind is ABSENT here, and
    # must certainly not name gpt-4o.
    assert "gpt-4o" not in u.get("unpriced_models", []), (
        "gpt-4o IS priced (input 2.5 / output 10.0) — only its CACHE rates "
        "are absent; naming it under unpriced_models is a false statement "
        "about a priced model, persisted into the checkpoint")
    assert "unpriced_models" not in u
    assert u["unpriced_cache_models"] == ["gpt-4o"]
    assert u["cost_incomplete"] is True, (
        "the figure is still an upper bound — incompleteness must survive "
        "the split")


def test_unit_usage_still_names_a_truly_unpriced_model():
    """The #216/#598 guard: a model with NO pricing record at all must stay
    in unpriced_models. The split must not empty that list."""
    t = TokenTracker()
    t.start_unit_tracking()
    t.record_call(model="mystery-model", input_tokens=1_000,
                  output_tokens=100, pricing=None)
    u = t.get_unit_usage()
    assert u["unpriced_models"] == ["mystery-model"]
    assert u["cost_incomplete"] is True
    assert "unpriced_cache_models" not in u


def test_enhance_metadata_does_not_call_a_priced_model_unpriced():
    """Pins the SIX agentic_enhancer/agent.py private thread-local reads
    (:350, :447, :524, :556, :600, :635) WITHOUT editing that file — it
    evaluates the literal expression those six sites use. After the split
    they read the pricing-unpriced set only, so agent_metadata stops
    asserting 'gpt-4o has no pricing record'."""
    t = TokenTracker()
    t.start_unit_tracking()
    t.record_call(model="gpt-4o", input_tokens=6_000, output_tokens=500,
                  pricing=_GPT4O_NO_CACHE_RATES,
                  usage_details={"cached_tokens": 4_096})
    # the verbatim agent.py:447-449 expression
    agent_value = sorted(getattr(
        getattr(t, "_thread_local", None), "unit_unpriced", set())) or None
    assert agent_value is None, (
        "the six agent.py private reads would persist "
        f"unpriced_models={agent_value} for a PRICED model")
    # and the truly-unpriced kind must still reach those six sites
    t2 = TokenTracker()
    t2.start_unit_tracking()
    t2.record_call(model="mystery-model", input_tokens=10, output_tokens=1,
                   pricing=None)
    assert sorted(getattr(getattr(t2, "_thread_local", None),
                          "unit_unpriced", set())) == ["mystery-model"]


def test_unit_usage_byte_identical_without_cache():
    """No incompleteness of either kind ⇒ exactly the 3 pre-#216 keys."""
    t = TokenTracker()
    t.start_unit_tracking()
    t.record_call(model="claude-sonnet-5", input_tokens=10, output_tokens=10,
                  pricing=_SONNET_PRICING)
    u = t.get_unit_usage()
    assert set(u) == {"input_tokens", "output_tokens", "cost_usd"}


def test_unit_usage_without_start_unit_tracking_is_the_bare_shape():
    """A thread that never started unit tracking must still get the 3-key
    dict, not an AttributeError — the getattr defaults are load-bearing
    (agent.py:244-245 calls start_unit_tracking defensively via getattr)."""
    t = TokenTracker()
    assert set(t.get_unit_usage()) == {
        "input_tokens", "output_tokens", "cost_usd"}


def test_resume_does_not_relabel_cache_unpriced_as_unpriced():
    """The full round-trip the design executed: run 1 records a priced-cache
    Anthropic call plus a cache-unpriced OpenAI call, the unit's usage is
    checkpointed, run 2 resumes it via add_prior_usage. The resumed artifact
    must NOT claim the priced model has no pricing record."""
    t1 = TokenTracker()
    t1.start_unit_tracking()
    t1.record_call(model="claude-sonnet-5", input_tokens=2_000,
                   output_tokens=100, pricing=_SONNET_PRICING,
                   usage_details={"cache_read_input_tokens": 8_000,
                                  "cache_creation_input_tokens": 1_000})
    t1.record_call(model="gpt-4o", input_tokens=6_000, output_tokens=500,
                  pricing=_GPT4O_NO_CACHE_RATES,
                  usage_details={"cached_tokens": 4_096})
    unit = t1.get_unit_usage()
    # the checkpoint record shape llm_reachability._share()/analyzer write
    ckpt = {k: unit[k] for k in unit}
    t2 = TokenTracker()
    t2.add_prior_usage(
        input_tokens=ckpt["input_tokens"],
        output_tokens=ckpt["output_tokens"],
        cost_usd=ckpt["cost_usd"],
        unpriced_models=ckpt.get("unpriced_models") or None)
    resumed = t2.get_totals()
    assert "gpt-4o" not in resumed["unpriced_models"], (
        "the resume persists a FALSE statement about a priced model")
    # the dollars were never the loss — pin that they still survive
    assert round(resumed["total_cost_usd"], 6) == round(ckpt["cost_usd"], 6)


def test_resume_of_resume_keeps_cost_incomplete_sticky():
    """Two successive injections: a truly-unpriced model's marker must stay
    sticky across both (the analyzer.py:825-831 run-cumulative claim)."""
    t = TokenTracker()
    t.add_prior_usage(input_tokens=10, output_tokens=1, cost_usd=0.0,
                      unpriced_models=["mystery-model"])
    t.add_prior_usage(input_tokens=10, output_tokens=1, cost_usd=0.001,
                      unpriced_models=None)
    totals = t.get_totals()
    assert totals["cost_incomplete"] is True
    assert totals["unpriced_models"] == ["mystery-model"]


def test_legacy_checkpoint_without_cache_keys_resumes_clean():
    """A pre-#626 checkpoint dict carries no cache keys at all. Every
    restore site reads it with .get(...) or [] — assert it, do not assume."""
    legacy = {"input_tokens": 100, "output_tokens": 10, "cost_usd": 0.002}
    t = TokenTracker()
    t.add_prior_usage(
        input_tokens=legacy["input_tokens"],
        output_tokens=legacy["output_tokens"],
        cost_usd=legacy["cost_usd"],
        unpriced_models=legacy.get("unpriced_models") or None)
    totals = t.get_totals()
    assert totals["cost_incomplete"] is False
    for k in ("total_cache_read_tokens", "total_cache_write_tokens",
              "unpriced_cache_models"):
        assert k not in totals


def test_forward_compat_cache_ids_are_not_folded_into_unpriced_models():
    """FIX-4B's seam: a checkpoint carrying unpriced_cache_models (written
    by a future version) must be ignored cleanly by this code — and must
    specifically NOT be folded into unpriced_models, which would regress
    straight back into the relabel this fix removes."""
    future = {"input_tokens": 100, "output_tokens": 10, "cost_usd": 0.002,
              "cost_incomplete": True, "unpriced_models": [],
              "unpriced_cache_models": ["gpt-4o"],
              "cache_read_tokens": 4_096}
    t = TokenTracker()
    t.add_prior_usage(
        input_tokens=future["input_tokens"],
        output_tokens=future["output_tokens"],
        cost_usd=future["cost_usd"],
        unpriced_models=future.get("unpriced_models") or None)
    assert "gpt-4o" not in t.get_totals()["unpriced_models"]


# FIX-4A, the regression the split would otherwise INTRODUCE.
#
# core/llm_reachability.py's _share() forwarded cost_incomplete ONLY when
# batch_usage["unpriced_models"] was non-empty. Before the split, a
# cache-unpriced unit landed in that list (the relabel), so the checkpoint
# record DID carry cost_incomplete=True — for the wrong reason, but the flag
# was there. After the split that list is empty for the cache kind, so the
# flag would silently disappear: the fix would trade a false label for a LOST
# signal. _share() must forward the cache kind too (present-only), so the
# per-unit record stays truthful AND stays loud.
#
# core/analyzer.py:224,253 store get_unit_usage() verbatim and so need no
# change — enumerated, not assumed.
def test_llr_checkpoint_record_keeps_cache_incompleteness_loud(tmp_path):
    import json as _json
    import os as _os

    from core.llm_reachability import analyze_reachability
    from utilities.llm import CompletionResult, PhaseBinding, TextBlock

    class _Adapter:
        name = "openai"
        supports_tools = True

        def complete(self, *, model, system, messages, max_tokens, tools=None):
            return CompletionResult(
                content=[TextBlock(_json.dumps(
                    {"signals": [{"unit_id": "a:f1", "kind": "entry_point",
                                  "confidence": "high", "reason": "argv"}]}))],
                input_tokens=10, output_tokens=10,
                stop_reason="end_turn")

        def validate(self, model):
            pass

    class _Tracker:
        """Emits exactly the real tracker's post-split cache-only unit shape."""

        def record_call(self, **kw):
            return {}

        def start_unit_tracking(self):
            pass

        def get_unit_usage(self):
            return {"input_tokens": 6_000, "output_tokens": 500,
                    "cost_usd": 0.02, "cost_incomplete": True,
                    "unpriced_cache_models": ["gpt-4o"]}

        def add_prior_usage(self, input_tokens, output_tokens, cost_usd,
                            unpriced_models=None, **kw):
            pass

    cp = str(tmp_path / "llm_reach_checkpoints")
    analyze_reachability(
        {"units": [{"id": "a:f1", "unit_type": "function",
                    "code": {"primary_code": "pass"}}]},
        binding=PhaseBinding(phase="llm_reach", adapter=_Adapter(),
                             model="gpt-4o", provider_name="openai"),
        checkpoint_path=cp, tracker=_Tracker())
    with open(_os.path.join(cp, "a_f1.json")) as fh:
        rec = _json.load(fh)
    assert rec["usage"].get("cost_incomplete") is True, (
        "the split must not LOSE the incompleteness flag the relabel used "
        "to carry — the record would read complete for a cache-unpriced unit")
    assert rec["usage"].get("unpriced_cache_models") == ["gpt-4o"], (
        "and it must say WHICH kind, so the record is not merely loud but true")
    assert "gpt-4o" not in (rec["usage"].get("unpriced_models") or []), (
        "while never relabelling the priced model as having no pricing record")


# ---------------------------------------------------------------------------
# FIX-3 (defect (c)): the report path ran a SECOND, parallel cost formula.
#
# There were two cost formulas in the tree — utilities/llm_client.py's
# record_call (cache-aware, F661-1 inclusive/exclusive semantics, the
# one-sided-multiplier rule) and report/generator.py's _extract_usage
# (input+output only). The report phase feeds the SAME provider usage_details
# to both (generator.py:813-819, :1032-1038), so the cache numbers arrive and
# were simply not used. Two surfaces, two answers, one scan:
#
#   anthropic priced cache  -> tracker 0.013650 vs generator 0.007500
#                              (the generator UNDER-bills by 45%)
#   openai/google unpriced  -> costs agree BY COINCIDENCE, but
#                              cost_incomplete flips True -> False
#                              (the #598 masquerade shape: a plausible
#                              figure labelled complete)
#
# The fix DELETES the second formula rather than patching it: one pure
# module-level price_usage() in llm_client.py, called by both.
def test_price_usage_is_importable_and_side_effect_free():
    """The extraction's own contract: a pure function, no tracker state."""
    from utilities.llm_client import normalize_cache_usage, price_usage
    counts = normalize_cache_usage({"cache_read_input_tokens": 8_000,
                                    "cache_creation_input_tokens": 1_000})
    assert counts == (8_000, 1_000, 0, 0)
    priced = price_usage(2_000, 100, _SONNET_PRICING, cache_counts=counts)
    assert priced.unpriced_cache is False
    assert priced.cache_read_tokens == 8_000
    assert priced.cache_write_tokens == 1_000
    # calling it twice must give the same answer (no accumulation)
    assert price_usage(2_000, 100, _SONNET_PRICING,
                       cache_counts=counts) == priced


def test_report_path_prices_cache_like_the_tracker():
    """T5 — the anthropic EXCLUSIVE priced-cache case: the generator billed
    input+output only and never billed the (disjoint) cache line items."""
    from report.generator import _extract_usage
    details = {"cache_read_input_tokens": 8_000,
               "cache_creation_input_tokens": 1_000}
    t = TokenTracker()
    rec = t.record_call(model="claude-sonnet-5", input_tokens=2_000,
                        output_tokens=100, pricing=_SONNET_PRICING,
                        usage_details=details)
    usage = _extract_usage(2_000, 100, "claude-sonnet-5",
                           usage_details=details, pricing=_SONNET_PRICING)
    assert usage["cost_usd"] == rec["cost_usd"], (
        f"the report path bills {usage['cost_usd']} where the tracker bills "
        f"{rec['cost_usd']} on identical inputs — one scan, two answers")


def test_report_path_marks_cache_unpriced_incomplete():
    """T6 — the openai INCLUSIVE unpriced-cache case: the dollars agreed by
    coincidence (both price the full input), but the generator claimed the
    figure was COMPLETE. That is the #598 masquerade."""
    from report.generator import _extract_usage
    details = {"cached_tokens": 4_096}
    usage = _extract_usage(6_000, 500, "gpt-4o", usage_details=details,
                           pricing=_GPT4O_NO_CACHE_RATES)
    assert usage["cost_incomplete"] is True, (
        "the cached traffic fell back to the full input rate — the figure is "
        "an upper bound and must not read as complete")
    assert usage["unpriced_cache_models"] == ["gpt-4o"]
    assert "gpt-4o" not in (usage.get("unpriced_models") or []), (
        "gpt-4o IS priced — the two kinds must not merge here either")


def test_report_path_does_not_double_bill_inclusive_cache():
    """The F661-1 rule must hold on the report path too: a PRICED inclusive
    cache must not bill the cached portion at both the full and the cache
    rate. (Guards against a fix that merely adds cache cost on top.)"""
    from report.generator import _extract_usage
    details = {"cached_tokens": 8_000}
    pricing = {"input": 2.0, "output": 10.0, "cache_read": 0.1}
    t = TokenTracker()
    rec = t.record_call(model="gpt-x", input_tokens=10_000, output_tokens=0,
                        pricing=pricing, usage_details=details)
    usage = _extract_usage(10_000, 0, "gpt-x", usage_details=details,
                           pricing=pricing)
    assert usage["cost_usd"] == rec["cost_usd"]
    assert usage["cost_usd"] == round((2_000 * 2 + 8_000 * 2 * 0.1) / 1e6, 6)


def test_report_path_byte_identical_without_cache():
    """No cache usage ⇒ the report usage dict keeps exactly its pre-#626
    keys (the present-only discipline, on this surface too)."""
    from report.generator import _extract_usage
    usage = _extract_usage(1_000, 100, "claude-sonnet-5",
                           pricing=_SONNET_PRICING)
    assert set(usage) == {"input_tokens", "output_tokens", "total_tokens",
                          "cost_usd"}


def test_report_path_unpriced_model_still_loud():
    """The #216/#598 guard on the report path: pricing=None keeps costing
    $0 with cost_incomplete + the id. FIX-3 must not disturb it."""
    from report.generator import _extract_usage
    usage = _extract_usage(1_000, 100, "mystery-model", pricing=None)
    assert usage["cost_usd"] == 0.0
    assert usage["cost_incomplete"] is True
    assert usage["unpriced_models"] == ["mystery-model"]


def test_merge_usage_aggregates_the_cache_line_items():
    """_merge_usage dropped every cache key and unioned only
    unpriced_models — the per-completion cache numbers died at the merge."""
    from report.generator import _merge_usage
    merged = _merge_usage([
        {"input_tokens": 100, "output_tokens": 10, "total_tokens": 110,
         "cost_usd": 0.001, "cache_read_tokens": 4_096,
         "cost_incomplete": True, "unpriced_cache_models": ["gpt-4o"]},
        {"input_tokens": 200, "output_tokens": 20, "total_tokens": 220,
         "cost_usd": 0.002, "cache_read_tokens": 1_000,
         "cache_write_tokens": 500, "unpriced_cache_models": ["gemini-2.5-pro"]},
    ])
    assert merged["cache_read_tokens"] == 5_096
    assert merged["cache_write_tokens"] == 500
    assert merged["unpriced_cache_models"] == ["gemini-2.5-pro", "gpt-4o"]
    assert merged["cost_incomplete"] is True


def test_merge_usage_byte_identical_without_cache():
    from report.generator import _merge_usage
    merged = _merge_usage([
        {"input_tokens": 100, "output_tokens": 10, "total_tokens": 110,
         "cost_usd": 0.001}])
    for k in ("cache_read_tokens", "cache_write_tokens",
              "unpriced_cache_models"):
        assert k not in merged


def test_usage_to_info_carries_cache_line_items():
    """T7 — divergence D4: _usage_to_info never populated the three cache
    fields, so ReportResult.usage always read 0/0/[]."""
    from core.reporter import _usage_to_info
    info = _usage_to_info({
        "input_tokens": 6_000, "output_tokens": 500, "total_tokens": 6_500,
        "cost_usd": 0.02, "completions": 1, "cost_incomplete": True,
        "cache_read_tokens": 4_096, "cache_write_tokens": 1_000,
        "unpriced_cache_models": ["gpt-4o"]})
    assert info.total_cache_read_tokens == 4_096
    assert info.total_cache_write_tokens == 1_000
    assert info.unpriced_cache_models == ["gpt-4o"]
    assert info.cost_incomplete is True
    # and the envelope stays present-only (FIX-1 interop)
    assert info.to_dict()["unpriced_cache_models"] == ["gpt-4o"]


def test_usage_to_info_without_cache_is_the_pre_626_envelope():
    from core.reporter import _usage_to_info
    info = _usage_to_info({"input_tokens": 100, "output_tokens": 10,
                           "total_tokens": 110, "cost_usd": 0.001})
    d = info.to_dict()
    for k in ("total_cache_read_tokens", "total_cache_write_tokens",
              "unpriced_cache_models"):
        assert k not in d


def test_tracker_and_report_result_agree_on_cached_traffic():
    """T8 — THE assertion that proves FIX-3 and nothing else does.

    core/reporter.py builds ReportResult.usage from the GENERATOR's figure
    while _record_usage_in_tracker hands the same usage_details to the
    TRACKER. Both surfaces ship in one scan (the tracker's totals reach
    scan.report.json; ReportResult.usage reaches the CLI report), so they
    must agree to the cent on the same traffic."""
    from core.reporter import _usage_to_info
    from report.generator import _extract_usage, _merge_usage
    details = {"cache_read_input_tokens": 8_000,
               "cache_creation_input_tokens": 1_000}
    # the generator path: per-completion extract -> merge -> UsageInfo
    merged = _merge_usage([_extract_usage(
        2_000, 100, "claude-sonnet-5", usage_details=details,
        pricing=_SONNET_PRICING)])
    info = _usage_to_info(merged)
    # the tracker path: _record_usage_in_tracker's record_call, same inputs
    t = TokenTracker()
    t.record_call(model="claude-sonnet-5",
                  input_tokens=merged["input_tokens"],
                  output_tokens=merged["output_tokens"],
                  pricing=_SONNET_PRICING,
                  usage_details=merged.get("usage_details"),
                  turns=merged.get("completions", 1))
    totals = t.get_totals()
    assert round(totals["total_cost_usd"], 6) == round(info.total_cost_usd, 6), (
        f"tracker ${totals['total_cost_usd']:.6f} vs ReportResult "
        f"${info.total_cost_usd:.6f} — one scan must not ship two costs")
    assert totals.get("total_cache_read_tokens") == info.total_cache_read_tokens
    assert totals.get("total_cache_write_tokens") == info.total_cache_write_tokens


def test_price_usage_is_the_only_formula():
    """T9 — the source guard (the test_issue598_pricing_masquerade.py style):
    report/generator.py must carry NO per-million cost arithmetic of its own.
    A second formula is how divergence (c) happened; a future edit that
    re-adds one must fail here, not in a billing reconciliation."""
    import pathlib
    src = (pathlib.Path(__file__).parent.parent
           / "report" / "generator.py").read_text()
    code = "\n".join(
        ln for ln in src.splitlines()
        if not ln.lstrip().startswith("#"))
    assert "1_000_000" not in code and "1000000" not in code, (
        "report/generator.py must call utilities.llm_client.price_usage, "
        "never re-derive the per-million rate arithmetic")


def test_summary_path_tracker_and_report_result_agree():
    """The SECOND _usage_to_info caller (core/reporter.py:1105, the summary
    format) bypasses _merge_usage entirely — _extract_usage feeds it
    directly. That is a distinct surface from the disclosure path
    (:1243, merged) and needs its own agreement proof."""
    from core.reporter import _usage_to_info
    from report.generator import _extract_usage
    details = {"cached_tokens": 4_096}
    usage = _extract_usage(6_000, 500, "gpt-4o", usage_details=details,
                           pricing=_GPT4O_NO_CACHE_RATES)
    info = _usage_to_info(usage)
    t = TokenTracker()
    t.record_call(model="gpt-4o", input_tokens=usage["input_tokens"],
                  output_tokens=usage["output_tokens"],
                  pricing=_GPT4O_NO_CACHE_RATES,
                  usage_details=usage.get("usage_details"),
                  turns=usage.get("completions", 1))
    totals = t.get_totals()
    assert round(totals["total_cost_usd"], 6) == round(info.total_cost_usd, 6)
    assert totals["cost_incomplete"] == info.cost_incomplete is True
    assert (totals.get("unpriced_cache_models")
            == info.unpriced_cache_models == ["gpt-4o"])
    assert (totals.get("total_cache_read_tokens")
            == info.total_cache_read_tokens == 4_096)


# ---------------------------------------------------------------------------
# HUNT ROUND 1 — the fix stage (F1/F2/F3/F4/F5/L1)
#
# F1: the shipped label called an unpriced-cache figure an UPPER bound in
#     every surface. That is true ONLY for the INCLUSIVE field shapes
#     (openai ``cached_tokens`` / google ``cached_content_token_count``,
#     which sit INSIDE the provider's input count, so an absent multiplier
#     bills them at the FULL input rate = an over-estimate). For the
#     EXCLUSIVE shapes (anthropic/bedrock ``cache_read_input_tokens`` /
#     ``cache_creation_input_tokens``, DISJOINT from input_tokens) an absent
#     multiplier contributes $0 — the figure is a LOWER bound. The shipped
#     census makes that the common case: 11/11 bedrock records are priced
#     with no cache block, and the bedrock adapter DOES emit the exclusive
#     fields (it imports anthropic.py's _response_to_unified).
# F3: the scan-level aggregate dropped the cache kind's ids and the cache
#     token deltas — "incomplete with no model named", the exact shape
#     F661-2 fixed one hop upstream.
# F4: the per-unit checkpoint carries the cache marker but every restore
#     site read ``unpriced_models`` only, so a resumed run read COMPLETE.
# F5: the #605 start-failed sentinel branch kept the #216 ids and dropped
#     the cache ids.
# ---------------------------------------------------------------------------

_BEDROCK_SONNET = pricing_map("bedrock")["us.anthropic.claude-sonnet-4-6"]
_GPT4O = pricing_map("openai")["gpt-4o"]


def test_exclusive_unpriced_cache_underreports_and_inclusive_overreports():
    """F1's executable oracle: the two shapes err in OPPOSITE directions, so
    no single-direction label can be true of both.

    EXCLUSIVE (bedrock, priced, no cache block — 11/11 of the shipped
    bedrock census): the cached tokens are disjoint from input_tokens and
    contribute $0 ⇒ the reported figure is BELOW the real bill (a LOWER
    bound). INCLUSIVE (gpt-4o, priced, no cache block): the cached tokens
    are already inside input_tokens and bill at the full input rate ⇒ the
    reported figure is ABOVE the real bill (an UPPER bound).
    """
    from utilities.llm_client import normalize_cache_usage, price_usage

    # --- exclusive: anthropic/bedrock ---
    excl = price_usage(10_000, 1_000, _BEDROCK_SONNET,
                       cache_counts=normalize_cache_usage(
                           {"cache_read_input_tokens": 90_000}))
    real_excl = ((10_000 / 1e6) * _BEDROCK_SONNET["input"]
                 + (1_000 / 1e6) * _BEDROCK_SONNET["output"]
                 + (90_000 / 1e6) * _BEDROCK_SONNET["input"] * 0.1)
    assert excl.unpriced_cache is True
    assert excl.cost_usd < real_excl, (
        "the exclusive shape's unpriced cache tokens contribute $0 — the "
        "figure CANNOT be an upper bound")
    assert round(excl.cost_usd / real_excl, 3) == 0.625

    # --- inclusive: openai ---
    incl = price_usage(10_000, 1_000, _GPT4O,
                       cache_counts=normalize_cache_usage(
                           {"cached_tokens": 8_000}))
    # the real bill if gpt-4o's documented 0.5x read multiplier were
    # configured: the 8 000 cached tokens at half the input rate.
    real_incl = ((2_000 / 1e6) * _GPT4O["input"]
                 + (1_000 / 1e6) * _GPT4O["output"]
                 + (8_000 / 1e6) * _GPT4O["input"] * 0.5)
    assert incl.unpriced_cache is True
    assert incl.cost_usd > real_incl, (
        "the inclusive shape's unpriced cache tokens bill at the full input "
        "rate — that direction IS an upper bound")


def test_cache_kind_direction_is_documented_per_shape():
    """F1: the ``unpriced_cache`` contract must state the direction PER
    SHAPE. A blanket "the figure is an UPPER bound" is false for the
    exclusive shapes (see the oracle above) and that sentence shipped in
    PricedUsage's field doc, in start_unit_tracking and in get_unit_usage.
    """
    import inspect

    from utilities import llm_client

    src = inspect.getsource(llm_client)
    field_doc = src.split("unpriced_cache: bool")[0].rsplit("#: a cache side", 1)[-1]
    low = field_doc.lower()
    assert "exclusive" in low and "inclusive" in low, (
        "PricedUsage.unpriced_cache's doc must name the two field shapes — "
        "the direction depends on them:\n" + field_doc)
    assert "lower" in low, (
        "the exclusive (anthropic/bedrock) direction — a LOWER bound — is "
        "missing from the field doc:\n" + field_doc)

    for fn in (llm_client.TokenTracker.start_unit_tracking,
               llm_client.TokenTracker.get_unit_usage):
        body = inspect.getsource(fn).lower()
        if "bound" not in body:
            continue
        assert "exclusive" in body or "inclusive" in body, (
            f"{fn.__qualname__} states a bound direction for the cache kind "
            f"without naming the field shape that makes it true")


# --- F3: the scan-level aggregate ------------------------------------------

def _scan_agg(tmp_path, step_reports):
    import json

    from core.scanner import _write_scan_report
    from core.schemas import AnalysisMetrics, ScanResult

    metrics = AnalysisMetrics(total=0, vulnerable=0, bypassable=0,
                              inconclusive=0, protected=0, safe=0, errors=0)
    result = ScanResult(output_dir=str(tmp_path), units_count=0,
                        language="python", metrics=metrics)
    path = _write_scan_report(str(tmp_path), result, step_reports,
                              repo_path=str(tmp_path / "repo"))
    return json.loads(Path(path).read_text())["token_usage"]


def test_scan_report_aggregate_names_the_cache_unpriced_models(tmp_path):
    """F3: a cache-only-incomplete scan must NOT ship
    {cost_incomplete: true, unpriced_models: []} — an un-attributable
    incomplete is the shape F661-2 deleted at the step hop."""
    tu = _scan_agg(tmp_path, [
        {"step": "verify", "cost_usd": 0.0495, "duration_seconds": 1.0,
         "token_usage": {
             "input_tokens": 10_000, "output_tokens": 1_000,
             "total_tokens": 11_000, "cache_read": 90_000,
             "cost_incomplete": True, "unpriced_models": [],
             "unpriced_cache_models": ["us.anthropic.claude-sonnet-4-6"]}},
    ])
    assert tu["cost_incomplete"] is True
    assert tu["unpriced_cache_models"] == ["us.anthropic.claude-sonnet-4-6"]
    assert tu["unpriced_models"] == []


def test_scan_report_aggregate_carries_the_cache_token_deltas(tmp_path):
    """F3: the cache line items are real traffic — the aggregate rebuilt
    token_usage from the step reports and dropped them, so the operator's
    artifact showed 11 000 tokens for a 101 000-token step."""
    tu = _scan_agg(tmp_path, [
        {"step": "analyze", "cost_usd": 0.01, "duration_seconds": 1.0,
         "token_usage": {"input_tokens": 100, "output_tokens": 10,
                         "total_tokens": 110, "cache_read": 90_000,
                         "cache_write": 1_000}},
        {"step": "verify", "cost_usd": 0.01, "duration_seconds": 1.0,
         "token_usage": {"input_tokens": 100, "output_tokens": 10,
                         "total_tokens": 110, "cache_read": 5_000}},
    ])
    assert tu["cache_read"] == 95_000
    assert tu["cache_write"] == 1_000
    # input/output/total stay the uncached line items (the #626 split —
    # cache is NEVER folded into total_input_tokens anywhere).
    assert tu["total_tokens"] == 220


def test_scan_report_aggregate_byte_identical_without_cache(tmp_path):
    """F3's guard: a no-cache scan's aggregate must gain NO new keys."""
    tu = _scan_agg(tmp_path, [
        {"step": "parse", "cost_usd": 0.1, "duration_seconds": 1.0,
         "token_usage": {"input_tokens": 5, "output_tokens": 5,
                         "total_tokens": 10}}])
    assert set(tu) == {"input_tokens", "output_tokens", "total_tokens"}


# --- F5: the #605 start-failed sentinel branch -----------------------------

def test_step_report_sentinel_branch_keeps_the_cache_unpriced_ids(tmp_path):
    """F5: when the START snapshot failed, the delta is unavailable but the
    WHICH-MODEL disclosure is not. The branch kept ``unpriced_models`` and
    dropped ``unpriced_cache_models`` — F661-2 applied to one branch only."""
    import json

    import core.step_report as sr
    from utilities.llm_client import get_global_tracker

    tracker = get_global_tracker()
    tracker.reset()
    real = sr._snapshot_usage
    seen = {"n": 0}

    def _fake():
        seen["n"] += 1
        if seen["n"] == 1:
            return (None, None)          # the #605 start-failed sentinel
        return real()

    sr._snapshot_usage = _fake
    try:
        with sr.step_context("verify", str(tmp_path)):
            tracker.record_call(
                model="us.anthropic.claude-sonnet-4-6",
                input_tokens=10_000, output_tokens=1_000,
                pricing=_BEDROCK_SONNET,
                usage_details={"cache_read_input_tokens": 90_000})
    finally:
        sr._snapshot_usage = real
        tracker.reset()

    tu = json.loads(
        (tmp_path / "verify.report.json").read_text())["token_usage"]
    assert tu["accounting_error"] is True
    assert tu["cost_incomplete"] is True
    assert tu["unpriced_cache_models"] == ["us.anthropic.claude-sonnet-4-6"]


# --- F4: the resume / summary layer ---------------------------------------

def test_add_prior_usage_restores_the_cache_incompleteness_marker():
    """F4's core: run 1's per-unit checkpoint carries the cache marker;
    ``add_prior_usage`` had nowhere to put it, so run 2 read COMPLETE."""
    t1 = TokenTracker()
    t1.start_unit_tracking()
    t1.record_call(model="us.anthropic.claude-sonnet-4-6",
                   input_tokens=10_000, output_tokens=1_000,
                   pricing=_BEDROCK_SONNET,
                   usage_details={"cache_read_input_tokens": 90_000})
    ckpt = t1.get_unit_usage()
    assert ckpt["unpriced_cache_models"] == ["us.anthropic.claude-sonnet-4-6"]

    t2 = TokenTracker()
    t2.add_prior_usage(
        ckpt["input_tokens"], ckpt["output_tokens"], ckpt["cost_usd"],
        unpriced_models=ckpt.get("unpriced_models") or None,
        unpriced_cache_models=ckpt.get("unpriced_cache_models") or None)
    totals = t2.get_totals()
    assert totals["cost_incomplete"] is True, (
        "a resumed run after cache-unpriced spend must not read complete")
    assert totals["unpriced_cache_models"] == ["us.anthropic.claude-sonnet-4-6"]
    # and the two kinds still never merge (F661-3)
    assert totals["unpriced_models"] == []


def test_add_prior_usage_cache_kind_is_sticky_across_two_injections():
    """The #216 stickiness contract, extended to the cache kind."""
    t = TokenTracker()
    t.add_prior_usage(10, 1, 0.0, unpriced_cache_models=["bedrock/x"])
    t.add_prior_usage(10, 1, 0.001)
    totals = t.get_totals()
    assert totals["cost_incomplete"] is True
    assert totals["unpriced_cache_models"] == ["bedrock/x"]
    assert totals["unpriced_models"] == []


def test_incomplete_markers_is_the_one_two_kind_rule():
    """F4's architectural half: the reason the F661-3 split made the drop
    TOTAL is that ~20 readers each re-implemented "which keys carry
    incompleteness". One helper now owns the rule (the #598 lesson:
    a second copy of a rule is the bug class, not the bug)."""
    from utilities.llm_client import incomplete_markers, unpriced_kinds_from

    assert incomplete_markers() == {}
    assert incomplete_markers([], []) == {}
    assert incomplete_markers(["m"], None) == {
        "cost_incomplete": True, "unpriced_models": ["m"]}
    assert incomplete_markers(None, ["c"]) == {
        "cost_incomplete": True, "unpriced_cache_models": ["c"]}
    assert incomplete_markers(["m"], ["c"]) == {
        "cost_incomplete": True, "unpriced_models": ["m"],
        "unpriced_cache_models": ["c"]}
    # sorted + de-duplicated, so two restore sites merging the same id agree
    assert incomplete_markers(["b", "a", "b"], None)["unpriced_models"] == ["a", "b"]

    # the symmetric reader — the ONE place that knows which keys to read
    assert unpriced_kinds_from(None) == ([], [])
    assert unpriced_kinds_from({}) == ([], [])
    assert unpriced_kinds_from({"input_tokens": 1}) == ([], [])   # legacy
    assert unpriced_kinds_from(
        {"unpriced_models": ["m"], "unpriced_cache_models": ["c"]}
    ) == (["m"], ["c"])


def test_analyzer_seed_summary_carries_the_cache_kind():
    """F4: analyzer._seed_summary is the resume seed for the analyze phase —
    it read ``unpriced_models`` only, so the cache kind died at the seed."""
    from core import analyzer

    unit_usage = {"input_tokens": 10_000, "output_tokens": 1_000,
                  "cost_usd": 0.0495, "cost_incomplete": True,
                  "unpriced_cache_models": ["us.anthropic.claude-sonnet-4-6"]}
    seed = analyzer._seed_summary(
        {"u1": {"result": {"verdict": "ok"}, "usage": unit_usage}}, None, None)
    assert seed["unpriced_cache_models"] == {"us.anthropic.claude-sonnet-4-6"}
    assert seed["unpriced_models"] == set()


def test_agent_result_metadata_carries_the_cache_kind():
    """F4: the enhance agent's AgentResult had no cache slot, so the six
    construction sites could only persist the #216 kind — every enhanced
    dataset row for a cache-unpriced unit read complete."""
    from utilities.agentic_enhancer.agent import AgentResult

    r = AgentResult(
        include_functions=[], usage_context="", security_classification="",
        classification_reasoning="", confidence=0.0, iterations=1,
        total_tokens=11_000, input_tokens=10_000, output_tokens=1_000,
        cost_usd=0.0495,
        unpriced_cache_models=["us.anthropic.claude-sonnet-4-6"])
    meta = r.to_dict()["agent_metadata"]
    assert meta["cost_incomplete"] is True
    assert meta["unpriced_cache_models"] == ["us.anthropic.claude-sonnet-4-6"]
    assert "unpriced_models" not in meta, (
        "the two kinds must stay disjoint (F661-3)")


def test_agent_result_without_either_kind_is_byte_identical():
    """The present-only guard for the new AgentResult slot."""
    from utilities.agentic_enhancer.agent import AgentResult

    r = AgentResult(
        include_functions=[], usage_context="", security_classification="",
        classification_reasoning="", confidence=0.0, iterations=1,
        total_tokens=3, input_tokens=2, output_tokens=1, cost_usd=0.001)
    assert set(r.to_dict()["agent_metadata"]) == {
        "iterations", "total_tokens", "input_tokens", "output_tokens",
        "cost_usd"}


def test_unit_unpriced_kinds_reads_both_thread_local_sets():
    """F4: agent.py read ``unit_unpriced`` in six places with a defensive
    getattr chain. One helper now reads BOTH sets, beside the method that
    creates them, so a third kind is a one-line change."""
    from utilities.llm_client import unit_unpriced_kinds

    t = TokenTracker()
    # before start_unit_tracking: both absent, present-only ⇒ both None
    assert unit_unpriced_kinds(t) == {"unpriced_models": None,
                                      "unpriced_cache_models": None}
    # a stub tracker with no thread-local at all must not raise
    assert unit_unpriced_kinds(object()) == {"unpriced_models": None,
                                             "unpriced_cache_models": None}
    t.start_unit_tracking()
    t.record_call(model="us.anthropic.claude-sonnet-4-6", input_tokens=1,
                  output_tokens=1, pricing=_BEDROCK_SONNET,
                  usage_details={"cache_read_input_tokens": 10})
    t.record_call(model="mystery", input_tokens=1, output_tokens=1)
    assert unit_unpriced_kinds(t) == {
        "unpriced_models": ["mystery"],
        "unpriced_cache_models": ["us.anthropic.claude-sonnet-4-6"]}


def test_every_resume_restore_site_reads_both_unpriced_kinds():
    """F4's census — the finding was not one site but SEVEN, and the next
    kind must not be able to repeat it. Every module that restores prior
    usage into a tracker must read the cache kind too."""
    import inspect

    from core import analyzer, llm_reachability
    from utilities import context_enhancer, finding_verifier
    from utilities.agentic_enhancer import agent
    from utilities.dynamic_tester import models as dt_models

    import utilities.dynamic_tester as dynamic_tester

    for mod in (analyzer, finding_verifier, context_enhancer, agent,
                llm_reachability, dynamic_tester, dt_models):
        src = inspect.getsource(mod)
        assert "unpriced_cache_models" in src, (
            f"{mod.__name__} restores/persists the #216 kind but not the "
            f"#626 cache kind — the F4 drop")

    # and the restore CALLS pass it: every add_prior_usage call site must
    # name the cache parameter (the slot existing is not the fix).
    for mod in (analyzer, finding_verifier, context_enhancer,
                llm_reachability, dynamic_tester):
        src = inspect.getsource(mod)
        for idx, chunk in enumerate(src.split("add_prior_usage(")[1:]):
            head = chunk[:400]
            assert "unpriced_cache_models" in head, (
                f"{mod.__name__} add_prior_usage call #{idx + 1} does not "
                f"restore the cache kind:\n{head}")


def test_dynamic_test_result_persists_the_cache_kind():
    """F4: the DT checkpoint record is a dataclass — the cache kind needed
    its own field or the generation spend's attribution died on resume."""
    from utilities.dynamic_tester.models import DynamicTestResult

    import dataclasses
    fields = {f.name for f in dataclasses.fields(DynamicTestResult)}
    assert "unpriced_cache_models" in fields
    r = DynamicTestResult(finding_id="VULN-001", status="PASS",
                          details="")
    # present-only: a no-cache row keeps the pre-#626 record shape (unlike
    # its unconditional #598 sibling, which is the pre-existing contract)
    assert "unpriced_cache_models" not in r.to_dict()
    r.unpriced_cache_models = ["us.anthropic.claude-sonnet-4-6"]
    assert r.to_dict()["unpriced_cache_models"] == [
        "us.anthropic.claude-sonnet-4-6"]
