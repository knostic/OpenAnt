"""#690 — the registry carries cache multipliers for only the anthropic
family: every cached OpenAI/Google/OpenRouter/Bedrock scan takes the
``cost_incomplete`` path instead of pricing the cached portion — and for
the EXCLUSIVE-field providers (bedrock, the anthropic response shape) the
cache contributes $0, an UNDER-report; for the INCLUSIVE providers
(openai/google/openrouter) the cached portion stays in the billed input at
the FULL rate, an over-estimate. Both wrong answers are executed in the
issue; the fix is the census discipline: source the per-family (and where
the vendor varies it, per-model) cache multipliers with receipts, so the
#661 accounting prices every provider's cached usage.

THE RULING (the issue's work list): (1) the multipliers sourced per the
census discipline — vendor-page receipts for the DIRECT families (OpenAI's
platform pricing page: the per-model cached-input column; Google's Vertex
pricing page: the cached-input columns), the OpenRouter models API (the
published per-model ``input_cache_read``/``input_cache_write`` token
prices — the multipliers derived as cache/base), and Bedrock (AWS's
prompt-caching docs verbatim for the 1.25x write + the model-specific
read; Anthropic's own pricing page for the Claude multipliers, the same
receipt the direct anthropic records carry — Bedrock's Claude cache
pricing mirrors the source family and the multipliers are RELATIVE, so
the x1.1 regional uplift cancels); (2) #661's exemplars re-pinned (the
unpriced-cache exemplar moves to a record that stays unrated); (3) the
UNPUBLISHED stay unrated — Google publishes NO cached-input price for the
2.0/1.5 models (no cache column on their tables) and no cache-write price
for ANY Gemini (the explicit-caching storage is per-token-hour, not
representable in the multiplier model — documented) — those records keep
the LOUD incomplete path, never a guessed rate.

Nodes (every witness drives the REAL registry + the REAL tracker):
  S1 -- the bedrock UNDER-REPORT: a us.anthropic.claude-opus-4-8 call with
        the exclusive cache shape prices at 0.1x read / 1.25x write and
        reads COMPLETE (base: $0 for the cache + cost_incomplete + the
        model named — the issue's executed probe).
  S2 -- the openai INCLUSIVE over-estimate: a gpt-4o call with cached_tokens
        prices the cached portion at 0.5x and reads COMPLETE (base: the
        full-rate over-bill + incomplete).
  S3 -- the google PUBLISHED rate: a gemini-2.5-pro call prices its cached
        reads at 0.1x and reads COMPLETE (base: incomplete).
  S4 -- the openrouter per-model listing: the anthropic/claude-opus-4.8
        route prices both sides (0.1x read / 1.25x write) and reads
        COMPLETE (base: incomplete).
  S5 -- the PER-MODEL receipt: gpt-4.1's cached input prices at 0.25x
        (NOT gpt-4o's 0.5x — the vendors vary the ratio per model; the
        registry records the per-model receipt, never a family-wide
        guess).
  S6 -- the z-ai catch: the glm routes' SHIPPED prices diverge from the
        listing's prompt prices — the records stay UNRATED WITH REASON
        (the loud path, the reason field a #690 deliverable — red at base
        via the missing reason), never a route multiplier pasted against
        a stale base.
  S7 -- the overlap-clamp guard (the fable-r1 catch): the OpenRouter->
        Google explicit-cache shape reports the same tokens as both
        cached AND written — the clamp marks the run INCOMPLETE (never a
        silent under-report; red at base via the unguarded clamp).
  C1 -- the UNPUBLISHED stay loud: gemini-2.0-flash (no cache column on
        Google's page) keeps the cost_incomplete path with the model
        named (base-green, stays green — never a guessed rate).
  C2 -- the unpriced exemplar: the ollama record with cache usage keeps
        the loud path (base-green; the #661 suite's new exemplar).
  C3 -- the anthropic byte-identical: claude-sonnet-5's multipliers and
        the priced cache call unchanged (base-green, the #661 contract).
  C4 -- the one-sided record semantics: a read-only record with WRITE
        usage still marks incomplete and prices the read side (the
        #661 T8 contract unchanged for the new read-only families).
"""

import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from core.model_registry import pricing_map  # noqa: E402
from utilities.llm_client import TokenTracker  # noqa: E402


def _bedrock_call(tracker, model, pricing, cache_read=100_000, cache_write=50_000,
                  input_tokens=10_000, output_tokens=1_000):
    return tracker.record_call(
        model=model, input_tokens=input_tokens, output_tokens=output_tokens,
        pricing=pricing,
        usage_details={"cache_read_input_tokens": cache_read,
                      "cache_creation_input_tokens": cache_write})


def test_bedrock_exclusive_cache_priced_and_complete():
    """S1: the bedrock UNDER-REPORT class — the exclusive cache shape
    contributes $0 at the unrated base (the issue's executed probe);
    at the rated head the 100k read prices at 0.1x and the 50k write at
    1.25x of the base input, and the run reads COMPLETE."""
    p = pricing_map("bedrock")["us.anthropic.claude-opus-4-8"]
    assert p["cache_read"] == 0.1 and p["cache_write"] == 1.25, (
        f"the bedrock multipliers absent or wrong: {p!r}")
    t = TokenTracker()
    _bedrock_call(t, "us.anthropic.claude-opus-4-8", p)
    totals = t.get_totals()
    assert not totals["cost_incomplete"], (
        f"the rated bedrock cache still reads incomplete: {totals!r}")
    assert "us.anthropic.claude-opus-4-8" not in totals.get(
        "unpriced_cache_models", []), totals
    # input 10k * $5.5 + output 1k * $27.5 + 100k*$5.5*0.1 + 50k*$5.5*1.25
    expected = (10_000 * 5.5 + 1_000 * 27.5
                + 100_000 * 5.5 * 0.1 + 50_000 * 5.5 * 1.25) / 1e6
    assert abs(totals["total_cost_usd"] - expected) < 1e-9, (
        f"the bedrock cache cost: expected {expected}, got {totals['total_cost_usd']}")


def test_openai_inclusive_cache_priced_and_complete():
    """S2: the openai INCLUSIVE over-estimate — the cached portion stays
    in prompt_tokens at the full rate at base (+ incomplete); at head it
    is priced at gpt-4o's 0.5x and the run reads COMPLETE."""
    p = pricing_map("openai")["gpt-4o"]
    assert p["cache_read"] == 0.5, f"gpt-4o's cached ratio: {p!r}"
    # the write is KNOWN, not absent: no premium on pre-5.6 models — the
    # inclusive write bills at exactly the base input rate (1.0x), so a
    # write-reporting run reads COMPLETE (never a false incompleteness)
    assert p["cache_write"] == 1.0, (
        f"gpt-4o's write must be the known no-premium 1.0: {p!r}")
    t = TokenTracker()
    # 6000 prompt_tokens INCLUDES 5000 cached (the inclusive shape)
    t.record_call(model="gpt-4o", input_tokens=6_000, output_tokens=500,
                 pricing=p, usage_details={"cached_tokens": 5_000})
    totals = t.get_totals()
    assert not totals["cost_incomplete"], (
        f"the rated openai cache still reads incomplete: {totals!r}")
    expected = (1_000 * 2.5 + 500 * 10.0 + 5_000 * 2.5 * 0.5) / 1e6
    assert abs(totals["total_cost_usd"] - expected) < 1e-9, (
        f"the inclusive billing: expected {expected}, got {totals['total_cost_usd']}")


def test_google_published_rate_priced_and_complete():
    """S3: Google's PUBLISHED cached-input price (the 2.5 family carries
    the cached columns on the Vertex pricing page) — gemini-2.5-pro's
    cached reads price at 0.1x and the run reads COMPLETE."""
    p = pricing_map("google")["gemini-2.5-pro"]
    assert p["cache_read"] == 0.1, f"the gemini cached ratio: {p!r}"
    assert "cache_write" not in p, "google publishes no cache-write price"
    t = TokenTracker()
    t.record_call(model="gemini-2.5-pro", input_tokens=6_000, output_tokens=500,
                 pricing=p,
                 usage_details={"cached_content_token_count": 5_000})
    totals = t.get_totals()
    assert not totals["cost_incomplete"], totals
    expected = (1_000 * 1.25 + 500 * 10.0 + 5_000 * 1.25 * 0.1) / 1e6
    assert abs(totals["total_cost_usd"] - expected) < 1e-9, totals["total_cost_usd"]


def test_openrouter_route_priced_and_complete():
    """S4: the OpenRouter listing — the anthropic/claude-opus-4.8 route's
    published per-token cache prices (0.1x read / 1.25x write of the
    route's prompt price) price both sides and the run reads COMPLETE."""
    p = pricing_map("openrouter")["anthropic/claude-opus-4.8"]
    assert p["cache_read"] == 0.1 and p["cache_write"] == 1.25, p
    t = TokenTracker()
    # the openrouter shape: cached_tokens + cache_write_tokens, both INSIDE
    # prompt_tokens
    t.record_call(model="anthropic/claude-opus-4.8", input_tokens=20_000,
                 output_tokens=1_000, pricing=p,
                 usage_details={"cached_tokens": 10_000,
                                "cache_write_tokens": 5_000})
    totals = t.get_totals()
    assert not totals["cost_incomplete"], totals
    expected = (5_000 * 5.0 + 1_000 * 25.0
                + 10_000 * 5.0 * 0.1 + 5_000 * 5.0 * 1.25) / 1e6
    assert abs(totals["total_cost_usd"] - expected) < 1e-9, totals["total_cost_usd"]


def test_per_model_receipt_honored():
    """S5: the PER-MODEL receipt — the gpt-4.1 family's cached input
    prices at 0.25x (OpenAI's own table: $0.50 cached vs $2.00 input),
    NOT gpt-4o's 0.5x; the registry records the per-model column, never
    a family-wide guess."""
    p41 = pricing_map("openai")["gpt-4.1"]
    p4o = pricing_map("openai")["gpt-4o"]
    assert p41["cache_read"] == 0.25 and p4o["cache_read"] == 0.5, (
        f"the per-model ratios: 4.1={p41.get('cache_read')} 4o={p4o.get('cache_read')}")
    t = TokenTracker()
    t.record_call(model="gpt-4.1", input_tokens=6_000, output_tokens=100,
                  pricing=p41, usage_details={"cached_tokens": 5_000})
    totals = t.get_totals()
    expected = (1_000 * 2.0 + 100 * 8.0 + 5_000 * 2.0 * 0.25) / 1e6
    assert abs(totals["total_cost_usd"] - expected) < 1e-9, totals["total_cost_usd"]


def test_zai_divergent_price_record_stays_unrated():
    """S6 (the z-ai catch, a #690 deliverable): the OpenRouter listing carries
    cache reads for the glm routes ($0.078/M on glm-5.3), but the
    records' SHIPPED base prices diverge from the listing's prompt
    prices ($1.4 vs $0.079) — rating the cache against the stale base
    would misprice the reads, so the records stay UNRATED WITH REASON
    (the loud cost_incomplete path, the over-estimate direction) pending
    the price refresh. A pasted route multiplier against a stale base is
    the exact mistake the census discipline stops."""
    p = pricing_map("openrouter")["z-ai/glm-5.3"]
    assert "cache_read" not in p, "the divergent-price record was rated"
    import json as _json
    from pathlib import Path as _Path
    _cfg = _json.loads((_Path(__file__).resolve().parents[3]
                        / "config" / "models.json").read_text())
    _by_id = {r["id"]: r for r in _cfg["models"]}
    # BOTH glm routes carry the reason (the C4 linkage: the flash record's
    # reason hunk is guarded too, not only the flagship glm-5.3)
    for _glm_id in ("z-ai/glm-5.3", "z-ai/glm-5.3-flash"):
        _reason = _by_id[_glm_id].get("cache_unrated_reason", "")
        assert isinstance(_reason, str) and len(_reason) > 80 and (
            "diverge" in _reason.lower() and "unrated" in _reason.lower()), (
            f"{_glm_id}: the unrated-with-reason record lost its reason: {_reason!r}")
    t = TokenTracker()
    t.record_call(model="z-ai/glm-5.3", input_tokens=6_000, output_tokens=100,
                  pricing=p, usage_details={"cached_tokens": 5_000})
    totals = t.get_totals()
    assert totals["cost_incomplete"], (
        "the divergent-price record must keep the loud path")
    assert "z-ai/glm-5.3" in totals["unpriced_cache_models"]


def test_unpublished_google_stays_loud():
    """C1: the UNPUBLISHED stay unrated — Google's page carries no
    cached-input column for the 2.0 models, so gemini-2.0-flash keeps
    the loud cost_incomplete path with the model named. Never a guessed
    rate (base-green, stays green)."""
    p = pricing_map("google")["gemini-2.0-flash"]
    assert "cache_read" not in p, "an unpublished rate was guessed"
    t = TokenTracker()
    t.record_call(model="gemini-2.0-flash", input_tokens=6_000, output_tokens=500,
                  pricing=p,
                  usage_details={"cached_content_token_count": 5_000})
    totals = t.get_totals()
    assert totals["cost_incomplete"], (
        "the unrated record must keep the loud path")
    assert "gemini-2.0-flash" in totals["unpriced_cache_models"]


def test_ollama_exemplar_stays_loud():
    """C2: the unrated exemplar — the ollama record with cache usage keeps
    the loud path (the #661 suite's re-pinned exemplar; base-green)."""
    p = pricing_map("ollama")["qwen3.8:27b"]
    assert "cache_read" not in p
    t = TokenTracker()
    t.record_call(model="qwen3.8:27b", input_tokens=6_000, output_tokens=500,
                  pricing=p, usage_details={"cached_tokens": 5_000})
    totals = t.get_totals()
    assert totals["cost_incomplete"]
    assert "qwen3.8:27b" in totals["unpriced_cache_models"]


def test_anthropic_contract_byte_identical():
    """C3: the pre-existing anthropic contract — the #661 record's
    multipliers and the priced cache call unchanged (base-green)."""
    p = pricing_map("anthropic")["claude-sonnet-5"]
    assert p["cache_read"] == 0.1 and p["cache_write"] == 1.25, p
    t = TokenTracker()
    t.record_call(model="claude-sonnet-5", input_tokens=10_000,
                  output_tokens=1_000, pricing=p,
                  usage_details={"cache_read_input_tokens": 100_000,
                                "cache_creation_input_tokens": 50_000})
    totals = t.get_totals()
    expected = (10_000 * 2.0 + 1_000 * 10.0
                + 100_000 * 2.0 * 0.1 + 50_000 * 2.0 * 1.25) / 1e6
    assert abs(totals["total_cost_usd"] - expected) < 1e-9, totals["total_cost_usd"]


def test_read_only_record_with_write_usage_stays_incomplete():
    """C4: the one-sided record semantics (the #661 T8 contract) — a
    read-only record (the google shape: genuinely no published write)
    with WRITE usage prices the read side and still marks the run
    incomplete, naming the model (base-green; the google family inherits
    the contract — the openai family's write is KNOWN at 1.0 and does
    NOT take this path)."""
    p = pricing_map("google")["gemini-2.5-pro"]
    t = TokenTracker()
    t.record_call(model="gemini-2.5-pro", input_tokens=6_000, output_tokens=100,
                  pricing=p,
                  usage_details={"cached_content_token_count": 5_000,
                                 "cache_write_tokens": 2_000})
    totals = t.get_totals()
    assert totals["cost_incomplete"], (
        "the used-but-unpriced write side must mark the run incomplete")
    assert "gemini-2.5-pro" in totals["unpriced_cache_models"]


def test_overlap_clamp_shape_marks_incomplete():
    """S7 (the fable-r1 overlap catch, a #690 deliverable): the OpenRouter->Google explicit-cache
    shape reports the SAME tokens as both cached_tokens AND
    cache_write_tokens — the inclusive subtraction clamps the billed
    input to 0, which (priced-complete since this fix) would silently
    under-report the uncached remainder; the guard marks the run
    INCOMPLETE instead (the loud path). Unreachable from OpenAnt today
    (no explicit-cache breakpoints sent); pinned against regressions of
    the #661 clamp itself."""
    from utilities.llm_client import normalize_cache_usage, price_usage
    p = pricing_map("openrouter")["google/gemini-2.5-flash-lite"]
    # prompt 5 137 INCLUDES 5 132 cached AND the same 5 132 written (the
    # live-verified overlap shape)
    priced = price_usage(5_137, 100, p,
                         cache_counts=normalize_cache_usage(
                             {"cached_tokens": 5_132,
                              "cache_write_tokens": 5_132}))
    assert priced.unpriced_cache is True, (
        "the clamped-overlap shape must read INCOMPLETE, never silently "
        "under-reported")
    # and a NON-overlapping shape on the same record stays complete
    priced2 = price_usage(5_137, 100, p,
                          cache_counts=normalize_cache_usage(
                              {"cached_tokens": 5_132}))
    assert priced2.unpriced_cache is False, priced2
