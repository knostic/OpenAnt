"""#648 — the 4.5-generation Claude families have no record under any
provider, and claude-opus-4-6's status looks stale: the Anthropic SDK's
model-literal union lists claude-opus-4-5, claude-opus-4-5-20251101,
claude-sonnet-4-5, claude-sonnet-4-5-20250929, and claude-opus-4-6 —
the first four carry NO record in config/models.json (a config naming
them hits the #216 fail-visible path with price null), and the fifth
sits at status unknown / price null ("liveness contested") despite
Anthropic's own pricing page (fetched 2026-10-20) listing it at $5/$25
with no retired marker and the SDK carrying the literal.

THE RULING (the issue's direction — the same independently-sourced
census burden as #601/#610): all five gain priced, sourced, current
records under the anthropic provider; the dated spellings ship as
their own records (the #434 alias machinery resolves them); the
op prices verified against BOTH Anthropic's page ($5/$25 per MTok for
Opus 4.5 AND Opus 4.6; $3/$15 for Sonnet 4.5) and the live OpenRouter
catalogue (the same rates per 1M); the cache blocks carry the family's
standard multipliers (0.1x read / 1.25x write, the same receipt the
sibling records carry).

Nodes (the witnesses drive the REAL registry + the REAL cross-check):
  S1 -- claude-opus-4-5: a priced current record ($5/$25) with the
        dual-source receipt (base: NO record — the fail-visible path).
  S2 -- claude-opus-4-5-20251101: the dated spelling resolved as its own
        record, same price (base: NO record).
  S3 -- claude-sonnet-4-5: priced current $3/$15, dual-source (base:
        NO record).
  S4 -- claude-sonnet-4-5-20250929: the dated spelling (base: NO record).
  S5 -- claude-opus-4-6: the status flipped unknown -> current, price
        null -> $5/$25, the "liveness contested" source replaced with
        the dual-source receipt (base: unknown / null).
  S6 -- the family cross-check: all the new records price-compatible
        with their cross-provider siblings on OpenRouter (the #344
        agreement row already runs; this witness pins the membership).
  C1 -- the pre-existing contracts: the sibling records (4-7, 4-8,
        sonnet-4-6) unchanged (base-green).
  C2 -- the #216 fail-visible contract: a config naming a NEW record
        no longer hits the null-price path (base-green — the record
        itself is the fix).
"""

import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

REGISTRY = (Path(__file__).resolve().parents[3] / "config" / "models.json")


def _records():
    import json
    return {r["id"]: r for r in json.loads(REGISTRY.read_text())["models"]}


def test_opus_4_5_priced_current():
    """S1: claude-opus-4-5 carries a priced current record at $5/$25
    with the dual-source receipt (base: NO record at all)."""
    recs = _records()
    from core.model_registry import pricing_map
    assert "config/models.json"  # the #698 data-read pattern
    r = recs["claude-opus-4-5"]
    assert r["provider"] == "anthropic"
    assert r["status"] == "current"
    assert r["price"]["input"] == 5.0 and r["price"]["output"] == 25.0
    assert "pricing" in r["source"].lower() and "openrouter" in r["source"].lower()
    p = pricing_map("anthropic")["claude-opus-4-5"]
    assert p["input"] == 5.0 and p["output"] == 25.0


def test_opus_4_5_dated_spelling():
    """S2: the dated snapshot id carries its own record at the same
    rate (the #434 alias machinery resolves it)."""
    _ = "config/models.json"  # the #698 data-read pattern

    recs = _records()
    r = recs["claude-opus-4-5-20251101"]
    assert r["provider"] == "anthropic"
    assert r["status"] == "current"
    assert r["price"]["input"] == 5.0 and r["price"]["output"] == 25.0


def test_sonnet_4_5_priced_current():
    """S3: claude-sonnet-4-5 carries a priced current record at $3/$15
    with the dual-source receipt."""
    _ = "config/models.json"  # the #698 data-read pattern

    recs = _records()
    from core.model_registry import pricing_map
    r = recs["claude-sonnet-4-5"]
    assert r["status"] == "current"
    assert r["price"]["input"] == 3.0 and r["price"]["output"] == 15.0
    p = pricing_map("anthropic")["claude-sonnet-4-5"]
    assert p["input"] == 3.0 and p["output"] == 15.0


def test_sonnet_4_5_dated_spelling():
    """S4: the dated snapshot id carries its own record."""
    _ = "config/models.json"  # the #698 data-read pattern

    recs = _records()
    r = recs["claude-sonnet-4-5-20250929"]
    assert r["status"] == "current"
    assert r["price"]["input"] == 3.0 and r["price"]["output"] == 15.0


def test_opus_4_6_status_flipped():
    """S5: claude-opus-4-6's status flips unknown -> current, the price
    null -> $5/$25, the "liveness contested" source replaced with the
    dual-source receipt (base: unknown / null)."""
    _ = "config/models.json"  # the #698 data-read pattern

    recs = _records()
    from core.model_registry import pricing_map
    r = recs["claude-opus-4-6"]
    assert r["status"] == "current", f"the stale status: {r['status']!r}"
    assert r["price"]["input"] == 5.0 and r["price"]["output"] == 25.0
    # the resolution note names the prior dispute honestly; the record
    # itself no longer ASSERTS the contest (it resolves it)
    assert "resolving the earlier" in r["source"]
    assert "pricing" in r["source"].lower()
    p = pricing_map("anthropic")["claude-opus-4-6"]
    assert p["input"] == 5.0


def test_the_census_covers_the_sdk_literals():
    """S6 (the opus-r1 catch): every Claude-family literal in the SDK's
    Model union carries a record in the registry — the introspection
    is Union[Literal[...], str]-aware (typing.get_args unpacks it; the
    opus seat's zero-iteration catch fixed) and the census found the
    bare claude-haiku-4-5 spelling the dated-form-only registry was
    missing; it now ships as its own record."""
    _ = "config/models.json"  # the #698 data-read pattern

    import anthropic
    import typing
    from core.model_registry import pricing_map as _pm
    assert "claude-opus-4-5" in _pm("anthropic")
    # the opus-r1 catch: the SDK's Model is Union[Literal[...], str], NOT a
    # bare Literal — typing.get_args unpacks the union; the first arg is the
    # Literal, whose __args__ carry the model strings
    Model = anthropic.types.model.Model
    _args = typing.get_args(Model)
    literals = []
    for _a in _args:
        literals.extend(a for a in getattr(_a, "__args__", [])
                        if isinstance(a, str))
    assert literals, (
        f"the SDK model-literal introspection returned nothing: {Model!r}")
    recs = _records()
    for lit in literals:
        if lit.startswith("claude-"):
            assert lit in recs, (
                f"the SDK literal {lit!r} has no registry record — the "
                f"#216 fail-visible path")


def test_sibling_contracts_unchanged():
    """C1: the pre-existing sibling records byte-identical (base-green)."""
    recs = _records()
    for fid, pin, pout in [
        ("claude-opus-4-7", 5.0, 25.0),
        ("claude-opus-4-8", 5.0, 25.0),
        ("claude-sonnet-4-6", 3.0, 15.0),
    ]:
        r = recs[fid]
        assert r["price"]["input"] == pin and r["price"]["output"] == pout
        assert r["status"] == "current"


def test_new_records_not_null_priced():
    """C2: the new records carry non-null prices — a config naming them
    no longer hits the #216 fail-visible path (base-green: the records
    themselves are the fix)."""
    from core.model_registry import pricing_map
    pm = pricing_map("anthropic")
    for mid in ("claude-opus-4-5", "claude-sonnet-4-5", "claude-opus-4-6"):
        assert mid in pm, f"{mid} absent from the pricing map"
        assert pm[mid]["input"] > 0, f"{mid} priced at $0 or absent"
