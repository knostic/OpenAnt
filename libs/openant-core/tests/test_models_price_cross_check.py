"""#344: records for the same model family must agree on price unless annotated.

config/models.json is the single source of truth for pricing, read by BOTH the Python
engine and the Go CLI. A model can be reachable through several providers (direct
anthropic, bedrock, openrouter), and the issue's census found 15 comparable families —
14 agree to the cent across providers, and the one that diverged (claude-opus-4-8:
15/75 on anthropic+bedrock vs 5/25 on openrouter, a clean 3x on BOTH numbers) was the
stale shipped-table rate: live Anthropic pricing and the live OpenRouter catalogue BOTH
say $5/$25 per MTok — 15/75 is the retired Opus 4.1-era rate. A run's reported cost was
off by 3x depending on routing.

This test holds the invariant the file already keeps in 14 of 15 cases: same-family
records agree unless the divergence is EXPLICITLY annotated. The escape hatch is the
optional `price_diverges` field (a non-empty reason string) on the diverging record — a
gateway may legitimately reprice, but it must say so.

The family map is a real normalization, not a bare regex — ids appear as `vendor/slug`
(OpenRouter), `region.vendor.id` plus `-vN:N` (Bedrock), and `id-YYYYMMDD` (Anthropic
date stamps), and `4.5` vs `4-5` dot/dash conventions differ across providers. Missing
any convention silently SPLITS a family and hides a comparable pair (the issue's
script originally stripped only `anthropic/` and reported 2 comparable families where
there are 15).
"""
import json
import re
from collections import defaultdict

from core.model_registry import find_models_config, pricing_map


def _family(model_id: str) -> str:
    """Normalise an id to its model family across every id convention in the file."""
    s = re.sub(r"^[a-z0-9][a-z0-9-]*/", "", model_id)    # vendor/ slug (OpenRouter, hyphens/digits incl.)
    s = re.sub(r"^(us|global|eu|apac|jp|au|ca|sa)\.[a-z0-9-]+\.", "", s)  # region.vendor. (Bedrock)
    # plain vendor-prefixed Bedrock ids (the -5-generation serving shape:
    # anthropic.claude-opus-5 — no region prefix, no ARN-versioned twins).
    # Stripped AFTER the region rule so us.anthropic.* keeps its region
    # handling first; only un-prefixed anthropic.* ids reach this arm.
    s = re.sub(r"^anthropic\.", "", s)
    s = re.sub(r"-v\d+:\d+$", "", s)                   # Bedrock version suffix
    s = re.sub(r":[a-z0-9-]+$", "", s)                   # OpenRouter variant (:free, :thinking, :batch)
    s = re.sub(r"-\d{8}$", "", s)                     # Anthropic date stamp
    return s.replace(".", "-")                        # 4.5 vs 4-5 conventions


def _priced_records(data):
    for m in data.get("models", []):
        price = m.get("price")
        if isinstance(price, dict) and "id" in m:
            yield m


def test_same_family_prices_agree_across_providers():
    conf = find_models_config()
    assert conf is not None, "config/models.json not locatable (find_models_config)"
    # wave r1 (opus): pin the encoding — the registry loader does, and a
    # non-UTF-8-default runner would raise UnicodeDecodeError instead of
    # reporting the invariant.
    data = json.loads(conf.read_text(encoding="utf-8"))
    fam = defaultdict(list)
    for r in _priced_records(data):
        fam[_family(r["id"])].append(r)

    disagreements = []
    for family, recs in sorted(fam.items()):
        # wave r1 (three axes): compare EVERY record in the family — the
        # per-provider setdefault kept only the FIRST bedrock record and the
        # second mirror (us./global. share provider "bedrock") escaped every
        # comparison: correcting one mirror while the other stayed 15/75 was
        # GREEN. And the price_diverges hatch exempts only the ANNOTATED
        # record's own comparisons, not the whole family (an annotated
        # OpenRouter reprice must not blind the check to the
        # anthropic-vs-bedrock pairs of the same family).
        comparable = [r for r in recs
                      if not (isinstance(r.get("price_diverges"), str)
                              and r["price_diverges"].strip())]
        annotated = [r for r in recs
                     if isinstance(r.get("price_diverges"), str)
                     and r["price_diverges"].strip()]
        if len(comparable) + len(annotated) < 2 or not comparable:
            continue
        base = comparable[0]
        b = (base["price"]["input"], base["price"]["output"])
        for r in comparable[1:]:
            if (r["price"]["input"], r["price"]["output"]) != b:
                disagreements.append(
                    f"{family}: {r['id']} says {r['price']} but "
                    f"{base['id']} says {base['price']}"
                )
    assert not disagreements, (
        "cross-provider price disagreement without a `price_diverges` annotation "
        "(the run's reported cost is off by the ratio depending on routing; "
        "annotate a legitimate gateway/endpoint reprice or correct the stale "
        "record):\n  " + "\n  ".join(disagreements)
    )


def test_family_map_distinguishes_every_convention():
    """The normalizer must not SPLIT or MERGE families wrongly — the guard the
    issue's own script needed (a missed convention hides comparable pairs)."""
    f = _family
    # split: different families stay different
    assert f("claude-opus-4-8") != f("claude-sonnet-4-6")
    assert f("claude-opus-4-8") != f("claude-opus-4-1")
    # merge: one family across all four conventions
    ids = {
        "claude-opus-4-8",                             # direct anthropic
        "us.anthropic.claude-opus-4-8",                 # bedrock regional
        "global.anthropic.claude-opus-4-8",             # bedrock global
        "anthropic/claude-opus-4.8",                    # openrouter
    }
    assert len({f(i) for i in ids}) == 1, {f(i) for i in ids}
    # the date-stamp and version-suffix forms too
    assert f("claude-haiku-4-5-20251001") == f("us.anthropic.claude-haiku-4-5-20251001-v1:0")
    assert f("claude-haiku-4-5-20251001") == f("anthropic/claude-haiku-4.5")


# ---------------------------------------------------------------------------
# N-A2b (PR #661 dry-hunt, round 2): the same cross-check, for the CACHE
# multipliers #626 added.
#
# Why this belongs in THIS file and not somewhere else: `pricing_map`'s own
# docstring (model_registry.py:154-157) justifies its pass-2 ALIAS fill with
# "same-family records agree on price by the #344 cross-check, so an alias
# landing on a sibling record is cost-safe by construction". #626 then started
# riding `cache_read` / `cache_write` on the very same entry object — and the
# cross-check above compares `price["input"]`/`price["output"]` only. So the
# sentence that makes aliasing safe stopped covering everything the entry
# carries. These rows close that gap.
#
# It is not hypothetical arithmetic: the shipped census has a documented
# EXCEPTION PAIR (claude-fable-5-1 and claude-mythos-5-1 read at 0.025x, every
# other anthropic record at 0.1x). An alias that landed on the wrong sibling
# would misprice cached reads by 4x, silently and with cost_incomplete=False.
# ---------------------------------------------------------------------------

def _cache_mult(rec):
    """``(read, write)`` for a record carrying a cache block, else ``None``."""
    cache = rec.get("cache")
    if not isinstance(cache, dict) or cache.get("read") is None:
        return None
    return (float(cache["read"]),
            None if cache.get("write") is None else float(cache["write"]))


def _cache_disagreements(records):
    """Same-family records that BOTH carry a cache block must agree.

    Factored out so the test below can prove the checker actually FIRES —
    see test_the_cache_agreement_checker_is_not_vacuous. Only records that
    carry a block are compared: by #344's rule the block lives on the
    anthropic record only, and an ABSENT block is a different claim
    (unpriced cache -> the #626 incomplete path), not a disagreement.
    """
    fam = defaultdict(list)
    for r in records:
        if _cache_mult(r) is not None:
            fam[_family(r["id"])].append(r)
    out = []
    for family, recs in sorted(fam.items()):
        base = recs[0]
        for r in recs[1:]:
            if _cache_mult(r) != _cache_mult(base):
                out.append(f"{family}: {r['id']} caches at {_cache_mult(r)} "
                           f"but {base['id']} caches at {_cache_mult(base)}")
    return out


def test_same_family_cache_multipliers_agree_across_providers():
    """The cache analogue of the #344 price row.

    HONEST SCOPE NOTE: the shipped census has ZERO cache-comparable families
    today — #344's rule puts the cache block on the anthropic record only, so
    every one of the 8 cache-carrying families has exactly one such record
    (the bedrock/openrouter siblings carry none). This row therefore guards
    the FUTURE: it goes live the moment a second provider is given cache
    rates, which is exactly when a 4x divergence could ship unnoticed. Its
    checker is proven to fire by the next test, so a green here is "no
    disagreement", never "nothing was compared".
    """
    conf = find_models_config()
    assert conf is not None, "config/models.json not locatable"
    data = json.loads(conf.read_text(encoding="utf-8"))
    assert not _cache_disagreements(list(_priced_records(data))), (
        "cross-provider CACHE-multiplier disagreement (#626 prices cached "
        "tokens at these multipliers of the base input rate, so a divergence "
        "misprices cached usage by the ratio depending on routing):\n  "
        + "\n  ".join(_cache_disagreements(list(_priced_records(data)))))


def test_the_cache_agreement_checker_is_not_vacuous():
    """Prove the checker above detects what it claims to detect.

    Without this, the zero-comparable-family census would make the row an
    unfalsifiable green — a text pin, not a test.
    """
    agree = [{"id": "claude-opus-5", "price": {"input": 5.0, "output": 25.0},
              "cache": {"read": 0.1, "write": 1.25}},
             {"id": "anthropic/claude-opus-5",
              "price": {"input": 5.0, "output": 25.0},
              "cache": {"read": 0.1, "write": 1.25}}]
    assert _cache_disagreements(agree) == []
    # the 4x read divergence (the exception-rate pasted onto a sibling)
    disagree = [dict(agree[0]),
                {"id": "anthropic/claude-opus-5",
                 "price": {"input": 5.0, "output": 25.0},
                 "cache": {"read": 0.025, "write": 1.25}}]
    assert len(_cache_disagreements(disagree)) == 1
    # and a WRITE-only divergence is caught too (not just read)
    wdiff = [dict(agree[0]),
             {"id": "anthropic/claude-opus-5",
              "price": {"input": 5.0, "output": 25.0},
              "cache": {"read": 0.1, "write": 2.0}}]
    assert len(_cache_disagreements(wdiff)) == 1
    # an ABSENT block is not a disagreement (the #626 incomplete path)
    absent = [dict(agree[0]),
              {"id": "anthropic/claude-opus-5",
               "price": {"input": 5.0, "output": 25.0}}]
    assert _cache_disagreements(absent) == []


def test_every_priced_spelling_carries_its_own_familys_cache_multiplier():
    """The alias row — the non-vacuous half of N-A2b.

    `pricing_map` pass 2 assigns the SAME entry object to every alias
    spelling, cache multipliers included. The shipped anthropic map has 17
    keys, 7 of them aliases carrying `cache_read` (claude-fable-5.1,
    claude-haiku-4-5, claude-haiku-4.5, claude-mythos-5.1, claude-opus-4.7,
    claude-opus-4.8, claude-sonnet-4.6). Each must carry the multiplier of a
    record in ITS OWN family — if the alias normalisation ever merged the
    0.025x exception pair with its 0.1x sibling, cached reads would misprice
    4x with no marker.
    """
    conf = find_models_config()
    data = json.loads(conf.read_text(encoding="utf-8"))
    # family -> the cache multipliers any record of that family declares
    by_family = defaultdict(set)
    for r in _priced_records(data):
        mult = _cache_mult(r)
        if mult is not None:
            by_family[_family(r["id"])].add(mult)

    providers = {r.get("provider") for r in _priced_records(data)}
    checked = 0
    for provider in sorted(p for p in providers if p):
        pmap = pricing_map(provider)
        for key, entry in pmap.items():
            if "cache_read" in entry:
                mult = (entry["cache_read"], entry.get("cache_write"))
                declared = by_family.get(_family(key), set())
                assert mult in declared, (
                    f"{provider}:{key} prices cached tokens at {mult}, which "
                    f"NO record of family {_family(key)!r} declares "
                    f"({declared or 'none'}) — an alias landed on a "
                    f"foreign-family cache rate")
                checked += 1
    # the census, asserted so a normalisation change that DROPS alias keys
    # cannot quietly shrink this row to nothing
    assert checked == 17, f"expected 17 cache-carrying priced keys, got {checked}"


def test_the_documented_cache_exception_pair_is_exactly_two_models():
    """#626's census claim, pinned: every anthropic cache read is 0.1x except
    the documented Fable 5.1 / Mythos 5.1 pair at 0.025x, and every write is
    1.25x. A rate pasted where a MULTIPLIER belongs (the easy mistake: these
    are fractions of the base input rate, not $/MTok) fails here."""
    conf = find_models_config()
    data = json.loads(conf.read_text(encoding="utf-8"))
    reads = defaultdict(set)
    writes = set()
    for r in _priced_records(data):
        mult = _cache_mult(r)
        if mult is not None:
            reads[mult[0]].add(r["id"])
            writes.add(mult[1])
    assert set(reads) == {0.1, 0.025}, set(reads)
    assert reads[0.025] == {"claude-fable-5-1", "claude-mythos-5-1"}
    assert writes == {1.25}, writes


def test_cache_block_lives_only_on_anthropic_records():
    """#344's letter for the cache kind: the multipliers are Anthropic's
    documented prompt-caching rates, so no other provider's record may claim
    them (a bedrock/openrouter gateway reprices and would need its own
    sourced block + the agreement row above)."""
    conf = find_models_config()
    data = json.loads(conf.read_text(encoding="utf-8"))
    offenders = [r["id"] for r in _priced_records(data)
                 if _cache_mult(r) is not None
                 and r.get("provider") != "anthropic"]
    assert offenders == [], offenders
    # non-vacuous: there ARE non-anthropic priced records to be wrong about
    others = [r["id"] for r in _priced_records(data)
              if r.get("provider") != "anthropic"]
    assert len(others) >= 20, len(others)
