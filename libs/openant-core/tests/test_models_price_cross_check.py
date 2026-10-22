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
    s = s.replace(".", "-")                            # 4.5 vs 4-5 conventions
    # the date stamp runs AFTER the dot->dash swap: the alias spellings
    # carry the date dot-attached (claude-haiku-4-5.20251001) and only the
    # swapped form matches the -\d{8}$ rule (the #690 bedrock alias catch —
    # the pre-#690 order left the dot-date as a phantom family suffix)
    s = re.sub(r"-\d{8}$", "", s)
    return s


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
        # the opus-r1 catch: the base must be a NON-ANNOTATED record (the
        # price row's own wave-r1 rule) — an annotated record as the base
        # would launder every sibling's divergence
        comparable = [r for r in recs
                      if not (isinstance(r.get("cache_diverges"), str)
                              and r["cache_diverges"].strip())]
        base = comparable[0] if comparable else recs[0]
        for r in recs:
            if _cache_mult(r) != _cache_mult(base):
                # the #690 hatch (mirroring price_diverges): an annotated
                # divergence names the ROUTE difference and is allowed —
                # the openrouter google routes list cache writes at their
                # own prices while Google's page publishes none.
                _why = (isinstance(r.get("cache_diverges"), str)
                        and r["cache_diverges"].strip())
                if _why:
                    continue
                out.append(f"{family}: {r['id']} caches at {_cache_mult(r)} "
                           f"but {base['id']} caches at {_cache_mult(base)}")
    return out


def test_same_family_cache_multipliers_agree_across_providers():
    """The cache analogue of the #344 price row.

    LIVE SINCE #690, AND #648 DID NOT CHANGE ITS SCOPE (the old note that
    said "zero cache-comparable families" is history): 21 comparable
    families — the 8 claude families across anthropic+bedrock+openrouter
    (the 0.025x exception pair agreeing on all three providers), the 9
    openai families across openai+openrouter (the per-model 0.5x/0.25x
    ratios agreeing), and the 4 gemini families across google+openrouter
    (the reads agreeing at 0.1x; the openrouter routes' writes
    hatch-annotated — Google's page publishes no write). #648's three new
    cache-bearing families (claude-opus-4-5, claude-sonnet-4-5 and the
    newly-priced claude-opus-4-6) are ANTHROPIC-ONLY — no bedrock or
    openrouter sibling carries them — so they raise the cache-bearing
    family count 23 -> 26 while leaving the COMPARABLE (multi-provider)
    count at 21. A green here is a real "no disagreement", never
    "nothing was compared".
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
    spelling, cache multipliers included. The #690 census as widened by
    #648 cache-rates 61 records across five providers
    (anthropic/bedrock/openai/google/openrouter) and the maps carry 130
    cache-bearing keys incl. their alias spellings (the bedrock region
    twins, the OpenRouter slug spellings). #648 contributes exactly 8 of
    them to the anthropic map (17 -> 25): the five record-id keys
    claude-opus-4-5, claude-opus-4-5-20251101, claude-sonnet-4-5,
    claude-sonnet-4-5-20250929 and claude-opus-4-6 (the status flip makes
    that one priced), plus the three dotted alias spellings
    claude-opus-4.5, claude-opus-4.6 and claude-sonnet-4.5 — the bare
    claude-haiku-4-5 record adds NO key because its spelling already
    shipped as an alias (the opus-r1 catch). Each must carry the
    multiplier of a record in ITS OWN family — if the alias normalisation
    ever merged the 0.025x exception pair with its 0.1x sibling, cached
    reads would misprice 4x with no marker.
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
    # the #690 census as widened by #648: every cache-carrying priced key
    # across ALL five providers' maps (the record ids + their alias
    # spellings). 122 (#690) + 8 (#648's 4.5-generation anthropic keys)
    # + 6 (#648's 5.5-generation keys: the three record ids claude-opus-5-5,
    # claude-sonnet-5-5 and claude-haiku-5-5, each plus its ONE dotted alias
    # spelling claude-opus-5.5 / claude-sonnet-5.5 / claude-haiku-5.5 —
    # anthropic's map goes 25 -> 31) = 136, derived by running this very
    # census on the records tree, never transcribed.
    assert checked == 136, f"expected 136 cache-carrying priced keys, got {checked}"


def test_the_documented_cache_exceptions_are_exactly_the_published_groups():
    """#626's census claim, pinned: every anthropic cache read is 0.1x except
    the DOCUMENTED exception groups, and every write is 1.25x. A rate pasted
    where a MULTIPLIER belongs (the easy mistake: these are fractions of the
    base input rate, not $/MTok) fails here.

    RENAMED at #648's 5.5-generation round, because the old name
    (``..._pair_is_exactly_two_models``) asserted a fact that stopped being
    true: Anthropic's pricing page now publishes TWO exception groups, not
    one pair. Its footnotes, fetched 2026-10-21:
      * 0.025x — "Cache hits and refreshes on Claude Fable 5.1 and Claude
        Mythos 5.1 are priced at 0.025x the base input price"
      * 0.05x  — "Cache hits and refreshes on Claude Opus 5.5 and Claude
        Sonnet 5.5 are priced at 0.05x the base input price"
      * "All other models use the standard 0.1x multiplier" — which is why
        claude-haiku-5-5, added in the same round, is pinned at 0.1x and
        NOT at a 5.5-generation rate. The generation does not set the
        multiplier; the page does, per model.
    The assertion is not weakened by the rename: both groups are pinned by
    EXACT set equality, so adding a model to either one, or inventing a
    third rate, still fails here."""
    conf = find_models_config()
    data = json.loads(conf.read_text(encoding="utf-8"))
    reads = defaultdict(set)
    writes = set()
    for r in _priced_records(data):
        mult = _cache_mult(r)
        if mult is not None:
            reads[mult[0]].add(r["id"])
            if mult[1] is not None:      # the read-only records carry no write
                writes.add(mult[1])
    # the #690 census: the reads are the per-family published ratios —
    # the anthropic/bedrock 0.1x with the documented 0.025x exception pair,
    # the openai per-model 0.5x/0.25x, the google 0.1x; the writes are
    # 1.25x (anthropic/bedrock/the openrouter claude+google routes at
    # their own published per-model prices)
    assert set(reads) == {0.1, 0.05, 0.025, 0.5, 0.25}, set(reads)
    assert reads[0.025] == {
        "claude-fable-5-1", "claude-mythos-5-1",
        "anthropic.claude-fable-5-1", "anthropic/claude-fable-5.1",
    }, reads[0.025]
    # the 0.05x group: the direct-anthropic records only. Unlike the 0.025x
    # group there is no bedrock (``anthropic.``) or openrouter
    # (``anthropic/``) sibling spelling, because no such record exists for
    # the 5.5 generation yet — so this set is 2, not 4, and a bedrock or
    # openrouter 5.5 record arriving later MUST land here rather than
    # silently at 0.1x.
    assert reads[0.05] == {
        "claude-opus-5-5", "claude-sonnet-5-5",
    }, reads[0.05]
    assert reads[0.5] == {"gpt-4o", "gpt-4o-mini", "o1", "o3-mini",
                          "openai/gpt-4o", "openai/gpt-4o-mini",
                          "openai/o1", "openai/o3-mini"}, reads[0.5]
    assert reads[0.25] == {"gpt-4.1", "gpt-4.1-mini", "gpt-4.1-nano",
                           "o3", "o4-mini", "openai/gpt-4.1",
                           "openai/gpt-4.1-mini", "openai/gpt-4.1-nano",
                           "openai/o3", "openai/o4-mini"}, reads[0.25]
    # the openai family's writes are KNOWN at 1.0 (no premium — OpenRouter's
    # docs: 'no cost on models before the GPT-5.6 family'); the google
    # routes' writes are the OpenRouter listings; anthropic/bedrock 1.25x
    assert writes == {1.25, 1.0, 0.3, 0.2778, 0.8333, 0.0556}, writes


def test_cache_block_lives_only_on_sourced_records():
    """#344's letter, SUPERSEDED at #690: the multipliers are SOURCED PER
    PROVIDER now (OpenAI/Google's own pages, the OpenRouter listings,
    Bedrock's docs + Anthropic's per-model rates), so the block lives on
    any record that carries a source receipt — and every one must: an
    unsourced cache block is a pasted rate, the exact mistake the census
    discipline exists to stop. The family-AGREEMENT row (and the
    cache_diverges hatch) covers the cross-provider consistency; this row
    covers the provenance."""
    conf = find_models_config()
    data = json.loads(conf.read_text(encoding="utf-8"))
    offenders = [r["id"] for r in _priced_records(data)
                 if _cache_mult(r) is not None
                 and not (isinstance(r.get("cache", {}).get("source"), str)
                          and r["cache"]["source"].strip())]
    assert offenders == [], offenders
    # non-vacuous: the census is now cross-provider (the #690 rate set)
    non_anthropic_rated = [r["id"] for r in _priced_records(data)
                           if _cache_mult(r) is not None
                           and r.get("provider") != "anthropic"]
    assert len(non_anthropic_rated) >= 40, len(non_anthropic_rated)
