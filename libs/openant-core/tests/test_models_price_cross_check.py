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

from core.model_registry import find_models_config


def _family(model_id: str) -> str:
    """Normalise an id to its model family across every id convention in the file."""
    s = re.sub(r"^[a-z0-9][a-z0-9-]*/", "", model_id)    # vendor/ slug (OpenRouter, hyphens/digits incl.)
    s = re.sub(r"^(us|global|eu|apac|jp|au|ca|sa)\.[a-z0-9-]+\.", "", s)  # region.vendor. (Bedrock)
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
