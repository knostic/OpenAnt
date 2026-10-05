"""Regression tests for issues #601 + #610 — the registry's direct-anthropic
coverage gap for the current Claude generation.

#601: claude-sonnet-5 / claude-opus-5 / claude-fable-5 existed only as
OpenRouter records; a config naming them under provider ``anthropic`` hit
the #216 fail-visible path ($0 + cost_incomplete) because
``pricing_map("anthropic")`` never crossed providers to find the twin.

#610: five SDK-listed literals (the Anthropic SDK's model-literal union, types/model.py:
claude-fable-5-1, claude-mythos-5-1, claude-mythos-5, claude-mythos-preview,
claude-opus-4-7) had no record under ANY provider. Four carry published
prices on Anthropic's pricing page (2026-09-18) and are added as priced
direct records; claude-mythos-preview has NO published price row (the
page references it only in tokenizer/long-context notes) and is added as
the registry-native form for a known-but-unpriceable model: status
"unknown", price null — the claude-opus-4-6 precedent. Its #216 treatment
is byte-identical to total absence (null-priced records are omitted from
pricing_map exactly as absent ones are); the record makes the deliberate
absence machine-readable instead of editorial.

Contract pinned here (the RED half: every rate/existence/alias/twin-link
assertion fails on master; the omission-flavored asserts are green-on-
master guards and are labeled as such):
- each priced record resolves under provider ``anthropic`` at the exact
  independently-sourced rates (Anthropic's pricing page 2026-09-18;
  OpenRouter's live catalogue corroborates where it serves the model);
- the two-number ids emit their dotted alias (the #434 machinery);
- the bare-id convention holds (a bare direct record generates no
  vendor-prefixed alias — ``anthropic/{id}`` is NOT served under the
  anthropic provider);
- the OpenRouter twins agree with the direct records EXACTLY (the #344
  cross-check guards the pair; the assert compares the two maps without
  duplicating rate literals);
- the mythos-preview record EXISTS (find_model resolves it) and is
  deliberately unpriced — the existence pin is the only delete-mutation
  guard (omission-flavored assertions pass whether the record never
  existed or exists-with-null-price).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.model_registry import find_model, pricing_map  # noqa: E402


# (id, input $/MTok, output $/MTok, dotted_alias_or_None)
# Sourced from Anthropic's pricing page (fetched 2026-09-18) and, where
# OpenRouter serves the model, corroborated by its live catalogue the
# same day — both live sources agree on every pair.
_DIRECT_ANTHROPIC_CURRENT = [
    # The page's note: the $2/$10 launch pricing for Sonnet 5 is now the
    # STANDARD price — the previously scheduled 2026-09-01 increase to
    # $3/$15 "will not occur".
    ("claude-sonnet-5", 2.0, 10.0, None),
    ("claude-opus-5", 5.0, 25.0, None),
    ("claude-fable-5", 10.0, 50.0, None),
    ("claude-fable-5-1", 10.0, 50.0, "claude-fable-5.1"),
    # limited availability (glasswing-gated) — the direct provider's
    # pricing page is the single source; OpenRouter does not serve them.
    ("claude-mythos-5", 10.0, 50.0, None),
    ("claude-mythos-5-1", 10.0, 50.0, "claude-mythos-5.1"),
    ("claude-opus-4-7", 5.0, 25.0, "claude-opus-4.7"),
]

# (bare direct id, OpenRouter twin id) — the pairs whose twin-link must
# agree exactly (#344's cross-check guards them; this assert pins the
# link without duplicating rate literals).
_TWIN_LINKS = [
    ("claude-sonnet-5", "anthropic/claude-sonnet-5"),
    ("claude-opus-5", "anthropic/claude-opus-5"),
    ("claude-fable-5", "anthropic/claude-fable-5"),
    ("claude-fable-5-1", "anthropic/claude-fable-5.1"),
    ("claude-opus-4-7", "anthropic/claude-opus-4.7"),
]


def test_direct_anthropic_records_resolve_at_sourced_rates():
    """RED on master: pricing_map("anthropic") carries none of the seven —
    every row's exact-rate assert fails (the #601/#610 gap)."""
    direct = pricing_map("anthropic")
    for model_id, price_in, price_out, _alias in _DIRECT_ANTHROPIC_CURRENT:
        assert direct[model_id] == {"input": price_in, "output": price_out}, (
            f"{model_id} must carry the independently-sourced direct rate "
            f"({price_in}/{price_out} $/MTok)")


def test_two_number_ids_emit_dotted_aliases():
    """RED on master: the records do not exist, so neither do their #434
    dotted aliases. The single-number ids emit none — pinned as the
    negative half against the MACHINERY (not a constructed lookalike
    string: _alias_spellings is the real claim, and the private-helper
    import mirrors test_model_config_centralize's own)."""
    from core.model_registry import _alias_spellings
    direct = pricing_map("anthropic")
    for model_id, price_in, price_out, dotted in _DIRECT_ANTHROPIC_CURRENT:
        if dotted is not None:
            assert direct[dotted] == {"input": price_in, "output": price_out}, (
                f"the #434 dotted alias {dotted} must carry {model_id}'s rate")
            assert _alias_spellings(model_id) == [dotted]
        else:
            # the negative half: a single-number id emits NO aliases
            assert _alias_spellings(model_id) == [], (
                f"a single-number id ({model_id}) must emit no aliases — "
                "the #434 machinery only fires on two numeric segments")


def test_bare_id_convention_no_vendor_prefixes_under_anthropic():
    """GUARD (green on master by absence): a bare direct record generates
    zero vendor-prefixed aliases (#434's vendor inference needs a slash
    in the id) — anthropic/claude-sonnet-5 is NOT served under the
    anthropic provider; the OpenRouter twin carries the prefixed spelling
    under the openrouter provider instead. Pinned as the family's honest
    shape, not a defect."""
    direct = pricing_map("anthropic")
    for model_id, _a, _b, _c in _DIRECT_ANTHROPIC_CURRENT:
        assert f"anthropic/{model_id}" not in direct


def test_openrouter_twins_agree_with_direct_records():
    """RED on master: the direct half of each pair is missing (and for
    fable-5.1/opus-4-7 the openrouter half too). The link assert compares
    the two maps — no rate literal is duplicated here; the #344 cross-
    check test guards the same agreement in the data file itself."""
    direct = pricing_map("anthropic")
    router = pricing_map("openrouter")
    for bare, prefixed in _TWIN_LINKS:
        assert direct[bare] == router[prefixed], (
            f"the {bare} family must agree across providers "
            f"(direct vs {prefixed})")


def test_mythos_preview_exists_deliberately_unpriced():
    """RED on master: find_model returns None (no record). The EXISTENCE
    pin is the only delete-mutation guard — omission-flavored asserts
    (pricing_map.get is None) pass whether the record never existed or
    exists-with-null-price, so they cannot carry the deliberate-absence
    claim alone (the review round's delete-mutation receipt)."""
    rec = find_model("claude-mythos-preview")
    assert rec is not None, (
        "claude-mythos-preview is SDK-listed (the Anthropic SDK's model "
        "literals, types/model.py) with NO published price row — the registry's "
        "native form for that is an unknown/null record, not silence")
    assert rec["provider"] == "anthropic"
    assert rec["status"] == "unknown"
    assert rec["price"] is None


def test_mythos_preview_is_omitted_from_pricing():
    """GUARD (green on master by absence): the unknown/null record is
    omitted from pricing_map exactly as an absent model is — #216's
    fail-visible path ($0 + cost_incomplete + the one-time warning) fires
    for a config naming it, byte-identical to the pre-record state."""
    assert pricing_map("anthropic").get("claude-mythos-preview") is None
