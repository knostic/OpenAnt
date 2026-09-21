"""Regression tests for issue #607 — the registry's Bedrock coverage gap for
the current Claude generation.

#607: claude-sonnet-5 / claude-opus-5 / claude-fable-5 existed only as
direct-anthropic (and OpenRouter) records; a config naming them under provider
``bedrock`` hit the #216 fail-visible path ($0 + cost_incomplete) because
``pricing_map("bedrock")`` carried no record for them.

The issue's original direction — add ``us.``/``global.`` inference-profile
twins mirroring the 4.x-era records — is superseded by the vendor's current
documentation: the -5 generation (with Opus 4.7/4.8) "do not have ARN-versioned
model IDs" and is omitted from the legacy model table (Anthropic's legacy
Bedrock guide, fetched 2026-09-21); the current Claude-in-Amazon-Bedrock
integration serves them under plain ``anthropic.claude-*`` model IDs.
Pattern-mirroring the 4.x id shapes would have fabricated ids (#344's
violation — the exact hazard the issue's evidence-state comment flagged); the
records added for this issue use the documented plain spellings.

Contract pinned here (the RED half: every rate/existence assertion fails on
master; the omission-flavored asserts are green-on-master guards and are
labeled as such):
- each record resolves under provider ``bedrock`` and agrees with the direct
  anthropic record EXACTLY (the map-compare assert; the #344 cross-check
  guards the data file itself — no rate literal is duplicated here);
- find_model resolves each record under provider ``bedrock`` (the
  delete-mutation guard);
- NO us./global. inference-profile twins exist for this generation — the
  anti-pattern-mirroring guard (green on master by absence; a regression that
  adds fabricated twins turns it RED);
- the single-number ids emit no #434 aliases (the machinery's negative half).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.model_registry import find_model, pricing_map  # noqa: E402


# (bedrock id, direct anthropic id) — ids from the Supported models table of
# Anthropic's current Claude-in-Amazon-Bedrock integration doc (fetched
# 2026-09-21); rates sourced from Anthropic's pricing page the same day and
# equal to the direct rate (Bedrock GLOBAL-endpoint pricing carries no
# premium; the 10% regional premium is an endpoint choice, not a model-id
# variant, so id-level pricing carries the global rate).
# (bedrock id, direct anthropic id, dotted_alias_or_None) — ids from the
# Supported models table of Anthropic's current Claude-in-Amazon-Bedrock
# integration doc (fetched 2026-09-21); rates sourced from Anthropic's
# pricing page the same day and equal to the direct rate (Bedrock
# GLOBAL-endpoint pricing carries no premium; the 10% regional premium is
# an endpoint choice, not a model-id variant, so id-level pricing carries
# the global rate).
_BEDROCK_CURRENT = [
    ("anthropic.claude-sonnet-5", "claude-sonnet-5", None),
    ("anthropic.claude-opus-5", "claude-opus-5", None),
    ("anthropic.claude-fable-5", "claude-fable-5", None),
    # Sibling sweep (the same gap class, same Supported-models table): these
    # two carry direct records and Bedrock serving but no bedrock record
    # either — fixed in the same run per the sibling commitment gate.
    ("anthropic.claude-fable-5-1", "claude-fable-5-1", "anthropic.claude-fable-5.1"),
    ("anthropic.claude-opus-4-7", "claude-opus-4-7", "anthropic.claude-opus-4.7"),
]


def test_bedrock_records_agree_with_direct_records():
    """RED on master: pricing_map("bedrock") carries none of the three —
    each lookup raises KeyError (the #607 gap). The assert compares the two
    maps, so no rate literal is duplicated; the #344 cross-check guards the
    same agreement in the data file itself."""
    bedrock = pricing_map("bedrock")
    direct = pricing_map("anthropic")
    for bedrock_id, direct_id, _dotted in _BEDROCK_CURRENT:
        assert bedrock[bedrock_id] == direct[direct_id], (
            f"{bedrock_id} must resolve under provider bedrock at the "
            f"direct rate (agrees with the {direct_id} record)")


def test_bedrock_records_exist_under_provider():
    """RED on master: find_model returns None for all three (no records).
    The existence pin is the delete-mutation guard (omission-flavored
    pricing asserts pass whether a record never existed or exists with a
    null price, so they cannot carry this claim alone)."""
    for bedrock_id, _direct_id, _dotted in _BEDROCK_CURRENT:
        rec = find_model(bedrock_id)
        assert rec is not None, (
            f"{bedrock_id} is served by Amazon Bedrock per the vendor's "
            "current integration docs — the registry's native form for "
            "that is a priced bedrock record, not silence")
        assert rec["provider"] == "bedrock"
        assert rec["status"] == "current"
        assert rec["price"] is not None


def test_no_inference_profile_twins_for_current_generation():
    """GUARD (green on master by absence): the -5 generation has NO
    ARN-versioned inference-profile ids — Anthropic's legacy Bedrock guide
    omits these models from its model table precisely because they "do not
    have ARN-versioned model IDs". A us./global. twin for them would be a
    fabricated id (#344's violation); this assert turns RED if one is ever
    added."""
    bedrock = pricing_map("bedrock")
    for bedrock_id, _direct_id, _dotted in _BEDROCK_CURRENT:
        assert f"us.{bedrock_id}" not in bedrock, (
            f"us.{bedrock_id} does not exist on Bedrock (no ARN-versioned "
            "ids for this generation) — a record for it would be a "
            "pattern-mirrored fabrication")
        assert f"global.{bedrock_id}" not in bedrock, (
            f"global.{bedrock_id} does not exist on Bedrock (no "
            "ARN-versioned ids for this generation) — a record for it "
            "would be a pattern-mirrored fabrication")


def test_single_number_ids_emit_no_aliases():
    """The #434 machinery's negative half (mirrors the #601 test): a
    single-number id emits no aliases; a two-number id emits exactly its
    dotted twin — the machinery only fires on two numeric segments, a
    vendor slug, or a date stamp."""
    from core.model_registry import _alias_spellings
    for bedrock_id, _direct_id, dotted in _BEDROCK_CURRENT:
        if dotted is None:
            assert _alias_spellings(bedrock_id) == [], (
                f"a single-number id ({bedrock_id}) must emit no aliases")
        else:
            assert _alias_spellings(bedrock_id) == [dotted], (
                f"the #434 dotted alias {dotted} must be the only alias "
                f"of {bedrock_id}")
