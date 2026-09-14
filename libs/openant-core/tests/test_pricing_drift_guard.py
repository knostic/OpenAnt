"""Guard against MODEL_PRICING drifting from the adapter's table (PR #69 M9).

``utilities.llm_client.MODEL_PRICING`` is a legacy export that mirrors
``AnthropicAdapter.pricing``. Issue #65 made each adapter the source of
truth for its own rates; #598 deleted the ``pricing is None``
substitution fallbacks (record_call, report/generator) — the global now
serves only legacy importers and this guard. If the two ever disagree,
a legacy importer would report stale costs — so pin them together here.
Fix a failure by updating MODEL_PRICING to match the adapter.
"""

from __future__ import annotations

from utilities.llm.providers.anthropic import AnthropicAdapter
from utilities.llm_client import MODEL_PRICING
from utilities.model_config import CLAUDE_HAIKU, CLAUDE_OPUS, CLAUDE_SONNET


def test_model_pricing_matches_anthropic_adapter():
    assert MODEL_PRICING == AnthropicAdapter.pricing, (
        "MODEL_PRICING drifted from AnthropicAdapter.pricing — the adapter "
        "is the source of truth; update the legacy global to match (or remove it)."
    )


def test_model_pricing_is_nonempty_and_prices_current_models():
    # Post-registry-cutover both sides read pricing_map("anthropic"); a missing
    # config now fails LOUD rather than yielding {}. But pin positive content
    # anyway so this guard can never pass VACUOUSLY on two equal-but-empty maps
    # (`{} == {}` is not "no drift"). Every current Anthropic default must be
    # present with a positive input rate.
    assert MODEL_PRICING, "MODEL_PRICING resolved empty — registry cutover priced no models"
    for model in (CLAUDE_OPUS, CLAUDE_SONNET, CLAUDE_HAIKU):
        assert MODEL_PRICING.get(model, {}).get("input", 0) > 0, (
            f"{model} missing or zero-priced in MODEL_PRICING"
        )
