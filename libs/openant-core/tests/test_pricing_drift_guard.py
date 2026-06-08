"""Guard against MODEL_PRICING drifting from the adapter's table (PR #69 M9).

``utilities.llm_client.MODEL_PRICING`` is a legacy fallback that duplicates
``AnthropicAdapter.pricing``. Issue #65 made each adapter the source of
truth for its own rates, but the global is still read on the
``pricing is None`` fallback path (record_call, report/generator). If the
two ever disagree, the fallback would report stale costs — so pin them
together here. Fix a failure by updating MODEL_PRICING to match the
adapter (or deleting it once no call site relies on the fallback).
"""

from __future__ import annotations

from utilities.llm.providers.anthropic import AnthropicAdapter
from utilities.llm_client import MODEL_PRICING


def test_model_pricing_matches_anthropic_adapter():
    assert MODEL_PRICING == AnthropicAdapter.pricing, (
        "MODEL_PRICING drifted from AnthropicAdapter.pricing — the adapter "
        "is the source of truth; update the legacy global to match (or remove it)."
    )
