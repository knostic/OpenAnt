"""Structural tests for the shared provider-model registry (config/models.json).

These replace the old ``test_builtin_model_ids_current.py``, which baked an
eternal, un-provenanced ``DEAD_MODEL_IDS`` set. The rule is: assert the SHAPE and
internal consistency of the registry, and that configured defaults resolve to a
non-retired entry — never that a specific id is alive or dead. Provenance
(``source`` + ``retrieved``) lives in the data, not in a test literal.

Freshness is deliberately NOT asserted by recency: a ``retrieved <= today`` check
needs the wall clock and is either flaky (fails as time passes) or a tautology.
So ``retrieved`` is required and format-validated only; staleness is an
operational/CI concern.
"""

from __future__ import annotations

import re
from datetime import date

import pytest

from core import model_registry as mr

_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@pytest.fixture(autouse=True)
def _fresh_cache():
    mr._load_config.cache_clear()
    yield
    mr._load_config.cache_clear()


def test_config_parses_and_models_is_a_list():
    models = mr.load_models()
    assert isinstance(models, list) and models, "models.json missing or empty"


def test_every_record_has_the_required_shape():
    for rec in mr.load_models():
        for field in ("id", "provider", "status", "price", "source", "retrieved"):
            assert field in rec, f"{rec.get('id')!r} missing {field!r}"
        assert rec["provider"] in mr._VALID_PROVIDERS, rec
        assert rec["status"] in mr._VALID_STATUS, rec
        # Provenance must be non-empty, or "status" is just an un-provenanced
        # assertion relocated from source into data.
        assert rec["source"].strip(), f"{rec['id']}: empty source"
        assert _ISO.match(rec["retrieved"]), f"{rec['id']}: bad retrieved {rec['retrieved']!r}"
        # retrieved must be a real, non-future date (a bound, not a recency window).
        assert date.fromisoformat(rec["retrieved"]) <= date.today(), (
            f"{rec['id']}: retrieved is in the future")


def test_model_ids_are_unique():
    ids = [r["id"] for r in mr.load_models()]
    dupes = {i for i in ids if ids.count(i) > 1}
    assert not dupes, f"duplicate model ids: {dupes}"


def test_price_nullness_matches_status():
    """current => real positive price; retired/unknown => null (never $0).

    This is the invariant the cost path depends on: a priced model is dispatchable
    and costs real money; an un-priced model must be omitted from pricing_map so it
    can never resolve to a silent $0.
    """
    for rec in mr.load_models():
        price = rec["price"]
        if rec["status"] == "current":
            assert price and price["input"] > 0 and price["output"] > 0, (
                f"{rec['id']}: current model must carry a positive price")
        else:
            assert price is None, (
                f"{rec['id']}: {rec['status']} model must have null price, not {price}")


def test_pricing_map_omits_null_priced_models():
    """A null-priced (retired/unknown) model is ABSENT from the map, not $0."""
    anthropic = mr.pricing_map("anthropic")
    assert anthropic["claude-opus-4-8"]["input"] > 0
    for retired in ("claude-opus-4-6", "claude-sonnet-4-20250514", "claude-opus-4-20250514"):
        assert retired not in anthropic, (
            f"{retired} is null-priced and must be omitted from pricing_map, "
            f"never emitted as a zero dict")


def test_configured_default_phase_models_resolve_to_non_retired():
    """The structural replacement for the eternal DEAD_MODEL_IDS list.

    A fresh, config-less install must not resolve its default phases to a retired
    model (that 404s every scan). Asserted WITHOUT naming which ids are dead:
    each default phase model must resolve to a registry entry whose status is not
    'retired'. Legacy constants (context_enhancer) are intentionally out of scope.
    """
    from utilities.llm.builtins import OPENANT_DEFAULT

    for phase, ref in OPENANT_DEFAULT.phases.items():
        rec = mr.find_model(ref.model)
        assert rec is not None, f"phase {phase!r} model {ref.model!r} not in registry"
        assert rec["status"] != "retired", (
            f"phase {phase!r} default {ref.model!r} resolves to a RETIRED model")
