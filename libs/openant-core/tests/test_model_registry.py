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
    """current => real positive price (cloud) or explicit $0 (local); retired/unknown => null.

    This is the invariant the cost path depends on: a priced model is dispatchable
    and costs real money; an un-priced model must be omitted from pricing_map so it
    can never resolve to a silent $0. Local-inference providers
    (``mr._LOCAL_PROVIDERS``) are the deliberate exception: their $0 is truthful
    and provenanced ("free by definition"), so a current local model must carry
    an EXPLICIT zero dict — never null (which would omit it from pricing_map and
    route it to the unknown-model warn path) and never an unverified vendor quote.
    """
    for rec in mr.load_models():
        price = rec["price"]
        if rec["status"] == "current":
            if rec["provider"] in mr._LOCAL_PROVIDERS:
                assert price and price["input"] == 0.0 and price["output"] == 0.0, (
                    f"{rec['id']}: local model must carry an explicit $0 price, not {price}")
            else:
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


def test_context_window_tokens_none_for_every_current_model():
    """Fix B: the ``context_window_tokens`` field ships unpopulated for
    every model today (schema only, no data population this release --
    see technical_capacity.py's own docstring) -- every current model
    must resolve to ``None`` here, routing callers to the one documented
    conservative fallback rather than a per-model guess."""
    for rec in mr.load_models():
        if rec.get("status") != "current":
            continue
        assert mr.context_window_tokens(rec["provider"], rec["id"]) is None


def test_context_window_tokens_unknown_model_and_provider_return_none():
    assert mr.context_window_tokens("anthropic", "does-not-exist-model") is None
    assert mr.context_window_tokens("does-not-exist-provider", "claude-opus-4-8") is None


def test_context_window_tokens_reads_populated_field(tmp_path, monkeypatch):
    """Schema/runtime-semantics check: when a record DOES carry
    ``context_window_tokens``, the accessor returns it verbatim -- mirrors
    ``max_output_tokens``'s own already-established alias-resolution
    contract exactly (bare/vendor-prefixed/dotted/dashed spellings)."""
    fake_config = tmp_path / "models.json"
    fake_config.write_text(
        '{"models": [{"id": "acme-model-1-0", "provider": "anthropic", '
        '"status": "current", "price": {"input": 1.0, "output": 2.0}, '
        '"context_window_tokens": 123456, "source": "test", "retrieved": "2026-01-01"}]}',
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENANT_MODELS_CONFIG", str(fake_config))
    mr._load_config.cache_clear()
    try:
        assert mr.context_window_tokens("anthropic", "acme-model-1-0") == 123456
        # Alias-tolerant: dashed <-> dotted version spelling.
        assert mr.context_window_tokens("anthropic", "acme-model-1.0") == 123456
    finally:
        mr._load_config.cache_clear()


def test_configured_default_phase_models_are_current():
    """Defaults must be CURRENT, not merely non-retired.

    Preserves the intent of the deleted ``test_default_registry_uses_current_ids``
    (a fresh install's default phases use live, priced models) WITHOUT naming
    which ids are blessed — a default resolving to an 'unknown'-status model would
    price at $0 with a warning, which is not a state a shipped default should be in.
    """
    from utilities.llm.builtins import OPENANT_DEFAULT

    for phase, ref in OPENANT_DEFAULT.phases.items():
        assert mr.model_status(ref.model) == "current", (
            f"phase {phase!r} default {ref.model!r} is not a 'current' model")
