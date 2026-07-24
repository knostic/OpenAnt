"""Lazy, registry-backed pricing for provider adapters.

Each adapter exposes ``pricing`` — ``{model_id: {"input", "output"}}`` — as a
class attribute. Before the ``config/models.json`` cutover that attribute was a
dict-literal snapshot materialised at import from ``utilities/model_config``.
It now resolves ``core.model_registry.pricing_map(<provider>)`` on FIRST ACCESS,
not at import, via the :class:`LazyProviderPricing` descriptor below.

Two properties this descriptor must hold (see CHECKPOINT Item 9 invariants):

* **Lazy, never import-time.** Reading the registry (and its JSON file) happens
  only when ``Adapter.pricing`` is actually touched — so ``openant --help`` and
  any import path that never prices a call stays independent of the config file.
* **Fail-LOUD, never AttributeError.** A missing/empty config makes
  ``pricing_map`` raise ``RuntimeError`` (via ``require_models``). This descriptor
  lets that ``RuntimeError`` propagate unchanged. It must NEVER raise
  ``AttributeError`` from ``__get__``: ``helpers.lookup_pricing`` does
  ``getattr(adapter, "pricing", {})``, and ``getattr``'s default swallows only
  ``AttributeError`` — an AttributeError here would silently degrade fail-loud to
  ``{}`` -> ``$0`` (the trap flagged by the paired-fix review at helpers.py:33).

Deliberately NOT cached on the descriptor: ``model_registry._load_config`` is
already ``lru_cache``d, so ``pricing_map`` is cheap AND honours ``cache_clear()``
in tests that swap the config. Caching a copy here would instead pin a stale
table across such a swap. Nothing mutates ``Adapter.pricing`` (verified by grep),
so returning a fresh dict per access is safe.
"""

from __future__ import annotations

from typing import Any


class LazyProviderPricing:
    """Resolve ``pricing_map(provider)`` on class- and instance-level access.

    A non-data descriptor: ``AnthropicAdapter.pricing`` (``obj is None``, used by
    the drift guard) and ``adapter.pricing`` (instance, used by
    ``helpers.lookup_pricing``) both route through ``__get__``.
    """

    def __init__(self, provider: str) -> None:
        self._provider = provider

    def __get__(self, obj: Any, objtype: Any = None) -> dict[str, dict[str, float]]:
        # Imported inside __get__ so merely importing an adapter does not pull
        # core.model_registry (or read config/models.json) until pricing is
        # actually needed — that is the whole point of the laziness.
        from core.model_registry import pricing_map

        return pricing_map(self._provider)
