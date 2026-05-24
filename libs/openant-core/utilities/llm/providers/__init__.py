"""Provider plugins.

Each module in this package implements :class:`utilities.llm.LLMAdapter`
for one provider type. The registry (``utilities.llm.registry``) reads
config.json's ``llm_providers[*].type`` field to decide which class to
instantiate.

Adding a provider:

1. Drop ``yourprovider.py`` in this directory.
2. Export a class implementing ``LLMAdapter``.
3. Register it in :func:`get_adapter_class` below.
4. Make ``tests/test_llm_adapter_contract.py`` pass with your adapter
   as a parametrized case.

See ``docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md`` for the
full recipe.
"""

from __future__ import annotations

from typing import Type

from ..adapter import LLMAdapter


def get_adapter_class(provider_type: str) -> Type[LLMAdapter]:
    """Resolve ``llm_providers[*].type`` to a concrete adapter class.

    The lookup is deliberately a hardcoded switch (not entry-point
    discovery) so OSS contributors see the full provider list by
    grepping for ``get_adapter_class`` — no plugin magic to debug.
    """
    if provider_type == "anthropic":
        from .anthropic import AnthropicAdapter

        return AnthropicAdapter
    if provider_type == "openai":
        from .openai import OpenAIAdapter

        return OpenAIAdapter
    if provider_type == "google":
        from .google import GoogleAdapter

        return GoogleAdapter

    raise ValueError(
        f"Unknown provider type: {provider_type!r}. "
        f"Supported in this release: 'anthropic', 'openai', 'google'. "
        f"To add a provider, see "
        f"docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md."
    )


def known_provider_types() -> list[str]:
    """Names of provider types this build knows about.

    Used by the Go CLI's ``llm-provider set`` to validate the
    ``type`` field before writing config.json.
    """
    return ["anthropic", "openai", "google"]
