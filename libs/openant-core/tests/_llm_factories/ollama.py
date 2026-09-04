"""Scenario factory for the Ollama adapter contract tests.

Ollama speaks OpenAI's Chat Completions wire format through the same
``openai`` SDK, so the scripted fake-client behaviors are shared with
the OpenAI factory — this module reuses its scenario handlers verbatim
and only swaps the adapter under construction. What differs between
Ollama and the other providers (no real API key, default localhost
base_url, connection-refused → "ollama serve" hint, unpulled-model 404
mapping, empty-completion-with-tools guard) is covered by the dedicated
``tests/test_llm_ollama_adapter.py``.

See ``tests/test_llm_adapter_contract.py`` for the scenario catalogue.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import openai

from utilities.llm import LLMAdapter
from utilities.llm.providers.ollama import OllamaAdapter

from .openai import _SCENARIO_HANDLERS as SCENARIO_HANDLERS


def make_adapter(scenario: str) -> LLMAdapter:
    """Build an OllamaAdapter whose SDK is scripted for ``scenario``."""
    if scenario not in SCENARIO_HANDLERS:
        raise KeyError(f"Unknown scenario: {scenario!r}")

    handler = SCENARIO_HANDLERS[scenario]

    def side_effect(**kwargs: Any) -> Any:
        return handler(kwargs)

    fake_client = MagicMock(spec=openai.OpenAI)
    fake_client.chat = MagicMock()
    fake_client.chat.completions = MagicMock()
    fake_client.chat.completions.create = MagicMock(side_effect=side_effect)

    return OllamaAdapter(_client=fake_client)
