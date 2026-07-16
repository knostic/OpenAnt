"""Canonical model-ID constants and per-provider pricing tables.

Single source of truth for every hard-coded model-ID string that used
to be duplicated across the product source:

* ``utilities/llm_client.py`` (``MODEL_PRICING``)
* ``utilities/context_enhancer.py`` (``CONTEXT_ENHANCEMENT_MODEL_LEGACY``)
* ``utilities/llm/builtins.py`` (``OPENANT_DEFAULT`` per-phase models)
* ``utilities/llm/providers/anthropic.py`` (``AnthropicAdapter.pricing``)
* ``utilities/llm/providers/google.py`` (``GoogleAdapter.pricing``)
* ``utilities/llm/providers/openai.py`` (``OpenAIAdapter.pricing``)

Those modules now import the constants and pricing maps below instead of
re-typing the literals. If a provider deprecates a model ID, or a price
changes, this file is the single place to edit.

This module is intentionally dependency-free (pure literals, no imports
from the rest of the package) so any module — including
``utilities/llm_client.py``, which the ``utilities.llm`` package imports
transitively — can import it without risking a circular import.
"""

from __future__ import annotations

# --- Anthropic (Claude) model IDs ------------------------------------
# Current IDs (must match utilities/llm/builtins.py OPENANT_DEFAULT).
CLAUDE_OPUS = "claude-opus-4-8"
CLAUDE_SONNET = "claude-sonnet-4-6"
CLAUDE_HAIKU = "claude-haiku-4-5-20251001"
# Retired IDs kept for historical reports / back-compat.
CLAUDE_OPUS_4_20250514 = "claude-opus-4-20250514"
CLAUDE_OPUS_4_6 = "claude-opus-4-6"
CLAUDE_SONNET_4_20250514 = "claude-sonnet-4-20250514"

# --- OpenAI model IDs -------------------------------------------------
GPT_4O = "gpt-4o"
GPT_4O_MINI = "gpt-4o-mini"
GPT_4_1 = "gpt-4.1"
GPT_4_1_MINI = "gpt-4.1-mini"
GPT_4_1_NANO = "gpt-4.1-nano"
O1 = "o1"
O3 = "o3"
O3_MINI = "o3-mini"
O4_MINI = "o4-mini"

# --- Google (Gemini) model IDs ---------------------------------------
GEMINI_2_5_PRO = "gemini-2.5-pro"
GEMINI_2_5_FLASH = "gemini-2.5-flash"
GEMINI_2_5_FLASH_LITE = "gemini-2.5-flash-lite"
GEMINI_2_0_FLASH = "gemini-2.0-flash"
GEMINI_2_0_FLASH_LITE = "gemini-2.0-flash-lite"
GEMINI_1_5_PRO = "gemini-1.5-pro"
GEMINI_1_5_FLASH = "gemini-1.5-flash"


# --- Per-provider pricing (USD per 1M tokens) ------------------------
# Authoritative rates each adapter ships with. Consumers reference these
# maps directly so the legacy ``MODEL_PRICING`` global in
# ``utilities/llm_client.py`` can never drift from the adapter table
# (see tests/test_pricing_drift_guard.py).
ANTHROPIC_PRICING: dict[str, dict[str, float]] = {
    # Current model IDs (must match utilities/llm/builtins.py OPENANT_DEFAULT).
    CLAUDE_OPUS: {"input": 15.00, "output": 75.00},
    CLAUDE_SONNET: {"input": 3.00, "output": 15.00},
    CLAUDE_HAIKU: {"input": 1.00, "output": 5.00},
    # Retired IDs kept for historical reports / back-compat.
    CLAUDE_OPUS_4_20250514: {"input": 15.00, "output": 75.00},
    CLAUDE_OPUS_4_6: {"input": 15.00, "output": 75.00},
    CLAUDE_SONNET_4_20250514: {"input": 3.00, "output": 15.00},
}

OPENAI_PRICING: dict[str, dict[str, float]] = {
    GPT_4O: {"input": 2.50, "output": 10.00},
    GPT_4O_MINI: {"input": 0.15, "output": 0.60},
    GPT_4_1: {"input": 2.00, "output": 8.00},
    GPT_4_1_MINI: {"input": 0.40, "output": 1.60},
    GPT_4_1_NANO: {"input": 0.10, "output": 0.40},
    O1: {"input": 15.00, "output": 60.00},
    O3: {"input": 2.00, "output": 8.00},
    O3_MINI: {"input": 1.10, "output": 4.40},
    O4_MINI: {"input": 1.10, "output": 4.40},
}

GOOGLE_PRICING: dict[str, dict[str, float]] = {
    GEMINI_2_5_PRO: {"input": 1.25, "output": 10.00},
    GEMINI_2_5_FLASH: {"input": 0.30, "output": 2.50},
    GEMINI_2_5_FLASH_LITE: {"input": 0.10, "output": 0.40},
    GEMINI_2_0_FLASH: {"input": 0.10, "output": 0.40},
    GEMINI_2_0_FLASH_LITE: {"input": 0.075, "output": 0.30},
    GEMINI_1_5_PRO: {"input": 1.25, "output": 5.00},
    GEMINI_1_5_FLASH: {"input": 0.075, "output": 0.30},
}
