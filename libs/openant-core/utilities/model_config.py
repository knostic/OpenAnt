"""Canonical model-ID constants.

Single source of truth for the hard-coded model-ID *strings* used across the
product source — e.g. ``utilities/llm/builtins.py``'s ``OPENANT_DEFAULT``
per-phase models and ``utilities/context_enhancer.py``'s
``CONTEXT_ENHANCEMENT_MODEL_LEGACY``.

**Pricing no longer lives here.** Per-provider pricing moved to the shared
``config/models.json`` registry, read by ``core/model_registry.py`` (Python) and
``apps/openant-cli/internal/models`` (Go). The adapters' ``pricing``,
``utilities/llm_client.MODEL_PRICING`` and the report generator now resolve rates
lazily from ``core.model_registry.pricing_map(<provider>)`` — retired/unknown ids
are omitted there so they can never price at a silent \\$0. The model-ID constants
remain here as the irreducible compile-time defaults, VALIDATED against the
registry (``tests/test_model_registry.py``) rather than being unchecked assertions.

This module is intentionally dependency-free (pure literals, no imports from the
rest of the package) so any module — including ``utilities/llm_client.py``, which
the ``utilities.llm`` package imports transitively — can import it without risking
a circular import.
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
# Older (pre-4.x) generation names still accepted as legacy CLI/env aliases.
CLAUDE_3_HAIKU_LEGACY = "claude-3-haiku"
CLAUDE_3_SONNET_LEGACY = "claude-3-sonnet"

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
