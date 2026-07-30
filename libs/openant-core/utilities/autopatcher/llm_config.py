"""Centralized LLM provider and model configuration.

Keep simple Python structures here so callers can dynamically build menus
and validate models without hardcoding values in `llm_client.py`.
"""

from ..model_config import (
    CLAUDE_3_HAIKU_LEGACY,
    CLAUDE_3_SONNET_LEGACY,
    CLAUDE_HAIKU,
    CLAUDE_OPUS_4_6,
    CLAUDE_SONNET,
    GPT_4O,
    GPT_4O_MINI,
)

# Default max output tokens for LLM completions. Override per-run via the
# LLM_MAX_TOKENS environment variable (see llm_client._resolve_max_tokens).
DEFAULT_MAX_TOKENS = 4096

LLM_CONFIG = {
    "openai": {
        "default_model": GPT_4O_MINI,
        "models": {
            GPT_4O_MINI: {"label": "fast"},
            GPT_4O: {"label": "strong"},
        },
    },
    "anthropic": {
        "default_model": CLAUDE_HAIKU,
        "models": {
            CLAUDE_HAIKU: {"label": "fast"},
            CLAUDE_SONNET: {"label": "balanced"},
            CLAUDE_OPUS_4_6: {"label": "strong"},
        },
    },
    "mock": {
        "default_model": "mock",
        "models": {"mock": {"label": "deterministic"}},
    },
}

# Backwards-compatible aliases for legacy model names
MODEL_ALIASES = {
    CLAUDE_3_HAIKU_LEGACY: CLAUDE_HAIKU,
    CLAUDE_3_SONNET_LEGACY: CLAUDE_SONNET,
}
