"""Centralized LLM provider and model configuration.

Keep simple Python structures here so callers can dynamically build menus
and validate models without hardcoding values in `llm_client.py`.
"""

# Default max output tokens for LLM completions. Override per-run via the
# LLM_MAX_TOKENS environment variable (see llm_client._resolve_max_tokens).
DEFAULT_MAX_TOKENS = 4096

LLM_CONFIG = {
    "openai": {
        "default_model": "gpt-4o-mini",
        "models": {
            "gpt-4o-mini": {"label": "fast"},
            "gpt-4o": {"label": "strong"},
        },
    },
    "anthropic": {
        "default_model": "claude-haiku-4-5-20251001",
        "models": {
            "claude-haiku-4-5-20251001": {"label": "fast"},
            "claude-sonnet-4-6": {"label": "balanced"},
            "claude-opus-4-6": {"label": "strong"},
        },
    },
    "mock": {
        "default_model": "mock",
        "models": {"mock": {"label": "deterministic"}},
    },
}

# Backwards-compatible aliases for legacy model names
MODEL_ALIASES = {
    "claude-3-haiku": "claude-haiku-4-5-20251001",
    "claude-3-sonnet": "claude-sonnet-4-6",
}
