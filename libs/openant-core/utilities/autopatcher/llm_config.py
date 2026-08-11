"""Centralized LLM provider and model configuration.

Keep simple Python structures here so callers can dynamically build menus
without hardcoding values in `llm_client.py`.

IMPORTANT: `LLM_CONFIG["<provider>"]["models"]` below is INFORMATIONAL
ONLY -- it drives the interactive model menu and the non-interactive
default, nothing else. It is NOT a whitelist: `llm_client.call_llm()` does
NOT reject an explicitly requested model (via LLM_MODEL or the interactive
menu) merely because it is absent from this dict, marked "retired", or
unpriced in config/models.json. The provider itself is the sole authority
on whether a model can actually be used -- an unrecognized model is only
ever discovered by the live API call rejecting it (LLMNotFoundError), which
llm_client.py handles explicitly (ModelUnavailableError / interactive
reselection) rather than silently substituting a different model. See
llm_client.py's module docstring for the full rationale.
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
