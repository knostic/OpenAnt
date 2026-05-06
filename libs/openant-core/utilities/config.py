"""
OpenAnt LLM configuration.

The Go CLI reads ~/.config/openant/config.json and injects settings as
environment variables before spawning the Python subprocess:

    ANTHROPIC_API_KEY       → API key (required by SDK, can be dummy for local AI)
    ANTHROPIC_BASE_URL      → LLM endpoint (e.g. http://localhost:8080)
    OPENANT_OPUS_MODEL      → Model name for heavy tasks (Stage 1, verify, report)
    OPENANT_SONNET_MODEL    → Model name for lighter tasks (enhance, consistency)

This module provides helpers that the rest of the Python codebase uses
instead of hardcoded model names and direct anthropic.Anthropic() calls.
"""

import os
from typing import Optional


# Default model names (Anthropic cloud)
_DEFAULT_OPUS = "claude-opus-4-6"
_DEFAULT_SONNET = "claude-sonnet-4-20250514"


def get_base_url() -> Optional[str]:
    """Return the LLM API base URL, or None for Anthropic's default."""
    return os.environ.get("ANTHROPIC_BASE_URL") or None


def get_api_key() -> Optional[str]:
    """Return the API key from environment."""
    return os.environ.get("ANTHROPIC_API_KEY") or None


def resolve_model(alias: str) -> str:
    """Resolve 'opus'/'sonnet' to an actual model ID.

    Reads OPENANT_OPUS_MODEL / OPENANT_SONNET_MODEL env vars (set by the
    Go CLI from config.json).  Falls back to Claude model names if not set.

    If *alias* is not 'opus' or 'sonnet', it is returned as-is (allows
    passing full model IDs directly).
    """
    if alias == "opus":
        return os.environ.get("OPENANT_OPUS_MODEL", _DEFAULT_OPUS)
    if alias == "sonnet":
        return os.environ.get("OPENANT_SONNET_MODEL", _DEFAULT_SONNET)
    return alias


def _should_verify_ssl() -> bool:
    """Check whether SSL verification is enabled.

    Reads OPENANT_VERIFY_SSL env var (set by Go CLI from config.json).
    Defaults to True (verify) unless explicitly set to 'false'.
    """
    val = os.environ.get("OPENANT_VERIFY_SSL", "true").lower()
    return val not in ("false", "0", "no")


def create_anthropic_client(**extra_kwargs):
    """Create an ``anthropic.Anthropic`` instance using config.

    Reads ANTHROPIC_BASE_URL and ANTHROPIC_API_KEY from the environment
    (injected by the Go CLI from config.json).  Use this everywhere instead
    of ``anthropic.Anthropic()`` directly.

    When a custom base_url is configured (local AI server), timeouts are
    extended to allow for model loading (llama-swap cold starts, etc.).
    SSL verification can be disabled via ``openant config set verify-ssl false``
    for servers with self-signed certificates.
    """
    import anthropic
    import httpx

    api_key = get_api_key()
    if not api_key:
        raise ValueError(
            "No API key found.  Run: openant config set api-key"
        )

    kwargs: dict = {"api_key": api_key}
    base_url = get_base_url()
    if base_url:
        kwargs["base_url"] = base_url
        # Local AI servers may need time to load models (cold start).
        # Default SDK connect timeout is 5s which is too short for
        # llama-swap model swapping.
        verify = _should_verify_ssl()
        kwargs["http_client"] = httpx.Client(
            verify=verify,
            timeout=httpx.Timeout(
                connect=300.0,   # 5 min for model loading / cold start
                read=600.0,      # 10 min for inference
                write=60.0,      # 1 min for sending request
                pool=120.0,      # 2 min for connection pool
            ),
        )
    kwargs.update(extra_kwargs)
    return anthropic.Anthropic(**kwargs)


def extract_text(response) -> str:
    """Extract the text content from an LLM response.

    Handles both standard models (content[0] is TextBlock) and thinking/
    reasoning models (content may start with ThinkingBlock(s) before the
    TextBlock).  Returns the first TextBlock's text, or empty string if
    no text block is found.
    """
    if not response.content:
        return ""
    for block in response.content:
        if getattr(block, "type", None) == "text":
            return block.text
    # Fallback: try the first block anyway
    return getattr(response.content[0], "text", "")
