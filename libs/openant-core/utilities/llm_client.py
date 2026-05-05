"""
Anthropic LLM Client

Wrapper for Claude API calls with built-in token tracking and cost calculation.

Classes:
    TokenTracker: Tracks token usage and costs across multiple LLM calls
    AnthropicClient: Synchronous Claude API client with automatic token tracking

Usage:
    from utilities.llm_client import AnthropicClient, get_global_tracker

    client = AnthropicClient(model="claude-opus-4-20250514")
    response = client.analyze_sync("Analyze this code...")

    tracker = get_global_tracker()
    print(f"Total cost: ${tracker.total_cost_usd:.4f}")

OpenRouter / non-Claude models:
    Set OPENANT_LLM_BASE_URL and OPENANT_LLM_API_KEY to route every
    anthropic.Anthropic(...) construction through a different endpoint
    (e.g. https://openrouter.ai/api/v1). Use a slash-form --model value
    (qwen/qwen-3-coder-480b) or the OpenCode-style openrouter/ prefix
    (openrouter/moonshotai/kimi-k2 -> moonshotai/kimi-k2).
"""

import json
import os
import sys
import threading
from typing import Optional
import anthropic
from dotenv import load_dotenv

from .rate_limiter import get_rate_limiter


# Pricing per million tokens (as of December 2024)
MODEL_PRICING = {
    "claude-opus-4-6": {"input": 15.00, "output": 75.00},
    "claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    # Fallback for unknown models (use Sonnet pricing as conservative estimate)
    "default": {"input": 3.00, "output": 15.00}
}


# Model aliases used by --model on the CLI. Anything not in this map and
# without a "/" is left as-is so future Claude IDs keep working.
MODEL_ALIASES = {
    "opus": "claude-opus-4-6",
    "sonnet": "claude-sonnet-4-20250514",
}


def resolve_model_id(value: str) -> str:
    """Resolve a --model argument to the literal ID sent to the API.

    Rules:
        - "opus" / "sonnet" -> their canonical Claude IDs.
        - A value containing "/" is passed through verbatim, with one
          exception: a leading "openrouter/" prefix is stripped so that
          OpenCode-style IDs like "openrouter/moonshotai/kimi-k2" work
          out of the box (they become "moonshotai/kimi-k2"). See issue #9.
        - Anything else is returned unchanged so explicit Claude IDs
          (e.g. "claude-opus-4-6") still work.
    """
    if not value:
        return value
    if value in MODEL_ALIASES:
        return MODEL_ALIASES[value]
    if "/" in value:
        if value.startswith("openrouter/"):
            return value[len("openrouter/"):]
        return value
    return value


_unknown_model_warned: set[str] = set()
_unknown_model_lock = threading.Lock()


def _warn_unknown_model_once(model: str) -> None:
    """Warn at most once per process for each unpriced model ID."""
    with _unknown_model_lock:
        if model in _unknown_model_warned:
            return
        _unknown_model_warned.add(model)
    print(
        f"[llm_client] No pricing entry for model '{model}'; cost rollups "
        f"for this model will report $0.00. Set MODEL_PRICING_OVERRIDE to "
        f"add it (see README).",
        file=sys.stderr,
    )


def _load_pricing_override() -> dict:
    """Parse MODEL_PRICING_OVERRIDE, returning {} on error."""
    raw = os.environ.get("MODEL_PRICING_OVERRIDE")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError) as exc:
        print(
            f"[llm_client] Could not parse MODEL_PRICING_OVERRIDE as JSON: {exc}",
            file=sys.stderr,
        )
        return {}
    if not isinstance(parsed, dict):
        print(
            "[llm_client] MODEL_PRICING_OVERRIDE must be a JSON object "
            "of {model_id: {input, output}}; ignoring.",
            file=sys.stderr,
        )
        return {}
    return parsed


def get_pricing(model: str) -> dict:
    """Return pricing for a model, honouring MODEL_PRICING_OVERRIDE.

    Override values take precedence over the built-in table. Unknown
    models default to {input: 0, output: 0} and emit a one-time warning.
    """
    override = _load_pricing_override()
    if model in override:
        return override[model]
    if model in MODEL_PRICING:
        return MODEL_PRICING[model]
    _warn_unknown_model_once(model)
    return {"input": 0.0, "output": 0.0}


def get_anthropic_client(**kwargs) -> "anthropic.Anthropic":
    """Construct an anthropic.Anthropic() honouring OPENANT_LLM_* env vars.

    When OPENANT_LLM_BASE_URL is set, the SDK is pointed at that endpoint
    (typically OpenRouter or a self-hosted Anthropic-compatible proxy).
    When OPENANT_LLM_API_KEY is set, that key is used in place of
    ANTHROPIC_API_KEY. Both fall through to the SDK's normal env handling
    when unset, so existing setups behave identically.

    Any kwargs (e.g. max_retries=5, api_key=...) are forwarded; explicit
    kwargs take precedence over the env var fallbacks.
    """
    base_url = os.environ.get("OPENANT_LLM_BASE_URL")
    api_key = os.environ.get("OPENANT_LLM_API_KEY")

    if base_url and "base_url" not in kwargs:
        kwargs["base_url"] = base_url
    if api_key and "api_key" not in kwargs:
        kwargs["api_key"] = api_key

    return anthropic.Anthropic(**kwargs)


class TokenTracker:
    """
    Tracks token usage and costs across LLM calls.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._thread_local = threading.local()
        self.reset()

    def reset(self):
        """Reset all counters."""
        with self._lock:
            self.calls = []
            self.total_input_tokens = 0
            self.total_output_tokens = 0
            self.total_cost_usd = 0.0

    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output)."""
        return self.total_input_tokens + self.total_output_tokens

    def record_call(self, model: str, input_tokens: int, output_tokens: int) -> dict:
        """
        Record a single LLM call.

        Args:
            model: Model identifier
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens

        Returns:
            Dict with call details including cost
        """
        # Get pricing for model. get_pricing() honours MODEL_PRICING_OVERRIDE
        # and falls back to {input: 0, output: 0} for unknown models with a
        # one-time warning, rather than silently estimating with Sonnet rates.
        pricing = get_pricing(model)

        # Calculate cost (pricing is per million tokens)
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        total_cost = input_cost + output_cost

        call_record = {
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round(total_cost, 6)
        }

        # Update totals (thread-safe)
        with self._lock:
            self.calls.append(call_record)
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += total_cost

        # Accumulate to thread-local unit tracking if active
        tl = self._thread_local
        if hasattr(tl, "unit_input"):
            tl.unit_input += input_tokens
            tl.unit_output += output_tokens
            tl.unit_cost += total_cost

        return call_record

    def add_prior_usage(self, input_tokens: int, output_tokens: int, cost_usd: float):
        """Inject usage from a prior run (e.g. restored checkpoints).

        This ensures step reports capture the total cost across all runs,
        not just the current run's API calls.
        """
        with self._lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += cost_usd

    def start_unit_tracking(self):
        """Start tracking usage for the current unit on this thread.

        Call before processing a unit, then call ``get_unit_usage()``
        after to get the accumulated usage for just that unit. Thread-safe
        because each thread has its own ``threading.local()`` storage.
        """
        tl = self._thread_local
        tl.unit_input = 0
        tl.unit_output = 0
        tl.unit_cost = 0.0

    def get_unit_usage(self) -> dict:
        """Return usage accumulated since ``start_unit_tracking()`` on this thread."""
        tl = self._thread_local
        return {
            "input_tokens": getattr(tl, "unit_input", 0),
            "output_tokens": getattr(tl, "unit_output", 0),
            "cost_usd": round(getattr(tl, "unit_cost", 0.0), 6),
        }

    def get_summary(self) -> dict:
        """
        Get summary of all tracked calls.

        Returns:
            Dict with totals and per-call breakdown
        """
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                "calls": list(self.calls),
            }

    def get_totals(self) -> dict:
        """
        Get just the totals (without per-call breakdown).

        Returns:
            Dict with totals only
        """
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
            }


# Global tracker instance for session-wide tracking
_global_tracker = TokenTracker()


def get_global_tracker() -> TokenTracker:
    """Get the global token tracker instance."""
    return _global_tracker


def reset_global_tracker():
    """Reset the global token tracker."""
    _global_tracker.reset()


class AnthropicClient:
    """
    Client for Anthropic Claude API.

    Uses Claude Opus 4 for vulnerability analysis.
    Tracks token usage and costs for all calls.
    """

    def __init__(self, model: str = "claude-opus-4-20250514", tracker: TokenTracker = None):
        """
        Initialize the Anthropic client.

        Args:
            model: Model identifier. Default is Claude Opus 4 (highest capability).
                   Use "claude-sonnet-4-20250514" for cost-effective option.
            tracker: Optional TokenTracker instance. Uses global tracker if not provided.
        """
        load_dotenv()

        # Either the OpenRouter override or ANTHROPIC_API_KEY must be set.
        if not os.getenv("OPENANT_LLM_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
            raise ValueError(
                "No API key found. Set ANTHROPIC_API_KEY, or for non-Claude "
                "providers set OPENANT_LLM_API_KEY (and OPENANT_LLM_BASE_URL)."
            )

        self.client = get_anthropic_client(max_retries=5)
        self.model = model
        self.tracker = tracker or _global_tracker
        self.last_call = None  # Store last call details

    async def analyze(self, prompt: str, max_tokens: int = 8192) -> str:
        """
        Send a prompt to Claude and get a response.

        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response

        Returns:
            Response text from Claude
        """
        # Wait if we're in a global backoff period
        rate_limiter = get_rate_limiter()
        rate_limiter.wait_if_needed()

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
        except anthropic.RateLimitError as exc:
            # Report to global rate limiter so all workers back off
            retry_after = float(exc.response.headers.get("retry-after", 0))
            get_rate_limiter().report_rate_limit(retry_after)
            raise

        # Track token usage
        self.last_call = self.tracker.record_call(
            model=self.model,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens
        )

        return message.content[0].text

    def analyze_sync(self, prompt: str, max_tokens: int = 8192, model: str = None, system: str = None) -> str:
        """
        Synchronous version of analyze.

        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response
            model: Optional model override (uses instance model if not specified)
            system: Optional system prompt for context/instructions

        Returns:
            Response text from Claude
        """
        used_model = model or self.model

        kwargs = {
            "model": used_model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        if system:
            kwargs["system"] = system

        # Wait if we're in a global backoff period
        rate_limiter = get_rate_limiter()
        rate_limiter.wait_if_needed()

        try:
            message = self.client.messages.create(**kwargs)
        except anthropic.RateLimitError as exc:
            # Report to global rate limiter so all workers back off
            retry_after = float(exc.response.headers.get("retry-after", 0))
            get_rate_limiter().report_rate_limit(retry_after)
            raise

        # Track token usage
        self.last_call = self.tracker.record_call(
            model=used_model,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens
        )

        return message.content[0].text

    def get_last_call(self) -> Optional[dict]:
        """
        Get details of the last API call.

        Returns:
            Dict with model, input_tokens, output_tokens, cost_usd
        """
        return self.last_call

    def get_session_totals(self) -> dict:
        """
        Get cumulative totals for this session.

        Returns:
            Dict with total_calls, total_input_tokens, total_output_tokens, total_cost_usd
        """
        return self.tracker.get_totals()

    def get_session_summary(self) -> dict:
        """
        Get full summary including per-call breakdown.

        Returns:
            Dict with totals and calls list
        """
        return self.tracker.get_summary()

    def get_usage(self, message) -> dict:
        """
        Extract token usage from a message response.

        Args:
            message: Response from messages.create()

        Returns:
            Dict with input_tokens, output_tokens
        """
        return {
            "input_tokens": message.usage.input_tokens,
            "output_tokens": message.usage.output_tokens
        }
