"""Ollama adapter — implements :class:`LLMAdapter` against a local Ollama server.

Ollama (https://ollama.com) serves open models locally behind an
OpenAI-compatible Chat Completions endpoint at ``http://localhost:11434/v1``.
Because the wire format is OpenAI's, this adapter is a thin delegation layer
over the OpenAI adapter's translation helpers (``_messages_to_openai`` /
``_tool_to_openai`` / ``_response_to_unified`` / ``_token_param``) — the same
reuse-not-duplicate approach the OpenRouter adapter takes. What it adds on
top is exactly the Ollama-specific surface:

* **No API key.** Ollama doesn't authenticate local requests. The adapter
  sends the literal placeholder ``"ollama"`` as the bearer token (the SDK
  requires a non-empty key; Ollama ignores it). There is deliberately NO
  environment-variable fallback: pointing OpenAnt at a *remote* Ollama or
  an Ollama-compatible gateway that DOES check keys is done via an explicit
  ``api_key`` in config.json, never by silently borrowing another
  provider's env credential.

* **Endpoint.** ``base_url`` defaults to ``http://localhost:11434/v1``
  (still overridable for a LAN/remote Ollama host). Like OpenRouter's,
  this base already carries the ``/v1`` segment.

* **Local = free.** Local inference costs nothing, so no pricing table is
  shipped: models absent from the shared registry report $0 via the
  documented "adapter without ``pricing``" path.

* **Error deltas** (verified against Ollama's OpenAI-compat docs and live
  server behavior, 2026-08):

  - Server not running / wrong port surfaces as ``APIConnectionError`` —
    mapped to :class:`LLMConnectionError` with a "start it with
    ``ollama serve``" hint, because "connection refused" on localhost is
    almost always a stopped daemon, not a network fault.
  - A model that isn't pulled is a **404** whose body says
    ``"model '<id>' not found, try pulling it first"`` — mapped to
    :class:`LLMNotFoundError` with an ``ollama pull`` hint so init-time
    validation reads as the fixable typo it is.

Tool-incapable models that ignore ``tools`` and return empty completions
are handled by the SHARED translator's empty-completion guard (raises
:class:`LLMResponseError`) — same path as every other OpenAI-wire
adapter; nothing Ollama-specific to add here.

Rate limiting matches the other adapters (local servers can still 429
under load); connection errors never touch the global limiter.
"""

from __future__ import annotations

from typing import Any, Optional

import openai

from ..adapter import (
    CompletionResult,
    LLMAuthError,
    LLMConnectionError,
    LLMNotFoundError,
    LLMRateLimitError,
    LLMResponseError,
    Message,
    ToolDef,
)
from ._ratelimit import report_rate_limit, wait_for_rate_limit
from .openai import (
    _messages_to_openai,
    _response_to_unified,
    _retry_after_from,
    _token_param,
    _tool_to_openai,
)
from .._redact import redact_secrets, redacted_cause_from


_DEFAULT_BASE_URL = "http://localhost:11434/v1"

# Ollama doesn't check Authorization headers on local requests, but the
# openai SDK requires a non-empty api_key. This placeholder is never a
# real credential.
_PLACEHOLDER_API_KEY = "ollama"

# Live-verified fragments of Ollama's 404 body for an unpulled model:
#   {"error":{"message":"model 'x' not found, try pulling it first","code":404}}
_NOT_PULLED_MARKERS = ("not found", "try pulling it")

_NOT_RUNNING_HINT = (
    " (could not reach the Ollama server — is it running? "
    "Start it with `ollama serve`, or set base_url in config.json for a "
    "non-default host/port)"
)

_PULL_HINT = (
    " (model not pulled into Ollama — run `ollama pull <model>`, or list "
    "installed models with `ollama list`)"
)


def _classify_error(exc: Exception, *, report_429: bool) -> Exception:
    """Map an ``openai`` SDK exception to the adapter taxonomy.

    Shared by ``complete()`` and ``validate()``; only ``complete()``
    reports 429s to the global limiter (``report_429``), matching the
    reference adapters.
    """
    message = redact_secrets(str(exc))
    lowered = message.lower()

    if isinstance(exc, openai.APIConnectionError):
        return LLMConnectionError(message + _NOT_RUNNING_HINT)
    if isinstance(exc, openai.RateLimitError):
        retry_after = _retry_after_from(exc)
        if report_429:
            report_rate_limit(retry_after)
        return LLMRateLimitError(message, retry_after=retry_after)
    if (
        isinstance(exc, openai.NotFoundError)
        or getattr(exc, "status_code", None) == 404
    ) and _is_not_pulled(lowered):
        return LLMNotFoundError(message + _PULL_HINT)
    if isinstance(exc, openai.NotFoundError):
        return LLMNotFoundError(message + _PULL_HINT)
    if isinstance(exc, (openai.AuthenticationError, openai.PermissionDeniedError)):
        # Only reachable against key-checking Ollama-compatible gateways;
        # stock Ollama never returns these.
        return LLMAuthError(message)
    # BadRequestError (other 400s), APIStatusError (5xx, anything else).
    return LLMResponseError(message)


def _is_not_pulled(lowered_message: str) -> bool:
    return all(marker in lowered_message for marker in _NOT_PULLED_MARKERS)


class OllamaAdapter:
    """:class:`LLMAdapter` implementation backed by a local Ollama server's
    OpenAI-compatible endpoint via ``openai.OpenAI``."""

    name = "ollama"
    supports_tools = True

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 2,
        _client: Optional[openai.OpenAI] = None,
    ):
        """Construct the adapter.

        Args:
            api_key: Ignored by stock Ollama. Only needed when targeting a
                key-checking Ollama-compatible gateway; defaults to a
                placeholder. Deliberately does NOT read any environment
                variable — no silent cross-provider credential reuse.
            base_url: Override the endpoint. ``None`` means
                ``http://localhost:11434/v1``.
            max_retries: Forwarded to the SDK (kept low — a down local
                server should fail fast, not retry-stall a scan).
            _client: Injected SDK instance for testing.
        """
        if _client is not None:
            self._client = _client
            return

        self._client = openai.OpenAI(
            api_key=api_key if api_key else _PLACEHOLDER_API_KEY,
            base_url=base_url if base_url is not None else _DEFAULT_BASE_URL,
            max_retries=max_retries,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def complete(
        self,
        *,
        model: str,
        system: Optional[str],
        messages: list[Message],
        max_tokens: int,
        tools: Optional[list[ToolDef]] = None,
    ) -> CompletionResult:
        request: dict[str, Any] = {
            "model": model,
            _token_param(model): max_tokens,
            "messages": _messages_to_openai(messages, system, model),
        }
        if tools:
            request["tools"] = [_tool_to_openai(t) for t in tools]

        # Cooperate with cross-worker backoff before issuing the call.
        wait_for_rate_limit()

        try:
            response = self._client.chat.completions.create(**request)
        except openai.APIError as exc:
            raise _classify_error(exc, report_429=True) from redacted_cause_from(exc)

        # NOTE: no adapter-level empty-completion guard here. The shared
        # ``_response_to_unified`` translator already raises
        # :class:`LLMResponseError` when a completion carries neither text
        # nor tool calls, so a tool-incapable small model that silently
        # ignores ``tools`` fails loud through the same path every other
        # OpenAI-wire adapter uses.
        return _response_to_unified(response, adapter="OllamaAdapter")

    def validate(self, model: str) -> None:
        try:
            response = self._client.chat.completions.create(**{
                "model": model,
                _token_param(model): 1,
                "messages": [{"role": "user", "content": "hi"}],
            })
        except openai.APIError as exc:
            raise _classify_error(exc, report_429=False) from redacted_cause_from(exc)

        choices = getattr(response, "choices", None) or []
        if not choices:
            raise LLMResponseError(
                f"OllamaAdapter: probe against {model!r} returned no choices"
            )
        # Touch the text so linters/type-checkers see the shape used; the
        # contract only requires success/failure signaling here.
        _ = getattr(choices[0].message, "content", None) or ""
