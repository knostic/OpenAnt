"""OpenRouter adapter — implements :class:`LLMAdapter` via the OpenAI SDK.

OpenRouter (https://openrouter.ai) is a routing gateway that fronts many
model providers behind one OpenAI-compatible Chat Completions endpoint,
one API key, and one balance. Because the wire format is OpenAI's, this
adapter is a thin delegation layer over the OpenAI adapter's translation
helpers (``_messages_to_openai`` / ``_tool_to_openai`` /
``_response_to_unified`` / ``_token_param``) — the same
reuse-not-duplicate approach the docstrings in ``openai.py`` describe.
What it adds on top is exactly the OpenRouter-specific surface:

* **Endpoint + auth.** ``base_url`` defaults to
  ``https://openrouter.ai/api/v1`` (still overridable for
  OpenRouter-compatible gateways). ``api_key`` falls back to
  ``OPENROUTER_API_KEY`` — never the SDK's ``OPENAI_API_KEY``, which
  would silently send an OpenAI key to a third party.

* **Attribution headers.** ``HTTP-Referer`` / ``X-Title`` identify
  OpenAnt in OpenRouter's rankings, per their attribution docs.

* **Model IDs.** OpenRouter model IDs are ``vendor/model`` slugs with
  dotted versions (``anthropic/claude-sonnet-4.6``,
  ``openai/gpt-4o-mini``); the full catalogue is at
  https://openrouter.ai/models. IDs pass through verbatim.
  ``_token_param`` already strips the ``openai/`` prefix, so reasoning
  models routed through OpenRouter get ``max_completion_tokens``.

* **Error deltas** (verified against a live OpenRouter account,
  2026-08-01, except where noted):

  - An unknown model is a **400** ``"... is not a valid model ID"`` —
    not a 404 — so the generic OpenAI mapping would bury it in
    :class:`LLMResponseError`. It maps to :class:`LLMNotFoundError`
    here so the registry's init-time ``validate()`` reports it as the
    typo it is. (Live-verified.)
  - **402** means the account balance is exhausted; it maps to
    :class:`LLMAuthError` with a top-up hint — an account-level,
    won't-fix-itself condition, not a per-request one. (Per OpenRouter
    error docs; not reproducible on a funded account.)
  - **403** is OpenRouter's *moderation* signal — "your input was
    flagged" — which maps to :class:`LLMRefusalError` so a moderated
    scan prompt doesn't read as an auth problem (or worse, a clean
    pass). A 403 without moderation wording still maps to
    :class:`LLMAuthError` (key disabled, org restrictions). (Per
    OpenRouter error docs.)
  - A provider that fails **mid-generation** surfaces as a normal 200
    with ``finish_reason == "error"``; that raises
    :class:`LLMResponseError` instead of warn-and-normalise, because a
    truncated completion must not read as a finding-free pass. (Per
    OpenRouter docs.)

Rate limiting matches the OpenAI adapter: 429s report to the
process-global ``RateLimiter`` and every request waits on it first, so
one worker's backpressure slows the whole fan-out.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import openai

from ..adapter import (
    CompletionResult,
    LLMAuthError,
    LLMConnectionError,
    LLMNotFoundError,
    LLMRateLimitError,
    LLMRefusalError,
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
from .._pricing import LazyProviderPricing
from .._redact import redact_secrets, redacted_cause_from


_DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

# Optional attribution headers, per https://openrouter.ai/docs/app-attribution.
# They only affect OpenRouter's public app rankings — never routing or auth.
_ATTRIBUTION_HEADERS = {
    "HTTP-Referer": "https://github.com/knostic/OpenAnt",
    "X-Title": "OpenAnt",
}

# Live-verified fragment of OpenRouter's unknown-model 400 body:
#   {'error': {'message': '<slug> is not a valid model ID', 'code': 400}}
_INVALID_MODEL_MARKER = "not a valid model id"

# OpenRouter's 403 moderation errors carry wording like "your input was
# flagged" / "requires moderation" / "violates the content policy"; a 403
# without it is a real permission problem.
_MODERATION_MARKERS = ("moderation", "flagged", "content policy", "violat")

# A 403 that names the KEY/account (disabled, abuse, suspended, revoked) is an
# auth/permission problem, NOT content moderation — it must win over the
# moderation markers above, since "flagged for abuse" contains "flagged".
_KEY_DISABLED_MARKERS = ("abuse", "disabled", "suspended", "revoked", "banned")

_CREDITS_HINT = (
    " (HTTP 402 from OpenRouter means the account balance is exhausted — "
    "top up at https://openrouter.ai/settings/credits)"
)

_MODEL_ID_HINT = (
    " (OpenRouter model IDs are vendor/model slugs, e.g. "
    "anthropic/claude-sonnet-4.6 — browse them at "
    "https://openrouter.ai/models)"
)


def _classify_error(exc: Exception, *, report_429: bool) -> Exception:
    """Map an ``openai`` SDK exception to the adapter taxonomy.

    Shared by ``complete()`` and ``validate()``; only ``complete()``
    reports 429s to the global limiter (``report_429``), matching the
    reference adapters — a validate() probe shouldn't back off a scan.
    """
    message = redact_secrets(str(exc))
    lowered = message.lower()

    if isinstance(exc, openai.AuthenticationError):
        return LLMAuthError(message)
    if isinstance(exc, openai.PermissionDeniedError):
        # OpenRouter reserves 403 for input-moderation flags. A key/account
        # problem (disabled, flagged FOR ABUSE, suspended) is also a 403 but is
        # an auth issue — check that first so a dead key isn't reported as a
        # per-prompt content refusal. Fall back to auth when neither matches.
        if any(marker in lowered for marker in _KEY_DISABLED_MARKERS):
            return LLMAuthError(message)
        if any(marker in lowered for marker in _MODERATION_MARKERS):
            return LLMRefusalError(message)
        return LLMAuthError(message)
    if isinstance(exc, openai.RateLimitError):
        retry_after = _retry_after_from(exc)
        if report_429:
            report_rate_limit(retry_after)
        return LLMRateLimitError(message, retry_after=retry_after)
    if isinstance(exc, openai.NotFoundError):
        return LLMNotFoundError(message + _MODEL_ID_HINT)
    if isinstance(exc, openai.APIConnectionError):
        return LLMConnectionError(message)
    if isinstance(exc, openai.BadRequestError) and _INVALID_MODEL_MARKER in lowered:
        return LLMNotFoundError(message + _MODEL_ID_HINT)
    if getattr(exc, "status_code", None) == 402:
        return LLMAuthError(message + _CREDITS_HINT)
    # BadRequestError (other 400s), APIStatusError (5xx, anything else).
    return LLMResponseError(message)


def _raise_on_error_finish(response: Any) -> None:
    """Raise when OpenRouter reports a mid-generation provider failure.

    OpenRouter surfaces an upstream provider error inside an otherwise
    successful response as ``finish_reason == "error"`` — a value no
    direct provider uses. Warn-and-normalise (the shared helper's
    unknown-reason path) would let a truncated completion pass as
    ``end_turn``; for a security scan that's a silent false negative.
    """
    choices = getattr(response, "choices", None) or []
    if choices and getattr(choices[0], "finish_reason", None) == "error":
        raise LLMResponseError(
            "OpenRouterAdapter: the upstream provider errored "
            "mid-generation (finish_reason='error'); the completion is "
            "incomplete. Retry, or pick a different route/model."
        )


class OpenRouterAdapter:
    """:class:`LLMAdapter` implementation backed by OpenRouter's
    OpenAI-compatible endpoint via ``openai.OpenAI``."""

    name = "openrouter"
    supports_tools = True

    # Resolved lazily from config/models.json (the shared registry) on
    # first access; see utilities/llm/_pricing.py. Records mirror the
    # `current` models of the three direct providers, under OpenRouter's
    # vendor/model IDs.
    pricing = LazyProviderPricing("openrouter")

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 5,
        _client: Optional[openai.OpenAI] = None,
    ):
        """Construct the adapter.

        Args:
            api_key: OpenRouter API key (``sk-or-...``). When ``None``,
                falls back to ``OPENROUTER_API_KEY`` in the environment.
                Resolved eagerly so the SDK can never fall through to
                its own ``OPENAI_API_KEY`` default and quietly send an
                OpenAI key to OpenRouter.
            base_url: Override the endpoint. ``None`` means
                ``https://openrouter.ai/api/v1``.
            max_retries: Forwarded to the SDK (retries transient 429s
                and 5xx client-side).
            _client: Injected SDK instance for testing.
        """
        if _client is not None:
            self._client = _client
            return

        if api_key is None:
            api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise LLMAuthError(
                "OpenRouterAdapter: no API key. Set `api_key` on the "
                "provider entry in config.json or export "
                "OPENROUTER_API_KEY. Keys are created at "
                "https://openrouter.ai/settings/keys."
            )

        self._client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url if base_url is not None else _DEFAULT_BASE_URL,
            max_retries=max_retries,
            default_headers=_ATTRIBUTION_HEADERS,
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

        _raise_on_error_finish(response)
        return _response_to_unified(response, adapter="OpenRouterAdapter")

    def validate(self, model: str) -> None:
        try:
            self._client.chat.completions.create(**{
                "model": model,
                _token_param(model): 1,
                "messages": [{"role": "user", "content": "hi"}],
            })
        except openai.APIError as exc:
            raise _classify_error(exc, report_429=False) from redacted_cause_from(exc)
