"""AWS Bedrock adapter — Claude models via ``anthropic.AnthropicBedrock``.

Bedrock serves the same Claude models through the same Messages API and
the same ``anthropic`` SDK wire types as the direct Anthropic API, so
this adapter reuses the Anthropic adapter's translation layer wholesale
(content blocks, stop reasons, refusal handling — see
``providers/anthropic.py``). What differs is everything around the
transport:

* **Client:** ``anthropic.AnthropicBedrock`` instead of
  ``anthropic.Anthropic``. Same request/response types, same typed
  exception classes.
* **Credentials:** native AWS SigV4 via the standard AWS credential
  chain — ``AWS_ACCESS_KEY_ID``/``AWS_SECRET_ACCESS_KEY`` environment
  variables, or a ``~/.aws`` profile. The registry constructs every
  adapter as ``cls(api_key=..., base_url=...)`` (see
  ``registry.build_adapter``), and Bedrock has no API-key equivalent in
  the pinned SDK, so ``api_key`` is IGNORED here (with a one-time
  warning when set). This keeps the config schema and the Go CLI
  untouched.
* **Region:** resolved by the SDK — ``AWS_REGION`` /
  ``AWS_DEFAULT_REGION`` env vars, then the boto3 session
  (``~/.aws/config``, incl. profile region). Since anthropic 1.0 there
  is NO ``us-east-1`` fallback: an unresolvable region raises the
  SDK's ``ValueError``, mapped here to ``LLMAuthError`` with the fix
  spelled out. ``base_url`` is still honoured as a full endpoint
  override (VPC endpoints, internal gateways).
* **Model IDs are inference profiles:** prefixed ``us.`` / ``eu.`` /
  ``global.`` — e.g. ``us.anthropic.claude-sonnet-4-6`` or
  ``global.anthropic.claude-haiku-4-5-20251001-v1:0`` (the version
  suffix varies by model) — not bare Anthropic model names. A model
  that is not enabled for the
  account/region surfaces as an AccessDenied-flavoured 403 — mapped to
  ``LLMAuthError`` with a pointer at the Bedrock console's
  "Model access" page. A malformed model ID surfaces as a 400
  ValidationException — mapped to ``LLMNotFoundError`` (best-effort
  message sniff) so a typo'd profile ID fails validate() the same way
  a typo'd model fails on the other adapters.
* **Missing credentials:** the SDK raises a bare ``RuntimeError`` from
  its SigV4 signing path when the chain resolves nothing; mapped to
  ``LLMAuthError`` so scans fail with a typed, actionable message.
* **No 529:** Bedrock throttling arrives as 429-equivalents through the
  SDK's ``RateLimitError`` and is reported to the global rate limiter
  exactly like the reference adapter. Bedrock does not emit Anthropic's
  529 "overloaded", but the 529 branch is kept (it is harmless and
  ``base_url`` may point at an Anthropic-compat gateway that does).
"""

from __future__ import annotations

import sys
import threading
from typing import Any, Optional

import anthropic

from ._ratelimit import report_rate_limit, wait_for_rate_limit
from .anthropic import (
    _message_to_anthropic,
    _response_to_unified,
    _retry_after_from,
    _tool_to_anthropic,
)
from .._pricing import LazyProviderPricing
from .._redact import redact_secrets, redacted_cause_from
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


_MODEL_ACCESS_HINT = (
    " (Bedrock AccessDenied usually means this model is not enabled for "
    "the account in this region — request it under 'Model access' in the "
    "Bedrock console, and check AWS_REGION matches where access was granted)"
)

_NO_CREDENTIALS_MARKER = "could not resolve credentials"

# One-time warning when a config sets api_key on a bedrock provider.
# Silent-ignoring config a user explicitly wrote would violate the
# no-silent-drops rule the other adapters follow.
_api_key_warned = False
_api_key_warned_lock = threading.Lock()


def _warn_api_key_ignored() -> None:
    global _api_key_warned
    with _api_key_warned_lock:
        if _api_key_warned:
            return
        _api_key_warned = True
    sys.stderr.write(
        "warning: BedrockAdapter ignores `api_key` — Bedrock authenticates "
        "via the AWS credential chain (AWS_ACCESS_KEY_ID/"
        "AWS_SECRET_ACCESS_KEY env vars or ~/.aws profile). Remove "
        "`api_key` from the bedrock provider entry to silence this.\n"
    )


def reset_warnings() -> None:
    """Clear this adapter's one-time-warning memory (for tests / new scans)."""
    global _api_key_warned
    with _api_key_warned_lock:
        _api_key_warned = False


class BedrockAdapter:
    """:class:`LLMAdapter` implementation backed by ``anthropic.AnthropicBedrock``."""

    name = "bedrock"
    supports_tools = True

    # Per-million-token rates, resolved lazily from config/models.json.
    # Bedrock's Claude token prices match the direct Anthropic API; the
    # registry keys them by inference-profile ID (us.anthropic...,
    # eu.anthropic...) so cost tracking resolves without warnings.
    pricing = LazyProviderPricing("bedrock")

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 5,
        _client: Optional[anthropic.AnthropicBedrock] = None,
    ):
        """Construct the adapter.

        Args:
            api_key: IGNORED (one-time warning when set). Bedrock has no
                API-key auth in the pinned SDK; credentials come from
                the standard AWS chain. Accepted so the registry can
                construct every adapter with the same two kwargs.
            base_url: Full endpoint override (VPC endpoint, gateway).
                ``None`` means the SDK's regional default
                (bedrock-runtime.<region>.amazonaws.com).
            max_retries: Forwarded to the SDK. The SDK's built-in retry
                covers transient network blips; our rate limiter
                handles 429-coordinated backoff on top.
            _client: Injected SDK instance for testing. Production
                callers should not pass this.
        """
        if api_key is not None:
            _warn_api_key_ignored()
        if _client is not None:
            self._client = _client
            return

        kwargs: dict[str, Any] = {"max_retries": max_retries}
        if base_url is not None:
            kwargs["base_url"] = base_url
        # Deliberately no aws_* kwargs: region and credentials resolve
        # through the SDK's own chain (AWS_REGION / AWS_DEFAULT_REGION
        # env → boto3 session/profile region) so `openant` behaves
        # exactly like the aws CLI on the same machine. anthropic>=1.0
        # REMOVED the old warned us-east-1 fallback and raises a bare
        # ValueError when nothing resolves; map it to a typed,
        # actionable error instead of crashing adapter construction.
        try:
            self._client = anthropic.AnthropicBedrock(**kwargs)
        except ValueError as exc:
            raise LLMAuthError(
                f"Bedrock region could not be resolved: {exc}. "
                "Set AWS_REGION / AWS_DEFAULT_REGION or a region in your "
                "AWS profile (~/.aws/config)."
            ) from redacted_cause_from(exc)

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
        # supports_tools=True so we don't gate-check `tools` here —
        # the contract allows tools through.
        request: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [_message_to_anthropic(m) for m in messages],
        }
        if system is not None:
            request["system"] = system
        if tools:
            request["tools"] = [_tool_to_anthropic(t) for t in tools]

        # Cooperate with the cross-worker backoff before issuing the
        # call — same pattern as the other adapters (see _ratelimit.py).
        wait_for_rate_limit()

        try:
            response = self._client.messages.create(**request)
        except anthropic.AuthenticationError as exc:
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.PermissionDeniedError as exc:
            # On Bedrock a 403 is most often AccessDenied for a model
            # the account never enabled — auth-shaped, but the fix is
            # in the Bedrock console, so say so.
            raise LLMAuthError(
                redact_secrets(str(exc)) + _MODEL_ACCESS_HINT
            ) from redacted_cause_from(exc)
        except anthropic.RateLimitError as exc:
            # Bedrock throttling (ThrottlingException) rides the SDK's
            # 429 mapping; report it to the global limiter exactly like
            # the reference adapter so multi-worker scans coordinate.
            retry_after = _retry_after_from(exc)
            report_rate_limit(retry_after)
            raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
        except anthropic.NotFoundError as exc:
            raise LLMNotFoundError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.APIConnectionError as exc:
            raise LLMConnectionError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.APIStatusError as exc:
            raise _classify_status_error(exc, report_429=True) from redacted_cause_from(exc)
        except RuntimeError as exc:
            # The SDK's SigV4 signer raises a bare RuntimeError when the
            # AWS chain resolves no credentials at all. Surface it typed.
            if _NO_CREDENTIALS_MARKER in str(exc):
                raise LLMAuthError(_no_credentials_message(exc)) from redacted_cause_from(exc)
            raise

        return _response_to_unified(response, adapter="BedrockAdapter")

    def validate(self, model: str) -> None:
        # Cheapest valid request: 1-token cap, single "hi" message.
        # Probing the actual configured inference-profile ID catches
        # typo'd/unenabled profiles at init. Like the reference
        # adapter, validate() does not wait on the cross-worker
        # backoff — it is a one-shot probe at scan startup.
        try:
            self._client.messages.create(
                model=model,
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
        except anthropic.AuthenticationError as exc:
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.PermissionDeniedError as exc:
            raise LLMAuthError(
                redact_secrets(str(exc)) + _MODEL_ACCESS_HINT
            ) from redacted_cause_from(exc)
        except anthropic.RateLimitError as exc:
            retry_after = _retry_after_from(exc)
            raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
        except anthropic.NotFoundError as exc:
            raise LLMNotFoundError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.APIConnectionError as exc:
            raise LLMConnectionError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.APIStatusError as exc:
            raise _classify_status_error(exc, report_429=False) from redacted_cause_from(exc)
        except RuntimeError as exc:
            if _NO_CREDENTIALS_MARKER in str(exc):
                raise LLMAuthError(_no_credentials_message(exc)) from redacted_cause_from(exc)
            raise


# ----------------------------------------------------------------------
# Bedrock-specific error classification
# ----------------------------------------------------------------------


def _classify_status_error(exc: anthropic.APIStatusError, *, report_429: bool) -> Exception:
    """Map a residual APIStatusError to the adapter taxonomy.

    Returns (not raises) the mapped exception so callers keep their
    ``raise ... from`` chaining at the call site.
    """
    status = getattr(exc, "status_code", None)
    message = redact_secrets(str(exc))
    if status in (429, 529):
        # 429 is Bedrock's throttling status; 529 is the Anthropic-compat
        # "overloaded" a base_url gateway may send. A typed RateLimitError
        # is normally caught upstream in ``complete()``; this covers a 429
        # that arrives as a bare APIStatusError. Both are transient.
        retry_after = _retry_after_from(exc)
        if report_429:
            report_rate_limit(retry_after)
        return LLMRateLimitError(message, retry_after=retry_after)
    if status == 400 and "model identifier" in message.lower():
        # Bedrock reports a malformed/unknown model ID as a 400
        # ValidationException ("The provided model identifier is
        # invalid."), not a 404. Best-effort sniff so a typo'd
        # inference-profile ID fails like a typo'd model elsewhere.
        return LLMNotFoundError(
            message + " (Bedrock model IDs are inference profiles, e.g. "
            "us.anthropic.claude-sonnet-4-6 — list what is enabled with "
            "`aws bedrock list-inference-profiles`)"
        )
    # Everything else (other 400s, 422, 500, ...) is a structural
    # response problem from the pipeline's perspective.
    return LLMResponseError(message)


def _no_credentials_message(exc: RuntimeError) -> str:
    return (
        f"{redact_secrets(str(exc))} — the AWS credential chain resolved no "
        f"credentials. Export AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (and "
        f"AWS_REGION), or configure a ~/.aws profile; the bedrock adapter "
        f"does not use `api_key`."
    )
