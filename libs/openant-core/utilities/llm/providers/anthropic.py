"""Anthropic adapter — reference implementation of :class:`LLMAdapter`.

This is the only adapter that ships with OpenAnt's open-source release.
It implements the full ``LLMAdapter`` contract against Anthropic's
``anthropic`` Python SDK, and supports tool calling for the agentic
``enhance`` and ``verify`` phases.

Translation details:

* **Unified blocks → Anthropic content:** ``TextBlock`` becomes
  ``{"type": "text", "text": ...}``, ``ToolUseBlock`` becomes
  ``{"type": "tool_use", ...}``, ``ToolResultBlock`` becomes
  ``{"type": "tool_result", "tool_use_id": ..., "content": ...}``.
* **Anthropic content → unified blocks:** the response's
  ``content`` is a list of ``TextBlock``-like and
  ``ToolUseBlock``-like SDK objects, which we walk by ``.type``.
* **Stop reason:** the SDK's strings ``end_turn``, ``tool_use``,
  ``max_tokens``, ``stop_sequence`` map 1:1 to our union. Anything
  else is normalised to ``end_turn`` to avoid breaking pipeline
  code on a future SDK addition.
* **Errors:** the anthropic SDK's class hierarchy maps cleanly to
  ours. A 529 ("overloaded") is treated as a transient rate-limit
  per the design call recorded in plan §10.

The adapter calls the existing global ``RateLimiter`` before each
request and reports 429/529 back to it, so multi-worker scans still
coordinate backoff the way they do today.
"""

from __future__ import annotations

import sys
import threading
from typing import Any, Optional

import anthropic

from ._ratelimit import report_rate_limit, wait_for_rate_limit
from .._redact import redact_secrets, redacted_cause_from
from ..adapter import (
    CompletionResult,
    ContentBlock,
    LLMAuthError,
    LLMConnectionError,
    LLMNotFoundError,
    LLMRateLimitError,
    LLMRefusalError,
    LLMResponseError,
    Message,
    StopReason,
    TextBlock,
    ToolDef,
    ToolResultBlock,
    ToolUseBlock,
)


_ANTHROPIC_STOP_REASONS: dict[str, StopReason] = {
    "end_turn": "end_turn",
    "tool_use": "tool_use",
    "max_tokens": "max_tokens",
    "stop_sequence": "stop_sequence",
}

# Anthropic's SDK ``StopReason`` literal (anthropic.types.StopReason)
# includes ``"refusal"`` — the model declined for safety/policy reasons.
# It is NOT in ``_ANTHROPIC_STOP_REASONS`` because it doesn't map to a
# normal termination; we surface it as a typed ``LLMRefusalError`` so a
# security scan doesn't read a refusal as a clean, finding-free pass.
_ANTHROPIC_REFUSAL_STOP_REASON = "refusal"

# Track stop_reasons we've already warned about so the stderr noise
# is one-line-per-novel-value, not per call. Guarded by a lock for
# consistency with ``_unknown_pricing_warned`` in
# ``utilities/llm_client.py`` — multiple worker threads can hit
# ``_response_to_unified`` concurrently when a scan parallelises
# units, and we don't want even a benign double-warning race.
_warned_stop_reasons: set[str] = set()
_warned_stop_reasons_lock = threading.Lock()

# Response content-block kinds we received but don't translate (dropped
# on the way to the pipeline). Warn once per kind. Per-process, lock-guarded.
_warned_block_kinds: set[str] = set()
_warned_block_kinds_lock = threading.Lock()


def _warn_unknown_block_kind(kind: str) -> None:
    """One-time stderr warning when the response carries a content-block
    kind the adapter doesn't translate, so a dropped block isn't silent."""
    should_warn = False
    with _warned_block_kinds_lock:
        if kind not in _warned_block_kinds:
            _warned_block_kinds.add(kind)
            should_warn = True
    if should_warn:
        sys.stderr.write(
            f"warning: AnthropicAdapter received unknown content block "
            f"kind {kind!r}; dropping it. If the pipeline should consume "
            f"this, add a ContentBlock kind in utilities/llm/adapter.py "
            f"and translate it here.\n"
        )


def reset_warnings() -> None:
    """Clear this adapter's one-time-warning memory (for tests / new scans)."""
    with _warned_stop_reasons_lock:
        _warned_stop_reasons.clear()
    with _warned_block_kinds_lock:
        _warned_block_kinds.clear()


class AnthropicAdapter:
    """:class:`LLMAdapter` implementation backed by ``anthropic.Anthropic``."""

    name = "anthropic"
    supports_tools = True

    # Per-million-token rates the adapter ships with. Authoritative
    # for Anthropic-hosted models AND for Anthropic-format proxies
    # that route those exact model IDs (e.g. an OpenRouter
    # provider that exposes claude-opus-4-6). When the adapter is
    # pointed at a non-Claude model ID (qwen/qwen-3-coder-480b via
    # OpenRouter), the lookup misses and the tracker reports $0 +
    # warning — the user can add to this dict locally if they need
    # accurate cost for a specific non-Claude model.
    pricing: dict[str, dict[str, float]] = {
        "claude-opus-4-20250514": {"input": 15.00, "output": 75.00},
        "claude-opus-4-6": {"input": 15.00, "output": 75.00},
        "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
        "claude-haiku-4-5-20251001": {"input": 1.00, "output": 5.00},
    }

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 5,
        _client: Optional[anthropic.Anthropic] = None,
    ):
        """Construct the adapter.

        Args:
            api_key: Anthropic-format API key. When ``None``, the SDK
                reads ``ANTHROPIC_API_KEY`` from the environment.
            base_url: Override the API host. ``None`` means the SDK's
                default (api.anthropic.com). Required when pointing
                at OpenRouter or any other Anthropic-compat endpoint.
            max_retries: Forwarded to the SDK. The SDK's built-in
                retry covers transient network blips; our rate
                limiter handles 429-coordinated backoff on top.
            _client: Injected SDK instance for testing. Production
                callers should not pass this.
        """
        if _client is not None:
            self._client = _client
            return

        kwargs: dict[str, Any] = {"max_retries": max_retries}
        if api_key is not None:
            kwargs["api_key"] = api_key
        if base_url is not None:
            kwargs["base_url"] = base_url
        self._client = anthropic.Anthropic(**kwargs)

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
        # call — same pattern the legacy AnthropicClient used, now
        # shared with the OpenAI and Google adapters (see _ratelimit.py).
        wait_for_rate_limit()

        try:
            response = self._client.messages.create(**request)
        except anthropic.AuthenticationError as exc:
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.PermissionDeniedError as exc:
            # 403 is auth-shaped enough to ride the same error class;
            # the user message is still informative.
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.RateLimitError as exc:
            retry_after = _retry_after_from(exc)
            report_rate_limit(retry_after)
            raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
        except anthropic.NotFoundError as exc:
            raise LLMNotFoundError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.APIConnectionError as exc:
            # Covers DNS, TCP, TLS, and SDK-mapped timeouts (the
            # SDK's APITimeoutError inherits from APIConnectionError).
            raise LLMConnectionError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.APIStatusError as exc:
            # 529 "overloaded" is transient; treat it like a 429 per
            # the design call so the rate-limiter coordinates backoff.
            status = getattr(exc, "status_code", None)
            if status == 529:
                retry_after = _retry_after_from(exc)
                report_rate_limit(retry_after)
                raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
            # Everything else (400, 422, 500, ...) is a structural
            # response problem from the pipeline's perspective.
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)

        return _response_to_unified(response)

    def validate(self, model: str) -> None:
        # Cheapest valid request: 1-token cap, single "hi" message.
        # Probing the actual configured model (not a hardcoded
        # haiku) catches typo'd model IDs at init, per plan §5.
        #
        # Note: this path deliberately does NOT call
        # ``rate_limiter.wait_if_needed()`` the way ``complete()``
        # does. validate() is a one-shot probe at scan startup
        # (registry.validate()), not a worker request — there's
        # nothing for the cross-worker backoff to coordinate yet.
        # A 429 returned here is still mapped to LLMRateLimitError
        # below so the caller sees a typed error.
        try:
            self._client.messages.create(
                model=model,
                max_tokens=1,
                messages=[{"role": "user", "content": "hi"}],
            )
        except anthropic.AuthenticationError as exc:
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.PermissionDeniedError as exc:
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.RateLimitError as exc:
            # 429 at init time is rare but possible (org-wide
            # quota cooling from a recent scan). Surface it as a
            # typed error so the caller can decide whether to
            # retry — same shape as the run-time path in complete().
            retry_after = _retry_after_from(exc)
            raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
        except anthropic.NotFoundError as exc:
            raise LLMNotFoundError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.APIConnectionError as exc:
            raise LLMConnectionError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except anthropic.APIStatusError as exc:
            # 529 "overloaded" at init time is the validation
            # equivalent of a 429; same transient-retry classification.
            status = getattr(exc, "status_code", None)
            if status == 529:
                retry_after = _retry_after_from(exc)
                raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
            # Everything else (400, 422, 500, ...) is a structural
            # response problem from the pipeline's perspective.
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)


# ----------------------------------------------------------------------
# Translation helpers
# ----------------------------------------------------------------------


def _message_to_anthropic(message: Message) -> dict[str, Any]:
    return {
        "role": message.role,
        "content": [_block_to_anthropic(block) for block in message.content],
    }


def _block_to_anthropic(block: ContentBlock) -> dict[str, Any]:
    if isinstance(block, TextBlock):
        return {"type": "text", "text": block.text}
    if isinstance(block, ToolUseBlock):
        return {
            "type": "tool_use",
            "id": block.id,
            "name": block.name,
            "input": block.input,
        }
    if isinstance(block, ToolResultBlock):
        return {
            "type": "tool_result",
            "tool_use_id": block.tool_use_id,
            "content": block.content,
        }
    # Unreachable: ContentBlock is a closed union. Defending against
    # a future block kind that someone forgot to teach this adapter.
    raise LLMResponseError(f"AnthropicAdapter: cannot serialise block of type {type(block).__name__}")


def _tool_to_anthropic(tool: ToolDef) -> dict[str, Any]:
    return {
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema,
    }


def _response_to_unified(response: Any) -> CompletionResult:
    """Translate an anthropic SDK ``Message`` object into our types."""
    content_blocks: list[ContentBlock] = []
    for block in response.content:
        kind = getattr(block, "type", None)
        if kind == "text":
            content_blocks.append(TextBlock(text=block.text))
        elif kind == "tool_use":
            content_blocks.append(
                ToolUseBlock(
                    id=block.id,
                    name=block.name,
                    input=block.input or {},
                )
            )
        elif kind:
            # Unknown block kind (e.g. a future "thinking" or "refusal"
            # block). Pipeline code only knows Text and ToolUse in
            # assistant turns, so we drop it — but warn once so the
            # symptom isn't silent. For a security tool, a silently
            # dropped "refusal" paired with a benign stop_reason could
            # read as an empty success.
            _warn_unknown_block_kind(str(kind))

    # R4-5: a usage-less response (rare, but seen on some proxies and on
    # error-shaped 200s) must not AttributeError here — the downstream
    # ``getattr(usage, ..., 0)`` already tolerates ``None``.
    usage = getattr(response, "usage", None)
    raw_stop = getattr(response, "stop_reason", None) or "end_turn"

    # R4-2: a populated refusal is the more specific signal — raise it
    # BEFORE the empty-content guard (a refusal may or may not carry
    # text). Anthropic reports this as ``stop_reason == "refusal"``.
    if raw_stop == _ANTHROPIC_REFUSAL_STOP_REASON:
        raise LLMRefusalError(
            "Anthropic refused the request (stop_reason='refusal'); the "
            "model declined to answer for safety or policy reasons"
        )

    # R4-1: an empty completion — no TextBlock AND no ToolUseBlock —
    # carries nothing the pipeline can act on. This happens when
    # ``response.content == []`` or when every block was an unknown kind
    # we dropped above. Surface it via the taxonomy instead of returning
    # an empty ``end_turn`` (mirrors the OpenAI empty-``choices`` and
    # Gemini empty-``candidates`` guards); for a SECURITY tool an empty
    # end_turn would read as a clean, passing result. A tool-use-only
    # response (ToolUseBlock present, no text) is VALID and is not caught
    # here because ``content_blocks`` is non-empty.
    if not content_blocks:
        raise LLMResponseError(
            "Anthropic returned no usable content (empty completion); the "
            "request may have been filtered or the response was malformed"
        )

    if raw_stop not in _ANTHROPIC_STOP_REASONS:
        # A future SDK release adding "refusal" / "content_filter" /
        # similar would otherwise look like a normal completion to
        # pipeline code. Warn once so the symptom doesn't go silent.
        # For a security-tool, treating a refusal as end_turn could
        # mask false negatives — the next pipeline release should
        # widen StopReason to include the new value explicitly.
        should_warn = False
        with _warned_stop_reasons_lock:
            if raw_stop not in _warned_stop_reasons:
                _warned_stop_reasons.add(raw_stop)
                should_warn = True
        if should_warn:
            sys.stderr.write(
                f"warning: AnthropicAdapter received unknown stop_reason "
                f"{raw_stop!r}; normalising to 'end_turn'. Add this value "
                f"to StopReason in utilities/llm/adapter.py and the "
                f"_ANTHROPIC_STOP_REASONS table if it's a new SDK addition.\n"
            )
    return CompletionResult(
        content=content_blocks,
        input_tokens=getattr(usage, "input_tokens", 0),
        output_tokens=getattr(usage, "output_tokens", 0),
        stop_reason=_ANTHROPIC_STOP_REASONS.get(raw_stop, "end_turn"),
        raw=response,
    )


def _retry_after_from(exc: Any) -> Optional[float]:
    """Extract a retry-after header value from an SDK exception.

    Returns ``None`` when the header is absent or unparseable — the
    rate limiter then falls back to its configured default backoff.
    """
    response = getattr(exc, "response", None)
    if response is None:
        return None
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    raw = None
    try:
        raw = headers.get("retry-after")
    except AttributeError:
        return None
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None
