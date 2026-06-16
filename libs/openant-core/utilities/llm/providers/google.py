"""Google Gemini adapter — implements :class:`LLMAdapter` against the
``google-genai`` SDK.

Ships alongside the Anthropic + OpenAI adapters so the pipeline supports
``provider type = "google"`` out of the box. Supports tool calling for
the agentic ``enhance`` and ``verify`` phases via Gemini's
``function_call`` / ``function_response`` parts.

Translation details (read ``HOW_TO_ADD_AN_ADAPTER.md`` §3 first):

* **Content shape.** Gemini structures requests as a list of
  ``Content`` objects, each with a role and a list of ``Part``
  objects. Parts can be text, function_call, or function_response.
  This contrasts with Anthropic's "list of typed blocks per message"
  and OpenAI's "message-per-tool-result". The pipeline's unified
  ``Message[]`` maps to Gemini's ``Content[]`` 1:1 — we don't need
  to split tool-results into separate messages the way the OpenAI
  adapter does.

* **Roles.** Pipeline ``user`` maps to Gemini ``user`` (for both
  text prompts AND function responses — Gemini doesn't have a
  separate "tool" role). Pipeline ``assistant`` maps to Gemini
  ``model``.

* **Tool calls.** A ``ToolUseBlock`` becomes a
  ``Part.from_function_call(name=..., args=...)``. A
  ``ToolResultBlock`` becomes a
  ``Part.from_function_response(name=..., response={...})``. We
  carry the matching function NAME (not ``tool_use_id``) because
  Gemini's protocol keys function_response on name; the
  ``tool_use_id`` is preserved as the original function call's id
  but does not participate in matching.

* **Finish reason.** Gemini's ``STOP`` / ``MAX_TOKENS`` map cleanly
  to our ``end_turn`` / ``max_tokens`` union. A ``SAFETY``,
  ``RECITATION``, or ``BLOCKLIST`` finish normalises to
  ``end_turn`` with a one-time stderr warning so a refusal doesn't
  silently look like a clean completion (important for a security
  tool). Tool calls are detected by the presence of a
  ``function_call`` part rather than a dedicated finish_reason
  value — when present, ``stop_reason`` becomes ``"tool_use"``
  regardless of the candidate's finish_reason.

* **Errors.** ``google.genai.errors.ClientError`` carries a ``.code``
  HTTP status that drives the taxonomy mapping: 401/403 →
  :class:`LLMAuthError`, 404 → :class:`LLMNotFoundError`, 429 →
  :class:`LLMRateLimitError`, everything else →
  :class:`LLMResponseError`. ``ServerError`` (5xx) also maps to
  :class:`LLMResponseError`. Network failures surface as
  ``httpx.ConnectError`` / ``httpx.TimeoutException`` since the
  SDK doesn't wrap them — caught and re-raised as
  :class:`LLMConnectionError`.
"""

from __future__ import annotations

import sys
import threading
from typing import Any, Optional

import httpx
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

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
from ._ratelimit import report_rate_limit, wait_for_rate_limit
from .._redact import redact_secrets, redacted_cause_from


# Gemini's FinishReason enum values, mapped to our StopReason union.
# Strings here match what ``str(candidate.finish_reason)`` produces;
# the SDK exposes it as an enum but compares equal to the string.
_GEMINI_FINISH_REASONS: dict[str, StopReason] = {
    "STOP": "end_turn",
    "FinishReason.STOP": "end_turn",
    "MAX_TOKENS": "max_tokens",
    "FinishReason.MAX_TOKENS": "max_tokens",
}

# Gemini candidate finish reasons that mean "blocked / refused" rather
# than a normal termination. We surface these as a typed
# ``LLMRefusalError`` so a security scan doesn't read a safety-blocked
# candidate as a clean, finding-free pass.
#
# We verified against the pinned google-genai SDK (v2.4.0) that
# ``types.FinishReason`` exposes SAFETY / RECITATION / BLOCKLIST /
# PROHIBITED_CONTENT / SPII (among others). We build the comparison set
# from the enum when importable so the names stay in sync with the SDK,
# and fall back to the bare string names otherwise. ``raw_finish`` is
# compared against BOTH the bare name (``"SAFETY"`` — what a test stub or
# a string-valued field yields) and the ``str(enum)`` form
# (``"FinishReason.SAFETY"`` — what the live SDK enum stringifies to).
_GEMINI_REFUSAL_NAMES = (
    "SAFETY",
    "RECITATION",
    "BLOCKLIST",
    "PROHIBITED_CONTENT",
    "SPII",
)


def _build_gemini_refusal_set() -> frozenset[str]:
    names: set[str] = set()
    finish_enum = getattr(genai_types, "FinishReason", None)
    for name in _GEMINI_REFUSAL_NAMES:
        names.add(name)
        member = getattr(finish_enum, name, None) if finish_enum is not None else None
        if member is not None:
            # Cover both ``str(member)`` ("FinishReason.SAFETY") and the
            # raw ``.value`` ("SAFETY") forms the SDK may surface.
            names.add(str(member))
            value = getattr(member, "value", None)
            if value is not None:
                names.add(str(value))
    return frozenset(names)


_GEMINI_REFUSAL_FINISH_REASONS = _build_gemini_refusal_set()

_warned_finish_reasons: set[str] = set()
_warned_finish_reasons_lock = threading.Lock()


def reset_warnings() -> None:
    """Clear this adapter's one-time-warning memory (for tests / new scans)."""
    with _warned_finish_reasons_lock:
        _warned_finish_reasons.clear()


class GoogleAdapter:
    """:class:`LLMAdapter` implementation backed by ``google.genai.Client``."""

    name = "google"
    supports_tools = True

    # Per-million-token rates. Gemini Pro has tiered pricing (under
    # 200K context vs over); we ship the more common <200K rates.
    # Users with long-context scans may need to override locally.
    # Models absent here report $0 + warning per issue #65 §9.
    pricing: dict[str, dict[str, float]] = {
        "gemini-2.5-pro": {"input": 1.25, "output": 10.00},
        "gemini-2.5-flash": {"input": 0.30, "output": 2.50},
        "gemini-2.5-flash-lite": {"input": 0.10, "output": 0.40},
        "gemini-2.0-flash": {"input": 0.10, "output": 0.40},
        "gemini-2.0-flash-lite": {"input": 0.075, "output": 0.30},
        "gemini-1.5-pro": {"input": 1.25, "output": 5.00},
        "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
    }

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 5,
        _client: Optional[genai.Client] = None,
    ):
        """Construct the adapter.

        Args:
            api_key: Gemini API key. When ``None``, the SDK reads
                ``GOOGLE_API_KEY`` / ``GEMINI_API_KEY`` from the env.
            base_url: Override the API host. ``None`` means the SDK's
                default (generativelanguage.googleapis.com). Required
                when pointing at Vertex AI or a Gemini-compat proxy.
            max_retries: Forwarded to the SDK as
                ``HttpOptions(retry_options=HttpRetryOptions(attempts=...))``.
                The google-genai SDK DOES expose retry configuration this
                way (verified against the pinned v2.4.0:
                ``HttpRetryOptions.attempts``); on top of the SDK's own
                retry, our rate limiter coordinates 429 backoff across
                workers — same division of labour as the other adapters.
            _client: Injected SDK instance for testing.
        """
        if _client is not None:
            self._client = _client
            return

        kwargs: dict[str, Any] = {}
        if api_key is not None:
            kwargs["api_key"] = api_key

        # Build HttpOptions whenever we need to set base_url and/or
        # retry_options. The SDK takes both on the same object, so we
        # assemble one set of fields and only construct it if non-empty —
        # passing an empty HttpOptions would needlessly override the SDK
        # defaults. ``max_retries`` maps to ``HttpRetryOptions.attempts``.
        http_options_fields: dict[str, Any] = {}
        if base_url is not None:
            http_options_fields["base_url"] = base_url
        if max_retries is not None:
            # F3 (round-5): the SDK's ``attempts`` field is the "Maximum
            # number of attempts, INCLUDING the original request" (verified
            # against pinned google-genai v2.4.0: "If 0 or 1, it means no
            # retries"). OpenAI/Anthropic ``max_retries`` instead counts
            # retries BEYOND the first request. So forwarding
            # ``attempts=max_retries`` was off-by-one — ``max_retries=5``
            # gave 6 attempts on the other adapters but only 5 here. Add 1
            # for parity: ``max_retries`` retries + the original request.
            # ``max_retries=0`` correctly maps to ``attempts=1`` (no
            # retries), matching the other adapters' zero-retry semantics.
            http_options_fields["retry_options"] = genai_types.HttpRetryOptions(
                attempts=max_retries + 1,
            )
        if http_options_fields:
            kwargs["http_options"] = genai_types.HttpOptions(**http_options_fields)

        self._client = genai.Client(**kwargs)

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
        contents = [_message_to_gemini(m) for m in messages]
        config_kwargs: dict[str, Any] = {"max_output_tokens": max_tokens}
        if system is not None:
            config_kwargs["system_instruction"] = system
        if tools:
            config_kwargs["tools"] = [_tool_to_gemini(t) for t in tools]

        # Cooperate with cross-worker backoff before issuing the call —
        # same dance the Anthropic adapter does (see _ratelimit.py).
        wait_for_rate_limit()

        try:
            response = self._client.models.generate_content(
                model=model,
                contents=contents,
                config=genai_types.GenerateContentConfig(**config_kwargs),
            )
        except genai_errors.ClientError as exc:
            code = _http_code_from(exc)
            if code in (401, 403):
                raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
            if code == 404:
                raise LLMNotFoundError(redact_secrets(str(exc))) from redacted_cause_from(exc)
            if code == 429:
                retry_after = _retry_after_from(exc)
                report_rate_limit(retry_after)
                raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except genai_errors.ServerError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except genai_errors.APIError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout, httpx.TimeoutException) as exc:
            raise LLMConnectionError(redact_secrets(str(exc))) from redacted_cause_from(exc)

        return _response_to_unified(response)

    def validate(self, model: str) -> None:
        try:
            self._client.models.generate_content(
                model=model,
                contents=[genai_types.Content(
                    role="user",
                    parts=[genai_types.Part.from_text(text="hi")],
                )],
                config=genai_types.GenerateContentConfig(max_output_tokens=1),
            )
        except genai_errors.ClientError as exc:
            code = _http_code_from(exc)
            if code in (401, 403):
                raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
            if code == 404:
                raise LLMNotFoundError(redact_secrets(str(exc))) from redacted_cause_from(exc)
            if code == 429:
                retry_after = _retry_after_from(exc)
                raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except genai_errors.ServerError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except genai_errors.APIError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout, httpx.TimeoutException) as exc:
            raise LLMConnectionError(redact_secrets(str(exc))) from redacted_cause_from(exc)


# ----------------------------------------------------------------------
# Translation helpers
# ----------------------------------------------------------------------


def _message_to_gemini(message: Message) -> genai_types.Content:
    """Translate one unified message to a Gemini ``Content``.

    Roles map as: ``user`` → ``user``, ``assistant`` → ``model``.
    Each block becomes one ``Part``:
      - ``TextBlock`` → ``Part.from_text``
      - ``ToolUseBlock`` → ``Part.from_function_call`` (assistant turns)
      - ``ToolResultBlock`` → ``Part.from_function_response`` (user turns)
    """
    role = "model" if message.role == "assistant" else "user"
    parts: list[genai_types.Part] = []
    for block in message.content:
        if isinstance(block, TextBlock):
            parts.append(genai_types.Part.from_text(text=block.text))
        elif isinstance(block, ToolUseBlock):
            parts.append(genai_types.Part.from_function_call(
                name=block.name,
                args=block.input or {},
            ))
        elif isinstance(block, ToolResultBlock):
            # Gemini's function_response keys on the function NAME, not
            # the original call's id. The pipeline carries that name on
            # ``ToolResultBlock.name`` (copied from the matching
            # ToolUseBlock); the tool_use_id rides along but isn't used
            # for matching. ``response`` must be a dict; wrap raw string
            # content in ``{"result": ...}`` since Gemini's contract
            # expects an object, not a bare value.
            parts.append(genai_types.Part.from_function_response(
                name=_name_for_tool_result(block),
                response={"result": block.content},
            ))
        else:  # pragma: no cover — closed union
            raise LLMResponseError(
                f"GoogleAdapter: cannot serialise block of type {type(block).__name__}"
            )
    return genai_types.Content(role=role, parts=parts)


def _name_for_tool_result(block: ToolResultBlock) -> str:
    """Recover the function name Gemini needs on a ``function_response``.

    Gemini matches each ``function_response`` to its originating
    ``function_call`` by NAME, not by id. The pipeline carries that
    name on ``ToolResultBlock.name`` (populated from the matching
    ``ToolUseBlock.name`` at the tool-result construction sites), so
    prefer it.

    Fall back to ``tool_use_id`` only for legacy callers that didn't
    set a name — note this is the *broken* path: the synthesised id
    (``gemini_<name>_<idx>``, see ``_response_to_unified``) does NOT
    equal the function name, so Gemini won't match it. The final
    ``"tool_response"`` constant just guarantees the SDK gets a
    non-empty string rather than ``None``.
    """
    return block.name or block.tool_use_id or "tool_response"


def _tool_to_gemini(tool: ToolDef) -> genai_types.Tool:
    return genai_types.Tool(function_declarations=[
        genai_types.FunctionDeclaration(
            name=tool.name,
            description=tool.description,
            parameters=tool.input_schema,
        ),
    ])


def _response_to_unified(response: Any) -> CompletionResult:
    """Translate a Gemini generate_content response into our types."""
    content_blocks: list[ContentBlock] = []
    raw_finish: str = "STOP"
    input_tokens = 0
    output_tokens = 0

    candidates = getattr(response, "candidates", None) or []
    if candidates:
        candidate = candidates[0]
        raw_finish = str(getattr(candidate, "finish_reason", None) or "STOP")

        content = getattr(candidate, "content", None)
        parts = getattr(content, "parts", None) or [] if content else []

        for part in parts:
            # Function calls take precedence — pipeline cares about
            # them before any text.
            fc = getattr(part, "function_call", None)
            if fc is not None and getattr(fc, "name", None):
                args = getattr(fc, "args", None) or {}
                # Gemini doesn't issue ids for function_call parts;
                # synthesise one so the pipeline's id-based tool_result
                # matching has something to use. We prefix with
                # ``gemini_`` for traceability when raw responses are
                # logged.
                fc_id = getattr(fc, "id", None) or f"gemini_{fc.name}_{len(content_blocks)}"
                content_blocks.append(ToolUseBlock(
                    id=fc_id,
                    name=fc.name,
                    input=dict(args) if args else {},
                ))
                continue
            text = getattr(part, "text", None)
            if text:
                content_blocks.append(TextBlock(text=text))
    else:
        # No candidates → the prompt itself was blocked/filtered (Gemini
        # reports this on prompt_feedback, not a candidate finish_reason).
        # Surface it instead of returning an empty end_turn, which pipeline
        # code would read as a clean (passing) result — for a security tool
        # that would mask a refusal as a non-finding.
        feedback = getattr(response, "prompt_feedback", None)
        block_reason = getattr(feedback, "block_reason", None) if feedback else None
        raise LLMResponseError(
            f"Gemini returned no candidates "
            f"(prompt blocked: {block_reason or 'unknown reason'})"
        )

    # Usage metadata lives on response.usage_metadata for the new SDK.
    usage = getattr(response, "usage_metadata", None)
    if usage is not None:
        input_tokens = getattr(usage, "prompt_token_count", 0) or 0
        # Gemini bills output as candidates + thoughts (thinking models
        # like gemini-2.5-* emit thoughts_token_count); count both so the
        # cost isn't undercounted.
        output_tokens = (
            (getattr(usage, "candidates_token_count", 0) or 0)
            + (getattr(usage, "thoughts_token_count", 0) or 0)
        )

    # R4-2: a safety/blocked candidate finish reason is the more
    # specific signal — raise it regardless of whether the candidate
    # carried partial text or a function_call. Gemini reports these as
    # SAFETY / RECITATION / BLOCKLIST / PROHIBITED_CONTENT / SPII.
    if raw_finish in _GEMINI_REFUSAL_FINISH_REASONS:
        raise LLMRefusalError(
            f"Gemini blocked the response (finish_reason={raw_finish!r}); "
            "the candidate was withheld for safety or policy reasons"
        )

    stop_reason: StopReason
    has_tool_use = any(isinstance(b, ToolUseBlock) for b in content_blocks)
    if has_tool_use:
        # Gemini doesn't use a dedicated finish_reason for tool calls;
        # the presence of a function_call part IS the signal.
        stop_reason = "tool_use"
    elif raw_finish in _GEMINI_FINISH_REASONS:
        stop_reason = _GEMINI_FINISH_REASONS[raw_finish]
    else:
        # SAFETY / RECITATION / BLOCKLIST / OTHER — warn once, fall
        # back to end_turn so pipeline code keeps moving. A future
        # release should widen StopReason if these become common.
        should_warn = False
        with _warned_finish_reasons_lock:
            if raw_finish not in _warned_finish_reasons:
                _warned_finish_reasons.add(raw_finish)
                should_warn = True
        if should_warn:
            sys.stderr.write(
                f"warning: GoogleAdapter received unknown finish_reason "
                f"{raw_finish!r}; normalising to 'end_turn'. Add this value "
                f"to StopReason in utilities/llm/adapter.py and "
                f"_GEMINI_FINISH_REASONS if Gemini added a new termination "
                f"reason.\n"
            )
        stop_reason = "end_turn"

    return CompletionResult(
        content=content_blocks,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        stop_reason=stop_reason,
        raw=response,
    )


def _http_code_from(exc: Any) -> Optional[int]:
    """Extract the HTTP status code from a genai SDK exception."""
    # The base APIError records ``code`` directly via __init__.
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return code
    return None


def _retry_after_from(exc: Any) -> Optional[float]:
    """Extract retry-after from a genai SDK exception's wrapped response."""
    response = getattr(exc, "response", None)
    if response is None:
        return None
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
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
