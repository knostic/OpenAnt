"""OpenAI adapter — implements :class:`LLMAdapter` against the OpenAI SDK.

Ships alongside the Anthropic reference adapter so the pipeline supports
``provider type = "openai"`` out of the box. Supports tool calling for
the agentic ``enhance`` and ``verify`` phases.

Translation details (read ``HOW_TO_ADD_AN_ADAPTER.md`` §3 first):

* **Tool-result aggregation.** The pipeline emits ONE user ``Message``
  carrying N ``ToolResultBlock``s in response to an assistant turn
  with N ``ToolUseBlock``s. OpenAI's Chat Completions API requires
  one ``{role: "tool", tool_call_id: ...}`` message per result.
  ``_messages_to_openai`` splits the single user message into N
  native ``tool`` messages — preserving the order so the API can
  match each result to its originating ``tool_call_id``.

* **Assistant tool calls.** ``ToolUseBlock``s become entries in the
  assistant message's ``tool_calls`` array. ``arguments`` is a JSON
  string (per the OpenAI shape), not a dict — we ``json.dumps`` the
  pipeline's ``input`` dict at the boundary.

* **Finish reason.** OpenAI's ``stop`` / ``tool_calls`` / ``length``
  map 1:1 to our ``end_turn`` / ``tool_use`` / ``max_tokens`` union.
  ``content_filter`` and other future values normalise to
  ``end_turn`` with a one-time stderr warning so a refusal doesn't
  silently look like a clean completion (relevant for a security
  tool where refusals can mask false negatives).

* **Errors.** ``openai`` SDK exceptions map to our 5-class taxonomy:
  ``AuthenticationError`` / ``PermissionDeniedError`` →
  :class:`LLMAuthError`, ``RateLimitError`` →
  :class:`LLMRateLimitError`, ``APIConnectionError`` (including
  timeout subclass) → :class:`LLMConnectionError`,
  ``NotFoundError`` → :class:`LLMNotFoundError`, everything else
  (``BadRequestError``, ``APIStatusError``) →
  :class:`LLMResponseError`.

OpenAI's protocol does not include a 529-equivalent "overloaded"
status; their backpressure is communicated via 429 + retry-after.
On top of the SDK's own client-side retry (``max_retries``), the
adapter reports 429s to the process-global ``RateLimiter`` (via
``_ratelimit``) and waits on it before each request — so one worker's
429 backs the *other* workers off, exactly like the Anthropic adapter.
The SDK retry handles the failing call itself; the global limiter
handles the fan-out to sibling workers.

Reasoning models (o1/o3/o4 families) require ``max_completion_tokens``
instead of ``max_tokens`` on Chat Completions; ``_token_param`` picks
the right key per model so a probe or scan against ``o1`` doesn't 400.
"""

from __future__ import annotations

import json
import re
import sys
import threading
from typing import Any, Optional

import openai

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


_OPENAI_FINISH_REASONS: dict[str, StopReason] = {
    "stop": "end_turn",
    "tool_calls": "tool_use",
    "length": "max_tokens",
}

# OpenAI's ``finish_reason`` literal includes ``"content_filter"`` — the
# response was withheld or truncated by the moderation layer. We surface
# it as a typed ``LLMRefusalError`` rather than normalising to
# ``end_turn``, so a security scan doesn't read a filtered response as a
# clean, finding-free pass.
_OPENAI_CONTENT_FILTER_REASON = "content_filter"

# OpenAI reasoning models (o1/o3/o4 families) reject ``max_tokens`` and
# require ``max_completion_tokens``. Match the bare ``o<digit>`` family
# — NOT ``gpt-4o`` / ``gpt-4o-mini``, which are regular chat models.
_REASONING_MODEL_RE = re.compile(r"^o[1-9]")

# Track finish_reasons we've already warned about. Per-process, lock-guarded.
_warned_finish_reasons: set[str] = set()
_warned_finish_reasons_lock = threading.Lock()

# Tool calls whose ``arguments`` we couldn't parse as JSON, keyed by tool
# name so a malformed-args bug is visible once instead of silently
# collapsing to an empty input dict (PR #69 H5). Per-process, lock-guarded.
_warned_bad_tool_json: set[str] = set()
_warned_bad_tool_json_lock = threading.Lock()


def _is_reasoning_model(model: str) -> bool:
    """True for OpenAI reasoning models (o1/o3/o4…) that need
    ``max_completion_tokens`` instead of ``max_tokens``.

    Strips any proxy prefix (``openai/o1`` → ``o1``) and matches the
    bare ``o<digit>`` family. ``gpt-4o`` is NOT a reasoning model.
    """
    bare = model.lower().rsplit("/", 1)[-1]
    return bool(_REASONING_MODEL_RE.match(bare))


def _token_param(model: str) -> str:
    """The request key for the output-token cap, per model family."""
    return "max_completion_tokens" if _is_reasoning_model(model) else "max_tokens"


def _warn_bad_tool_json(tool_name: str) -> None:
    """One-time stderr warning when a tool call's ``arguments`` aren't valid JSON."""
    should_warn = False
    with _warned_bad_tool_json_lock:
        if tool_name not in _warned_bad_tool_json:
            _warned_bad_tool_json.add(tool_name)
            should_warn = True
    if should_warn:
        sys.stderr.write(
            f"warning: OpenAIAdapter could not parse tool-call arguments for "
            f"{tool_name!r} as JSON; passing empty input {{}}. The tool call "
            f"will likely fail downstream with a missing-field error.\n"
        )


def reset_warnings() -> None:
    """Clear this adapter's one-time-warning memory (for tests / new scans)."""
    with _warned_finish_reasons_lock:
        _warned_finish_reasons.clear()
    with _warned_bad_tool_json_lock:
        _warned_bad_tool_json.clear()


class OpenAIAdapter:
    """:class:`LLMAdapter` implementation backed by ``openai.OpenAI``."""

    name = "openai"
    supports_tools = True

    # Per-million-token rates (USD per 1M tokens). Models absent here
    # report $0 with a one-time stderr warning per issue #65 §9. Add to
    # this dict in your local fork if you scan against a model OpenAI
    # added after this file's last update. Prices drift — verify against
    # OpenAI's current list (https://openai.com/api/pricing/).
    #
    # o1-mini / o1-preview are intentionally absent: they reject the
    # ``developer`` role and lack tool support, so the adapter does not
    # advertise them (PR #69 H3). ``o1`` / ``o3-mini`` / ``o3`` / ``o4-mini``
    # accept ``developer`` + tools and stay supported.
    pricing: dict[str, dict[str, float]] = {
        "gpt-4o": {"input": 2.50, "output": 10.00},
        "gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "gpt-4.1": {"input": 2.00, "output": 8.00},
        "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
        "gpt-4.1-nano": {"input": 0.10, "output": 0.40},
        "o1": {"input": 15.00, "output": 60.00},
        "o3": {"input": 2.00, "output": 8.00},
        "o3-mini": {"input": 1.10, "output": 4.40},
        "o4-mini": {"input": 1.10, "output": 4.40},
    }

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
            api_key: OpenAI API key. When ``None``, the SDK reads
                ``OPENAI_API_KEY`` from the environment.
            base_url: Override the API host. ``None`` means the SDK's
                default (api.openai.com). Set this for
                OpenAI-compatible proxies (LiteLLM, vLLM, etc.).
            max_retries: Forwarded to the SDK. The SDK retries
                transient 429s and 5xx automatically; the pipeline
                does not add its own retry loop on top.
            _client: Injected SDK instance for testing.
        """
        if _client is not None:
            self._client = _client
            return

        kwargs: dict[str, Any] = {"max_retries": max_retries}
        if api_key is not None:
            kwargs["api_key"] = api_key
        if base_url is not None:
            kwargs["base_url"] = base_url
        self._client = openai.OpenAI(**kwargs)

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
        except openai.AuthenticationError as exc:
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.PermissionDeniedError as exc:
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.RateLimitError as exc:
            retry_after = _retry_after_from(exc)
            report_rate_limit(retry_after)
            raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
        except openai.NotFoundError as exc:
            raise LLMNotFoundError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.APIConnectionError as exc:
            # Covers DNS, TCP, TLS, and SDK-mapped timeouts (the SDK's
            # APITimeoutError inherits from APIConnectionError).
            raise LLMConnectionError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.BadRequestError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.APIStatusError as exc:
            # Everything else (5xx, unexpected statuses).
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)

        return _response_to_unified(response)

    def validate(self, model: str) -> None:
        try:
            self._client.chat.completions.create(**{
                "model": model,
                _token_param(model): 1,
                "messages": [{"role": "user", "content": "hi"}],
            })
        except openai.AuthenticationError as exc:
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.PermissionDeniedError as exc:
            raise LLMAuthError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.RateLimitError as exc:
            retry_after = _retry_after_from(exc)
            raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after) from redacted_cause_from(exc)
        except openai.NotFoundError as exc:
            raise LLMNotFoundError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.APIConnectionError as exc:
            raise LLMConnectionError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.BadRequestError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except openai.APIStatusError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)


# ----------------------------------------------------------------------
# Translation helpers
# ----------------------------------------------------------------------


def _messages_to_openai(
    messages: list[Message], system: Optional[str], model: str
) -> list[dict[str, Any]]:
    """Translate unified messages to OpenAI Chat Completions shape.

    System prompts are sent as a leading message rather than a separate
    parameter. The *role* of that leading message is model-aware:
    reasoning models (o1/o3/o4…) reject the ``system`` role with a 400,
    so the prompt is routed to a ``{role: "developer"}`` message — the
    replacement OpenAI defines for steering reasoning models. Regular
    chat models (``gpt-4o`` etc.) keep ``{role: "system"}``.

    Tool results in a user turn become N standalone ``{role: "tool"}``
    messages, each with its own ``tool_call_id``. Plain text in a user
    turn becomes a trailing ``{role: "user"}`` message — so a mixed
    user turn (rare but allowed by the contract) emits tools-then-text
    in that order, matching how OpenAI expects tool responses to
    immediately follow the assistant call that triggered them.
    """
    out: list[dict[str, Any]] = []
    if system:
        system_role = "developer" if _is_reasoning_model(model) else "system"
        out.append({"role": system_role, "content": system})

    for message in messages:
        text_blocks = [b for b in message.content if isinstance(b, TextBlock)]
        tool_use_blocks = [b for b in message.content if isinstance(b, ToolUseBlock)]
        tool_result_blocks = [b for b in message.content if isinstance(b, ToolResultBlock)]

        if message.role == "user":
            # Tool results MUST come first — they reference a prior
            # assistant message's tool_calls.
            for tr in tool_result_blocks:
                out.append({
                    "role": "tool",
                    "tool_call_id": tr.tool_use_id,
                    "content": tr.content,
                })
            # Plain user text (typically a follow-up question, or the
            # initial prompt when no tool_results are present).
            if text_blocks:
                out.append({
                    "role": "user",
                    "content": "\n".join(b.text for b in text_blocks),
                })
        elif message.role == "assistant":
            msg: dict[str, Any] = {"role": "assistant"}
            # When an assistant message has tool_calls, OpenAI accepts
            # content=null. When there's text alongside, send both.
            if text_blocks:
                msg["content"] = "\n".join(b.text for b in text_blocks)
            else:
                msg["content"] = None
            if tool_use_blocks:
                msg["tool_calls"] = [
                    {
                        "id": tu.id,
                        "type": "function",
                        "function": {
                            "name": tu.name,
                            "arguments": json.dumps(tu.input or {}),
                        },
                    }
                    for tu in tool_use_blocks
                ]
            out.append(msg)
        else:  # pragma: no cover — Role is a closed Literal
            raise LLMResponseError(
                f"OpenAIAdapter: unknown message role {message.role!r}"
            )
    return out


def _tool_to_openai(tool: ToolDef) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema,
        },
    }


def _response_to_unified(response: Any) -> CompletionResult:
    """Translate an OpenAI ChatCompletion response into our types."""
    choices = getattr(response, "choices", None) or []
    if not choices:
        # No choices → nothing the pipeline can act on. Surface it via
        # the taxonomy instead of letting an IndexError escape unmapped
        # (mirrors the Gemini empty-``candidates`` guard); for a security
        # tool an empty end_turn would read as a clean, passing result.
        raise LLMResponseError(
            "OpenAI returned no choices (empty completion); the request "
            "may have been filtered or the response was malformed"
        )
    choice = choices[0]
    message = choice.message

    content_blocks: list[ContentBlock] = []

    # Text content. May be None or empty when the message is purely
    # tool_calls; only emit a TextBlock when there's actual text.
    text = getattr(message, "content", None)
    if text:
        content_blocks.append(TextBlock(text=text))

    # Tool calls. The SDK exposes them as a list (or None) of objects
    # with .id, .type, .function.name, .function.arguments (string).
    tool_calls = getattr(message, "tool_calls", None) or []
    for tc in tool_calls:
        arguments = getattr(tc.function, "arguments", "") or ""
        try:
            input_dict = json.loads(arguments) if arguments else {}
        except json.JSONDecodeError:
            # Malformed JSON from the model is rare but possible. Warn
            # once per tool so the failure mode is visible, then fall
            # back to an empty dict: the subsequent tool execution
            # surfaces a clear "missing required field" error, and a
            # multi-tool turn's other calls still proceed.
            _warn_bad_tool_json(getattr(tc.function, "name", "<unknown>"))
            input_dict = {}
        content_blocks.append(ToolUseBlock(
            id=tc.id,
            name=tc.function.name,
            input=input_dict,
        ))

    raw_finish = getattr(choice, "finish_reason", None) or "stop"

    # R4-2: a content-filter finish is the more specific signal — raise
    # it regardless of whether the message carried partial text/tool
    # calls. OpenAI reports this as ``finish_reason == "content_filter"``.
    if raw_finish == _OPENAI_CONTENT_FILTER_REASON:
        raise LLMRefusalError(
            "OpenAI content-filtered the response "
            "(finish_reason='content_filter'); the completion was withheld "
            "or truncated by the moderation layer"
        )

    if raw_finish not in _OPENAI_FINISH_REASONS:
        should_warn = False
        with _warned_finish_reasons_lock:
            if raw_finish not in _warned_finish_reasons:
                _warned_finish_reasons.add(raw_finish)
                should_warn = True
        if should_warn:
            sys.stderr.write(
                f"warning: OpenAIAdapter received unknown finish_reason "
                f"{raw_finish!r}; normalising to 'end_turn'. Add this value "
                f"to StopReason in utilities/llm/adapter.py and "
                f"_OPENAI_FINISH_REASONS if OpenAI added a new termination "
                f"reason.\n"
            )

    usage = getattr(response, "usage", None)
    return CompletionResult(
        content=content_blocks,
        input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
        output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
        stop_reason=_OPENAI_FINISH_REASONS.get(raw_finish, "end_turn"),
        raw=response,
    )


def _retry_after_from(exc: Any) -> Optional[float]:
    """Extract a retry-after header value from an SDK exception."""
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
