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
import os
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
    LLMError,
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
from .._pricing import LazyProviderPricing
from .._redact import redact_secrets, redacted_cause_from


_OPENAI_FINISH_REASONS: dict[str, StopReason] = {
    "stop": "end_turn",
    "tool_calls": "tool_use",
    "length": "max_tokens",
}

# OpenAI's ``finish_reason`` literal includes ``"content_filter"`` — the
# response was withheld or truncated by a filter (which filter — model
# safety classifier or gateway moderation — is provider/route-specific and
# NOT asserted; #212). We surface it as a typed ``LLMRefusalError`` rather
# than normalising to ``end_turn``, so a security scan doesn't read a
# filtered response as a clean, finding-free pass.
_OPENAI_CONTENT_FILTER_REASON = "content_filter"

# OpenAI reasoning models (o1/o3/o4 families) reject ``max_tokens`` and
# require ``max_completion_tokens`` on Chat Completions. Match the bare
# ``o<digit>`` family — NOT ``gpt-4o`` / ``gpt-4o-mini``, which are regular
# chat models. The gpt-5+ generation is ALSO reasoning-class (see
# ``_is_reasoning_model``, which unions this with ``_RESPONSES_MODEL_RE``):
# it normally routes to the Responses API and so never reaches
# ``_token_param``/the role logic — EXCEPT when forced onto the chat path
# via the ``use_responses_api=False`` override, where it must still get
# ``max_completion_tokens`` + the ``developer`` role or the request 400s.
_REASONING_MODEL_RE = re.compile(r"^o[1-9]")

# gpt-5+ generation → OpenAI Responses API (/v1/responses). gpt-5 rejects
# ``tools`` + ``reasoning`` on Chat Completions, which the agentic enhance
# and verify phases require; Responses supports both. Kept deliberately
# narrow: only the gpt-5..gpt-9 families. Everything else (gpt-4o, o-series)
# stays on the unchanged Chat Completions path. Override per-adapter via the
# ``use_responses_api`` ctor arg (for base_url proxies that expose a gpt-5 id
# over a chat-completions-only endpoint). NOTE: ``o1[0-9]`` and future
# non-``gpt-``-prefixed reasoning families are intentionally out of scope here.
_RESPONSES_MODEL_RE = re.compile(r"^gpt-[5-9]([.-]|$)")


def _is_gpt5_responses_family(bare: str) -> bool:
    """True for the gpt-5..gpt-9 REASONING ids that use /v1/responses.

    Excludes the non-reasoning gpt-5 variants — the chat models (``gpt-5-chat``,
    ``gpt-5-chat-latest``) and the web-search models (``gpt-5-search-api``) —
    which reject the ``reasoning`` param the responses path always sends and are
    served on Chat Completions (like ``gpt-4o-search-preview``). Via the tail
    anchor on ``_RESPONSES_MODEL_RE`` it also does not match unrelated numbering
    like ``gpt-50``. ``bare`` must already be lower-cased, proxy-prefix stripped,
    and whitespace-trimmed. This is the ENDPOINT decision only; the token-param /
    role class — which the ``-chat`` variants share but the ``-search`` variants
    don't — is ``_is_gpt5_completion_token_family``.
    """
    return bool(_RESPONSES_MODEL_RE.match(bare)) and "-chat" not in bare and "-search" not in bare


def _is_gpt5_completion_token_family(bare: str) -> bool:
    """True for gpt-5..gpt-9 ids that take ``max_completion_tokens`` + the
    ``developer`` role on Chat Completions — the whole generation EXCEPT the
    ``-search`` variants, which take ``max_tokens`` + ``system`` like
    ``gpt-4o-search-preview``. Live-verified: ``gpt-5.2-chat-latest`` rejects
    ``max_tokens`` (needs ``max_completion_tokens``) while ``gpt-5-search-api``
    accepts ``max_tokens``. Decoupled from the ENDPOINT decision
    (``_is_gpt5_responses_family``): a ``-chat`` id is chat-endpoint yet still
    completion-token-class. ``bare`` must be lower-cased, proxy-stripped, trimmed.
    """
    return bool(_RESPONSES_MODEL_RE.match(bare)) and "-search" not in bare

# Track finish_reasons we've already warned about. Per-process, lock-guarded.
_warned_finish_reasons: set[str] = set()
_warned_finish_reasons_lock = threading.Lock()

# Tool calls whose ``arguments`` we couldn't parse as JSON, keyed by tool
# name so a malformed-args bug is visible once instead of silently
# collapsing to an empty input dict (PR #69 H5). Per-process, lock-guarded.
_warned_bad_tool_json: set[str] = set()
_warned_bad_tool_json_lock = threading.Lock()


def _is_reasoning_model(model: str) -> bool:
    """True for OpenAI reasoning models that need ``max_completion_tokens``
    (not ``max_tokens``) and the ``developer`` role (not ``system``).

    Covers the o-series (``o1``/``o3``/``o4``…) AND the gpt-5+ generation —
    the latter is reasoning-class too, so a gpt-5 forced onto the chat path
    (``use_responses_api=False``) gets the right per-request shape instead of
    a 400. This unions ``_REASONING_MODEL_RE`` (o-series) with
    ``_is_gpt5_completion_token_family`` (the gpt-5+ generation minus the
    ``-search`` variants) — the token-param/role class, which is BROADER than the
    responses-ENDPOINT class (``_is_gpt5_responses_family``): a gpt-5 ``-chat``
    variant is served on Chat Completions but still needs ``max_completion_tokens``
    there. Strips any proxy prefix (``openai/o1`` → ``o1``) and surrounding
    whitespace. ``gpt-4o`` and the ``-search`` variants are NOT completion-token-class.
    """
    bare = model.lower().rsplit("/", 1)[-1].strip()
    return bool(_REASONING_MODEL_RE.match(bare) or _is_gpt5_completion_token_family(bare))


def _token_param(model: str) -> str:
    """The request key for the output-token cap, per model family."""
    return "max_completion_tokens" if _is_reasoning_model(model) else "max_tokens"


def _warn_bad_tool_json(tool_name: str, *, adapter: str = "OpenAIAdapter") -> None:
    """One-time stderr warning when a tool call's ``arguments`` aren't valid JSON."""
    should_warn = False
    with _warned_bad_tool_json_lock:
        if tool_name not in _warned_bad_tool_json:
            _warned_bad_tool_json.add(tool_name)
            should_warn = True
    if should_warn:
        sys.stderr.write(
            f"warning: {adapter} could not parse tool-call arguments for "
            f"{tool_name!r} as JSON; passing empty input {{}}. The tool call "
            f"will likely fail downstream with a missing-field error.\n"
        )


def reset_warnings() -> None:
    """Clear this adapter's one-time-warning memory (for tests / new scans)."""
    with _warned_finish_reasons_lock:
        _warned_finish_reasons.clear()
    with _warned_bad_tool_json_lock:
        _warned_bad_tool_json.clear()
    with _warned_unknown_output_items_lock:
        _warned_unknown_output_items.clear()
    with _warned_responses_statuses_lock:
        _warned_responses_statuses.clear()


# ---------------------------------------------------------------------------
# Responses-API routing + shared helpers
# ---------------------------------------------------------------------------

# Output items on the Responses API we deliberately do not surface as content:
# ``reasoning`` (internal chain, kept out of ``CompletionResult.content`` per the
# adapter's "reasoning stays internal" invariant). Any OTHER unexpected item type
# (mcp_call, shell_call, custom_tool_call, …) is warned about once so a silently
# dropped output surface is visible — mirrors the Anthropic adapter's guard.
_warned_unknown_output_items: set[str] = set()
_warned_unknown_output_items_lock = threading.Lock()

# Abnormal Responses statuses / incomplete-reasons we've already warned about
# (per-process, lock-guarded) — mirrors ``_warned_finish_reasons`` on the chat
# path so a truncated/abnormal-but-non-empty response is observable, not silent.
_warned_responses_statuses: set[str] = set()
_warned_responses_statuses_lock = threading.Lock()


def _warn_unknown_responses_status(value: str) -> None:
    """One-time stderr warning for an unrecognized/abnormal Responses status or
    incomplete reason — mirrors the chat path's unknown-``finish_reason`` warning
    (see ``_response_to_unified``) so an abnormal-but-non-empty response is visible
    instead of silently reading as a clean ``end_turn`` (a false negative for a
    security tool)."""
    should_warn = False
    with _warned_responses_statuses_lock:
        if value not in _warned_responses_statuses:
            _warned_responses_statuses.add(value)
            should_warn = True
    if should_warn:
        sys.stderr.write(
            f"warning: OpenAIAdapter received an abnormal Responses status/reason "
            f"{value!r} carrying partial content; relabelling stop_reason to "
            f"'max_tokens' so a truncated/abnormal response is not read as a clean "
            f"completion. Add an explicit handler if OpenAI introduced a new "
            f"termination status/reason.\n"
        )


def _use_responses_api(model: str, override: Optional[bool]) -> bool:
    """Route gpt-5+ to /v1/responses; everything else to Chat Completions.

    ``override`` (from the adapter ctor) wins when not ``None`` — lets a
    ``base_url`` proxy exposing a gpt-5 id over a chat-completions-only endpoint
    force the chat path, or force responses for an unrecognised id.
    """
    if override is not None:
        return override
    bare = model.lower().rsplit("/", 1)[-1].strip()
    return bool(_is_gpt5_responses_family(bare))


# Reasoning models spend output tokens on hidden reasoning that counts against
# ``max_output_tokens``; a Claude-tuned cap (the pipeline passes ~4096) can be
# fully consumed by reasoning, yielding status="incomplete" with no visible
# text/tool-call — which for a SAST tool would silently read as "nothing found".
# Floor the responses-path output budget so the visible answer always has room.
_RESPONSES_MIN_OUTPUT_TOKENS = 16000

# Reasoning effort for the Responses path. Default from env; "medium" balances
# quality vs reasoning-token cost across thousands of units. Not threaded through
# per-phase config: PhaseRef carries only (provider, model), and adding a field
# would require a coordinated Python + Go CLI config-schema change.
_DEFAULT_REASONING_EFFORT = os.environ.get("OPENANT_OPENAI_REASONING_EFFORT", "medium")


def _map_openai_exception(exc: Exception, *, report_rl: bool) -> "LLMError":
    """Map an ``openai`` SDK exception to the unified taxonomy (secrets redacted).

    Shared by the Chat Completions and Responses paths so both surface the same
    error classes and both feed cross-worker backoff on a 429. Raise the result
    with ``... from redacted_cause_from(exc)`` at the call site.
    """
    if isinstance(exc, (openai.AuthenticationError, openai.PermissionDeniedError)):
        return LLMAuthError(redact_secrets(str(exc)))
    if isinstance(exc, openai.RateLimitError):
        retry_after = _retry_after_from(exc)
        if report_rl:
            report_rate_limit(retry_after)
        return LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after)
    if isinstance(exc, openai.NotFoundError):
        return LLMNotFoundError(redact_secrets(str(exc)))
    if isinstance(exc, openai.APIConnectionError):
        # Covers DNS, TCP, TLS, and SDK-mapped timeouts (APITimeoutError
        # inherits from APIConnectionError).
        return LLMConnectionError(redact_secrets(str(exc)))
    # BadRequestError + any other APIStatusError (5xx, unexpected statuses).
    return LLMResponseError(redact_secrets(str(exc)))


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
    # Resolved lazily from config/models.json (the shared registry) on
    # first access; see utilities/llm/_pricing.py.
    pricing = LazyProviderPricing("openai")

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 5,
        use_responses_api: Optional[bool] = None,
        reasoning_effort: Optional[str] = None,
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
            use_responses_api: Force the endpoint choice. ``None`` (default)
                auto-selects: gpt-5+ → /v1/responses, everything else →
                Chat Completions. ``True``/``False`` overrides — needed for a
                ``base_url`` proxy that exposes a gpt-5 id over a
                chat-completions-only endpoint (set ``False``), or vice versa.
            reasoning_effort: Reasoning effort for the Responses path
                (none|minimal|low|medium|high|xhigh). ``None`` uses the
                ``OPENANT_OPENAI_REASONING_EFFORT`` env default ("medium").
            _client: Injected SDK instance for testing.
        """
        self._use_responses_api_override = use_responses_api
        self._reasoning_effort = reasoning_effort or _DEFAULT_REASONING_EFFORT
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
        if _use_responses_api(model, self._use_responses_api_override):
            return self._complete_responses(model, system, messages, max_tokens, tools)

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
        except (openai.APIStatusError, openai.APIConnectionError) as exc:
            raise _map_openai_exception(exc, report_rl=True) from redacted_cause_from(exc)

        return _response_to_unified(response)

    def _complete_responses(
        self,
        model: str,
        system: Optional[str],
        messages: list[Message],
        max_tokens: int,
        tools: Optional[list[ToolDef]],
    ) -> CompletionResult:
        """gpt-5+ path via /v1/responses (supports tools + reasoning together).

        Stateless: the full message history is re-sent each turn. The model's
        ``reasoning`` items ARE emitted (at effort>=medium) but are deliberately
        dropped and never threaded back (``_responses_to_unified`` discards them;
        the unified ``Message`` type carries no reasoning block). This does not
        400 the follow-up tool turns because ``_messages_to_responses`` re-sends
        ``function_call`` items with ``call_id`` ONLY — never the server-issued
        ``fc_...`` item id — so the history reads as developer-synthesized tool
        history, which the Responses API accepts; the model simply re-reasons.
        ``store=False`` keeps analysed source off OpenAI's servers.

        LATENT TRAP: the reasoning-pairing enforcement is *id-keyed*. Do NOT start
        echoing the server ``fc_...``/``id`` on re-sent ``function_call`` items, nor
        re-send ``rs_...`` reasoning items under ``store=False`` without
        ``include=["reasoning.encrypted_content"]`` — either makes every follow-up
        turn 400 ("function_call provided without its required reasoning item").
        Proper reasoning threading needs encrypted_content + a reasoning block in
        the unified types + the agent.py echo — a deliberate, wider change.
        """
        request: dict[str, Any] = {
            "model": model,
            "input": _messages_to_responses(messages),
            "max_output_tokens": max(max_tokens, _RESPONSES_MIN_OUTPUT_TOKENS),
            "reasoning": {"effort": self._reasoning_effort},
            "store": False,
        }
        if system:
            request["instructions"] = system
        if tools:
            request["tools"] = [_tool_to_responses(t) for t in tools]

        wait_for_rate_limit()
        try:
            response = self._client.responses.create(**request)
        except (openai.APIStatusError, openai.APIConnectionError) as exc:
            raise _map_openai_exception(exc, report_rl=True) from redacted_cause_from(exc)

        return _responses_to_unified(response)

    def validate(self, model: str) -> None:
        # Probe the ENDPOINT the scan will actually use — a chat-completions
        # ping for a gpt-5 model would both 400 (max_tokens) and validate the
        # wrong endpoint (a proxy without Responses access would pass init then
        # fail every unit).
        try:
            if _use_responses_api(model, self._use_responses_api_override):
                # Prove the /v1/responses endpoint + model are reachable, pinging
                # with the SAME ``reasoning`` effort ``_complete_responses`` will
                # send. Effort values are model-specific (e.g. gpt-5.6 rejects
                # "minimal"), so omitting it would let a rejected effort pass init
                # and then 400 every unit — validate() must fail fast on it. A
                # structurally valid 200 (incl. status="incomplete" if reasoning
                # eats the budget) is success — only an exception fails init.
                self._client.responses.create(
                    model=model,
                    input="Reply with OK.",
                    max_output_tokens=1000,
                    reasoning={"effort": self._reasoning_effort},
                    store=False,
                )
            else:
                self._client.chat.completions.create(**{
                    "model": model,
                    _token_param(model): 1,
                    "messages": [{"role": "user", "content": "hi"}],
                })
        except (openai.APIStatusError, openai.APIConnectionError) as exc:
            # report_rl=False: a validate ping must not back off sibling workers.
            raise _map_openai_exception(exc, report_rl=False) from redacted_cause_from(exc)


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


def _messages_to_responses(messages: list[Message]) -> list[dict[str, Any]]:
    """Translate unified messages to Responses-API ``input`` items.

    System is sent via the ``instructions`` param (not an item). Per message, in
    order: tool RESULTS first (they reference a prior function_call), then plain
    text — matching how the API expects ``function_call_output`` to follow its
    call. Assistant tool calls become ``function_call`` items; assistant/user
    text becomes a role message. An assistant turn with only tool calls emits no
    role message (correct for Responses). Parallel tool calls preserve order.
    """
    out: list[dict[str, Any]] = []
    for message in messages:
        text_blocks = [b for b in message.content if isinstance(b, TextBlock)]
        tool_use_blocks = [b for b in message.content if isinstance(b, ToolUseBlock)]
        tool_result_blocks = [b for b in message.content if isinstance(b, ToolResultBlock)]

        if message.role == "user":
            for tr in tool_result_blocks:
                out.append({
                    "type": "function_call_output",
                    "call_id": tr.tool_use_id,
                    "output": tr.content,
                })
            if text_blocks:
                out.append({
                    "role": "user",
                    "content": "\n".join(b.text for b in text_blocks),
                })
        elif message.role == "assistant":
            if text_blocks:
                out.append({
                    "role": "assistant",
                    "content": "\n".join(b.text for b in text_blocks),
                })
            for tu in tool_use_blocks:
                out.append({
                    "type": "function_call",
                    "call_id": tu.id,
                    "name": tu.name,
                    "arguments": json.dumps(tu.input or {}),
                })
        else:  # pragma: no cover — Role is a closed Literal
            raise LLMResponseError(
                f"OpenAIAdapter: unknown message role {message.role!r}"
            )
    return out


def _tool_to_responses(tool: ToolDef) -> dict[str, Any]:
    # Responses function tools are FLATTENED (no nested "function"), and
    # ``strict`` must be explicit: OpenAnt's tool schemas are not strict-mode
    # compatible (no ``additionalProperties: false``), so strict=True would 400.
    return {
        "type": "function",
        "name": tool.name,
        "description": tool.description,
        "parameters": tool.input_schema,
        "strict": False,
    }


def _warn_unknown_output_item(kind: str) -> None:
    """One-time stderr warning for an unhandled Responses output item type."""
    should = False
    with _warned_unknown_output_items_lock:
        if kind not in _warned_unknown_output_items:
            _warned_unknown_output_items.add(kind)
            should = True
    if should:
        sys.stderr.write(
            f"warning: OpenAIAdapter saw an unhandled Responses output item "
            f"{kind!r}; ignoring it. If it carries output the pipeline needs, add "
            f"handling in _responses_to_unified.\n"
        )


def _responses_refusal_text(response: Any) -> Optional[str]:
    """#212: the provider's own refusal text on a filtered Responses call.

    Present-only scan of the message output parts (``output_text`` parts may
    carry a ``refusal`` sibling on gateway-routed calls); ``None`` when the
    provider supplied none. Never asserts WHO filtered.
    """
    for item in getattr(response, "output", None) or []:
        if getattr(item, "type", None) != "message":
            continue
        for part in getattr(item, "content", None) or []:
            if getattr(part, "type", None) in ("output_text", "refusal"):
                text = getattr(part, "refusal", None)
                if text:
                    return text
    return None


def _responses_to_unified(response: Any) -> CompletionResult:
    """Translate an OpenAI ``Response`` (Responses API) into unified types.

    Order matters: a hard failure, a filtered response, or an empty completion
    must NOT read as a clean ``end_turn`` — for a SAST tool that is a silent
    false-negative — so status is inspected before content, and a content-free
    result raises (mirrors the Chat Completions empty-``choices`` guard).
    """
    status = getattr(response, "status", None)
    if status in ("failed", "cancelled"):
        err = getattr(response, "error", None)
        detail = (getattr(err, "message", None) or str(err)) if err is not None else status
        raise LLMResponseError(redact_secrets(f"OpenAI Responses {status}: {detail}"))

    stop_reason: StopReason = "end_turn"
    if status == "incomplete":
        reason = getattr(getattr(response, "incomplete_details", None), "reason", None)
        if reason == "content_filter":
            # #212: do NOT assert WHO filtered ("moderation layer") — the
            # provider's own refusal text, when present, says (and this
            # reporter-verified case: it is usually the MODEL's safety
            # classifier, not a gateway). Carry the provider's words verbatim.
            refusal_text = _responses_refusal_text(response)
            # Redact per the module's invariant: every provider-supplied
            # string embedded in an error message passes redact_secrets()
            # (a gateway echoing secret-shaped text into a refusal must
            # not leak into persisted artifacts).
            detail = (f"; refusal: {redact_secrets(refusal_text)}"
                      if refusal_text else "")
            raise LLMRefusalError(
                "OpenAI refused the request (incomplete: content_filter)"
                f"{detail}"
            )
        elif reason == "max_output_tokens":
            stop_reason = "max_tokens"
        else:
            # Any other/unknown incomplete reason (incl. None): the response was
            # truncated, so it must NOT read as a clean end_turn even when it
            # carries partial content — the empty-content guard below only fires
            # on EMPTY content. Relabel as max_tokens (the honest "not a clean
            # finish" signal) and warn once, mirroring the chat path's
            # unknown-finish_reason handling.
            _warn_unknown_responses_status(f"incomplete:{reason!r}")
            stop_reason = "max_tokens"
    elif status not in (None, "completed"):
        # An unrecognized / non-terminal top-level status (in_progress, queued,
        # requires_action, or a future value) on a synchronous responses.create
        # is abnormal; failed/cancelled already raised above. A partial body must
        # not be laundered into a clean end_turn.
        _warn_unknown_responses_status(str(status))
        stop_reason = "max_tokens"

    content_blocks: list[ContentBlock] = []
    for item in getattr(response, "output", None) or []:
        itype = getattr(item, "type", None)
        if itype == "message":
            for part in getattr(item, "content", None) or []:
                ptype = getattr(part, "type", None)
                if ptype == "output_text":
                    text = getattr(part, "text", "")
                    if text:
                        content_blocks.append(TextBlock(text=text))
                elif ptype == "refusal":
                    # A refusal is a nested content part (NOT a top-level item and
                    # NOT part of output_text) — surface as a typed error.
                    raise LLMRefusalError(
                        f"OpenAI refused the request "
                        f"(refusal: {getattr(part, 'refusal', '')!r})"
                    )
                else:
                    _warn_unknown_output_item(f"message.{ptype}")
        elif itype == "function_call":
            arguments = getattr(item, "arguments", "") or ""
            try:
                input_dict = json.loads(arguments) if arguments else {}
            except json.JSONDecodeError:
                _warn_bad_tool_json(getattr(item, "name", "<unknown>"))
                input_dict = {}
            content_blocks.append(ToolUseBlock(
                id=item.call_id,
                name=item.name,
                input=input_dict,
            ))
        elif itype == "reasoning":
            # Internal chain — deliberately kept out of unified content.
            pass
        else:
            _warn_unknown_output_item(str(itype))

    # ``incomplete`` (max_output_tokens) wins over tool_use: a function_call in a
    # truncated response may carry incomplete-JSON arguments, so don't advertise
    # it as an actionable tool call.
    if any(isinstance(b, ToolUseBlock) for b in content_blocks) and stop_reason != "max_tokens":
        stop_reason = "tool_use"

    if not content_blocks:
        raise LLMResponseError(
            f"OpenAI Responses returned no usable content (status={status!r}); the "
            "request may have been truncated (reasoning consumed the budget) or filtered"
        )

    usage = getattr(response, "usage", None)
    return CompletionResult(
        content=content_blocks,
        input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
        output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
        stop_reason=stop_reason,
        raw=response,
    )


def _response_to_unified(
    response: Any, *, adapter: str = "OpenAIAdapter"
) -> CompletionResult:
    """Translate an OpenAI ChatCompletion response into our types.

    ``adapter`` labels error/warning text so a derivative adapter that reuses
    this translation (e.g. OpenRouter) attributes failures to itself, not to
    ``OpenAIAdapter``.
    """
    choices = getattr(response, "choices", None) or []
    if not choices:
        # No choices → nothing the pipeline can act on. Surface it via
        # the taxonomy instead of letting an IndexError escape unmapped
        # (mirrors the Gemini empty-``candidates`` guard); for a security
        # tool an empty end_turn would read as a clean, passing result.
        raise LLMResponseError(
            f"{adapter} returned no choices (empty completion); the request "
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
            _warn_bad_tool_json(getattr(tc.function, "name", "<unknown>"), adapter=adapter)
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
    # #212: carry the provider's own refusal words (``message.refusal``)
    # verbatim when present, and never assert WHO filtered without
    # evidence — the "moderation layer" phrasing sent #212's reporter
    # chasing a route change when the refusals were the model's own
    # safety classifier.
    if raw_finish == _OPENAI_CONTENT_FILTER_REASON:
        refusal_text = getattr(getattr(choice, "message", None), "refusal", None)
        # Redact per the module invariant (see the Responses path).
        detail = (f"; refusal: {redact_secrets(refusal_text)}"
                  if refusal_text else "")
        raise LLMRefusalError(
            f"{adapter} refused the request "
            f"(finish_reason='content_filter'){detail}"
        )

    # An empty completion -- no text AND no tool calls (``message.content`` is
    # None/empty with no ``tool_calls``) -- carries nothing the pipeline can act
    # on. Surface it via the taxonomy instead of returning an empty end_turn
    # (mirrors the Responses path's no-usable-content guard and the Anthropic/
    # Gemini adapters); for a SECURITY tool an empty end_turn would read as a
    # clean, passing result. A tool-use-only response is VALID and not caught
    # here because ``content_blocks`` is non-empty. Refusal/content_filter is the
    # more specific signal and already raised above.
    if not content_blocks:
        raise LLMResponseError(
            f"{adapter} returned an empty completion (no text or tool calls); the "
            "request may have been filtered or the response was malformed"
        )

    if raw_finish not in _OPENAI_FINISH_REASONS:
        should_warn = False
        with _warned_finish_reasons_lock:
            if raw_finish not in _warned_finish_reasons:
                _warned_finish_reasons.add(raw_finish)
                should_warn = True
        if should_warn:
            sys.stderr.write(
                f"warning: {adapter} received unknown finish_reason "
                f"{raw_finish!r}; treating as 'max_tokens' (not a clean finish) so "
                f"a truncated/abnormal chat response is not read as complete. Add "
                f"this value to StopReason in utilities/llm/adapter.py and "
                f"_OPENAI_FINISH_REASONS if OpenAI added a new termination reason.\n"
            )

    usage = getattr(response, "usage", None)
    return CompletionResult(
        content=content_blocks,
        input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
        output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
        # BUG-7: an UNKNOWN finish_reason defaults to "max_tokens", not "end_turn" —
        # the chat-path analog of _responses_to_unified's abnormal-status handling, so
        # a proxy/future-value truncation isn't laundered into a clean completion.
        # Known reasons (stop/tool_calls/length) use their explicit mapping above.
        stop_reason=_OPENAI_FINISH_REASONS.get(raw_finish, "max_tokens"),
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
