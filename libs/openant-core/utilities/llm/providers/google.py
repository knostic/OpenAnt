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

import httpcore
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
from .._pricing import LazyProviderPricing
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
# We verified (and tests/test_llm_sdk_contract_floor.py re-derives against the
# INSTALLED SDK) that
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


def _gemini_output_tokens(usage: Any) -> int:
    """Gemini's output-token billing rule, as the single source of truth.

    Gemini bills output as candidates + thoughts (thinking models like
    gemini-2.5-* emit ``thoughts_token_count``); count both so the cost
    isn't undercounted. ``tests/test_llm_sdk_contract_floor.py`` drives
    this against the INSTALLED SDK's ``usage_metadata`` type — a field
    rename in a future google-genai turns that floor RED.
    """
    return (getattr(usage, "candidates_token_count", 0) or 0) + (
        getattr(usage, "thoughts_token_count", 0) or 0
    )


def _extract_usage_details(usage: Any) -> Optional[dict]:
    """Pass-through capture (#211): Gemini usage detail fields.

    Copies ``thoughts_token_count`` / ``cached_content_token_count``
    VERBATIM when present; ``None`` otherwise (absent ≠ 0). Never feeds
    the cost formula — note ``thoughts_token_count`` is ALREADY summed
    into ``output_tokens`` above (Gemini bills candidates + thoughts as
    output), so these captured fields are informational for bill
    reconciliation, not additional billed tokens.
    """
    if usage is None:
        return None
    details: dict = {}
    for field_name in ("thoughts_token_count", "cached_content_token_count"):
        value = getattr(usage, field_name, None)
        if value is not None:
            details[field_name] = value
    return details or None


class GoogleAdapter:
    """:class:`LLMAdapter` implementation backed by ``google.genai.Client``."""

    name = "google"
    supports_tools = True

    # Per-million-token rates. Gemini Pro has tiered pricing (under
    # 200K context vs over); we ship the more common <200K rates.
    # Users with long-context scans may need to override locally.
    # Models absent here report $0 + warning per issue #65 §9.
    # Resolved lazily from config/models.json (the shared registry) on
    # first access; see utilities/llm/_pricing.py.
    pricing = LazyProviderPricing("google")

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_retries: int = 5,
        request_timeout: Optional[int] = 600,
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
                way (``HttpRetryOptions.attempts`` is a declared field of
                the installed SDK — tests/test_llm_sdk_contract_floor.py
                re-derives the field's existence on every run; the attempt-
                COUNTING semantics below are documented, not machine-checked);
                on top of the SDK's own
                retry, our rate limiter coordinates 429 backoff across
                workers — same division of labour as the other adapters.
            request_timeout: Per-request HTTP timeout in SECONDS, mapped
                to ``HttpOptions.timeout`` (MILLISECONDS). #604: genai's
                default is explicitly UNBOUNDED (the SDK inserts
                ``timeout=None``; the other five adapters inherit their
                SDK's finite 600 s default), so this adapter defaults to
                **600** for parity. ``None`` is the explicit unbounded
                opt-out (the pre-#604 behavior). ``<= 0`` is rejected —
                genai's timeout handling is truthiness-guarded, so a ``0``
                would be SILENT-unbounded. Semantics, stated honestly:
                the value bounds each transport OPERATION (httpx
                connect/read/write/pool) — each read resets the read
                timer, so a slow-drip response can outlast it; a
                fully-stalled request times out at the configured value
                PER ATTEMPT, with the SDK's own retry layer (tenacity
                retries ``httpx.TimeoutException``/``ConnectError`` with
                jittered backoff) and the pipeline's retry passes
                multiplying on top. Note the connect leg: a single
                HttpOptions timeout value bounds ALL FOUR httpx phases,
                so connect waits up to the same 600 s here where the five
                other adapters' SDKs carry ``connect=5`` — a connect-level
                black hole blocks ~600 s per attempt (still finite, and
                documented rather than worked around; a per-leg timeout
                would need genai's client_args plumbing). genai also
                couples the client timeout to an ``X-Server-Timeout:
                ceil(seconds)`` header on every request — a
                server-directed hint genai is alone in sending (every
                SDK discloses its client timeout in SOME header form:
                the anthropic/openai family's stainless headers already
                do), but this one is an instruction to the server, which
                is what a security scanner's fingerprint surface grows
                by. An adapter adopts this knob by declaring the
                ``request_timeout`` constructor kwarg (the
                ``build_adapter`` capability check keys on it).
            _client: Injected SDK instance for testing.
        """
        # #604: the rejection is an UNCONDITIONAL constructor contract —
        # it fires before the ``_client`` injection early-return (an
        # injected caller passing 0 must not slip the silent-unbounded
        # trap downstream). Bools are rejected explicitly (``isinstance(
        # True, int)`` is True — a ``True`` would silently become 1000 ms)
        # and non-ints too (a float would defer to pydantic's ValidationError).
        if request_timeout is not None and (
                isinstance(request_timeout, bool)
                or not isinstance(request_timeout, int)
                or request_timeout <= 0):
            raise ValueError(
                f"request_timeout must be a positive integer (seconds) or "
                f"None (unbounded), got {request_timeout!r}"
            )
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
        # #604: ``request_timeout`` (seconds) maps to
        # ``HttpOptions.timeout`` (milliseconds).
        http_options_fields: dict[str, Any] = {}
        if base_url is not None:
            http_options_fields["base_url"] = base_url
        if request_timeout is not None:
            http_options_fields["timeout"] = request_timeout * 1000
        if max_retries is not None:
            # F3 (round-5): the SDK's ``attempts`` field is the "Maximum
            # number of attempts, INCLUDING the original request" (verified
            # against the installed google-genai (the FIELD is re-derived by
            # tests/test_llm_sdk_contract_floor.py; this counting SEMANTICS is
            # documented, not machine-checked): "If 0 or 1, it means no
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
                kind, g_delay = _google_429_details(exc)
                if retry_after is None:
                    retry_after = g_delay  # #663: RetryInfo carries the wait
                # #716 hunt defect 3: quota never arms the all-worker pause
                if kind != "quota":
                    report_rate_limit(retry_after)
                raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after,
                                        kind=kind) from redacted_cause_from(exc)
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except genai_errors.ServerError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except genai_errors.APIError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        # 4b (the real-transport guard's catch): the previous clause named
        # six httpx classes individually and MISSED ReadError /
        # RemoteProtocolError (a mid-connection reset escaped untyped —
        # proven live by the accept-then-close guard test).
        # httpx.TransportError is the single base of every transport error
        # in the httpx family (connect, read, write, pool, remote-protocol,
        # the timeout family) — strictly wider than the old list, never
        # narrower. The httpcore bases are BELT-AND-BRACES for a raw
        # httpcore exception arriving un-wrapped (httpx maps httpcore into
        # its OWN hierarchy — httpx.ReadError is NOT httpcore.ReadError;
        # the families chain via `raise ... from`, neither inherits the
        # other). httpcore's roots are NetworkError / ProtocolError /
        # TimeoutException (there is no httpcore.TransportError); all three
        # are caught. A transport-backend flip (the httpx2 direction the
        # anthropic/openai SDKs already took) changes which family arrives;
        # this clause and the guard tests keep the mapping honest.
        except (httpx.TransportError, httpcore.NetworkError, httpcore.ProtocolError, httpcore.TimeoutException) as exc:
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
                kind, g_delay = _google_429_details(exc)
                if retry_after is None:
                    retry_after = g_delay  # #663: RetryInfo carries the wait
                raise LLMRateLimitError(redact_secrets(str(exc)), retry_after=retry_after,
                                        kind=kind) from redacted_cause_from(exc)
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except genai_errors.ServerError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        except genai_errors.APIError as exc:
            raise LLMResponseError(redact_secrets(str(exc))) from redacted_cause_from(exc)
        # The same transport clause as complete()'s (see its comment).
        except (httpx.TransportError, httpcore.NetworkError, httpcore.ProtocolError, httpcore.TimeoutException) as exc:
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
        # #212: a prompt-level policy block IS a refusal (the same
        # deterministic-refusal family as a candidate-level SAFETY finish)
        # — typed accordingly and marker-aligned so the verify phase's
        # print-time refused count derives for this family too. Only when
        # the provider actually SUPPLIED a block reason: an empty-candidates
        # response with no prompt_feedback evidence stays a plain response
        # error (retryable shape upstream), never an evidence-free refusal
        # claim (fable D2 — the fix's own no-assertion-beyond-evidence rule).
        if block_reason:
            raise LLMRefusalError(
                f"Gemini refused the request "
                f"(prompt blocked: {block_reason})"
            )
        raise LLMResponseError(
            f"Gemini returned no candidates (empty response; no prompt "
            "block reason supplied)"
        )

    # Usage metadata lives on response.usage_metadata for the new SDK.
    usage = getattr(response, "usage_metadata", None)
    if usage is not None:
        input_tokens = getattr(usage, "prompt_token_count", 0) or 0
        output_tokens = _gemini_output_tokens(usage)
    usage_details = _extract_usage_details(usage)

    # R4-2: a safety/blocked candidate finish reason is the more
    # specific signal — raise it regardless of whether the candidate
    # carried partial text or a function_call. Gemini reports these as
    # SAFETY / RECITATION / BLOCKLIST / PROHIBITED_CONTENT / SPII.
    if raw_finish in _GEMINI_REFUSAL_FINISH_REASONS:
        # #212: message aligned with the cross-adapter refusal marker
        # ("refused the request") so the verify phase's print-time refused
        # count derives correctly for every provider family.
        raise LLMRefusalError(
            f"Gemini refused the request (finish_reason={raw_finish!r}); "
            "the candidate was withheld for safety or policy reasons"
        )

    # R4-1: a candidate that carried NO usable content -- no TextBlock and no
    # function_call ToolUseBlock (a thinking-only/blank candidate, or one whose
    # parts were all dropped) -- has nothing the pipeline can act on. Surface it
    # via the taxonomy instead of returning an empty end_turn, which pipeline
    # code would read as a clean (passing) result -- for a security tool that
    # masks a blank as a non-finding. Mirrors the no-candidates guard above and
    # the Anthropic / OpenAI empty-content guards. A tool-use-only candidate is
    # VALID and not caught here because content_blocks is non-empty. Refusal is
    # the more specific signal and already raised above.
    if not content_blocks:
        # #569: the budget wording is DETERMINISTIC-CLASS-ONLY — a
        # MAX_TOKENS stop is the thinking-budget exhaustion (the raised-cap
        # retry class); every other empty candidate (filtered/malformed)
        # keeps the #292 same-cap rationale and must NOT carry the marker.
        if raw_finish in ("MAX_TOKENS", "FinishReason.MAX_TOKENS"):
            raise LLMResponseError(
                "Gemini returned a candidate with no usable content (empty "
                "completion); the response was truncated — a thinking "
                "model consumed the token budget before emitting output"
            )
        raise LLMResponseError(
            "Gemini returned a candidate with no usable content (empty "
            "completion); the response may have been filtered or malformed"
        )

    stop_reason: StopReason
    has_tool_use = any(isinstance(b, ToolUseBlock) for b in content_blocks)
    mapped = _GEMINI_FINISH_REASONS.get(raw_finish)
    if mapped is None:
        # SAFETY/RECITATION/BLOCKLIST refusals already raised above; a remaining
        # unmapped value is an UNKNOWN/abnormal termination. R2-C + round-5: it is
        # not a clean finish AND it wins over tool_use — Gemini emits a function_call
        # part even on an abnormal termination, so an unknown reason carrying a tool
        # call must NOT be laundered into a clean tool_use. Warn once, treat as
        # max_tokens (mirrors the OpenAI adapter; checked BEFORE has_tool_use).
        should_warn = False
        with _warned_finish_reasons_lock:
            if raw_finish not in _warned_finish_reasons:
                _warned_finish_reasons.add(raw_finish)
                should_warn = True
        if should_warn:
            sys.stderr.write(
                f"warning: GoogleAdapter received unknown finish_reason "
                f"{raw_finish!r}; treating as 'max_tokens' (not a clean finish). "
                f"Add this value to StopReason in utilities/llm/adapter.py and "
                f"_GEMINI_FINISH_REASONS if Gemini added a new termination "
                f"reason.\n"
            )
        stop_reason = "max_tokens"
    elif mapped == "max_tokens":
        # R2-A: a TRUNCATED response wins over tool_use. Gemini emits a
        # function_call part even when it hit the token cap, so tool_use must
        # not mask MAX_TOKENS (mirrors the OpenAI responses path) — otherwise a
        # truncated finish call reaches the consumer as a clean tool_use and is
        # accepted as a complete verdict/classification (a silent false-negative).
        stop_reason = "max_tokens"
    elif has_tool_use:
        # A KNOWN, non-truncation finish reason with a function_call part: Gemini
        # doesn't use a dedicated finish_reason for tool calls, so the part IS the
        # signal.
        stop_reason = "tool_use"
    else:
        stop_reason = mapped

    return CompletionResult(
        content=content_blocks,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        usage_details=usage_details,
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


def _google_429_details(exc: Any) -> tuple[str, Optional[float]]:
    """Classify a genai 429 from its structured details (#663).

    Google's 429 (RESOURCE_EXHAUSTED) is EITHER a short-window throttle
    (RPM/TPM -- bounded backoff helps) OR a hard quota (a daily cap, an
    explicitly-enforced zero -- backoff does not restore access). The
    discriminator lives in the error details, NEVER in the prose:
    - QuotaFailure.violations[].quotaId carrying "PerDay" -> quota;
    - RetryInfo.retryDelay ("12s") -> a throttle with a KNOWN wait,
      surfaced as retry_after (Google's 429s never carry the header);
    - bare RESOURCE_EXHAUSTED with neither -> throttle (the vendor's own
      troubleshooting doc: exponential backoff).
    """
    # T1 round-1 (F3): the genai SDK sets APIError.details = the ENTIRE
    # response JSON ({"error": {...}}) -- there is no .error/._error attr.
    body = getattr(exc, "_error", None) or getattr(exc, "error", None)
    details = None
    if isinstance(body, dict):
        details = body.get("details")
    if not isinstance(details, list):
        raw = getattr(exc, "details", None)  # the full response dict
        if isinstance(raw, dict):
            inner = raw.get("error")
            if isinstance(inner, dict):
                details = inner.get("details")
    if not isinstance(details, list):
        return "throttle", None
    retry_after = None
    for d in details:
        if not isinstance(d, dict):
            continue
        dtype = d.get("@type", "")
        if "QuotaFailure" in dtype:
            violations = d.get("violations") or []
            for v in violations:
                quota_id = str(v.get("quotaId", ""))
                # An explicitly-enforced zero is a quota whatever the
                # metric's window: the entitlement IS the zero — backoff
                # cannot restore it (the docstring's own promise, read).
                quota_value = str(v.get("quotaValue", "")).strip()
                if ("PerDay" in quota_id or "perday" in quota_id.lower()
                        or quota_value in ("0", "0.0")):
                    return "quota", None
        elif "RetryInfo" in dtype:
            delay = str(d.get("retryDelay", ""))
            if delay.endswith("s"):
                try:
                    retry_after = float(delay[:-1])
                except ValueError:
                    pass
    return "throttle", retry_after


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
