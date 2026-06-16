"""LLM adapter interface — the contract every provider plugin satisfies.

Design notes (read these before adding an adapter):

1. **Minimal surface.** The protocol exposes ``complete()`` and
   ``validate()``. That's it. No streaming, no vision, no system
   tools, no prompt caching, no batching — the pipeline doesn't use
   them today, and adding them later is cheaper than removing them
   from a frozen interface. Adapters are free to use those features
   internally for efficiency.

2. **Unified content blocks are the contract.** Every adapter
   translates ``TextBlock`` / ``ToolUseBlock`` / ``ToolResultBlock``
   to and from its provider's native types. A future Gemini adapter
   that invents a ``ThinkingBlock`` to expose Gemini's reasoning
   field is welcome to do so internally but MUST surface only the
   three block kinds defined here. Otherwise pipeline code that
   inspects ``result.content`` breaks the moment someone swaps
   providers — defeating the point of the adapter layer.

3. **``supports_tools`` is static.** Phases that need tool calling
   (``verify``, agentic ``enhance``) check this attribute at
   config-validation time, before any call is made. If your
   provider supports tool use, set it to ``True``; if not, ``False``.
   A ``False`` adapter is still useful for the simple-completion
   phases.

4. **Errors are typed.** Map your provider's auth error to
   :class:`LLMAuthError`, its 429 to :class:`LLMRateLimitError`,
   etc. The pipeline's retry/backoff and user-facing error messages
   are keyed on these classes, not on provider-native exception
   types.

5. **Tracking is the registry's job, not yours.** ``complete()``
   returns raw token counts; the registry threads them through
   ``TokenTracker``. Don't update tracking from inside the adapter.

If you're reading this because you're adding a provider: also read
``docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Content blocks
# ---------------------------------------------------------------------------
#
# Three kinds. Adapters MUST translate everything they receive into one of
# these on the way back to the pipeline. Tool use is modeled as paired
# ``ToolUseBlock`` (assistant emits) + ``ToolResultBlock`` (next user turn
# carries) so the unified message stream is order-preserving and
# stateless — no hidden tool_call_id juggling outside the adapter layer.


@dataclass(frozen=True)
class TextBlock:
    """Plain text from the model (or from the user prompt)."""

    text: str


@dataclass(frozen=True)
class ToolUseBlock:
    """Model is asking us to invoke a tool.

    Attributes:
        id: Provider-issued identifier for this tool call. Opaque to
            the pipeline — the only contract is that the matching
            ``ToolResultBlock.tool_use_id`` in a later user turn
            equals this value.
        name: Tool name as advertised in :class:`ToolDef`.
        input: Tool arguments, already JSON-deserialised into a dict.
    """

    id: str
    name: str
    input: dict[str, Any]


@dataclass(frozen=True)
class ToolResultBlock:
    """Pipeline's response to a prior ``ToolUseBlock``.

    Attributes:
        tool_use_id: Matches the ``id`` of the ``ToolUseBlock`` that
            triggered this result.
        content: JSON-serialised tool output. Adapters wrap this in
            whatever shape the provider expects.
        name: Originating tool's name, copied from the matching
            ``ToolUseBlock.name``. Optional — Anthropic and OpenAI key
            tool results on ``tool_use_id`` and ignore this. The Gemini
            adapter REQUIRES it: Gemini matches a ``function_response``
            to its ``function_call`` by NAME, not id, so a result built
            without ``name`` would never match its call. Defaults to
            ``None`` so existing call sites and adapters keep working.
    """

    tool_use_id: str
    content: str
    name: Optional[str] = None


ContentBlock = TextBlock | ToolUseBlock | ToolResultBlock


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


Role = Literal["user", "assistant"]


@dataclass(frozen=True)
class Message:
    """One turn in a conversation.

    A ``user`` turn may carry text and/or ``ToolResultBlock`` content.
    An ``assistant`` turn may carry text and/or ``ToolUseBlock``
    content. System prompts are passed as a separate parameter to
    ``complete()``, not as messages — that's how most providers
    model it natively and we don't gain anything by pretending
    otherwise.

    ``content`` is stored as a tuple so the dataclass's ``frozen=True``
    is honored at every level — passing a list at construction is
    accepted and normalised. A frozen dataclass that held a mutable
    list would let callers do ``msg.content.append(...)`` and
    surprise themselves; the tuple makes that a ``TypeError``.
    """

    role: Role
    content: tuple[ContentBlock, ...]

    def __post_init__(self):
        # Accept list for ergonomic call-site construction
        # (``Message(role="user", content=[TextBlock(...)])``) and
        # normalise to tuple. ``object.__setattr__`` is the
        # documented escape hatch for assigning on frozen
        # dataclasses during ``__post_init__``.
        if isinstance(self.content, list):
            object.__setattr__(self, "content", tuple(self.content))


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolDef:
    """A tool the model is allowed to call.

    ``input_schema`` is a JSON Schema dict. Most providers accept JSON
    Schema directly (Anthropic, OpenAI, Gemini all do); adapters that
    need a different format translate at call time.
    """

    name: str
    description: str
    input_schema: dict[str, Any]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


StopReason = Literal[
    "end_turn",      # model decided it was done
    "tool_use",      # model emitted a tool_use block expecting a result
    "max_tokens",    # ran into the max_tokens cap
    "stop_sequence", # hit a stop sequence (rare in our pipeline)
]


@dataclass
class CompletionResult:
    """What ``complete()`` returns.

    Attributes:
        content: One or more content blocks the model emitted, in
            order. Pipeline code inspects ``content`` to decide
            whether to execute tool calls and loop. Stored as a
            tuple so accidental mutation by callers becomes a
            ``TypeError`` (matches the immutability invariant
            ``Message.content`` already enforces).
        input_tokens: From the provider's usage metadata.
        output_tokens: Ditto.
        stop_reason: Normalised across providers. The pipeline's
            agentic loops branch on ``"tool_use"`` to know whether
            to execute tools and continue.
        raw: Provider-native response object, kept for adapter-side
            diagnostics. Pipeline code MUST NOT depend on this — it
            varies by provider and breaks the abstraction.
    """

    content: tuple[ContentBlock, ...]
    input_tokens: int
    output_tokens: int
    stop_reason: StopReason
    raw: Any = field(default=None, repr=False)

    def __post_init__(self):
        # Accept list for ergonomic construction by adapters; freeze
        # to tuple before returning to pipeline code.
        if isinstance(self.content, list):
            self.content = tuple(self.content)


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class LLMError(Exception):
    """Base for every adapter-surfaced error.

    The pipeline catches this directly only as a last resort; most
    call sites care about one of the concrete subclasses below.
    """


class LLMAuthError(LLMError):
    """Credentials rejected by the provider (401/403)."""


class LLMRateLimitError(LLMError):
    """Provider returned 429 or equivalent.

    Attributes:
        retry_after: Seconds to wait before retrying, if the
            provider reported one. ``None`` means "we don't know".
    """

    def __init__(self, message: str, *, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


class LLMConnectionError(LLMError):
    """DNS, TCP, TLS, or timeout failure reaching the endpoint."""


class LLMNotFoundError(LLMError):
    """Model name doesn't exist at this provider, or path 404."""


class LLMResponseError(LLMError):
    """Provider returned a structurally invalid response.

    Used when the response parses but doesn't match what the protocol
    requires (e.g. missing usage block, malformed tool_use). Distinct
    from connection errors and rate limits so the pipeline can decide
    whether to retry.
    """


class LLMRefusalError(LLMResponseError):
    """Provider refused to answer or content-filtered the response.

    Raised when a completion's finish/stop reason explicitly signals a
    refusal or safety block — Anthropic ``stop_reason == "refusal"``,
    OpenAI ``finish_reason == "content_filter"``, or a Gemini candidate
    whose ``finish_reason`` is in the safety/blocked set (SAFETY,
    RECITATION, PROHIBITED_CONTENT, BLOCKLIST, SPII, …).

    Subclasses :class:`LLMResponseError` on purpose: every existing
    ``except LLMResponseError`` handler keeps catching these, so the
    pipeline's retry/error-reporting paths don't need to change. The
    distinct type only matters to a caller that wants to treat a
    deliberate refusal differently from a malformed response — for a
    SECURITY tool that distinction is load-bearing, because a silently
    swallowed refusal would otherwise read as a clean, finding-free pass.
    """


# ---------------------------------------------------------------------------
# The adapter protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class LLMAdapter(Protocol):
    """Every provider plugin implements this.

    Adapters are constructed by the registry with the resolved
    provider config (api_key, base_url, etc.). They are stateless
    dispatchers: ``complete()`` may be called concurrently from
    multiple threads on the same instance.

    Required class-level attributes (Protocol-enforced via
    ``runtime_checkable`` isinstance checks):

    * ``name``: short string used as the ``type`` field in
      config.json's ``llm_providers`` entries. E.g. ``"anthropic"``,
      ``"openai"``, ``"google"``.
    * ``supports_tools``: ``True`` iff this provider implements the
      tool-use round-trip described in this module's docstring.

    Optional class-level attribute (NOT Protocol-enforced):

    * ``pricing``: ``dict[str, {"input": $/Mtok, "output": $/Mtok}]``
      mapping every model ID this adapter ships rates for to its
      per-million-token costs. Models absent from the dict report
      $0 with a one-time warning via the token tracker — issue #65
      forbids guessing across providers because the prior "fall back
      to Sonnet rates" path produced plausible-but-wrong totals for
      non-Claude runs. Pricing lives on the adapter (not in a shared
      global) so each provider PR owns its rates and there's no
      cross-provider drift surface. Callers query it via
      ``getattr(adapter, "pricing", {})``; an adapter that omits the
      attribute entirely is conforming, it just produces $0 cost
      reports.
    """

    name: str
    supports_tools: bool

    def complete(
        self,
        *,
        model: str,
        system: Optional[str],
        messages: list[Message],
        max_tokens: int,
        tools: Optional[list[ToolDef]] = None,
    ) -> CompletionResult:
        """Send one completion request, return the parsed result.

        Args:
            model: Provider-specific model identifier (e.g.
                ``"claude-opus-4-6"``, ``"gemini-2.5-flash"``).
            system: Optional system prompt. Adapters pass it through
                their provider's native system-prompt mechanism.
            messages: Conversation history. The last message may be
                a ``user`` turn carrying ``ToolResultBlock`` content
                (continuing a tool-use loop) or fresh text.
            max_tokens: Upper bound on response length.
            tools: When non-empty, the model may emit
                ``ToolUseBlock`` content and ``stop_reason`` may be
                ``"tool_use"``. Adapters whose ``supports_tools`` is
                ``False`` MUST raise :class:`LLMResponseError` if
                ``tools`` is non-empty, rather than silently dropping
                the tools.

        Raises:
            LLMAuthError, LLMRateLimitError, LLMConnectionError,
            LLMNotFoundError, LLMResponseError. Provider-native
            exceptions are mapped before being raised.
        """
        ...

    def validate(self, model: str) -> None:
        """Probe the endpoint+model with a minimal 1-token call.

        Used at ``openant init`` time to fail loud BEFORE the user
        starts a paid scan. The registry calls this once per unique
        ``(provider, model)`` pair referenced by the resolved
        llm-config, so a config that uses three distinct models on
        the same provider triggers three probes — that's by design:
        we want to catch typo'd model names too, not just bad keys.

        Implementations should send the cheapest possible request
        the provider supports (e.g. ``max_tokens=1``).

        Raises:
            LLMAuthError, LLMConnectionError, LLMNotFoundError as
            appropriate. Success returns ``None``.
        """
        ...
