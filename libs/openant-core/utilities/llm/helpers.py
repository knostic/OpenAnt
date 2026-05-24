"""Convenience helpers built on top of the adapter interface.

Most pipeline call sites send a single text prompt and get a single
text response back — Stage 1 detect, JSON correction, single-shot
enhance, report-remediation. These don't need the full
``adapter.complete()`` plumbing (block construction, content
inspection, token tracking) at every call site.

:func:`simple_text` is that shortcut. Tool-use callers
(``finding_verifier`` and ``agentic_enhancer/agent``) keep talking
to ``binding.adapter.complete()`` directly because they need to
inspect content blocks and continue the conversation.
"""

from __future__ import annotations

from typing import Optional

from ..llm_client import TokenTracker, get_global_tracker
from .adapter import Message, TextBlock
from .registry import PhaseBinding


def lookup_pricing(binding: PhaseBinding) -> Optional[dict]:
    """Return the adapter's price entry for ``binding.model``, or None.

    Centralises the ``getattr(binding.adapter, "pricing", {}).get(...)``
    pattern that otherwise repeats at every call site that records a
    completion against the tracker. Returning ``None`` when the
    adapter has no entry lets the tracker emit its one-time
    unknown-model warning instead of guessing the rate.
    """
    return getattr(binding.adapter, "pricing", {}).get(binding.model)


def simple_text(
    binding: PhaseBinding,
    prompt: str,
    *,
    system: Optional[str] = None,
    max_tokens: int = 8192,
    tracker: Optional[TokenTracker] = None,
) -> str:
    """Send one user-prompt completion, return the concatenated text reply.

    Args:
        binding: Phase binding from :meth:`PhaseRegistry.get`. The
            adapter + model embedded in it are what the call actually
            uses — no caller-side model selection.
        prompt: Plain text user message.
        system: Optional system prompt.
        max_tokens: Upper bound on response length.
        tracker: Token tracker to record this call against. Defaults
            to the global tracker so callers that don't care about
            multi-tracker setups don't have to thread one through.

    Returns:
        Concatenated text from every :class:`TextBlock` in the
        response. Non-text blocks (e.g. a stray ``tool_use`` if the
        model misbehaves) are dropped — this is the "I just want
        text" helper, so callers that need richer handling should
        use ``binding.adapter.complete()`` directly.
    """
    used_tracker = tracker if tracker is not None else get_global_tracker()

    messages = [Message(role="user", content=[TextBlock(prompt)])]
    result = binding.adapter.complete(
        model=binding.model,
        system=system,
        messages=messages,
        max_tokens=max_tokens,
    )
    # Pricing lives on the adapter (issue #65 §9). Pass it through
    # so the tracker isn't forced to consult a shared global per
    # provider — the result is per-model accuracy without
    # cross-provider drift.
    used_tracker.record_call(
        model=binding.model,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        pricing=lookup_pricing(binding),
    )

    return "\n".join(
        block.text for block in result.content if isinstance(block, TextBlock)
    )
