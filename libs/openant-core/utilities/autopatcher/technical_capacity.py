"""Fix B -- per-call technical source-evidence capacity.

Replaces the arbitrary stage-local character constants that used to gate
whether already-resolved repository evidence ever reached an LLM call
(pre-Fix-B: ``evidence_fusion.DEFAULT_MAX_CHARS`` = 4,000 for the
"planner_evidence" stage, ``remediation_planner.FINAL_TARGET_SLICE_MAX_CHARS``
= 10,000 for "final_target_slice", ``remediation_planner.
MAX_POST_PATCH_SOURCE_CHARS`` = 6,000 for "post_patch_recovery" -- see
``context_budget.py``'s own module docstring for the full history of what
those numbers were and why they were never technically justified). A real
regression demonstrated the failure mode directly: a Planning prompt
reported requested repository evidence as successfully RESOLVED while the
corresponding full-file source was OMITTED purely because a small,
arbitrary character ceiling was reached -- not because the evidence didn't
exist, was unavailable, or because investigation was exhausted.

This module computes ONE thing: how many characters of repository source
evidence may safely be added to a specific LLM call without risking a real
provider context-window overflow. It is NOT a resource/cost budget (see
``context_budget.py``'s own updated docstring) -- Fix B implements no
user-facing spend limit; this is purely a technical per-call capacity
computation, always active, never optional, and never gated by any CLI
policy flag.

The one and only approximation in the whole computation is
``CONSERVATIVE_CHARS_PER_TOKEN`` -- no tokenizer exists anywhere in this
codebase, and none is added here (a real tokenizer would need to be
provider-specific, adding a dependency per provider in
``core.model_registry._VALID_PROVIDERS``, for more precision than a
release-hardening fix needs -- see the Fix B design amendment this
implements). Every other quantity in the equation (system-prompt length,
vulnerability-report length, any other already-rendered non-source prompt
text) is measured EXACTLY via ``len()`` on a string already in hand at the
point a caller asks for a ceiling -- never estimated.

The equation::

    available_input_tokens = total_context_tokens
                              - reserved_output_tokens - SAFETY_MARGIN_TOKENS
    available_input_chars  = available_input_tokens * CONSERVATIVE_CHARS_PER_TOKEN
    source_capacity_chars  = available_input_chars - known_overhead_chars

``total_context_tokens`` comes from ``core.model_registry.
context_window_tokens(provider, model)`` when the model registry has a
real record for the active model, else ``CONSERVATIVE_FALLBACK_CONTEXT_
WINDOW_TOKENS`` -- recorded either way in the returned ``capacity_source``,
never silently conflated (see ``SourceCapacityResult``).
"""

from __future__ import annotations

from typing import NamedTuple, Optional

from core.model_registry import context_window_tokens as _registry_context_window_tokens

CONSERVATIVE_CHARS_PER_TOKEN = 3.0
"""Deliberately BELOW a realistic ~3.5-4.5 chars/token average for English
prose and source code under typical BPE-style tokenizers. Converting a
token budget to a character ceiling via a LOWER ratio always UNDER-states
how many characters a real (less token-dense) text could actually spend,
so even a pathologically token-dense block (heavy identifiers/punctuation/
non-ASCII) stays at or under the real token limit. Using a HIGHER ratio
would risk the reverse: a character count that looks fine but is actually
over the provider's real token ceiling. This constant only has to be safe
in ONE direction, and this is it.

Never adjusted per stage, per provider, or per model -- one number, used
everywhere, so a capacity decision is reproducible across stages and never
silently drifts stage-to-stage."""

SAFETY_MARGIN_TOKENS = 2_000
"""A small, fixed, additional reserve subtracted from the total context
window before the char conversion -- absorbs markdown/heading boilerplate
this module does not itemize (e.g. "## Vulnerability report", section
joins) plus minor model-registry staleness. Kept small and named, not a
large hidden fudge factor stacked on top of CONSERVATIVE_CHARS_PER_TOKEN's
own conservatism."""

CONSERVATIVE_FALLBACK_CONTEXT_WINDOW_TOKENS = 60_000
"""The ONE documented, provider-independent, deterministic fallback used
only when the model registry (core.model_registry.context_window_tokens)
has no entry for the active provider/model -- true for every model today,
since config/models.json ships this field unpopulated (Fix B adds the
schema, not model-specific data). Deliberately the SAME constant
regardless of stage or provider: a missing capacity fact must never
silently produce a different guess in different places. Sized to be
safely below even a "small" current-generation model's real context
window while remaining an order of magnitude larger than the arbitrary
stage-local constants Fix B removes (4,000/10,000/6,000 chars) -- never
treated as authoritative; every caller can distinguish this from a real
registry-sourced figure via SourceCapacityResult.capacity_source."""

CAPACITY_SOURCE_MODEL_REGISTRY = "model_registry"
CAPACITY_SOURCE_CONSERVATIVE_FALLBACK = "conservative_fallback"


class SourceCapacityResult(NamedTuple):
    """The complete, structured result of one source-evidence capacity
    decision -- everything a caller needs both to render evidence AND to
    record, in a trace, whether this number is exact-registry-derived or
    an explicitly-labeled conservative guess.

    `capacity_is_approximate` is always True: even a real model_registry-
    sourced `context_window_tokens` figure still passes through
    CONSERVATIVE_CHARS_PER_TOKEN's own token-to-character approximation --
    there is no code path in this module that produces an exact character
    ceiling, by construction, because no tokenizer exists here (see module
    docstring)."""

    source_capacity_chars: int
    capacity_source: str  # CAPACITY_SOURCE_MODEL_REGISTRY | CAPACITY_SOURCE_CONSERVATIVE_FALLBACK
    context_window_tokens: int
    reserved_output_tokens: int
    safety_margin_tokens: int
    chars_per_token_ratio: float
    known_overhead_chars: int
    capacity_is_approximate: bool = True

    def as_dict(self) -> dict:
        return self._asdict()


def compute_source_capacity(
    provider: "Optional[str]",
    model: "Optional[str]",
    *,
    reserved_output_tokens: int,
    known_overhead_chars: int,
) -> SourceCapacityResult:
    """The one implementation of Fix B's per-call source-capacity
    equation (see module docstring for the full equation).

    `provider`/`model` of None (unresolved -- e.g. before the first real
    LLM call, or mock mode) is treated identically to "no registry record
    for this model": falls straight to the conservative fallback, never
    raises.

    `reserved_output_tokens`/`known_overhead_chars` must be the CALLER's
    own real, already-known numbers for the specific call this ceiling
    will gate -- this function performs no estimation of either; it only
    approximates the token<->char conversion of the total capacity figure.

    Never returns a negative ceiling: clamped to 0 if reserved output
    tokens, the safety margin, and known overhead together already exceed
    the total context window -- a caller then omits every candidate for
    this call, exactly like any other "nothing fits" outcome, never a
    crash.

    Deterministic: same inputs always produce the same result -- no
    caching, no hidden state; a caller that wants per-run caching (see
    context_budget.ContextBudgetController) does so on top of this
    function, not inside it.
    """
    registry_tokens = None
    if provider and model:
        registry_tokens = _registry_context_window_tokens(provider, model)

    if registry_tokens:
        total_context_tokens = int(registry_tokens)
        capacity_source = CAPACITY_SOURCE_MODEL_REGISTRY
    else:
        total_context_tokens = CONSERVATIVE_FALLBACK_CONTEXT_WINDOW_TOKENS
        capacity_source = CAPACITY_SOURCE_CONSERVATIVE_FALLBACK

    available_input_tokens = max(
        0, total_context_tokens - int(reserved_output_tokens) - SAFETY_MARGIN_TOKENS,
    )
    available_input_chars = available_input_tokens * CONSERVATIVE_CHARS_PER_TOKEN
    source_capacity_chars = max(0, int(available_input_chars) - max(0, int(known_overhead_chars)))

    return SourceCapacityResult(
        source_capacity_chars=source_capacity_chars,
        capacity_source=capacity_source,
        context_window_tokens=total_context_tokens,
        reserved_output_tokens=int(reserved_output_tokens),
        safety_margin_tokens=SAFETY_MARGIN_TOKENS,
        chars_per_token_ratio=CONSERVATIVE_CHARS_PER_TOKEN,
        known_overhead_chars=max(0, int(known_overhead_chars)),
    )
