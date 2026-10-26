"""Shared Markdown code-fence helper for prompt builders.

Both the Stage-1 analysis prompt (`vulnerability_analysis.py`) and the Stage-2
verification prompt (`verification_prompts.py`) interpolate UNTRUSTED analyzed
source code into Markdown code fences. Per the CommonMark spec, a fenced code
block opened with N backticks is closed by the first subsequent line that is a
run of >= N backticks. A bare ``` fence is therefore escapable: untrusted
content containing its own ``` line breaks out of the fence and the remainder is
read as prompt-level instructions (prompt injection — the attacker can steer the
analyst's / verifier's verdict).

This module centralises the one safe-fence implementation so both prompt
builders share identical behaviour (no duplication).
"""

from __future__ import annotations

import re


class Untrusted:
    """#709: the structural marker for prompt-untrusted content — a scanned
    repo's code/fields or a prior stage's LLM output, on its way into a
    prompt. THE CHOKE-POINT: an ``Untrusted`` REFUSES raw interpolation —
    ``str()``/f-strings/``%`` all raise — so a prompt builder holding untrusted
    content as ``Untrusted`` cannot splice it into a prompt EXCEPT through
    this module's two unwrap points (``safe_code_fence`` / ``collapse_inline``
    — the only places that read ``.value``), each of which returns a plain
    ``str`` that is inert-by-construction (a fence that cannot be escaped /
    a single line with no newline). A forgetful new interpolation site
    therefore CRASHES the builder instead of silently passing (#248's
    convention gap: the fence was a convention enforced by one invariant
    test — a detection control; this marker is structural at runtime).

    Deliberately NOT a ``str`` subclass: subclassing would make every
    existing interpolation silently succeed (the exact gap this closes).
    ``.value`` is the captured content, coerced ONCE at the boundary — the
    wrapper is the PRODUCER's statement that the content crossed the trust
    boundary, and the two primitives are the CONSUMER's unwrap.
    """

    __slots__ = ("value",)

    def __init__(self, value) -> None:
        # coerce once, exactly as the primitives did before (str(value) —
        # collapse_inline's documented None/whitespace semantics survive).
        # IDEMPOTENT (the fable-r1 N2 catch): Untrusted(Untrusted(x)) is the
        # same as Untrusted(x) — a double-wrap (a form-A site wrapping an
        # already-wrapped value) must not crash on the inner wrapper's
        # refusing __str__.
        if isinstance(value, Untrusted):
            object.__setattr__(self, "value", value.value)
            return
        object.__setattr__(self, "value", str(value))

    def _refuse(self, *_args, **_kwargs):
        raise TypeError(
            "Untrusted content must be unwrapped through "
            "prompts._fence.safe_code_fence / collapse_inline before "
            "interpolation (the #709 choke-point: raw interpolation of "
            "scanned-repo or prior-stage content is refused, not fenced "
            "after the fact)")

    __str__ = _refuse
    __repr__ = _refuse
    __format__ = _refuse


def fence_block(text, language: str = "") -> str:
    """#709: the COMPLETE fenced block, assembled INSIDE this module — the
    structural unwrap point for untrusted BLOCK content.

    Returns ``f"{run}{language}\n{text}\n{run}"`` where ``run`` is
    ``safe_code_fence(text)`` — the exact per-builder assembly #248 left
    duplicated at every call site (each of which could in principle mismatch
    its own open/close runs); centralising it means a builder never
    interpolates untrusted content at all — it interpolates only this
    function's plain-str result (inert by construction: the content sits
    inside a run strictly longer than any run it contains).

    ``language`` rides the OPENING fence as the info-string (``run + lang``);
    the closer is the bare run. Accepts ``str | Untrusted``.
    """
    content = _unwrap(text)
    run = safe_code_fence(content)
    # #709 (the fable-r1 N1 catch): the info-string rides the OPENING fence
    # line — a newline in a caller-supplied language would forge a prompt
    # line, a backtick could break the opener's run. Hardened to the inert
    # token form (single line, no backticks); unreachable with the current
    # literal callers, closed by construction anyway.
    language = " ".join(str(language or "").splitlines()).replace("`", "")
    return f"{run}{language}\n{content}\n{run}"


def _unwrap(text):
    """The single internal unwrap: the ONLY code that reads ``Untrusted.value``
    — both primitives route through here, so the two unwrap points stay the
    only two."""
    if isinstance(text, Untrusted):
        return text.value
    return text


def safe_code_fence(text) -> str:
    """Return a backtick run guaranteed to enclose ``text`` un-escapably.

    The returned run is STRICTLY LONGER than the longest consecutive backtick
    run anywhere in ``text`` (minimum 3). No line inside the content can then
    satisfy the CommonMark closing rule (a line of >= N backticks), so the
    content stays inert data and cannot break out to inject prompt-level
    instructions.

    Callers that need a language info-string open with ``safe_code_fence(text)
    + language`` and close with the bare ``safe_code_fence(text)`` — both share
    this same length-aware run so the content cannot close the block early.
    """
    # #709: the unwrap point — an Untrusted block is read here (and only
    # here / in collapse_inline); the returned fence is a plain str built
    # for the content, and the CALLER assembles the fenced block with it.
    text = _unwrap(text)
    # Defensive: tolerate a None/empty body (a missing context block, an
    # empty unit) rather than raising mid prompt-build — an absent body has
    # no backtick runs, so the minimum fence applies.
    runs = re.findall(r"`+", text or "")
    longest = max((len(r) for r in runs), default=0)
    return "`" * max(3, longest + 1)


def collapse_inline(value) -> str:
    """Collapse an untrusted value to a single inert line for use as an INLINE
    prompt LABEL (a header/metadata field, not a fenced block).

    The companion to ``safe_code_fence``: multi-line untrusted content that is
    interpolated on its own label line (a verdict, route_key, file:function, a
    finding name) can forge a ``### Finding``/instruction line via an embedded
    newline. ``str.splitlines()`` recognises the full set of line boundaries
    (\\n \\r \\r\\n \\v \\f \\x1c-\\x1e \\x85 \\u2028 \\u2029) — a SUPERSET of
    CommonMark's line endings — so joining on a single space guarantees the
    result contains none of them. Centralised here so the fence/collapse pair
    lives in one module and a future hardening (e.g. also stripping tabs)
    reaches every call site at once, instead of drifting across ~10 copies.

    Returns "" only for a genuinely empty value; a whitespace-only or non-string
    value comes back as its single-line str() form (e.g. "   " -> "   ", None ->
    "None") — inert for header-forgery either way. Callers that want a placeholder
    keep their own ``or "unknown"`` (it will not fire for whitespace-only input).
    """
    # #709: the unwrap point — an Untrusted label field is read here; the
    # returned single line is a plain inert str.
    value = _unwrap(value)
    return " ".join(str(value).splitlines())
