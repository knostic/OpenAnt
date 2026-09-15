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


def safe_code_fence(text: str) -> str:
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
    return " ".join(str(value).splitlines())
