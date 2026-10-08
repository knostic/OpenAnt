"""The one depth-0 JSON-object extractor every LLM-response parser shares.

PR #242 replaced ``core.analysis_core.parse_response``'s naive JSON fallback
-- slice from the first ``{`` to the last ``}``, then ``json.loads`` the slice
-- with a depth-0 brace scanner that tracks JSON-string state and escapes, so
a brace anywhere in the model's surrounding prose no longer invalidates the
span.  Its own body disclosed the residual it left behind: "Also unchanged: 7
sibling LLM-response parsers still use the naive ``rfind("}")`` span."  There
were nine such sites in eight modules (#673).

This module is that scanner's single home.  Two reasons it lives here and not
in ``core.analysis_core``:

1.  ``parse_response`` fuses the scanner onto *verdict* semantics -- it keeps
    only objects carrying a ``verdict``/``finding`` key and routes competing
    or malformed-but-verdict-shaped spans to ERROR+retry (the #236/#242
    false-negative-safety contract).  Seven of the nine sibling sites parse
    replies that carry no verdict key at all, so they cannot call it.
2.  They could not import it anyway.  ``utilities/__init__.py`` eagerly
    imports six of the eight sibling modules and ``core/analysis_core.py``
    imports two of them back, so a module-level import of a name out of
    ``core.analysis_core`` from inside ``utilities/`` is an ImportError in
    both directions -- the "11-module SCC via ``utilities/__init__.py`` ...
    held together by deferred in-function imports" hazard in
    ARCHITECTURE.md section 6.

Therefore: **this module imports nothing but the standard library**, which is
what makes it importable at module level from ``core/``, ``utilities/`` and
``context/`` alike.  Keep it that way -- there is a test.

``scan_depth0_spans`` is the shared mechanism; ``parse_response`` layers its
verdict-ambiguity rules on top, unchanged.  ``extract_json_object`` is the
policy the nine sibling sites want: the single decoded object, or ``None``.
"""

from __future__ import annotations

import json
from typing import Any, Optional

__all__ = ["UNDECODABLE", "scan_depth0_spans", "extract_json_object"]


class _Undecodable:
    """Sentinel type: a balanced depth-0 span that is not valid JSON."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNDECODABLE"


#: Marks a balanced depth-0 span that ``json`` refused.  Deliberately not
#: ``None``, which is a legitimate decoded JSON value.
UNDECODABLE = _Undecodable()


def scan_depth0_spans(text: str) -> "tuple[list[tuple[str, Any]], bool]":
    """Find every balanced ``{...}`` span at brace-depth 0.

    Tracks JSON-string state (with escapes) so braces inside string values --
    or balanced code braces in a preamble -- do not offset the depth.  Each
    span is decoded **in isolation**, which bounds the JSONDecodeError
    position math to the span (it was O(n^2) on multi-MB responses) and keeps
    the span's text available to callers that need to inspect it.

    Returns ``(spans, ended_in_string)`` where ``spans`` is a list of
    ``(span_text, decoded_value_or_UNDECODABLE)`` in source order, and
    ``ended_in_string`` is True if the scan finished inside a JSON string --
    quote parity is then untrustworthy and a caller may choose not to guess.

    Only depth-0 objects are reported: a nested example dict inside a
    malformed outer object is never mistaken for the outer one.
    """
    decoder = json.JSONDecoder()
    spans: "list[tuple[str, Any]]" = []
    depth = 0
    in_string = False
    escape = False
    obj_start: Optional[int] = None
    for pos, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            if depth == 0:
                obj_start = pos
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and obj_start is not None:
                    span = text[obj_start:pos + 1]
                    try:
                        spans.append((span, decoder.decode(span)))
                    except json.JSONDecodeError:
                        spans.append((span, UNDECODABLE))
                    obj_start = None
    return spans, in_string


def _naive_span_object(text: str) -> Optional[dict]:
    """The pre-#242 extractor: first ``{`` to last ``}``, decoded.

    Retained deliberately, as the *last* resort rather than the first.  The
    depth-0 scan has one blind spot the naive slice does not: an odd number of
    ``"`` in the surrounding prose shifts quote parity, and the scan then sees
    no depth-0 object at all.  Falling back keeps
    :func:`extract_json_object` a strict superset of what every call site
    already recovered -- a robustness fix must not drop a reply that parses
    before it.
    """
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            value = json.loads(text[start:end])
        except json.JSONDecodeError:
            return None
        if isinstance(value, dict):
            return value
    return None


def extract_json_object(text: str) -> Optional[dict]:
    """Pull the single JSON object out of a model response, or ``None``.

    Returns the object when exactly one balanced depth-0 span decodes to a
    dict.  **Several decoded objects are ambiguous and return ``None``** --
    never the first or the last one.  That is #236's constraint, which #242
    adopted rather than relaxed: blind-picking turns a visible parse failure
    into a silent wrong answer (a trailing ``example: {SAFE}`` block
    overriding a real ``{VULNERABLE}``), and every call site already treats
    ``None`` as "could not parse" and has its own fallback.

    Does **not** strip markdown fences or try a whole-text ``json.loads``
    first: call sites differ in both and keep their own.  This replaces only
    their naive-slice fallback.
    """
    if not text:
        return None
    spans, _ended_in_string = scan_depth0_spans(text)
    decoded = [value for _span, value in spans if isinstance(value, dict)]
    if len(decoded) == 1:
        return decoded[0]
    if not decoded:
        return _naive_span_object(text)
    return None
