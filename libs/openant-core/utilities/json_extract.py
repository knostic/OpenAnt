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

    Retained deliberately, and it is load-bearing rather than vestigial: it is
    the depth-0 scan's *parity cross-check*.  The scan assumes it starts
    outside a JSON string, so a stray ``"`` in the model's prose inverts its
    string state -- and an inverted scan both misses the real object's braces
    and reports balanced ``{}`` *inside* a string value as a depth-0 object.

    This slice cannot make that mistake, because it never interprets quotes.
    When it decodes, ``text[first-{ : last-} ]`` is one complete, valid JSON
    object, and that is a strictly wider and unambiguous reading of the text --
    see :func:`extract_json_object` for why it therefore wins any disagreement.
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

    The naive slice is consulted as a **cross-check on quote parity**, not as a
    mere last resort.  :func:`scan_depth0_spans` assumes it begins outside a
    JSON string; one stray ``"`` in the prose inverts that, and the scan then
    reports a balanced ``{}`` sitting inside a string VALUE as the depth-0
    object -- ``{}`` instead of the reply (a silent wrong answer), or two such
    artefacts and therefore ``None`` (a drop).  Gating on the scan's own
    ``ended_in_string`` flag does not cover it: a second stray quote restores
    final parity while the state stays inverted across the object, so the flag
    reads False on exactly the shapes that need rescuing.

    So: if the naive slice decodes to a dict and the scan disagrees, the scan's
    string state was corrupted and the slice wins.  That is sound, not a
    heuristic.  If the slice decodes, its span is ONE valid JSON object; any
    differing scan span must then lie strictly inside that span, and under
    correct parity a depth-0 object cannot sit strictly inside another depth-0
    object's extent (two sibling depth-0 objects would leave the slice invalid
    JSON).  Disagreement therefore *implies* inverted parity.

    #236 survives it: the slice yields a dict only when the whole span is a
    single valid JSON document, which cannot hold two competing top-level
    objects -- so this can never blind-pick one of them. THE None-PRESERVATION
    RESIDUAL (declared, F1c/F1d): under INVERTED quote parity (a stray quote
    before the object) a competing pick or a {}-in-string value may be
    returned where the naive slice returned None -- the superset property
    ("whenever the slice decodes to a dict, return that same dict") is
    unconditional; the None-preservation is NOT.

    Does **not** strip markdown fences or try a whole-text ``json.loads``
    first: call sites differ in both and keep their own.  This replaces only
    their naive-slice fallback.

    Residual, disclosed: when parity is inverted AND two objects genuinely
    compete, the slice covers both, fails to decode, and cannot arbitrate -- the
    scan's corrupted single span is returned.  ``parse_response`` has behaved
    that way since #242; it is pre-existing, not introduced here.
    """
    if not text:
        return None
    spans, _ended_in_string = scan_depth0_spans(text)
    decoded = [value for _span, value in spans if isinstance(value, dict)]
    naive = _naive_span_object(text)
    if naive is not None and (len(decoded) != 1 or decoded[0] != naive):
        return naive
    if len(decoded) == 1:
        return decoded[0]
    return None
