"""Regression test for F9: USER_INPUT_PATTERNS FastAPI alternation needs a word boundary.

The pattern ``(Query|Body|Form|File|Header|Cookie)\\s*\\(`` (no leading ``\\b``)
matches any identifier *ending* in one of those words, so ordinary library
calls like ``setCookie(``, ``PQsendQuery(`` or ``getHeader(`` were flagged as
user-input sources and seeded as false remote-web entry points across C/Go/
PHP/Python repos. The fix anchors the alternation with ``\\b`` so only the
standalone FastAPI dependency symbols match.
"""

from __future__ import annotations

import re

from utilities.agentic_enhancer.entry_point_detector import USER_INPUT_PATTERNS


def _fastapi_pattern():
    """The FastAPI Query/Body/.../Cookie alternation from USER_INPUT_PATTERNS."""
    for p in USER_INPUT_PATTERNS:
        if "Cookie" in p and "Query" in p:
            return re.compile(p)
    raise AssertionError("FastAPI input pattern not found in USER_INPUT_PATTERNS")


FALSE_POSITIVES = [
    "res.setCookie(token)",
    "PQsendQuery(conn, sql)",
    "req.getHeader('X')",
    "parseMultipartFile(x)",
    "renderBody(html)",
    "buildForm(fields)",
]

TRUE_POSITIVES = [
    "def handler(c: str = Cookie(None)): ...",
    "def handler(q: str = Query(...)): ...",
    "def handler(b: Item = Body(...)): ...",
    "def handler(h: str = Header(None)): ...",
]


def test_input_pattern_rejects_substring_false_positives():
    pat = _fastapi_pattern()
    for code in FALSE_POSITIVES:
        assert pat.search(code) is None, f"false positive: {code!r} matched {pat.pattern!r}"


def test_input_pattern_still_matches_standalone_symbols():
    pat = _fastapi_pattern()
    for code in TRUE_POSITIVES:
        assert pat.search(code) is not None, f"regressed: {code!r} no longer matches"
