"""
Conformance test for the json_corrector output-cap truncation bug.

Bug (finding jsoncorrect-output-cap-2048): utilities/json_corrector.py
``extract_json_with_llm`` capped the correction call at ``max_tokens=2048``.
The correction has to reproduce the ENTIRE corrected verdict JSON (verdict +
an array of vulnerabilities, each with 8 fields, + reasoning). A large but
perfectly valid corrected JSON exceeds 2048 tokens, so the provider truncates
the reply mid-structure. ``_parse_json_response`` then fails to parse the
truncated (unbalanced-brace) JSON and returns ``None`` -- so a recoverable
response is REJECTED and ``attempt_correction`` emits an ERROR verdict.

The sibling module that GENERATES this exact schema, utilities/finding_verifier.py,
uses ``MAX_TOKENS_PER_RESPONSE = 4096``; the ``simple_text`` helper defaults to
8192. json_corrector alone under-capped at 2048.

This test stubs ``simple_text`` with a fake provider that returns a large valid
corrected JSON, TRUNCATED to whatever ``max_tokens`` budget it is handed
(~4 chars/token) -- exactly how a real provider cuts a reply off at the cap.

    RED  on pristine core: max_tokens=2048 -> reply truncated -> parse fails
                           -> attempt_correction returns verdict ERROR.
    GREEN on patched core:  raised cap -> full JSON fits -> parse succeeds
                           -> verdict VULNERABLE preserved.

Select the core under test with OPENANT_CORE_ROOT (defaults to pristine).
"""

import json
import os
import sys


_CORE_ROOT = os.environ.get(
    "OPENANT_CORE_ROOT",
    "/Users/gadievron/Documents/ClaudeNew/OpenAnt/new-bugs-2/OpenAnt/libs/openant-core",
)
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)


# A large but perfectly valid corrected JSON: many vulnerabilities, each with
# the full 8-field schema. Serialized it is well over 2048 tokens (~8KB), so a
# 2048-token cap truncates it; an un-capped/raised budget lets it through whole.
def _build_large_valid_json() -> str:
    vulns = []
    for i in range(40):
        vulns.append({
            "type": "SQL Injection",
            "severity": "CRITICAL",
            "source": f"req.body.field_{i} entering handler number {i} of the route",
            "sink": f"db.query() call site {i} in core/appHandler.js building raw SQL",
            "flow": f"user input field_{i} -> string concatenation -> db.query -> database",
            "evidence": f"var q = 'SELECT * FROM Users WHERE x=' + req.body.field_{i};",
            "why_vulnerable": (
                f"User-controlled field_{i} is concatenated directly into the SQL "
                f"statement with no parameterization or escaping, allowing injection."
            ),
        })
    doc = {
        "verdict": "VULNERABLE",
        "confidence": 0.95,
        "vulnerabilities": vulns,
        "reasoning": "Multiple injection sinks reached by untrusted request fields.",
    }
    return json.dumps(doc, indent=2)


_LARGE_VALID_JSON = _build_large_valid_json()


def _run():
    import utilities.json_corrector as jc

    captured = {}

    # Fake provider: returns the large valid JSON, but truncated to the token
    # budget it was given (~4 chars/token) -- i.e. it stops emitting at the cap.
    def _fake_simple_text(binding, prompt, *, max_tokens=8192, **kwargs):
        captured["max_tokens"] = max_tokens
        char_budget = max_tokens * 4
        return _LARGE_VALID_JSON[:char_budget]

    original = jc.simple_text
    jc.simple_text = _fake_simple_text
    try:
        result = jc.JSONCorrector(binding=None).attempt_correction(
            "not json, please recover this large analysis result"
        )
    finally:
        jc.simple_text = original

    # Sanity: the full JSON really is big enough that a 2048-token cap truncates
    # it (otherwise the test would not exercise the bug).
    assert len(_LARGE_VALID_JSON) > 2048 * 4, (
        "fixture JSON too small to exercise the 2048-token cap"
    )

    assert result.get("verdict") == "VULNERABLE", (
        f"correction was rejected: verdict={result.get('verdict')!r} "
        f"json_corrected={result.get('json_corrected')!r}; the output cap of "
        f"max_tokens={captured.get('max_tokens')} truncated a valid corrected JSON"
    )
    assert result.get("json_corrected") is True, "expected a successful correction"
    print(
        f"PASS: large valid corrected JSON survives (cap={captured.get('max_tokens')})"
    )


def test_json_corrector_output_not_truncated_by_cap():
    _run()


if __name__ == "__main__":
    _run()
