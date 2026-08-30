"""
JSON Corrector

When the LLM returns a response that cannot be parsed as JSON, this module
uses an LLM to extract the structured data from the malformed response.

This handles cases where:
1. The model starts explaining before returning JSON
2. The JSON is incomplete or truncated
3. The JSON has syntax errors
4. The response contains multiple JSON objects

Note (issue #65): JSON correction inherits the parent phase's
:class:`PhaseBinding` rather than hardcoding Sonnet. For all-Anthropic
users this means Opus-phase corrections now also use Opus — a small
cost bump — but it's the only correct behavior for non-Anthropic
configurations where a "Sonnet" model may not even exist.
"""

import json
import sys
from typing import List, Optional

from .llm import PhaseBinding, simple_text


# Default (analyze/verify) schema. The corrector is also called by the enhance
# and review phases whose output shapes have NO verdict — those callers pass
# their own ``schema`` so the extraction prompt asks for the correct shape.
_VULN_SCHEMA = """{
    "verdict": "VULNERABLE" | "SAFE" | "INSUFFICIENT_CONTEXT",
    "confidence": 0.0-1.0,
    "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
    "vulnerabilities": [
        {
            "type": "SQL Injection | XSS | Command Injection | Path Traversal | Open Redirect | XXE | Insecure Deserialization | Broken Access Control | Other",
            "severity": "CRITICAL | HIGH | MEDIUM | LOW",
            "source": "description of where tainted data enters",
            "sink": "description of dangerous operation",
            "flow": "data flow description",
            "evidence": "code snippet",
            "why_vulnerable": "explanation"
        }
    ],
    "reasoning": "analysis summary"
}"""


def get_json_extraction_prompt(raw_response: str, schema: Optional[str] = None) -> str:
    """
    Generate a prompt to extract JSON from a malformed response.

    Args:
        raw_response: The malformed response to recover structured data from.
        schema: Expected JSON schema for the calling phase. Defaults to the
            analyze/verify vuln schema; enhance/review callers pass their own
            so a valid enhance/review response isn't rewritten into a verdict.
    """
    # Truncate very long responses
    if len(raw_response) > 8000:
        raw_response = raw_response[:8000] + "\n... [truncated]"

    schema = schema or _VULN_SCHEMA

    # raw_response is prior-stage malformed LLM output (untrusted; it echoes
    # scanned source). It was delimited only by literal `---` lines, which a
    # payload can trivially forge to inject instructions steering the re-emitted
    # verdict JSON. Wrap it in a length-adaptive fence so it stays inert data.
    from prompts._fence import safe_code_fence
    _rf = safe_code_fence(raw_response)

    return f"""The following is a response from a security analysis pipeline that should have been JSON but wasn't properly formatted.

Your task is to extract the structured data and return it as valid JSON.

The expected JSON schema is:
{schema}

Raw response to extract from:
{_rf}
{raw_response}
{_rf}

Return ONLY valid JSON matching the schema above. Preserve every field that is present in the raw response; do not invent values. If a required field cannot be determined, use the most conservative default for that field.

Respond with the JSON only, no markdown, no explanation:"""


# Verify-stage (finding_verifier Stage 2) finish schema — agree/correct_finding/
# explanation (+ optional exploit_path/security_weakness), NOT the Stage-1 vuln
# schema. Exposed both as ``get_verify_extraction_prompt`` (used by verify-stage
# callers that want a ready-made prompt) and reachable via ``schema=`` on the
# generic corrector.
_VERIFY_SCHEMA = """{
    "agree": true | false,
    "correct_finding": "safe" | "protected" | "bypassable" | "vulnerable" | "inconclusive",
    "explanation": "detailed explanation of the analysis",
    "exploit_path": {
        "entry_point": "where attacker input enters (or null)",
        "data_flow": ["step 1", "step 2"],
        "sink_reached": true | false,
        "attacker_control_at_sink": "full" | "partial" | "none",
        "path_broken_at": "where/why the path breaks (or null)"
    },
    "security_weakness": "dangerous patterns that exist but aren't currently exploitable (or null)"
}"""


def get_verify_extraction_prompt(raw_response: str) -> str:
    """
    Generate a prompt to extract JSON from a malformed *verify-stage*
    (finding_verifier Stage 2) response.

    The verify stage's finish schema is agree/correct_finding/explanation
    (+ optional exploit_path/security_weakness) — NOT the Stage-1 analyze
    schema (verdict/vulnerabilities/reasoning). Using the analyze prompt here
    would ask the model for the wrong shape and drop a valid verification.

    This is a thin convenience wrapper over :func:`get_json_extraction_prompt`
    with the verify schema pre-filled; the reconciled corrector reaches the
    same shape when a caller passes ``schema=`` directly.
    """
    return get_json_extraction_prompt(raw_response, schema=_VERIFY_SCHEMA)


def extract_json_with_llm(
    binding: PhaseBinding,
    raw_response: str,
    schema: Optional[str] = None,
) -> Optional[dict]:
    """
    Use LLM to extract JSON from a malformed response.

    Args:
        binding: Phase binding to issue the LLM call against. Typically
            the binding of whatever phase received the malformed
            response in the first place (analyze, verify, etc.).
        raw_response: The raw response that failed to parse
        schema: Expected JSON schema for the calling phase (see
            ``get_json_extraction_prompt``). None => default vuln schema.

    Returns:
        Parsed JSON dict if successful, None otherwise
    """
    if not raw_response or len(raw_response.strip()) < 10:
        return None

    prompt = get_json_extraction_prompt(raw_response, schema=schema)

    try:
        # The correction must reproduce the FULL verdict JSON (verdict + an array
        # of vulnerabilities + reasoning), which routinely exceeds 2048 tokens for
        # a multi-finding response. A 2048-token cap truncated valid corrections
        # mid-structure, so _parse_json_response rejected them. Match the schema's
        # own producer (finding_verifier MAX_TOKENS_PER_RESPONSE) and simple_text's
        # 8192 default so a large valid correction is never cut off.
        llm_response = simple_text(binding, prompt, max_tokens=8192)
        return _parse_json_response(llm_response)
    except Exception as e:
        print(f"      JSON extraction failed: {e}", file=sys.stderr)
        return None


def _parse_json_response(response: str) -> Optional[dict]:
    """Parse JSON response from LLM."""
    response = response.strip()

    # Remove markdown code blocks if present
    if response.startswith("```json"):
        response = response[7:]
    elif response.startswith("```"):
        response = response[3:]

    if response.endswith("```"):
        response = response[:-3]

    response = response.strip()

    try:
        return json.loads(response)
    except json.JSONDecodeError:
        # Try to find JSON in the response
        start = response.find("{")
        end = response.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(response[start:end])
            except json.JSONDecodeError:
                pass
    return None


class JSONCorrector:
    """
    Handles JSON correction for malformed LLM responses.
    """

    def __init__(self, binding: PhaseBinding):
        """
        Initialize the corrector.

        Args:
            binding: Phase binding for the LLM call. Reuse the binding
                of the phase whose response we're correcting so the
                correction call goes through the same provider+model.
        """
        self.binding = binding

    def attempt_correction(
        self,
        raw_response: str,
        schema: Optional[str] = None,
        required_keys: Optional[List[str]] = None,
    ) -> dict:
        """
        Attempt to correct a malformed JSON response.

        Args:
            raw_response: The raw response that failed to parse
            schema: Expected JSON schema for the calling phase. None => the
                default analyze/verify vuln schema. Enhance/review phases pass
                their own shape so a valid non-verdict response is recovered
                as-is instead of being rewritten into a vuln verdict.
            required_keys: Keys that must be present for the correction to count
                as successful. Defaults to ``["verdict"]`` (vuln shape). Callers
                with a non-verdict shape pass their own required keys.

        Returns:
            Corrected result dict
        """
        # Non-verdict schemas skip the vuln-specific finding->verdict
        # normalization; their success gate is their own required_keys.
        vuln_mode = schema is None
        if required_keys is None:
            required_keys = ["verdict"]

        print(f"      Attempting JSON correction with LLM...", file=sys.stderr)

        # Only forward ``schema`` when a caller supplied one, so pre-existing
        # 2-arg stubs of extract_json_with_llm keep working on the default path.
        if schema is None:
            extracted = extract_json_with_llm(self.binding, raw_response)
        else:
            extracted = extract_json_with_llm(self.binding, raw_response, schema=schema)

        if extracted:
            if vuln_mode:
                # Normalize the extracted finding casing so downstream lowercase
                # gates (verifier/reporter) don't silently drop a capitalized
                # "Vulnerable". Recover-only: lowercase, never invent a verdict.
                if "finding" in extracted and isinstance(extracted["finding"], str):
                    extracted["finding"] = extracted["finding"].lower()

                # Verify-stage shape recovery on the DEFAULT path: a verify finish
                # dict carries the enum in ``correct_finding`` (lowercase) with no
                # ``verdict`` key. Lowercase-normalize it and derive a ``verdict``
                # so a default-args correction of a verify response passes the
                # verdict-only success gate instead of being rejected as ERROR.
                # (Verify callers that pass schema=/required_keys= skip this block
                # entirely and are gated on their own keys.) Recover-only.
                if "correct_finding" in extracted and isinstance(extracted["correct_finding"], str):
                    extracted["correct_finding"] = extracted["correct_finding"].lower()
                    if "verdict" not in extracted:
                        # #316: an off-enum correct_finding is a malformed
                        # reply, not a verdict — map through the verify enum
                        # (_VERIFY_SCHEMA's five) and route anything else to
                        # ERROR (the caller's not-in-("ERROR", None) gate
                        # then rejects the correction) instead of
                        # synthesizing a verdict no consumer recognizes.
                        _verify_finding_to_verdict = {
                            "safe": "SAFE",
                            "protected": "PROTECTED",
                            "bypassable": "BYPASSABLE",
                            "vulnerable": "VULNERABLE",
                            "inconclusive": "INCONCLUSIVE",
                        }
                        extracted["verdict"] = _verify_finding_to_verdict.get(
                            extracted["correct_finding"], "ERROR"
                        )

                # Normalize finding -> verdict
                if "verdict" not in extracted and "finding" in extracted:
                    finding = extracted["finding"]
                    mapping = {
                        "vulnerable": "VULNERABLE", "safe": "SAFE",
                        "protected": "PROTECTED", "bypassable": "BYPASSABLE",
                        "inconclusive": "INCONCLUSIVE",
                        "insufficient_context": "INSUFFICIENT_CONTEXT",
                    }
                    if not isinstance(finding, str):
                        # Mirror of analysis_core._normalize_result: a
                        # non-string finding is a malformed reply — the one
                        # error shape, not a crash on .lower().
                        extracted["verdict"] = "ERROR"
                    else:
                        # #316: an unrecognized finding string maps to ERROR — a
                        # failed correction is visible and retried; a synthesized
                        # verdict is silently uncountable.
                        extracted["verdict"] = mapping.get(finding.lower(), "ERROR")

            # Validate the extracted data has the caller's required fields
            if vuln_mode and str(extracted.get("verdict", "")).upper() == "ERROR":
                # #316: the correction recovered no recognizable verdict (the
                # mappers' ERROR default) — report failure, not "successful!",
                # so the log matches what the caller adopts. Case-insensitive:
                # the extracted verdict is only upper-cased later, by
                # _normalize_result.
                print(f"      JSON correction failed: recovered no recognizable verdict", file=sys.stderr)
            elif all(k in extracted for k in required_keys):
                extracted["json_corrected"] = True
                print(f"      JSON correction successful! keys={list(extracted.keys())}", file=sys.stderr)
                return extracted
            else:
                missing = [k for k in required_keys if k not in extracted]
                print(f"      JSON correction failed: missing required fields {missing}", file=sys.stderr)
        else:
            print(f"      JSON correction failed: could not extract JSON", file=sys.stderr)

        # Return error result
        return {
            "verdict": "ERROR",
            "confidence": 0,
            "vulnerabilities": [],
            "reasoning": "Failed to parse response and JSON correction unsuccessful",
            "raw_response": raw_response[:500],
            "json_corrected": False,
            "json_correction_attempted": True
        }


def test_json_corrector():
    """Test the JSON corrector with sample malformed responses."""

    # Sample malformed response from actual experiment (GET:/app/redirect)
    test_cases = [
        {
            "name": "Explanation before JSON",
            "response": """Looking at the `GET:/app/redirect` endpoint, I need to trace the data flow and identify any security vulnerabilities.

**1. Entry Point Location:**
- Route defined in `routes/app.js` line 46: `router.get('/redirect', appHandler.redirect)`
- Handler function: `appHandler.redirect` in `core/appHandler.js`

**2. Data Flow Analysis:**

The handler function is defined in `core/appHandler.js` lines 178-184:
```javascript
module.exports.redirect = function (req, res) {
    if (req.query.url) {
        res.redirect(req.query.url);
    } else {
        res.redirect('/app/dashboard');
    }
}
```

This endpoint takes `req.query.url` directly from user input and passes it to `res.redirect()` without any validation.

{
    "verdict": "VULNERABLE",
    "confidence": 0.95,
    "vulnerabilities": [
        {
            "type": "Open Redirect",
            "severity": "MEDIUM",
            "source": "req.query.url in GET:/app/redirect",
            "sink": "res.redirect() in core/appHandler.js:180",
            "flow": "GET request -> req.query.url -> res.redirect(url)",
            "evidence": "res.redirect(req.query.url)",
            "why_vulnerable": "User-controlled URL is passed directly to redirect without validation"
        }
    ],
    "reasoning": "The endpoint is vulnerable to open redirect attacks"
}"""
        },
        {
            "name": "Truncated JSON",
            "response": """{
    "verdict": "VULNERABLE",
    "confidence": 0.9,
    "vulnerabilities": [
        {
            "type": "SQL Injection",
            "severity": "CRITICAL",
            "source": "req.body.username",
            "sink": "db.query()",
            "flow": "user input -> query concatenation -> database"""
        },
        {
            "name": "Analysis without JSON",
            "response": """The POST:/app/usersearch endpoint is vulnerable to SQL injection.

The user input from req.body.login is directly concatenated into the SQL query:
var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";

This allows attackers to inject SQL commands. For example: admin' OR '1'='1' --

The vulnerability is CRITICAL because it allows unauthorized data access.

Verdict: VULNERABLE
Confidence: 0.95"""
        }
    ]

    print("Testing JSON Corrector")
    print("=" * 60)

    # Resolve a binding for the analyze phase from the active config.
    from .llm import build_phase_registry, load_config_file, resolve_llm_config

    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, None))
    corrector = JSONCorrector(registry.get("analyze"))

    for test_case in test_cases:
        print(f"\nTest: {test_case['name']}")
        print(f"Response preview: {test_case['response'][:100]}...")
        print()

        result = corrector.attempt_correction(test_case['response'])

        print(f"Result:")
        print(f"  Verdict: {result.get('verdict')}")
        print(f"  Confidence: {result.get('confidence')}")
        print(f"  JSON Corrected: {result.get('json_corrected', False)}")
        if result.get('vulnerabilities'):
            for vuln in result['vulnerabilities']:
                print(f"  - {vuln.get('type')}: {vuln.get('severity')}")

        print("-" * 60)


if __name__ == "__main__":
    test_json_corrector()
