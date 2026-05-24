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
from typing import Optional

from .llm import PhaseBinding, simple_text


def get_json_extraction_prompt(raw_response: str) -> str:
    """
    Generate a prompt to extract JSON from a malformed response.
    """
    # Truncate very long responses
    if len(raw_response) > 8000:
        raw_response = raw_response[:8000] + "\n... [truncated]"

    return f"""The following is a response from a security analysis that should have been JSON but wasn't properly formatted.

Your task is to extract the security analysis data and return it as valid JSON.

The expected JSON schema is:
{{
    "verdict": "VULNERABLE" | "SAFE" | "INSUFFICIENT_CONTEXT",
    "confidence": 0.0-1.0,
    "vulnerabilities": [
        {{
            "type": "SQL Injection | XSS | Command Injection | Path Traversal | Open Redirect | XXE | Insecure Deserialization | Broken Access Control | Other",
            "severity": "CRITICAL | HIGH | MEDIUM | LOW",
            "source": "description of where tainted data enters",
            "sink": "description of dangerous operation",
            "flow": "data flow description",
            "evidence": "code snippet",
            "why_vulnerable": "explanation"
        }}
    ],
    "reasoning": "analysis summary"
}}

Raw response to extract from:
---
{raw_response}
---

Return ONLY valid JSON matching the schema above. If you cannot determine the verdict, use "INSUFFICIENT_CONTEXT".
If the response indicates vulnerabilities were found, set verdict to "VULNERABLE" and populate the vulnerabilities array.
If the response indicates the code is safe, set verdict to "SAFE" with an empty vulnerabilities array.

Respond with the JSON only, no markdown, no explanation:"""


def extract_json_with_llm(
    binding: PhaseBinding,
    raw_response: str,
) -> Optional[dict]:
    """
    Use LLM to extract JSON from a malformed response.

    Args:
        binding: Phase binding to issue the LLM call against. Typically
            the binding of whatever phase received the malformed
            response in the first place (analyze, verify, etc.).
        raw_response: The raw response that failed to parse

    Returns:
        Parsed JSON dict if successful, None otherwise
    """
    if not raw_response or len(raw_response.strip()) < 10:
        return None

    prompt = get_json_extraction_prompt(raw_response)

    try:
        llm_response = simple_text(binding, prompt, max_tokens=2048)
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

    def attempt_correction(self, raw_response: str) -> dict:
        """
        Attempt to correct a malformed JSON response.

        Args:
            raw_response: The raw response that failed to parse

        Returns:
            Corrected result dict
        """
        print(f"      Attempting JSON correction with LLM...", file=sys.stderr)

        extracted = extract_json_with_llm(self.binding, raw_response)

        if extracted:
            # Normalize finding -> verdict
            if "verdict" not in extracted and "finding" in extracted:
                finding = extracted["finding"]
                mapping = {
                    "vulnerable": "VULNERABLE", "safe": "SAFE",
                    "protected": "PROTECTED", "bypassable": "BYPASSABLE",
                    "inconclusive": "INCONCLUSIVE",
                    "insufficient_context": "INSUFFICIENT_CONTEXT",
                }
                extracted["verdict"] = mapping.get(finding.lower(), finding.upper())

            # Validate the extracted data has required fields
            if "verdict" in extracted:
                extracted["json_corrected"] = True
                print(f"      JSON correction successful! Verdict: {extracted.get('verdict')}", file=sys.stderr)
                return extracted
            else:
                print(f"      JSON correction failed: missing verdict field", file=sys.stderr)
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
