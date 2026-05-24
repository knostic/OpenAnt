"""
Ground Truth Challenger

This module is used ONLY in test mode when ground truths are available.
It challenges the ground truths when assessment results contradict them:

1. False Positives (FP): Model says VULNERABLE, ground truth says SAFE
   - Challenge: Is the ground truth correct, or did the model find a real vulnerability?

2. False Negatives (FN): Model says SAFE, ground truth says VULNERABLE
   - Challenge: Is the ground truth correct, or is the model right that it's safe?

Uses LLM arbitration to provide a third opinion and detailed reasoning.
"""

import json
import sys
from typing import Optional
from dataclasses import dataclass

from .llm import PhaseBinding, simple_text


@dataclass
class ChallengeResult:
    """Result of challenging a ground truth."""
    route_key: str
    challenge_type: str  # "FP" or "FN"
    model_verdict: str
    ground_truth: str
    arbitration_verdict: str  # "MODEL_CORRECT", "GROUND_TRUTH_CORRECT", "UNCERTAIN"
    confidence: float
    reasoning: str
    vulnerabilities_found: list  # If arbitration found vulnerabilities
    recommendation: str  # What should the ground truth be?


def get_fp_challenge_prompt(route_key: str, code: str, model_reasoning: str, model_vulnerabilities: list) -> str:
    """
    Generate a prompt to challenge a potential false positive.

    The model said VULNERABLE, but ground truth says SAFE.
    We need to determine who is right.
    """
    vuln_details = ""
    if model_vulnerabilities:
        vuln_details = "\n\nVulnerabilities claimed by the model:\n"
        for i, v in enumerate(model_vulnerabilities, 1):
            vuln_details += f"""
{i}. Type: {v.get('type', 'Unknown')}
   Severity: {v.get('severity', 'Unknown')}
   Source: {v.get('source', 'N/A')}
   Sink: {v.get('sink', 'N/A')}
   Flow: {v.get('flow', 'N/A')}
   Evidence: {v.get('evidence', 'N/A')}
   Why Vulnerable: {v.get('why_vulnerable', 'N/A')}
"""

    return f"""You are a senior security researcher arbitrating a disagreement between a vulnerability scanner and a ground truth dataset.

## Situation
- **Endpoint**: {route_key}
- **Scanner verdict**: VULNERABLE
- **Ground truth**: SAFE (not vulnerable)

The scanner claims this endpoint is vulnerable, but the ground truth dataset says it's safe.
Your job is to determine who is correct.

## Code Being Analyzed
```
{code}
```

## Scanner's Reasoning
{model_reasoning}
{vuln_details}

## Your Task
Carefully analyze the code and determine:
1. Is there actually a security vulnerability in this code?
2. Is the scanner's analysis correct, or is it a false positive?
3. Could the ground truth be wrong (i.e., is this actually vulnerable)?

Be thorough and consider:
- Is user input actually reaching a dangerous sink without proper sanitization?
- Are there framework-level protections that prevent exploitation?
- Is the vulnerability theoretical but not practically exploitable?
- Could this be a real vulnerability that the ground truth missed?

CRITICAL: You MUST respond with ONLY valid JSON. No explanation before or after. Start with {{ and end with }}.

{{
    "arbitration_verdict": "MODEL_CORRECT" | "GROUND_TRUTH_CORRECT" | "UNCERTAIN",
    "confidence": 0.0-1.0,
    "reasoning": "Detailed explanation of your analysis and conclusion",
    "is_exploitable": true | false,
    "exploitation_requirements": "What would be needed to exploit this (if applicable)",
    "recommendation": "What the ground truth should be: VULNERABLE or SAFE"
}}

If the model found a real, exploitable vulnerability that the ground truth missed, say MODEL_CORRECT.
If the scanner raised a false alarm (the code is actually safe), say GROUND_TRUTH_CORRECT.
If you cannot definitively determine, say UNCERTAIN.

RESPOND WITH JSON ONLY. NO OTHER TEXT."""


def get_fn_challenge_prompt(route_key: str, code: str, ground_truth_vuln_type: str, ground_truth_description: str = None) -> str:
    """
    Generate a prompt to challenge a potential false negative.

    The model said SAFE, but ground truth says VULNERABLE.
    We need to determine who is right.
    """
    gt_details = f" - specifically: {ground_truth_description}" if ground_truth_description else ""

    return f"""You are a senior security researcher arbitrating a disagreement about a SPECIFIC vulnerability.

## The Dispute
- **Endpoint**: {route_key}
- **Scanner verdict**: SAFE (no vulnerabilities found)
- **Ground truth claim**: This endpoint has a **{ground_truth_vuln_type}** vulnerability{gt_details}

## Your Task
Determine whether the **specific claimed vulnerability ({ground_truth_vuln_type})** exists in this endpoint.

IMPORTANT:
- Focus ONLY on whether {ground_truth_vuln_type} exists in THIS endpoint ({route_key})
- Do NOT discuss vulnerabilities in other endpoints or other vulnerability types
- Trace the data flow for THIS specific endpoint from input to output

## Code
```
{code}
```

## Analysis Steps
1. Find the handler for {route_key}
2. Trace user input through that specific handler
3. Determine if the data flow creates a {ground_truth_vuln_type} vulnerability
4. Consider: even if storage is "safe", is the data later displayed without encoding?

CRITICAL: Respond with ONLY valid JSON.

{{
    "arbitration_verdict": "MODEL_CORRECT" | "GROUND_TRUTH_CORRECT" | "UNCERTAIN",
    "confidence": 0.0-1.0,
    "reasoning": "Your analysis of whether {ground_truth_vuln_type} exists in {route_key} specifically",
    "vulnerability_found": {{
        "type": "{ground_truth_vuln_type}",
        "source": "where tainted data enters",
        "sink": "where it causes harm",
        "flow": "the data flow in THIS endpoint",
        "evidence": "specific code from THIS endpoint"
    }} | null,
    "recommendation": "VULNERABLE or SAFE"
}}

RESPOND WITH JSON ONLY."""


def _parse_json_response(response: str, binding: Optional[PhaseBinding] = None) -> Optional[dict]:
    """Parse JSON response from LLM, with LLM correction fallback."""
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

    # Fallback: use LLM to correct malformed JSON
    if response.strip() and binding is not None:
        try:
            from utilities.json_corrector import JSONCorrector
            corrector = JSONCorrector(binding)
            corrected = corrector.attempt_correction(response)
            if corrected.get("verdict") != "ERROR":
                corrected["json_corrected"] = True
                return corrected
        except Exception:
            pass
    return None


class GroundTruthChallenger:
    """
    Challenges ground truths when model results contradict them.

    This is used only in test mode to:
    1. Validate false positives - is the model wrong, or is the ground truth wrong?
    2. Validate false negatives - did the model miss something, or is the ground truth wrong?
    """

    def __init__(self, binding: PhaseBinding):
        """
        Initialize the challenger.

        Args:
            binding: Phase binding for the LLM call (typically the analyze phase's).
        """
        self.binding = binding

    def challenge_false_positive(
        self,
        route_key: str,
        code: str,
        model_result: dict
    ) -> ChallengeResult:
        """
        Challenge a potential false positive.

        The model said VULNERABLE, ground truth says SAFE.

        Args:
            route_key: The endpoint being analyzed
            code: The code that was analyzed
            model_result: The model's analysis result

        Returns:
            ChallengeResult with arbitration verdict
        """
        print(f"      Challenging FP: {route_key}", file=sys.stderr)

        prompt = get_fp_challenge_prompt(
            route_key=route_key,
            code=code,
            model_reasoning=model_result.get("reasoning", ""),
            model_vulnerabilities=model_result.get("vulnerabilities", [])
        )

        try:
            response = simple_text(self.binding, prompt)
            parsed = _parse_json_response(response, binding=self.binding)

            if parsed:
                return ChallengeResult(
                    route_key=route_key,
                    challenge_type="FP",
                    model_verdict="VULNERABLE",
                    ground_truth="SAFE",
                    arbitration_verdict=parsed.get("arbitration_verdict", "UNCERTAIN"),
                    confidence=parsed.get("confidence", 0.5),
                    reasoning=parsed.get("reasoning", ""),
                    vulnerabilities_found=model_result.get("vulnerabilities", []) if parsed.get("arbitration_verdict") == "MODEL_CORRECT" else [],
                    recommendation=parsed.get("recommendation", "SAFE")
                )
        except Exception as e:
            print(f"      Challenge failed: {e}", file=sys.stderr)
            return ChallengeResult(
                route_key=route_key,
                challenge_type="FP",
                model_verdict="VULNERABLE",
                ground_truth="SAFE",
                arbitration_verdict="UNCERTAIN",
                confidence=0.0,
                reasoning=f"Arbitration failed: {str(e)}",
                vulnerabilities_found=[],
                recommendation="SAFE"
            )

        return ChallengeResult(
            route_key=route_key,
            challenge_type="FP",
            model_verdict="VULNERABLE",
            ground_truth="SAFE",
            arbitration_verdict="UNCERTAIN",
            confidence=0.0,
            reasoning="Could not parse arbitration response",
            vulnerabilities_found=[],
            recommendation="SAFE"
        )

    def challenge_false_negative(
        self,
        route_key: str,
        code: str,
        ground_truth_vuln_type: str,
        ground_truth_description: str = None
    ) -> ChallengeResult:
        """
        Challenge a potential false negative.

        The model said SAFE, ground truth says VULNERABLE.

        Args:
            route_key: The endpoint being analyzed
            code: The code that was analyzed
            ground_truth_vuln_type: The vulnerability type from ground truth
            ground_truth_description: Optional description of the vulnerability

        Returns:
            ChallengeResult with arbitration verdict
        """
        print(f"      Challenging FN: {route_key}", file=sys.stderr)
        print(f"      Code length: {len(code)} chars", file=sys.stderr)

        prompt = get_fn_challenge_prompt(
            route_key=route_key,
            code=code,
            ground_truth_vuln_type=ground_truth_vuln_type,
            ground_truth_description=ground_truth_description
        )

        try:
            response = simple_text(self.binding, prompt)
            parsed = _parse_json_response(response, binding=self.binding)

            if not parsed:
                print(f"      Failed to parse response: {response[:500]}...", file=sys.stderr)

            if parsed:
                vulns = []
                if parsed.get("vulnerability_found"):
                    vulns = [parsed["vulnerability_found"]]

                return ChallengeResult(
                    route_key=route_key,
                    challenge_type="FN",
                    model_verdict="SAFE",
                    ground_truth="VULNERABLE",
                    arbitration_verdict=parsed.get("arbitration_verdict", "UNCERTAIN"),
                    confidence=parsed.get("confidence", 0.5),
                    reasoning=parsed.get("reasoning", ""),
                    vulnerabilities_found=vulns,
                    recommendation=parsed.get("recommendation", "VULNERABLE")
                )
        except Exception as e:
            print(f"      Challenge failed: {e}", file=sys.stderr)
            return ChallengeResult(
                route_key=route_key,
                challenge_type="FN",
                model_verdict="SAFE",
                ground_truth="VULNERABLE",
                arbitration_verdict="UNCERTAIN",
                confidence=0.0,
                reasoning=f"Arbitration failed: {str(e)}",
                vulnerabilities_found=[],
                recommendation="VULNERABLE"
            )

        return ChallengeResult(
            route_key=route_key,
            challenge_type="FN",
            model_verdict="SAFE",
            ground_truth="VULNERABLE",
            arbitration_verdict="UNCERTAIN",
            confidence=0.0,
            reasoning="Could not parse arbitration response",
            vulnerabilities_found=[],
            recommendation="VULNERABLE"
        )

    def challenge_results(
        self,
        results: list[dict],
        ground_truths: dict,
        code_by_route: dict
    ) -> dict:
        """
        Challenge all false positives and false negatives in results.

        Args:
            results: List of analysis results from experiment
            ground_truths: Dict mapping route_key to {"vulnerable": bool, "type": str}
            code_by_route: Dict mapping route_key to the code that was analyzed

        Returns:
            Dict with challenge summary and individual results
        """
        challenges = {
            "false_positives": [],
            "false_negatives": [],
            "summary": {
                "total_fp_challenged": 0,
                "total_fn_challenged": 0,
                "fp_model_correct": 0,
                "fp_ground_truth_correct": 0,
                "fp_uncertain": 0,
                "fn_model_correct": 0,
                "fn_ground_truth_correct": 0,
                "fn_uncertain": 0
            }
        }

        for result in results:
            route_key = result.get("route_key")
            if not route_key or route_key not in ground_truths:
                continue

            gt = ground_truths[route_key]
            gt_vulnerable = gt.get("vulnerable", False)
            model_verdict = result.get("verdict")

            # Check for false positive (model: VULNERABLE, GT: SAFE)
            if model_verdict == "VULNERABLE" and not gt_vulnerable:
                code = code_by_route.get(route_key, "")
                challenge = self.challenge_false_positive(route_key, code, result)
                challenges["false_positives"].append(challenge.__dict__)
                challenges["summary"]["total_fp_challenged"] += 1

                if challenge.arbitration_verdict == "MODEL_CORRECT":
                    challenges["summary"]["fp_model_correct"] += 1
                elif challenge.arbitration_verdict == "GROUND_TRUTH_CORRECT":
                    challenges["summary"]["fp_ground_truth_correct"] += 1
                else:
                    challenges["summary"]["fp_uncertain"] += 1

            # Check for false negative (model: SAFE, GT: VULNERABLE)
            elif model_verdict == "SAFE" and gt_vulnerable:
                code = code_by_route.get(route_key, "")
                vuln_type = gt.get("type", "Unknown")
                vuln_description = gt.get("description", None)
                challenge = self.challenge_false_negative(route_key, code, vuln_type, vuln_description)
                challenges["false_negatives"].append(challenge.__dict__)
                challenges["summary"]["total_fn_challenged"] += 1

                if challenge.arbitration_verdict == "MODEL_CORRECT":
                    challenges["summary"]["fn_model_correct"] += 1
                elif challenge.arbitration_verdict == "GROUND_TRUTH_CORRECT":
                    challenges["summary"]["fn_ground_truth_correct"] += 1
                else:
                    challenges["summary"]["fn_uncertain"] += 1

        return challenges


def print_challenge_report(challenges: dict) -> None:
    """Print a formatted report of challenge results."""
    summary = challenges["summary"]

    print("\n" + "=" * 70, file=sys.stderr)
    print("GROUND TRUTH CHALLENGE REPORT", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    # False Positives
    print(f"\n### False Positives Challenged: {summary['total_fp_challenged']}", file=sys.stderr)
    if summary['total_fp_challenged'] > 0:
        print(f"    - Model was correct (GT wrong): {summary['fp_model_correct']}", file=sys.stderr)
        print(f"    - Ground truth was correct:    {summary['fp_ground_truth_correct']}", file=sys.stderr)
        print(f"    - Uncertain:                   {summary['fp_uncertain']}", file=sys.stderr)

        for fp in challenges["false_positives"]:
            print(f"\n    {fp['route_key']}:", file=sys.stderr)
            print(f"      Verdict: {fp['arbitration_verdict']} (confidence: {fp['confidence']:.2f})", file=sys.stderr)
            print(f"      Recommendation: {fp['recommendation']}", file=sys.stderr)
            print(f"      Reasoning: {fp['reasoning'][:200]}...", file=sys.stderr)

    # False Negatives
    print(f"\n### False Negatives Challenged: {summary['total_fn_challenged']}", file=sys.stderr)
    if summary['total_fn_challenged'] > 0:
        print(f"    - Model was correct (GT wrong): {summary['fn_model_correct']}", file=sys.stderr)
        print(f"    - Ground truth was correct:    {summary['fn_ground_truth_correct']}", file=sys.stderr)
        print(f"    - Uncertain:                   {summary['fn_uncertain']}", file=sys.stderr)

        for fn in challenges["false_negatives"]:
            print(f"\n    {fn['route_key']}:", file=sys.stderr)
            print(f"      Verdict: {fn['arbitration_verdict']} (confidence: {fn['confidence']:.2f})", file=sys.stderr)
            print(f"      Recommendation: {fn['recommendation']}", file=sys.stderr)
            print(f"      Reasoning: {fn['reasoning'][:200]}...", file=sys.stderr)

    # Overall assessment
    print("\n### Overall Assessment", file=sys.stderr)
    total_challenged = summary['total_fp_challenged'] + summary['total_fn_challenged']
    model_correct = summary['fp_model_correct'] + summary['fn_model_correct']
    gt_correct = summary['fp_ground_truth_correct'] + summary['fn_ground_truth_correct']
    uncertain = summary['fp_uncertain'] + summary['fn_uncertain']

    if total_challenged > 0:
        print(f"    Total challenges: {total_challenged}", file=sys.stderr)
        print(f"    Model likely correct: {model_correct} ({100*model_correct/total_challenged:.1f}%)", file=sys.stderr)
        print(f"    Ground truth likely correct: {gt_correct} ({100*gt_correct/total_challenged:.1f}%)", file=sys.stderr)
        print(f"    Uncertain: {uncertain} ({100*uncertain/total_challenged:.1f}%)", file=sys.stderr)

        if model_correct > gt_correct:
            print("\n    >>> The model appears to be MORE accurate than the ground truth!", file=sys.stderr)
            print("    >>> Consider reviewing and updating the ground truth dataset.", file=sys.stderr)
        elif gt_correct > model_correct:
            print("\n    >>> The ground truth appears to be correct.", file=sys.stderr)
            print("    >>> Model may need tuning to reduce false positives/negatives.", file=sys.stderr)

    print("\n" + "=" * 70, file=sys.stderr)


def test_challenger():
    """Test the ground truth challenger with sample data."""
    from .llm import build_phase_registry, load_config_file, resolve_llm_config

    print("Testing Ground Truth Challenger", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, None))
    challenger = GroundTruthChallenger(registry.get("analyze"))

    # Sample FP test case
    fp_code = """
// Route: POST:/app/products
router.post('/products', isAuthenticated, function(req, res) {
    var name = req.body.name;
    var code = req.body.code;
    var tags = req.body.tags;

    // Using parameterized query
    db.query('INSERT INTO products (name, code, tags) VALUES (?, ?, ?)',
             [name, code, tags], function(err, results) {
        if (err) {
            return res.status(500).json({error: 'Database error'});
        }
        res.json({success: true, id: results.insertId});
    });
});
"""

    fp_result = {
        "verdict": "VULNERABLE",
        "confidence": 0.85,
        "vulnerabilities": [{
            "type": "SQL Injection",
            "severity": "HIGH",
            "source": "req.body.name, req.body.code, req.body.tags",
            "sink": "db.query()",
            "flow": "User input -> INSERT query",
            "evidence": "db.query('INSERT INTO products...')",
            "why_vulnerable": "User input inserted into SQL query"
        }],
        "reasoning": "User-controlled input from request body is used in database query"
    }

    print("\n--- Testing False Positive Challenge ---", file=sys.stderr)
    print(f"Code: {fp_code[:100]}...", file=sys.stderr)
    print(f"Model says: VULNERABLE (SQL Injection)", file=sys.stderr)
    print(f"Ground truth says: SAFE", file=sys.stderr)

    fp_challenge = challenger.challenge_false_positive(
        route_key="POST:/app/products",
        code=fp_code,
        model_result=fp_result
    )

    print(f"\nArbitration result:", file=sys.stderr)
    print(f"  Verdict: {fp_challenge.arbitration_verdict}", file=sys.stderr)
    print(f"  Confidence: {fp_challenge.confidence}", file=sys.stderr)
    print(f"  Recommendation: {fp_challenge.recommendation}", file=sys.stderr)
    print(f"  Reasoning: {fp_challenge.reasoning[:200]}...", file=sys.stderr)

    # Sample FN test case
    fn_code = """
// Route: GET:/app/redirect
router.get('/redirect', function(req, res) {
    var url = req.query.url;
    if (url) {
        res.redirect(url);
    } else {
        res.redirect('/home');
    }
});
"""

    print("\n--- Testing False Negative Challenge ---", file=sys.stderr)
    print(f"Code: {fn_code[:100]}...", file=sys.stderr)
    print(f"Model says: SAFE", file=sys.stderr)
    print(f"Ground truth says: VULNERABLE (Open Redirect)", file=sys.stderr)

    fn_challenge = challenger.challenge_false_negative(
        route_key="GET:/app/redirect",
        code=fn_code,
        ground_truth_vuln_type="Open Redirect"
    )

    print(f"\nArbitration result:", file=sys.stderr)
    print(f"  Verdict: {fn_challenge.arbitration_verdict}", file=sys.stderr)
    print(f"  Confidence: {fn_challenge.confidence}", file=sys.stderr)
    print(f"  Recommendation: {fn_challenge.recommendation}", file=sys.stderr)
    print(f"  Reasoning: {fn_challenge.reasoning[:200]}...", file=sys.stderr)

    print("\n" + "=" * 60, file=sys.stderr)


if __name__ == "__main__":
    test_challenger()
