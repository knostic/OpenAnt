"""Stage 1 analysis primitives.

These three functions were defined in ``experiment.py`` — a research harness that
is NOT a packaged module — and imported from there by ``core/analyzer.py``. That
made the installed product unimportable: `pip install openant` ships the seven
packages listed in pyproject, `experiment.py` is a loose top-level file, and
``import core.analyzer`` raised ModuleNotFoundError in any clean environment.
Verified by building a wheel and installing it into an empty venv.

The dependency also ran the wrong way round: production reaching into research
code. It now runs research -> product; ``experiment.py`` imports these from here.

Nothing else moved. These were chosen because they are exactly what ``core`` used
and they depend only on stdlib and shipped packages (utilities/, prompts/).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from datetime import datetime

from prompts.prompt_selector import get_analysis_prompt
from prompts.vulnerability_analysis import get_system_prompt as get_stage1_system_prompt
from utilities.context_reviewer import ContextReviewer
from utilities.json_corrector import JSONCorrector
from utilities.llm import PhaseBinding, simple_text

if TYPE_CHECKING:  # avoids a runtime cycle: context/ imports utilities/ which
    # imports prompts/ which imports core/. The annotation is a string either way.
    from context.application_context import ApplicationContext

def _normalize_result(result: dict) -> dict:
    """Normalize LLM response fields to canonical names.

    Handles cases where the model returns 'finding' instead of 'verdict',
    or uses different casing/naming conventions.
    """
    # Normalize finding -> verdict
    if "verdict" not in result and "finding" in result:
        finding = result["finding"]
        if not isinstance(finding, str):
            # A non-string finding (list/dict/null/number) is a malformed model reply,
            # not a verdict — map it to ERROR so the error / manual-review accounting
            # counts it, instead of a garbage verdict (e.g. "['VULNERABLE']" from
            # str(finding).upper()) that silently escapes that accounting.
            result["verdict"] = "ERROR"
        else:
            finding_to_verdict = {
                "vulnerable": "VULNERABLE",
                "safe": "SAFE",
                "protected": "PROTECTED",
                "bypassable": "BYPASSABLE",
                "inconclusive": "INCONCLUSIVE",
                "insufficient_context": "INSUFFICIENT_CONTEXT",
            }
            result["verdict"] = finding_to_verdict.get(finding.lower(), finding.upper())

    # Ensure verdict is uppercase
    if "verdict" in result and isinstance(result["verdict"], str):
        result["verdict"] = result["verdict"].upper()

    # Ensure CWE fields are always present.
    if "cwe_id" not in result:
        result["cwe_id"] = 0
    if "cwe_name" not in result:
        result["cwe_name"] = None

    return result


def parse_response(response: str) -> dict:
    """Parse JSON response from Claude."""
    # Try to extract JSON from response
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
        result = json.loads(response)
        return _normalize_result(result)
    except json.JSONDecodeError as e:
        # Try to find JSON object in response
        start = response.find("{")
        end = response.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                result = json.loads(response[start:end])
                return _normalize_result(result)
            except json.JSONDecodeError:
                pass

        return {
            "verdict": "ERROR",
            "confidence": 0,
            "vulnerabilities": [],
            "reasoning": f"Failed to parse response: {str(e)}",
            "raw_response": response[:500]
        }


def analyze_unit(
    binding: PhaseBinding,
    unit: dict,
    use_multifile: bool = False,
    json_corrector: JSONCorrector = None,
    context_reviewer: ContextReviewer = None,
    app_context: "ApplicationContext" = None
) -> dict:
    """
    Analyze a single code unit.

    Args:
        binding: Phase binding (provider+model) for the analyze phase.
        unit: The code unit to analyze
        use_multifile: If True, use multi-file prompt for enhanced datasets
        json_corrector: Optional JSON corrector. If not provided, one is created
                        internally when parsing fails (matching behavior of other
                        LLM-calling components like finding_verifier and context_enhancer).
        context_reviewer: Optional context reviewer for proactive context enhancement
        app_context: Optional ApplicationContext for reducing false positives

    Returns analysis result with timing and token info.
    """
    # Extract code from unit
    code_field = unit.get("code", {})
    if isinstance(code_field, dict):
        code = code_field.get("primary_code", "")
        # Check if dependencies were inlined into this unit's primary_code
        primary_origin = code_field.get("primary_origin", {})
        has_deps_inlined = primary_origin.get("deps_inlined", primary_origin.get("enhanced", False))
        files_included = primary_origin.get("files_included", [])
    else:
        code = code_field
        has_deps_inlined = False
        files_included = []

    # Extract agent context (security classification from agentic parser)
    agent_context = unit.get("agent_context", {})
    security_classification = agent_context.get("security_classification")
    classification_reasoning = agent_context.get("reasoning")

    # Get route info
    route = unit.get("route") or {}
    if route:
        route_key = f"{route.get('method', 'GET')}:{route.get('path', '/unknown')}"
        handler = route.get("handler", "main")
    else:
        # Non-route unit: use unit ID as identifier
        route_key = unit.get("id", "unknown")
        handler = route_key.split(":")[-1] if ":" in route_key else route_key

    # Language defaults to "code" for generic code block formatting
    language = "code"

    # Proactively enhance context if reviewer is enabled
    context_enhanced = False
    additional_files_added = []
    if context_reviewer and use_multifile:
        print(f"      Reviewing context for missing files...")
        enhanced_code, enhanced_files = context_reviewer.enhance_context(
            code=code,
            route=route_key,
            handler=handler,
            files_included=files_included
        )
        if len(enhanced_files) > len(files_included):
            additional_files_added = [f for f in enhanced_files if f not in files_included]
            code = enhanced_code
            files_included = enhanced_files
            context_enhanced = True
            print(f"      Added {len(additional_files_added)} files via LLM review")

    # Generate prompt - single unified prompt for all cases
    prompt = get_analysis_prompt(
        code=code,
        language=language,
        route=route_key,
        files_included=files_included,
        security_classification=security_classification,
        classification_reasoning=classification_reasoning,
        app_context=app_context
    )

    # Call the configured analyze-phase model with the threat-model system prompt.
    start_time = datetime.now()
    system_prompt = get_stage1_system_prompt(app_context=app_context)
    response = simple_text(binding, prompt, system=system_prompt)
    elapsed = (datetime.now() - start_time).total_seconds()

    # Parse response
    result = parse_response(response)

    # If parsing failed or verdict is missing, try JSON correction
    if result.get("verdict") in ("ERROR", None):
        # Create JSONCorrector internally if not provided (same pattern as other components).
        # JSONCorrector inherits the analyze binding — correction calls
        # go to the same provider+model as the failing call.
        if json_corrector is None:
            json_corrector = JSONCorrector(binding)
        corrected = json_corrector.attempt_correction(response)
        corrected = _normalize_result(corrected)
        if corrected.get("verdict") not in ("ERROR", None):
            result = corrected

    result["route_key"] = route_key
    result["elapsed_seconds"] = elapsed
    result["prompt_length"] = len(prompt)
    result["response_length"] = len(response)
    result["code_length"] = len(code)
    result["files_included"] = files_included
    result["has_deps_inlined"] = has_deps_inlined
    result["context_reviewed"] = context_enhanced
    if additional_files_added:
        result["files_added_by_review"] = additional_files_added

    # Track security classification from agentic parser
    if security_classification:
        result["security_classification"] = security_classification
        result["classification_reasoning"] = classification_reasoning

    return result
