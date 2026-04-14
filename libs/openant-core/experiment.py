#!/usr/bin/env python3
"""
OpenAnt Experiment Runner - Two-Stage Vulnerability Analysis

Runs vulnerability analysis on code datasets using a two-stage pipeline:

    Stage 1 (Detection): Claude analyzes each code unit with simple prompts
                         asking "What does this code do?" and "What is the risk?"

    Stage 2 (Verification): Opus with tool access validates each Stage 1 finding
                            by exploring the codebase (search usages, read functions)

Finding Categories:
    - vulnerable: Exploitable vulnerability, no protection
    - bypassable: Security controls can be circumvented
    - inconclusive: Cannot determine security posture
    - protected: Dangerous operations with effective controls
    - safe: No security-sensitive operations

Usage:
    python experiment.py --dataset flowise --verify          # Full two-stage analysis
    python experiment.py --dataset flowise                   # Stage 1 only
    python experiment.py --dataset flowise --verify-verbose  # Verbose Stage 2 output
    python experiment.py --dataset dvna --limit 5            # Analyze first 5 units

Output:
    experiment_{dataset}_{model}_{timestamp}.json
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from utilities.llm_client import AnthropicClient, get_global_tracker
from prompts.prompt_selector import get_analysis_prompt
from prompts.vulnerability_analysis import get_system_prompt as get_stage1_system_prompt
from utilities.context_corrector import ContextCorrector
from utilities.json_corrector import JSONCorrector
from utilities.ground_truth_challenger import GroundTruthChallenger, print_challenge_report
from utilities.context_reviewer import ContextReviewer
from utilities.finding_verifier import FindingVerifier
from utilities.agentic_enhancer.repository_index import RepositoryIndex, load_index_from_file

# Import application context (optional - for reducing false positives)
try:
    from context.application_context import ApplicationContext, load_context
    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False
    ApplicationContext = None
    load_context = None


# Path to datasets (local to this project)
DATASETS_PATH = os.path.join(os.path.dirname(__file__), "datasets")

DATASETS = {
    "dvna": os.path.join(DATASETS_PATH, "dvna/dataset.json"),
    "nodegoat": os.path.join(DATASETS_PATH, "nodegoat/dataset.json"),
    "juice_shop": os.path.join(DATASETS_PATH, "juice_shop/dataset.json"),
    "flowise": os.path.join(DATASETS_PATH, "flowise/dataset.json"),
    "flowise_vuln4": os.path.join(DATASETS_PATH, "flowise/dataset_vulnerable_4.json"),
    "flowise_test10": os.path.join(DATASETS_PATH, "flowise/test_10_units.json"),
    "github_patches": os.path.join(DATASETS_PATH, "github_patches/dataset_10_samples.json"),
    "github_patches_2": os.path.join(DATASETS_PATH, "github_patches/dataset_2_samples.json"),
    "github_patches_6": os.path.join(DATASETS_PATH, "github_patches/dataset_6_samples.json"),
    "github_patches_v2_new": os.path.join(DATASETS_PATH, "github_patches/dataset_v2_new_only.json"),
    "github_patches_9_misclassified": os.path.join(DATASETS_PATH, "github_patches/dataset_9_misclassified.json"),
    "geospatial": os.path.join(DATASETS_PATH, "geospatial/dataset.json"),
    "geospatial_vuln12": os.path.join(DATASETS_PATH, "geospatial/dataset_vulnerable_12.json"),
    "object_browser": os.path.join(DATASETS_PATH, "object_browser/dataset.json"),
    "object_browser_vuln25": os.path.join(DATASETS_PATH, "object_browser/dataset_vulnerable_25.json"),
    "uptime_kuma": os.path.join(DATASETS_PATH, "uptime_kuma/dataset.json"),
    "code_server": os.path.join(DATASETS_PATH, "code_server_exploitable/dataset.json"),
    "code_server_vuln4": os.path.join(DATASETS_PATH, "code_server_vulnerable/dataset.json"),
    "anything_llm": os.path.join(DATASETS_PATH, "anything_llm_exploitable/dataset.json"),
    "flowise_non_codeql": os.path.join(DATASETS_PATH, "flowise/dataset_non_codeql_exploitable.json"),
    "flowise_stage1_vuln": os.path.join(DATASETS_PATH, "flowise/dataset_stage1_vulnerable.json"),
    "langchain": os.path.join(DATASETS_PATH, "langchain/dataset_exploitable.json"),
    "langchain_vuln": os.path.join(DATASETS_PATH, "langchain/dataset_stage1_vulnerable.json"),
    "flask": os.path.join(DATASETS_PATH, "flask/dataset_filtered.json"),
    "paperless": os.path.join(DATASETS_PATH, "paperless-ngx/dataset_exploitable.json"),
    "paperless_stage2": os.path.join(DATASETS_PATH, "paperless-ngx/dataset_stage2.json"),
    "n8n": os.path.join(DATASETS_PATH, "n8n/dataset_exploitable.json"),
}

ENHANCED_DATASETS = {
    "dvna": os.path.join(DATASETS_PATH, "dvna/dataset_enhanced.json"),
    "nodegoat": os.path.join(DATASETS_PATH, "nodegoat/dataset_enhanced.json"),
    "juice_shop": os.path.join(DATASETS_PATH, "juice_shop/dataset_enhanced.json"),
    "flowise": os.path.join(DATASETS_PATH, "flowise/dataset.json"),
    "flowise_vuln4": os.path.join(DATASETS_PATH, "flowise/dataset_vulnerable_4.json"),
    "flowise_test10": os.path.join(DATASETS_PATH, "flowise/test_10_units.json"),
    "github_patches": os.path.join(DATASETS_PATH, "github_patches/dataset_10_samples.json"),
    "github_patches_2": os.path.join(DATASETS_PATH, "github_patches/dataset_2_samples.json"),
    "github_patches_6": os.path.join(DATASETS_PATH, "github_patches/dataset_6_samples.json"),
    "github_patches_v2_new": os.path.join(DATASETS_PATH, "github_patches/dataset_v2_new_only.json"),
    "github_patches_9_misclassified": os.path.join(DATASETS_PATH, "github_patches/dataset_9_misclassified.json"),
    "geospatial": os.path.join(DATASETS_PATH, "geospatial/dataset.json"),
    "geospatial_vuln12": os.path.join(DATASETS_PATH, "geospatial/dataset_vulnerable_12.json"),
    "object_browser": os.path.join(DATASETS_PATH, "object_browser/dataset.json"),
    "object_browser_vuln25": os.path.join(DATASETS_PATH, "object_browser/dataset_vulnerable_25.json"),
    "uptime_kuma": os.path.join(DATASETS_PATH, "uptime_kuma/dataset.json"),
    "code_server": os.path.join(DATASETS_PATH, "code_server_exploitable/dataset.json"),
    "code_server_vuln4": os.path.join(DATASETS_PATH, "code_server_vulnerable/dataset.json"),
    "anything_llm": os.path.join(DATASETS_PATH, "anything_llm_exploitable/dataset.json"),
    "flowise_non_codeql": os.path.join(DATASETS_PATH, "flowise/dataset_non_codeql_exploitable.json"),
    "flowise_stage1_vuln": os.path.join(DATASETS_PATH, "flowise/dataset_stage1_vulnerable.json"),
    "langchain": os.path.join(DATASETS_PATH, "langchain/dataset_exploitable.json"),
    "langchain_vuln": os.path.join(DATASETS_PATH, "langchain/dataset_stage1_vulnerable.json"),
    "flask": os.path.join(DATASETS_PATH, "flask/dataset_filtered.json"),
    "paperless": os.path.join(DATASETS_PATH, "paperless-ngx/dataset_exploitable.json"),
    "paperless_stage2": os.path.join(DATASETS_PATH, "paperless-ngx/dataset_stage2.json"),
    "n8n": os.path.join(DATASETS_PATH, "n8n/dataset_exploitable.json"),
}

GROUND_TRUTHS = {
    "dvna": os.path.join(DATASETS_PATH, "dvna/ground_truth.json"),
    "nodegoat": os.path.join(DATASETS_PATH, "nodegoat/ground_truth.json"),
    "juice_shop": os.path.join(DATASETS_PATH, "juice_shop/ground_truth.json"),
    "github_patches": os.path.join(DATASETS_PATH, "github_patches/ground_truth.json"),
    "github_patches_2": os.path.join(DATASETS_PATH, "github_patches/ground_truth.json"),
}

# Repository paths for context correction
REPO_PATHS = {
    "dvna": "/Users/nahumkorda/code/dvna",
    "nodegoat": "/Users/nahumkorda/code/NodeGoat",
    "juice_shop": "/Users/nahumkorda/code/juice-shop",
    "flowise": "/Users/nahumkorda/code/test_repos/Flowise",
    "geospatial": "/Users/nahumkorda/code/test_repos/streamlit-geospatial",
    "object_browser": "/Users/nahumkorda/code/test_repos/object-browser",
    "object_browser_vuln25": "/Users/nahumkorda/code/test_repos/object-browser",
    "uptime_kuma": "/Users/nahumkorda/code/test_repos/uptime-kuma",
    "code_server": "/Users/nahumkorda/code/test_repos/code-server",
    "code_server_vuln4": "/Users/nahumkorda/code/test_repos/code-server",
    "anything_llm": "/Users/nahumkorda/code/test_repos/anything-llm",
    "flowise_non_codeql": "/Users/nahumkorda/code/test_repos/Flowise",
    "flowise_stage1_vuln": "/Users/nahumkorda/code/test_repos/Flowise",
    "langchain": "/Users/nahumkorda/code/test_repos/langchain",
    "langchain_vuln": "/Users/nahumkorda/code/test_repos/langchain",
    "flask": "/Users/nahumkorda/code/test_repos/flask",
    "paperless": "/Users/nahumkorda/code/test_repos/paperless-ngx",
    "paperless_stage2": "/Users/nahumkorda/code/test_repos/paperless-ngx",
    "n8n": "/Users/nahumkorda/code/test_repos/n8n",
}

# Analyzer output paths for Stage 2 verification (repository index)
ANALYZER_OUTPUTS = {
    "flowise": os.path.join(DATASETS_PATH, "flowise/analyzer_output.json"),
    "flowise_vuln4": os.path.join(DATASETS_PATH, "flowise/analyzer_output.json"),
    "geospatial": os.path.join(DATASETS_PATH, "geospatial/analyzer_output.json"),
    "geospatial_vuln12": os.path.join(DATASETS_PATH, "geospatial/analyzer_output_vulnerable_12.json"),
    "object_browser": os.path.join(DATASETS_PATH, "object_browser/analyzer_output.json"),
    "object_browser_vuln25": os.path.join(DATASETS_PATH, "object_browser/analyzer_output.json"),
    "uptime_kuma": os.path.join(DATASETS_PATH, "uptime_kuma/analyzer_output.json"),
    "code_server": os.path.join(DATASETS_PATH, "code_server_non_codeql/analyzer_output.json"),
    "code_server_vuln4": os.path.join(DATASETS_PATH, "code_server_non_codeql/analyzer_output.json"),
    "anything_llm": os.path.join(DATASETS_PATH, "anything_llm_exploitable/analyzer_output.json"),
    "flowise_non_codeql": os.path.join(DATASETS_PATH, "flowise/analyzer_output.json"),
    "flowise_stage1_vuln": os.path.join(DATASETS_PATH, "flowise/analyzer_output.json"),
    "langchain": os.path.join(DATASETS_PATH, "langchain/analyzer_output.json"),
    "langchain_vuln": os.path.join(DATASETS_PATH, "langchain/analyzer_output.json"),
    "flask": os.path.join(DATASETS_PATH, "flask/analyzer_output.json"),
    "paperless": os.path.join(DATASETS_PATH, "paperless-ngx/analyzer_output.json"),
    "paperless_stage2": os.path.join(DATASETS_PATH, "paperless-ngx/analyzer_output.json"),
    "n8n": os.path.join(DATASETS_PATH, "n8n/analyzer_output_with_callgraph.json"),
}

# Application context paths for reducing false positives
# These are generated by: python -m context.generate_context /path/to/repo
APPLICATION_CONTEXTS = {
    "langchain": os.path.join(DATASETS_PATH, "langchain/application_context.json"),
    "langchain_vuln": os.path.join(DATASETS_PATH, "langchain/application_context.json"),
    "flask": os.path.join(DATASETS_PATH, "flask/application_context.json"),
    "paperless": os.path.join(DATASETS_PATH, "paperless-ngx/application_context.json"),
    "paperless_stage2": os.path.join(DATASETS_PATH, "paperless-ngx/application_context.json"),
}


def load_application_context(dataset_name: str) -> "ApplicationContext | None":
    """Load application context for a dataset if available.

    Args:
        dataset_name: Name of the dataset.

    Returns:
        ApplicationContext if available, None otherwise.
    """
    if not HAS_APP_CONTEXT:
        return None

    context_path = APPLICATION_CONTEXTS.get(dataset_name)
    if not context_path or not os.path.exists(context_path):
        return None

    try:
        return load_context(Path(context_path))
    except Exception as e:
        print(f"Warning: Could not load application context: {e}")
        return None


def load_dataset(name: str, enhanced: bool = False) -> dict:
    """Load a dataset by name."""
    datasets = ENHANCED_DATASETS if enhanced else DATASETS
    path = datasets.get(name)
    if not path or not os.path.exists(path):
        raise ValueError(f"Dataset not found: {name} (enhanced={enhanced})")

    with open(path, "r") as f:
        return json.load(f)


def load_ground_truth(name: str) -> dict:
    """Load ground truth for a dataset."""
    path = GROUND_TRUTHS.get(name)
    if not path or not os.path.exists(path):
        return {}

    with open(path, "r") as f:
        return json.load(f)


def get_ground_truth_verdict(ground_truth: dict, route_key: str) -> str:
    """
    Get the expected verdict for a route from ground truth.

    Uses standard ground truth schema: categories.true_positives / categories.true_negatives

    Returns: "VULNERABLE", "SAFE", or "UNKNOWN"
    """
    categories = ground_truth.get("categories", {})

    # Check true_positives (vulnerable routes)
    true_positives = categories.get("true_positives", {}).get("routes", [])
    for route in true_positives:
        if route.get("route_key") == route_key:
            return "VULNERABLE"

    # Check true_negatives (safe routes)
    true_negatives = categories.get("true_negatives", {}).get("routes", [])
    for route in true_negatives:
        if route.get("route_key") == route_key:
            return "SAFE"

    return "UNKNOWN"


def _normalize_result(result: dict) -> dict:
    """Normalize LLM response fields to canonical names.

    Handles cases where the model returns 'finding' instead of 'verdict',
    or uses different casing/naming conventions.
    """
    # Normalize finding -> verdict
    if "verdict" not in result and "finding" in result:
        finding = result["finding"]
        # Map finding values to verdict values
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
    client: AnthropicClient,
    unit: dict,
    use_multifile: bool = False,
    json_corrector: JSONCorrector = None,
    context_reviewer: ContextReviewer = None,
    app_context: "ApplicationContext" = None
) -> dict:
    """
    Analyze a single code unit.

    Args:
        client: Anthropic client
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

    # Call Claude with system prompt for threat model awareness
    start_time = datetime.now()
    system_prompt = get_stage1_system_prompt(app_context=app_context)
    response = client.analyze_sync(prompt, system=system_prompt)
    elapsed = (datetime.now() - start_time).total_seconds()

    # Parse response
    result = parse_response(response)

    # If parsing failed or verdict is missing, try JSON correction
    if result.get("verdict") in ("ERROR", None):
        # Create JSONCorrector internally if not provided (same pattern as other components)
        if json_corrector is None:
            json_corrector = JSONCorrector(client)
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


def run_experiment(
    dataset_name: str,
    limit: int = None,
    model: str = "opus",
    enhanced: bool = True,
    correct_context: bool = True,
    correct_json: bool = True,
    challenge_ground_truth: bool = True,
    review_context: bool = False,
    verify: bool = False,
    verify_verbose: bool = False
) -> dict:
    """
    Run the experiment on a dataset.

    Args:
        dataset_name: Name of dataset to analyze
        limit: Max number of units to analyze (None = all)
        model: "opus" or "sonnet"
        enhanced: If True, use enhanced datasets with multi-file context (default: True)
        correct_context: If True, attempt to correct INSUFFICIENT_CONTEXT by finding missing code (default: True)
        correct_json: If True, attempt to correct malformed JSON responses using LLM (default: True)
        challenge_ground_truth: If True, challenge FP/FN cases with LLM arbitration (default: True)
        review_context: If True, use LLM to proactively review and enhance context before analysis (default: False, expensive)
        verify: If True, run Stage 2 verification on all results (default: False)
        verify_verbose: If True, print verbose output during verification (default: False)

    Returns:
        Experiment results with metrics
    """
    # Select model
    model_id = "claude-opus-4-20250514" if model == "opus" else "claude-sonnet-4-20250514"
    print(f"Using model: {model_id}")
    print(f"Enhanced context: {enhanced}")
    print(f"Context correction: {correct_context}")
    print(f"JSON correction: {correct_json}")
    print(f"Challenge ground truth: {challenge_ground_truth}")
    print(f"Review context (LLM): {review_context}")
    print(f"Stage 2 verification: {verify}")

    # Initialize client
    client = AnthropicClient(model=model_id)

    # Initialize context corrector if enabled
    corrector = None
    if correct_context:
        repo_path = REPO_PATHS.get(dataset_name)
        if repo_path and os.path.exists(repo_path):
            corrector = ContextCorrector(client, repo_path, max_retries=2)
            print(f"Context corrector enabled (repo: {repo_path})")

    # Initialize JSON corrector if enabled
    json_corrector = None
    if correct_json:
        json_corrector = JSONCorrector(client)
        print("JSON corrector enabled")

    # Initialize context reviewer if enabled
    context_reviewer = None
    if review_context:
        repo_path = REPO_PATHS.get(dataset_name)
        if repo_path and os.path.exists(repo_path):
            context_reviewer = ContextReviewer(client, repo_path)
            print(f"Context reviewer enabled (repo: {repo_path})")

    # Load application context if available (reduces false positives)
    app_context = load_application_context(dataset_name)
    if app_context:
        print(f"Application context loaded: {app_context.application_type}")
        print(f"  Purpose: {app_context.purpose[:80]}...")
        print(f"  Requires remote trigger: {app_context.requires_remote_trigger}")
    else:
        print("No application context available (run: python -m context.generate_context /path/to/repo)")

    # Load data
    print(f"Loading dataset: {dataset_name}")
    dataset = load_dataset(dataset_name, enhanced=enhanced)
    ground_truth = load_ground_truth(dataset_name)

    units = dataset.get("units", [])
    if limit:
        units = units[:limit]

    print(f"Analyzing {len(units)} units...")
    print("-" * 60)

    results = []
    code_by_route = {}  # Track code for each route (for challenger)
    metrics = {
        "total": len(units),
        "true_positives": 0,
        "true_negatives": 0,
        "false_positives": 0,
        "false_negatives": 0,
        "unknown_ground_truth": 0,
        "insufficient_context": 0,
        "corrections_attempted": 0,
        "corrections_successful": 0,
        "json_corrections_attempted": 0,
        "json_corrections_successful": 0,
        "errors": 0,
    }

    for i, unit in enumerate(units):
        unit_id = unit.get("id", f"unit_{i}")
        # Check for security classification from agentic parser
        agent_context = unit.get("agent_context", {})
        security_classification = agent_context.get("security_classification")
        classification_tag = f" [{security_classification}]" if security_classification else ""
        print(f"[{i+1}/{len(units)}] Analyzing {unit_id}{classification_tag}...")

        try:
            result = analyze_unit(client, unit, use_multifile=enhanced, json_corrector=json_corrector, context_reviewer=context_reviewer, app_context=app_context)

            # Track code for this route (for challenger)
            code_field = unit.get("code", {})
            route = unit.get("route") or {}
            if route:
                route_key = f"{route.get('method', 'GET')}:{route.get('path', '/unknown')}"
            else:
                route_key = unit.get("id", "unknown")
            if isinstance(code_field, dict):
                code_by_route[route_key] = code_field.get("primary_code", "")
            else:
                code_by_route[route_key] = code_field

            # Track JSON corrections
            if result.get("json_corrected"):
                metrics["json_corrections_attempted"] += 1
                metrics["json_corrections_successful"] += 1
            elif result.get("json_correction_attempted"):
                metrics["json_corrections_attempted"] += 1

            # Attempt correction if INSUFFICIENT_CONTEXT and corrector is enabled
            if result.get("verdict") == "INSUFFICIENT_CONTEXT" and corrector:
                print(f"      Attempting context correction...")
                metrics["corrections_attempted"] += 1

                # Get original code and files for correction
                code_field = unit.get("code", {})
                original_code = code_field.get("primary_code", "") if isinstance(code_field, dict) else code_field
                files_included = code_field.get("primary_origin", {}).get("files_included", []) if isinstance(code_field, dict) else []

                # Get route info for prompt generation
                route = unit.get("route") or {}
                if route:
                    route_key = f"{route.get('method', 'GET')}:{route.get('path', '/unknown')}"
                    handler = route.get("handler", "main")
                else:
                    route_key = unit.get("id", "unknown")
                    handler = route_key.split(":")[-1] if ":" in route_key else route_key

                # Language defaults to "code" for generic code block formatting
                language = "code"

                # Create a prompt generator function for the corrector
                def make_prompt(expanded_code, expanded_files):
                    return get_analysis_prompt(
                        code=expanded_code,
                        language=language,
                        route=route_key,
                        files_included=expanded_files
                    )

                # Attempt correction
                corrected_result = corrector.attempt_correction(
                    original_result=result,
                    original_code=original_code,
                    prompt_generator=make_prompt,
                    files_included=files_included
                )

                # Check if correction was successful
                if corrected_result.get("verdict") != "INSUFFICIENT_CONTEXT":
                    metrics["corrections_successful"] += 1
                    print(f"      Correction successful! New verdict: {corrected_result.get('verdict')}")
                    if corrected_result.get("files_added"):
                        print(f"      Added files: {', '.join(corrected_result['files_added'])}")
                else:
                    correction_status = corrected_result.get("correction_status", "unknown")
                    print(f"      Correction failed: {correction_status}")

                # Preserve route_key and other metadata from original result
                corrected_result["route_key"] = result.get("route_key")
                corrected_result["code_length"] = result.get("code_length")
                corrected_result["has_deps_inlined"] = result.get("has_deps_inlined")
                result = corrected_result

            results.append(result)

            # Get ground truth
            expected = get_ground_truth_verdict(ground_truth, result["route_key"])
            actual = result.get("verdict", "ERROR")

            result["expected"] = expected
            result["correct"] = (expected == actual) if expected != "UNKNOWN" else None

            # Update metrics
            if actual == "INSUFFICIENT_CONTEXT":
                metrics["insufficient_context"] += 1
            elif expected == "UNKNOWN":
                metrics["unknown_ground_truth"] += 1
            elif actual == "ERROR":
                metrics["errors"] += 1
            elif expected == "VULNERABLE" and actual == "VULNERABLE":
                metrics["true_positives"] += 1
            elif expected == "SAFE" and actual == "SAFE":
                metrics["true_negatives"] += 1
            elif expected == "SAFE" and actual == "VULNERABLE":
                metrics["false_positives"] += 1
            elif expected == "VULNERABLE" and actual == "SAFE":
                metrics["false_negatives"] += 1
            elif expected == "VULNERABLE" and actual == "INSUFFICIENT_CONTEXT":
                # Count as false negative (missed vulnerability)
                metrics["false_negatives"] += 1

            # Print result
            status = "?" if expected == "UNKNOWN" else ("✓" if result["correct"] else "✗")
            print(f"    {status} Verdict: {actual} (expected: {expected})")
            print(f"      Confidence: {result.get('confidence', 'N/A')}")
            print(f"      Time: {result.get('elapsed_seconds', 0):.1f}s")
            print(f"      Code: {result.get('code_length', 0):,} chars")

            if result.get("vulnerabilities"):
                for vuln in result["vulnerabilities"][:2]:  # Show first 2
                    print(f"      - {vuln.get('type')}: {vuln.get('sink', '')[:50]}")

        except Exception as e:
            print(f"    ✗ Error: {str(e)}")
            metrics["errors"] += 1
            results.append({
                "unit_id": unit_id,
                "verdict": "ERROR",
                "error": str(e)
            })

        print()

    # Stage 2: Verification (if enabled)
    if verify:
        print("\n" + "=" * 60)
        print("STAGE 2: VERIFYING ALL RESULTS...")
        print("=" * 60)

        # Load repository index
        analyzer_output_path = ANALYZER_OUTPUTS.get(dataset_name)
        if not analyzer_output_path or not os.path.exists(analyzer_output_path):
            print(f"WARNING: No analyzer_output.json found for {dataset_name}")
            print("Stage 2 verification requires analyzer_output.json from parser pipeline")
            print("Skipping verification...")
        else:
            print(f"Loading repository index from: {analyzer_output_path}")
            repo_index = load_index_from_file(analyzer_output_path)
            print(f"Index loaded: {len(repo_index.functions)} functions")

            verifier = FindingVerifier(
                index=repo_index,
                tracker=get_global_tracker(),
                verbose=verify_verbose,
                app_context=app_context
            )

            # Track verification metrics
            metrics["verifications_total"] = 0
            metrics["verifications_agreed"] = 0
            metrics["verifications_disagreed"] = 0
            metrics["consistency_updates"] = 0

            # Include ALL results for verification (including inconclusive and those with missing finding)
            # Stage 2 should verify everything to catch Stage 1 errors
            valid_results = []
            for r in results:
                finding = r.get("finding")
                # If finding is None but verdict exists (from JSON correction), use verdict
                if finding is None and r.get("verdict"):
                    r["finding"] = r["verdict"].lower()
                    finding = r["finding"]
                # Include everything except hard errors
                if r.get("verdict") != "ERROR" or finding:
                    valid_results.append(r)
            print(f"Verifying {len(valid_results)} results with consistency check...")
            print()

            # Use batch verification with consistency cross-check
            for i, result in enumerate(valid_results):
                route_key = result.get("route_key", "unknown")
                stage1_finding = result.get("finding", "inconclusive")

                print(f"[{i+1}/{len(valid_results)}] Verifying: {route_key}")
                print(f"    Stage 1 finding: {stage1_finding}")

                try:
                    # Get code for this result
                    code = code_by_route.get(route_key, "")

                    verification = verifier.verify_result(
                        code=code,
                        finding=stage1_finding,
                        attack_vector=result.get("attack_vector"),
                        reasoning=result.get("reasoning", ""),
                        files_included=result.get("files_included", [])
                    )

                    # Update result with verification
                    result["verification"] = verification.to_dict()
                    metrics["verifications_total"] += 1

                    if verification.agree:
                        metrics["verifications_agreed"] += 1
                        print(f"    ✓ AGREED: {verification.correct_finding}")
                    else:
                        metrics["verifications_disagreed"] += 1
                        result["finding"] = verification.correct_finding
                        result["verification_note"] = f"Changed from {stage1_finding} to {verification.correct_finding}"
                        print(f"    ✗ DISAGREED: {stage1_finding} → {verification.correct_finding}")

                    if verify_verbose:
                        print(f"    Explanation: {verification.explanation[:100]}...")
                        print(f"    Iterations: {verification.iterations}")
                        # Show exploit path if available
                        if verification.exploit_path:
                            ep = verification.exploit_path
                            print(f"    Exploit path:")
                            print(f"      Entry point: {ep.entry_point}")
                            print(f"      Sink reached: {ep.sink_reached}")
                            print(f"      Attacker control: {ep.attacker_control_at_sink}")
                            if ep.path_broken_at:
                                print(f"      Path broken at: {ep.path_broken_at}")
                        if verification.security_weakness:
                            print(f"    Security weakness: {verification.security_weakness}")

                except Exception as e:
                    print(f"    ✗ Verification error: {str(e)}")

                print()

            # Run consistency cross-check on all verified results
            print("Running consistency cross-check...")
            valid_results = verifier._check_consistency(valid_results, code_by_route)

            # Count consistency updates
            for result in valid_results:
                if result.get("consistency_update"):
                    metrics["consistency_updates"] += 1
                    update = result["consistency_update"]
                    print(f"    Consistency update: {result.get('route_key')}")
                    print(f"      {update.get('from')} → {update.get('to')}")
                    print(f"      Reason: {update.get('reason', 'Similar code pattern')}")

            # Recalculate metrics after verification
            print("\nRecalculating metrics after verification...")
            metrics["true_positives"] = 0
            metrics["true_negatives"] = 0
            metrics["false_positives"] = 0
            metrics["false_negatives"] = 0

            for result in results:
                expected = result.get("expected", "UNKNOWN")
                actual = result.get("verdict", "ERROR")

                if expected == "UNKNOWN" or actual in ["ERROR", "INSUFFICIENT_CONTEXT"]:
                    continue

                if expected == "VULNERABLE" and actual == "VULNERABLE":
                    metrics["true_positives"] += 1
                elif expected == "SAFE" and actual == "SAFE":
                    metrics["true_negatives"] += 1
                elif expected == "SAFE" and actual == "VULNERABLE":
                    metrics["false_positives"] += 1
                elif expected == "VULNERABLE" and actual == "SAFE":
                    metrics["false_negatives"] += 1

            print(f"Post-verification: TP={metrics['true_positives']}, TN={metrics['true_negatives']}, FP={metrics['false_positives']}, FN={metrics['false_negatives']}")

    # Challenge ground truth if enabled and there are FP/FN cases
    challenges = None
    if challenge_ground_truth and (metrics["false_positives"] > 0 or metrics["false_negatives"] > 0):
        print("\n" + "=" * 60)
        print("CHALLENGING GROUND TRUTHS...")
        print("=" * 60)

        # Build ground_truths dict in the format expected by challenger
        gt_for_challenger = {}
        categories = ground_truth.get("categories", {})

        # Add true_positives (vulnerable routes)
        for route in categories.get("true_positives", {}).get("routes", []):
            rk = route.get("route_key")
            if rk:
                gt_for_challenger[rk] = {
                    "vulnerable": True,
                    "type": route.get("classification", route.get("vulnerability_type", "Unknown")),
                    "description": route.get("error", route.get("notes", None))
                }

        # Add true_negatives (safe routes)
        for route in categories.get("true_negatives", {}).get("routes", []):
            rk = route.get("route_key")
            if rk:
                gt_for_challenger[rk] = {
                    "vulnerable": False,
                    "type": None
                }

        # Run the challenger
        challenger = GroundTruthChallenger(client)
        challenges = challenger.challenge_results(results, gt_for_challenger, code_by_route)

        # Print challenge report
        print_challenge_report(challenges)

    # Calculate final metrics
    evaluated = (
        metrics["true_positives"] +
        metrics["true_negatives"] +
        metrics["false_positives"] +
        metrics["false_negatives"]
    )

    if evaluated > 0:
        metrics["precision"] = (
            metrics["true_positives"] /
            (metrics["true_positives"] + metrics["false_positives"])
            if (metrics["true_positives"] + metrics["false_positives"]) > 0 else 0
        )
        metrics["recall"] = (
            metrics["true_positives"] /
            (metrics["true_positives"] + metrics["false_negatives"])
            if (metrics["true_positives"] + metrics["false_negatives"]) > 0 else 0
        )
        metrics["accuracy"] = (
            (metrics["true_positives"] + metrics["true_negatives"]) / evaluated
        )
        if metrics["precision"] + metrics["recall"] > 0:
            metrics["f1"] = (
                2 * metrics["precision"] * metrics["recall"] /
                (metrics["precision"] + metrics["recall"])
            )
        else:
            metrics["f1"] = 0

    experiment_result = {
        "dataset": dataset_name,
        "model": model_id,
        "enhanced": enhanced,
        "timestamp": datetime.now().isoformat(),
        "metrics": metrics,
        "results": results
    }

    if challenges:
        experiment_result["challenges"] = challenges

    return experiment_result


def print_summary(experiment: dict):
    """Print experiment summary."""
    metrics = experiment["metrics"]

    print("=" * 60)
    print("EXPERIMENT SUMMARY")
    print("=" * 60)
    print(f"Dataset: {experiment['dataset']}")
    print(f"Model: {experiment['model']}")
    print(f"Enhanced context: {experiment.get('enhanced', False)}")
    print(f"Total units: {metrics['total']}")
    print()
    print("Results:")
    print(f"  True Positives:      {metrics['true_positives']}")
    print(f"  True Negatives:      {metrics['true_negatives']}")
    print(f"  False Positives:     {metrics['false_positives']}")
    print(f"  False Negatives:     {metrics['false_negatives']}")
    print(f"  Unknown GT:          {metrics['unknown_ground_truth']}")
    print(f"  Insufficient Context:{metrics['insufficient_context']}")
    print(f"  Errors:              {metrics['errors']}")
    if metrics.get('corrections_attempted', 0) > 0:
        print()
        print("Context Corrections:")
        print(f"  Attempted:           {metrics['corrections_attempted']}")
        print(f"  Successful:          {metrics['corrections_successful']}")
    if metrics.get('json_corrections_attempted', 0) > 0:
        print()
        print("JSON Corrections:")
        print(f"  Attempted:           {metrics['json_corrections_attempted']}")
        print(f"  Successful:          {metrics['json_corrections_successful']}")
    if metrics.get('verifications_total', 0) > 0:
        print()
        print("Stage 2 Verification:")
        print(f"  Total verified:      {metrics['verifications_total']}")
        print(f"  Agreed:              {metrics['verifications_agreed']}")
        print(f"  Disagreed:           {metrics['verifications_disagreed']}")
        if metrics.get('consistency_updates', 0) > 0:
            print(f"  Consistency updates: {metrics['consistency_updates']}")
    print()
    if "accuracy" in metrics:
        print("Metrics:")
        print(f"  Accuracy:  {metrics['accuracy']:.1%}")
        print(f"  Precision: {metrics['precision']:.1%}")
        print(f"  Recall:    {metrics['recall']:.1%}")
        print(f"  F1 Score:  {metrics['f1']:.1%}")


def main():
    parser = argparse.ArgumentParser(description="Run vulnerability analysis experiment")
    parser.add_argument(
        "--dataset", "-d",
        choices=list(DATASETS.keys()),
        default="dvna",
        help="Dataset to analyze (default: dvna)"
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        default=None,
        help="Limit number of units to analyze"
    )
    parser.add_argument(
        "--model", "-m",
        choices=["opus", "sonnet"],
        default="opus",
        help="Model to use (default: opus for best capability)"
    )
    parser.add_argument(
        "--no-enhanced",
        action="store_true",
        help="Disable enhanced dataset (multi-file context enabled by default)"
    )
    parser.add_argument(
        "--no-correct",
        action="store_true",
        help="Disable INSUFFICIENT_CONTEXT correction (enabled by default)"
    )
    parser.add_argument(
        "--no-json-correct",
        action="store_true",
        help="Disable JSON error recovery (enabled by default)"
    )
    parser.add_argument(
        "--no-challenge",
        action="store_true",
        help="Disable ground truth challenging (enabled by default)"
    )
    parser.add_argument(
        "--review", "-r",
        action="store_true",
        help="Use LLM to proactively review and enhance context before analysis (expensive, disabled by default)"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Enable Stage 2 verification of all results using Opus with tool access"
    )
    parser.add_argument(
        "--verify-verbose",
        action="store_true",
        help="Print verbose output during Stage 2 verification"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Output file for results JSON"
    )

    args = parser.parse_args()

    # Run experiment
    experiment = run_experiment(
        dataset_name=args.dataset,
        limit=args.limit,
        model=args.model,
        enhanced=not args.no_enhanced,
        correct_context=not args.no_correct,
        correct_json=not args.no_json_correct,
        challenge_ground_truth=not args.no_challenge,
        review_context=args.review,
        verify=args.verify,
        verify_verbose=args.verify_verbose
    )

    # Print summary
    print_summary(experiment)

    # Save results
    if args.output:
        output_path = args.output
    else:
        suffix = "" if args.no_enhanced else "_enhanced"
        output_path = f"experiment_{args.dataset}_{args.model}{suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(output_path, "w") as f:
        json.dump(experiment, f, indent=2)

    print()
    print(f"Results saved to: {output_path}")


if __name__ == "__main__":
    main()
