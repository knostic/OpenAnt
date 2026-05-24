"""Stage 1 consistency check for detection results.

This module provides consistency checking after Stage 1 detection to catch
cases where similar code patterns receive inconsistent verdicts.

Key difference from Stage 2 consistency check:
- Groups by function signature pattern ACROSS files (not just within same file)
- Catches cases like OpenAI vs Anthropic httpx clients that have identical
  vulnerability patterns but are in different provider directories
"""

import re
import json
from typing import Optional
from dataclasses import dataclass

from utilities.llm_client import TokenTracker
from utilities.llm import PhaseBinding, simple_text


MAX_TOKENS = 4096


@dataclass
class Stage1ConsistencyResult:
    """Result of a Stage 1 consistency check."""
    pattern_identified: str
    consistent_verdict: str
    findings_updated: list
    explanation: str


def get_stage1_consistency_prompt(findings: list, code_samples: dict) -> str:
    """Generate prompt for Stage 1 consistency check."""
    findings_text = ""
    for i, f in enumerate(findings, 1):
        route_key = f.get("route_key", "unknown")
        code_snippet = code_samples.get(route_key, "")[:800]
        findings_text += f"""
### Finding {i}: {route_key}
- Current verdict: {f.get('verdict', 'unknown')}
- Reasoning: {f.get('reasoning', 'N/A')[:300]}...
- Code:
```
{code_snippet}
```
"""

    return f"""You are checking Stage 1 detection consistency across similar code patterns.

These functions have similar signatures/purposes but received DIFFERENT verdicts:

{findings_text}

Analyze whether these functions have the SAME vulnerability characteristics.
If they do, they should have the SAME verdict.

Consider:
1. Do they accept the same types of potentially dangerous inputs (URLs, paths, etc.)?
2. Do they perform the same operations with those inputs?
3. Are the security implications identical?

Important: Minor differences like additional parameters, caching decorators, or
different provider names (OpenAI vs Anthropic) do NOT change the fundamental
security characteristics if the core vulnerability pattern is the same.

Respond with JSON:
{{
    "are_equivalent": true | false,
    "pattern_identified": "brief description of the common vulnerability pattern",
    "consistent_verdict": "VULNERABLE" | "SAFE" | "INCONCLUSIVE",
    "explanation": "why these should or should not have the same verdict",
    "findings_to_update": [
        {{
            "route_key": "full route key",
            "original_verdict": "what it was",
            "should_be": "what it should be",
            "reason": "why"
        }}
    ]
}}"""


def _extract_function_signature_pattern(route_key: str) -> str:
    """
    Extract a normalized function signature pattern from a route key.

    Examples:
    - "libs/partners/openai/.../foo.py:_build_async_httpx_client" -> "*_async_httpx_client"
    - "libs/partners/anthropic/.../bar.py:_get_default_async_httpx_client" -> "*_async_httpx_client"
    - "libs/core/documents/base.py:Blob.as_bytes" -> "*.as_bytes"
    """
    if ":" not in route_key:
        return route_key

    file_part, func_part = route_key.rsplit(":", 1)

    # Extract just the filename for grouping similar utilities across providers
    filename = file_part.rsplit("/", 1)[-1] if "/" in file_part else file_part

    # Normalize function names:
    # 1. Class methods like ClassName.method -> *.method
    if "." in func_part:
        _, method = func_part.rsplit(".", 1)
        normalized = f"*.{method}"
    else:
        # 2. Strip common prefixes iteratively to get the "core purpose"
        # e.g., "_get_default_async_httpx_client" -> "async_httpx_client"
        # e.g., "_build_async_httpx_client" -> "async_httpx_client"
        normalized = func_part

        # Remove leading underscores
        normalized = normalized.lstrip("_")

        # Iteratively strip common action/modifier prefixes
        # NOTE: Don't strip async_/sync_ as they're meaningful for grouping
        prefixes_to_strip = [
            "build_", "get_", "create_", "make_", "init_", "setup_",
            "default_", "cached_", "new_"
        ]

        changed = True
        while changed:
            changed = False
            for prefix in prefixes_to_strip:
                if normalized.startswith(prefix):
                    normalized = normalized[len(prefix):]
                    changed = True
                    break

        normalized = f"*_{normalized}"

    # Include filename in pattern to avoid grouping unrelated functions
    # e.g., "_client_utils.py:*_async_httpx_client"
    return f"{filename}:{normalized}"


def _group_by_signature_pattern(results: list) -> dict:
    """
    Group results by function signature pattern across all files.

    This catches similar functions in different provider libraries.
    """
    groups = {}

    for result in results:
        route_key = result.get("route_key", "")
        pattern = _extract_function_signature_pattern(route_key)

        if pattern not in groups:
            groups[pattern] = []
        groups[pattern].append(result)

    return groups


def run_stage1_consistency_check(
    results: list,
    code_by_route: dict,
    binding: PhaseBinding,
    tracker: TokenTracker,
    logger=None
) -> list:
    """
    Run consistency check on Stage 1 detection results.

    Groups findings by function signature pattern and ensures similar
    functions have consistent verdicts.

    Args:
        results: List of Stage 1 detection results
        code_by_route: Dict mapping route_key to code snippet
        tracker: TokenTracker for cost tracking
        logger: Optional logger for output

    Returns:
        Updated results list with consistency corrections applied
    """
    def log(level, msg, **extra):
        if logger:
            getattr(logger, level)(msg, extra=extra)

    # Group by signature pattern
    pattern_groups = _group_by_signature_pattern(results)

    # Find groups with inconsistent verdicts
    inconsistent_groups = []
    for pattern, group in pattern_groups.items():
        if len(group) < 2:
            continue

        # Get verdicts (normalize to uppercase)
        verdicts = set()
        for r in group:
            v = r.get("verdict", "").upper()
            # Treat VULNERABLE and BYPASSABLE as equivalent for grouping
            if v in ("VULNERABLE", "BYPASSABLE"):
                verdicts.add("VULNERABLE")
            elif v in ("SAFE", "PROTECTED"):
                verdicts.add("SAFE")
            else:
                verdicts.add(v)

        if len(verdicts) > 1:
            inconsistent_groups.append((pattern, group))

    if not inconsistent_groups:
        log("info", "Stage 1 consistency check: All similar patterns have consistent verdicts",
            step="detect")
        return results

    log("info", f"Stage 1 consistency check: Found {len(inconsistent_groups)} inconsistent pattern(s)",
        step="detect")

    for pattern, group in inconsistent_groups:
        verdicts = [r.get("verdict", "UNKNOWN") for r in group]
        route_keys = [r.get("route_key", "") for r in group]

        log("warning", f"Inconsistency in pattern '{pattern}'",
            step="detect", details={"findings": route_keys, "verdicts": verdicts})

        # Call LLM to resolve
        try:
            consistency_result = _resolve_stage1_inconsistency(
                binding, group, code_by_route, tracker
            )

            if consistency_result and consistency_result.findings_updated:
                # Apply updates
                for update in consistency_result.findings_updated:
                    route_key = update.get("route_key")
                    new_verdict = update.get("should_be", "").upper()

                    if not new_verdict:
                        continue

                    for result in results:
                        if result.get("route_key") == route_key:
                            old_verdict = result.get("verdict", "UNKNOWN")
                            if old_verdict.upper() != new_verdict:
                                result["verdict"] = new_verdict
                                result["stage1_consistency_update"] = {
                                    "from": old_verdict,
                                    "to": new_verdict,
                                    "reason": update.get("reason"),
                                    "pattern": consistency_result.pattern_identified
                                }
                                log("info", f"Stage 1 consistency update: {old_verdict} -> {new_verdict}",
                                    step="detect", unit_id=route_key)

        except Exception as e:
            log("error", f"Stage 1 consistency resolution failed: {e}", step="detect")

    return results


def _resolve_stage1_inconsistency(
    binding: PhaseBinding,
    group: list,
    code_by_route: dict,
    tracker: TokenTracker,
) -> Optional[Stage1ConsistencyResult]:
    """Use LLM to resolve inconsistent Stage 1 verdicts."""
    prompt = get_stage1_consistency_prompt(group, code_by_route)

    try:
        text = simple_text(
            binding,
            prompt,
            system="You are checking verdict consistency across similar code patterns in a security analysis.",
            max_tokens=MAX_TOKENS,
            tracker=tracker,
        )

        # Extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', text)
        if json_match:
            result = json.loads(json_match.group())

            if result.get("are_equivalent", False):
                return Stage1ConsistencyResult(
                    pattern_identified=result.get("pattern_identified", "unknown"),
                    consistent_verdict=result.get("consistent_verdict", "INCONCLUSIVE"),
                    findings_updated=result.get("findings_to_update", []),
                    explanation=result.get("explanation", "")
                )

    except json.JSONDecodeError:
        pass
    except Exception:
        pass

    return None
