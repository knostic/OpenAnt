"""Parse container output and classify dynamic test results.

Each test container is expected to print a single JSON object to stdout:
{
    "status": "CONFIRMED|NOT_REPRODUCED|BLOCKED|INCONCLUSIVE|ERROR",
    "details": "Human-readable explanation",
    "evidence": [{"type": "file_read|http_response|command_output|network_capture", "content": "..."}]
}
"""

import json

from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence, VALID_STATUSES
from utilities.dynamic_tester.docker_executor import DockerExecutionResult


def collect_result(
    finding: dict,
    generation: dict | None,
    execution: DockerExecutionResult | None,
    generation_cost: float = 0.0,
) -> DynamicTestResult:
    """Parse container output into a DynamicTestResult.

    Args:
        finding: Original finding dict from pipeline_output.json
        generation: Test generation output (or None if generation failed)
        execution: Docker execution result (or None if not run)
        generation_cost: Cost of LLM test generation in USD

    Returns:
        DynamicTestResult with parsed status and evidence
    """
    finding_id = finding.get("id", "unknown")

    # Generation failed
    if generation is None:
        return DynamicTestResult(
            finding_id=finding_id,
            status="ERROR",
            details="Test generation failed — LLM did not return valid test code",
            generation_cost_usd=generation_cost,
        )

    # Execution not attempted
    if execution is None:
        return DynamicTestResult(
            finding_id=finding_id,
            status="ERROR",
            details="Docker execution was not attempted",
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            generation_cost_usd=generation_cost,
        )

    # Build failure
    if execution.build_error:
        return DynamicTestResult(
            finding_id=finding_id,
            status="ERROR",
            details=f"Docker build failed: {execution.build_error[:2000]}",
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Timeout
    if execution.timed_out:
        return DynamicTestResult(
            finding_id=finding_id,
            status="INCONCLUSIVE",
            details="Container execution timed out",
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Parse stdout for the JSON result
    parsed = _parse_container_output(execution.stdout)

    if parsed is None:
        return DynamicTestResult(
            finding_id=finding_id,
            status="ERROR",
            details=f"Container did not produce valid JSON output. "
                    f"Exit code: {execution.exit_code}. "
                    f"Stderr: {execution.stderr[:300]}",
            evidence=[TestEvidence(type="command_output", content=execution.stdout[:2000])],
            test_code=generation.get("test_script", ""),
            dockerfile=generation.get("dockerfile", ""),
            docker_compose=generation.get("docker_compose", ""),
            elapsed_seconds=execution.elapsed_seconds,
            generation_cost_usd=generation_cost,
        )

    # Valid JSON output
    status = parsed.get("status", "ERROR")
    if status not in VALID_STATUSES:
        status = "INCONCLUSIVE"

    evidence = []
    for e in (parsed.get("evidence") or []):
        if isinstance(e, dict) and "type" in e and "content" in e:
            evidence.append(TestEvidence(type=e["type"], content=str(e["content"])[:5000]))

    return DynamicTestResult(
        finding_id=finding_id,
        status=status,
        details=parsed.get("details", ""),
        evidence=evidence,
        test_code=generation.get("test_script", ""),
        dockerfile=generation.get("dockerfile", ""),
        docker_compose=generation.get("docker_compose", ""),
        elapsed_seconds=execution.elapsed_seconds,
        generation_cost_usd=generation_cost,
    )


def _parse_container_output(stdout: str) -> dict | None:
    """Extract the JSON result object from container stdout.

    The container may print debug info before the JSON. We look for the
    last valid JSON object in the output.
    """
    if not stdout.strip():
        return None

    # Try parsing the entire output as JSON
    try:
        return json.loads(stdout.strip())
    except json.JSONDecodeError:
        pass

    # Try each line from the end (last JSON object wins)
    lines = stdout.strip().split("\n")
    for line in reversed(lines):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

    return None
