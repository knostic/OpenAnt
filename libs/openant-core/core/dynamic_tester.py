"""
Dynamic testing wrapper.

Runs Docker-isolated exploit tests against confirmed vulnerabilities.
Wraps ``utilities.dynamic_tester.run_dynamic_tests()``.
"""

import json
import os
import shutil
import sys

from core.schemas import DynamicTestStepResult, UsageInfo
from core import tracking


def run_tests(
    pipeline_output_path: str,
    output_dir: str,
    max_retries: int = 3,
) -> DynamicTestStepResult:
    """Run dynamic exploit tests on confirmed vulnerabilities.

    Requires Docker to be installed and running.

    Args:
        pipeline_output_path: Path to ``pipeline_output.json``.
        output_dir: Directory for test results.
        max_retries: Max retries per finding on error (default 3).

    Returns:
        DynamicTestStepResult with counts and paths.

    Raises:
        RuntimeError: If Docker is not available.
        FileNotFoundError: If pipeline_output_path doesn't exist.
    """
    # Check Docker availability
    if not shutil.which("docker"):
        raise RuntimeError(
            "Docker is required for dynamic testing but was not found. "
            "Install Docker and ensure it is running."
        )

    if not os.path.exists(pipeline_output_path):
        raise FileNotFoundError(
            f"pipeline_output.json not found: {pipeline_output_path}"
        )

    os.makedirs(output_dir, exist_ok=True)

    # Check how many findings to test
    with open(pipeline_output_path) as f:
        pipeline_data = json.load(f)

    findings = pipeline_data.get("findings", [])
    testable = [
        f for f in findings
        if f.get("stage2_verdict") in ("confirmed", "agreed", "vulnerable")
    ]

    print(f"[Dynamic Test] {len(testable)} testable findings "
          f"(out of {len(findings)} total)", file=sys.stderr)

    if not testable:
        results_path = os.path.join(output_dir, "dynamic_test_results.json")
        with open(results_path, "w") as f:
            json.dump({"findings_tested": 0, "results": []}, f, indent=2)

        return DynamicTestStepResult(
            results_json_path=results_path,
            findings_tested=0,
            usage=tracking.get_usage(),
        )

    # Import and run
    from utilities.dynamic_tester import run_dynamic_tests

    print(f"[Dynamic Test] Running with max_retries={max_retries}...",
          file=sys.stderr)

    results = run_dynamic_tests(
        pipeline_output_path,
        output_dir,
        max_retries=max_retries,
    )

    # Count outcomes
    confirmed = 0
    not_reproduced = 0
    blocked = 0
    inconclusive = 0
    errors = 0

    for r in results:
        status = r.get("status", "") if isinstance(r, dict) else getattr(r, "status", "")
        if status == "CONFIRMED":
            confirmed += 1
        elif status == "NOT_REPRODUCED":
            not_reproduced += 1
        elif status == "BLOCKED":
            blocked += 1
        elif status == "INCONCLUSIVE":
            inconclusive += 1
        elif status == "ERROR":
            errors += 1

    results_json_path = os.path.join(output_dir, "dynamic_test_results.json")
    results_md_path = os.path.join(output_dir, "dynamic_test_results.md")

    # Check which output files exist (dynamic_tester may write them itself)
    if not os.path.exists(results_md_path):
        results_md_path = None

    tracking.log_usage("Dynamic Test")

    print(f"\n[Dynamic Test] Results: {confirmed} confirmed, "
          f"{not_reproduced} not reproduced, {blocked} blocked, "
          f"{inconclusive} inconclusive, {errors} errors", file=sys.stderr)

    return DynamicTestStepResult(
        results_json_path=results_json_path,
        results_md_path=results_md_path,
        findings_tested=len(testable),
        confirmed=confirmed,
        not_reproduced=not_reproduced,
        blocked=blocked,
        inconclusive=inconclusive,
        errors=errors,
        usage=tracking.get_usage(),
    )
