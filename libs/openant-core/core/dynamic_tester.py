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
from core.verdict_taxonomy import DYNAMIC_TESTABLE
from core import tracking
from utilities.file_io import normalize_results, read_json, write_json


def run_tests(
    pipeline_output_path: str,
    output_dir: str,
    max_retries: int = 3,
    repo_path: str | None = None,
    registry=None,
    llm_config_name: str | None = None,
) -> DynamicTestStepResult:
    """Run dynamic exploit tests on confirmed vulnerabilities.

    Requires Docker to be installed and running.

    Args:
        pipeline_output_path: Path to ``pipeline_output.json``.
        output_dir: Directory for test results.
        max_retries: Max retries per finding on error (default 3).
        registry: Pre-built PhaseRegistry passed down by the scanner.
            Standalone callers omit this and pay one config-load.
        llm_config_name: Name of the llm-config when registry is None.

    Returns:
        DynamicTestStepResult with counts and paths.

    Raises:
        RuntimeError: If Docker is not available.
        FileNotFoundError: If pipeline_output_path doesn't exist.
    """
    # #214: snapshot cumulative usage at phase start so the "Dynamic Test"
    # summary below reports this phase's delta, not the prior phases' total.
    _phase_baseline = tracking.get_usage()
    # #333 (wave r1 opus): the #281 cross-phase console contract, applied to
    # the dynamic-test step — the pre-injection snapshot below captured the
    # checkpoint injection's restored tokens/cost while excluding their
    # calls, so a resumed run's console line double-counted the restored
    # spend (10 checkpoints at $0.60 + one $0.03 retry printed $0.63). The
    # mutable holder is refreshed AT the injection site
    # (utilities/dynamic_tester), so the phase line reports only the NEW
    # retry spend — the same contract analyze/verify/enhance carry.
    _baseline_holder = {
        "cost_usd": _phase_baseline.total_cost_usd,
        "tokens": _phase_baseline.total_tokens,
        "calls": _phase_baseline.total_calls,
    }
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
    pipeline_data = read_json(pipeline_output_path)
    # fa18 TRUST BOUNDARY: normalize model `findings` to dicts-only at load
    # (presence-guarded) so the testability filter's `f.get(...)` is safe.
    if "findings" in pipeline_data:
        normalize_results(pipeline_data, "findings")
    findings = pipeline_data.get("findings", [])
    testable = [
        f for f in findings
        if f.get("stage2_verdict") in DYNAMIC_TESTABLE
    ]

    print(f"[Dynamic Test] {len(testable)} testable findings "
          f"(out of {len(findings)} total)", file=sys.stderr)

    if not testable:
        results_path = os.path.join(output_dir, "dynamic_test_results.json")
        write_json(results_path, {"findings_tested": 0, "results": []})

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
        repo_path=repo_path,
        registry=registry,
        llm_config_name=llm_config_name,
        usage_baseline=_baseline_holder,
    )
    # #333 (wave r1): rebuild the baseline from the refreshed holder — the
    # phase line now EXCLUDES the restored checkpoints' spend (it was
    # reported by their original run's line; including it again
    # double-counts across a resume).
    _phase_baseline = UsageInfo(
        total_calls=_baseline_holder["calls"],
        total_tokens=_baseline_holder["tokens"],
        total_cost_usd=_baseline_holder["cost_usd"],
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

    tracking.log_usage("Dynamic Test", _phase_baseline)

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
