"""Dynamic testing module for OpenAnt.

Takes pipeline_output.json from the static analysis pipeline and dynamically
tests all detected vulnerabilities using Docker containers.

Supports checkpoint/resume: each completed finding is saved to a per-unit
checkpoint file so interrupted runs can resume automatically.

Public API:
    run_dynamic_tests(pipeline_output_path, output_dir) -> list[DynamicTestResult]
"""

import json
import os
import sys

from utilities.dynamic_tester.models import DynamicTestResult
from utilities.dynamic_tester.test_generator import generate_test, regenerate_test
from utilities.dynamic_tester.docker_executor import run_single_container
from utilities.dynamic_tester.result_collector import collect_result
from utilities.dynamic_tester.reporter import generate_report
from utilities.llm_client import get_global_tracker


def run_dynamic_tests(
    pipeline_output_path: str,
    output_dir: str | None = None,
    max_retries: int = 3,
    checkpoint_path: str | None = None,
) -> list[DynamicTestResult]:
    """Run dynamic tests for all findings in a pipeline output file.

    Args:
        pipeline_output_path: Path to pipeline_output.json
        output_dir: Directory for output files. Defaults to same directory
                    as pipeline_output_path.
        max_retries: Max retries per finding on error (default 3).
        checkpoint_path: Path to checkpoint directory for resume support.

    Returns:
        List of DynamicTestResult objects
    """
    # Load pipeline output
    with open(pipeline_output_path, "r") as f:
        pipeline = json.load(f)

    findings = pipeline.get("findings", [])
    repo_info = {
        "name": pipeline.get("repository", {}).get("name", "unknown"),
        "language": pipeline.get("repository", {}).get("language", "Python"),
        "application_type": pipeline.get("application_type", "unknown"),
    }

    if not findings:
        print("No findings to test.", file=sys.stderr)
        return []

    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(pipeline_output_path))
    os.makedirs(output_dir, exist_ok=True)

    # Set up checkpoint support
    checkpoint = None
    checkpointed = {}
    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "dynamic_test_checkpoints")

    from core.checkpoint import StepCheckpoint
    checkpoint = StepCheckpoint("dynamic_test", output_dir)
    checkpoint.dir = checkpoint_path
    if checkpoint.exists:
        checkpointed = checkpoint.load()

    # Count successful vs errored checkpoints. Errored ones are NOT "already
    # done" — they'll be retried with fresh test generation on resume.
    successful_ids = {fid for fid, cp in checkpointed.items()
                      if cp.get("status") != "ERROR"}
    errored_ids = {fid for fid in checkpointed.keys() if fid not in successful_ids}

    if successful_ids:
        print(f"Restored {len(successful_ids)} already-tested findings from checkpoints",
              file=sys.stderr, flush=True)
    if errored_ids:
        print(f"Retrying {len(errored_ids)} previously errored findings",
              file=sys.stderr, flush=True)

    # Use the global tracker so step_context captures dynamic-test cost in
    # dynamic-test.report.json (same as enhance/analyze/verify).
    tracker = get_global_tracker()

    # Inject prior usage from ALL existing checkpoints (both successful and
    # errored) so the report shows total cost across runs. The errored
    # entries will be retried — their initial attempt cost is preserved,
    # and the retry API calls get added on top.
    _prior_input = 0
    _prior_output = 0
    _prior_cost = 0.0
    for _cp in checkpointed.values():
        _prior_cost += _cp.get("generation_cost_usd", 0) or 0
        _prior_input += _cp.get("generation_input_tokens", 0) or 0
        _prior_output += _cp.get("generation_output_tokens", 0) or 0
    if _prior_cost > 0 or _prior_input > 0 or _prior_output > 0:
        tracker.add_prior_usage(_prior_input, _prior_output, _prior_cost)

    results: list[DynamicTestResult] = []

    total = len(findings)
    restored = len(successful_ids)
    remaining = total - restored
    _completed = restored
    _errors = 0

    # Write initial summary so Go CLI can show accurate counts
    checkpoint.ensure_dir()
    checkpoint.write_summary(total, _completed, _errors, {}, phase="in_progress")

    print(f"Dynamic testing {total} findings from {repo_info['name']} "
          f"({restored} already done, {remaining} remaining)",
          file=sys.stderr)

    try:
      for i, finding in enumerate(findings):
        finding_id = finding.get("id", f"FINDING-{i+1}")

        # Skip already-checkpointed findings, but ONLY if they succeeded.
        # Errored findings fall through to fresh test generation + Docker run,
        # so code/prompt fixes take effect on resume.
        cp_data = checkpointed.get(finding_id)
        if cp_data and cp_data.get("status") != "ERROR":
            result = DynamicTestResult(
                finding_id=finding_id,
                status=cp_data.get("status", "ERROR"),
                details=cp_data.get("details", ""),
                elapsed_seconds=cp_data.get("elapsed_seconds", 0),
                generation_cost_usd=cp_data.get("generation_cost_usd", 0),
                generation_input_tokens=cp_data.get("generation_input_tokens", 0),
                generation_output_tokens=cp_data.get("generation_output_tokens", 0),
                retry_count=cp_data.get("retry_count", 0),
                test_code=cp_data.get("test_code", ""),
                dockerfile=cp_data.get("dockerfile", ""),
                docker_compose=cp_data.get("docker_compose", ""),
            )
            results.append(result)
            continue

        print(f"\n[{i+1}/{total}] Testing {finding_id}: "
              f"{finding.get('name', 'unknown')}...", file=sys.stderr)

        # Begin per-unit tracking so we can capture token counts for this
        # finding in addition to cost.
        tracker.start_unit_tracking()

        # Step 1: Generate test
        print("  Generating test...", file=sys.stderr)
        generation = generate_test(finding, repo_info, tracker)
        unit_usage = tracker.get_unit_usage()
        generation_cost = unit_usage["cost_usd"]

        if generation is None:
            print("  Test generation failed.", file=sys.stderr)
            result = collect_result(finding, None, None, generation_cost)
            result.generation_input_tokens = unit_usage["input_tokens"]
            result.generation_output_tokens = unit_usage["output_tokens"]
            results.append(result)
            if checkpoint:
                checkpoint.save(finding_id, result.to_dict())
            continue

        print(f"  Generated (${generation_cost:.4f}). Running in Docker...",
              file=sys.stderr)

        # Step 2: Execute in Docker and retry on errors
        execution = run_single_container(generation, finding_id)
        result = collect_result(finding, generation, execution, generation_cost)
        retry_count = 0

        while result.status == "ERROR" and retry_count < max_retries:
            # Extract error message: build error > stderr > application-level details
            if execution.build_error:
                error_msg = execution.build_error
                error_type = "Build"
            elif execution.exit_code != 0 and execution.stderr:
                error_msg = execution.stderr
                error_type = "Runtime"
            else:
                error_msg = result.details
                error_type = "Application"

            if execution.timed_out:
                print(f"  Timed out — not retrying.", file=sys.stderr)
                break

            retry_count += 1
            print(f"  {error_type} error. Retry {retry_count}/{max_retries} "
                  f"with error feedback...", file=sys.stderr)

            retry_gen = regenerate_test(
                finding, repo_info, generation,
                error_msg, tracker,
            )
            # Refresh unit usage after retry (tracker accumulates across calls
            # on the same thread).
            unit_usage = tracker.get_unit_usage()
            generation_cost = unit_usage["cost_usd"]

            if retry_gen is None:
                print(f"  Retry generation failed.", file=sys.stderr)
                break

            generation = retry_gen
            execution = run_single_container(generation, finding_id)
            result = collect_result(finding, generation, execution, generation_cost)
            print(f"  Retry {retry_count} result: {result.status} "
                  f"(${generation_cost:.4f})", file=sys.stderr)

        result.retry_count = retry_count
        result.generation_input_tokens = unit_usage["input_tokens"]
        result.generation_output_tokens = unit_usage["output_tokens"]
        results.append(result)

        # Save checkpoint and update summary after each finding
        if checkpoint:
            checkpoint.save(finding_id, result.to_dict())
            _completed += 1
            if result.status == "ERROR":
                _errors += 1
            checkpoint.write_summary(total, _completed, _errors, {}, phase="in_progress")

        print(f"  Result: {result.status} ({result.elapsed_seconds:.1f}s)",
              file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[Dynamic Test] Interrupted — progress saved to checkpoints",
              file=sys.stderr, flush=True)
        return results

    # Generate report
    total_cost = tracker.total_cost_usd
    report_md = generate_report(results, repo_info["name"], total_cost)

    report_path = os.path.join(output_dir, "DYNAMIC_TEST_RESULTS.md")
    with open(report_path, "w") as f:
        f.write(report_md)
    print(f"\nReport written to {report_path}", file=sys.stderr)

    # Save structured results JSON
    results_path = os.path.join(output_dir, "dynamic_test_results.json")
    with open(results_path, "w") as f:
        json.dump({
            "repository": repo_info["name"],
            "total_findings": len(findings),
            "total_cost_usd": round(total_cost, 6),
            "results": [r.to_dict() for r in results],
        }, f, indent=2, ensure_ascii=False)
    print(f"Results JSON written to {results_path}", file=sys.stderr)

    # Mark done. Checkpoints are preserved as a permanent artifact alongside
    # results — allows retroactive retry of errored findings after fixes.
    if checkpoint:
        checkpoint.write_summary(total, _completed, _errors, {}, phase="done")

    return results
