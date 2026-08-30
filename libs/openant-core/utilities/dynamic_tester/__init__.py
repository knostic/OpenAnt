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

from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence
from utilities.dynamic_tester.test_generator import generate_test, regenerate_test
from utilities.dynamic_tester.docker_executor import run_single_container
from utilities.dynamic_tester.result_collector import collect_result
from utilities.dynamic_tester.reporter import generate_report
from utilities.llm_client import get_global_tracker
from utilities.llm import (
    PhaseRegistry,
    build_phase_registry,
    load_config_file,
    resolve_llm_config,
)
from utilities.file_io import normalize_results, read_json, write_json, open_utf8



def should_skip_for_language(file_path: str, scan_language: str | None) -> tuple[bool, str]:
    """Whether a finding should be skipped for lack of a Docker template.

    Args:
        file_path: The finding's file, which decides its language.
        scan_language: Scan-wide language, used when the path has no
            recognizable extension.

    Returns:
        ``(skip, reason)``. ``reason`` names the language so a skipped finding
        leaves an auditable trail rather than an unexplained gap.
    """
    from core.language_registry import language_for_path
    from utilities.dynamic_tester.test_generator import resolve_docker_template

    if resolve_docker_template(file_path, scan_language) is not None:
        return False, ""
    language = language_for_path(file_path) or scan_language or "unknown"
    return True, (
        f"no dynamic-test Docker template for {language}; "
        "skipped instead of generating an untemplated test"
    )

def _summary_counts_from_checkpoints(checkpointed) -> dict:
    """#311: derive write_summary's counts from the SAVED UNIT FILES.

    The loop previously accumulated `_completed`/`_errors` locally, which
    (a) bypassed the generation-failure `continue` — an errored run wrote
    `errors: 0` — and (b) counted errors as a SUBSET of completed while
    `StepCheckpoint.status()` recomputes them as DISJOINT, so the two
    sources disagreed even without the bypass. Deriving from the same
    source `status()` reads makes the two structurally incapable of
    drifting. The retry contract is unchanged: an ERROR checkpoint is
    still classified not-done and retried on resume.
    """
    if not checkpointed:
        return {"completed": 0, "errors": 1 if checkpointed is False else 0}
    completed = errors = 0
    for cp in checkpointed.values():
        if not isinstance(cp, dict):
            continue
        if cp.get("status") == "ERROR":
            errors += 1
        else:
            completed += 1
    return {"completed": completed, "errors": errors}


def run_dynamic_tests(
    pipeline_output_path: str,
    output_dir: str | None = None,
    max_retries: int = 3,
    checkpoint_path: str | None = None,
    repo_path: str | None = None,
    registry: PhaseRegistry | None = None,
    llm_config_name: str | None = None,
) -> list[DynamicTestResult]:
    """Run dynamic tests for all findings in a pipeline output file.

    Args:
        pipeline_output_path: Path to pipeline_output.json
        output_dir: Directory for output files. Defaults to same directory
                    as pipeline_output_path.
        max_retries: Max retries per finding on error (default 3).
        checkpoint_path: Path to checkpoint directory for resume support.
        repo_path: Path to the repository root. When given, the vulnerable
            source file is pre-staged into the Docker build context so
            ``COPY <filename> .`` works on the first try.

    Returns:
        List of DynamicTestResult objects
    """
    # Resolve the dynamic_test phase binding from the registry once and
    # reuse it across every finding. Standalone-invocation path
    # validates upfront; scanner-driven calls trust the scanner's probe.
    if registry is None:
        from utilities.llm import probe_registry_or_raise

        cf = load_config_file()
        registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
        probe_registry_or_raise(registry)
    dynamic_test_binding = registry.get("dynamic_test")

    # Load pipeline output
    pipeline = read_json(pipeline_output_path)
    # fa18 TRUST BOUNDARY: normalize model `findings` to dicts-only at load
    # (presence-guarded) so the DYNAMIC_TESTABLE filter's `f.get(...)` is safe.
    if "findings" in pipeline:
        normalize_results(pipeline, "findings")
    findings = pipeline.get("findings", [])
    # Enforce the dynamic-testability filter at the execution site. Only
    # findings asserted vulnerable are worth an active Docker reproduction;
    # core/dynamic_tester.py computes the same filter for reporting, but the
    # per-finding loop lives here, so without this every finding (regardless
    # of stage2_verdict) was dynamically tested anyway.
    from core.verdict_taxonomy import DYNAMIC_TESTABLE
    findings = [f for f in findings
                if f.get("stage2_verdict") in DYNAMIC_TESTABLE]
    repo_info = {
        "name": pipeline.get("repository", {}).get("name", "unknown"),
        # No default language. The previous "Python" fallback silently told the
        # generator that an unknown-language repo was Python; an explicit
        # "unknown" lets per-finding resolution decide and makes the gap visible.
        "language": pipeline.get("repository", {}).get("language") or "unknown",
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

    # Write initial summary so Go CLI can show accurate counts.
    # #311: DERIVED from the saved unit files (the same source status()
    # recomputes from) — not loop-local accumulators, which bypassed the
    # generation-failure path and wrote errors: 0 for errored runs.
    _counts = _summary_counts_from_checkpoints(checkpointed)
    _completed = _counts["completed"]
    _errors = _counts["errors"]
    checkpoint.ensure_dir()
    checkpoint.write_summary(total, _completed, _errors, {}, phase="in_progress")

    print(f"Dynamic testing {total} findings from {repo_info['name']} "
          f"({restored} already done, {remaining} remaining)",
          file=sys.stderr)

    try:
      for i, finding in enumerate(findings):
        # str() at the boundary: id is repo/JSON-derived and may be non-str; it flows
        # to run_single_container's finding_id.lower() and checkpoint's safe_filename,
        # both of which would raise on a non-str and abort the whole run.
        finding_id = str(finding.get("id", f"FINDING-{i+1}"))

        # Skip already-checkpointed findings, but ONLY if they succeeded.
        # Errored findings fall through to fresh test generation + Docker run,
        # so code/prompt fixes take effect on resume.

        cp_data = checkpointed.get(finding_id)
        if cp_data and cp_data.get("status") != "ERROR":
            result = DynamicTestResult(
                finding_id=finding_id,
                # #314: thread the identity through resume so a checkpointed
                # verdict merges on the same key as a fresh one.
                identity_key=finding.get("identity_key", ""),
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
                # Reconstruct the exploit-proof evidence too — it's serialized in the
                # checkpoint but was dropped on resume, so a restored CONFIRMED finding
                # silently lost its command_output/file_read/http_response proof.
                evidence=[
                    TestEvidence(type=e.get("type", ""), content=e.get("content", ""))
                    for e in cp_data.get("evidence", []) if isinstance(e, dict)
                ],
            )
            results.append(result)
            continue

        # Skip findings whose language has no Docker template, BEFORE spending
        # an LLM call generating a test the harness cannot usefully run.
        # Placed AFTER the checkpoint hit: a finding CONFIRMED by an
        # earlier run must keep that verdict on resume, not be downgraded
        # to SKIPPED and lose its exploit evidence.
        _loc = finding.get("location")
        _file = _loc.get("file") if isinstance(_loc, dict) else None
        _file = _file if isinstance(_file, str) else ""  # location.file may be non-str (JSON)
        _skip, _reason = should_skip_for_language(_file, repo_info.get("language"))
        if _skip:
            print(f"\n[{i+1}/{total}] SKIPPED {finding_id}: {_reason}", file=sys.stderr)
            results.append(DynamicTestResult(
                finding_id=finding_id,
                identity_key=finding.get("identity_key", ""),
                status="SKIPPED", details=_reason,
                elapsed_seconds=0,
            ))
            continue

        print(f"\n[{i+1}/{total}] Testing {finding_id}: "
              f"{finding.get('name', 'unknown')}...", file=sys.stderr)

        # Begin per-unit tracking so we can capture token counts for this
        # finding in addition to cost.
        tracker.start_unit_tracking()

        # Step 1: Generate test
        print("  Generating test...", file=sys.stderr)
        generation = generate_test(finding, repo_info, dynamic_test_binding, tracker)
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
                # #311: the saved ERROR unit file IS the count — derive the
                # summary from the unit files so this branch can no longer
                # write errors: 0 for an errored run.
                _counts = _summary_counts_from_checkpoints(checkpoint.load())
                _completed = _counts["completed"]
                _errors = _counts["errors"]
                checkpoint.write_summary(total, _completed, _errors, {},
                                         phase="in_progress")
            continue

        print(f"  Generated (${generation_cost:.4f}). Running in Docker...",
              file=sys.stderr)

        # Resolve the vulnerable source file for pre-staging. location.file is a
        # DETERMINISTIC repo-derived path (reporter.py sets it to route_key.split(":")[0],
        # the parser's repo-relative path of the unit) — repo-author-controlled, and in a
        # standalone run the findings JSON is fully caller-supplied. A `..`/absolute value,
        # or an in-repo symlink pointing outside, would make the copy escape repo_path and
        # read a HOST file into the Docker build context (read/exfil). Confine the resolved
        # path under repo_path (realpath also blocks the symlink case); skip on escape —
        # source_file stays None, the already-supported no-source path. Guard the types too:
        # `location` may be a non-dict and `file` a non-str (JSON), which must not raise
        # (an unwrapped raise aborts the whole run — see docker_executor._refuse_compose).
        source_file = None
        if repo_path:
            _loc = finding.get("location")
            rel_path = _loc.get("file", "") if isinstance(_loc, dict) else ""
            if isinstance(rel_path, str) and rel_path:
                repo_root = os.path.realpath(repo_path)
                resolved = os.path.realpath(os.path.join(repo_path, rel_path))
                if ((resolved == repo_root or resolved.startswith(repo_root + os.sep))
                        and os.path.isfile(resolved)):
                    source_file = resolved

        # Step 2: Execute in Docker and retry on errors
        execution = run_single_container(generation, finding_id,
                                         source_file=source_file)
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
                error_msg, dynamic_test_binding, tracker,
            )
            # Refresh unit usage after retry (tracker accumulates across calls
            # on the same thread).
            unit_usage = tracker.get_unit_usage()
            generation_cost = unit_usage["cost_usd"]

            if retry_gen is None:
                print(f"  Retry generation failed.", file=sys.stderr)
                break

            generation = retry_gen
            execution = run_single_container(generation, finding_id,
                                             source_file=source_file)
            result = collect_result(finding, generation, execution, generation_cost)
            print(f"  Retry {retry_count} result: {result.status} "
                  f"(${generation_cost:.4f})", file=sys.stderr)

        result.retry_count = retry_count
        result.generation_input_tokens = unit_usage["input_tokens"]
        result.generation_output_tokens = unit_usage["output_tokens"]
        results.append(result)

        # Save checkpoint and update summary after each finding.
        # #311: the counts are re-derived from the saved unit files (the
        # checkpoint was just saved, so the derivation includes it).
        if checkpoint:
            checkpoint.save(finding_id, result.to_dict())
            _counts = _summary_counts_from_checkpoints(checkpoint.load())
            _completed = _counts["completed"]
            _errors = _counts["errors"]
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
    with open_utf8(report_path, "w") as f:
        f.write(report_md)
    print(f"\nReport written to {report_path}", file=sys.stderr)

    # Save structured results JSON
    results_path = os.path.join(output_dir, "dynamic_test_results.json")
    with open_utf8(results_path, "w") as f:
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
        # #311: the final summary derives from the unit files too — the
        # authoritative record, structurally identical to status().
        _counts = _summary_counts_from_checkpoints(checkpoint.load())
        checkpoint.write_summary(total, _counts["completed"],
                                 _counts["errors"], {}, phase="done")

    return results
