"""
Report generation wrapper.

Wraps the existing report generators:
- generate_report.py   — HTML report with Chart.js
- export_csv.py        — CSV export
- report/generator.py  — LLM-based summary and disclosure documents

Also provides ``build_pipeline_output()`` which assembles analysis results
into the ``pipeline_output.json`` format consumed by ``python -m report``
and ``run_dynamic_tests()``.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from core.schemas import ReportResult

# Root of openant-core
_CORE_ROOT = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Pipeline output builder
# ---------------------------------------------------------------------------

def build_pipeline_output(
    results_path: str,
    output_path: str,
    repo_name: str | None = None,
    repo_url: str | None = None,
    language: str | None = None,
    commit_sha: str | None = None,
    application_type: str = "web_app",
    processing_level: str | None = None,
    step_reports: list[dict] | None = None,
) -> str:
    """Build ``pipeline_output.json`` from analysis results.

    Reads ``results.json`` or ``results_verified.json`` and transforms
    confirmed vulnerable/bypassable findings into the schema expected by
    ``report/generator.py`` and ``utilities/dynamic_tester``.

    Args:
        results_path: Path to ``results.json`` or ``results_verified.json``.
        output_path: Where to write ``pipeline_output.json``.
        repo_name: Repository name (e.g. ``"langchain-ai/langchain"``).
        repo_url: Repository URL.
        language: Primary language.
        commit_sha: Commit SHA being analyzed.
        application_type: App type for context (default ``"web_app"``).
        processing_level: Processing level used (``"reachable"``, etc.).
        step_reports: Optional list of step report dicts for duration/cost info.

    Returns:
        The *output_path* written to.
    """
    print(f"[Report] Building pipeline_output.json...", file=sys.stderr)

    with open(results_path) as f:
        experiment = json.load(f)

    all_results = experiment.get("results", [])
    code_by_route = experiment.get("code_by_route", {})
    metrics = experiment.get("metrics", {})

    # Use confirmed_findings if present (verified results), else filter manually
    confirmed = experiment.get("confirmed_findings")
    if confirmed is None:
        confirmed = [
            r for r in all_results
            if r.get("finding", r.get("verdict", "").lower()) in ("vulnerable", "bypassable")
            and r.get("verification", {}).get("agree", True)  # unverified = assume confirmed
        ]

    # Build findings in PipelineOutput schema
    findings_data = []
    for i, finding in enumerate(confirmed):
        route_key = finding.get("route_key") or finding.get("unit_id", "unknown")

        # Look up full result for extra fields
        full_result = next(
            (r for r in all_results
             if (r.get("route_key") or r.get("unit_id")) == route_key),
            finding,
        )

        # Extract vulnerability details from nested structure if present
        vulns = finding.get("vulnerabilities", [])
        vuln = vulns[0] if vulns else {}

        description = (
            vuln.get("description")
            or finding.get("reasoning")
            or full_result.get("reasoning")
        )

        vulnerable_code = vuln.get("vulnerable_code") or code_by_route.get(route_key)

        impact = vuln.get("impact") or finding.get("attack_vector")

        steps_to_reproduce = vuln.get("steps_to_reproduce")
        if not steps_to_reproduce:
            parts = []
            if finding.get("attack_vector"):
                parts.append(finding["attack_vector"])
            exploit_path = finding.get("exploit_path") or {}
            if exploit_path.get("data_flow"):
                parts.append("Data flow: " + " -> ".join(exploit_path["data_flow"]))
            if finding.get("verification_explanation"):
                parts.append("Verification: " + finding["verification_explanation"])
            steps_to_reproduce = "\n\n".join(parts) if parts else None

        # Determine stage2 verdict
        verification = finding.get("verification", {})
        if verification.get("agree", False):
            stage2_verdict = "confirmed" if finding.get("exploit_path") else "agreed"
        elif verification:
            stage2_verdict = "rejected"
        else:
            stage2_verdict = finding.get("finding", "vulnerable")

        findings_data.append({
            "id": f"VULN-{i+1:03d}",
            "name": vuln.get("name", finding.get("finding", "Unknown Vulnerability")),
            "short_name": vuln.get("short_name", finding.get("verdict", "vuln")),
            "location": {
                "file": route_key.split(":")[0] if ":" in route_key else "unknown",
                "function": route_key,
            },
            "cwe_id": vuln.get("cwe_id", 0),
            "cwe_name": vuln.get("cwe_name", "Unknown"),
            "stage1_verdict": finding.get("verdict", finding.get("finding", "vulnerable")),
            "stage2_verdict": stage2_verdict,
            "description": description,
            "vulnerable_code": vulnerable_code,
            "impact": impact,
            "suggested_fix": vuln.get("suggested_fix"),
            "steps_to_reproduce": steps_to_reproduce,
        })

    # Compute costs and durations from step reports
    costs = {}
    durations = {}
    skipped_steps = []
    if step_reports:
        for sr in step_reports:
            step = sr.get("step", "unknown")
            if sr.get("cost_usd"):
                costs[step] = {"actual": sr["cost_usd"]}
            if sr.get("duration_seconds"):
                durations[step] = sr["duration_seconds"]

    total_units = metrics.get("total", len(all_results))

    pipeline_output = {
        "repository": {
            "name": repo_name or experiment.get("dataset", "unknown"),
            "url": repo_url or "",
            "language": language or "",
            "commit_sha": commit_sha,
        },
        "analysis_date": datetime.now(timezone.utc).isoformat(),
        "application_type": application_type,
        "pipeline_stats": {
            "total_units": total_units,
            "reachable_units": total_units,
            "units_analyzed": total_units - metrics.get("errors", 0),
            "processing_level": processing_level,
            "costs": costs,
            "durations": durations,
            "skipped_steps": skipped_steps,
        },
        "results": {
            "vulnerable": metrics.get("vulnerable", 0) + metrics.get("bypassable", 0),
            "safe": metrics.get("safe", 0) + metrics.get("protected", 0),
            "inconclusive": metrics.get("inconclusive", 0),
            "total": total_units,
        },
        "findings": findings_data,
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(pipeline_output, f, indent=2, ensure_ascii=False)

    print(f"  pipeline_output.json: {len(findings_data)} findings", file=sys.stderr)
    print(f"  Written to {output_path}", file=sys.stderr)

    return output_path, len(findings_data)


def generate_html_report(
    results_path: str,
    dataset_path: str,
    output_path: str,
) -> ReportResult:
    """Generate an interactive HTML report with Chart.js.

    Wraps generate_report.py via subprocess.

    Args:
        results_path: Path to experiment/results JSON.
        dataset_path: Path to dataset JSON.
        output_path: Path for the output HTML file.

    Returns:
        ReportResult with the output path.
    """
    print("[Report] Generating HTML report...", file=sys.stderr)

    # Pass step reports dir so the HTML report can include cost/time breakdown
    step_reports_dir = os.path.dirname(os.path.abspath(results_path))

    script = _CORE_ROOT / "generate_report.py"
    cmd = [
        sys.executable, str(script), results_path, dataset_path, output_path,
        "--step-reports-dir", step_reports_dir,
    ]

    result = subprocess.run(cmd, stdout=sys.stderr, stderr=sys.stderr, cwd=str(_CORE_ROOT))

    if result.returncode != 0:
        raise RuntimeError(f"HTML report generation failed (exit code {result.returncode})")

    print(f"  HTML report: {output_path}", file=sys.stderr)
    return ReportResult(output_path=output_path, format="html")


def generate_csv_report(
    results_path: str,
    dataset_path: str,
    output_path: str,
) -> ReportResult:
    """Export results to CSV.

    Wraps export_csv.py via subprocess.

    Args:
        results_path: Path to experiment/results JSON.
        dataset_path: Path to dataset JSON.
        output_path: Path for the output CSV file.

    Returns:
        ReportResult with the output path.
    """
    print("[Report] Generating CSV report...", file=sys.stderr)

    script = _CORE_ROOT / "export_csv.py"
    cmd = [sys.executable, str(script), results_path, dataset_path, output_path]

    result = subprocess.run(cmd, stdout=sys.stderr, stderr=sys.stderr, cwd=str(_CORE_ROOT))

    if result.returncode != 0:
        raise RuntimeError(f"CSV export failed (exit code {result.returncode})")

    print(f"  CSV report: {output_path}", file=sys.stderr)
    return ReportResult(output_path=output_path, format="csv")


def generate_summary_report(
    results_path: str,
    output_path: str,
) -> ReportResult:
    """Generate LLM-based summary report (Markdown).

    Calls report/generator.py directly (in-process) for proper cost tracking.

    Args:
        results_path: Path to pipeline_output.json or results JSON.
        output_path: Path for the output Markdown file.

    Returns:
        ReportResult with the output path and usage info.
    """
    import json
    from report.generator import generate_summary_report as _generate_summary, merge_dynamic_results
    from report.schema import validate_pipeline_output, ValidationError

    print("[Report] Generating summary report (LLM)...", file=sys.stderr)

    with open(results_path) as f:
        pipeline_data = json.load(f)

    # Merge dynamic test results if available
    pipeline_data = merge_dynamic_results(pipeline_data, results_path)

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        raise RuntimeError(f"Invalid pipeline output: {e}")

    report_text, usage = _generate_summary(pipeline_data)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(report_text)

    print(f"  Summary report: {output_path}", file=sys.stderr)
    print(f"  Cost: ${usage['cost_usd']:.4f} ({usage['total_tokens']:,} tokens)", file=sys.stderr)

    # Record in global tracker so step_context picks it up
    _record_usage_in_tracker(usage)

    return ReportResult(output_path=output_path, format="summary", usage=_usage_to_info(usage))


def generate_disclosure_docs(
    results_path: str,
    output_dir: str,
) -> ReportResult:
    """Generate per-vulnerability disclosure documents.

    Calls report/generator.py directly (in-process) for proper cost tracking.

    Args:
        results_path: Path to pipeline_output.json or results JSON.
        output_dir: Directory for disclosure Markdown files.

    Returns:
        ReportResult with the output directory path and usage info.
    """
    import json
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from report.generator import generate_disclosure as _generate_disclosure, _merge_usage, merge_dynamic_results
    from report.schema import validate_pipeline_output, ValidationError

    print("[Report] Generating disclosure documents (LLM)...", file=sys.stderr)

    with open(results_path) as f:
        pipeline_data = json.load(f)

    # Merge dynamic test results if available
    pipeline_data = merge_dynamic_results(pipeline_data, results_path)

    try:
        validate_pipeline_output(pipeline_data)
    except ValidationError as e:
        raise RuntimeError(f"Invalid pipeline output: {e}")

    os.makedirs(output_dir, exist_ok=True)

    product_name = pipeline_data["repository"]["name"]
    all_usages = []
    count = 0

    # Collect confirmed findings first
    confirmed = [
        (i, finding) for i, finding in enumerate(pipeline_data["findings"], 1)
        if finding.get("stage2_verdict") in ("confirmed", "agreed", "vulnerable")
    ]

    if not confirmed:
        print("  No confirmed vulnerabilities to generate disclosures for.", file=sys.stderr)
    else:
        print(f"  Generating {len(confirmed)} disclosures in parallel (8 workers)...",
              file=sys.stderr)

        def _one(args):
            i, finding = args
            disclosure_text, usage = _generate_disclosure(finding, product_name)
            safe_name = finding["short_name"].replace(" ", "_").upper()
            filename = f"DISCLOSURE_{i:02d}_{safe_name}.md"
            filepath = os.path.join(output_dir, filename)
            with open(filepath, "w") as f:
                f.write(disclosure_text)
            return finding["short_name"], filepath, usage

        executor = ThreadPoolExecutor(max_workers=8)
        futures = {executor.submit(_one, item): item for item in confirmed}
        try:
            for future in as_completed(futures):
                name, filepath, usage = future.result()
                all_usages.append(usage)
                count += 1
                print(f"  [{count}/{len(confirmed)}] {name} -> {filepath}",
                      file=sys.stderr)
        except KeyboardInterrupt:
            print("\n[Report] Interrupted — cancelling pending disclosures...",
                  file=sys.stderr, flush=True)
            executor.shutdown(wait=False, cancel_futures=True)
            raise
        executor.shutdown(wait=False)

    merged_usage = _merge_usage(all_usages) if all_usages else {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "cost_usd": 0.0}

    print(f"  Disclosures: {count} files in {output_dir}", file=sys.stderr)
    print(f"  Cost: ${merged_usage['cost_usd']:.4f} ({merged_usage['total_tokens']:,} tokens)", file=sys.stderr)

    # Record in global tracker so step_context picks it up
    _record_usage_in_tracker(merged_usage)

    return ReportResult(output_path=output_dir, format="disclosure", usage=_usage_to_info(merged_usage))


def _record_usage_in_tracker(usage: dict):
    """Record usage in the global TokenTracker so step_context captures it."""
    try:
        from utilities.llm_client import get_global_tracker
        tracker = get_global_tracker()
        # Record as a single aggregated call
        if usage.get("total_tokens", 0) > 0:
            tracker.record_call(
                model="claude-opus-4-6",
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
            )
    except Exception:
        pass  # Best effort — don't break report generation


def _usage_to_info(usage: dict):
    """Convert a usage dict to a UsageInfo dataclass."""
    from core.schemas import UsageInfo
    return UsageInfo(
        total_calls=1,
        total_input_tokens=usage.get("input_tokens", 0),
        total_output_tokens=usage.get("output_tokens", 0),
        total_tokens=usage.get("total_tokens", 0),
        total_cost_usd=usage.get("cost_usd", 0.0),
    )
