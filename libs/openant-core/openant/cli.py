#!/usr/bin/env python3
"""
OpenAnt CLI — Unified command-line interface for vulnerability analysis.

Commands:
    openant scan /path/to/repo --output /tmp/results
    openant parse /path/to/repo --output /tmp/results
    openant enhance dataset.json --analyzer-output ao.json --repo-path /repo -o enhanced.json
    openant analyze dataset.json --output /tmp/results
    openant verify results.json --analyzer-output ao.json --output /tmp/results
    openant build-output results.json -o pipeline_output.json
    openant dynamic-test pipeline_output.json -o /tmp/dt/
    openant report results.json --format html --output report.html

All commands output JSON to stdout and logs to stderr.
Exit codes: 0 = clean, 1 = vulnerabilities found, 2 = error.
"""

import argparse
import json
import os
import sys
import tempfile


def _output_json(data: dict):
    """Write JSON to stdout."""
    json.dump(data, sys.stdout, indent=2)
    sys.stdout.write("\n")


def _load_step_reports(directory: str) -> list[dict]:
    """Load all {step}.report.json files from a directory.

    Used by standalone commands (build-output, report) to feed
    cost/duration data into pipeline_output.json.
    """
    import glob
    reports = []
    for path in glob.glob(os.path.join(directory, "*.report.json")):
        try:
            with open(path) as f:
                reports.append(json.load(f))
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def cmd_scan(args):
    """Scan a repository end-to-end."""
    from core.scanner import scan_repository
    from core.schemas import success, error

    output_dir = args.output or tempfile.mkdtemp(prefix="open_ant_")

    try:
        result = scan_repository(
            repo_path=args.repo,
            output_dir=output_dir,
            language=args.language or "auto",
            processing_level=args.level,
            verify=args.verify,
            generate_context=not args.no_context,
            generate_report=not args.no_report,
            skip_tests=not args.no_skip_tests,
            limit=args.limit,
            model=args.model,
            enhance=not args.no_enhance,
            enhance_mode=args.enhance_mode,
            dynamic_test=args.dynamic_test,
            workers=args.workers,
            backoff_seconds=args.backoff,
        )

        _output_json(success(result.to_dict()))

        # Exit 1 if vulnerabilities found
        if result.metrics.vulnerable > 0 or result.metrics.bypassable > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_parse(args):
    """Parse a repository into a dataset."""
    from core.parser_adapter import parse_repository
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = args.output or tempfile.mkdtemp(prefix="open_ant_parse_")

    try:
        with step_context("parse", output_dir, inputs={
            "repo_path": os.path.abspath(args.repo),
            "language": args.language or "auto",
            "processing_level": args.level,
            "skip_tests": not args.no_skip_tests,
        }) as ctx:
            result = parse_repository(
                repo_path=args.repo,
                output_dir=output_dir,
                language=args.language or "auto",
                processing_level=args.level,
                skip_tests=not args.no_skip_tests,
                name=getattr(args, "name", None),
            )

            ctx.summary = {
                "total_units": result.units_count,
                "language": result.language,
                "processing_level": result.processing_level,
            }
            ctx.outputs = {
                "dataset_path": result.dataset_path,
                "analyzer_output_path": result.analyzer_output_path,
            }

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_enhance(args):
    """Enhance a dataset with security context."""
    from core.enhancer import enhance_dataset
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    # Default output path: same dir as input, with _enhanced suffix
    if args.output:
        output_path = args.output
    else:
        base, ext = os.path.splitext(args.dataset)
        output_path = f"{base}_enhanced{ext}"

    output_dir = os.path.dirname(os.path.abspath(output_path))

    try:
        with step_context("enhance", output_dir, inputs={
            "dataset_path": os.path.abspath(args.dataset),
            "analyzer_output_path": os.path.abspath(args.analyzer_output) if args.analyzer_output else None,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
            "mode": args.mode,
        }) as ctx:
            result = enhance_dataset(
                dataset_path=args.dataset,
                output_path=output_path,
                analyzer_output_path=args.analyzer_output,
                repo_path=args.repo_path,
                mode=args.mode,
                checkpoint_path=args.checkpoint,
                workers=args.workers,
                backoff_seconds=args.backoff,
            )

            ctx.summary = {
                "units_enhanced": result.units_enhanced,
                "error_count": result.error_count,
                "classifications": result.classifications,
                "mode": args.mode,
            }
            if result.error_summary:
                ctx.summary["error_summary"] = result.error_summary
            ctx.outputs = {
                "enhanced_dataset_path": result.enhanced_dataset_path,
            }

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_analyze(args):
    """Run vulnerability analysis on a dataset.

    With --verify, chains Stage 1 detection into Stage 2 verification
    automatically (convenience shortcut for ``analyze`` + ``verify``).
    """
    from core.analyzer import run_analysis
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    output_dir = args.output or tempfile.mkdtemp(prefix="open_ant_analyze_")

    exploitable_filter = "all" if args.exploitable_all else ("strict" if args.exploitable_only else None)

    try:
        with step_context("analyze", output_dir, inputs={
            "dataset_path": os.path.abspath(args.dataset),
            "model": args.model,
            "exploitable_filter": exploitable_filter,
            "limit": args.limit,
        }) as ctx:
            result = run_analysis(
                dataset_path=args.dataset,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=args.app_context,
                repo_path=args.repo_path,
                limit=args.limit,
                model=args.model,
                exploitable_filter=exploitable_filter,
                workers=args.workers,
                checkpoint_path=getattr(args, "checkpoint", None),
                backoff_seconds=args.backoff,
            )

            ctx.summary = {
                "total_units": result.metrics.total,
                "analyzed": result.metrics.total - result.metrics.errors,
                "verdicts": {
                    "vulnerable": result.metrics.vulnerable,
                    "bypassable": result.metrics.bypassable,
                    "inconclusive": result.metrics.inconclusive,
                    "protected": result.metrics.protected,
                    "safe": result.metrics.safe,
                    "errors": result.metrics.errors,
                },
            }
            ctx.outputs = {
                "results_path": result.results_path,
            }

        # If --verify, chain into Stage 2
        if args.verify:
            if not args.analyzer_output:
                print("[Analyze] WARNING: --verify requires --analyzer-output. "
                      "Skipping verification.", file=sys.stderr)
            else:
                from core.verifier import run_verification
                with step_context("verify", output_dir, inputs={
                    "results_path": result.results_path,
                    "analyzer_output_path": os.path.abspath(args.analyzer_output),
                }) as vctx:
                    vresult = run_verification(
                        results_path=result.results_path,
                        output_dir=output_dir,
                        analyzer_output_path=args.analyzer_output,
                        app_context_path=args.app_context,
                        repo_path=args.repo_path,
                        workers=args.workers,
                        backoff_seconds=args.backoff,
                    )

                    vctx.summary = {
                        "findings_input": vresult.findings_input,
                        "findings_verified": vresult.findings_verified,
                        "agreed": vresult.agreed,
                        "disagreed": vresult.disagreed,
                        "confirmed_vulnerabilities": vresult.confirmed_vulnerabilities,
                    }
                    vctx.outputs = {
                        "verified_results_path": vresult.verified_results_path,
                    }

                _output_json(success(vresult.to_dict()))
                if vresult.confirmed_vulnerabilities > 0:
                    return 1
                return 0

        _output_json(success(result.to_dict()))

        # Exit 1 if vulnerabilities found
        if result.metrics.vulnerable > 0 or result.metrics.bypassable > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_verify(args):
    """Run Stage 2 attacker-simulation verification on Stage 1 results."""
    from core.verifier import run_verification
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    output_dir = args.output or tempfile.mkdtemp(prefix="open_ant_verify_")

    try:
        with step_context("verify", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
            "analyzer_output_path": os.path.abspath(args.analyzer_output),
            "app_context_path": os.path.abspath(args.app_context) if args.app_context else None,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
        }) as ctx:
            result = run_verification(
                results_path=args.results,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=args.app_context,
                repo_path=args.repo_path,
                workers=args.workers,
                checkpoint_path=getattr(args, "checkpoint", None),
                backoff_seconds=args.backoff,
            )

            ctx.summary = {
                "findings_input": result.findings_input,
                "findings_verified": result.findings_verified,
                "agreed": result.agreed,
                "disagreed": result.disagreed,
                "confirmed_vulnerabilities": result.confirmed_vulnerabilities,
            }
            ctx.outputs = {
                "verified_results_path": result.verified_results_path,
            }

        _output_json(success(result.to_dict()))

        # Exit 1 if confirmed vulnerabilities
        if result.confirmed_vulnerabilities > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_build_output(args):
    """Build pipeline_output.json from analysis results."""
    from core.reporter import build_pipeline_output
    from core.schemas import success, error
    from core.step_report import step_context

    output_dir = os.path.dirname(os.path.abspath(args.output))

    # Load existing step reports for cost/duration data
    results_dir = os.path.dirname(os.path.abspath(args.results))
    step_reports = _load_step_reports(results_dir)

    try:
        with step_context("build-output", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
        }) as ctx:
            path, findings_count = build_pipeline_output(
                results_path=args.results,
                output_path=args.output,
                repo_name=args.repo_name,
                repo_url=args.repo_url,
                language=args.language,
                commit_sha=args.commit_sha,
                application_type=args.app_type or "web_app",
                processing_level=args.processing_level,
                step_reports=step_reports,
            )

            ctx.outputs = {"pipeline_output_path": path}

        _output_json(success({"pipeline_output_path": path, "findings_count": findings_count}))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_dynamic_test(args):
    """Run Docker-isolated dynamic exploit testing."""
    from core.dynamic_tester import run_tests
    from core.schemas import success, error
    from core.step_report import step_context
    from core import tracking

    tracking.reset_tracking()

    output_dir = args.output or tempfile.mkdtemp(prefix="openant_dyntest_")

    try:
        with step_context("dynamic-test", output_dir, inputs={
            "pipeline_output_path": os.path.abspath(args.pipeline_output),
            "max_retries": args.max_retries,
        }) as ctx:
            result = run_tests(
                pipeline_output_path=args.pipeline_output,
                output_dir=output_dir,
                max_retries=args.max_retries,
            )

            ctx.summary = {
                "findings_tested": result.findings_tested,
                "confirmed": result.confirmed,
                "not_reproduced": result.not_reproduced,
                "blocked": result.blocked,
                "inconclusive": result.inconclusive,
                "errors": result.errors,
            }
            ctx.outputs = {
                "results_json_path": result.results_json_path,
                "results_md_path": result.results_md_path,
            }

        _output_json(success(result.to_dict()))

        if result.confirmed > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def _default_report_output(results_path: str, fmt: str) -> str:
    """Derive a sensible default output path based on format."""
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(results_path)), "final-reports")
    defaults = {
        "html": os.path.join(reports_dir, "report.html"),
        "csv": os.path.join(reports_dir, "report.csv"),
        "summary": os.path.join(reports_dir, "report.md"),
        "disclosure": os.path.join(reports_dir, "disclosures"),
    }
    return defaults.get(fmt, os.path.join(reports_dir, "report"))


def cmd_report(args):
    """Generate reports from analysis results.

    Accepts either a ``pipeline_output.json`` (via ``--pipeline-output``) or
    a raw ``results.json`` as positional argument.  For summary/disclosure
    formats, ``pipeline_output.json`` is required; if only results are given,
    it is built automatically.
    """
    from core.reporter import (
        build_pipeline_output,
        generate_csv_report,
        generate_summary_report,
        generate_disclosure_docs,
    )
    from core.schemas import success, error
    from core.step_report import step_context

    fmt = args.format
    output_path = args.output or _default_report_output(args.results, fmt)
    output_dir = os.path.dirname(os.path.abspath(output_path))

    # Check if dynamic tests have been run (for summary/disclosure formats)
    if fmt in ("summary", "disclosure") and not getattr(args, "skip_dt_check", False):
        results_dir = os.path.dirname(os.path.abspath(args.results))
        dt_results_path = os.path.join(results_dir, "dynamic_test_results.json")
        if not os.path.exists(dt_results_path):
            print(
                "\nDynamic tests haven't been run yet.\n"
                "If this is intentional, press Y to generate reports without dynamic test data.\n"
                "Otherwise, run 'openant dynamic-test' first.\n",
                file=sys.stderr,
            )
            try:
                answer = input("[Y/n] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "n"
            if answer not in ("y", "yes", ""):
                print("Aborted. Run 'openant dynamic-test' first.", file=sys.stderr)
                return 0

    try:
        with step_context("report", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
            "format": fmt,
        }) as ctx:
            # For summary/disclosure, we need pipeline_output.json
            pipeline_output_path = args.pipeline_output
            if fmt in ("summary", "disclosure") and not pipeline_output_path:
                # Auto-build pipeline_output from results, with step report data
                results_dir = os.path.dirname(os.path.abspath(args.results))
                step_reports = _load_step_reports(results_dir)
                pipeline_output_path = os.path.join(output_dir, "pipeline_output.json")
                build_pipeline_output(
                    results_path=args.results,
                    output_path=pipeline_output_path,
                    repo_name=args.repo_name,
                    step_reports=step_reports,
                )

            if fmt == "html":
                # HTML reports are now rendered by the Go CLI via report-data.
                # This code path should not be reached — Go handles html directly.
                _output_json(error("HTML reports are generated by the Go CLI. Use 'openant report -f html' instead."))
                return 2
            elif fmt == "csv":
                if not args.dataset:
                    _output_json(error("--dataset is required for CSV reports"))
                    return 2
                result = generate_csv_report(args.results, args.dataset, output_path)
            elif fmt == "summary":
                result = generate_summary_report(pipeline_output_path, output_path)
            elif fmt == "disclosure":
                result = generate_disclosure_docs(pipeline_output_path, output_path)
            else:
                _output_json(error(f"Unknown format: {fmt}"))
                return 2

            ctx.summary = {"format": fmt}
            ctx.outputs = {"output_path": output_path}

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_checkpoint_status(args):
    """Report checkpoint status for a checkpoint directory.

    Internal subcommand — not user-facing. Called by the Go CLI to get
    accurate completed/errored counts by reading actual checkpoint files.
    """
    from core.checkpoint import StepCheckpoint
    from core.schemas import success, error

    checkpoint_dir = args.checkpoint_dir
    if not os.path.isdir(checkpoint_dir):
        _output_json(error(f"Checkpoint directory not found: {checkpoint_dir}"))
        return 2

    try:
        status = StepCheckpoint.status(checkpoint_dir)
        _output_json(success(status))
        return 0
    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_report_data(args):
    """Prepare pre-computed report data as JSON for the Go HTML renderer.

    Internal subcommand — not user-facing. Called by the Go CLI to get
    all data needed to render the HTML overview report.

    Outputs a JSON blob with stats, chart data, findings, remediation HTML,
    and step reports — everything display-ready.
    """
    import html as html_mod
    import anthropic
    from core.schemas import success, error
    from core.step_report import step_context
    from utilities.llm_client import get_global_tracker

    results_path = args.results
    dataset_path = args.dataset

    if not dataset_path:
        _output_json(error("--dataset is required for report-data"))
        return 2

    results_dir = os.path.dirname(os.path.abspath(results_path))

    try:
        with step_context("report-data", results_dir, inputs={
            "results_path": os.path.abspath(results_path),
            "dataset_path": os.path.abspath(dataset_path),
        }) as ctx:
            # Load data
            with open(results_path) as f:
                experiment = json.load(f)
            with open(dataset_path) as f:
                dataset = json.load(f)

            # --- Load dynamic test results if available ---
            # Dynamic tests use VULN-XXX IDs from pipeline_output.json,
            # but report-data works with route_keys from results_verified.json.
            # Bridge via pipeline_output's location.function (== route_key).
            dt_by_route_key = {}
            dt_path = os.path.join(results_dir, "dynamic_test_results.json")
            po_path = os.path.join(results_dir, "pipeline_output.json")
            if os.path.exists(dt_path) and os.path.exists(po_path):
                with open(dt_path) as f:
                    dt_data = json.load(f)
                with open(po_path) as f:
                    po_data = json.load(f)

                # Map VULN-ID → route_key from pipeline_output
                vuln_id_to_route = {}
                for finding in po_data.get("findings", []):
                    fid = finding.get("id")
                    route = finding.get("location", {}).get("function", "")
                    if fid and route:
                        vuln_id_to_route[fid] = route

                # Map route_key → dynamic test result
                for dr in dt_data.get("results", []):
                    fid = dr.get("finding_id")
                    route = vuln_id_to_route.get(fid)
                    if route:
                        dt_by_route_key[route] = dr

                print(f"[Report] Loaded {len(dt_by_route_key)} dynamic test results", file=sys.stderr)

            # --- Prepare findings ---
            units_by_id = {u["id"]: u for u in dataset.get("units", [])}

            verdict_order = ["vulnerable", "bypassable", "inconclusive", "protected", "safe"]
            verdict_colors = {
                "vulnerable": "#dc3545",
                "bypassable": "#fd7e14",
                "inconclusive": "#6c757d",
                "protected": "#28a745",
                "safe": "#20c997",
            }
            verdict_priority = {v: i for i, v in enumerate(verdict_order)}
            dt_status_order = ["CONFIRMED", "INCONCLUSIVE", "ERROR", "", "BLOCKED", "NOT_REPRODUCED"]
            dt_status_priority = {s: i for i, s in enumerate(dt_status_order)}

            verdict_counts = {}
            file_verdicts = {}
            findings = []

            for result in experiment.get("results", []):
                route_key = result.get("route_key", "")
                verdict = result.get("finding", "")
                file_path = route_key.rsplit(":", 1)[0] if ":" in route_key else route_key
                unit = units_by_id.get(route_key, {})
                llm_context = unit.get("llm_context") or {}
                verification = result.get("verification") or {}

                # Justification: prefer stage2, fallback to stage1
                justification = verification.get("explanation", "")
                if not justification:
                    justification = result.get("reasoning", "")
                justification = justification[:300]

                # Downgrade unverified findings to inconclusive
                if justification.strip() == "Max iterations reached":
                    verdict = "inconclusive"

                verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

                # Track worst verdict per file
                if file_path not in file_verdicts:
                    file_verdicts[file_path] = verdict
                elif verdict_priority.get(verdict, 3) < verdict_priority.get(file_verdicts[file_path], 3):
                    file_verdicts[file_path] = verdict

                func_name = route_key.split(":")[-1] if ":" in route_key else route_key

                # Dynamic test result for this finding
                dt_result = dt_by_route_key.get(route_key)
                dt_status = ""
                dt_details = ""
                if dt_result:
                    dt_status = dt_result.get("status", "")
                    dt_details = dt_result.get("details", "")

                findings.append({
                    "verdict": verdict,
                    "verdict_color": verdict_colors.get(verdict, "#6c757d"),
                    "file": file_path,
                    "function": func_name,
                    "attack_vector": result.get("attack_vector", "") or "",
                    "analysis": justification,
                    "dynamic_test_status": dt_status,
                    "dynamic_test_details": dt_details,
                    "number": 0,  # assigned after sort
                })

            # Sort by verdict priority, then by dynamic test status within each group
            findings.sort(key=lambda f: (
                verdict_priority.get(f["verdict"], 3),
                dt_status_priority.get(f["dynamic_test_status"], 3),
            ))
            for i, f in enumerate(findings, 1):
                f["number"] = i

            # --- Group findings by verdict, sub-grouped by dynamic test outcome ---
            dt_subgroup_defs = [
                ("Confirmed", lambda s: s == "CONFIRMED"),
                ("Not reproduced", lambda s: s in ("NOT_REPRODUCED", "BLOCKED")),
                ("Test error", lambda s: s == "ERROR"),
                ("Not tested", lambda s: s in ("", "INCONCLUSIVE")),
            ]

            findings_by_verdict = []
            for v in verdict_order:
                group = [f for f in findings if f["verdict"] == v]
                if not group:
                    continue

                subgroups = []
                for label, predicate in dt_subgroup_defs:
                    sg_findings = [f for f in group if predicate(f.get("dynamic_test_status", ""))]
                    if sg_findings:
                        subgroups.append({"label": label, "findings": sg_findings})

                findings_by_verdict.append({
                    "verdict": v,
                    "verdict_color": verdict_colors[v],
                    "count": len(group),
                    "open_by_default": v in ("vulnerable", "bypassable"),
                    "findings": group,
                    "subgroups": subgroups,
                    "has_subgroups": len(subgroups) > 1,
                })

            # --- Chart data ---
            unit_chart = {
                "labels": [v for v in verdict_order if v in verdict_counts],
                "data": [verdict_counts.get(v, 0) for v in verdict_order if v in verdict_counts],
                "colors": [verdict_colors[v] for v in verdict_order if v in verdict_counts],
            }

            file_verdict_counts = {}
            for v in file_verdicts.values():
                file_verdict_counts[v] = file_verdict_counts.get(v, 0) + 1

            file_chart = {
                "labels": [v for v in verdict_order if v in file_verdict_counts],
                "data": [file_verdict_counts.get(v, 0) for v in verdict_order if v in file_verdict_counts],
                "colors": [verdict_colors[v] for v in verdict_order if v in file_verdict_counts],
            }

            # --- Stats ---
            total_units = len(experiment.get("results", []))
            total_files = len(file_verdicts)

            stats = {
                "total_units": total_units,
                "total_files": total_files,
                "vulnerable": verdict_counts.get("vulnerable", 0),
                "bypassable": verdict_counts.get("bypassable", 0),
                "secure": verdict_counts.get("protected", 0) + verdict_counts.get("safe", 0),
            }

            # --- Remediation guidance (LLM call) ---
            actionable = [f for f in findings if f["verdict"] in ("vulnerable", "bypassable", "inconclusive")]

            if not actionable:
                remediation_html = "<p>No vulnerabilities or security concerns found. All code units are either safe or properly protected.</p>"
            else:
                findings_text = ""
                for f in actionable:
                    findings_text += f"""
### Finding #{f['number']}: {f['file']}:{f['function']}
- **Verdict**: {f['verdict']}
- **Attack Vector**: {f['attack_vector'] or 'Not specified'}
- **Analysis**: {f['analysis'][:500]}
"""
                prompt = f"""Analyze these security findings and provide:

1. **Executive Summary**: A brief overview of the security posture (2-3 sentences)

2. **Prioritized Action Items**: Group remediation steps by priority: Critical Priority, High Priority, Medium Priority.
   For each item:
   - What to fix
   - Why it's important
   - How to fix it (concrete steps)
   When referencing findings, use their exact numbers with # prefix (e.g. #4, #12, #13, #14).
   Do NOT invent specific timeframes like "fix within 72 hours" — use only the priority labels above.

3. **Quick Wins**: Any simple fixes that would immediately improve security

Format your response as HTML (use <h3>, <p>, <ul>, <li>, <strong> tags). Do not include ```html markers.

## Findings to Analyze:
{findings_text}
"""
                print("[Report] Generating remediation guidance (LLM)...", file=sys.stderr)
                client = anthropic.Anthropic()
                response = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=4096,
                    messages=[{"role": "user", "content": prompt}],
                )
                remediation_html = response.content[0].text

                # Post-process: linkify finding references like #4, #12-#14
                import re
                def _linkify_finding(m):
                    num = m.group(1)
                    return f'<a href="#finding-{num}" class="finding-ref">#{num}</a>'
                remediation_html = re.sub(r'#(\d+)', _linkify_finding, remediation_html)

                # Track usage
                usage = response.usage
                tracker = get_global_tracker()
                tracker.record_call(
                    model="claude-sonnet-4-20250514",
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                )
                print(f"  Remediation cost: ${(usage.input_tokens / 1e6) * 3.0 + (usage.output_tokens / 1e6) * 15.0:.4f}", file=sys.stderr)

            # --- Step reports ---
            step_reports_data = []
            for sr in _load_step_reports(results_dir):
                duration = sr.get("duration_seconds", 0)
                cost = sr.get("cost_usd", 0)
                if duration >= 60:
                    dur_str = f"{duration / 60:.1f}m"
                else:
                    dur_str = f"{duration:.1f}s"
                cost_str = f"${cost:.2f}" if cost > 0 else "-"

                step_reports_data.append({
                    "step": sr.get("step", "unknown"),
                    "duration": dur_str,
                    "cost": cost_str,
                    "status": sr.get("status", "unknown"),
                    "timestamp": sr.get("timestamp", ""),
                })

            # Sort by timestamp
            step_reports_data.sort(key=lambda s: s.get("timestamp", ""))

            # --- Category descriptions (static) ---
            categories = [
                {"verdict": "vulnerable", "color": "#dc3545", "description": "Code contains an exploitable security vulnerability with no effective protection. Immediate remediation required."},
                {"verdict": "bypassable", "color": "#fd7e14", "description": "Security controls exist but can be circumvented under certain conditions. Review and strengthen protections."},
                {"verdict": "inconclusive", "color": "#6c757d", "description": "Security posture could not be determined. Manual review recommended to assess risk."},
                {"verdict": "protected", "color": "#28a745", "description": "Code handles potentially dangerous operations but has effective security controls in place."},
                {"verdict": "safe", "color": "#20c997", "description": "Code does not involve security-sensitive operations or poses no security risk."},
            ]

            from datetime import datetime

            # --- Repo info from pipeline_output.json ---
            repo_name = ""
            commit_sha = ""
            language = ""
            repo_url = ""
            if os.path.exists(po_path):
                try:
                    with open(po_path) as f:
                        po = json.load(f)
                    repo_info = po.get("repository", {})
                    repo_name = repo_info.get("name", "")
                    commit_sha = repo_info.get("commit_sha", "")
                    language = repo_info.get("language", "")
                    repo_url = repo_info.get("url", "")
                except (json.JSONDecodeError, OSError):
                    pass

            # --- Totals from step reports ---
            total_duration_seconds = 0.0
            total_cost_usd = 0.0
            for sr in _load_step_reports(results_dir):
                total_duration_seconds += sr.get("duration_seconds", 0)
                total_cost_usd += sr.get("cost_usd", 0)

            report_data = {
                "title": "Security Analysis Report",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "repo_name": repo_name,
                "commit_sha": commit_sha,
                "language": language,
                "repo_url": repo_url,
                "total_duration_seconds": total_duration_seconds,
                "total_cost_usd": total_cost_usd,
                "stats": stats,
                "unit_chart": unit_chart,
                "file_chart": file_chart,
                "remediation_html": remediation_html,
                "findings": findings,
                "findings_by_verdict": findings_by_verdict,
                "step_reports": step_reports_data,
                "categories": categories,
            }

            ctx.summary = {"findings": len(findings), "actionable": len(actionable)}

        _output_json(success(report_data))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def main():
    parser = argparse.ArgumentParser(
        prog="openant",
        description="Two-stage SAST tool using Claude for vulnerability analysis",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ---------------------------------------------------------------
    # scan — all-in-one
    # ---------------------------------------------------------------
    scan_p = subparsers.add_parser(
        "scan",
        help="Scan a repository (full pipeline: parse + enhance + detect + verify + report)",
    )
    scan_p.add_argument("repo", help="Path to repository")
    scan_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    scan_p.add_argument(
        "--language", "-l",
        choices=["auto", "python", "javascript", "go", "c", "ruby", "php"],
        default="auto",
        help="Language (default: auto-detect)",
    )
    scan_p.add_argument(
        "--level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="reachable",
        help="Processing level (default: reachable)",
    )
    scan_p.add_argument("--verify", action="store_true", help="Enable Stage 2 attacker simulation")
    scan_p.add_argument("--no-context", action="store_true", help="Skip application context generation")
    scan_p.add_argument("--no-enhance", action="store_true", help="Skip context enhancement step")
    scan_p.add_argument(
        "--enhance-mode",
        choices=["agentic", "single-shot"],
        default="agentic",
        help="Enhancement mode (default: agentic — thorough but more expensive)",
    )
    scan_p.add_argument("--no-report", action="store_true", help="Skip report generation")
    scan_p.add_argument("--dynamic-test", action="store_true",
                        help="Enable Docker-isolated dynamic testing (off by default)")
    scan_p.add_argument("--no-skip-tests", action="store_true", help="Include test files in parsing (default: tests are skipped)")
    scan_p.add_argument("--limit", type=int, help="Max units to analyze")
    scan_p.add_argument("--model", choices=["opus", "sonnet"], default="opus", help="Model (default: opus)")
    scan_p.add_argument("--workers", type=int, default=8,
                        help="Number of parallel workers for LLM steps (default: 8)")
    scan_p.add_argument("--backoff", type=int, default=30,
                        help="Seconds to wait when rate-limited (default: 30)")
    scan_p.set_defaults(func=cmd_scan)

    # ---------------------------------------------------------------
    # parse — repository parsing only
    # ---------------------------------------------------------------
    parse_p = subparsers.add_parser("parse", help="Parse a repository into a dataset")
    parse_p.add_argument("repo", help="Path to repository")
    parse_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    parse_p.add_argument(
        "--language", "-l",
        choices=["auto", "python", "javascript", "go", "c", "ruby", "php"],
        default="auto",
        help="Language (default: auto-detect)",
    )
    parse_p.add_argument(
        "--level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="reachable",
        help="Processing level (default: reachable)",
    )
    parse_p.add_argument("--no-skip-tests", action="store_true", help="Include test files in parsing (default: tests are skipped)")
    parse_p.add_argument("--name", help="Dataset name (default: derived from repo path)")
    parse_p.set_defaults(func=cmd_parse)

    # ---------------------------------------------------------------
    # enhance — add security context to a dataset
    # ---------------------------------------------------------------
    enhance_p = subparsers.add_parser("enhance", help="Enhance a dataset with security context")
    enhance_p.add_argument("dataset", help="Path to dataset JSON from parse step")
    enhance_p.add_argument("--analyzer-output", help="Path to analyzer_output.json (required for agentic mode)")
    enhance_p.add_argument("--repo-path", help="Path to the repository (required for agentic mode)")
    enhance_p.add_argument("--output", "-o", help="Output path for enhanced dataset (default: {input}_enhanced.json)")
    enhance_p.add_argument("--checkpoint", help="Path to save/resume checkpoint (agentic mode)")
    enhance_p.add_argument(
        "--mode",
        choices=["agentic", "single-shot"],
        default="agentic",
        help="Enhancement mode (default: agentic — thorough but more expensive)",
    )
    enhance_p.add_argument("--workers", type=int, default=8,
                           help="Number of parallel workers for LLM calls (default: 8)")
    enhance_p.add_argument("--backoff", type=int, default=30,
                           help="Seconds to wait when rate-limited (default: 30)")
    enhance_p.set_defaults(func=cmd_enhance)

    # ---------------------------------------------------------------
    # analyze — run analysis on existing dataset
    # ---------------------------------------------------------------
    analyze_p = subparsers.add_parser("analyze", help="Run vulnerability analysis on a dataset")
    analyze_p.add_argument("dataset", help="Path to dataset JSON")
    analyze_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    analyze_p.add_argument("--verify", action="store_true", help="Enable Stage 2 attacker simulation")
    analyze_p.add_argument("--analyzer-output", help="Path to analyzer_output.json (for Stage 2)")
    analyze_p.add_argument("--app-context", help="Path to application_context.json")
    analyze_p.add_argument("--limit", type=int, help="Max units to analyze")
    analyze_p.add_argument("--repo-path", help="Path to the repository (for context correction)")
    exploit_group = analyze_p.add_mutually_exclusive_group()
    exploit_group.add_argument("--exploitable-all", action="store_true",
                               help="Analyze units classified as exploitable or vulnerable_internal (safer, compensates for parser gaps)")
    exploit_group.add_argument("--exploitable-only", action="store_true",
                               help="Analyze only units classified as exploitable (strict, use after parser entry point fixes)")
    analyze_p.add_argument("--model", choices=["opus", "sonnet"], default="opus", help="Model (default: opus)")
    analyze_p.add_argument("--workers", type=int, default=8,
                           help="Number of parallel workers for LLM calls (default: 8)")
    analyze_p.add_argument("--checkpoint", help="Path to checkpoint directory for save/resume")
    analyze_p.add_argument("--backoff", type=int, default=30,
                           help="Seconds to wait when rate-limited (default: 30)")
    analyze_p.set_defaults(func=cmd_analyze)

    # ---------------------------------------------------------------
    # verify — Stage 2 attacker simulation (standalone)
    # ---------------------------------------------------------------
    verify_p = subparsers.add_parser("verify", help="Run Stage 2 verification on analysis results")
    verify_p.add_argument("results", help="Path to results.json from analyze step")
    verify_p.add_argument("--analyzer-output", required=True, help="Path to analyzer_output.json")
    verify_p.add_argument("--app-context", help="Path to application_context.json")
    verify_p.add_argument("--repo-path", help="Path to the repository")
    verify_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    verify_p.add_argument("--workers", type=int, default=8,
                          help="Number of parallel workers for LLM calls (default: 8)")
    verify_p.add_argument("--checkpoint", help="Path to checkpoint directory for save/resume")
    verify_p.add_argument("--backoff", type=int, default=30,
                          help="Seconds to wait when rate-limited (default: 30)")
    verify_p.set_defaults(func=cmd_verify)

    # ---------------------------------------------------------------
    # build-output — assemble pipeline_output.json
    # ---------------------------------------------------------------
    bo_p = subparsers.add_parser("build-output", help="Build pipeline_output.json from results")
    bo_p.add_argument("results", help="Path to results.json or results_verified.json")
    bo_p.add_argument("--output", "-o", required=True, help="Output path for pipeline_output.json")
    bo_p.add_argument("--repo-name", help="Repository name (e.g. owner/repo)")
    bo_p.add_argument("--repo-url", help="Repository URL")
    bo_p.add_argument("--language", help="Primary language")
    bo_p.add_argument("--commit-sha", help="Commit SHA")
    bo_p.add_argument("--app-type", help="Application type (default: web_app)")
    bo_p.add_argument("--processing-level", help="Processing level used")
    bo_p.set_defaults(func=cmd_build_output)

    # ---------------------------------------------------------------
    # dynamic-test — Docker-isolated exploit testing
    # ---------------------------------------------------------------
    dt_p = subparsers.add_parser("dynamic-test", help="Run dynamic exploit testing (requires Docker)")
    dt_p.add_argument("pipeline_output", help="Path to pipeline_output.json")
    dt_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    dt_p.add_argument("--max-retries", type=int, default=3,
                      help="Max retries per finding on error (default: 3)")
    dt_p.set_defaults(func=cmd_dynamic_test)

    # ---------------------------------------------------------------
    # report — generate reports from results
    # ---------------------------------------------------------------
    report_p = subparsers.add_parser("report", help="Generate reports from analysis results")
    report_p.add_argument("results", help="Path to results JSON or pipeline_output.json")
    report_p.add_argument(
        "--format", "-f",
        choices=["html", "csv", "summary", "disclosure"],
        default="disclosure",
        help="Report format (default: disclosure)",
    )
    report_p.add_argument("--dataset", help="Path to dataset JSON (required for html/csv)")
    report_p.add_argument("--pipeline-output", help="Path to pipeline_output.json (for summary/disclosure; auto-built if absent)")
    report_p.add_argument("--repo-name", help="Repository name (used when auto-building pipeline_output)")
    report_p.add_argument("--output", "-o", help="Output path (default: derived from results path and format)")
    report_p.set_defaults(func=cmd_report)

    # ---------------------------------------------------------------
    # report-data — internal: prepare pre-computed report data as JSON
    # ---------------------------------------------------------------
    rd_p = subparsers.add_parser("report-data", help="(internal) Prepare report data for Go renderer")
    rd_p.add_argument("results", help="Path to results/experiment JSON")
    rd_p.add_argument("--dataset", required=True, help="Path to dataset JSON")
    rd_p.set_defaults(func=cmd_report_data)

    # ---------------------------------------------------------------
    # checkpoint-status — internal: report checkpoint status for Go CLI
    # ---------------------------------------------------------------
    cs_p = subparsers.add_parser("checkpoint-status",
        help="(internal) Report checkpoint status for a directory")
    cs_p.add_argument("checkpoint_dir", help="Path to checkpoint directory")
    cs_p.set_defaults(func=cmd_checkpoint_status)

    args = parser.parse_args()
    return args.func(args)


def _get_version() -> str:
    """Get version from package."""
    try:
        from openant import __version__
        return __version__
    except ImportError:
        return "0.1.0"


if __name__ == "__main__":
    sys.exit(main())
