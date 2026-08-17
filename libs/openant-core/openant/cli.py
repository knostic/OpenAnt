#!/usr/bin/env python3
"""
OpenAnt CLI — Unified command-line interface for vulnerability analysis.

Commands:
    openant scan /path/to/repo --output /tmp/results
    openant parse /path/to/repo --output /tmp/results
    openant generate-context /path/to/repo -o /tmp/results/application_context.json
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

from core.language_registry import supported_languages
from core.language_selection import (
    DEFAULT_MIN_FILES,
    DEFAULT_MIN_SHARE,
    report_exclusions,
    select_languages,
)
from core.verdict_taxonomy import FINDING_VERDICT_ORDER
from utilities.file_io import normalize_results, read_json


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
            reports.append(read_json(path))
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def cmd_scan(args):
    """Scan a repository end-to-end."""
    from core.scanner import scan_repository
    from core.schemas import success, error

    output_dir = args.output or tempfile.mkdtemp(prefix="open_ant_")

    try:
        # Resolve multi-language selection BEFORE scanning so an invalid flag
        # combination fails fast rather than after a full parse.
        _selection = _select_languages_for(args)

        result = scan_repository(
            repo_path=args.repo,
            output_dir=output_dir,
            language=args.language or "auto",
            languages=_selection.selected if _selection else None,
            excluded_languages=dict(_selection.excluded) if _selection else None,
            strict_languages=getattr(args, "strict_languages", False),
            processing_level=args.level,
            verify=args.verify,
            generate_context=not args.no_context,
            generate_report=not args.no_report,
            skip_tests=not args.no_skip_tests,
            limit=args.limit,
            llm_config_name=args.llm_config,
            enhance=not args.no_enhance,
            enhance_mode=args.enhance_mode,
            dynamic_test=args.dynamic_test,
            workers=args.workers,
            backoff_seconds=args.backoff,
            repo_name=getattr(args, "repo_name", None),
            repo_url=getattr(args, "repo_url", None),
            commit_sha=getattr(args, "commit_sha", None),
            diff_manifest=getattr(args, "diff_manifest", None),
            library_mode=getattr(args, "library_mode", False),
            llm_reachability=getattr(args, "llm_reachability", False),
            llm_reachability_max_code_bytes=getattr(
                args, "llm_reachability_max_code_bytes", 1500
            ),
        )

        scan_payload = result.to_dict()
        # Surface the diff block on the envelope so the Go CLI banner can
        # render an "Incremental: base..head" line on success. The block
        # is the same one written into pipeline_output.json by reporter.py.
        if result.pipeline_output_path and os.path.exists(result.pipeline_output_path):
            try:
                po = read_json(result.pipeline_output_path)
                diff_block = po.get("diff")
                if isinstance(diff_block, dict) and diff_block.get("mode") == "incremental":
                    scan_payload["diff"] = diff_block
            except (json.JSONDecodeError, OSError):
                pass
        _output_json(success(scan_payload))

        # Exit 1 if vulnerabilities found
        if result.metrics.vulnerable > 0 or result.metrics.bypassable > 0:
            return 1
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def _select_languages_for(args):
    """LanguageSelection for this invocation, or None only for an explicit ``-l``.

    **`auto` now means every detected language, not the dominant one.** This is a
    deliberate behaviour change and it is the point of the feature: the request was
    "all languages we currently support should be detected in the repo and it
    should scan all of them, not just the main one" — a statement about what the
    tool does by default, which an opt-in flag does not satisfy.

    The machinery this needs already existed and was already reviewed:
    ``select_languages`` applies the file-count and share thresholds, always keeps
    the dominant language so a selection can never be empty, and
    ``report_exclusions`` prints any language it dropped. Only the early return
    here forced the legacy single-language path, so removing it is the whole
    inversion.

    Returns None only when the caller named a single language explicitly with
    ``-l <lang>``, which remains the escape hatch and the way to get the old
    behaviour.

    What changes for existing users: multi-language repositories now cost more to
    scan and produce more findings. That is the intended effect; the loud
    selection/exclusion banner is the mitigation, so the coverage change is never
    silent.
    """
    explicit = getattr(args, "language", "auto") not in (None, "auto")
    multi = (getattr(args, "languages", None)
             or getattr(args, "all_languages", False)
             or getattr(args, "multi_language", False))
    if explicit and not multi:
        return None
    from core.parser_adapter import detect_languages

    return resolve_language_selection(args, detect_languages(args.repo))


def cmd_parse(args):
    """Parse a repository into a dataset."""
    from core.parser_adapter import _maybe_apply_diff_filter, parse_repository
    from core.schemas import ParseResult
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
            selection = _select_languages_for(args)

            if selection is not None and selection.is_multi:
                # Multi-language: fan out into <output_dir>/<lang>/, then merge
                # into the single dataset the rest of the pipeline consumes.
                from core.dataset_merge import (
                    merge_analyzer_outputs,
                    merge_datasets,
                    write_call_graph_index,
                )
                from core.parser_adapter import parse_repository_multi

                outcomes = parse_repository_multi(
                    repo_path=args.repo,
                    run_dir=output_dir,
                    languages=selection.selected,
                    processing_level=args.level,
                    skip_tests=not args.no_skip_tests,
                    name=getattr(args, "name", None),
                    fresh=getattr(args, "fresh", False),
                    library_mode=getattr(args, "library_mode", False),
                    strict=getattr(args, "strict_languages", False),
                )
                dataset_path = os.path.join(output_dir, "dataset.json")
                analyzer_path = os.path.join(output_dir, "analyzer_output.json")
                merge_stats = merge_datasets(outcomes, dataset_path)
                merge_analyzer_outputs(outcomes, analyzer_path)
                write_call_graph_index(
                    outcomes, os.path.join(output_dir, "call_graphs.json")
                )

                failed = [o for o in outcomes if not o.ok]
                result = ParseResult(
                    dataset_path=dataset_path,
                    analyzer_output_path=analyzer_path if os.path.exists(analyzer_path) else None,
                    units_count=merge_stats.total_units,
                    # Scalar stays the PRIMARY language for back-compat.
                    language=selection.primary,
                    processing_level=args.level,
                    languages=merge_stats.languages,
                    language_stats=merge_stats.units_per_language,
                    per_language={o.language: o.to_dict() for o in outcomes},
                    parse_errors=[o.to_dict() for o in failed],
                    excluded_languages=dict(selection.excluded),
                )
                _maybe_apply_diff_filter(
                    result, output_dir, getattr(args, "diff_manifest", None)
                )
            else:
                # NOTE: exclusions are attached AFTER this call — see below.
                # The one-language case is exactly when a coverage gap exists,
                # so the legacy branch must report it too.
                result = parse_repository(
                    repo_path=args.repo,
                    output_dir=output_dir,
                    # Honour an explicit single-language selection. `-l` is
                    # mutually exclusive with --languages, so args.language is
                    # ALWAYS "auto" here — using it silently re-detected the
                    # dominant language and parsed something the user did not
                    # ask for, while reporting success.
                    language=(
                        selection.selected[0] if selection and selection.selected
                        else (args.language or "auto")
                    ),
                    processing_level=args.level,
                    skip_tests=not args.no_skip_tests,
                    name=getattr(args, "name", None),
                    diff_manifest=getattr(args, "diff_manifest", None),
                    fresh=getattr(args, "fresh", False),
                    library_mode=getattr(args, "library_mode", False),
                )

            # Attach exclusions on BOTH branches. The multi-language branch
            # sets them when constructing its ParseResult; the single-language
            # branch gets them here, because parse_repository knows nothing
            # about selection policy.
            if selection is not None and not result.excluded_languages:
                result.excluded_languages = dict(selection.excluded)

            ctx.summary = {
                "total_units": result.units_count,
                "language": result.language,
                "processing_level": result.processing_level,
                "excluded_languages": result.excluded_languages,
            }
            # Surface diff stats in the parse step report if present.
            diff_report = os.path.join(output_dir, "diff_filter.report.json")
            if os.path.exists(diff_report):
                try:
                    ctx.summary["diff_stats"] = read_json(diff_report)
                except (json.JSONDecodeError, OSError):
                    pass
            ctx.outputs = {
                "dataset_path": result.dataset_path,
                "analyzer_output_path": result.analyzer_output_path,
            }

        _output_json(success(result.to_dict()))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2


def cmd_generate_context(args):
    """Generate application security context for a repository."""
    from pathlib import Path
    from context.application_context import (
        generate_application_context,
        save_context,
        format_context_for_prompt,
    )
    from core.schemas import success, error
    from core.step_report import step_context
    from utilities.llm import (
        build_phase_registry,
        load_config_file,
        probe_registry_or_raise,
        resolve_llm_config,
    )

    # Default output to the CWD, NOT the scanned repo root: writing the context
    # into the checkout would let a later scan silently auto-load it as
    # finding-suppression config. Suppression must be an explicit operator act.
    output_path = args.output or os.path.join(os.getcwd(), "application_context.json")
    output_dir = os.path.dirname(os.path.abspath(output_path))

    try:
        with step_context("generate-context", output_dir, inputs={
            "repo_path": os.path.abspath(args.repo),
            "force": args.force,
        }) as ctx:
            # generate_application_context requires a PhaseBinding for the
            # app_context phase (model + adapter live in the binding, not
            # caller-side). Same registry idiom as the threat-model command.
            cf = load_config_file()
            registry = build_phase_registry(
                cf, resolve_llm_config(cf, getattr(args, "llm_config", None))
            )
            probe_registry_or_raise(registry)
            app_context = generate_application_context(
                Path(args.repo),
                registry.get("app_context"),
                force_regenerate=args.force,
            )
            # generate_application_context returns None when the LLM yields an
            # incomplete context; surface a clear message instead of letting
            # save_context(None) raise an opaque asdict() error.
            if app_context is None:
                _output_json(error("Could not generate application context (LLM returned an incomplete result)."))
                return 2
            save_context(app_context, Path(output_path))

            ctx.summary = {
                "application_type": app_context.application_type,
                "confidence": app_context.confidence,
                "source": app_context.source,
            }
            ctx.outputs = {"app_context_path": os.path.abspath(output_path)}

        result = {
            "app_context_path": os.path.abspath(output_path),
            "application_type": app_context.application_type,
            "purpose": app_context.purpose,
            "confidence": app_context.confidence,
            "source": app_context.source,
        }

        if args.show_prompt:
            result["prompt_format"] = format_context_for_prompt(app_context)

        _output_json(success(result))
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
                llm_config_name=args.llm_config,
                workers=args.workers,
                backoff_seconds=args.backoff,
                limit=args.limit,
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

    # Application context is used ONLY when the operator passes it explicitly.
    # Auto-discovering it from the scanned repo (or stale output dirs) would let
    # repo-supplied config silently suppress findings — an explicit act only.
    app_context_path = args.app_context

    try:
        with step_context("analyze", output_dir, inputs={
            "dataset_path": os.path.abspath(args.dataset),
            "llm_config": args.llm_config,
            "exploitable_filter": exploitable_filter,
            "limit": args.limit,
        }) as ctx:
            result = run_analysis(
                dataset_path=args.dataset,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=app_context_path,
                repo_path=args.repo_path,
                limit=args.limit,
                llm_config_name=args.llm_config,
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
                        app_context_path=app_context_path,
                        repo_path=args.repo_path,
                        workers=args.workers,
                        backoff_seconds=args.backoff,
                        # Propagate --llm-config so the chained verify stage
                        # uses the same configured model as analyze, not the default.
                        llm_config_name=args.llm_config,
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

    # Application context is used ONLY when the operator passes it explicitly
    # (see the analyze command for the rationale — no silent auto-discovery).
    app_context_path = args.app_context

    try:
        with step_context("verify", output_dir, inputs={
            "results_path": os.path.abspath(args.results),
            "analyzer_output_path": os.path.abspath(args.analyzer_output),
            "app_context_path": os.path.abspath(app_context_path) if app_context_path else None,
            "repo_path": os.path.abspath(args.repo_path) if args.repo_path else None,
        }) as ctx:
            result = run_verification(
                results_path=args.results,
                output_dir=output_dir,
                analyzer_output_path=args.analyzer_output,
                app_context_path=app_context_path,
                repo_path=args.repo_path,
                workers=args.workers,
                checkpoint_path=getattr(args, "checkpoint", None),
                backoff_seconds=args.backoff,
                llm_config_name=args.llm_config,
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
                repo_path=getattr(args, "repo_path", None),
                llm_config_name=args.llm_config,
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
            if not sys.stdin.isatty():
                # Non-interactive (Go CLI pipes stdin) — continue silently.
                answer = "y"
            else:
                sys.stderr.write("[Y/n] ")
                sys.stderr.flush()
                try:
                    answer = sys.stdin.readline().strip().lower()
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
                result = generate_summary_report(
                    pipeline_output_path, output_path,
                    llm_config_name=args.llm_config,
                )
            elif fmt == "disclosure":
                result = generate_disclosure_docs(
                    pipeline_output_path, output_path,
                    llm_config_name=args.llm_config,
                )
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
    from core.schemas import success, error
    from core.step_report import step_context
    from utilities.llm_client import get_global_tracker
    from utilities.llm import (
        build_phase_registry,
        load_config_file,
        resolve_llm_config,
        simple_text,
    )

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
            experiment = read_json(results_path)
            # fa17 TRUST BOUNDARY: normalize model-supplied `results` to dicts-only
            # once at load. This also fixes the total_units stat below —
            # `len(experiment.get("results", []))` now counts the filtered list
            # (matching len(findings)) instead of the raw, poisoned array.
            normalize_results(experiment)
            dataset = read_json(dataset_path)

            # --- Load dynamic test results if available ---
            # Dynamic tests use VULN-XXX IDs from pipeline_output.json,
            # but report-data works with route_keys from results_verified.json.
            # Bridge by reconstructing route_key = location.file + ":" + location.function
            # (location.function is the bare name; file+":"+function == route_key, D3b).
            dt_by_route_key = {}
            dt_path = os.path.join(results_dir, "dynamic_test_results.json")
            po_path = os.path.join(results_dir, "pipeline_output.json")
            if os.path.exists(dt_path) and os.path.exists(po_path):
                dt_data = read_json(dt_path)
                # fa17 TRUST BOUNDARY: dynamic_test_results.json is a separate
                # model-supplied schema; normalize its `results` to dicts-only so
                # the `for dr in dt_data.get("results", [])` loop below is safe.
                normalize_results(dt_data)
                po_data = read_json(po_path)
                # fa18 TRUST BOUNDARY: normalize model `findings` from
                # pipeline_output.json to dicts-only at load (presence-guarded)
                # so the `finding.get("id")` mapping loop below is safe.
                if "findings" in po_data:
                    normalize_results(po_data, "findings")

                # Map VULN-ID → route_key from pipeline_output
                vuln_id_to_route = {}
                for finding in po_data.get("findings", []):
                    fid = finding.get("id")
                    loc = finding.get("location", {})
                    route = (
                        f"{loc.get('file', '')}:{loc.get('function', '')}"
                        if loc.get("file") else loc.get("function", "")
                    )
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

            verdict_order = list(FINDING_VERDICT_ORDER)
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

            # FAM-ROBUST (fa16): `results` is model-supplied; a non-Anthropic
            # model can emit a bare string/number where a result dict is
            # expected. Drop non-dict elements at loop entry so every `.get()`
            # below is safe (mirrors the fa15 guard in core/reporter.py).
            for result in [r for r in experiment.get("results", []) if isinstance(r, dict)]:
                route_key = result.get("route_key", "")
                # Fall back to the raw ``verdict`` field when ``finding`` is
                # absent, else finding-less vulnerable results are dropped from
                # the count. Mirrors the canonical read in reporter.py.
                verdict = str(result.get("finding") or result.get("verdict", "")).lower()
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
                # attack_vector and analysis are untrusted Stage-1/2 LLM output.
                # Interpolated raw they could inject prompt instructions (or a
                # fake `### Finding` header) into the remediation prompt. Fence
                # each with a length-adaptive run so it stays inert data. (The
                # remediation_html sink is also an XSS vector — HTML-escaping at
                # the sink is a separate, deferred hardening; this closes the
                # prompt-injection half.)
                from prompts._fence import safe_code_fence, collapse_inline
                findings_text = ""
                for f in actionable:
                    _av = f['attack_vector'] or 'Not specified'
                    _an = f['analysis'][:500]
                    _avf = safe_code_fence(_av)
                    _anf = safe_code_fence(_an)
                    # file/function derive from the (poisonable) route_key; collapse
                    # newlines so they can't forge a `### Finding` header line.
                    _file = collapse_inline(f['file'])
                    _func = collapse_inline(f['function'])
                    findings_text += f"""
### Finding #{f['number']}: {_file}:{_func}
- **Verdict**: {f['verdict']}
- **Attack Vector**:
{_avf}
{_av}
{_avf}
- **Analysis**:
{_anf}
{_an}
{_anf}
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
                # The remediation-guidance call rides the report phase
                # so a single ``--llm-config`` flips it together with
                # the summary/disclosure generation in report/generator.py.
                cf = load_config_file()
                registry = build_phase_registry(
                    cf, resolve_llm_config(cf, getattr(args, "llm_config", None))
                )
                tracker = get_global_tracker()
                remediation_html = simple_text(
                    registry.get("report"),
                    prompt,
                    max_tokens=4096,
                    tracker=tracker,
                )

                # Post-process: linkify finding references like #4, #12-#14
                import re
                def _linkify_finding(m):
                    num = m.group(1)
                    return f'<a href="#finding-{num}" class="finding-ref">#{num}</a>'
                remediation_html = re.sub(r'#(\d+)', _linkify_finding, remediation_html)

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
            diff_block = None
            if os.path.exists(po_path):
                try:
                    po = read_json(po_path)
                    repo_info = po.get("repository", {})
                    repo_name = repo_info.get("name", "")
                    commit_sha = repo_info.get("commit_sha", "")
                    language = repo_info.get("language", "")
                    repo_url = repo_info.get("url", "")
                    # Pass through the diff block when this scan ran in
                    # incremental mode; the Go renderer surfaces base..head
                    # in the report header.
                    raw_diff = po.get("diff")
                    if isinstance(raw_diff, dict) and raw_diff.get("mode") == "incremental":
                        diff_block = {
                            "mode": raw_diff.get("mode"),
                            "base_sha": raw_diff.get("base_sha", ""),
                            "head_sha": raw_diff.get("head_sha", ""),
                            "scope": raw_diff.get("scope", ""),
                            "units_in_diff": raw_diff.get("units_in_diff", 0) or 0,
                            "units_total_parsed": raw_diff.get("units_total_parsed", 0) or 0,
                            "changed_files": raw_diff.get("changed_files", 0) or 0,
                            "pr_number": raw_diff.get("pr_number") or 0,
                        }
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
                "diff": diff_block,
            }

            ctx.summary = {"findings": len(findings), "actionable": len(actionable)}

        _output_json(success(report_data))
        return 0

    except Exception as e:
        _output_json(error(str(e)))
        return 2



def resolve_language_selection(args, counts: dict[str, int]):
    """Turn parsed CLI flags into a :class:`LanguageSelection`.

    Kept as a standalone function so the flag semantics are testable without
    running a scan, and so `scan` and `parse` cannot drift apart.

    `-l auto` (the default) means every detected language above the size
    threshold — not the dominant one (see ``_select_languages_for``). ``-l <lang>``
    narrows to a single language, ``--languages`` to a named subset, and
    ``--all-languages`` scans everything detected regardless of the threshold.

    Raises:
        ValueError: If an explicit `-l <lang>` is combined with a multi-language
            flag — one names a single language, the other names a set, and
            silently preferring either would surprise someone.
    """
    explicit = getattr(args, "language", "auto") not in (None, "auto")
    # `multi_language` was missing here while `_select_languages_for` did treat it
    # as a trigger, so `-l go --multi-language` silently dropped the multi flag and
    # then blamed the exclusion on `--languages`, which the user never passed.
    multi = (getattr(args, "languages", None)
             or getattr(args, "all_languages", False)
             or getattr(args, "multi_language", False))

    if explicit and multi:
        raise ValueError(
            "-l/--language is mutually exclusive with --languages/--all-languages/"
            f"--multi-language: got -l {args.language} alongside a multi-language "
            "flag. Use one or the other."
        )

    if explicit:
        include = [args.language]
    elif getattr(args, "languages", None):
        include = [p.strip() for p in args.languages.split(",") if p.strip()]
    else:
        include = None

    selection = select_languages(
        counts,
        include=include,
        all_languages=getattr(args, "all_languages", False),
        min_files=getattr(args, "min_language_files", DEFAULT_MIN_FILES),
        min_share=getattr(args, "min_language_share", DEFAULT_MIN_SHARE),
    )
    # Report here rather than at each call site: this is the single point every
    # command funnels through, so a coverage gap cannot escape by way of a
    # caller that forgot to print it.
    report_exclusions(selection.excluded)
    return selection



def cmd_threat_model(args):
    """Generate or validate a repository's OPENANT.THREATMODEL.md."""
    from pathlib import Path

    from context.threat_model import (
        THREAT_MODEL_FILENAME,
        ThreatModelValidationError,
        load_threat_model,
    )
    from core.schemas import error, success

    repo = Path(args.repo)

    if args.validate_only:
        # CI-friendly: parse and validate a committed model, spend nothing.
        target = repo / THREAT_MODEL_FILENAME
        if not target.exists():
            _output_json(error(f"{THREAT_MODEL_FILENAME} not found in {repo}"))
            return 2
        try:
            context = load_threat_model(repo)
        except ThreatModelValidationError as exc:
            _output_json(error(str(exc)))
            return 2
        _output_json(success({
            "path": str(target),
            "application_type": context.application_type,
            "attacker_profiles": len(context.attacker_profiles or []),
            "valid": True,
        }))
        return 0

    from context.threat_model_agent import (
        ThreatModelGenerationError,
        generate_threat_model,
    )
    from utilities.llm import (
        build_phase_registry,
        load_config_file,
        probe_registry_or_raise,
        resolve_llm_config,
    )

    try:
        config = load_config_file()
        registry = build_phase_registry(
            config, resolve_llm_config(config, args.llm_config))
        probe_registry_or_raise(registry)
        # Reuses the app_context phase — adding a phase would break every
        # existing user config (see context/threat_model_agent.py).
        path = generate_threat_model(
            repo,
            registry.get("app_context"),
            force=args.force,
            output_path=Path(args.output_md) if args.output_md else None,
        )
    except ThreatModelGenerationError as exc:
        _output_json(error(str(exc)))
        return 2
    except Exception as exc:  # noqa: BLE001 - surface any provider error cleanly
        _output_json(error(str(exc)))
        return 2

    _output_json(success({"path": str(path)}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the full CLI parser.

    Split out of ``main()`` so tests can introspect the parser — in
    particular to assert that ``--language`` choices stay in lock-step with
    ``config/languages.json`` rather than drifting as hardcoded literals.
    """
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
        choices=["auto", *supported_languages()],
        default="auto",
        help="Language (default: auto-detect)",
    )
    scan_p.add_argument(
        "--languages",
        default=None,
        help=(
            "Comma-separated languages to parse, e.g. 'python,go'. Bypasses the "
            "detection thresholds. Mutually exclusive with an explicit -l <lang>."
        ),
    )
    scan_p.add_argument(
        "--all-languages",
        action="store_true",
        help="Parse every detected language, ignoring the size thresholds.",
    )
    scan_p.add_argument(
        "--multi-language",
        action="store_true",
        help=(
            "Scan every detected language that clears the size thresholds. "
            "Excluded languages are reported as an explicit coverage gap."
        ),
    )
    scan_p.add_argument(
        "--min-language-files",
        type=int,
        default=DEFAULT_MIN_FILES,
        help=f"Minimum source files for a language to be scanned (default: {DEFAULT_MIN_FILES}).",
    )
    scan_p.add_argument(
        "--min-language-share",
        type=float,
        default=DEFAULT_MIN_SHARE,
        help=f"Minimum share of source files for a language (default: {DEFAULT_MIN_SHARE}).",
    )
    scan_p.add_argument(
        "--strict-languages",
        action="store_true",
        help="Abort the run if any selected language fails to parse (default: continue degraded).",
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
    scan_p.add_argument("--library-mode", action="store_true",
                        help="Seed the exported public API as entry points (for libraries with no main/route/CLI entry point)")
    scan_p.add_argument("--limit", type=int, help="Max units to analyze")
    scan_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config in ~/.config/openant/config.json. "
            "Defaults to the file's default_llm (or the built-in "
            "`openant-default` when no config file exists). See "
            "docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md."
        ),
    )
    scan_p.add_argument("--workers", type=int, default=8,
                        help="Number of parallel workers for LLM steps (default: 8)")
    scan_p.add_argument("--repo-name", help="Repository name (org/repo)")
    scan_p.add_argument("--repo-url", help="Repository URL")
    scan_p.add_argument("--commit-sha", help="Commit SHA")
    scan_p.add_argument("--backoff", type=int, default=30,
                        help="Seconds to wait when rate-limited (default: 30)")
    scan_p.add_argument("--diff-manifest", help="Path to diff_manifest.json for incremental scanning")
    scan_p.add_argument(
        "--llm-reachability",
        action="store_true",
        dest="llm_reachability",
        help="Enable the LLM reachability review stage (Opus). "
             "Surfaces entry points and external-input sites the structural "
             "pass would miss by reviewing the full codebase before the "
             "reachability filter is applied. Off by default — enabling "
             "this incurs cost proportional to total repo size, not the "
             "filtered unit count (~one Opus call per 25 units across the "
             "whole codebase).",
    )
    scan_p.add_argument(
        "--llm-reachability-max-code-bytes",
        type=int,
        default=1500,
        dest="llm_reachability_max_code_bytes",
        help="Max code bytes per unit sent to the LLM reachability stage "
             "(default: 1500). Higher values (e.g. 4096, 8192) catch "
             "entry-point indicators past byte 1500 in long handlers / "
             "generated code, at proportional Opus cost increase. Only "
             "meaningful with --llm-reachability.",
    )
    scan_p.set_defaults(func=cmd_scan)

    # ---------------------------------------------------------------
    # parse — repository parsing only
    # ---------------------------------------------------------------
    parse_p = subparsers.add_parser("parse", help="Parse a repository into a dataset")
    parse_p.add_argument("repo", help="Path to repository")
    parse_p.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    parse_p.add_argument(
        "--language", "-l",
        choices=["auto", *supported_languages()],
        default="auto",
        help="Language (default: auto-detect)",
    )
    parse_p.add_argument(
        "--languages",
        default=None,
        help=(
            "Comma-separated languages to parse, e.g. 'python,go'. Bypasses the "
            "detection thresholds. Mutually exclusive with an explicit -l <lang>."
        ),
    )
    parse_p.add_argument(
        "--all-languages",
        action="store_true",
        help="Parse every detected language, ignoring the size thresholds.",
    )
    parse_p.add_argument(
        "--multi-language",
        action="store_true",
        help=(
            "Scan every detected language that clears the size thresholds. "
            "Excluded languages are reported as an explicit coverage gap."
        ),
    )
    parse_p.add_argument(
        "--min-language-files",
        type=int,
        default=DEFAULT_MIN_FILES,
        help=f"Minimum source files for a language to be scanned (default: {DEFAULT_MIN_FILES}).",
    )
    parse_p.add_argument(
        "--min-language-share",
        type=float,
        default=DEFAULT_MIN_SHARE,
        help=f"Minimum share of source files for a language (default: {DEFAULT_MIN_SHARE}).",
    )
    parse_p.add_argument(
        "--strict-languages",
        action="store_true",
        help="Abort the run if any selected language fails to parse (default: continue degraded).",
    )
    parse_p.add_argument(
        "--level",
        choices=["all", "reachable", "codeql", "exploitable"],
        default="reachable",
        help="Processing level (default: reachable)",
    )
    parse_p.add_argument("--no-skip-tests", action="store_true", help="Include test files in parsing (default: tests are skipped)")
    parse_p.add_argument("--library-mode", action="store_true",
                         help="Seed the exported public API as entry points (for libraries with no main/route/CLI entry point)")
    parse_p.add_argument("--name", help="Dataset name (default: derived from repo path)")
    parse_p.add_argument("--diff-manifest", help="Path to diff_manifest.json; tags units with diff_selected")
    parse_p.add_argument("--fresh", action="store_true",
                         help="Delete existing dataset.json and reparse from scratch (default: reuse existing units; other artifacts preserved)")
    parse_p.set_defaults(func=cmd_parse)

    # ---------------------------------------------------------------
    # generate-context — generate application security context
    # ---------------------------------------------------------------
    gc_p = subparsers.add_parser(
        "generate-context",
        help="Generate application security context for a repository",
    )
    gc_p.add_argument("repo", help="Path to repository")
    gc_p.add_argument("--output", "-o",
                       help="Output path (default: ./application_context.json in the "
                            "current directory — never written into the scanned repo)")
    gc_p.add_argument("--force", action="store_true",
                       help="Force regeneration, ignoring OPENANT.md override files")
    gc_p.add_argument("--show-prompt", action="store_true",
                       help="Include formatted prompt text in output")
    gc_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config in ~/.config/openant/config.json. "
            "Defaults to the file's default_llm."
        ),
    )
    gc_p.set_defaults(func=cmd_generate_context)

    # ---------------------------------------------------------------
    # enhance — add security context to a dataset
    # ---------------------------------------------------------------
    enhance_p = subparsers.add_parser("enhance", help="Enhance a dataset with security context")
    enhance_p.add_argument("dataset", help="Path to dataset JSON from parse step")
    enhance_p.add_argument("--analyzer-output", help="Path to analyzer_output.json (required for agentic mode)")
    enhance_p.add_argument("--repo-path", help="Path to the repository (required for agentic mode)")
    enhance_p.add_argument("--output", "-o", help="Output path for enhanced dataset (default: {input}_enhanced.json)")
    enhance_p.add_argument("--checkpoint", help="Path to save/resume checkpoint (agentic mode)")
    enhance_p.add_argument("--limit", type=int, help="Max units to enhance")
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
    enhance_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config in ~/.config/openant/config.json. "
            "Defaults to the file's default_llm (or the built-in "
            "`openant-default` when no config file exists)."
        ),
    )
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
    analyze_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config in ~/.config/openant/config.json. "
            "Defaults to the file's default_llm (or the built-in "
            "`openant-default` when no config file exists)."
        ),
    )
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
    verify_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config in ~/.config/openant/config.json. "
            "Defaults to the file's default_llm (or the built-in "
            "`openant-default` when no config file exists)."
        ),
    )
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
    dt_p.add_argument("--repo-path", help="Path to the repository root (for pre-staging source files into Docker build context)")
    dt_p.add_argument("--max-retries", type=int, default=3,
                      help="Max retries per finding on error (default: 3)")
    dt_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config in ~/.config/openant/config.json. "
            "Defaults to the file's default_llm (or the built-in "
            "`openant-default` when no config file exists)."
        ),
    )
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
    report_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config in ~/.config/openant/config.json. "
            "Defaults to the file's default_llm (or the built-in "
            "`openant-default` when no config file exists). Used by "
            "the summary and disclosure formats; ignored for csv/html."
        ),
    )
    report_p.set_defaults(func=cmd_report)

    # ---------------------------------------------------------------
    # report-data — internal: prepare pre-computed report data as JSON
    # ---------------------------------------------------------------
    rd_p = subparsers.add_parser("report-data", help="(internal) Prepare report data for Go renderer")
    rd_p.add_argument("results", help="Path to results/experiment JSON")
    rd_p.add_argument("--dataset", required=True, help="Path to dataset JSON")
    rd_p.add_argument(
        "--llm-config",
        default=None,
        help=(
            "Name of the llm-config in ~/.config/openant/config.json. "
            "Defaults to the file's default_llm (or the built-in "
            "`openant-default` when no config file exists). Used by the "
            "HTML-report remediation guidance, which rides the report phase."
        ),
    )
    rd_p.set_defaults(func=cmd_report_data)

    # ---------------------------------------------------------------
    # checkpoint-status — internal: report checkpoint status for Go CLI
    # ---------------------------------------------------------------
    cs_p = subparsers.add_parser("checkpoint-status",
        help="(internal) Report checkpoint status for a directory")
    cs_p.add_argument("checkpoint_dir", help="Path to checkpoint directory")
    # ---------------------------------------------------------------
    # threat-model — generate or validate OPENANT.THREATMODEL.md
    # ---------------------------------------------------------------
    tm_p = subparsers.add_parser(
        "threat-model",
        help="Generate or validate a repository's OPENANT.THREATMODEL.md",
    )
    tm_p.add_argument("repo", help="Path to repository")
    tm_p.add_argument(
        "--force", action="store_true",
        help="Regenerate even if a threat model exists (backs it up first)",
    )
    tm_p.add_argument(
        "--validate-only", action="store_true",
        help="Validate an existing threat model and exit. Makes no LLM call.",
    )
    tm_p.add_argument("--output-md", help="Write here instead of the repo root")
    tm_p.add_argument(
        "--llm-config", default=None,
        help="Name of the llm-config in ~/.config/openant/config.json",
    )
    tm_p.set_defaults(func=cmd_threat_model)

    cs_p.set_defaults(func=cmd_checkpoint_status)

    return parser


def main():
    args = build_parser().parse_args()
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
