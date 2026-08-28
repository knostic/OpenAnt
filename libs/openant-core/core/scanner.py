"""
All-in-one scanner orchestrator.

Runs the full pipeline:

    Parse → App Context → Enhance → Detect → Verify
        → Build pipeline_output → Dynamic Test → Report

This is the implementation behind ``open-ant scan <path>``.

Each step:
 1. Writes its own ``{step}.report.json`` via ``step_context``.
 2. Can be individually skipped with ``--no-{step}`` flags.
 3. Feeds its outputs into the next step.

On completion, a final ``scan.report.json`` aggregates all step reports.
"""

import json
import os
import shutil
import sys
from pathlib import Path

from core.schemas import (
    ScanResult, AnalysisMetrics, UsageInfo, StepReport,
)
from core.step_report import step_context
from core import tracking
from utilities.file_io import read_json, write_json
from utilities.llm.adapter import LLMAuthError

# Import app context generator (optional)
try:
    from context.application_context import (
        generate_application_context,
        save_context,
    )
    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False



def resolve_call_graph_dirs(output_dir: str) -> dict[str | None, str]:
    """Directories holding a usable ``call_graph.json``, keyed by language.

    Multi-language runs write one per language under ``<run>/<lang>/`` and
    record them in ``call_graphs.json``; single-language runs keep the legacy
    flat layout. Both are resolved here so the re-filter does not need to know
    which shape it is looking at.

    Entries are validated against the filesystem rather than trusted from the
    index — a stale index would otherwise point the filter at a graph that no
    longer exists.

    Returns:
        ``{language: dir}``, or ``{None: run_dir}`` for the legacy layout, or
        ``{}`` when no call graph exists anywhere.
    """
    index_path = os.path.join(output_dir, "call_graphs.json")
    if os.path.exists(index_path):
        try:
            index = read_json(index_path)
        except (json.JSONDecodeError, OSError):
            index = {}
        dirs: dict[str | None, str] = {}
        for language, rel in (index or {}).items():
            candidate = os.path.join(output_dir, rel)
            if os.path.isfile(candidate):
                dirs[language] = os.path.dirname(candidate)
        return dirs

    if os.path.isfile(os.path.join(output_dir, "call_graph.json")):
        return {None: output_dir}
    return {}



def scope_entry_points_to_units(entry_point_ids, units: list[dict]) -> set:
    """Restrict promoted entry-point ids to those present in *units*.

    ``apply_reachability_filter`` unions ``extra_entry_points`` into its seed
    set BEFORE evaluating the empty-seed safety net. Passing the whole run's
    promoted ids to a single language's filter therefore hands it seeds that do
    not exist in that language's call graph: the seed set is non-empty, so the
    "no entry points — pass everything through rather than black out" guard
    never fires, BFS reaches nothing, and every unit of that language is
    dropped from the scan while it still reports success.

    Scoping per partition restores the guard: a language with no promoted units
    of its own gets an EMPTY seed set, which is exactly the condition the
    safety net is written to detect.
    """
    if not entry_point_ids:
        return set()
    unit_ids = {u.get("id") for u in units if u.get("id")}
    return {eid for eid in entry_point_ids if eid in unit_ids}


def partition_units_by_language(units: list[dict]) -> dict[str | None, list[dict]]:
    """Group units by their ``language`` stamp.

    Units from a legacy single-language dataset carry no stamp and group under
    ``None``. The partition is lossless: every input unit lands in exactly one
    bucket, so re-filtering per language cannot silently drop units.
    """
    parts: dict[str | None, list[dict]] = {}
    for unit in units:
        parts.setdefault(unit.get("language"), []).append(unit)
    return parts


def scan_repository(
    repo_path: str,
    output_dir: str,
    language: str = "auto",
    languages: list[str] | None = None,
    excluded_languages: dict[str, str] | None = None,
    strict_languages: bool = False,
    processing_level: str = "reachable",
    verify: bool = False,
    generate_context: bool = True,
    generate_report: bool = True,
    skip_tests: bool = True,
    limit: int | None = None,
    llm_config_name: str | None = None,
    enhance: bool = True,
    enhance_mode: str = "agentic",
    dynamic_test: bool = False,
    workers: int = 8,
    backoff_seconds: int = 30,
    repo_name: str | None = None,
    repo_url: str | None = None,
    commit_sha: str | None = None,
    diff_manifest: str | None = None,
    llm_reachability: bool = False,
    llm_reachability_max_code_bytes: int = 1500,
    library_mode: bool = False,
) -> ScanResult:
    """Scan a repository for vulnerabilities.

    Orchestrates the full OpenAnt pipeline:

    1. **Parse** repository into a dataset
    2. **App Context** — generate application context (optional)
    3. **Enhance** — add security context via agentic/single-shot LLM (optional)
    4. **Detect** — Stage 1 vulnerability detection
    5. **Verify** — Stage 2 attacker simulation (optional)
    6. **Build pipeline_output.json** — bridge format for reports + dynamic tests
    7. **Dynamic Test** — Docker-isolated exploit testing (optional, off by default)
    8. **Report** — summary + disclosure documents (optional, merges dynamic test results)

    Args:
        repo_path: Path to the repository to scan.
        output_dir: Directory for all output files.
        language: ``"auto"``, ``"python"``, ``"javascript"``, ``"go"``, or ``"c"``.
        languages: Optional explicit list of languages to parse. With more than
            one entry the parse fans out per language into ``<output_dir>/<lang>/``
            and the datasets are merged; every later stage still runs ONCE over
            the merged dataset. Omitted or single-element means the unchanged
            single-language path.
        strict_languages: If True, abort when any selected language fails to
            parse instead of continuing with the survivors.
        processing_level: ``"all"``, ``"reachable"``, ``"codeql"``, or ``"exploitable"``.
        verify: If True, run Stage 2 attacker simulation after detection.
        generate_context: If True, generate application context (reduces FP).
        generate_report: If True, generate summary + disclosure reports.
        skip_tests: If True, exclude test files from parsing (default: True).
        limit: Max number of units to analyze and enhance (the LLM
            reachability pass still reviews the full codebase).
        enhance: If True, run agentic/single-shot context enhancement.
        enhance_mode: ``"agentic"`` (thorough) or ``"single-shot"`` (fast).
        dynamic_test: If True, run Docker-isolated dynamic testing (requires Docker).
        workers: Number of parallel workers for LLM steps (default: 8).
        backoff_seconds: Seconds to wait when rate-limited (default: 30).

    Returns:
        ScanResult with paths to all generated files and metrics.
    """
    repo_path = os.path.abspath(repo_path)
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    # Reset tracking
    tracking.reset_tracking()

    # Build the registry once at scan start. Sub-steps reuse it, so
    # a single --llm-config controls every phase without each step
    # re-reading the config file or having to thread the name through.
    # ``probe_registry_or_raise`` runs a 1-token probe per unique
    # (provider, model) pair before any expensive work begins, so bad
    # keys / typo'd model IDs / unreachable endpoints surface here as
    # a clean LLMError rather than mid-scan.
    from utilities.llm import (
        build_phase_registry,
        load_config_file,
        probe_registry_or_raise,
        resolve_llm_config,
    )
    cf = load_config_file()
    registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
    print(f"[Scan] LLM config: {registry.config_name}", file=sys.stderr)
    probe_registry_or_raise(registry)

    result = ScanResult(output_dir=output_dir)
    collected_step_reports: list[dict] = []

    # Count total steps for progress display
    total_steps = _count_steps(
        generate_context, enhance, verify, generate_report, dynamic_test,
        llm_reachability=llm_reachability,
    )
    step_num = 0

    def _step_label(name: str) -> str:
        nonlocal step_num
        # #219: a "Skipping ..." notice is not a performed step; the denominator
        # (_count_steps) counts only steps that RUN, so numbering skips too
        # pushed the numerator past the total (e.g. the report step printed as
        # [8/7]). Render skips without a step number.
        if name.startswith("Skipping"):
            return f"  - {name}"
        step_num += 1
        return f"[{step_num}/{total_steps}] {name}"

    _print_banner(repo_path, output_dir, language, processing_level,
                  verify, generate_context, enhance, enhance_mode,
                  generate_report, dynamic_test, workers, backoff_seconds)

    # ---------------------------------------------------------------
    # Step 1: Parse
    # ---------------------------------------------------------------
    from core.parser_adapter import parse_repository
    from core.schemas import ParseResult

    # When LLM reachability is enabled the stage must see ALL units so it can
    # identify entry points the structural pass would miss.  Parse with "all"
    # here; the structural filter is re-applied after LLM signals are merged.
    effective_parse_level = (
        "all" if (llm_reachability and processing_level != "all") else processing_level
    )

    print(_step_label("Parsing repository..."), file=sys.stderr)
    if effective_parse_level != processing_level:
        print(
            "  [LLM reachability] parsing all units; structural filter runs after LLM signals",
            file=sys.stderr,
        )

    with step_context("parse", output_dir, inputs={
        "repo_path": repo_path,
        "language": language,
        "processing_level": effective_parse_level,
        "skip_tests": skip_tests,
    }) as ctx:
        if languages and len(languages) > 1:
            # Fan out per language, then merge into the single dataset every
            # later stage consumes. Post-parse stages are unchanged and still
            # run ONCE — the merge is what makes that possible.
            from core.dataset_merge import (
                merge_analyzer_outputs,
                merge_datasets,
                write_call_graph_index,
            )
            from core.parser_adapter import (
                _maybe_apply_diff_filter,
                parse_repository_multi,
            )

            outcomes = parse_repository_multi(
                repo_path=repo_path,
                run_dir=output_dir,
                languages=languages,
                processing_level=effective_parse_level,
                skip_tests=skip_tests,
                library_mode=library_mode,
                strict=strict_languages,
            )
            _dataset_path = os.path.join(output_dir, "dataset.json")
            _analyzer_path = os.path.join(output_dir, "analyzer_output.json")
            _merge_stats = merge_datasets(outcomes, _dataset_path)
            merge_analyzer_outputs(outcomes, _analyzer_path)
            write_call_graph_index(
                outcomes, os.path.join(output_dir, "call_graphs.json")
            )

            _failed = [o for o in outcomes if not o.ok]
            parse_result = ParseResult(
                dataset_path=_dataset_path,
                analyzer_output_path=(
                    _analyzer_path if os.path.exists(_analyzer_path) else None
                ),
                units_count=_merge_stats.total_units,
                # Scalar stays the PRIMARY language: it is serialized into JSON
                # the Go CLI unmarshals.
                language=_merge_stats.languages[0] if _merge_stats.languages else language,
                processing_level=effective_parse_level,
                languages=_merge_stats.languages,
                language_stats=_merge_stats.units_per_language,
                per_language={o.language: o.to_dict() for o in outcomes},
                parse_errors=[o.to_dict() for o in _failed],
            )
            # Applied once against the MERGED dataset, not per language.
            _maybe_apply_diff_filter(parse_result, output_dir, diff_manifest)
        else:
            parse_result = parse_repository(
                repo_path=repo_path,
                output_dir=output_dir,
                language=(languages[0] if languages else language),
                processing_level=effective_parse_level,
                skip_tests=skip_tests,
                diff_manifest=diff_manifest,
                library_mode=library_mode,
            )

        ctx.summary = {
            "total_units": parse_result.units_count,
            "language": parse_result.language,
            "processing_level": parse_result.processing_level,
        }
        # If the parse step generated a diff_stats report, attach it.
        _diff_report = os.path.join(output_dir, "diff_filter.report.json")
        if os.path.exists(_diff_report):
            try:
                ctx.summary["diff_stats"] = read_json(_diff_report)
            except (json.JSONDecodeError, OSError):
                pass
        ctx.outputs = {
            "dataset_path": parse_result.dataset_path,
            "analyzer_output_path": parse_result.analyzer_output_path,
        }

    result.dataset_path = parse_result.dataset_path
    result.analyzer_output_path = parse_result.analyzer_output_path
    result.units_count = parse_result.units_count
    result.language = parse_result.language
    # getattr with defaults: `parse_repository` is duck-typed by callers and
    # test stubs that predate these fields. Attribute access would turn a
    # missing optional field into an AttributeError mid-scan.
    result.languages = getattr(parse_result, "languages", []) or []
    result.language_stats = getattr(parse_result, "language_stats", {}) or {}
    result.per_language = getattr(parse_result, "per_language", {}) or {}
    result.parse_errors = getattr(parse_result, "parse_errors", []) or []
    result.excluded_languages = dict(excluded_languages or {})
    collected_step_reports.append(_load_step_report(output_dir, "parse"))

    print(f"  Parsed: {parse_result.units_count} units ({parse_result.language})",
          file=sys.stderr)
    print(file=sys.stderr)

    # Active dataset path — may be updated by enhance step
    active_dataset_path = parse_result.dataset_path

    # ---------------------------------------------------------------
    # Step 2: Application Context (optional)
    # ---------------------------------------------------------------
    app_context_path: str | None = None
    if generate_context and HAS_APP_CONTEXT:
        print(_step_label("Generating application context..."), file=sys.stderr)

        with step_context("app-context", output_dir, inputs={
            "repo_path": repo_path,
        }) as ctx:
            # A threat model committed to the scanned repo is authoritative and
            # short-circuits generation. Loaded OUTSIDE the try below on
            # purpose: a malformed one must abort the scan rather than degrade
            # into a default context, because silently applying the wrong
            # security model to every finding is worse than failing loudly.
            from context.threat_model import load_threat_model

            threat_model_ctx = load_threat_model(Path(repo_path))

            if threat_model_ctx is not None:
                app_context_path = os.path.join(output_dir, "application_context.json")
                save_context(threat_model_ctx, Path(app_context_path))
                result.app_context_path = app_context_path
                result.context_source = "threat_model"
                # R5: carry the file's provenance (sha over raw bytes) and the
                # previously discarded permissive-model warnings onto the result
                # so both land in scan.report.json / pipeline_output.json rather
                # than reaching only stderr (which CI discards).
                result.threat_model_sha256 = threat_model_ctx.source_sha256
                result.threat_model_warnings = list(
                    threat_model_ctx.permissive_warnings
                )
                ctx.summary = {
                    "application_type": threat_model_ctx.application_type,
                    "context_source": "threat_model",
                }
                ctx.outputs = {"app_context_path": app_context_path}
                print(
                    "  Using repo-supplied threat model: "
                    f"{threat_model_ctx.application_type}",
                    file=sys.stderr,
                )
            else:
                try:
                    context = generate_application_context(
                        Path(repo_path), registry.get("app_context")
                    )
                    app_context_path = os.path.join(
                        output_dir, "application_context.json"
                    )
                    save_context(context, Path(app_context_path))
                    result.app_context_path = app_context_path
                    result.context_source = "generated"
                    ctx.summary = {
                        "application_type": context.application_type,
                        "context_source": "generated",
                    }
                    ctx.outputs = {"app_context_path": app_context_path}
                    print(f"  App type: {context.application_type}", file=sys.stderr)
                except Exception as e:
                    print(f"  WARNING: App context generation failed: {e}",
                          file=sys.stderr)
                    print("  Continuing without app context.", file=sys.stderr)
                    ctx.status = "skipped"
                    ctx.summary = {"skipped": True, "reason": str(e)}
                    # Record the crash like the enhance/verify/dynamic-test
                    # handlers do — otherwise the degraded scan (default threat
                    # model) is absent from result.skipped_steps / scan.report.json
                    # / pipeline_output.json and the summary claims "No steps were
                    # skipped" (only the per-step report + stderr carried it).
                    _record_skip(result, "app-context", "failed")

        collected_step_reports.append(_load_step_report(output_dir, "app-context"))
    elif generate_context:
        print(_step_label("Skipping application context (module not available)."),
              file=sys.stderr)
        _record_skip(result, "app-context", "module_unavailable")
    else:
        print(_step_label("Skipping application context (--no-context)."),
              file=sys.stderr)
        # Skipping is a legitimate operator choice, but doing it silently while
        # the repo ships a threat model means the scan runs under a different
        # security model than the repository declares, invisibly.
        if (Path(repo_path) / "OPENANT.THREATMODEL.md").exists():
            print(
                "  NOTE: this repository ships an OPENANT.THREATMODEL.md, which "
                "--no-context discards. The scan will NOT use its attacker "
                "profiles or vulnerability criteria.",
                file=sys.stderr,
            )
        _record_skip(result, "app-context", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 2.5: LLM Reachability review (optional, opt-in)
    # ---------------------------------------------------------------
    # Runs after parse + app-context and before enhance/analyze. Because parse
    # was done with processing_level="all" (when filtering is requested), the
    # LLM sees every unit in the codebase and can identify entry points the
    # structural heuristics would miss.  After signals are applied the
    # structural reachability filter is re-run with LLM-promoted entry points
    # added as extra BFS seeds, so the final dataset honours the user's
    # requested processing_level.  Threading app_context into the prompt helps
    # the model reason about expected entry points (e.g. "this is a web_app,
    # look for HTTP handlers").
    if llm_reachability:
        from core.llm_reachability import (
            analyze_reachability,
            apply_signals,
            signals_to_json,
        )

        llm_reach_binding = registry.get("llm_reach")
        print(_step_label("Running LLM reachability review..."), file=sys.stderr)

        with step_context("llm-reachability", output_dir, inputs={
            "dataset_path": active_dataset_path,
            "model": llm_reach_binding.model,
            "provider": llm_reach_binding.provider_name,
        }) as ctx:
            try:
                dataset = read_json(active_dataset_path)
            except Exception as exc:
                # Broaden beyond (OSError, json.JSONDecodeError): read_json opens
                # strict UTF-8, so a bad-encoding dataset raises UnicodeDecodeError
                # (a ValueError). NOTE: this inner guard predates the whole-body
                # wrap below (#268) and stays for its precise skip reason; the
                # body wrap catches everything else (corrupt call_graph.json in
                # the re-filter, failed writes) and degrades the same way.
                print(f"  WARNING: failed to load dataset: {exc}", file=sys.stderr)
                ctx.status = "skipped"
                ctx.summary = {"skipped": True, "reason": str(exc)}
                # Record the crash so the degraded reachability pass (no
                # LLM-promoted entry points -> potential missed vulns) is
                # visible in the artifacts, not only on CI-discarded stderr.
                _record_skip(result, "llm-reachability", "failed")
                dataset = None

            # #268: guard the WHOLE stage body (the pattern enhance/verify
            # use), not just the dataset read — a non-LLM failure below
            # (corrupt call_graph.json in the re-filter at parser_adapter,
            # a failed write_json) previously aborted the whole scan via
            # step_context re-raise instead of degrading to a recorded skip.
            # Provider errors are NOT at issue: analyze_reachability already
            # skips failed batches, re-raising only LLMAuthError by design —
            # and that one MUST still abort (bad credentials must not be
            # silently skipped into a "successful" degraded scan).
            pre_llmreach_units_count = result.units_count
            try:
                if dataset is not None:
                    app_ctx_payload = None
                    if app_context_path and os.path.exists(app_context_path):
                        try:
                            app_ctx_payload = read_json(app_context_path)
                        except Exception as exc:
                            # Broad like the dataset load above: this optional
                            # app-context read must never abort the scan. read_json
                            # opens strict UTF-8, so a bad-encoding self-written file
                            # raises UnicodeDecodeError (not OSError/JSONDecodeError);
                            # a missing payload just means the reachability prompt
                            # runs without the extra app-context hint. Warn (like the
                            # dataset-load sibling) so this recall-affecting
                            # degradation is visible, not silent.
                            print(
                                f"  WARNING: could not read app context for "
                                f"reachability ({exc}); continuing without the "
                                f"app-context hint.",
                                file=sys.stderr,
                            )
                            app_ctx_payload = None

                    # --limit governs the analyze AND enhance stages, not how many units the
                    # LLM reachability pass reviews — it must see the full
                    # codebase to find missed entry points.
                    signals = analyze_reachability(
                        dataset=dataset,
                        app_context=app_ctx_payload,
                        binding=llm_reach_binding,
                        max_code_bytes=llm_reachability_max_code_bytes,
                    )
                    summary = apply_signals(dataset, signals)

                    signals_path = os.path.join(output_dir, "llm_reachability.json")
                    write_json(signals_path, {"signals": signals_to_json(signals)}, indent=2)

                    pre_filter_count = len(dataset.get("units", []))
                    post_filter_count = pre_filter_count
                    refilter_supported = False

                    # Re-apply the structural reachability filter using
                    # LLM-promoted entry points as additional BFS seeds.
                    # Only possible when the parser persisted call_graph.json.
                    # Which parsers do so is determined by PROBING THE FILESYSTEM
                    # below, not by a hardcoded language list — an earlier comment
                    # here claimed only Python and Zig persist it, which is wrong
                    # (JavaScript writes a fully-formed call_graph.json too). Keep
                    # this probe-based: parsers gain and lose the behaviour over
                    # time, and a stale list here would silently skip re-filtering
                    # for a language that actually supports it.
                    if processing_level != "all":
                        cg_dirs = resolve_call_graph_dirs(output_dir)
                        if cg_dirs:
                            from core.parser_adapter import apply_reachability_filter

                            llm_promoted_ids = {
                                u["id"] for u in dataset.get("units", [])
                                if u.get("is_entry_point") and u.get("id")
                            }
                            partitions = partition_units_by_language(
                                dataset.get("units", [])
                            )
                            kept: list[dict] = []
                            unfilterable: dict[str, int] = {}
                            # Per-language reachability_filter stats, aggregated back
                            # onto the rebuilt dataset below. Without this the rebuild
                            # at `dataset = {**dataset, "units": kept}` carried the
                            # ORIGINAL (pre-LLM) metadata, so the reporter rendered
                            # "reachability filtering not applied" on a scan that DID
                            # prune via the LLM-seeded re-filter.
                            refilter_by_language: dict[str, dict] = {}

                            for lang, lang_units in partitions.items():
                                lang_dir = cg_dirs.get(lang)
                                if lang_dir is None and None in cg_dirs:
                                    # Legacy flat layout: one graph covers everything.
                                    lang_dir = cg_dirs[None]
                                if lang_dir is None:
                                    # This language's parser persisted no call graph,
                                    # so its units pass through unfiltered — the
                                    # pre-existing behaviour, now scoped per language
                                    # instead of disabling the filter for the whole
                                    # scan just because the primary lacked a graph.
                                    unfilterable[lang or "unknown"] = len(lang_units)
                                    kept.extend(lang_units)
                                    continue

                                # Deep-copy metadata: the shallow {**dataset} copy
                                # shares the nested metadata dict across every
                                # per-language call, so each filter's stats
                                # overwrote the previous language's.
                                lang_dataset = {
                                    **dataset,
                                    "units": lang_units,
                                    "metadata": dict(dataset.get("metadata") or {}),
                                }
                                filtered = apply_reachability_filter(
                                    lang_dataset,
                                    lang_dir,
                                    processing_level,
                                    extra_entry_points=scope_entry_points_to_units(
                                        llm_promoted_ids, lang_units
                                    ),
                                    library_mode=library_mode,
                                )
                                kept.extend(filtered.get("units", []))
                                _rf = (filtered.get("metadata") or {}).get(
                                    "reachability_filter"
                                )
                                if _rf:
                                    refilter_by_language[lang or "unknown"] = _rf

                            # Rebuild the dataset, aggregating the per-language filter
                            # stats into metadata so the reporter reads a real record
                            # instead of the stale pre-LLM one. Unfilterable languages
                            # (no call graph) are folded in as pass-throughs so the
                            # aggregate reconciles with len(kept).
                            _new_md = dict(dataset.get("metadata") or {})
                            # Only stamp a record when a real per-language filter ran.
                            # If every language was unfilterable (no call graph), the
                            # units passed through untouched, so leaving no record —
                            # the honest "not applied" signal — is correct; a "0%
                            # reduction" record would falsely claim filtering happened.
                            if refilter_by_language:
                                _per_lang = dict(refilter_by_language)
                                _unfiltered = 0
                                for _lang, _cnt in unfilterable.items():
                                    _unfiltered += _cnt
                                    _per_lang[_lang] = {
                                        "original_units": _cnt,
                                        "entry_points": 0,
                                        "reachable_units": _cnt,
                                        "filtered_out": 0,
                                        "reduction_percentage": 0,
                                        "unfilterable": True,
                                    }
                                _orig = sum(
                                    r.get("original_units", 0) for r in _per_lang.values()
                                )
                                _reach = sum(
                                    r.get("reachable_units", 0) for r in _per_lang.values()
                                )
                                _agg = {
                                    "original_units": _orig,
                                    "entry_points": sum(
                                        r.get("entry_points", 0) for r in _per_lang.values()
                                    ),
                                    "reachable_units": _reach,
                                    "filtered_out": _orig - _reach,
                                    # Units that flowed through unfiltered (no call
                                    # graph for their language) — folded into the
                                    # totals above but surfaced explicitly so the
                                    # record never silently claims they were filtered.
                                    "unfiltered_units": _unfiltered,
                                    "reduction_percentage": (
                                        round((1 - _reach / _orig) * 100, 1)
                                        if _orig
                                        else 0
                                    ),
                                    "per_language": _per_lang,
                                }
                                # Lift any per-language advisory (e.g. an empty-seed
                                # blackout — a language that flowed through unfiltered
                                # because it had no real entry points) to the top
                                # level, where the reporter reads it (reporter.py:505).
                                # Without this the record reads "filter applied, N%
                                # reduction" while hiding that a language blacked out —
                                # the exact fidelity gap this record exists to close.
                                _warnings = [
                                    f"{_lang}: {_r['warning']}"
                                    for _lang, _r in _per_lang.items()
                                    if _r.get("warning")
                                ]
                                if _warnings:
                                    _agg["warning"] = "; ".join(_warnings)
                                _new_md["reachability_filter"] = _agg
                            else:
                                # No real filter ran (every language unfilterable):
                                # honour the "not applied" contract by clearing any
                                # record inherited from an upstream merge, so a stale
                                # record can never misdescribe the passed-through units.
                                _new_md.pop("reachability_filter", None)
                            dataset = {**dataset, "units": kept, "metadata": _new_md}
                            post_filter_count = len(kept)
                            result.units_count = post_filter_count
                            refilter_supported = True

                            for lang, count in unfilterable.items():
                                print(
                                    f"\n  WARNING: {lang} persisted no call_graph.json; "
                                    f"{count} unit(s) skip post-LLM re-filtering and "
                                    f"flow to downstream stages unfiltered.",
                                    file=sys.stderr,
                                )
                        else:
                            # Parser doesn't persist call_graph.json — the full
                            # unfiltered dataset will flow to downstream stages.
                            # Warn loudly so the cost impact is visible.
                            print(
                                f"  WARNING: --llm-reachability with "
                                f"--level {processing_level}: "
                                f"{parse_result.language} does not yet support "
                                f"post-LLM re-filtering (call_graph.json not found). "
                                f"Downstream stages will process all "
                                f"{pre_filter_count} units instead of the filtered "
                                f"subset — this may significantly increase cost.",
                                file=sys.stderr,
                            )

                    # Persist final dataset so downstream stages see promoted
                    # entry points, per-unit signals, and the applied filter.
                    write_json(active_dataset_path, dataset, indent=2)

                    ctx.summary = {
                        "units_reviewed": pre_filter_count,
                        "signals_added": summary["signals_applied"],
                        "entry_points_promoted": summary["entry_points_promoted"],
                        "units_touched": summary["units_touched"],
                        "post_filter_units": post_filter_count,
                        "refilter_supported": refilter_supported,
                    }
                    ctx.outputs = {"signals_path": signals_path}

                    print(
                        f"  LLM reachability: {summary['signals_applied']} signals, "
                        f"{summary['entry_points_promoted']} new entry points",
                        file=sys.stderr,
                    )
                    if processing_level != "all" and refilter_supported:
                        print(
                            f"  After reachability filter: {post_filter_count} units",
                            file=sys.stderr,
                        )
            except LLMAuthError:
                # The designed abort: bad credentials surface loudly, never
                # degrade into a skip (a silently-skipped reachability pass
                # reads as a clean run to a credential-less user).
                raise
            except Exception as exc:
                # #268 (wave catch): the body mutates result.units_count
                # mid-flow (post-re-filter) BEFORE the dataset persist; a
                # failure in that window left the count describing a dataset
                # that never reached disk. Restore the pre-stage count so the
                # result matches what downstream actually consumes.
                result.units_count = pre_llmreach_units_count
                print(
                    f"  WARNING: LLM reachability stage failed: {exc}",
                    file=sys.stderr,
                )
                ctx.status = "skipped"
                ctx.summary = {"skipped": True, "reason": str(exc)}
                # Record the crash so the degraded reachability pass is
                # visible in the artifacts, matching the dataset-read guard.
                _record_skip(result, "llm-reachability", "failed")
                dataset = None

        collected_step_reports.append(
            _load_step_report(output_dir, "llm-reachability")
        )
    else:
        _record_skip(result, "llm-reachability", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 3: Enhance (optional)
    # ---------------------------------------------------------------
    if enhance:
        from core.enhancer import enhance_dataset

        print(_step_label("Enhancing dataset..."), file=sys.stderr)

        enhanced_path = os.path.join(output_dir, "dataset_enhanced.json")

        with step_context("enhance", output_dir, inputs={
            "dataset_path": active_dataset_path,
            "analyzer_output_path": parse_result.analyzer_output_path,
            "repo_path": repo_path,
            "mode": enhance_mode,
        }) as ctx:
            # Enhance is OPTIONAL: a failure here must not discard the completed
            # parse work. Catch-and-continue (matching app-context /
            # llm-reachability), since step_context re-raises otherwise.
            try:
                enhance_result = enhance_dataset(
                    dataset_path=active_dataset_path,
                    output_path=enhanced_path,
                    analyzer_output_path=parse_result.analyzer_output_path,
                    repo_path=repo_path,
                    mode=enhance_mode,
                    registry=registry,
                    workers=workers,
                    backoff_seconds=backoff_seconds,
                    # checkpoint_path auto-derived from output_path
                    # #213: --limit bounds the enhance phase too — the
                    # scan's cheapest-mode flag must bound the run's spend,
                    # and enhance is a high-volume per-unit LLM phase. NOTE
                    # the ordering trade-off (deliberate, per the issue's
                    # ruling): a limited run selects units BEFORE the
                    # enhancer writes security_classification, so analyze's
                    # classification-priority re-sort no-ops on the
                    # pre-limited set — bounded runs choose cost-bound over
                    # classification-priority coverage. (LLM reachability
                    # stays unbounded: it needs the full corpus.)
                    limit=limit,
                )

                ctx.summary = {
                    "units_enhanced": enhance_result.units_enhanced,
                    "error_count": enhance_result.error_count,
                    "classifications": enhance_result.classifications,
                    "mode": enhance_mode,
                }
                if enhance_result.error_summary:
                    ctx.summary["error_summary"] = enhance_result.error_summary
                ctx.outputs = {
                    "enhanced_dataset_path": enhance_result.enhanced_dataset_path,
                }

                result.enhanced_dataset_path = enhance_result.enhanced_dataset_path
                active_dataset_path = enhance_result.enhanced_dataset_path

                print(f"  Enhanced: {enhance_result.units_enhanced} units", file=sys.stderr)
                print(f"  Classifications: {enhance_result.classifications}", file=sys.stderr)
                if enhance_result.error_summary:
                    print(f"  Errors: {enhance_result.error_count} ({enhance_result.error_summary})", file=sys.stderr)
            except Exception as e:
                print(f"  WARNING: Enhancement failed: {e}", file=sys.stderr)
                print("  Continuing with the un-enhanced dataset.", file=sys.stderr)
                ctx.status = "skipped"
                ctx.summary = {"skipped": True, "reason": str(e)}
                _record_skip(result, "enhance", "failed")

        collected_step_reports.append(_load_step_report(output_dir, "enhance"))
    else:
        print(_step_label("Skipping enhancement (--no-enhance)."), file=sys.stderr)
        _record_skip(result, "enhance", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 4: Detect (Stage 1)
    # ---------------------------------------------------------------
    from core.analyzer import run_analysis

    print(_step_label("Running vulnerability detection (Stage 1)..."), file=sys.stderr)

    analyze_binding = registry.get("analyze")
    with step_context("analyze", output_dir, inputs={
        "dataset_path": active_dataset_path,
        "model": analyze_binding.model,
        "provider": analyze_binding.provider_name,
        "limit": limit,
    }) as ctx:
        analyze_result = run_analysis(
            dataset_path=active_dataset_path,
            output_dir=output_dir,
            analyzer_output_path=parse_result.analyzer_output_path,
            app_context_path=app_context_path,
            repo_path=repo_path,
            limit=limit,
            registry=registry,
            workers=workers,
            backoff_seconds=backoff_seconds,
        )

        ctx.summary = {
            "total_units": analyze_result.metrics.total,
            "analyzed": analyze_result.metrics.total - analyze_result.metrics.errors,
            "verdicts": {
                "vulnerable": analyze_result.metrics.vulnerable,
                "bypassable": analyze_result.metrics.bypassable,
                "inconclusive": analyze_result.metrics.inconclusive,
                "protected": analyze_result.metrics.protected,
                "safe": analyze_result.metrics.safe,
                "errors": analyze_result.metrics.errors,
            },
        }
        ctx.outputs = {"results_path": analyze_result.results_path}

    result.results_path = analyze_result.results_path
    result.metrics = analyze_result.metrics
    collected_step_reports.append(_load_step_report(output_dir, "analyze"))
    print(file=sys.stderr)

    # Active results path — may be updated by verify step
    active_results_path = analyze_result.results_path

    # ---------------------------------------------------------------
    # Step 5: Verify (Stage 2) — optional
    # ---------------------------------------------------------------
    has_findings = (
        analyze_result.metrics.vulnerable > 0
        or analyze_result.metrics.bypassable > 0
    )

    if verify and has_findings:
        from core.verifier import run_verification

        print(_step_label("Running verification (Stage 2)..."), file=sys.stderr)

        with step_context("verify", output_dir, inputs={
            "results_path": analyze_result.results_path,
            "analyzer_output_path": parse_result.analyzer_output_path,
        }) as ctx:
            # Verify is OPTIONAL: a failure here must not discard completed
            # parse/analyze work (step_context re-raises otherwise).
            try:
                verify_result = run_verification(
                    results_path=analyze_result.results_path,
                    output_dir=output_dir,
                    analyzer_output_path=parse_result.analyzer_output_path,
                    app_context_path=app_context_path,
                    repo_path=repo_path,
                    workers=workers,
                    backoff_seconds=backoff_seconds,
                    registry=registry,
                )

                ctx.summary = {
                    "findings_input": verify_result.findings_input,
                    "findings_verified": verify_result.findings_verified,
                    "agreed": verify_result.agreed,
                    "disagreed": verify_result.disagreed,
                    "confirmed_vulnerabilities": verify_result.confirmed_vulnerabilities,
                    "needs_review": verify_result.needs_review,
                    "error_count": verify_result.error_count,
                }
                ctx.outputs = {
                    "verified_results_path": verify_result.verified_results_path,
                }

                result.verified_results_path = verify_result.verified_results_path
                active_results_path = verify_result.verified_results_path

                print(f"  Confirmed: {verify_result.confirmed_vulnerabilities} vulnerabilities",
                      file=sys.stderr)
                if verify_result.needs_review:
                    print(f"  Needs manual review: {verify_result.needs_review} "
                          f"(verification incomplete)", file=sys.stderr)

                # Update metrics from verified results.
                #
                # PR #69 F5: ONLY genuine Stage-2 disagreements (verdict downgraded)
                # fold into ``safe``. Findings whose verification could not COMPLETE
                # (``needs_review``) or that errored (``error_count``) must NOT inflate
                # ``safe`` — they are preserved Stage-1 potential vulnerabilities
                # awaiting manual review. Errors stay in the ``errors`` bucket.
                result.metrics = AnalysisMetrics(
                    total=analyze_result.metrics.total,
                    vulnerable=verify_result.confirmed_vulnerabilities,
                    bypassable=0,
                    inconclusive=analyze_result.metrics.inconclusive,
                    protected=analyze_result.metrics.protected,
                    safe=analyze_result.metrics.safe + verify_result.disagreed,
                    errors=analyze_result.metrics.errors + verify_result.error_count,
                    verified=verify_result.findings_verified,
                    stage2_agreed=verify_result.agreed,
                    stage2_disagreed=verify_result.disagreed,
                    needs_review=verify_result.needs_review,
                )
            except Exception as e:
                print(f"  WARNING: Verification failed: {e}", file=sys.stderr)
                print("  Continuing with unverified Stage 1 results.", file=sys.stderr)
                ctx.status = "skipped"
                ctx.summary = {"skipped": True, "reason": str(e)}
                _record_skip(result, "verify", "failed")

        collected_step_reports.append(_load_step_report(output_dir, "verify"))
    elif verify and not has_findings:
        print(_step_label("Skipping verification (no vulnerable findings)."),
              file=sys.stderr)
        _record_skip(result, "verify", "no_candidates")
    else:
        print(_step_label("Skipping verification (--no-verify or not requested)."),
              file=sys.stderr)
        _record_skip(result, "verify", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 6: Build pipeline_output.json
    # ---------------------------------------------------------------
    from core.reporter import build_pipeline_output

    print(_step_label("Building pipeline_output.json..."), file=sys.stderr)

    pipeline_output_path = os.path.join(output_dir, "pipeline_output.json")

    with step_context("build-output", output_dir, inputs={
        "results_path": active_results_path,
    }) as ctx:
        build_pipeline_output(
            results_path=active_results_path,
            output_path=pipeline_output_path,
            repo_name=repo_name or os.path.basename(repo_path),
            repo_url=repo_url,
            commit_sha=commit_sha,
            language=result.language,
            application_type=(
                app_context_path and _read_app_type(app_context_path)
            ) or "web_app",
            processing_level=processing_level,
            step_reports=collected_step_reports,
            context_source=result.context_source,
            threat_model_sha256=result.threat_model_sha256,
            threat_model_warnings=result.threat_model_warnings,
            # Authoritative skip data so pipeline_output.json reflects real
            # pipeline status (esp. a non-aborting verify failure) instead of
            # always reporting "nothing skipped". At this point (Step 6) all
            # pre-build skips incl. verify are already recorded; dynamic-test/
            # report skips are recorded later and remain in scan.report.json.
            skipped_steps=list(result.skipped_steps),
            skipped_step_reasons=dict(result.skipped_step_reasons),
        )

        ctx.outputs = {"pipeline_output_path": pipeline_output_path}

    result.pipeline_output_path = pipeline_output_path
    collected_step_reports.append(_load_step_report(output_dir, "build-output"))
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 7: Dynamic Test (optional, off by default)
    # ---------------------------------------------------------------
    if dynamic_test and has_findings:
        if not shutil.which("docker"):
            print(_step_label("Skipping dynamic test (Docker not found)."),
                  file=sys.stderr)
            _record_skip(result, "dynamic-test", "docker_unavailable")
        else:
            from core.dynamic_tester import run_tests

            print(_step_label("Running dynamic tests (Docker)..."), file=sys.stderr)

            with step_context("dynamic-test", output_dir, inputs={
                "pipeline_output_path": pipeline_output_path,
            }) as ctx:
                # Dynamic test is OPTIONAL: a failure here must not discard
                # completed work (step_context re-raises otherwise).
                try:
                    dt_result = run_tests(
                        pipeline_output_path=pipeline_output_path,
                        output_dir=output_dir,
                        registry=registry,
                    )

                    ctx.summary = {
                        "findings_tested": dt_result.findings_tested,
                        "confirmed": dt_result.confirmed,
                        "not_reproduced": dt_result.not_reproduced,
                        "blocked": dt_result.blocked,
                        "inconclusive": dt_result.inconclusive,
                        "errors": dt_result.errors,
                    }
                    ctx.outputs = {
                        "results_json_path": dt_result.results_json_path,
                        "results_md_path": dt_result.results_md_path,
                    }

                    result.dynamic_test_path = dt_result.results_json_path

                    print(f"  Dynamic test: {dt_result.confirmed} confirmed, "
                          f"{dt_result.not_reproduced} not reproduced", file=sys.stderr)
                except Exception as e:
                    print(f"  WARNING: Dynamic test failed: {e}", file=sys.stderr)
                    print("  Continuing without dynamic-test results.", file=sys.stderr)
                    ctx.status = "skipped"
                    ctx.summary = {"skipped": True, "reason": str(e)}
                    _record_skip(result, "dynamic-test", "failed")

            collected_step_reports.append(
                _load_step_report(output_dir, "dynamic-test"),
            )
    elif dynamic_test and not has_findings:
        print(_step_label("Skipping dynamic test (no findings to test)."),
              file=sys.stderr)
        _record_skip(result, "dynamic-test", "no_candidates")
    else:
        print(_step_label("Skipping dynamic test (not enabled)."), file=sys.stderr)
        _record_skip(result, "dynamic-test", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Step 8: Report (optional)
    # ---------------------------------------------------------------
    if generate_report:
        from core.reporter import generate_summary_report, generate_disclosure_docs

        print(_step_label("Generating reports..."), file=sys.stderr)

        with step_context("report", output_dir, inputs={
            "pipeline_output_path": pipeline_output_path,
        }) as ctx:
            report_dir = os.path.join(output_dir, "report")
            os.makedirs(report_dir, exist_ok=True)

            summary_path = os.path.join(report_dir, "SUMMARY_REPORT.md")
            disclosures_dir = os.path.join(report_dir, "disclosures")

            outputs = {}

            try:
                # Thread the scan's --llm-config through to the report phase
                # (else it silently falls back to the file's default_llm).
                generate_summary_report(pipeline_output_path, summary_path, llm_config_name)
                result.summary_path = summary_path
                outputs["summary_path"] = summary_path
                print(f"  Summary: {summary_path}", file=sys.stderr)
            except Exception as e:
                print(f"  WARNING: Summary report failed: {e}", file=sys.stderr)
                ctx.errors.append(f"Summary report: {e}")

            # Only generate disclosures if there are findings
            if has_findings:
                try:
                    generate_disclosure_docs(pipeline_output_path, disclosures_dir, llm_config_name)
                    outputs["disclosures_dir"] = disclosures_dir
                    print(f"  Disclosures: {disclosures_dir}", file=sys.stderr)
                except Exception as e:
                    print(f"  WARNING: Disclosure docs failed: {e}", file=sys.stderr)
                    ctx.errors.append(f"Disclosure docs: {e}")

            ctx.summary = {"formats_generated": list(outputs.keys())}
            ctx.outputs = outputs

        collected_step_reports.append(_load_step_report(output_dir, "report"))
    else:
        print(_step_label("Skipping report generation (--no-report)."), file=sys.stderr)
        _record_skip(result, "report", "not_requested")
    print(file=sys.stderr)

    # ---------------------------------------------------------------
    # Final: Aggregate scan report
    # ---------------------------------------------------------------
    result.usage = tracking.get_usage()
    result.step_reports = collected_step_reports

    _write_scan_report(output_dir, result, collected_step_reports)
    _print_summary(result)

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _count_steps(
    generate_context: bool,
    enhance: bool,
    verify: bool,
    generate_report: bool,
    dynamic_test: bool,
    llm_reachability: bool = False,
) -> int:
    """Count total steps for progress display (always includes parse, detect, build-output)."""
    count = 3  # parse + detect + build-output (always run)
    if generate_context:
        count += 1
    if enhance:
        count += 1
    if verify:
        count += 1
    if generate_report:
        count += 1
    if dynamic_test:
        count += 1
    if llm_reachability:
        count += 1
    return count


def _record_skip(result: ScanResult, step: str, reason: str) -> None:
    """Record that ``step`` was skipped.

    Appends the bare step name to ``result.skipped_steps`` (UNCHANGED behaviour
    — telemetry consumers read this flat list) and ADDITIVELY records the
    disambiguated cause in ``result.skipped_step_reasons`` so distinct causes
    (e.g. verify auto-skip 'no_candidates' vs opt-out 'not_requested') are no
    longer conflated to one bare string.
    """
    result.skipped_steps.append(step)
    result.skipped_step_reasons[step] = reason


def _load_step_report(output_dir: str, step: str) -> dict:
    """Load a step report JSON from disk. Returns empty dict on failure."""
    path = os.path.join(output_dir, f"{step}.report.json")
    try:
        return read_json(path)
    except Exception:
        return {"step": step, "status": "unknown"}


def _read_app_type(app_context_path: str) -> str | None:
    """Read application_type from an app context JSON file."""
    try:
        data = read_json(app_context_path)
        return data.get("application_type")
    except Exception:
        return None


# Coverage fields the shared walker (core/repo_walk.py STAT_KEYS) records when it
# refuses a symlink or cannot read a directory. Parsers persist them into their
# per-language scan-result file's ``statistics`` block, NOT into dataset.json —
# so the merge into ``per_language`` never carries them. They are the only signal
# that a scan skipped part of the tree; without them a partially-covered scan of
# a hostile repo looks identical to a clean one. Aggregated here, at report time.
_COVERAGE_COUNT_KEYS = ("symlinks_skipped", "directories_unreadable")
_COVERAGE_EXAMPLE_KEYS = ("symlink_examples", "unreadable_examples")
# Parsers disagree on the filename: the in-process Python parser writes
# scan_result.json (singular); the subprocess parsers write scan_results.json.
_SCAN_RESULT_FILENAMES = ("scan_result.json", "scan_results.json")


def _read_coverage_stats(dir_path: str) -> dict:
    """Return the coverage keys present in a directory's scan-result file, or {}.

    Reads OUR output artifact, not anything from the scanned repo, so a plain
    read is safe. Only keys that are actually present are returned — absence is
    NOT coerced to zero here, because the caller must distinguish "the parser
    instruments coverage and skipped nothing" (a count key present at 0) from
    "the parser does not instrument coverage at all" (the key absent). Coercing
    absence to 0 is exactly the false-``symlinks_skipped: 0`` assurance this
    aggregation exists to avoid.
    """
    for name in _SCAN_RESULT_FILENAMES:
        candidate = os.path.join(dir_path, name)
        if not os.path.isfile(candidate):
            continue
        try:
            stats = read_json(candidate).get("statistics", {}) or {}
        except Exception:
            return {}
        return {
            k: stats[k]
            for k in (*_COVERAGE_COUNT_KEYS, *_COVERAGE_EXAMPLE_KEYS)
            if k in stats
        }
    return {}


def _language_scan_dirs(result: ScanResult) -> list[tuple[str, str]]:
    """``(language, scan-output-dir)`` pairs to probe for coverage.

    Multi-language runs carry a per-language ``output_dir`` in ``per_language``;
    the single-language passthrough writes straight into ``result.output_dir``
    with an empty ``per_language``. Both are normalised to the same pair list so
    coverage is attributable to a named language either way.
    """
    pairs: list[tuple[str, str]] = []
    for lang, spec in (result.per_language or {}).items():
        out = spec.get("output_dir") if isinstance(spec, dict) else None
        pairs.append((lang, out or result.output_dir))
    if not pairs:
        pairs.append((result.language, result.output_dir))
    return pairs


def _collect_coverage(result: ScanResult) -> dict:
    """Aggregate skipped-symlink / unreadable-dir figures across languages.

    A language is "instrumented" iff its scan-result ``statistics`` carries at
    least one coverage COUNT key. This is a presence PROBE, deliberately not a
    hardcoded per-language allowlist: the parser set gains and loses coverage
    instrumentation over time, and a stale allowlist would fail dangerously —
    silently summing a de-instrumented language's absent keys as 0, i.e. a false
    "nothing skipped". The probe fails safe instead: an uninstrumented language
    is disclosed in ``languages_without_coverage_data`` rather than counted as 0,
    so a ``symlinks_skipped: 0`` aggregate is trustworthy ONLY when that list is
    empty. (JavaScript and Go do not yet instrument coverage; they appear in the
    list until their parsers emit the snake_case keys.)
    """
    counts = {k: 0 for k in _COVERAGE_COUNT_KEYS}
    examples: dict[str, list] = {k: [] for k in _COVERAGE_EXAMPLE_KEYS}
    without_data: list[str] = []
    for lang, d in _language_scan_dirs(result):
        stats = _read_coverage_stats(d)
        if not any(k in stats for k in _COVERAGE_COUNT_KEYS):
            without_data.append(lang or "unknown")
            continue
        for k in _COVERAGE_COUNT_KEYS:
            counts[k] += int(stats.get(k, 0) or 0)
        for k in _COVERAGE_EXAMPLE_KEYS:
            for ex in stats.get(k, []) or []:
                if len(examples[k]) < 5 and ex not in examples[k]:
                    examples[k].append(ex)
    return {
        **counts,
        **examples,
        "languages_without_coverage_data": sorted(set(without_data)),
    }


def _write_scan_report(
    output_dir: str,
    result: ScanResult,
    step_reports: list[dict],
) -> str:
    """Write ``scan.report.json`` — the aggregate report for the full pipeline."""
    total_cost = sum(sr.get("cost_usd", 0) for sr in step_reports)
    total_duration = sum(sr.get("duration_seconds", 0) for sr in step_reports)
    total_input = sum(
        sr.get("token_usage", {}).get("input_tokens", 0) for sr in step_reports
    )
    total_output = sum(
        sr.get("token_usage", {}).get("output_tokens", 0) for sr in step_reports
    )

    scan_report = StepReport(
        step="scan",
        summary={
            "units_count": result.units_count,
            "language": result.language,
            "metrics": result.metrics.to_dict(),
            "steps_completed": [sr.get("step") for sr in step_reports],
            "steps_skipped": result.skipped_steps,
            # ADDITIVE / non-breaking: disambiguated skip cause per step.
            # `steps_skipped` above stays a flat bare list (consumers read it).
            "steps_skipped_reasons": result.skipped_step_reasons,
            # Multi-language coverage + which path supplied the security model.
            # Previously omitted here, so a merged/degraded scan and a
            # single-language clean one produced indistinguishable reports.
            "languages": result.languages,
            "language_stats": result.language_stats,
            "per_language": result.per_language,
            "parse_errors": result.parse_errors,
            "excluded_languages": result.excluded_languages,
            "degraded": result.degraded,
            "context_source": result.context_source,
            # R5: provenance of a repo-supplied threat model. sha is absent (key
            # omitted) when no threat model was loaded — never the empty hash.
            **(
                {"threat_model_sha256": result.threat_model_sha256}
                if result.threat_model_sha256
                else {}
            ),
            "threat_model_warnings": result.threat_model_warnings,
            # Aggregate of what the walker refused (symlinks) or could not read
            # (directories), summed across languages from each scan-result file.
            "coverage": _collect_coverage(result),
        },
        inputs={"repo_path": result.output_dir.replace(os.path.abspath("."), ".")},
        outputs={
            "dataset_path": result.dataset_path,
            "enhanced_dataset_path": result.enhanced_dataset_path,
            "results_path": result.results_path,
            "verified_results_path": result.verified_results_path,
            "pipeline_output_path": result.pipeline_output_path,
            "summary_path": result.summary_path,
            "dynamic_test_path": result.dynamic_test_path,
        },
        cost_usd=round(total_cost, 6),
        duration_seconds=round(total_duration, 2),
        token_usage={
            "input_tokens": total_input,
            "output_tokens": total_output,
            "total_tokens": total_input + total_output,
            # #216: the aggregate rebuilds token_usage from the step
            # reports — OR-aggregate the incomplete-cost marker across them
            # (a rebuild must not drop the advisory).
            **({
                "cost_incomplete": True,
                "unpriced_models": sorted({m for sr in step_reports
                                           for m in (sr.get("token_usage", {})
                                                     .get("unpriced_models") or [])}),
            } if any(sr.get("token_usage", {}).get("cost_incomplete")
                     for sr in step_reports) else {}),
        },
    )

    path = scan_report.write(output_dir)
    print(f"[Scan] Aggregate report: {path}", file=sys.stderr)
    return path


def _print_banner(
    repo_path: str,
    output_dir: str,
    language: str,
    processing_level: str,
    verify: bool,
    generate_context: bool,
    enhance: bool,
    enhance_mode: str,
    generate_report: bool,
    dynamic_test: bool,
    workers: int = 8,
    backoff_seconds: int = 30,
) -> None:
    """Print the scan configuration banner."""
    print("=" * 60, file=sys.stderr)
    print("OPENANT SCAN", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Repository:    {repo_path}", file=sys.stderr)
    print(f"  Output:        {output_dir}", file=sys.stderr)
    print(f"  Language:      {language}", file=sys.stderr)
    print(f"  Level:         {processing_level}", file=sys.stderr)
    print(f"  Enhance:       {enhance} ({enhance_mode})", file=sys.stderr)
    print(f"  Verify (S2):   {verify}", file=sys.stderr)
    print(f"  App context:   {generate_context}", file=sys.stderr)
    print(f"  Report:        {generate_report}", file=sys.stderr)
    print(f"  Dynamic test:  {dynamic_test}", file=sys.stderr)
    workers_label = f"{workers} (parallel)" if workers > 1 else "1 (sequential)"
    print(f"  Workers:       {workers_label}", file=sys.stderr)
    print(f"  Rate backoff:  {backoff_seconds}s", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(file=sys.stderr)


def _print_summary(result: ScanResult) -> None:
    """Print the final scan summary."""
    print("=" * 60, file=sys.stderr)
    print("SCAN COMPLETE", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"  Units analyzed: {result.metrics.total}", file=sys.stderr)
    print(f"  Vulnerable:     {result.metrics.vulnerable}", file=sys.stderr)
    print(f"  Bypassable:     {result.metrics.bypassable}", file=sys.stderr)
    print(f"  Protected:      {result.metrics.protected}", file=sys.stderr)
    print(f"  Safe:           {result.metrics.safe}", file=sys.stderr)
    print(f"  Inconclusive:   {result.metrics.inconclusive}", file=sys.stderr)
    # PR #69 F5: surface findings whose Stage-2 verification could not complete
    # so they read distinctly from "safe" in the headline summary.
    if result.metrics.needs_review:
        print(f"  Needs review:   {result.metrics.needs_review} "
              f"(verification incomplete)", file=sys.stderr)
    print(f"  Errors:         {result.metrics.errors}", file=sys.stderr)
    if result.metrics.verified:
        print(f"  Verified:       {result.metrics.verified} "
              f"({result.metrics.stage2_agreed} agreed, "
              f"{result.metrics.stage2_disagreed} disagreed)", file=sys.stderr)
    print(f"  Cost:           ${result.usage.total_cost_usd:.4f}", file=sys.stderr)
    print(f"  Output:         {result.output_dir}", file=sys.stderr)
    if result.skipped_steps:
        print(f"  Skipped:        {', '.join(result.skipped_steps)}", file=sys.stderr)
    if result.usage.total_input_tokens == 0 and result.metrics.errors > 0:
        print("", file=sys.stderr)
        print("  *** No API calls succeeded — repository was NOT analyzed. ***", file=sys.stderr)
        print("  *** Check your API key: openant set-api-key <key>          ***", file=sys.stderr)
    print("=" * 60, file=sys.stderr)
