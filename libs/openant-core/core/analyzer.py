"""
Analysis wrapper (Stage 1 — detection only).

Wraps the experiment.py analysis logic, accepting file paths instead of
hardcoded dataset names. Reuses the existing analysis functions directly.

Stage 2 verification is handled separately by ``core.verifier``.

Checkpoints are always enabled. Per-unit results are saved to
``{output_dir}/analyze_checkpoints/`` so interrupted runs can resume.
On successful completion the checkpoint dir is removed.
"""

import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from core.schemas import AnalyzeResult, AnalysisMetrics, UsageInfo
from core import tracking
from core.checkpoint import StepCheckpoint, analyze_result_is_error
from core.progress import ProgressReporter

# Import existing analysis machinery
from utilities.llm_client import get_global_tracker
from utilities.llm import (
    PhaseBinding,
    PhaseRegistry,
    build_phase_registry,
    load_config_file,
    resolve_llm_config,
)
from utilities.file_io import read_json, write_json
from utilities.json_corrector import JSONCorrector
from utilities.rate_limiter import get_rate_limiter, is_rate_limit_error, is_retryable_error

# These live in core/ because core is shipped and experiment.py is not: importing
# them from the research harness made `import core.analyzer` fail in any installed
# environment (ModuleNotFoundError: no module named 'experiment').
from core.analysis_core import (
    analyze_unit,
    parse_response,
    _normalize_result,
)

# Import application context (optional)
try:
    from context.application_context import ApplicationContext, load_context
    HAS_APP_CONTEXT = True
except ImportError:
    HAS_APP_CONTEXT = False
    load_context = None


def _unit_security_classification(unit):
    """Return a unit's security_classification, regardless of enhance mode.

    Agentic enhance writes ``unit['agent_context']['security_classification']``;
    single-shot enhance writes ``unit['llm_context']`` and historically had no
    classification at all. Reading only ``agent_context`` silently dropped every
    single-shot unit from ``--exploitable-only/all``. Prefer
    agent_context, fall back to llm_context, else None.
    """
    agent_ctx = unit.get("agent_context")
    if isinstance(agent_ctx, dict) and agent_ctx.get("security_classification") is not None:
        return agent_ctx.get("security_classification")
    llm_ctx = unit.get("llm_context")
    if isinstance(llm_ctx, dict) and llm_ctx.get("security_classification") is not None:
        return llm_ctx.get("security_classification")
    return None


# Truncation priority: higher score = kept first when --limit drops units.
# Units the enhancer flagged as exploitable/vulnerable_internal must outrank
# unclassified/neutral code so a limited run does not silently drop the most
# security-relevant units.
_LIMIT_PRIORITY = {"exploitable": 2, "vulnerable_internal": 1}


def _limit_classification(unit):
    """Return a unit's security_classification regardless of enhance mode.

    Agentic enhance writes ``unit['agent_context']['security_classification']``;
    single-shot enhance writes ``unit['llm_context']``. Reading only one mode
    would treat the other's classified units as un-prioritized.
    """
    for ctx_key in ("agent_context", "llm_context"):
        ctx = unit.get(ctx_key)
        if isinstance(ctx, dict) and ctx.get("security_classification") is not None:
            return ctx.get("security_classification")
    return None


def _apply_limit(units, limit):
    """Truncate ``units`` to ``limit``, keeping the highest-priority units.

    Units arrive from the parser in alphabetical-by-path order
    (repository_scanner.py sorts ``self.files`` by path). A raw head-slice
    therefore kept the first N alphabetical units (``Doc/`` before ``Lib/``)
    with no relevance weighting, silently dropping high-value code on a
    ``--limit`` run.

    Sort by enhancement security_classification (exploitable >
    vulnerable_internal > other) before slicing. The sort is stable, so units
    in the same classification tier keep their original (alphabetical) order;
    a no-limit call returns the list unchanged.
    """
    if not limit:
        return units
    prioritized = sorted(
        units,
        key=lambda u: _LIMIT_PRIORITY.get(_limit_classification(u), 0),
        reverse=True,
    )
    return prioritized[:limit]


def _process_unit(binding: PhaseBinding, unit, index, json_corrector, app_context):
    """Process a single unit for Stage 1 detection.

    Returns a dict with all result data. Does not mutate shared state.
    """
    uid = unit.get("id", f"unit_{index}")
    start = time.monotonic()
    tracker = get_global_tracker()
    tracker.start_unit_tracking()

    try:
        result = analyze_unit(
            binding, unit,
            use_multifile=True,
            json_corrector=json_corrector,
            app_context=app_context,
        )

        # Ensure unit_id is always present
        result["unit_id"] = uid

        # Ensure finding field is always set (may be None after JSON correction)
        # and normalize its casing at ingestion. A model may emit a capitalized
        # finding (e.g. "Vulnerable"); the downstream verifier/reporter gates
        # compare against lowercase literals, so an un-normalized value would be
        # silently dropped (a security false-negative). Recover-only: lowercase
        # an existing verdict/finding string, never manufacture one.
        if result.get("finding"):
            result["finding"] = str(result["finding"]).lower()
        elif result.get("verdict"):
            result["finding"] = str(result["verdict"]).lower()

        # Extract code for verify step
        route_key = result.get("route_key", uid)
        code_field = unit.get("code", {})
        if isinstance(code_field, dict):
            code_for_route = code_field.get("primary_code", "")
        else:
            code_for_route = code_field

        finding = result.get("finding", "error")
        elapsed = time.monotonic() - start
        worker = threading.current_thread().name

        return {
            "index": index,
            "result": result,
            "route_key": route_key,
            "code_for_route": code_for_route,
            "finding": finding,
            "elapsed": elapsed,
            "error": None,
            "worker": worker,
            "usage": tracker.get_unit_usage(),
        }

    except Exception as e:
        elapsed = time.monotonic() - start
        worker = threading.current_thread().name
        return {
            "index": index,
            "result": {
                "unit_id": uid,
                "verdict": "ERROR",
                "finding": "error",
                "error": str(e),
            },
            "route_key": uid,
            "code_for_route": "",
            "finding": "error",
            "elapsed": elapsed,
            "error": str(e),
            "worker": worker,
            "usage": tracker.get_unit_usage(),
        }


def _run_detection(units, binding: PhaseBinding, json_corrector, app_context, workers,
                   checkpoint=None, summary_callback=None):
    """Run Stage 1 detection across all units.

    Uses ThreadPoolExecutor for parallel processing when workers > 1.
    Supports checkpoint/resume via the checkpoint parameter.

    Args:
        summary_callback: Optional callable(finding, usage=None) called from
            main thread after each unit completes. Used for _summary.json updates.

    Returns (results_list, code_by_route_dict) in original unit order.
    """
    total = len(units)
    tracker = get_global_tracker()

    # Load checkpoint state
    checkpointed = {}
    if checkpoint is not None:
        checkpointed = checkpoint.load()
        if checkpointed:
            print(f"[Detect] Restored {len(checkpointed)} units from checkpoints",
                  file=sys.stderr, flush=True)

    progress = ProgressReporter("Detect", total, tracker=tracker, completed=len(checkpointed))

    mode = "sequential" if workers <= 1 else f"parallel ({workers} workers)"
    remaining = total - len(checkpointed)
    print(f"[Detect] Mode: {mode}, {remaining} units to process ({len(checkpointed)} already done)",
          file=sys.stderr, flush=True)

    # Pre-populate results from checkpoints, but ONLY for successfully-completed
    # units. Errored units are loaded into the "units_to_process" list so they
    # get retried on resume (matches enhance's behavior).
    results = [None] * total
    code_by_route = {}
    units_to_process = []

    # Hoisted to module level (testable; mirrors checkpoint.py's predicates).
    for i, unit in enumerate(units):
        uid = unit.get("id", f"unit_{i}")
        cp_data = checkpointed.get(uid)
        if cp_data and not _cp_is_error(cp_data):
            results[i] = cp_data.get("result", {})
            code_by_route[cp_data.get("route_key", uid)] = cp_data.get("code_for_route", "")
        else:
            units_to_process.append((i, unit))

    def _process_and_save(i, unit):
        out = _process_unit(binding, unit, i, json_corrector, app_context)
        # Save checkpoint
        if checkpoint is not None:
            uid = out["result"].get("unit_id", f"unit_{i}")
            cp_data = {
                "result": out["result"],
                "route_key": out["route_key"],
                "code_for_route": out["code_for_route"],
            }
            if out.get("usage"):
                cp_data["usage"] = out["usage"]
            checkpoint.save(uid, cp_data)
        return out

    if workers <= 1:
        # Sequential mode
        try:
            for i, unit in units_to_process:
                out = _process_and_save(i, unit)
                results[i] = out["result"]
                code_by_route[out["route_key"]] = out["code_for_route"]
                if summary_callback:
                    summary_callback(out["finding"], usage=out.get("usage"))
                progress.report(
                    out["result"].get("unit_id", f"unit_{i}"),
                    detail=out["finding"],
                    unit_elapsed=out["elapsed"],
                )
        except KeyboardInterrupt:
            print(_interrupt_report(results, total), file=sys.stderr, flush=True)
            progress.finish()
            # #313: stop swallowing the interrupt. The checkpoints are
            # written (per-unit saves happen in _process_and_save) and the
            # report is printed; swallowing it made the None placeholders
            # reach _count_verdicts (AttributeError) and the resulting
            # error envelope made the Go CLI record the interrupt as a
            # FAILED scan — the interrupt short-circuit fires only on
            # empty stdout.
            raise
        progress.finish()
        return results, code_by_route

    # Parallel mode
    executor = ThreadPoolExecutor(max_workers=workers)
    future_to_index = {}
    for i, unit in units_to_process:
        future = executor.submit(_process_and_save, i, unit)
        future_to_index[future] = i

    try:
        for future in as_completed(future_to_index):
            out = future.result()
            idx = out["index"]
            results[idx] = out["result"]
            code_by_route[out["route_key"]] = out["code_for_route"]
            if summary_callback:
                summary_callback(out["finding"], usage=out.get("usage"))
            worker = out.get("worker", "?")
            progress.report(
                out["result"].get("unit_id", f"unit_{idx}"),
                detail=f"{out['finding']}  [{worker}]",
                unit_elapsed=out["elapsed"],
            )
    except KeyboardInterrupt:
        print("[Detect] Interrupted — cancelling pending work...",
              file=sys.stderr, flush=True)
        executor.shutdown(wait=False, cancel_futures=True)
        print(_interrupt_report(results, total), file=sys.stderr, flush=True)
        progress.finish()
        raise  # #313: see the sequential handler note
    else:
        executor.shutdown(wait=False)

    progress.finish()

    return results, code_by_route


def _interrupt_report(results, total):
    """#313: what an interrupted run actually did — N analysed, M not
    started, checkpoints written. Both numbers derive from the results
    list (the None placeholders are the not-started units)."""
    analysed = sum(1 for r in results if r is not None)
    not_started = total - analysed
    return (
        f"[Detect] Interrupted after {analysed}/{total} unit(s) "
        f"({not_started} not started); progress saved to checkpoints")


def _cp_is_error(cp_data):
    """Is this checkpointed unit an error (must be re-analyzed, not adopted)?

    Delegates to ``checkpoint.analyze_result_is_error`` — the one shared
    predicate (load_ids / status / the summary seed below all use it; four
    hand-copies drifted within one PR).
    """
    res = cp_data.get("result", {}) if cp_data else {}
    return analyze_result_is_error(res)


def _seed_summary(existing: dict) -> dict:
    """Seed the _summary.json counters from checkpointed rows.

    Counts as completed ONLY the rows adoption will keep: an errored row
    (``analyze_result_is_error``) is re-analyzed and its outcome is owned by
    ``_summary_callback`` — seeding it here (as completed OR as an error)
    double-counts on resume (completed + errors > total; the pre-existing
    verdict=="ERROR" over-count, which #316/#324 was extending to the
    neither-key shape). Usage tokens accumulate over ALL rows — the spend
    happened regardless of the row's fate.

    Returns: completed, input_tokens, output_tokens, cost_usd,
    unpriced_models (the #216 marker).
    """
    completed = 0
    input_tokens = 0
    output_tokens = 0
    cost_usd = 0.0
    unpriced: set = set()
    for _cp in existing.values():
        if not analyze_result_is_error(_cp.get("result") or {}):
            completed += 1
        _usage = _cp.get("usage", {})
        input_tokens += _usage.get("input_tokens", 0)
        output_tokens += _usage.get("output_tokens", 0)
        cost_usd += _usage.get("cost_usd", 0.0)
        # #216: restore the incomplete-cost marker from per-unit records.
        unpriced.update(_usage.get("unpriced_models") or [])
    return {
        "completed": completed,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_usd": cost_usd,
        "unpriced_models": unpriced,
    }


def _count_verdicts(results):
    """Count verdict categories from a results list."""
    counts = {
        "vulnerable": 0,
        "bypassable": 0,
        "inconclusive": 0,
        "protected": 0,
        "safe": 0,
        "errors": 0,
    }
    for r in results:
        # #313: an interrupted run leaves None placeholders for units that
        # never ran — skip them (an un-run unit is not a verdict; the
        # checkpoint-resume semantics own those units).
        if r is None:
            continue
        # #324/null-verdict: an INEFFECTIVE finding (absent/None/non-string/
        # empty) falls back to the verdict, which must itself be an effective
        # string — the eager ``.lower()`` default crashed post-LLM-spend on
        # ``{"verdict": null}``.
        finding = r.get("finding")
        verdict = r.get("verdict")
        if not isinstance(finding, str) or not finding.strip():
            finding = verdict if isinstance(verdict, str) and verdict.strip() else None
        if finding is None:
            # Neither an effective finding nor an effective verdict — the
            # malformed shape (#324; null/empty verdicts): an error, not a
            # silent drop.
            counts["errors"] += 1
        elif finding.lower() in counts:
            counts[finding.lower()] += 1
        elif verdict == "ERROR" or finding.lower() == "error":
            # finding=="error" without verdict=="ERROR" (a legacy
            # half-stamped row): agree with analyze_result_is_error, which
            # classifies it as an error.
            counts["errors"] += 1
        # else: an unrecognized verdict — the documented F13 gap (dropped).
    return counts


def _analyze_fingerprint(binding) -> dict:
    """Build the analyze-phase backend-identity fingerprint.

    The static system + user-analysis templates are rendered with
    ``app_context=None`` (mandatory: the LLM-generated threat model is
    non-deterministic per scan and must not enter the key). An unrenderable
    template becomes a sentinel via ``render_template_texts`` → forces re-run
    rather than a stale adoption.
    """
    from core.backend_identity import fingerprint_for_binding, render_template_texts
    from prompts.vulnerability_analysis import get_system_prompt
    from prompts.prompt_selector import get_analysis_prompt
    texts = render_template_texts([
        lambda: get_system_prompt(app_context=None),
        lambda: get_analysis_prompt(code="", language="code", app_context=None),
    ])
    return fingerprint_for_binding(binding, texts)


def _archive_stale_results(output_dir: str, current_fp: str) -> None:
    """Preserve a prior scan's report before this run overwrites it.

    If ``output_dir/results.json`` exists and was produced under a DIFFERENT
    ``analyze_fingerprint``, rename it to ``results__<short-fp>.json`` (an
    unstamped file → ``results__legacy.json``) so a re-scan with a different
    model/config preserves the prior analyze report. The suffix is the SAME short
    form as ``StepCheckpoint._archive_dir`` — the last ``:``-split segment, first 8
    hex — so the ``sha256:`` prefix's colon never lands in a filename (a colon
    breaks ``os.replace`` on Windows: the OSError is swallowed and a later run
    overwrites the prior results.json, defeating the preservation promise).

    Scope (named residual): this preserves the Stage-1 ``results.json`` only.
    ``results_verified.json`` (Stage-2, and the file the serve/report layer
    prefers) is NOT fingerprint-checked or archived here — a backend-swap re-scan
    run without ``--verify`` leaves the prior verified file in place. That is
    pre-existing base behaviour (base overwrote ``results.json`` unconditionally);
    extending identity/preservation to ``results_verified.json`` is a follow-up.

    Collision-safe: if the target archive name already exists (an A→B→A config
    alternation, or two unstamped reports both → ``results__legacy.json``), a
    ``-<n>`` suffix is appended rather than overwriting — mirroring
    ``_archive_dir`` — so no prior report is ever destroyed. Best-effort: any error
    leaves the file in place (preserve-not-destroy; never crash the scan).
    """
    results_path = os.path.join(output_dir, "results.json")
    if not os.path.exists(results_path):
        return
    try:
        prior = read_json(results_path)
    except (json.JSONDecodeError, OSError, ValueError):
        return
    if not isinstance(prior, dict):
        return
    old_fp = prior.get("analyze_fingerprint")
    if old_fp == current_fp:
        return
    # Short, filesystem-safe suffix: drop the ``sha256:`` prefix (its colon is
    # illegal in a Windows filename) and keep the first 8 hex chars. A machine
    # stamp is always a str; a hand-corrupted non-string stamp must NOT crash the
    # scan (the function's contract is best-effort) — treat it as unstamped.
    suffix = old_fp.split(":")[-1][:8] if isinstance(old_fp, str) and old_fp else "legacy"
    # Never clobber an existing archive (distinct prior report under the same
    # short suffix): append -<n> until the name is free, as _archive_dir does.
    base = os.path.join(output_dir, f"results__{suffix}")
    archive = f"{base}.json"
    n = 1
    while os.path.exists(archive):
        archive = f"{base}-{n}.json"
        n += 1
    try:
        os.replace(results_path, archive)
        print(f"[Analyze] Prior scan's results.json (fingerprint {suffix}) "
              f"preserved as {os.path.basename(archive)}.", file=sys.stderr)
    except OSError:
        pass


def run_analysis(
    dataset_path: str,
    output_dir: str,
    analyzer_output_path: str | None = None,
    app_context_path: str | None = None,
    repo_path: str | None = None,
    limit: int | None = None,
    registry: PhaseRegistry | None = None,
    llm_config_name: str | None = None,
    exploitable_filter: str | None = None,
    workers: int = 8,
    checkpoint_path: str | None = None,
    backoff_seconds: int = 30,
) -> AnalyzeResult:
    """Run Stage 1 vulnerability detection on a dataset.

    This is the clean wrapper around experiment.py's run_experiment() logic,
    accepting file paths instead of dataset names. Stage 1 only — for Stage 2
    verification use ``core.verifier.run_verification()``.

    Checkpoints are always enabled. Per-unit results are saved to
    ``{output_dir}/analyze_checkpoints/`` so interrupted runs resume
    automatically.

    Args:
        dataset_path: Path to dataset.json produced by a parser.
        output_dir: Directory to write results.json.
        analyzer_output_path: Path to analyzer_output.json (unused here,
            accepted for interface compatibility).
        app_context_path: Path to application_context.json (reduces false positives).
        repo_path: Path to the repository (for context correction).
        limit: Max number of units to analyze.
        registry: Pre-built PhaseRegistry. Scanners pass theirs;
            standalone callers leave this None and a registry is
            constructed from ``llm_config_name`` (and probed upfront).
        llm_config_name: Name of the llm-config when ``registry`` is
            None. ``None`` falls through to the active/default config.
        exploitable_filter: Filter by enhancement classification. Options:
            None (default) — no filtering, analyze all units.
            "all" — keep exploitable + vulnerable_internal (recommended).
            "strict" — keep exploitable only (use after parser fixes).
        checkpoint_path: Path to checkpoint directory. If None, auto-derived
            from output_dir.
        workers: Number of parallel workers (default: 8).
        backoff_seconds: Seconds to wait on rate limit before retry (default: 30).

    Returns:
        AnalyzeResult with results path, metrics, and usage.
    """
    # #214: snapshot cumulative usage at phase start so the "Stage 1" summary
    # below reports this phase's delta, not the prior phases' total.
    _phase_baseline = tracking.get_usage()
    os.makedirs(output_dir, exist_ok=True)

    # Configure global rate limiter
    from utilities.rate_limiter import configure_rate_limiter
    configure_rate_limiter(backoff_seconds=float(backoff_seconds))

    # Set up checkpoint
    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoints")
    checkpoint = StepCheckpoint("Analyze", output_dir)
    checkpoint.dir = checkpoint_path

    # Resolve the binding for the analyze phase from the registry.
    # When this function builds its own registry (standalone
    # `openant analyze` invocation), probe it upfront so a bad key /
    # typo'd model fails loudly here rather than mid-scan. Callers
    # that pass an explicit ``registry`` are expected to have done
    # their own validation (e.g. the scanner).
    if registry is None:
        from utilities.llm import probe_registry_or_raise

        cf = load_config_file()
        registry = build_phase_registry(cf, resolve_llm_config(cf, llm_config_name))
        probe_registry_or_raise(registry)
    binding = registry.get("analyze")
    print(f"[Analyze] Provider: {binding.provider_name}, Model: {binding.model}", file=sys.stderr)

    # I2 adopt gate: BEFORE loading any prior checkpoints, verify the backend
    # identity that produced them matches the current one. A changed model /
    # provider / adapter / static template archives the stale dir aside and
    # forces a re-run rather than silently adopting another backend's verdicts.
    # Run AFTER the checkpoint.dir override above.
    analyze_fp = _analyze_fingerprint(binding)
    checkpoint.sync_identity(analyze_fp)
    # Preserve a prior scan's final report before this run overwrites it.
    _archive_stale_results(output_dir, analyze_fp["key_digest"])

    # JSON corrector inherits the analyze binding so correction calls
    # route through the same provider+model.
    json_corrector = JSONCorrector(binding)

    # Load application context if provided
    app_context = None
    if app_context_path and HAS_APP_CONTEXT and os.path.exists(app_context_path):
        app_context = load_context(Path(app_context_path))
        print(f"[Analyze] App context: {app_context.application_type}", file=sys.stderr)

    # Load dataset
    print(f"[Analyze] Loading dataset: {dataset_path}", file=sys.stderr)
    dataset = read_json(dataset_path)
    units = dataset.get("units", [])

    # Diff filter: if upstream parse stamped diff_selected on units (PR-diff
    # mode), drop the unselected ones. Pre-diff datasets have no field and
    # are processed unchanged.
    if any("diff_selected" in u for u in units):
        _pre = len(units)
        units = [u for u in units if u.get("diff_selected")]
        print(f"[Analyze] Diff filter: {_pre} -> {len(units)} units", file=sys.stderr)

    # Optional: filter by enhancement security classification
    if exploitable_filter:
        original_count = len(units)
        if exploitable_filter == "strict":
            keep = ("exploitable",)
        else:  # "all" — default when filtering is enabled
            keep = ("exploitable", "vulnerable_internal")
        # Read classification mode-agnostically (agent_context OR llm_context)
        # so single-shot-enhanced datasets are not silently dropped.
        classified = sum(1 for u in units if _unit_security_classification(u) is not None)
        units = [u for u in units if _unit_security_classification(u) in keep]
        # Loud guard: a filter that matches nothing because the dataset carries
        # NO classifications at all is almost always an un-enhanced / wrong-mode
        # input, not a genuine "0 exploitable units" result. Warn instead of
        # silently returning an empty analysis.
        if original_count and classified == 0:
            print(
                f"[Analyze] WARNING: --exploitable filter ({exploitable_filter}) "
                f"requested but NONE of the {original_count} units carry a "
                "security_classification (run `enhance` first; single-shot mode "
                "must populate llm_context.security_classification). "
                "Filter matched 0 units.",
                file=sys.stderr,
            )
        print(f"[Analyze] Exploitable filter ({exploitable_filter}): {original_count} -> {len(units)} units", file=sys.stderr)

    if limit:
        # Priority-sort before truncating so a --limit run keeps the most
        # security-relevant units rather than the alphabetically-first ones.
        units = _apply_limit(units, limit)

    total = len(units)
    print(f"[Analyze] Analyzing {total} units...", file=sys.stderr)

    # Initialize summary tracking for _summary.json
    # Count checkpointed units to seed the counters and sum existing usage
    _existing = checkpoint.load()
    _summary_error_breakdown = {}
    # #293 adjudication: analyze has NO third state — "inconclusive" is a
    # first-class COMPLETED verdict (verdict_taxonomy FINDING_VERDICT_ORDER;
    # the Stage-1 prompt's own enum), not a degenerate no-verdict marker like
    # verify's verification.incomplete or enhance's INCOMPLETE_CLASSIFICATION.
    # The third bucket stays 0 here but is still emitted for shape consistency.
    _summary_incomplete = 0
    _seed = _seed_summary(_existing)
    _summary_completed = _seed["completed"]
    _summary_errors = 0  # errored rows are re-analyzed; _summary_callback owns them
    _summary_input_tokens = _seed["input_tokens"]
    _summary_output_tokens = _seed["output_tokens"]
    _summary_cost_usd = _seed["cost_usd"]
    _summary_unpriced: set[str] = _seed["unpriced_models"]

    def _usage_dict():
        usage = {"input_tokens": _summary_input_tokens,
                 "output_tokens": _summary_output_tokens,
                 "cost_usd": round(_summary_cost_usd, 6)}
        # #216: persist the unpriced set into _summary.json so a resume of
        # a resume keeps the marker (run-cumulative semantics).
        _all_unpriced = set(_summary_unpriced) | set(
            get_global_tracker().get_totals().get("unpriced_models") or [])
        if _all_unpriced:
            usage["cost_incomplete"] = True
            usage["unpriced_models"] = sorted(_all_unpriced)
        return usage

    # Inject prior usage into tracker so step_report captures the total
    if _summary_input_tokens or _summary_output_tokens or _summary_unpriced:
        get_global_tracker().add_prior_usage(
            _summary_input_tokens, _summary_output_tokens, _summary_cost_usd)
        # #281: re-snapshot the phase baseline AFTER the injection — the
        # pre-injection baseline made the "Stage 1" delta include the prior
        # session's tokens/cost (calls exclude restored units while
        # tokens/cost included them: an internally inconsistent line, and
        # #214's "this phase's delta" contract broken on resumed runs).
        # The step reports' totals still include the prior usage (the
        # run-total contract); only the per-phase stderr line is the delta.
        _phase_baseline = tracking.get_usage()

    # Write initial summary
    checkpoint.write_summary(total, _summary_completed, _summary_errors,
                             _summary_error_breakdown, phase="in_progress",
                             usage=_usage_dict(), incomplete=_summary_incomplete)

    def _summary_callback(finding, usage=None):
        """Update summary counters after each unit. Called from main thread."""
        nonlocal _summary_completed, _summary_incomplete, _summary_errors
        nonlocal _summary_error_breakdown
        nonlocal _summary_input_tokens, _summary_output_tokens, _summary_cost_usd
        if finding == "error":
            _summary_errors += 1
            _summary_error_breakdown["api"] = _summary_error_breakdown.get("api", 0) + 1
        else:
            # #293 adjudication: "inconclusive"/"insufficient_context" are
            # completed verdicts (taxonomy), not incomplete — no third state.
            _summary_completed += 1
        if usage:
            _summary_input_tokens += usage.get("input_tokens", 0)
            _summary_output_tokens += usage.get("output_tokens", 0)
            _summary_cost_usd += usage.get("cost_usd", 0.0)
        checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                 _summary_error_breakdown, phase="in_progress",
                                 usage=_usage_dict(), incomplete=_summary_incomplete)

    # --- Stage 1: Detection ---
    results, code_by_route = _run_detection(
        units, binding, json_corrector, app_context, workers, checkpoint=checkpoint,
        summary_callback=_summary_callback,
    )

    # Auto-retry failed units with transient errors (rate limit, connection, timeout, 5xx)
    retryable_indices = [
        i for i, r in enumerate(results)
        if r and is_retryable_error(r.get("error"))
    ]
    if retryable_indices:
        rate_limiter = get_rate_limiter()
        backoff = rate_limiter.time_until_ready()
        if backoff > 0:
            print(f"[Analyze] Retrying {len(retryable_indices)} failed units "
                  f"(waiting {backoff:.0f}s for rate limit to clear)...", file=sys.stderr)
            rate_limiter.wait_if_needed()
        else:
            print(f"[Analyze] Retrying {len(retryable_indices)} failed units (transient errors)...",
                  file=sys.stderr)

        # Retry sequentially to avoid re-triggering rate limit
        for i in retryable_indices:
            unit = units[i]
            out = _process_unit(binding, unit, i, json_corrector, app_context)
            results[i] = out["result"]
            code_by_route[out["route_key"]] = out["code_for_route"]

            # Update summary: retry produced a verdict → flip error to
            # completed (#293 adjudication: inconclusive is a completed
            # verdict; analyze has no third state)
            if out["finding"] != "error":
                _summary_errors = max(0, _summary_errors - 1)
                _summary_completed += 1
            retry_usage = out.get("usage", {})
            _summary_input_tokens += retry_usage.get("input_tokens", 0)
            _summary_output_tokens += retry_usage.get("output_tokens", 0)
            _summary_cost_usd += retry_usage.get("cost_usd", 0.0)
            checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                     _summary_error_breakdown, phase="in_progress",
                                     usage=_usage_dict(), incomplete=_summary_incomplete)

            # Update checkpoint
            if checkpoint is not None:
                uid = out["result"].get("unit_id", f"unit_{i}")
                cp_data = {
                    "result": out["result"],
                    "route_key": out["route_key"],
                    "code_for_route": out["code_for_route"],
                }
                if out.get("usage"):
                    cp_data["usage"] = out["usage"]
                checkpoint.save(uid, cp_data)

            print(f"  Retry {i+1}/{len(retryable_indices)}: {out['finding']} (retry)",
                  file=sys.stderr, flush=True)

    # Write final summary with phase="done"
    checkpoint.write_summary(total, _summary_completed, _summary_errors,
                             _summary_error_breakdown, phase="done",
                             usage=_usage_dict(), incomplete=_summary_incomplete)

    tracking.log_usage("Stage 1", _phase_baseline)

    # Compute verdict counts from results
    counts = _count_verdicts(results)

    # --- Stage 1 Consistency Check ---
    consistency_corrections = 0
    try:
        from utilities.stage1_consistency import run_stage1_consistency_check
        print("\n[Analyze] Running consistency check...", file=sys.stderr)
        results = run_stage1_consistency_check(results, code_by_route, binding, get_global_tracker())
        # Count corrections
        for r in results:
            if r.get("stage1_consistency_update"):
                consistency_corrections += 1
        if consistency_corrections:
            print(f"  Consistency corrections: {consistency_corrections}", file=sys.stderr)
            counts = _count_verdicts(results)
    except ImportError:
        print("[Analyze] Stage 1 consistency check not available, skipping.", file=sys.stderr)
    except Exception as e:
        print(f"[Analyze] Consistency check error (non-fatal): {e}", file=sys.stderr)

    # --- Write results ---
    results_path = os.path.join(output_dir, "results.json")
    experiment_result = {
        "dataset": os.path.basename(dataset_path),
        "model": binding.model,
        "provider": binding.provider_name,
        "timestamp": datetime.now().isoformat(),
        "metrics": {
            "total": len(units),
            **counts,
        },
        "results": results,
        "code_by_route": code_by_route,
        # Stamp the analyze-phase KEY digest so (a) a later re-scan with a
        # different config archives this report instead of overwriting it, and
        # (b) the verify phase can fold it into its own adopt-gate KEY — an
        # analyze-model/provider/template swap regenerates this digest and
        # thereby invalidates any verify checkpoints produced against the old
        # analyze run (closes the verify-overwrite corruption). Deterministic +
        # persisted → zero re-pay.
        "analyze_fingerprint": analyze_fp["key_digest"],
    }

    write_json(results_path, experiment_result)
    print(f"\n[Analyze] Results written to {results_path}", file=sys.stderr)

    # Checkpoints are preserved as a permanent artifact alongside results.
    # Final summary (phase="done") was already written before result writing.

    # Build return value
    usage = tracking.get_usage()
    metrics = AnalysisMetrics(
        total=len(units),
        vulnerable=counts["vulnerable"],
        bypassable=counts["bypassable"],
        inconclusive=counts["inconclusive"],
        protected=counts["protected"],
        safe=counts["safe"],
        errors=counts["errors"],
    )

    return AnalyzeResult(
        results_path=results_path,
        metrics=metrics,
        usage=usage,
    )
