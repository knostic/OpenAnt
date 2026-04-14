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
from core.checkpoint import StepCheckpoint
from core.progress import ProgressReporter

# Import existing analysis machinery
from utilities.llm_client import AnthropicClient, get_global_tracker
from utilities.json_corrector import JSONCorrector
from utilities.rate_limiter import get_rate_limiter, is_rate_limit_error, is_retryable_error

# Reuse the core analysis functions from experiment.py
from experiment import (
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


def _process_unit(client, unit, index, json_corrector, app_context):
    """Process a single unit for Stage 1 detection.

    Returns a dict with all result data. Does not mutate shared state.
    """
    uid = unit.get("id", f"unit_{index}")
    start = time.monotonic()
    tracker = get_global_tracker()
    tracker.start_unit_tracking()

    try:
        result = analyze_unit(
            client, unit,
            use_multifile=True,
            json_corrector=json_corrector,
            app_context=app_context,
        )

        # Ensure unit_id is always present
        result["unit_id"] = uid

        # Ensure finding field is always set (may be None after JSON correction)
        if not result.get("finding") and result.get("verdict"):
            result["finding"] = result["verdict"].lower()

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


def _run_detection(units, client, json_corrector, app_context, workers,
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

    def _cp_is_error(cp_data):
        res = cp_data.get("result", {}) if cp_data else {}
        return res.get("verdict") == "ERROR" or res.get("finding") == "error"

    for i, unit in enumerate(units):
        uid = unit.get("id", f"unit_{i}")
        cp_data = checkpointed.get(uid)
        if cp_data and not _cp_is_error(cp_data):
            results[i] = cp_data.get("result", {})
            code_by_route[cp_data.get("route_key", uid)] = cp_data.get("code_for_route", "")
        else:
            units_to_process.append((i, unit))

    def _process_and_save(i, unit):
        out = _process_unit(client, unit, i, json_corrector, app_context)
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
            print("[Detect] Interrupted — progress saved to checkpoints",
                  file=sys.stderr, flush=True)
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
        print("[Detect] Progress saved to checkpoints",
              file=sys.stderr, flush=True)
    else:
        executor.shutdown(wait=False)

    progress.finish()

    return results, code_by_route


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
        finding = r.get("finding", r.get("verdict", "error").lower())
        if finding in counts:
            counts[finding] += 1
        elif r.get("verdict") == "ERROR":
            counts["errors"] += 1
    return counts


def run_analysis(
    dataset_path: str,
    output_dir: str,
    analyzer_output_path: str | None = None,
    app_context_path: str | None = None,
    repo_path: str | None = None,
    limit: int | None = None,
    model: str = "opus",
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
        model: "opus" or "sonnet".
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
    os.makedirs(output_dir, exist_ok=True)

    # Configure global rate limiter
    from utilities.rate_limiter import configure_rate_limiter
    configure_rate_limiter(backoff_seconds=float(backoff_seconds))

    # Set up checkpoint
    if checkpoint_path is None:
        checkpoint_path = os.path.join(output_dir, "analyze_checkpoints")
    checkpoint = StepCheckpoint("Analyze", output_dir)
    checkpoint.dir = checkpoint_path

    # Select model
    model_id = "claude-opus-4-6" if model == "opus" else "claude-sonnet-4-20250514"
    print(f"[Analyze] Model: {model_id}", file=sys.stderr)

    # Initialize client
    client = AnthropicClient(model=model_id)

    # Initialize JSON corrector
    json_corrector = JSONCorrector(client)

    # Load application context if provided
    app_context = None
    if app_context_path and HAS_APP_CONTEXT and os.path.exists(app_context_path):
        app_context = load_context(Path(app_context_path))
        print(f"[Analyze] App context: {app_context.application_type}", file=sys.stderr)

    # Load dataset
    print(f"[Analyze] Loading dataset: {dataset_path}", file=sys.stderr)
    with open(dataset_path) as f:
        dataset = json.load(f)

    units = dataset.get("units", [])

    # Optional: filter by enhancement security classification
    if exploitable_filter:
        original_count = len(units)
        if exploitable_filter == "strict":
            keep = ("exploitable",)
        else:  # "all" — default when filtering is enabled
            keep = ("exploitable", "vulnerable_internal")
        units = [
            u for u in units
            if u.get("agent_context", {}).get("security_classification") in keep
        ]
        print(f"[Analyze] Exploitable filter ({exploitable_filter}): {original_count} -> {len(units)} units", file=sys.stderr)

    if limit:
        units = units[:limit]

    total = len(units)
    print(f"[Analyze] Analyzing {total} units...", file=sys.stderr)

    # Initialize summary tracking for _summary.json
    # Count checkpointed units to seed the counters and sum existing usage
    _existing = checkpoint.load()
    _summary_completed = 0
    _summary_errors = 0
    _summary_error_breakdown = {}
    _summary_input_tokens = 0
    _summary_output_tokens = 0
    _summary_cost_usd = 0.0
    for _uid, _cp in _existing.items():
        _r = _cp.get("result", {})
        if _r.get("verdict") == "ERROR" or _r.get("finding") == "error":
            _summary_errors += 1
            _summary_error_breakdown["api"] = _summary_error_breakdown.get("api", 0) + 1
        else:
            _summary_completed += 1
        _cp_usage = _cp.get("usage", {})
        _summary_input_tokens += _cp_usage.get("input_tokens", 0)
        _summary_output_tokens += _cp_usage.get("output_tokens", 0)
        _summary_cost_usd += _cp_usage.get("cost_usd", 0.0)

    def _usage_dict():
        return {"input_tokens": _summary_input_tokens,
                "output_tokens": _summary_output_tokens,
                "cost_usd": round(_summary_cost_usd, 6)}

    # Inject prior usage into tracker so step_report captures the total
    if _summary_input_tokens or _summary_output_tokens:
        tracker.add_prior_usage(
            _summary_input_tokens, _summary_output_tokens, _summary_cost_usd)

    # Write initial summary
    checkpoint.write_summary(total, _summary_completed, _summary_errors,
                             _summary_error_breakdown, phase="in_progress",
                             usage=_usage_dict())

    def _summary_callback(finding, usage=None):
        """Update summary counters after each unit. Called from main thread."""
        nonlocal _summary_completed, _summary_errors, _summary_error_breakdown
        nonlocal _summary_input_tokens, _summary_output_tokens, _summary_cost_usd
        if finding == "error":
            _summary_errors += 1
            _summary_error_breakdown["api"] = _summary_error_breakdown.get("api", 0) + 1
        else:
            _summary_completed += 1
        if usage:
            _summary_input_tokens += usage.get("input_tokens", 0)
            _summary_output_tokens += usage.get("output_tokens", 0)
            _summary_cost_usd += usage.get("cost_usd", 0.0)
        checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                 _summary_error_breakdown, phase="in_progress",
                                 usage=_usage_dict())

    # --- Stage 1: Detection ---
    results, code_by_route = _run_detection(
        units, client, json_corrector, app_context, workers, checkpoint=checkpoint,
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
            out = _process_unit(client, unit, i, json_corrector, app_context)
            results[i] = out["result"]
            code_by_route[out["route_key"]] = out["code_for_route"]

            # Update summary: retry succeeded → flip error to completed
            if out["finding"] != "error":
                _summary_errors = max(0, _summary_errors - 1)
                _summary_completed += 1
            retry_usage = out.get("usage", {})
            _summary_input_tokens += retry_usage.get("input_tokens", 0)
            _summary_output_tokens += retry_usage.get("output_tokens", 0)
            _summary_cost_usd += retry_usage.get("cost_usd", 0.0)
            checkpoint.write_summary(total, _summary_completed, _summary_errors,
                                     _summary_error_breakdown, phase="in_progress",
                                     usage=_usage_dict())

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
                             usage=_usage_dict())

    tracking.log_usage("Stage 1")

    # Compute verdict counts from results
    counts = _count_verdicts(results)

    # --- Stage 1 Consistency Check ---
    consistency_corrections = 0
    try:
        from utilities.stage1_consistency import run_stage1_consistency_check
        print("\n[Analyze] Running consistency check...", file=sys.stderr)
        results = run_stage1_consistency_check(results, code_by_route, get_global_tracker())
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
        "model": model_id,
        "timestamp": datetime.now().isoformat(),
        "metrics": {
            "total": len(units),
            **counts,
        },
        "results": results,
        "code_by_route": code_by_route,
    }

    with open(results_path, "w") as f:
        json.dump(experiment_result, f, indent=2)

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
