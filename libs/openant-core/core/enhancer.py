"""
Context enhancement wrapper.

Wraps utilities/context_enhancer.py, providing a path-based interface
for both agentic and single-shot enhancement modes.

Checkpoints are always enabled for agentic mode. Per-unit progress is saved
to ``{output_dir}/enhance_checkpoints/`` so interrupted runs can resume
automatically. On successful completion the checkpoint dir is removed.
"""

import json
import os
import sys

from core.schemas import EnhanceResult, UsageInfo
from core import tracking
from core.progress import ProgressReporter
from utilities.rate_limiter import configure_rate_limiter


def enhance_dataset(
    dataset_path: str,
    output_path: str,
    analyzer_output_path: str | None = None,
    repo_path: str | None = None,
    mode: str = "agentic",
    checkpoint_path: str | None = None,
    model: str = "sonnet",
    workers: int = 8,
    backoff_seconds: int = 30,
) -> EnhanceResult:
    """Enhance a parsed dataset with security context.

    Args:
        dataset_path: Path to dataset.json from the parse step.
        output_path: Path to write the enhanced dataset.
        analyzer_output_path: Path to analyzer_output.json (required for agentic mode).
        repo_path: Path to the repository (required for agentic mode).
        mode: "agentic" (thorough, tool-use) or "single-shot" (fast, cheaper).
        checkpoint_path: Path to save/resume checkpoint (agentic mode only).
            If None, auto-derived from output_path.
        model: "sonnet" (default, cost-effective).
        workers: Number of parallel workers (default: 8).
        backoff_seconds: Seconds to wait on rate limit before retry (default: 30).

    Returns:
        EnhanceResult with output path, stats, and usage.
    """
    # Configure global rate limiter
    configure_rate_limiter(backoff_seconds=float(backoff_seconds))

    model_id = "claude-sonnet-4-20250514" if model == "sonnet" else "claude-opus-4-6"
    print(f"[Enhance] Mode: {mode}", file=sys.stderr)
    print(f"[Enhance] Model: {model_id}", file=sys.stderr)

    # Auto-derive checkpoint path for agentic mode
    if mode == "agentic" and checkpoint_path is None:
        output_dir = os.path.dirname(os.path.abspath(output_path))
        checkpoint_path = os.path.join(output_dir, "enhance_checkpoints")

    # Import here to avoid heavy imports at module load
    from utilities.llm_client import AnthropicClient, get_global_tracker
    from utilities.context_enhancer import ContextEnhancer

    tracker = get_global_tracker()
    client = AnthropicClient(model=model_id, tracker=tracker)
    enhancer = ContextEnhancer(client=client, tracker=tracker)

    # Load dataset
    print(f"[Enhance] Loading dataset: {dataset_path}", file=sys.stderr)
    with open(dataset_path) as f:
        dataset = json.load(f)

    units = dataset.get("units", [])
    print(f"[Enhance] Units to enhance: {len(units)}", file=sys.stderr)

    # Set up progress reporter
    progress = ProgressReporter("Enhance", len(units), tracker=tracker)

    def _on_unit_done(unit_id: str, classification: str, unit_elapsed: float):
        progress.report(
            unit_label=unit_id,
            detail=classification,
            unit_elapsed=unit_elapsed,
        )

    def _on_restored(count: int):
        progress.completed = count

    # Run enhancement
    if mode == "agentic":
        if not analyzer_output_path:
            raise ValueError("Agentic mode requires --analyzer-output")

        enhanced = enhancer.enhance_dataset_agentic(
            dataset=dataset,
            analyzer_output_path=analyzer_output_path,
            repo_path=repo_path,
            checkpoint_path=checkpoint_path,
            progress_callback=_on_unit_done,
            restored_callback=_on_restored,
            workers=workers,
        )
    elif mode == "single-shot":
        enhanced = enhancer.enhance_dataset(
            dataset,
            progress_callback=_on_unit_done,
            workers=workers,
        )
    else:
        raise ValueError(f"Unknown enhancement mode: {mode}. Use 'agentic' or 'single-shot'.")

    progress.finish()

    # Compute classification distribution and error summary FIRST (before cleanup decision)
    classifications = {}
    error_count = 0
    error_summary = {}
    context_key = "agent_context" if mode == "agentic" else "llm_context"

    for unit in enhanced.get("units", []):
        ctx = unit.get(context_key, {})
        if ctx.get("error"):
            error_count += 1
            err = ctx["error"]
            if isinstance(err, dict):
                err_type = err.get("type", "unknown")
            else:
                err_type = "legacy_string"
            error_summary[err_type] = error_summary.get(err_type, 0) + 1
            continue
        cls = ctx.get("security_classification", "unknown")
        classifications[cls] = classifications.get(cls, 0) + 1

    # Checkpoints are preserved as a permanent artifact alongside results.
    # Final summary (phase="done") is written by context_enhancer.

    # Write enhanced dataset
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(enhanced, f, indent=2)

    print(f"[Enhance] Enhanced dataset: {output_path}", file=sys.stderr)
    print(f"[Enhance] Classifications: {classifications}", file=sys.stderr)
    if error_count:
        print(f"[Enhance] Errors: {error_count} ({error_summary})", file=sys.stderr)

    tracking.log_usage("Enhance")

    usage = tracking.get_usage()

    return EnhanceResult(
        enhanced_dataset_path=output_path,
        units_enhanced=len(units) - error_count,
        error_count=error_count,
        error_summary=error_summary,
        classifications=classifications,
        usage=usage,
    )
