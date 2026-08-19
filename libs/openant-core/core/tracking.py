"""
Usage tracking wrapper.

Exposes the existing TokenTracker from utilities/llm_client.py
with scan-level summary and stderr logging.
"""

import sys

from utilities.llm_client import get_global_tracker, reset_global_tracker
from core.schemas import UsageInfo


def reset_tracking():
    """Reset the global token tracker for a new scan."""
    reset_global_tracker()


def get_usage() -> UsageInfo:
    """Get current usage as a UsageInfo dataclass."""
    tracker = get_global_tracker()
    totals = tracker.get_totals()
    return UsageInfo(
        total_calls=totals["total_calls"],
        total_input_tokens=totals["total_input_tokens"],
        total_output_tokens=totals["total_output_tokens"],
        total_tokens=totals["total_tokens"],
        total_cost_usd=totals["total_cost_usd"],
    )


def log_usage(prefix: str = "", baseline: "UsageInfo | None" = None):
    """Log a usage summary to stderr.

    With ``baseline`` (a ``get_usage()`` snapshot taken at the phase's start),
    the line reports THIS PHASE's delta instead of the cumulative run totals.
    The per-phase callers ("Stage 1"/"Stage 2"/"Enhance") log the global
    cumulative tracker, so a "Stage 2:" line summed every prior phase and
    overstated the phase's own calls/tokens/cost (#214). Without a baseline the
    behaviour is unchanged (cumulative).
    """
    usage = get_usage()
    if baseline is not None:
        calls = usage.total_calls - baseline.total_calls
        tokens = usage.total_tokens - baseline.total_tokens
        cost = usage.total_cost_usd - baseline.total_cost_usd
    else:
        calls, tokens, cost = (
            usage.total_calls, usage.total_tokens, usage.total_cost_usd,
        )
    label = f"{prefix}: " if prefix else ""
    print(
        f"  {label}{calls} API calls, {tokens:,} tokens, ${cost:.4f}",
        file=sys.stderr,
    )
