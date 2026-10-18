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
        # .get (the #216 read pattern): a stubbed/old get_totals shape
        # lacks the key — the honest zero, never a KeyError.
        total_turns=totals.get("total_turns", 0),
        total_input_tokens=totals["total_input_tokens"],
        total_output_tokens=totals["total_output_tokens"],
        total_tokens=totals["total_tokens"],
        total_cost_usd=totals["total_cost_usd"],
        cost_incomplete=totals.get("cost_incomplete", False),
        unpriced_models=totals.get("unpriced_models", []),
        total_cache_read_tokens=totals.get("total_cache_read_tokens", 0),
        total_cache_write_tokens=totals.get("total_cache_write_tokens", 0),
        unpriced_cache_models=totals.get("unpriced_cache_models", []),
    )


def cost_marker(usage: "UsageInfo | dict") -> str:
    """#786: the human-line completeness marker for an unpriced run.

    The #616/#663 rule — an unpriced cost must read incomplete, never as a
    complete-looking figure — is carried by every machine channel
    (``cost_incomplete`` + ``unpriced_models`` on UsageInfo / the totals
    dict); this renders it on the human lines. Accepts a ``UsageInfo`` or a
    totals/usage ``dict`` (both spellings exist across the callers); returns
    "" when the flag is clear, so a fully-priced run's lines are unchanged.
    """
    if isinstance(usage, dict):
        incomplete = bool(usage.get("cost_incomplete", False))
        models = usage.get("unpriced_models") or []
    else:
        incomplete = bool(getattr(usage, "cost_incomplete", False))
        models = list(getattr(usage, "unpriced_models", None) or [])
    if not incomplete:
        return ""
    n = len(models) if models else 1
    return f" (incomplete: {n} unpriced model(s) — an under-count)"


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
        turns = usage.total_turns - baseline.total_turns
        tokens = usage.total_tokens - baseline.total_tokens
        cost = usage.total_cost_usd - baseline.total_cost_usd
    else:
        calls, turns, tokens, cost = (
            usage.total_calls, usage.total_turns,
            usage.total_tokens, usage.total_cost_usd,
        )
    label = f"{prefix}: " if prefix else ""
    # #624: the line names BOTH populations — the completions the records
    # cover (turns; one per single completion, the billed turns per
    # conversation) and the records themselves. The old "N API calls"
    # label lied per phase (enhance records units; single-shot records
    # completions; the verifier records conversations). Exclusions,
    # stated: SDK-internal HTTP retries, raising turns that billed
    # nothing, KeyboardInterrupt'd turns, add_prior_usage-injected
    # summary spend, and the threat-model repo-explorer loop (which
    # records nothing to the tracker at all — a named follow-up) all lie
    # outside the counts (tracker-observed, not network claims).
    # #786 (T1 rounds 1+2, F1->F-B): the phase line's marker. The per-phase
    # unpriced ledger does not exist (the tracker's set only GROWS — a model
    # unpriced before the baseline and dispatched again this phase can never
    # appear in a set difference), so the delta arithmetic both over-reports
    # (a fully-priced phase after an unpriced one) and UNDER-reports (the
    # re-spending case — the #616 violation). The honest conservative form:
    # when the RUN's cost is incomplete, the phase figure is not provably
    # complete — say that, never asserting the phase figure itself is an
    # under-count (the run-scoped note), never claiming completeness.
    if baseline is None:
        marker = cost_marker(usage)
    else:
        unpriced = {m for m in (getattr(usage, "unpriced_models", None) or [])}
        marker = ("" if not unpriced else
                  f" (run cost incomplete: {len(unpriced)} unpriced "
                  f"model(s) — this phase's figure may exclude their spend)")
    print(
        f"  {label}{turns} completions ({calls} records), "
        f"{tokens:,} tokens, ${cost:.4f}{marker}",
        file=sys.stderr,
    )
