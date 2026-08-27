"""
Token tracker.

This module used to host the ``AnthropicClient`` wrapper plus its pricing
table. Issue #65 moved actual LLM IO to the pluggable
:mod:`utilities.llm` package (one adapter per provider, behind a
unified Protocol). What's left here is the cross-thread
:class:`TokenTracker` that adapters call ``record_call`` on — kept in
its own module because the pipeline records prior usage on resume and
several layers depend on the singleton accessor.

Classes:
    TokenTracker: Tracks token usage and costs across LLM calls

Usage:
    from utilities.llm_client import TokenTracker, get_global_tracker

    tracker = get_global_tracker()
    print(f"Total cost: ${tracker.total_cost_usd:.4f}")
"""

import importlib
import sys
import threading

from core.model_registry import pricing_map


# Pricing per million tokens. LEGACY fallback: issue #65 moved pricing onto
# each adapter, and ``config/models.json`` (read by core.model_registry) is now
# the source of truth for BOTH the adapters and this global. ``MODEL_PRICING``
# still backstops call sites that don't pass an adapter-provided ``pricing``
# (record_call's fallback, report/generator) and the drift guard, but it is
# served LAZILY from the registry via module ``__getattr__`` below — never a
# frozen import-time snapshot — so it can neither drift from the adapter table
# nor price from a stale copy, and a missing config fails LOUD at first use
# instead of pricing every model at $0. Retired/unknown ids are omitted
# (lookup miss -> warn + $0).


def __getattr__(name: str):
    # PEP 562 hook: resolve MODEL_PRICING on demand. Fires for attribute access
    # and ``from utilities.llm_client import MODEL_PRICING`` — but NOT for a bare
    # ``MODEL_PRICING`` reference inside this module, which is why record_call
    # calls ``pricing_map("anthropic")`` directly.
    if name == "MODEL_PRICING":
        return pricing_map("anthropic")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

_unknown_pricing_warned: set[str] = set()
_unknown_pricing_lock = threading.Lock()


def _warn_unknown_pricing(model: str) -> None:
    """Emit a one-time stderr warning the first time we cost an unknown model."""
    with _unknown_pricing_lock:
        if model in _unknown_pricing_warned:
            return
        _unknown_pricing_warned.add(model)
    sys.stderr.write(
        f"warning: no pricing for model {model!r}; cost will be reported as $0. "
        f"Add it to config/models.json (the shared model registry) for accurate totals.\n"
    )


class TokenTracker:
    """
    Tracks token usage and costs across LLM calls.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._thread_local = threading.local()
        self.reset()

    def reset(self):
        """Reset all counters."""
        with self._lock:
            self.calls = []
            self.total_input_tokens = 0
            self.total_output_tokens = 0
            self.total_cost_usd = 0.0
            # #216: models dispatched without a pricing record (their cost
            # contributes $0 — the run's cost figure is incomplete).
            self._unpriced_models: set[str] = set()

    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output)."""
        return self.total_input_tokens + self.total_output_tokens

    def record_call(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        *,
        pricing: dict[str, float] | None = None,
        usage_details: dict | list | None = None,
    ) -> dict:
        """
        Record a single LLM call.

        Args:
            model: Model identifier.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            pricing: Optional ``{"input": $/Mtok, "output": $/Mtok}``
                from the adapter that made the call. When provided,
                this is authoritative — adapters own their rates per
                issue #65. When omitted, we fall back to the legacy
                global ``MODEL_PRICING`` so call sites that haven't
                been threaded through yet still produce a number
                (with a one-time stderr warning on miss). New code
                should always pass ``pricing`` via
                ``binding.adapter.pricing.get(binding.model)``.
            usage_details: Pass-through capture (#211): provider-supplied
                billing-relevant DETAIL fields (reasoning tokens; cache
                read/write tokens) VERBATIM — a dict for a single call,
                or a list of per-turn dicts for an agentic loop. Stored
                on the call record for reconciliation against a provider
                bill; NEVER summed into totals and NEVER in the cost
                formula (whether a provider's ``completion_tokens``
                already includes reasoning differs by route — summing
                would double-count on including routes).

        Returns:
            Dict with call details including cost.
        """
        if pricing is None:
            pricing = pricing_map("anthropic").get(model)
        if pricing is None:
            _warn_unknown_pricing(model)
            total_cost = 0.0
            # #216: an unpriced-but-dispatched model must be LOUD in the
            # artifacts, not just stderr — record it so get_totals exposes
            # cost_incomplete + unpriced_models (flows to UsageInfo → step
            # reports → scan.report.json).
            with self._lock:
                self._unpriced_models.add(model)
            tl = self._thread_local
            if hasattr(tl, "unit_unpriced"):
                tl.unit_unpriced.add(model)
        else:
            input_cost = (input_tokens / 1_000_000) * pricing["input"]
            output_cost = (output_tokens / 1_000_000) * pricing["output"]
            total_cost = input_cost + output_cost

        call_record = {
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round(total_cost, 6),
            # #211 pass-through capture: stored VERBATIM (absent when the
            # provider supplied none — never a fabricated empty dict; in the
            # per-turn list form, turns without details appear as None
            # ENTRIES), never summed into the totals below, never in cost.
            **({"usage_details": usage_details} if usage_details is not None else {}),
        }

        # Update totals (thread-safe)
        with self._lock:
            self.calls.append(call_record)
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += total_cost

        # Accumulate to thread-local unit tracking if active
        tl = self._thread_local
        if hasattr(tl, "unit_input"):
            tl.unit_input += input_tokens
            tl.unit_output += output_tokens
            tl.unit_cost += total_cost

        return call_record

    def add_prior_usage(self, input_tokens: int, output_tokens: int, cost_usd: float,
                        unpriced_models: list[str] | None = None):
        """Inject usage from a prior run (e.g. restored checkpoints).

        This ensures step reports capture the total cost across all runs,
        not just the current run's API calls. ``unpriced_models`` restores
        the #216 incomplete-cost marker across a resume (the tracker resets
        per process; without this, a resumed run's cost silently looks
        complete again).
        """
        with self._lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += cost_usd
            if unpriced_models:
                self._unpriced_models.update(unpriced_models)

    def start_unit_tracking(self):
        """Start tracking usage for the current unit on this thread.

        Call before processing a unit, then call ``get_unit_usage()``
        after to get the accumulated usage for just that unit. Thread-safe
        because each thread has its own ``threading.local()`` storage.
        """
        tl = self._thread_local
        tl.unit_input = 0
        tl.unit_output = 0
        tl.unit_cost = 0.0
        tl.unit_unpriced: set[str] = set()

    def get_unit_usage(self) -> dict:
        """Return usage accumulated since ``start_unit_tracking()`` on this thread."""
        tl = self._thread_local
        usage = {
            "input_tokens": getattr(tl, "unit_input", 0),
            "output_tokens": getattr(tl, "unit_output", 0),
            "cost_usd": round(getattr(tl, "unit_cost", 0.0), 6),
        }
        # #216: the unit's own unpriced models — persisted into the unit's
        # checkpoint record so a resume restores the incomplete-cost marker.
        unpriced = getattr(tl, "unit_unpriced", set())
        if unpriced:
            usage["cost_incomplete"] = True
            usage["unpriced_models"] = sorted(unpriced)
        return usage

    def get_summary(self) -> dict:
        """
        Get summary of all tracked calls.

        Returns:
            Dict with totals and per-call breakdown
        """
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                # #216: the cost figure is INCOMPLETE when any dispatched
                # model had no pricing (its tokens counted, its dollars $0).
                "cost_incomplete": bool(self._unpriced_models),
                "unpriced_models": sorted(self._unpriced_models),
                "calls": list(self.calls),
            }

    def get_totals(self) -> dict:
        """
        Get just the totals (without per-call breakdown).

        Returns:
            Dict with totals only
        """
        with self._lock:
            return {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                "cost_incomplete": bool(self._unpriced_models),
                "unpriced_models": sorted(self._unpriced_models),
            }


# Global tracker instance for session-wide tracking
_global_tracker = TokenTracker()


def get_global_tracker() -> TokenTracker:
    """Get the global token tracker instance."""
    return _global_tracker


def reset_warning_state() -> None:
    """Clear all one-time-warning memory so a fresh scan (or test) re-warns.

    The pricing-warning set here plus each adapter's warn sets (unknown
    stop/finish reasons, dropped block kinds, malformed tool JSON) are
    intentionally process-global, so production prints one line per
    novel value. Tests asserting "warned once" — and a brand-new scan —
    want a clean slate. Adapter modules are imported lazily and guarded
    so this stays safe even if a provider SDK isn't installed.
    """
    with _unknown_pricing_lock:
        _unknown_pricing_warned.clear()
    for modname in ("anthropic", "openai", "google"):
        try:
            mod = importlib.import_module(f"utilities.llm.providers.{modname}")
        except Exception:
            continue
        reset = getattr(mod, "reset_warnings", None)
        if callable(reset):
            reset()


def reset_global_tracker():
    """Reset the global token tracker (and one-time-warning state)."""
    _global_tracker.reset()
    reset_warning_state()


# NOTE: the ``AnthropicClient`` class that used to live here was deleted
# as part of issue #65. Every call site now goes through
# :mod:`utilities.llm` (Protocol-based adapter layer). See
# ``docs/features/llm-providers/plan.wip.md`` for the migration map.
