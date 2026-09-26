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


# Pricing per million tokens. Issue #65 moved pricing onto each adapter, and
# ``config/models.json`` (read by core.model_registry) is the source of truth
# for BOTH the adapters and this global. ``MODEL_PRICING`` remains for the
# drift guard and any legacy importers (#598: record_call's substitution
# fallback is DELETED — a missing price is the #216 loud path, never a
# substituted Anthropic rate), served LAZILY from the registry via module
# ``__getattr__`` below — never a frozen import-time snapshot — so it can
# neither drift from the adapter table nor price from a stale copy, and a
# missing config fails LOUD at first use. Retired/unknown ids are omitted
# (lookup miss -> warn + $0).


def __getattr__(name: str):
    # PEP 562 hook: resolve MODEL_PRICING on demand. Fires for attribute access
    # and ``from utilities.llm_client import MODEL_PRICING``. (#598: record_call
    # no longer touches the Anthropic map — the substitution is deleted; this
    # hook serves only the drift guard and legacy importers.)
    if name == "MODEL_PRICING":
        return pricing_map("anthropic")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

_unknown_pricing_warned: set[str] = set()
_unknown_pricing_lock = threading.Lock()
# #605: the accounting-failure counter — MODULE-LEVEL, never on the
# tracker (a poisoned tracker cannot be trusted to count its own failure).
# Read directly by core.step_report at step end; the get_totals() key is
# present-only (UsageInfo has no field — the marker reaches the step
# reports and the scan aggregate, not the typed usage envelope).
_accounting_errors = 0
_accounting_errors_lock = threading.Lock()


def record_accounting_error() -> None:
    """#605: count a silently-swallowed accounting failure (the report-phase
    tracker hand-off) — surfaced in get_totals() (present-only) and carried
    by the step reports' token_usage + the scan aggregate's OR (never a
    complete-looking artifact). NOTE: UsageInfo itself has no field; the
    marker flows through the step-report snapshots and the aggregate, not
    the CLI's typed usage envelope."""
    global _accounting_errors
    with _accounting_errors_lock:
        _accounting_errors += 1


def _accounting_error_count() -> int:
    with _accounting_errors_lock:
        return _accounting_errors


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

    #626 cache accounting: the provider-supplied cache usage fields
    (captured verbatim per #211) feed the cost formula AT THEIR OWN RATES
    when the model's pricing record carries cache multipliers
    (``cache_read`` / ``cache_write``, multipliers of the base input rate);
    they stay OUT of ``total_input_tokens`` for the EXCLUSIVE (anthropic)
    field shapes — disjoint line items. The INCLUSIVE shapes (openai's
    ``cached_tokens``, google's ``cached_content_token_count``) are already
    INSIDE the provider's input count: the COST formula subtracts the
    priced portion (never billed twice), while ``total_input_tokens``
    stays verbatim (the provider's own number — reconciliation is
    provider-dependent by design). Cache usage on
    a record WITHOUT multipliers marks the run ``cost_incomplete`` and
    names the model in ``unpriced_cache_models`` — a cached run must never
    read as a silently-cheap complete one.
    """

    # The cross-provider field shapes, normalized: every provider's
    # "tokens served from cache" and "tokens written to cache" spelling,
    # SPLIT BY INCLUSION SEMANTICS (F661-1, 2026-09-22): the anthropic/
    # bedrock fields are DISJOINT from the input count (input_tokens
    # excludes them); the openai/google fields are SUBSETS of it
    # (prompt_tokens / prompt_token_count already contain the cached
    # portion — pricing input as-is PLUS the cache line items bills the
    # cached tokens twice).
    _CACHE_READ_FIELDS_EXCLUSIVE = ("cache_read_input_tokens",)      # anthropic / bedrock
    _CACHE_READ_FIELDS_INCLUSIVE = ("cached_tokens",                 # openai / openrouter
                                    "cached_content_token_count")    # google
    _CACHE_WRITE_FIELDS_EXCLUSIVE = ("cache_creation_input_tokens",)  # anthropic / bedrock
    _CACHE_WRITE_FIELDS_INCLUSIVE = ("cache_write_tokens",)           # openrouter (inside prompt_tokens)
    # the union (the captured-verbatim normalization, unchanged)
    _CACHE_READ_FIELDS = _CACHE_READ_FIELDS_EXCLUSIVE + _CACHE_READ_FIELDS_INCLUSIVE
    _CACHE_WRITE_FIELDS = _CACHE_WRITE_FIELDS_EXCLUSIVE + _CACHE_WRITE_FIELDS_INCLUSIVE

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
            # #624: the turn total — one per-record count of the LLM
            # completions whose usage reached the tracker (a conversation
            # record carries its billed turns; a single completion
            # carries 1).
            self.total_turns = 0
            # #216: models dispatched without a pricing record (their cost
            # contributes $0 — the run's cost figure is incomplete).
            self._unpriced_models: set[str] = set()
            # #626: models whose cache usage appeared but whose pricing
            # record carries no cache multipliers (the cache portion is
            # unpriceable — incomplete, never $0-silent).
            self._unpriced_cache_models: set[str] = set()
            # #626: the cache line items (separate from input/output —
            # the billing-reconciliation totals).
            self.total_cache_read_tokens = 0
            self.total_cache_write_tokens = 0

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
        turns: int | None = None,
    ) -> dict:
        """
        Record a single LLM call.

        Args:
            model: Model identifier.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            pricing: Optional ``{"input": $/Mtok, "output": $/Mtok}``
                from the adapter that made the call — authoritative;
                adapters own their rates per issue #65. Every production
                call site passes ``pricing`` via
                ``binding.adapter.pricing.get(binding.model)``; a lookup
                miss (None) is UNKNOWN pricing and takes the #216 loud
                path (a one-time warning + $0 + cost_incomplete) — never
                a substituted rate (#598: the masquerade deleted).
            usage_details: Pass-through capture (#211): provider-supplied
                billing-relevant DETAIL fields (reasoning tokens; cache
                read/write tokens) VERBATIM — a dict for a single call,
                or a list of per-turn dicts for an agentic loop. Stored
                on the call record for reconciliation against a provider
                bill. #626 deliberately AMENDED the blanket exclusion for
                the CACHE fields: they price at their own multipliers.
                EXCLUSIVE shapes (anthropic) total as separate line items;
                INCLUSIVE shapes (openai/google) sit inside the input
                count — the cost formula subtracts the priced portion,
                the totals stay verbatim per provider. The REASONING fields remain outside
                the cost formula verbatim (whether a provider's
                ``completion_tokens`` already includes reasoning differs
                by route — summing would double-count on including
                routes).
            turns: #624 — the number of LLM completions this record
                covers: 1 (the default) for a single completion
                (``usage_details`` dict/None); REQUIRED for an agentic
                conversation record (``usage_details`` list) — the count
                of billed turns (the list length, including the ``None``
                entry for a raising turn that billed — #537/#609).
                A pure count: never in the cost formula (pricing is
                token-only), never injected by ``add_prior_usage`` (the
                resumed-run population matches ``total_calls``).

        Returns:
            Dict with call details including cost.
        """
        # #624: the guard runs FIRST — a contract-violating call (a
        # per-turn list without its turn declaration) must leave ZERO
        # tracker footprint (no unpriced-marker, no warning slot consumed,
        # no partial state).
        if isinstance(usage_details, list) and turns is None:
            raise ValueError(
                "record_call: usage_details is a per-turn list but "
                "turns was not passed — a conversation record must "
                "declare its billed-turn count (#624)")
        # #626: normalize the cache usage out of usage_details (dict or
        # per-turn list; None entries are absent turns by the #211 contract).
        cache_read = 0        # exclusive semantics (anthropic): NOT in input
        cache_write = 0       # exclusive semantics
        cache_read_incl = 0   # inclusive semantics (openai/google): already in input
        cache_write_incl = 0  # inclusive semantics
        _detail_rows = (usage_details if isinstance(usage_details, list)
                        else [usage_details])
        for _row in _detail_rows:
            if not isinstance(_row, dict):
                continue
            for _f in self._CACHE_READ_FIELDS_EXCLUSIVE:
                _v = _row.get(_f)
                if isinstance(_v, int) and _v > 0:
                    cache_read += _v
            for _f in self._CACHE_READ_FIELDS_INCLUSIVE:
                _v = _row.get(_f)
                if isinstance(_v, int) and _v > 0:
                    cache_read_incl += _v
            for _f in self._CACHE_WRITE_FIELDS_EXCLUSIVE:
                _v = _row.get(_f)
                if isinstance(_v, int) and _v > 0:
                    cache_write += _v
            for _f in self._CACHE_WRITE_FIELDS_INCLUSIVE:
                _v = _row.get(_f)
                if isinstance(_v, int) and _v > 0:
                    cache_write_incl += _v
        has_cache_usage = (cache_read > 0 or cache_write > 0
                           or cache_read_incl > 0 or cache_write_incl > 0)
        if pricing is None:
            # #598: an omitted/missing ``pricing`` is UNKNOWN pricing — the
            # #216 loud path below. The legacy Anthropic-catalogue
            # substitution (deleted) silently reported a plausible
            # wrong-rate cost with cost_incomplete=False — the masquerade.
            # Every production call site passes pricing (census-pinned in
            # tests/test_issue598_pricing_masquerade.py); a None here is a
            # lookup miss (a misconfigured adapter), never a threaded call.
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
            # F661-1: the inclusive providers' cached portion is INSIDE
            # input_tokens — subtract it from the billed input (it prices
            # at its own multiplier below, never twice). T1 round-2 (F-A):
            # subtract ONLY the portion that actually prices at a
            # multiplier — an unpriced inclusive cache (the shipped
            # census: no openai/google cache rates) must degrade to the
            # FULL-RATE upper bound (master's direction, over-estimate +
            # cost_incomplete), never to a $0 under-report of the cached
            # tokens.
            _incl_priced = 0
            if cache_read_incl and "cache_read" in pricing:
                _incl_priced += cache_read_incl
            if cache_write_incl and "cache_write" in pricing:
                _incl_priced += cache_write_incl
            _billed_input = input_tokens - _incl_priced
            if _billed_input < 0:
                _billed_input = 0
            input_cost = (_billed_input / 1_000_000) * pricing["input"]
            output_cost = (output_tokens / 1_000_000) * pricing["output"]
            total_cost = input_cost + output_cost
            # #626: the cache portion, priced at its own multipliers of the
            # base input rate. Present cache usage WITHOUT multipliers
            # (below) keeps the tokens counted, the cache cost $0, and the
            # run marked incomplete — never a silent $0-complete read.
            if has_cache_usage:
                # T8 fix (2026-09-21, the retro probe): each side prices
                # ONLY with its own multiplier — a one-sided record (read
                # present, write absent) must not price the missing side at
                # $0.0 and read complete; the used-but-unpriced side marks
                # the run incomplete and names the model.
                cache_cost = 0.0
                unpriced_side = False
                _cache_read_all = cache_read + cache_read_incl
                _cache_write_all = cache_write + cache_write_incl
                if _cache_read_all:
                    if "cache_read" in pricing:
                        cache_cost += (_cache_read_all / 1_000_000) * pricing[
                            "input"] * pricing["cache_read"]
                    else:
                        unpriced_side = True
                if _cache_write_all:
                    if "cache_write" in pricing:
                        cache_cost += (_cache_write_all / 1_000_000) * pricing[
                            "input"] * pricing["cache_write"]
                    else:
                        unpriced_side = True
                total_cost += cache_cost
                if unpriced_side:
                    with self._lock:
                        self._unpriced_cache_models.add(model)
                    tl = self._thread_local
                    if hasattr(tl, "unit_unpriced"):
                        tl.unit_unpriced.add(model)

        # #624: the turns identity — the guard above already rejected an
        # undeclared list; a single completion defaults to 1.
        if isinstance(usage_details, list):
            record_turns = turns
        else:
            record_turns = turns if turns is not None else 1

        call_record = {
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cost_usd": round(total_cost, 6),
            "turns": record_turns,
            # #626: the cache line items (present-only — a call with no
            # cache usage is byte-identical to the pre-#626 record shape).
            **({"cache_read_tokens": cache_read + cache_read_incl}
               if (cache_read or cache_read_incl) else {}),
            **({"cache_write_tokens": cache_write + cache_write_incl}
               if (cache_write or cache_write_incl) else {}),
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
            self.total_turns += record_turns
            # #626: cached input is a SEPARATE line item — never folded
            # into total_input_tokens (the uncached/cached split is the
            # billing-reconciliation shape).
            if cache_read or cache_read_incl:
                self.total_cache_read_tokens += cache_read + cache_read_incl
            if cache_write or cache_write_incl:
                self.total_cache_write_tokens += cache_write + cache_write_incl

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
            out = {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                # #624: the completion count the records cover (one per
                # single completion, the billed turns per conversation).
                "total_turns": self.total_turns,
                # #216: the cost figure is INCOMPLETE when any dispatched
                # model had no pricing (its tokens counted, its dollars $0)
                # — #626: or cached usage the record could not price.
                "cost_incomplete": bool(self._unpriced_models
                                        or self._unpriced_cache_models),
                "unpriced_models": sorted(self._unpriced_models),
                "calls": list(self.calls),
            }
            # #626/T8: the same present-only cache line items get_totals
            # carries (the reconciliation surfaces must agree).
            if self.total_cache_read_tokens:
                out["total_cache_read_tokens"] = self.total_cache_read_tokens
            if self.total_cache_write_tokens:
                out["total_cache_write_tokens"] = self.total_cache_write_tokens
            if self._unpriced_cache_models:
                out["unpriced_cache_models"] = sorted(self._unpriced_cache_models)
            return out

    def get_totals(self) -> dict:
        """
        Get just the totals (without per-call breakdown).

        Returns:
            Dict with totals only
        """
        with self._lock:
            out = {
                "total_calls": len(self.calls),
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "total_tokens": self.total_input_tokens + self.total_output_tokens,
                "total_cost_usd": round(self.total_cost_usd, 6),
                # #624: the completion count (see get_summary).
                "total_turns": self.total_turns,
                "cost_incomplete": bool(self._unpriced_models
                                        or self._unpriced_cache_models),
                "unpriced_models": sorted(self._unpriced_models),
            }
            # #626: present-only — a run with no cache usage serializes
            # byte-identical to the pre-#626 totals.
            if self.total_cache_read_tokens:
                out["total_cache_read_tokens"] = self.total_cache_read_tokens
            if self.total_cache_write_tokens:
                out["total_cache_write_tokens"] = self.total_cache_write_tokens
            if self._unpriced_cache_models:
                out["unpriced_cache_models"] = sorted(self._unpriced_cache_models)
            # #605: present-only — a healthy run's totals serialize
            # byte-identical to pre-#605.
            _errs = _accounting_error_count()
            if _errs:
                out["accounting_errors"] = _errs
            return out



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
    want a clean slate. ALSO zeroes the #605 accounting-error counter
    (the two lifecycles are the same: per-scan, never mid-run). Adapter
    modules are imported lazily and guarded so this stays safe even if a
    provider SDK isn't installed.
    """
    global _accounting_errors
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
    # #604: the registry's unconsumed-knob one-time warning rides the same
    # per-scan lifecycle (lazy import: registry imports modules that import
    # this one — only safe at call time, never at module import). No
    # ImportError guard: registry has no optional third-party imports
    # (adapters resolve lazily inside get_adapter_class), so a failure here
    # means a genuinely broken package — and a silent except would un-wire
    # the reset, making the warning's tests order-dependent (the exact
    # hazard this wiring exists to prevent). ORDER (#609 review): the
    # #605 counter zeroes FIRST — a broken-package import failure must
    # never leave the accounting counter un-zeroed (the two lifecycles
    # are the same per-scan window, but the zero is unconditional).
    with _accounting_errors_lock:
        _accounting_errors = 0

    _registry_mod = importlib.import_module("utilities.llm.registry")
    # the DIRECT call, not getattr(..., None) + callable() — a registry-side
    # rename must fail LOUD here (AttributeError at scan start), never
    # silently degrade the warning from per-scan to per-process (the exact
    # hazard the adjacent comment names; the silent-None fallback
    # contradicted it — the panel seat's catch)
    _registry_mod.reset_unconsumed_timeout_warning()
    # #625: same contract for the thinking knob's one-time warning.
    _registry_mod.reset_unconsumed_thinking_warning()


def reset_global_tracker():
    """Reset the global token tracker (and one-time-warning state)."""
    _global_tracker.reset()
    reset_warning_state()


# NOTE: the ``AnthropicClient`` class that used to live here was deleted
# as part of issue #65. Every call site now goes through
# :mod:`utilities.llm` (Protocol-based adapter layer). See
# ``docs/features/llm-providers/plan.wip.md`` for the migration map.
