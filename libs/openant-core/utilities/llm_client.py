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
from typing import NamedTuple

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


# ---------------------------------------------------------------------------
# THE cost formula — one function, no second copy.
#
# #626/F661-3: there used to be TWO cost formulas in this tree — the tracker's
# (cache-aware) and report/generator.py's _extract_usage (input+output only).
# The report phase feeds the SAME provider usage_details to both, so on an
# anthropic priced-cache call the tracker billed $0.0091 and the generator
# $0.0050 on identical inputs (a 45% under-report), and on an openai/google
# implicitly-cached call the costs agreed by coincidence while the generator
# flipped cost_incomplete True -> False (the #598 masquerade: a plausible
# figure labelled complete). Patching the second formula would have left the
# CLASS of bug alive, so the second formula is gone and both callers share
# this one. It is PURE: no tracker state, no locks, no I/O, no warnings.
#
# The cross-provider field shapes, normalized, SPLIT BY INCLUSION SEMANTICS
# (F661-1, 2026-09-22): the anthropic/bedrock fields are DISJOINT from the
# input count (input_tokens excludes them); the openai/google fields are
# SUBSETS of it (prompt_tokens / prompt_token_count already contain the
# cached portion — pricing input as-is PLUS the cache line items bills the
# cached tokens twice).
CACHE_READ_FIELDS_EXCLUSIVE = ("cache_read_input_tokens",)      # anthropic / bedrock
CACHE_READ_FIELDS_INCLUSIVE = ("cached_tokens",                 # openai / openrouter
                               "cached_content_token_count")    # google
CACHE_WRITE_FIELDS_EXCLUSIVE = ("cache_creation_input_tokens",)  # anthropic / bedrock
CACHE_WRITE_FIELDS_INCLUSIVE = ("cache_write_tokens",)           # openrouter (inside prompt_tokens — the OpenAI-normalized usage shape: OpenRouter's usage-object docs (openrouter.ai/docs/features/prompt-caching, fetched 2026-10-20) show cache_write_tokens in prompt_tokens_details, the same inclusive shape as OpenAI's cached_tokens)
# the union (the captured-verbatim normalization, unchanged)
CACHE_READ_FIELDS = CACHE_READ_FIELDS_EXCLUSIVE + CACHE_READ_FIELDS_INCLUSIVE
CACHE_WRITE_FIELDS = CACHE_WRITE_FIELDS_EXCLUSIVE + CACHE_WRITE_FIELDS_INCLUSIVE


class CacheCounts(NamedTuple):
    """The four normalized cache token counts, by inclusion semantics."""

    read: int = 0            # exclusive (anthropic): NOT inside input_tokens
    write: int = 0           # exclusive
    read_incl: int = 0       # inclusive (openai/google): already inside input
    write_incl: int = 0      # inclusive

    @property
    def any(self) -> bool:
        return bool(self.read or self.write or self.read_incl
                    or self.write_incl)

    @property
    def read_total(self) -> int:
        return self.read + self.read_incl

    @property
    def write_total(self) -> int:
        return self.write + self.write_incl


class PricedUsage(NamedTuple):
    """The priced result: dollars plus the cache line items and the kind."""

    cost_usd: float = 0.0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    #: a cache side was USED but its multiplier is absent from ``pricing`` —
    #: the run is incomplete. The DIRECTION the figure errs in depends on the
    #: provider's field shape and is OPPOSITE for the two (PR#661 hunt F1 —
    #: the round-1 label asserted "an UPPER bound" for both, which was false
    #: for the ENTIRE shipped bedrock census at the #661 pin — pre-#690
    #: the bedrock family carried no cache rates; #690 rated all 11):
    #:
    #:   EXCLUSIVE shapes (anthropic/bedrock ``cache_read_input_tokens`` /
    #:     ``cache_creation_input_tokens``) are DISJOINT from ``input_tokens``,
    #:     so an absent multiplier contributes $0 — the figure is a **LOWER**
    #:     bound. Executed: us.anthropic.claude-sonnet-4-6, 10k in / 1k out /
    #:     90k cache-read → formula $0.049500 vs real $0.079200 (ratio 0.625).
    #:   INCLUSIVE shapes (openai ``cached_tokens``, google
    #:     ``cached_content_token_count``) are already INSIDE ``input_tokens``,
    #:     so an absent multiplier bills them at the full input rate — the
    #:     figure is an **UPPER** bound.
    #:
    #: Neither is the same as an absent pricing RECORD (#216), which omits the
    #: spend entirely (also a lower bound, but of a priced-model-less kind).
    #: No rendering surface may assert one direction for the cache kind: the
    #: serialized envelope carries no inclusion-shape discriminator (see the
    #: named follow-up in the PR body), so the operator-facing wording states
    #: the condition and that the figure may be under- OR over-stated.
    unpriced_cache: bool = False


def normalize_cache_usage(usage_details: dict | list | None) -> CacheCounts:
    """Normalize provider cache fields out of ``usage_details``.

    Accepts a dict or a per-turn list (None entries are absent turns by the
    #211 contract) and sums each turn's cache fields. Pure.
    """
    read = write = read_incl = write_incl = 0
    rows = usage_details if isinstance(usage_details, list) else [usage_details]
    for row in rows:
        if not isinstance(row, dict):
            continue
        for _f in CACHE_READ_FIELDS_EXCLUSIVE:
            _v = row.get(_f)
            if isinstance(_v, int) and _v > 0:
                read += _v
        for _f in CACHE_READ_FIELDS_INCLUSIVE:
            _v = row.get(_f)
            if isinstance(_v, int) and _v > 0:
                read_incl += _v
        for _f in CACHE_WRITE_FIELDS_EXCLUSIVE:
            _v = row.get(_f)
            if isinstance(_v, int) and _v > 0:
                write += _v
        for _f in CACHE_WRITE_FIELDS_INCLUSIVE:
            _v = row.get(_f)
            if isinstance(_v, int) and _v > 0:
                write_incl += _v
    return CacheCounts(read, write, read_incl, write_incl)


class ErrorPathTurn(NamedTuple):
    """The RAISING turn's own billed usage, read off an exception. PURE.

    Built by :func:`error_path_turn` — see there for why this type exists at
    all rather than three copies of the same four lines.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    #: the raising turn's ``usage_details`` VERBATIM (#211), or None when the
    #: exception carried none. A dict only: a single turn's detail.
    usage_details: dict | None = None

    @property
    def billed(self) -> bool:
        """Did the provider bill for the raising turn at all?

        The CACHE counts are part of the answer, and that is the whole point:
        on the EXCLUSIVE (anthropic) shape the cached read is DISJOINT from
        ``input_tokens``, so a full cache hit arrives as 0 input / 0 output
        with a 90k billed read. A guard that consults only input/output drops
        that call WHOLESALE — the F-A1 round's M4 mutant.
        """
        return bool(self.input_tokens or self.output_tokens
                    or normalize_cache_usage(self.usage_details).any)

    @property
    def entries(self) -> list:
        """The raising turn's per-turn ``usage_details`` entries, for
        concatenation onto a conversation's list.

        ONE entry when the turn billed, NONE when it did not — so
        ``len(list)`` stays the #624 billed-turn count at every call site, and
        the entry carries the turn's detail instead of a hard-coded ``None``
        (the defect: #626 prices entirely off ``usage_details``).
        """
        return [self.usage_details] if self.billed else []


def error_path_turn(exc: BaseException) -> ErrorPathTurn:
    """Read the raising turn's billed usage off ``exc``. PURE, never raises.

    THE shared error-path usage constructor. Three recorders fold the same
    exception into the same ``record_call`` here (the sink-keyed census is
    closed at three and pinned by
    ``tests/test_issue626_conversation_error_path_cache.py``):
    ``llm/helpers.simple_completion``, ``finding_verifier.verify_result`` and
    ``agentic_enhancer.agent.analyze_unit``. Each had re-derived the same four
    lines, and #626 — which prices the cache off ``usage_details`` — reached
    exactly one of the three.

    DUCK-TYPED on purpose: two of the three handlers are ``except Exception``
    (they must record a conversation's accumulated spend whatever the failure
    class), so the usage attributes are read by ``getattr``. Only
    ``LLMResponseError``/``LLMRefusalError`` carry them (#537: a rejected
    reply the provider billed); a connection/auth/limit error contributes
    nothing and yields a zero turn.

    It NEVER raises, and that guarantee is load-bearing rather than hygiene
    (#609 ENG-1): an accounting failure inside an exception handler would
    REPLACE the original exception, and the original's retryability class
    (rate_limit vs connection vs structural) is what the retry loops key on.
    So the coercions are guarded — in ONE try, matching the pre-existing
    agent.py belt exactly: a foreign exception with a non-int-coercible token
    attribute yields 0/0, never a partial read.

    There is deliberately NO arithmetic here and no cost: the caller folds
    these counts into the SAME ``record_call``/``price_usage`` path its success
    exits use. A second cost formula on the error path is exactly what #598
    was.
    """
    try:
        exc_in = int(getattr(exc, "input_tokens", 0) or 0)
        exc_out = int(getattr(exc, "output_tokens", 0) or 0)
    except Exception:
        exc_in = exc_out = 0
    try:
        details = getattr(exc, "usage_details", None)
    except Exception:          # a property that raises — the ENG-1 class
        details = None
    if not isinstance(details, dict):
        # #211 verbatim means a dict for ONE turn. Anything else (a list, a
        # str, a Mock) is not a turn's detail: absent, never fabricated.
        details = None
    return ErrorPathTurn(exc_in, exc_out, details)


def price_usage(
    input_tokens: int,
    output_tokens: int,
    pricing: dict[str, float],
    *,
    cache_counts: CacheCounts | None = None,
) -> PricedUsage:
    """Price one call's tokens. PURE — the single cost formula.

    ``pricing`` must NOT be None: an absent pricing record is the #216/#598
    loud path and belongs to the caller (it costs $0 and names the model),
    never to a substituted rate here.
    """
    counts = cache_counts or CacheCounts()
    # F661-1: the inclusive providers' cached portion is INSIDE
    # input_tokens — subtract it from the billed input (it prices at its
    # own multiplier below, never twice). T1 round-2 (F-A): subtract ONLY
    # the portion that actually prices at a multiplier — an unpriced
    # inclusive cache (the #661-era census had no openai/google rates; the post-#690 unrated class: the ollama records, the unpublished-cache google 2.0/1.5 models, the divergent-price z-ai routes)
    # must degrade to the FULL-RATE upper bound (master's direction,
    # over-estimate + cost_incomplete), never to a $0 under-report of the
    # cached tokens.
    _incl_priced = 0
    if counts.read_incl and "cache_read" in pricing:
        _incl_priced += counts.read_incl
    if counts.write_incl and "cache_write" in pricing:
        _incl_priced += counts.write_incl
    _billed_input = input_tokens - _incl_priced
    unpriced_side = False
    if _billed_input < 0:
        _billed_input = 0
        # the fable-r1 overlap catch (the OpenRouter->Google explicit-cache
        # shape reports the SAME tokens as both cached_tokens AND
        # cache_write_tokens, live-verified: prompt=5137, cached=5132,
        # write=5132 — the subtraction clamps away the whole uncached
        # remainder, silently under-reporting min(uncached, overlap) x
        # the input rate with cost_incomplete=False). Unreachable from
        # OpenAnt today (no explicit-cache breakpoints are ever sent),
        # but priced-complete since #690 — mark the run INCOMPLETE so the
        # shape is loud, never silently under-reported.
        unpriced_side = True
    total_cost = ((_billed_input / 1_000_000) * pricing["input"]
                  + (output_tokens / 1_000_000) * pricing["output"])
    if counts.any:
        # #626: the cache portion, priced at its own multipliers of the
        # base input rate. T8 fix (2026-09-21, the retro probe): each side
        # prices ONLY with its own multiplier — a one-sided record (read
        # present, write absent) must not price the missing side at $0.0
        # and read complete; the used-but-unpriced side marks the run
        # incomplete and names the model.
        cache_cost = 0.0
        if counts.read_total:
            if "cache_read" in pricing:
                cache_cost += ((counts.read_total / 1_000_000)
                               * pricing["input"] * pricing["cache_read"])
            else:
                unpriced_side = True
        if counts.write_total:
            if "cache_write" in pricing:
                cache_cost += ((counts.write_total / 1_000_000)
                               * pricing["input"] * pricing["cache_write"])
            else:
                unpriced_side = True
        total_cost += cache_cost
    return PricedUsage(total_cost, counts.read_total, counts.write_total,
                       unpriced_side)


# ---------------------------------------------------------------------------
# The TWO-KIND incompleteness rule — ONE implementation (PR#661 hunt F4)
#
# There are two kinds of incomplete cost and they are NOT interchangeable:
#
#   unpriced_models        the model had NO pricing record (#216/#598). Its
#                          spend is attributed $0, so the figure OMITS it.
#   unpriced_cache_models  the model IS priced; only its cache multipliers
#                          are absent (#626). Its error direction depends on
#                          the provider's field shape — see
#                          PricedUsage.unpriced_cache.
#
# Before this, ~20 call sites across 7 modules each re-implemented "which
# keys carry incompleteness and when". That is why the F661-3 relabel — which
# split the per-unit cache set out of ``unit_unpriced`` into its own
# thread-local — made the cache kind vanish from every ``_summary.json``,
# every resume seed and every enhanced dataset row at once: none of those
# readers had been taught the new key, and nothing could tell them. The rule
# now lives HERE, next to the code that creates the two sets, so a third kind
# is a change to two functions instead of an archaeology exercise.
#
# Both are PRESENT-ONLY: no kind ⇒ no keys ⇒ a pre-#216 artifact shape.
# ---------------------------------------------------------------------------


def incomplete_markers(unpriced=None, unpriced_cache=None) -> dict:
    """The incompleteness marker keys for a usage/summary dict.

    Returns ``{}`` when neither kind is present (never a fabricated
    ``cost_incomplete: False`` — absent means "nothing to disclose", and the
    byte-identity contract for a clean run depends on the absence).

    Accepts any iterables (sets, lists, None); emits SORTED, de-duplicated
    lists so two restore sites that merged the same ids agree byte-for-byte.
    """
    _u = sorted(set(unpriced or ()))
    _c = sorted(set(unpriced_cache or ()))
    out: dict = {}
    if _u or _c:
        out["cost_incomplete"] = True
    if _u:
        out["unpriced_models"] = _u
    if _c:
        out["unpriced_cache_models"] = _c
    return out


def unpriced_kinds_from(usage) -> tuple[list[str], list[str]]:
    """Read BOTH unpriced kinds out of a persisted usage/metadata dict.

    The symmetric reader for ``incomplete_markers``: the ONE place that knows
    which keys a checkpoint, a ``_summary.json`` or an ``agent_metadata``
    block carries. Tolerates None / non-dict / a pre-#626 dict with neither
    key (both lists empty) — every restore site reads legacy checkpoints.
    """
    if not isinstance(usage, dict):
        return [], []
    return (list(usage.get("unpriced_models") or []),
            list(usage.get("unpriced_cache_models") or []))


def turn_has_spend(usage=None, *, input_tokens=None, output_tokens=None,
                   cost_usd=None, unpriced=None, unpriced_cache=None) -> bool:
    """Did this turn / unit / phase actually spend anything?

    THE one predicate every ledger WRITE GATE and resume SEED condition keys
    on, and the COST disjunct is the whole reason it exists. Cache-only spend
    — a turn billed entirely as a cache read — reaches these ledgers as 0
    input / 0 output tokens carrying a real dollar cost (the enhance, analyze
    and verify ledgers never see a cache token key: cache spend arrives folded
    into ``cost_usd``), and on a PRICED model there is no unpriced marker
    either. A gate that asks only about tokens and markers therefore answers
    "no work happened" about a turn that cost money — so the usage block is
    not written, the prior usage is not injected, and the spend is orphaned on
    resume while the phase summary, whose folds are unguarded, reports the
    dollars in full.

    Five sites asked that question five times and all five omitted cost
    (context_enhancer.py:809/:1032/:1239, analyzer.py:865,
    finding_verifier.py:867). It is ONE predicate missing at five places, not
    five bugs, which is why it lives here beside ``incomplete_markers`` and
    ``unpriced_kinds_from`` rather than being re-derived per site.

    Two call shapes, because the five sites need both:

      * ``turn_has_spend(usage_dict)`` — a persisted ``usage`` /
        ``agent_state`` block. The marker kinds are read through
        ``unpriced_kinds_from``, so this stays the symmetric partner of
        ``incomplete_markers``: one place knows which keys carry what.
      * ``turn_has_spend(input_tokens=..., output_tokens=..., cost_usd=...,
        unpriced=..., unpriced_cache=...)`` — loose accumulators.

    A keyword ALWAYS overrides the dict, so a site may pass the dict and
    override just the kinds it merged from several sources. Each of the five
    is resolved INDEPENDENTLY: passing ``unpriced=`` alone must not suppress
    the dict's ``unpriced_cache_models`` (an all-or-nothing marker pair would
    silently under-report the other kind at a future site, and the census pin
    that funnels new gates here only checks that this predicate is CALLED).

    Returns False for a genuinely empty turn — all zero, no markers. That is
    load-bearing, not a detail: the present-only artifact discipline depends
    on a no-spend phase still writing NO usage block and injecting nothing, so
    a clean run's checkpoint stays byte-identical to the pre-#598 shape.

    Never raises for any value a JSON decode can produce. Every caller also
    reads LEGACY checkpoints, two of them on worker threads, and three of
    these gates previously tested bare truthiness — so a malformed payload
    that used to read falsy (``[]``) must not start raising inside the gate.
    The promise is stated against the DECODER rather than loosely, because the
    first version of it was not true: a JSON integer is unbounded and a float
    is not, so a 10**400 token count raised OverflowError out of the gate
    where the bare truthiness test it replaced had restored the spend.
    """
    src = usage if isinstance(usage, dict) else {}
    if input_tokens is None:
        input_tokens = src.get("input_tokens", 0)
    if output_tokens is None:
        output_tokens = src.get("output_tokens", 0)
    if cost_usd is None:
        cost_usd = src.get("cost_usd", 0.0)
    if unpriced is None or unpriced_cache is None:
        _src_unpriced, _src_cache = unpriced_kinds_from(src)
        if unpriced is None:
            unpriced = _src_unpriced
        if unpriced_cache is None:
            unpriced_cache = _src_cache

    def _num(value) -> float:
        try:
            return float(value or 0)
        except (TypeError, ValueError, OverflowError):
            # Fall back to TRUTHINESS rather than raise inside a gate that
            # previously only tested truthiness. Two distinct payloads land
            # here and the fallback is right for both:
            #   * a malformed legacy value (a list, a non-numeric string);
            #   * OverflowError -- a Python int is unbounded and a float is
            #     not, so a JSON-decoded count of 10**400 cannot be converted
            #     at all. It is still SPEND: treating it as no-spend would
            #     orphan the dollars beside it, which is this round's defect.
            # Note the asymmetry this preserves on purpose: the string "0"
            # parses to 0.0 above and stays a SKIP (#609's all-zero skip on a
            # stringly-typed legacy field), while "abc" reads as spend here.
            return 1.0 if value else 0.0

    return bool(_num(input_tokens) or _num(output_tokens) or _num(cost_usd)
                or unpriced or unpriced_cache)


def unit_unpriced_kinds(tracker) -> dict:
    """The current thread's per-unit unpriced ids, BOTH kinds, as kwargs.

    Returned as ``{"unpriced_models": [...] | None,
    "unpriced_cache_models": [...] | None}`` so a result-object construction
    site can splat it; ``None`` keeps the per-field present-only rule.

    Defensive by the same contract ``start_unit_tracking``'s callers rely on:
    a tracker stub with no ``_thread_local``, or a thread that never called
    ``start_unit_tracking``, yields both ``None`` rather than raising — the
    enhance agent constructs results on worker threads and in tests with
    tracker doubles.
    """
    tl = getattr(tracker, "_thread_local", None)
    return {
        "unpriced_models":
            sorted(getattr(tl, "unit_unpriced", None) or ()) or None,
        "unpriced_cache_models":
            sorted(getattr(tl, "unit_unpriced_cache", None) or ()) or None,
    }


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

    # The cross-provider field shapes live at module level now (one copy,
    # shared with price_usage/normalize_cache_usage and the report path).
    # These aliases keep every existing ``self._CACHE_*`` reader working.
    _CACHE_READ_FIELDS_EXCLUSIVE = CACHE_READ_FIELDS_EXCLUSIVE
    _CACHE_READ_FIELDS_INCLUSIVE = CACHE_READ_FIELDS_INCLUSIVE
    _CACHE_WRITE_FIELDS_EXCLUSIVE = CACHE_WRITE_FIELDS_EXCLUSIVE
    _CACHE_WRITE_FIELDS_INCLUSIVE = CACHE_WRITE_FIELDS_INCLUSIVE
    _CACHE_READ_FIELDS = CACHE_READ_FIELDS
    _CACHE_WRITE_FIELDS = CACHE_WRITE_FIELDS

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
        provider_cost_usd: float | None = None,
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
            provider_cost_usd: #797 — the provider's OWN reported cost
                for this call (OpenRouter's ``usage.cost``, surfaced by the
                adapter on the CompletionResult). PREFERRED over the local
                table when present: the authoritative charged number IS the
                cost (no lookup, no unpriced marker, the record carries
                ``cost_source: "provider"``); None keeps the two existing
                paths byte-identical (the table; the #216 loud path for the
                residual gap — models that report neither).
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
        # The normalization AND the pricing below both come from the shared
        # module-level pair, so the report path cannot drift from this one
        # (#626/F661-3 — see price_usage's comment).
        _counts = normalize_cache_usage(usage_details)
        cache_read = _counts.read
        cache_write = _counts.write
        cache_read_incl = _counts.read_incl
        cache_write_incl = _counts.write_incl
        has_cache_usage = _counts.any
        # #797: the provider's own reported cost — the PREFERRED source.
        # The authoritative charge (the local table approximates it): no
        # lookup, no #216 unpriced marker for this call, the record names
        # its source. The cache TOKEN line items still record; the
        # cache-UNPRICED marker is suppressed by design — the provider's
        # number IS the priced total, so a cache-table gap no longer
        # makes the call's cost incomplete (the r1-F3 correction: the
        # marker lived in the else-arm the preference skips).
        _provider_reported = (provider_cost_usd is not None)
        if _provider_reported:
            total_cost = float(provider_cost_usd)
        elif pricing is None:
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
            # THE one cost formula (module-level, pure, shared with the
            # report path). Everything the old inline body did — the F661-1
            # inclusive subtraction, the T1 round-2 full-rate upper bound
            # for an unpriced inclusive cache, the T8 per-side multiplier
            # rule — lives in price_usage now, unchanged.
            _priced = price_usage(input_tokens, output_tokens, pricing,
                                  cache_counts=_counts)
            total_cost = _priced.cost_usd
            if has_cache_usage:
                if _priced.unpriced_cache:
                    with self._lock:
                        self._unpriced_cache_models.add(model)
                    # F661-3 (the relabel fix): the per-unit set for the
                    # CACHE kind is its own — tl.unit_unpriced carries the
                    # #216 "no pricing record at all" kind only. Merging
                    # them made get_unit_usage (and the six private
                    # thread-local reads in agentic_enhancer/agent.py)
                    # persist a false claim about a PRICED model.
                    tl = self._thread_local
                    if hasattr(tl, "unit_unpriced_cache"):
                        tl.unit_unpriced_cache.add(model)

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
            # #797: the cost's SOURCE, present-only — "provider" names the
            # authoritative reported number; absent means the local table
            # (or the #216 loud $0).
            **({"cost_source": "provider"} if _provider_reported else {}),
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
                        unpriced_models: list[str] | None = None,
                        unpriced_cache_models: list[str] | None = None):
        """Inject usage from a prior run (e.g. restored checkpoints).

        This ensures step reports capture the total cost across all runs,
        not just the current run's API calls. ``unpriced_models`` restores
        the #216 incomplete-cost marker across a resume (the tracker resets
        per process; without this, a resumed run's cost silently looks
        complete again).

        ``unpriced_cache_models`` is the #626 kind's slot (PR#661 hunt F4).
        It did not exist, so the per-unit checkpoint's cache marker — which
        ``get_unit_usage`` has always written — had nowhere to go: run 1
        persisted ``cost_incomplete: True`` with the model named and run 2's
        tracker read ``cost_incomplete: False``. Both kinds are restored into
        their OWN set; they must never merge (F661-3 — calling a priced model
        "unpriced" in the resumed artifact is a false statement, and that
        relabel is what made this drop total).

        NOT restored here: the cache TOKEN ledger
        (``total_cache_read_tokens`` / ``total_cache_write_tokens``). The
        per-unit checkpoint shape has never carried it, so restoring it means
        new checkpoint keys plus token parameters on this method — the pinned
        F661-3-proper follow-up, deliberately out of this round. A resumed
        run is therefore SILENT about cache token volume and CORRECT about
        cache-cost incompleteness, which is the trust gate the harness keys
        on.
        """
        with self._lock:
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost_usd += cost_usd
            if unpriced_models:
                self._unpriced_models.update(unpriced_models)
            if unpriced_cache_models:
                self._unpriced_cache_models.update(unpriced_cache_models)

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
        # The two incompleteness KINDS are tracked separately and both are
        # created HERE, in one method, so no partially-initialized
        # thread-local can exist (record_call's hasattr guards and
        # agentic_enhancer/agent.py:244-245's defensive getattr call both
        # depend on that).
        #   unit_unpriced       — #216: no pricing record at all (cost $0,
        #                         the figure is a LOWER bound)
        #   unit_unpriced_cache — #626: pricing present, cache multipliers
        #                         absent. The error DIRECTION depends on the
        #                         provider's field shape and is opposite for
        #                         the two: the EXCLUSIVE shapes contribute $0
        #                         (a LOWER bound), the INCLUSIVE shapes bill
        #                         at the full input rate (an UPPER bound).
        #                         See PricedUsage.unpriced_cache — a single
        #                         direction must never be asserted for this
        #                         kind (PR#661 hunt F1).
        tl.unit_unpriced: set[str] = set()
        tl.unit_unpriced_cache: set[str] = set()

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
        # #626/F661-3: the cache kind is emitted under its OWN key. The two
        # must never merge: unpriced_models means "no pricing record at all"
        # (the figure omits that spend), unpriced_cache_models means "the
        # model IS priced but its cache multipliers are absent" — whose error
        # direction depends on the provider's field shape (exclusive ⇒ a
        # lower bound, inclusive ⇒ an upper bound; see
        # PricedUsage.unpriced_cache). Both markers are present-only, so a
        # unit with neither serializes to exactly the three pre-#216 keys and
        # a legacy checkpoint reader sees no new keys.
        #
        # PR#661 hunt F4: the marker keys are stamped by ``incomplete_markers``
        # — the ONE implementation of the two-kind rule, shared with every
        # phase's ``_usage_dict`` and every resume seed. The F661-3 split made
        # the cache kind vanish below this hop precisely because ~20 readers
        # each re-implemented "which keys carry incompleteness".
        usage.update(incomplete_markers(
            getattr(tl, "unit_unpriced", None),
            getattr(tl, "unit_unpriced_cache", None)))
        return usage

    # #786: the human-line completeness read — a plain-attribute accessor
    # (never get_totals), so the #608 contract (sanctioned readers only)
    # holds for every new render site.
    def cost_incomplete_models(self) -> list:
        return sorted(self._unpriced_models)

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
