"""ContextBudgetController -- Fix B: per-run cache of the ONE technical
source-evidence capacity ceiling for each of Auto Patcher's repository
source/context acquisition stages.

--------------------------------------------------------------------------
History (pre-Fix-B, kept for anyone reading old traces/reports/tests):

Final-Target Slicing / Deterministic Pre-Patch Acquisition (Slice 2) /
Guided Pre-Patch Acquisition (Slice 3) / Post-Patch Recovery (Slice 4) all
shared ONE soft character ceiling -- remediation_planner.
FINAL_TARGET_SLICE_MAX_CHARS (10,000 chars) -- plus Slice 4's own
additional per-round total (MAX_POST_PATCH_SOURCE_CHARS, 6,000 chars) and
Planning's own evidence render (evidence_fusion.DEFAULT_MAX_CHARS, 4,000
chars). This module used to let a caller (the CLI, or another library
caller) opt in to additional, FIXED-SIZE "windows" of that same budget via
three policies ("ask"/"always"/"never") and a `--max-context-budget-
windows` hard cap.

A real regression demonstrated why that whole model was wrong: a Planning
prompt reported requested repository evidence as successfully RESOLVED,
while the corresponding full-file source was OMITTED because a "budget"
of 4,000 x N characters -- an arbitrary legacy constant, never derived
from any real model's context capacity -- ran out. The evidence existed,
was located, and was never delivered to the LLM in usable form, purely
because of a resource mechanic that had nothing to do with genuine
technical capacity. Investigation (see the Fix B architecture
investigation and its two design amendments) found no real per-call
token/cost/call metering existed anywhere in this codebase to justify
"windows" as a resource concept either -- it was, in effect, an arbitrary
technical-capacity guess wearing resource-policy clothing.
--------------------------------------------------------------------------

Fix B removes the window/policy model entirely. Repository evidence is now
bounded ONLY by:

  1. `utilities.autopatcher.technical_capacity` -- the real, per-call
     technical capacity of the LLM call this evidence will be embedded
     in, derived from the active model's registry-documented context
     window (or one documented conservative fallback) minus the exact,
     already-known overhead of everything else that call's prompt
     contains. This is a TECHNICAL ceiling, not a resource budget, and it
     is always active -- there is no "no ceiling" mode, because a real
     LLM call always has finite capacity.

  2. Structural exploration bounds (MAX_PLANNING_ATTEMPTS,
     MAX_EVIDENCE_REQUESTS_PER_ROUND, MAX_ACQUISITION_ROUNDS,
     MAX_GUIDED_ACQUISITION_ROUNDS, MAX_POST_PATCH_RECOVERY_ROUNDS, etc.)
     -- plain module constants in remediation_planner.py, untouched by
     Fix B, and never touched by this module either.

There is deliberately NO user-facing resource/cost/call budget in Fix B
(see the Fix B design amendments for why: no pre-call token estimator or
model-context-window metadata existed anywhere in this codebase to make
one accurate, and inventing an inaccurate one would repeat the exact
mistake this fix exists to correct). A future, separate workstream may
add a genuine cost/token/call meter on top of the already-accurate,
already-POST-hoc `utilities.llm_client.TokenTracker` -- this module is not
that, and does not attempt to be.

`ContextBudgetController` still exists, in a much smaller role: a per-run
cache so a given acquisition stage's technical-capacity decision is
computed once (the active model does not change mid-run) and reused
everywhere that stage's ceiling is consulted, plus a place to collect
trace/provenance data. `budget_controller=None` (every existing library
caller, and any caller that never builds one) computes the exact SAME
technical-capacity number on the fly instead -- "no controller" has never
meant "no ceiling", and after Fix B it also never means "a smaller,
arbitrary ceiling": the number is identical either way. This class only
adds caching/observability on top of it.

The two legacy CLI flags (`--context-budget-policy`/
`--max-context-budget-windows`) are still ACCEPTED by `openant/cli.py`
(so nothing that already passes them breaks), but they no longer
construct or influence anything in this module -- see `openant/cli.py`'s
own deprecation handling.
"""

from __future__ import annotations

from typing import Optional

from .llm_client import resolve_max_tokens
from .technical_capacity import SourceCapacityResult, compute_source_capacity

# Kept only so a stray import of the old policy vocabulary (tests, a
# deprecation-message check) doesn't need to invent its own copy. No
# runtime code in this module reads this value for any decision anymore.
CONTEXT_BUDGET_POLICIES = ("ask", "always", "never")
"""Historical policy vocabulary -- Fix B: no longer consulted by anything
in this module. `openant/cli.py` still validates `--context-budget-policy`
against this (so a bad value still errors clearly), purely for a
deprecation message; it no longer selects any runtime behavior here."""


class ContextBudgetController:
    """Owns, for one pipeline run, PROVIDER/MODEL identity plus a per-stage
    cache of the ONE technical source-capacity ceiling `utilities.
    autopatcher.technical_capacity.compute_source_capacity()` computes for
    that stage. A caller constructs one controller per pipeline run and
    passes it into `utilities.autopatcher.pipeline.run(budget_controller=
    ...)`.

    provider/model: the active LLM binding's identity, used for the
    model-registry capacity lookup (see `technical_capacity.compute_
    source_capacity`). `None`/`None` (the default -- e.g. constructed
    before the first real LLM call resolves one, or mock mode) is treated
    identically to "no registry record for this model": routes to the one
    documented conservative fallback, never raises. A caller that already
    knows the resolved (provider, model) pair (see `utilities.autopatcher.
    llm_client.resolve_active_model()`) should pass it; a caller that
    doesn't can safely omit it -- the fallback path is exact and
    deterministic, just less precise.
    """

    def __init__(
        self,
        provider: "Optional[str]" = None,
        model: "Optional[str]" = None,
        *,
        policy: "Optional[str]" = None,
        max_windows: "Optional[int]" = None,
        interactive: "Optional[bool]" = None,
        confirm=None,
    ) -> None:
        # policy/max_windows/interactive/confirm: DEPRECATED, pre-Fix-B
        # constructor arguments -- accepted (never raise a TypeError on an
        # existing caller) but otherwise ignored. There is no policy to
        # choose and no window count to cap: every stage's ceiling is the
        # real technical capacity computed by `technical_capacity.
        # compute_source_capacity`, unconditionally. Kept as keyword-only
        # so no positional-argument caller could have relied on them
        # (this class's positional signature was always `(policy,
        # max_windows, ...)` before Fix B; a caller passing them
        # positionally today would silently bind to `provider`/`model`
        # instead of raising, which is exactly why this class validated
        # `policy`/`max_windows` strictly before -- Fix B accepts this
        # narrow risk deliberately, since nothing in this class can act on
        # an invalid value anymore either way).
        self.provider = provider
        self.model = model
        self._stages: "dict[str, SourceCapacityResult]" = {}
        self._used_chars: "dict[str, int]" = {}

    def effective_budget(
        self,
        stage: str,
        *,
        reserved_output_tokens: "Optional[int]" = None,
        known_overhead_chars: int = 0,
    ) -> int:
        """The stage's technical source-capacity ceiling, in characters --
        computed once (via `technical_capacity.compute_source_capacity`)
        and cached for the rest of this run, mirroring the fact that the
        active provider/model is fixed for the whole run. A stage already
        cached from an earlier call returns its cached ceiling unchanged,
        regardless of whatever `reserved_output_tokens`/
        `known_overhead_chars` a LATER call happens to pass -- exactly one
        real capacity decision per stage per run, never a moving target
        mid-run, and never re-derived from a smaller/incomplete overhead
        estimate a later caller might supply.

        `reserved_output_tokens=None` (the default) resolves the real,
        currently-configured output-token reserve via `llm_client.
        resolve_max_tokens()` -- callers that already know it may pass it
        explicitly, but every real production call site can safely omit
        it."""
        cached = self._stages.get(stage)
        if cached is not None:
            return cached.source_capacity_chars
        result = compute_source_capacity(
            self.provider,
            self.model,
            reserved_output_tokens=(
                resolve_max_tokens() if reserved_output_tokens is None else reserved_output_tokens
            ),
            known_overhead_chars=known_overhead_chars,
        )
        self._stages[stage] = result
        return result.source_capacity_chars

    def capacity_result(self, stage: str) -> "Optional[SourceCapacityResult]":
        """The full structured capacity decision for `stage`, if
        `effective_budget()` has been called for it at least once this run
        -- else `None`. For trace/provenance only (see `to_trace_dict()`
        and `pipeline.py`'s debug-JSON writers) -- never consulted by any
        evidence-rendering decision itself, which reads only
        `effective_budget()`'s plain int."""
        return self._stages.get(stage)

    def record_used(self, stage: str, used_chars: int) -> None:
        """Best-effort observability only, for the structured trace --
        records the largest `used_chars` seen for `stage` this run. Never
        consulted by `effective_budget()`'s own decision."""
        self._used_chars[stage] = max(self._used_chars.get(stage, 0), used_chars)

    def request_extension(
        self,
        stage: str,
        window_size: "Optional[int]" = None,
        *,
        reason: str = "",
        affected_targets: "Optional[list]" = None,
        initial_windows: int = 1,
    ) -> bool:
        """DEPRECATED no-op, retained ONLY so every pre-existing
        remediation_planner.py retry call site (Slices 2/3/4) needs no
        signature changes. ALWAYS returns False: `effective_budget()`
        already returned this stage's full technical capacity on its very
        first call for this run -- there is no additional "window" left to
        grant, because after Fix B there is no window mechanic at all
        (see this module's own history section above). A caller observing
        `False` here behaves exactly as it always has when a budget
        extension was denied -- it proceeds with whatever capacity
        `effective_budget()` already gave it, recording the omission
        structurally (see `remediation_planner._SourceExcerptPlan`'s
        `omission_reason` field)."""
        return False

    def to_trace_dict(self) -> dict:
        """The full structured trace for this run's technical-capacity
        decisions -- safe to embed verbatim into an existing debug
        artifact (see `pipeline.py`'s reports/debug/*.json writers). Never
        raises."""
        return {
            "provider": self.provider,
            "model": self.model,
            "stages": {
                name: {**result.as_dict(), "used_chars": self._used_chars.get(name, 0)}
                for name, result in self._stages.items()
            },
        }
