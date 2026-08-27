"""Canonical 13-stage Auto Patcher pipeline registry -- replay foundation.

This module is the SINGLE source of truth for:

  - the canonical list of Auto Patcher pipeline stages, in pipeline order
  - each stage's declared upstream dependencies (by canonical name, not
    numeric position)
  - each stage's execution-capability requirements (repo access, Docker,
    an LLM provider) -- used by the replay engine for CAPABILITY-AWARE
    preflight (e.g. replaying report_generation must never require Docker)
  - each stage's owned LLM observability tags -- which `stage=` values a
    replay of this stage is allowed to see captured, per the "a replay may
    execute ONLY the LLM calls owned by the selected stage" guarantee

This is Auto-Patcher-specific and deliberately explicit: a plain module-
level tuple/dict registry, not a generic plugin architecture, not an
abstract class hierarchy. See utilities/autopatcher/tools/TRACING_AND_DEBUGGING.md
and the architecture report this module implements (Batch A / Foundation,
cleanup pass) for the full rationale.

DELIBERATELY STATIC, SIDE-EFFECT FREE, IMPORT-ORDER INDEPENDENT: everything
in this module is built once, from pure literals, when the module is first
imported -- ``STAGE_SPECS`` never changes after that, regardless of what
else gets imported, in what order, or how many times. There is NO
registration function here and nothing here ever mutates. This module
answers exactly one question: "what IS this canonical stage" (its
dependencies, capabilities, LLM ownership) -- a question with a single,
permanent, always-known answer for all 13 stages from day one.

It deliberately does NOT answer "is this stage replayable today, and if
so, how" -- that is a moving target (only test_analysis_and_plan has an
implementation so far, and Batch B/C will add more incrementally) tracked
explicitly by replay_engine.REPLAY_HANDLERS, a plain dict literal in a
DIFFERENT module. Importing replay_engine.py must never mutate anything in
this module -- see replay_engine.py's module docstring for why that
separation is the whole point of this design (previously, Batch A had a
``register_run_fn()`` that mutated this module's ``STAGE_SPECS`` as an
import side effect; this cleanup pass removed it entirely).

Production pipeline.py is NOT refactored onto this registry in Batch A --
see pipeline.py's own module docstring / the architecture report's Phase B
scope. This module only describes the pipeline; it does not (yet) drive it.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

# ---------------------------------------------------------------------------
# Canonical stage names, in pipeline order. Stable identifiers -- used as
# dict keys, CLI --stage values, and manifest "stages"/"replaces_stage"
# keys. Never renamed casually; a rename is a schema-affecting change.
# ---------------------------------------------------------------------------

REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING = "repository_analysis_and_remediation_planning"
REMEDIATION_STRATEGY = "remediation_strategy"
GUIDED_CONTEXT_ACQUISITION = "guided_context_acquisition"
PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION = "patch_generation_and_post_patch_investigation"
CHALLENGER = "challenger"
PATCH_REPAIR_AND_CALIBRATION = "patch_repair_and_calibration"
PATCH_REVIEW = "patch_review"
CONFIDENCE_SCORING = "confidence_scoring"
IMPACT_AND_BEHAVIOR_ANALYSIS = "impact_and_behavior_analysis"
TEST_ANALYSIS_AND_PLAN = "test_analysis_and_plan"
EXISTING_TEST_COMPARISON = "existing_test_comparison"
TRUST_SIGNALS_AND_RECOMMENDATION = "trust_signals_and_recommendation"
REPORT_GENERATION = "report_generation"

CANONICAL_STAGE_ORDER: "tuple[str, ...]" = (
    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
    REMEDIATION_STRATEGY,
    GUIDED_CONTEXT_ACQUISITION,
    PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
    CHALLENGER,
    PATCH_REPAIR_AND_CALIBRATION,
    PATCH_REVIEW,
    CONFIDENCE_SCORING,
    IMPACT_AND_BEHAVIOR_ANALYSIS,
    TEST_ANALYSIS_AND_PLAN,
    EXISTING_TEST_COMPARISON,
    TRUST_SIGNALS_AND_RECOMMENDATION,
    REPORT_GENERATION,
)

# Explicitly NOT a canonical stage anymore: the Phase-1 name
# "test_plan_discovery" is superseded by test_analysis_and_plan, which
# absorbs it as an internal sub-operation (see replay_engine.py). Listed
# here only so a stale reference is easy to grep for -- never added to
# CANONICAL_STAGE_ORDER or STAGE_SPECS.
_RETIRED_LEGACY_STAGE_NAMES: "frozenset[str]" = frozenset({"test_plan_discovery"})


@dataclass(frozen=True)
class StageSpec:
    """Everything the replay/full-run architecture needs to know about
    WHAT one canonical stage is -- never whether or how it can be
    replayed today (see replay_engine.ReplayHandler for that).

    Fields
    ------
    name:
        Canonical stage name (one of CANONICAL_STAGE_ORDER).
    order:
        0-based position in CANONICAL_STAGE_ORDER -- a stable integer for
        display/sorting only; dependency resolution never uses this, only
        the ``dependencies`` graph (a stage may legitimately depend on a
        stage that is not its immediate numeric predecessor, and may NOT
        depend on every stage that numerically precedes it).
    dependencies:
        The stage's FINAL, approved canonical dependency set -- other
        canonical stage names whose resolved artifact this stage's full
        production contract requires. This is the permanent graph; it does
        not shrink or grow as implementation work proceeds.
    requires_repo_access, requires_docker, requires_llm_provider:
        Capability flags for capability-aware preflight (see
        replay_engine.py). Declared explicitly per stage -- never derived
        heuristically from the stage's name or dependencies.
    owns_llm_tags:
        The ``stage=`` values this canonical stage's production code is
        allowed to emit to ``llm_client.call_llm``. Used to enforce "a
        replay of stage X executes only LLM calls owned by X". Some tags
        currently appear in more than one stage's owns_llm_tags (see
        KNOWN_AMBIGUOUS_LLM_TAGS below) -- this is an honest reflection of
        current production code, not a design goal.
    owns_external_execution:
        True if this stage's production contract performs expensive
        external work (subprocess, Docker, repository parsing) as part of
        its own responsibility -- used for the "replay must not trigger
        external work owned by another stage" guarantee once more stages
        are replayable.
    """

    name: str
    order: int
    dependencies: "tuple[str, ...]"
    requires_repo_access: bool
    requires_docker: bool
    requires_llm_provider: bool
    owns_llm_tags: "tuple[str, ...]"
    owns_external_execution: bool


# ---------------------------------------------------------------------------
# The approved dependency graph (canonical names, not numeric IDs).
# ---------------------------------------------------------------------------

STAGE_DEPENDENCIES: "dict[str, tuple[str, ...]]" = {
    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: (),
    REMEDIATION_STRATEGY: (
        REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
    ),
    GUIDED_CONTEXT_ACQUISITION: (
        REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
        REMEDIATION_STRATEGY,
    ),
    PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION: (
        REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
        REMEDIATION_STRATEGY,
        GUIDED_CONTEXT_ACQUISITION,
    ),
    CHALLENGER: (
        PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
    ),
    PATCH_REPAIR_AND_CALIBRATION: (
        PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
        CHALLENGER,
    ),
    PATCH_REVIEW: (
        PATCH_REPAIR_AND_CALIBRATION,
    ),
    CONFIDENCE_SCORING: (
        PATCH_REPAIR_AND_CALIBRATION,
        PATCH_REVIEW,
    ),
    IMPACT_AND_BEHAVIOR_ANALYSIS: (
        PATCH_REPAIR_AND_CALIBRATION,
    ),
    TEST_ANALYSIS_AND_PLAN: (
        PATCH_REPAIR_AND_CALIBRATION,
        IMPACT_AND_BEHAVIOR_ANALYSIS,
    ),
    EXISTING_TEST_COMPARISON: (
        PATCH_REPAIR_AND_CALIBRATION,
        TEST_ANALYSIS_AND_PLAN,
    ),
    TRUST_SIGNALS_AND_RECOMMENDATION: (
        PATCH_REPAIR_AND_CALIBRATION,
        IMPACT_AND_BEHAVIOR_ANALYSIS,
        TEST_ANALYSIS_AND_PLAN,
        EXISTING_TEST_COMPARISON,
    ),
    REPORT_GENERATION: tuple(
        s for s in CANONICAL_STAGE_ORDER if s != REPORT_GENERATION
    ),
}


# ---------------------------------------------------------------------------
# LLM ownership -- an honest reflection of current production `stage=` tags,
# not an aspirational design. Some tags are currently owned by more than
# one canonical stage (see KNOWN_AMBIGUOUS_LLM_TAGS) because the underlying
# production code has not been split apart for all of them yet (Batch A
# fixed this for patch_generation/patch_repair_regeneration only -- see
# pipeline.py's _REPAIR_REGENERATION_STAGE and the architecture report's
# item 29 for "challenger", which remains ambiguous between the challenger
# and patch_repair_and_calibration stages pending a future batch).
# ---------------------------------------------------------------------------

STAGE_OWNED_LLM_TAGS: "dict[str, tuple[str, ...]]" = {
    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: ("remediation_planning",),
    REMEDIATION_STRATEGY: ("remediation_strategy",),
    GUIDED_CONTEXT_ACQUISITION: ("guided_context_request",),
    PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION: (
        "patch_generation",
        "patch_generation_contract_retry",
    ),
    CHALLENGER: ("challenger",),
    PATCH_REPAIR_AND_CALIBRATION: (
        "finding_calibration",
        "challenger",
        "patch_repair_regeneration",
    ),
    PATCH_REVIEW: ("patch_review",),
    CONFIDENCE_SCORING: ("confidence_scorer",),
    IMPACT_AND_BEHAVIOR_ANALYSIS: (),
    TEST_ANALYSIS_AND_PLAN: ("test_plan_discovery",),
    EXISTING_TEST_COMPARISON: (),
    TRUST_SIGNALS_AND_RECOMMENDATION: (),
    REPORT_GENERATION: (),
}

# Tags legitimately owned by more than one canonical stage today -- a KNOWN,
# tracked gap (not silently hidden): full LLM-ownership enforcement cannot
# yet distinguish which of these stages actually made a captured call with
# one of these tags. "patch_generation"/"patch_generation_contract_retry"
# vs. "patch_repair_regeneration" was disambiguated in Batch A (see
# pipeline.py); "challenger" (owned by both `challenger` and
# `patch_repair_and_calibration`) was NOT -- it was out of this batch's
# explicitly approved scope. See the Batch A report, item 29.
KNOWN_AMBIGUOUS_LLM_TAGS: "dict[str, tuple[str, ...]]" = {
    "challenger": (CHALLENGER, PATCH_REPAIR_AND_CALIBRATION),
}


# ---------------------------------------------------------------------------
# Capability metadata -- declared explicitly per stage, never derived from
# the stage's name.
# ---------------------------------------------------------------------------

_REPO_ACCESS: "dict[str, bool]" = {
    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: True,
    REMEDIATION_STRATEGY: True,
    GUIDED_CONTEXT_ACQUISITION: True,
    PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION: True,
    CHALLENGER: False,
    PATCH_REPAIR_AND_CALIBRATION: True,
    PATCH_REVIEW: False,
    CONFIDENCE_SCORING: False,
    IMPACT_AND_BEHAVIOR_ANALYSIS: True,
    TEST_ANALYSIS_AND_PLAN: True,
    EXISTING_TEST_COMPARISON: True,
    TRUST_SIGNALS_AND_RECOMMENDATION: False,
    REPORT_GENERATION: False,
}

_DOCKER: "dict[str, bool]" = {name: False for name in CANONICAL_STAGE_ORDER}
_DOCKER[EXISTING_TEST_COMPARISON] = True

_LLM_PROVIDER: "dict[str, bool]" = {
    name: bool(STAGE_OWNED_LLM_TAGS[name]) for name in CANONICAL_STAGE_ORDER
}

_EXTERNAL_EXECUTION: "dict[str, bool]" = {name: False for name in CANONICAL_STAGE_ORDER}
_EXTERNAL_EXECUTION[REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING] = True  # repo parse
_EXTERNAL_EXECUTION[PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION] = True  # git apply/check + repo parse
_EXTERNAL_EXECUTION[PATCH_REPAIR_AND_CALIBRATION] = True  # git apply/check on regenerated patch
_EXTERNAL_EXECUTION[EXISTING_TEST_COMPARISON] = True  # Docker build+run


def _build_registry() -> "dict[str, StageSpec]":
    """Pure function of the literals above -- called exactly once, at
    module import time, to build STAGE_SPECS. Also used directly by tests
    that want a fresh, independent copy (e.g. to prove import-order
    independence) without relying on the module-level singleton."""
    registry: "dict[str, StageSpec]" = {}
    for order, name in enumerate(CANONICAL_STAGE_ORDER):
        registry[name] = StageSpec(
            name=name,
            order=order,
            dependencies=STAGE_DEPENDENCIES[name],
            requires_repo_access=_REPO_ACCESS[name],
            requires_docker=_DOCKER[name],
            requires_llm_provider=_LLM_PROVIDER[name],
            owns_llm_tags=STAGE_OWNED_LLM_TAGS[name],
            owns_external_execution=_EXTERNAL_EXECUTION[name],
        )
    return registry


# Immutable (MappingProxyType) on top of "never mutated after construction
# by convention" -- a belt-and-suspenders guarantee that nothing, anywhere,
# can accidentally turn this back into an import-order-dependent registry.
# There is no register_*()-style function in this module; there never
# should be one again (see module docstring).
STAGE_SPECS: "MappingProxyType[str, StageSpec]" = MappingProxyType(_build_registry())


def is_canonical_stage(name: str) -> bool:
    return name in STAGE_SPECS
