"""Generic Auto Patcher single-stage replay engine -- Batch A foundation.

Generalizes the Phase-1 mechanics already proven by stage_replay.py
(``replay_test_plan_discovery``) into a stage-registry-driven engine that
can, in principle, replay ANY canonical stage from stage_registry.py --
provided that stage has an entry in ``REPLAY_HANDLERS`` below. Batch A
registers exactly one: ``test_analysis_and_plan`` (a TRANSITIONAL
implementation -- see below). Every other canonical stage is present in
stage_registry.STAGE_SPECS (so dependency declarations, capability
metadata, and LLM ownership are all real from day one) but has no handler
yet, so replaying it fails cleanly via ReplayEngineError, before any I/O
beyond the cheap checks themselves.

WHAT IS REGISTERED WHERE, AND WHY (cleanup-batch redesign): stage_registry.py
is deliberately static and side-effect free -- it answers "what IS this
canonical stage" (dependencies, capabilities, LLM ownership), a question
with one permanent answer per stage, known from day one, independent of
which stages happen to be replayable at any given moment. THIS module
answers a completely different, and much more volatile, question: "which
stages can actually be replayed TODAY, and with what implementation." That
answer is ``REPLAY_HANDLERS``, an explicit dict literal built once here --
never a function that mutates stage_registry.STAGE_SPECS as an import side
effect (an earlier version of this module did that via a
``register_run_fn()`` call; it has been removed). Importing this module
therefore has ZERO effect on stage_registry.STAGE_SPECS, and
stage_registry.STAGE_SPECS is identical no matter what else has or hasn't
been imported, in what order.

This module OWNS every replay-specific concern:
  - source lineage loading (lineage.py)
  - dependency resolution + staleness detection (lineage.py)
  - capability-aware preflight (repo identity/clean-state, Docker
    readiness, LLM provider configuration -- each gated on the selected
    stage's declared capability flags, never run unconditionally)
  - stage invocation (calling the registered handler's run_fn)
  - provenance recording + manifest persistence

Production stage functions (``discover_test_plan``, and every future
stage's real implementation) contain ZERO replay-specific lineage logic --
they are plain functions of their real inputs, called by a stage's
``run_fn`` adapter exactly as production code calls them. The ``run_fn``
adapters registered here are thin: call the real production function(s),
write the stage's own artifact shape to disk, and hand back a
``RunFnResult`` -- they never touch manifests, lineage, or provenance
themselves.

Reused, not rewritten, from stage_replay.py (Phase 1): SourceProvenance,
resolve_source_provenance, validate_target_repository, and the output-
directory safety check. These are already stage-agnostic; nothing about
generalizing replay to more stages requires changing them.

-----------------------------------------------------------------------
"PERSISTED" != "REPLAYABLE" -- READ THIS BEFORE BATCH B
-----------------------------------------------------------------------
Whether a canonical stage's structured artifact can be RESOLVED (a real
StageExecution record exists for it in the lineage) is entirely
independent of whether that stage has an entry in REPLAY_HANDLERS.
lineage.resolve_effective() only ever looks for a matching execution
record -- it has no knowledge of, and no import dependency on, this
module at all. A future full run can therefore record a real
"patch_repair_and_calibration" execution (once ITS production code is
migrated to persist one) long before patch_repair_and_calibration itself
gains a REPLAY_HANDLERS entry -- see
tests/patch/test_lineage.py::test_produced_artifact_resolves_even_when_stage_has_no_replay_handler
for the proof, and lineage.py's module docstring for the full v3
execution-record model this depends on.

This is exactly what test_analysis_and_plan's FINAL contract will need:
it depends on patch_repair_and_calibration and
impact_and_behavior_analysis (stage_registry.STAGE_DEPENDENCIES), so
BEFORE test_analysis_and_plan's full contract can be implemented here,
run_traced.py's PRODUCTION full-run writer must start persisting real
structured artifacts for those two stages -- independent of, and almost
certainly before, either of them gets its own REPLAY_HANDLERS entry. Do
NOT conflate "give this stage a replay handler" with "make this stage's
output resolvable as a dependency" when planning Batch B -- they are
separate, independently-schedulable pieces of work.

-----------------------------------------------------------------------
TRANSITIONAL SCOPE OF test_analysis_and_plan IN BATCH A -- READ THIS
-----------------------------------------------------------------------
test_analysis_and_plan's FINAL, approved contract combines test support
analysis (testing_support.py / test_suggester.py) with Test Plan Discovery
(test_plan_discovery.py), and depends on patch_repair_and_calibration and
impact_and_behavior_analysis (see stage_registry.STAGE_DEPENDENCIES).
Neither of those two upstream stages is replayable yet, NOR does any full
run persist a structured artifact for either of them yet (see the
PERSISTED != REPLAYABLE section above) -- and test support/suggested-tests
logic has not been extracted from pipeline.py's report renderer yet
either (see the architecture report, item 11).

Migrating ONLY the already-working Test Plan Discovery replay onto the new
canonical name, honestly, means this batch's test_analysis_and_plan
handler:
  - calls the CURRENT discover_test_plan(repo_root, llm) production
    function -- identical to Phase 1's replay_test_plan_discovery -- and
    NOTHING else.
  - requires ZERO upstream dependencies to execute
    (REPLAY_HANDLERS[TEST_ANALYSIS_AND_PLAN].dependencies == (), a
    DECLARED, NARROWER subset of the approved final dependencies -- never
    silently widened, never claiming to have consumed dependencies it did
    not; validated at import time by _validate_replay_handlers()).
  - persists ONLY the TestExecutionPlan sub-artifact (or a rejection
    reason). It does NOT compute or persist test_support/suggested_tests
    -- doing so would fabricate state production does not yet produce.
  - marks its own manifest entry "transitional": true, with explicit
    "sub_artifacts_produced"/"sub_artifacts_not_yet_produced" lists, so
    nothing about this state is misleading to a later reader of the
    manifest.

A future batch that implements the full contract must: (1) migrate
run_traced.py to persist real artifacts for patch_repair_and_calibration
and impact_and_behavior_analysis, (2) widen this handler's run_fn to also
compute test_support/suggested_tests, and (3) update
REPLAY_HANDLERS[TEST_ANALYSIS_AND_PLAN].dependencies back to the full
approved set -- at which point downstream stages (existing_test_comparison
etc.) become correctly dependency-checked against it. Nothing else in this
engine needs to change for that to happen; see lineage.py's module
docstring for why "consumed" living in each execution's own manifest
record, not read from the live registry, is what makes this transition
safe.
"""

from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import lineage
from .llm_call_tracing import LLMCallCapture
from .llm_client import LLMClient, ensure_provider_configured
from .run_metadata import collect_full_commit_sha, find_openant_root, is_worktree_clean
from .stage_registry import (
    CANONICAL_STAGE_ORDER,
    STAGE_SPECS,
    TEST_ANALYSIS_AND_PLAN,
    StageSpec,
    is_canonical_stage,
)
from .stage_replay import (  # noqa: F401 -- reused verbatim, see module docstring
    SourceProvenance,
    StageReplayError,
    resolve_source_provenance,
    validate_target_repository,
)
from .stage_replay import _validate_output_dir_is_safe
from .test_plan_discovery import discover_test_plan


class ReplayEngineError(RuntimeError):
    """Raised whenever the generic replay engine cannot proceed -- always
    BEFORE any LLM/external work. Distinct from StageReplayError (which a
    stage's own run_fn, or a reused stage_replay.py helper, may still
    raise for stage-specific infrastructure failures) so a caller can tell
    "the engine itself refused" apart from "the stage's own preflight
    refused" -- run_stage.py's CLI catches both the same way."""


@dataclass(frozen=True)
class RunFnResult:
    """What a stage's run_fn hands back to the engine. The engine, not the
    run_fn, turns this into a StageExecution record / writes
    run_manifest.json -- run_fn only writes its OWN artifact file(s).

    `llm_calls`/`external_calls` are the real, ordered call records this
    execution made (e.g. {"seq":..., "stage":..., "prompt_file":...,
    "response_file":...}) -- attributed to THIS execution, not a bare
    stage-name tag, which is what lets two executions of the same
    canonical stage (once production instrumentation lands in a later
    batch) keep their LLM history unambiguous even when their raw
    `stage=` tags collide."""

    outcome: "Optional[str]"
    artifact_path: "Optional[Path]"
    llm_calls: list = dataclasses.field(default_factory=list)
    external_calls: list = dataclasses.field(default_factory=list)
    extra_stage_fields: dict = dataclasses.field(default_factory=dict)


@dataclass(frozen=True)
class ReplayResult:
    stage: str
    execution_id: str
    outcome: "Optional[str]"
    manifest: dict
    output_dir: Path


@dataclass(frozen=True)
class ReplayHandler:
    """One canonical stage's ACTUAL replay implementation TODAY --
    deliberately separate from stage_registry.StageSpec (see module
    docstring). A stage's static metadata is permanent; whether/how it can
    be replayed is a moving target this dataclass captures explicitly.
    """

    run_fn: Callable
    dependencies: "tuple[str, ...]"
    """What THIS handler currently requires to execute -- may be a strict
    subset of stage_registry.STAGE_DEPENDENCIES[name] during a
    transitional migration (see TEST_ANALYSIS_AND_PLAN below). Validated
    at import time (_validate_replay_handlers) to never be a SUPERSET of
    the approved dependency graph."""


def _assert_llm_ownership(calls: "list[dict]", stage_name: str) -> None:
    """Fail loudly if a stage's run_fn made an LLM call tagged with a
    stage= value it does not own (stage_registry.STAGE_OWNED_LLM_TAGS).
    This cannot prevent the call itself (ownership can only be verified
    after it happened), but it prevents the engine from persisting a
    misleading successful artifact on top of a wiring bug -- the run
    aborts here, before any manifest/artifact is written."""
    owned = set(STAGE_SPECS[stage_name].owns_llm_tags)
    for call in calls:
        if call["stage"] not in owned:
            raise ReplayEngineError(
                f"LLM ownership violation: replaying {stage_name!r} (which "
                f"owns tags {sorted(owned)}) captured a call tagged "
                f"{call['stage']!r}, which it does not own. This indicates "
                f"a bug in {stage_name!r}'s run_fn wiring, not a "
                f"legitimate dependency -- refusing to persist this replay."
            )


# ---------------------------------------------------------------------------
# test_analysis_and_plan -- transitional run_fn (see module docstring)
# ---------------------------------------------------------------------------


def _run_test_analysis_and_plan(
    *,
    repo_root: "Optional[Path]",
    llm: "Optional[LLMClient]",
    output_dir: Path,
    resolved_dependencies: dict,
) -> RunFnResult:
    rejection_reason: "list[str]" = []
    with LLMCallCapture() as capture:
        plan = discover_test_plan(repo_root, llm, rejection_reason=rejection_reason)

    llm_call_records: "list[dict]" = []
    for call in capture.calls:
        seq = call["seq"]
        tag = call["stage"]
        prompt_path = output_dir / f"{seq:03d}_{tag}.prompt.txt"
        response_path = output_dir / f"{seq:03d}_{tag}.response.txt"
        prompt_path.write_text(call["prompt"], encoding="utf-8")
        response_path.write_text(call["response"] or "", encoding="utf-8")
        llm_call_records.append({
            "seq": seq,
            "stage": tag,
            "prompt_file": prompt_path.name,
            "response_file": response_path.name,
        })

    _assert_llm_ownership(capture.calls, TEST_ANALYSIS_AND_PLAN)

    if plan is not None:
        outcome = "accepted"
        artifact_path = output_dir / "test_execution_plan.json"
        artifact_path.write_text(json.dumps(dataclasses.asdict(plan), indent=2), encoding="utf-8")
    else:
        outcome = "rejected"
        reason = rejection_reason[0] if rejection_reason else "unknown (no rejection reason captured)"
        artifact_path = output_dir / "rejection_reason.json"
        artifact_path.write_text(json.dumps({"reason": reason}, indent=2), encoding="utf-8")

    return RunFnResult(
        outcome=outcome,
        artifact_path=artifact_path,
        llm_calls=llm_call_records,
        extra_stage_fields={
            "transitional": True,
            "sub_artifacts_produced": ["test_execution_plan"],
            "sub_artifacts_not_yet_produced": ["test_support", "suggested_tests"],
        },
    )


# ---------------------------------------------------------------------------
# The explicit replay-handler mapping -- a plain dict literal, built once,
# NEVER mutated by importing this or any other module. This is the ONLY
# place "is stage X replayable today" is decided.
# ---------------------------------------------------------------------------

REPLAY_HANDLERS: "dict[str, ReplayHandler]" = {
    TEST_ANALYSIS_AND_PLAN: ReplayHandler(
        run_fn=_run_test_analysis_and_plan,
        # Narrower than the approved final {patch_repair_and_calibration,
        # impact_and_behavior_analysis} -- see module docstring.
        dependencies=(),
    ),
}


def _validate_replay_handlers() -> None:
    """Run once at import time: every handler must reference a real
    canonical stage, and its declared dependencies must be a SUBSET of
    that stage's approved final dependency graph -- a handler may require
    less than the full contract during a transitional migration, never
    more. Fails fast (ValueError) if this module itself is misconfigured;
    never silently accepted."""
    for name, handler in REPLAY_HANDLERS.items():
        if not is_canonical_stage(name):
            raise ValueError(f"REPLAY_HANDLERS references unknown canonical stage {name!r}.")
        approved = set(STAGE_SPECS[name].dependencies)
        declared = set(handler.dependencies)
        if not declared <= approved:
            raise ValueError(
                f"REPLAY_HANDLERS[{name!r}].dependencies {handler.dependencies} "
                f"is not a subset of the approved dependencies "
                f"{STAGE_SPECS[name].dependencies} -- a replay handler may "
                f"require FEWER dependencies than the final contract, never more."
            )


_validate_replay_handlers()


def replayable_stage_names() -> "tuple[str, ...]":
    return tuple(name for name in CANONICAL_STAGE_ORDER if name in REPLAY_HANDLERS)


# ---------------------------------------------------------------------------
# Capability-aware preflight -- each check gated on the SELECTED stage's
# own declared capability flags, never run unconditionally. Small, direct
# functions so each can be unit-tested against any capability combination
# even before a second real stage is replayable.
# ---------------------------------------------------------------------------


def _repo_preflight(spec: StageSpec, repo_root_override: "Optional[str]", provenance: SourceProvenance) -> "Optional[Path]":
    """Runs the repo SHA/clean-worktree gate ONLY if this stage declares
    requires_repo_access. A stage that does not touch the repository (e.g.
    trust_signals_and_recommendation, report_generation) must never pay
    for -- or be blocked by -- a check its own contract never needed."""
    if spec.requires_repo_access:
        return validate_target_repository(repo_root_override, provenance, stage=spec.name)
    return Path(repo_root_override) if repo_root_override else None


def _docker_preflight(spec: StageSpec) -> None:
    """Runs Docker readiness ONLY if this stage declares requires_docker
    (today: only existing_test_comparison). Replaying report_generation
    must never require Docker -- this is the mechanism that guarantees it."""
    if not spec.requires_docker:
        return
    from .existing_test_regression import preflight_test_comparison_environment

    preflight_test_comparison_environment()


def _llm_provider_preflight(spec: StageSpec) -> None:
    """Runs LLM provider/credential resolution ONLY if this stage owns any
    LLM tags. A deterministic stage (impact_and_behavior_analysis,
    trust_signals_and_recommendation, report_generation) never pays for
    provider resolution it will never use."""
    if spec.requires_llm_provider:
        ensure_provider_configured()


# ---------------------------------------------------------------------------
# The engine itself
# ---------------------------------------------------------------------------


def replay_stage(
    *,
    source_run: "Path | str",
    stage_name: str,
    output_dir: "Path | str",
    repo_root_override: "Optional[str]" = None,
) -> ReplayResult:
    """Replay exactly one canonical stage's CURRENT production
    implementation, using upstream state resolved from `source_run`'s
    lineage (a full run, or any prior replay). Never invokes any other
    stage. Raises ReplayEngineError (or StageReplayError, from a reused
    stage_replay.py helper) for every failure, ALWAYS before any
    LLM/external work.
    """
    source_run = Path(source_run)
    output_dir = Path(output_dir)

    # 1. Unknown stage -- before any I/O at all.
    if not is_canonical_stage(stage_name):
        raise ReplayEngineError(
            f"Unknown stage {stage_name!r}. Canonical stages: "
            f"{', '.join(CANONICAL_STAGE_ORDER)}."
        )
    spec = STAGE_SPECS[stage_name]

    # 2. Registered but not replayable yet -- before any I/O at all.
    #    "Not replayable" here means only "no REPLAY_HANDLERS entry" -- it
    #    says NOTHING about whether a structured artifact for this stage
    #    could still be resolved as someone else's dependency (see module
    #    docstring's PERSISTED != REPLAYABLE section).
    handler = REPLAY_HANDLERS.get(stage_name)
    if handler is None:
        replayable = replayable_stage_names()
        raise ReplayEngineError(
            f"Stage {stage_name!r} is registered but not replayable yet. "
            f"Currently replayable: {', '.join(replayable) if replayable else '(none)'}."
        )

    # 3. Output-directory safety -- filesystem check only, no work done.
    _validate_output_dir_is_safe(source_run, output_dir)

    # 4. Resolve source lineage + this handler's EFFECTIVE dependencies
    #    (which may be a transitional subset of the stage's final approved
    #    contract -- see ReplayHandler.dependencies). Missing/stale
    #    dependency -> fail BEFORE any preflight or run_fn.
    chain = lineage.build_chain(source_run)
    cache: dict = {}
    resolved_dependencies: "dict[str, lineage.Resolution]" = {}
    for dep in handler.dependencies:
        resolution = lineage.resolve_effective(chain, dep, cache)
        if not resolution.is_resolved:
            raise ReplayEngineError(
                f"Cannot replay {stage_name!r}: dependency {dep!r} is "
                f"{resolution.state} in this lineage ({resolution.reason}). "
                f"Replay {dep!r} first."
            )
        resolved_dependencies[dep] = resolution

    # 5. Source provenance (needed for repo identity + openant/LLM
    #    provenance recording regardless of this stage's capabilities).
    trace_manifest_path = lineage.resolve_manifest_path(source_run)
    trace_dir = trace_manifest_path.parent
    manifest = lineage.load_manifest(source_run)
    provenance = resolve_source_provenance(trace_dir, manifest)

    # 6. Capability-aware preflight -- each check gated on `spec`'s own
    #    declared flags, never run unconditionally.
    repo_root = _repo_preflight(spec, repo_root_override, provenance)
    _docker_preflight(spec)
    _llm_provider_preflight(spec)

    # 7. Invoke the CURRENT production implementation via the registered
    #    handler's run_fn -- this is the only step that may make an
    #    LLM/external call.
    llm = LLMClient(api_key=os.environ.get("OPENAI_API_KEY", "")) if spec.requires_llm_provider else None
    output_dir.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(timezone.utc)
    run_result = handler.run_fn(
        repo_root=repo_root,
        llm=llm,
        output_dir=output_dir,
        resolved_dependencies=resolved_dependencies,
    )
    finished_at = datetime.now(timezone.utc)

    # 8. OpenAnt/LLM provenance -- reused verbatim from stage_replay.py's
    #    own logic (source vs. replay, never required to match).
    import utilities.autopatcher.llm_client as _llm_module

    openant_root = find_openant_root()
    replay_patcher_commit = collect_full_commit_sha(openant_root) if openant_root else None
    replay_openant_dirty = None if openant_root is None else (is_worktree_clean(openant_root) is False)

    replay_provider = _llm_module._cached_provider
    if replay_provider == "mock":
        replay_model = "mock"
    else:
        replay_model = _llm_module._cached_model.get(replay_provider) if replay_provider else None

    consumed = {dep: res.as_identity_dict() for dep, res in resolved_dependencies.items()}

    # replay_of: does a prior execution of THIS SAME canonical stage exist
    # anywhere in the source lineage? Purely a provenance pointer (not a
    # data dependency, so it never participates in staleness checking) --
    # set only when genuinely knowable, never fabricated. Today, every
    # full run's lineage has no real StageExecution history yet (see
    # lineage.py's module docstring), so this is null for a replay's FIRST
    # hop and only becomes non-null once the same stage is replayed again
    # from a lineage that already contains a real execution of it.
    replay_of = lineage.find_latest_execution_identity(chain, stage_name)

    # run_stage.py always creates exactly one new execution per invocation
    # ("execute one stage and stop") into a freshly-validated, empty
    # --output directory -- sequence is therefore always 1 within it.
    execution_id = lineage.make_execution_id(1, stage_name)
    execution_record = lineage.new_execution_record(
        execution_id=execution_id,
        canonical_stage=stage_name,
        sequence=1,
        invocation_kind=lineage.INVOCATION_KIND_REPLAY,
        consumed=consumed,
        outcome=run_result.outcome,
        replay_of=replay_of,
        artifact_path=run_result.artifact_path,
        llm_calls=run_result.llm_calls,
        external_calls=run_result.external_calls,
        timing={
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "duration_seconds": (finished_at - started_at).total_seconds(),
        },
        extra=run_result.extra_stage_fields,
    )

    replay_manifest = lineage.new_replay_manifest(
        parent=source_run,
        target_repository={
            "repo_root": str(repo_root) if repo_root else provenance.repo_root,
            "repo_commit": provenance.repo_commit,
        },
        openant={
            "source_patcher_commit": provenance.patcher_commit,
            "replay_patcher_commit": replay_patcher_commit,
            "replay_openant_dirty": replay_openant_dirty,
        },
        llm={
            "source_provider": provenance.llm_provider,
            "source_model": provenance.llm_model,
            "replay_provider": replay_provider,
            "replay_model": replay_model,
        },
        executions=[execution_record],
    )
    (output_dir / "run_manifest.json").write_text(json.dumps(replay_manifest, indent=2), encoding="utf-8")

    return ReplayResult(
        stage=stage_name,
        execution_id=execution_id,
        outcome=run_result.outcome,
        manifest=replay_manifest,
        output_dir=output_dir,
    )
