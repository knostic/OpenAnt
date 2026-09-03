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
from .confidence_scorer import score_confidence
from .evidence_fusion import RepositoryUnderstanding
from .execution_recorder import from_jsonable, to_jsonable
from .existing_test_amendment import evaluate_existing_test_comparison_with_amendment
from .existing_test_regression import (
    ExistingTestComparisonResult,
    not_verified_result,
)
from .llm_call_tracing import LLMCallCapture
from .post_patch_evaluation import AnchorObservation, CoverageResult
from .repository_grounding_models import RepositoryGroundingResult
from .llm_client import LLMClient, ensure_provider_configured
from .patch_challenger import challenge_patch
from .patch_reviewer import review_patch
from .pipeline import (
    PipelineResult,
    _adjust_confidence_score_for_challenger,
    _build_report,
    _classify_challenger,
    _run_constraint_signals,
    _run_guided_context_acquisition,
    _run_impact_and_behavior_analysis,
    _run_patch_generation_and_investigation,
    _run_patch_repair_and_calibration,
    _run_remediation_signals,
    _run_repository_analysis_and_remediation_planning,
    _STATIC_SIGNALS_AVAILABLE,
)
from .post_patch_investigation import derive_pre_patch_anchors
from .remediation_planner import (
    EditReadinessResult,
    FinalTargetSliceResult,
    RemediationPlanResult,
    RemediationStrategyResult,
    generate_remediation_strategy,
)
from .run_metadata import collect_full_commit_sha, find_openant_root, is_worktree_clean
from .stage_registry import (
    CANONICAL_STAGE_ORDER,
    CHALLENGER,
    CONFIDENCE_SCORING,
    EXISTING_TEST_COMPARISON,
    GUIDED_CONTEXT_ACQUISITION,
    IMPACT_AND_BEHAVIOR_ANALYSIS,
    PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
    PATCH_REPAIR_AND_CALIBRATION,
    PATCH_REVIEW,
    REMEDIATION_STRATEGY,
    REPORT_GENERATION,
    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
    STAGE_SPECS,
    TEST_ANALYSIS_AND_PLAN,
    StageSpec,
    is_canonical_stage,
)
from .test_execution_models import TestExecutionPlan
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
    `stage=` tags collide.

    `extra_consumed`: {canonical_stage: lineage.Resolution} for any
    dependency this run_fn resolved and genuinely USED on its own,
    OPTIONALLY, via the `chain` it was given -- never through
    handler.dependencies (see _resolve_authoritative_candidate). Merged
    into the written manifest's `consumed` field alongside the mandatory,
    handler.dependencies-derived entries, so `consumed` stays a truthful
    record of what this execution actually read, without requiring an
    optional stage to be a mandatory (and therefore replay-blocking)
    canonical dependency. Empty by default -- every existing run_fn is
    unaffected."""

    outcome: "Optional[str]"
    artifact_path: "Optional[Path]"
    llm_calls: list = dataclasses.field(default_factory=list)
    external_calls: list = dataclasses.field(default_factory=list)
    extra_stage_fields: dict = dataclasses.field(default_factory=dict)
    extra_consumed: dict = dataclasses.field(default_factory=dict)


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
# Shared helpers -- used by every run_fn below (Batch B7 additions), not
# just the transitional test_analysis_and_plan handler.
# ---------------------------------------------------------------------------


def _write_llm_calls_for_stage(calls: "list[dict]", output_dir: Path) -> "list[dict]":
    """Write each captured call's prompt/response to disk and return the
    ordered, pointer-only record list a RunFnResult.llm_calls expects --
    extracted from _run_test_analysis_and_plan (Batch A) so every run_fn
    added since (Batch B7: patch_generation_and_post_patch_investigation/
    challenger/patch_repair_and_calibration/patch_review/
    confidence_scoring) shares this exact, already-proven logic instead of
    each reimplementing it."""
    llm_call_records: "list[dict]" = []
    for call in calls:
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
    return llm_call_records


def _load_json_artifact(resolution: "lineage.Resolution") -> dict:
    """Read and parse an upstream execution's own persisted JSON artifact
    -- the mechanism every run_fn below uses to reconstruct real upstream
    state (never rediscovering/regenerating it)."""
    if resolution.artifact_path is None:
        raise ReplayEngineError(
            f"Cannot replay: dependency resolved at {resolution.run_dir!r} "
            f"has no artifact_path -- nothing to reconstruct from."
        )
    return json.loads(Path(resolution.artifact_path).read_text(encoding="utf-8"))


def _resolve_authoritative_candidate(chain, s6_artifact: dict) -> "tuple[str, dict]":
    """THE one shared, deterministic rule for which candidate patch a
    downstream replay stage (patch_review, confidence_scoring,
    report_generation) must use -- see existing_test_amendment.py's module
    docstring and stage_registry.py's own comment on why this is
    deliberately NOT a canonical dependency.

    Resolves EXISTING_TEST_COMPARISON OPTIONALLY, directly via `chain`
    (the exact same lineage.resolve_effective() idiom
    _run_replay_report_generation already used for S11 before this
    feature existed) -- never through handler.dependencies, so a lineage
    with no existing_test_comparison execution at all (the overwhelming
    majority: compare_existing_tests defaults False) never fails this
    resolution; it just falls back.

    Returns (patch, extra_consumed):
      - S11 resolved AND its own artifact shows an ACCEPTED amendment
        (authoritative_candidate.source == "existing_test_amendment") ->
        (S11's amended patch, {EXISTING_TEST_COMPARISON: s11_resolution})
        -- the caller must merge `extra_consumed` into its RunFnResult so
        the manifest truthfully records that S11 was actually consumed.
      - Otherwise (no S11 execution in this lineage, or one exists but
        never accepted an amendment) -> (S6's own authoritative patch, {})
        -- extra_consumed is empty; the caller must NOT claim S11 was
        consumed when it demonstrably wasn't used.

    Never duplicated inline in each of the three call sites -- see module
    docstring on the Existing Test Amendment feature."""
    s6_patch = s6_artifact["authoritative_candidate"]["patch"]
    if chain is None:
        return s6_patch, {}
    s11_resolution = lineage.resolve_effective(chain, EXISTING_TEST_COMPARISON, {})
    if not s11_resolution.is_resolved:
        return s6_patch, {}
    s11_artifact = _load_json_artifact(s11_resolution)
    authoritative = s11_artifact.get("authoritative_candidate")
    if not authoritative or authoritative.get("source") != "existing_test_amendment":
        return s6_patch, {}
    return authoritative["patch"], {EXISTING_TEST_COMPARISON: s11_resolution}


# ---------------------------------------------------------------------------
# test_analysis_and_plan -- transitional run_fn (see module docstring)
# ---------------------------------------------------------------------------


def _run_test_analysis_and_plan(
    *,
    repo_root: "Optional[Path]",
    llm: "Optional[LLMClient]",
    output_dir: Path,
    resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    rejection_reason: "list[str]" = []
    with LLMCallCapture() as capture:
        plan = discover_test_plan(repo_root, llm, rejection_reason=rejection_reason)

    llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)

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
# repository_analysis_and_remediation_planning (Stage 1) -- Batch B8.
#
# Calls the SAME shared executor production uses
# (pipeline._run_repository_analysis_and_remediation_planning, extracted
# verbatim from pipeline.run() in this same batch). S1 is the pipeline's
# genesis stage -- stage_registry.STAGE_DEPENDENCIES[S1] == (), so there is
# no upstream canonical stage to resolve `vulnerability_text` (S1's own
# real run-level input) from. Instead this run_fn resolves S1's OWN nearest
# PRIOR execution from `chain` (the same lineage.build_chain(source_run)
# object replay_stage() already built to resolve every declared
# dependency) via the same lineage.resolve_effective() every other handler
# uses -- never a new resolution mechanism, just applied to this stage's
# own name instead of a dependency's. That prior execution's artifact
# already carries vulnerability_text (a Batch B7 additive field). This
# always succeeds when replaying S1: `source_run` is always either a full
# run (which always ran S1 first) or a prior replay whose OWN parent chain
# traces back to one.
#
# KNOWN, HONEST LIMITATION: `investigation_output_dir` is passed as None
# (matching S4 replay's already-accepted `_investigation_context=None`
# limitation -- a real, already-supported production code path, not a
# replay-only simplification).
# ---------------------------------------------------------------------------


def _run_replay_repository_analysis_and_remediation_planning(
    *,
    repo_root,
    llm,
    output_dir: Path,
    resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    if chain is None:
        raise ReplayEngineError(
            "Cannot replay repository_analysis_and_remediation_planning: no "
            "lineage chain was supplied to resolve its own prior execution."
        )
    self_resolution = lineage.resolve_effective(chain, REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING, {})
    if not self_resolution.is_resolved:
        raise ReplayEngineError(
            f"Cannot replay repository_analysis_and_remediation_planning: no "
            f"prior execution of this stage exists in this lineage "
            f"({self_resolution.state}: {self_resolution.reason})."
        )
    s1_prior = _load_json_artifact(self_resolution)
    vulnerability_text = s1_prior["vulnerability_text"]

    with LLMCallCapture() as capture:
        s1_locals = _run_repository_analysis_and_remediation_planning(
            vulnerability_text=vulnerability_text,
            repo_root=repo_root,
            investigation_output_dir=None,
            llm=llm,
        )

    llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)
    _assert_llm_ownership(capture.calls, REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING)

    plan_result = s1_locals["_plan_result"]
    plan_text = s1_locals["_plan_text"]
    if plan_result is not None:
        outcome = "generated"
    elif plan_text:
        outcome = "skipped_hand_authored_plan"
    else:
        outcome = "unavailable"

    artifact = {
        "plan_result": to_jsonable(plan_result),
        "repository_understanding": to_jsonable(s1_locals["_repository_understanding"]),
        "pre_patch_anchors": to_jsonable(s1_locals["_pre_patch_anchors"]),
        "vulnerability_text": vulnerability_text,
        "repository_understanding_ctx": s1_locals["_repository_understanding_ctx"],
        "planner_evidence_ctx": s1_locals["_planner_evidence_ctx"],
        "plan_ctx": s1_locals["_plan_ctx"],
        "repo_code": s1_locals["_repo_code"],
        "grounding": to_jsonable(s1_locals["_grounding"]),
    }
    artifact_path = output_dir / "repository_analysis_and_remediation_planning.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    return RunFnResult(
        outcome=outcome,
        artifact_path=artifact_path,
        llm_calls=llm_call_records,
        extra_stage_fields={
            "canonical_contract_scope": "full",
            "replay_limitations": {"investigation_context": "not reconstructed (None) -- see run_fn docstring"},
        },
    )


# ---------------------------------------------------------------------------
# remediation_strategy (Stage 2) -- Batch B8. generate_remediation_strategy()
# is already a pure, standalone production function; this adapter only
# resolves S1's real persisted evidence and wraps the call -- no extraction
# from pipeline.py needed (same pattern as challenger/patch_review).
# ---------------------------------------------------------------------------


def _run_replay_remediation_strategy(
    *,
    repo_root,
    llm,
    output_dir: Path,
    resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s1 = _load_json_artifact(resolved_dependencies[REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING])
    vulnerability_text = s1["vulnerability_text"]
    repository_understanding_ctx = s1.get("repository_understanding_ctx") or ""
    planner_evidence_ctx = s1.get("planner_evidence_ctx") or ""
    plan_ctx = s1.get("plan_ctx") or ""
    repo_code = s1.get("repo_code") or ""

    with LLMCallCapture() as capture:
        strategy_result = generate_remediation_strategy(
            vulnerability_text, llm, repo_root, None,
            repo_grounding_ctx=repo_code,
            repository_understanding_ctx=repository_understanding_ctx,
            discovery_plan_ctx=plan_ctx,
            planner_evidence_ctx=planner_evidence_ctx,
        )

    llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)
    _assert_llm_ownership(capture.calls, REMEDIATION_STRATEGY)

    outcome = "generated" if strategy_result is not None and strategy_result.rendered else (
        "skipped_no_planner_evidence" if not planner_evidence_ctx else "unavailable"
    )
    artifact = {"strategy_result": to_jsonable(strategy_result)}
    artifact_path = output_dir / "remediation_strategy.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    return RunFnResult(
        outcome=outcome,
        artifact_path=artifact_path,
        llm_calls=llm_call_records,
        extra_stage_fields={
            "replay_limitations": {"investigation_context": "not reconstructed (None) -- see S4 run_fn docstring"},
        },
    )


# ---------------------------------------------------------------------------
# guided_context_acquisition (Stage 3) -- Batch B8. Calls the SAME shared
# executor production uses (pipeline._run_guided_context_acquisition,
# extracted verbatim from pipeline.run() in this same batch) -- the Final-
# Target Slice, Edit Readiness Gate, Slice 2 deterministic + Slice 3
# LLM-guided acquisition, and the target-file fallback, all preserved
# exactly. KNOWN, HONEST LIMITATION: `_investigation_context` is None
# (same already-accepted limitation as S4/S2 replay above) and
# `budget_controller` is None (fixed-budget default).
# ---------------------------------------------------------------------------


def _run_replay_guided_context_acquisition(
    *,
    repo_root,
    llm,
    output_dir: Path,
    resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s1 = _load_json_artifact(resolved_dependencies[REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING])
    s2 = _load_json_artifact(resolved_dependencies[REMEDIATION_STRATEGY])

    vulnerability_text = s1["vulnerability_text"]
    plan_result = from_jsonable(RemediationPlanResult, s1.get("plan_result"))
    strategy_result = from_jsonable(RemediationStrategyResult, s2.get("strategy_result"))

    with LLMCallCapture() as capture:
        s3_locals = _run_guided_context_acquisition(
            vulnerability_text=vulnerability_text, llm=llm, repo_root=repo_root, budget_controller=None,
            _strategy_result=strategy_result, _plan_result=plan_result, _investigation_context=None,
        )

    llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)
    _assert_llm_ownership(capture.calls, GUIDED_CONTEXT_ACQUISITION)

    slice_result = s3_locals["_slice_result"]
    edit_readiness = s3_locals["_edit_readiness"]
    skip_patch_generation = s3_locals["_skip_patch_generation"]
    has_targets = strategy_result is not None and (strategy_result.target_files or strategy_result.target_symbols)
    outcome = "ready" if slice_result is not None else ("skipped_no_strategy_targets" if not has_targets else "unavailable")

    artifact = {
        "slice_result": to_jsonable(slice_result),
        "edit_readiness": to_jsonable(edit_readiness),
        "skip_patch_generation": skip_patch_generation,
    }
    artifact_path = output_dir / "guided_context_acquisition.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    return RunFnResult(
        outcome=outcome,
        artifact_path=artifact_path,
        llm_calls=llm_call_records,
        extra_stage_fields={
            "replay_limitations": {"investigation_context": "not reconstructed (None) -- see run_fn docstring"},
        },
    )


# ---------------------------------------------------------------------------
# The explicit replay-handler mapping -- a plain dict literal, built once,
# NEVER mutated by importing this or any other module. This is the ONLY
# place "is stage X replayable today" is decided.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# patch_generation_and_post_patch_investigation (Stage 4) -- Batch B7.
#
# Calls the SAME shared executor production uses
# (pipeline._run_patch_generation_and_investigation, extracted verbatim
# from pipeline.run() in this same batch) -- this run_fn is a thin adapter
# reconstructing that function's real inputs from upstream artifacts, never
# a parallel reimplementation of Stage 4's own logic.
#
# KNOWN, HONEST LIMITATION: `_investigation_context` (a repo-parser cache
# object, never persisted as JSON -- see build_investigation_context) is
# passed as None, exactly like a real production run that never received
# an investigation_output_dir (an already-supported, real production code
# path -- not a replay-only simplification of Stage 4's OWN contract).
# `budget_controller` is likewise None (fixed-budget behavior, the default
# for most production callers already). Every other input (vulnerability_
# text, the Planner/Strategy/Slice structured results, Edit Readiness) is
# reconstructed from real upstream artifacts via execution_recorder.
# from_jsonable() and used exactly as production does.
# ---------------------------------------------------------------------------


def _run_replay_patch_generation_and_investigation(
    *, repo_root, llm, output_dir: Path, resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s1 = _load_json_artifact(resolved_dependencies[REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING])
    s2 = _load_json_artifact(resolved_dependencies[REMEDIATION_STRATEGY])
    s3 = _load_json_artifact(resolved_dependencies[GUIDED_CONTEXT_ACQUISITION])

    vulnerability_text = s1["vulnerability_text"]
    plan_result = from_jsonable(RemediationPlanResult, s1.get("plan_result"))
    repository_understanding = from_jsonable(RepositoryUnderstanding, s1.get("repository_understanding"))
    repository_understanding_ctx = s1.get("repository_understanding_ctx") or ""
    pre_patch_anchors = (
        derive_pre_patch_anchors(repository_understanding) if repository_understanding is not None else None
    )

    strategy_result = from_jsonable(RemediationStrategyResult, s2.get("strategy_result"))

    edit_readiness = from_jsonable(EditReadinessResult, s3.get("edit_readiness"))
    slice_result = from_jsonable(FinalTargetSliceResult, s3.get("slice_result"))
    skip_patch_generation = bool(s3.get("skip_patch_generation"))

    # Reconstructed the same way pipeline.run() assembles it -- concatenating
    # each upstream stage's own rendered text, in the same order, skipping
    # empty parts. Real, persisted content; not an approximation of VALUES,
    # only of the (unpersisted) _repo_code/_pattern_ctx/_planner_evidence_ctx
    # sections production also includes -- see this function's docstring.
    code_context = "\n\n".join(
        p for p in [
            plan_result.rendered if plan_result else "",
            repository_understanding_ctx,
            strategy_result.rendered if strategy_result else "",
            slice_result.rendered if slice_result else "",
        ] if p and p.strip()
    )

    with LLMCallCapture() as capture:
        s4_locals = _run_patch_generation_and_investigation(
            vulnerability_text=vulnerability_text, llm=llm, repo_root=repo_root, code_context=code_context,
            budget_controller=None, _skip_patch_generation=skip_patch_generation,
            _edit_readiness=edit_readiness, _slice_result=slice_result, _investigation_context=None,
            _pre_patch_anchors=pre_patch_anchors, _plan_result=plan_result, _strategy_result=strategy_result,
        )

    llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)
    _assert_llm_ownership(capture.calls, PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION)

    patch = s4_locals["patch"]
    outcome = (
        "no_candidate_patch"
        if s4_locals["_patch_validation_skip_reason"] is not None or not (patch and patch.strip())
        else "settled"
    )
    _post_patch_ctx = s4_locals["_post_patch_ctx"]
    artifact = {
        "patch": patch,
        "original_patch": s4_locals["original_patch"],
        "retry_patch": s4_locals["retry_patch"],
        "retry_attempted": s4_locals["retry_attempted"],
        "retry_succeeded": s4_locals["retry_succeeded"],
        "retry_failed_file": s4_locals["retry_failed_file"],
        "retry_error_before": s4_locals["retry_error_before"],
        "hygiene_findings": to_jsonable(s4_locals["hygiene_findings"]),
        "applicability_result": to_jsonable(s4_locals["applicability_result"]),
        "final_repair_meta": to_jsonable(s4_locals["_final_repair_meta"]),
        "patch_target_conformance": to_jsonable(s4_locals["_patch_target_conformance"]),
        "post_patch_recovery": to_jsonable(s4_locals["_post_patch_recovery"]),
        "post_patch_observations": to_jsonable(s4_locals["_post_patch_observations"]),
        "post_patch_coverage": to_jsonable(s4_locals["_post_patch_coverage"]),
        "investigated_patch": s4_locals["_investigated_patch"],
        "code_context": code_context,
        "challenger_context": code_context + (("\n\n" + _post_patch_ctx) if _post_patch_ctx.strip() else ""),
        "vulnerability_text": vulnerability_text,
    }
    artifact_path = output_dir / "patch_generation_and_post_patch_investigation.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    return RunFnResult(
        outcome=outcome,
        artifact_path=artifact_path,
        llm_calls=llm_call_records,
        extra_stage_fields={
            "canonical_contract_scope": "full",
            "replay_limitations": {"investigation_context": "not reconstructed (None) -- see run_fn docstring"},
        },
    )


# ---------------------------------------------------------------------------
# challenger (Stage 5) -- Batch B7. challenge_patch() is already a pure,
# standalone production function; this adapter only resolves S4's real
# persisted patch/context and wraps the call.
# ---------------------------------------------------------------------------


def _run_replay_challenger(
    *, repo_root, llm, output_dir: Path, resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s4 = _load_json_artifact(resolved_dependencies[PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION])
    vulnerability_text = s4["vulnerability_text"]
    patch = s4["patch"]
    challenger_context = s4.get("challenger_context") or ""

    with LLMCallCapture() as capture:
        challenger = challenge_patch(vulnerability_text, patch, llm, code_context=challenger_context)

    llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)
    _assert_llm_ownership(capture.calls, CHALLENGER)

    outcome = "settled" if (patch and patch.strip()) else "skipped_no_candidate_patch"
    artifact = {
        "challenger": to_jsonable(challenger),
        "classified_challenger": to_jsonable(_classify_challenger(challenger)),
    }
    artifact_path = output_dir / "challenger.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    return RunFnResult(outcome=outcome, artifact_path=artifact_path, llm_calls=llm_call_records)


# ---------------------------------------------------------------------------
# patch_repair_and_calibration (Stage 6) -- Batch B7. Calls the SAME shared
# executor production uses (pipeline._run_patch_repair_and_calibration,
# extracted verbatim in this same batch). Repair regeneration/re-challenge
# remain internal to this one execution, exactly as production -- never
# migrated to canonical S4#2/S5#2 in this MVP.
# ---------------------------------------------------------------------------


def _run_replay_patch_repair_and_calibration(
    *, repo_root, llm, output_dir: Path, resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s4 = _load_json_artifact(resolved_dependencies[PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION])
    s5 = _load_json_artifact(resolved_dependencies[CHALLENGER])

    vulnerability_text = s4["vulnerability_text"]
    patch = s4["patch"]
    code_context = s4.get("code_context") or ""
    challenger_context = s4.get("challenger_context") or ""
    applicability_result = s4.get("applicability_result") or {}
    hygiene_findings = s4.get("hygiene_findings") or []
    final_repair_meta = s4.get("final_repair_meta")
    post_patch_observations = s4.get("post_patch_observations")
    investigated_patch = s4.get("investigated_patch")
    challenger = s5["challenger"]

    with LLMCallCapture() as capture:
        s6_locals = _run_patch_repair_and_calibration(
            vulnerability_text=vulnerability_text, llm=llm, repo_root=repo_root, code_context=code_context,
            challenger_context=challenger_context, patch=patch, challenger=challenger,
            applicability_result=applicability_result, hygiene_findings=hygiene_findings,
            _final_repair_meta=final_repair_meta, _post_patch_observations=post_patch_observations,
            _investigated_patch=investigated_patch,
        )

    llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)
    _assert_llm_ownership(capture.calls, PATCH_REPAIR_AND_CALIBRATION)

    final_patch = s6_locals["patch"]
    repair_attempted = s6_locals["repair_attempted"]
    outcome = "no_candidate_patch" if not (final_patch and final_patch.strip()) and not repair_attempted else "settled"

    if not repair_attempted:
        repair_outcome = "not_triggered_no_defects" if s6_locals["_orig_defect_count"] == 0 else "not_triggered_gate_declined"
    elif s6_locals["_r_applicable"] is None:
        repair_outcome = "attempted_failed"
    elif s6_locals["_r_applicable"] is False:
        repair_outcome = "attempted_inapplicable"
    elif s6_locals["repair_succeeded"]:
        repair_outcome = "attempted_applicable_accepted"
    elif s6_locals["repair_rechallenged"]:
        repair_outcome = "attempted_applicable_rejected"
    else:
        repair_outcome = "attempted_failed"

    authoritative_candidate = {
        "source": "internal_repair" if s6_locals["repair_succeeded"] else "original",
        "patch": final_patch,
        "applicability_result": to_jsonable(s6_locals["applicability_result"]),
        "hygiene_findings": to_jsonable(s6_locals["hygiene_findings"]),
    }
    artifact = {
        "original_candidate_evaluated": {
            "patch": patch,
            "challenger": to_jsonable(s6_locals["_repair_classified"]),
        },
        "repair_attempted": repair_attempted,
        "repair_regeneration": (
            {
                "patch": s6_locals["repair_patch_content"],
                "hygiene_findings": to_jsonable(s6_locals["_r_hygiene"]) if repair_attempted else None,
                "applicability_result": to_jsonable(s6_locals["_r_app"]) if repair_attempted else None,
            } if repair_attempted else None
        ),
        "repair_rechallenge": (
            {
                "challenger": to_jsonable(s6_locals["repair_challenger_result"]),
                "confirmed_defect_count": s6_locals["repair_defect_count"],
            } if s6_locals["repair_rechallenged"] else None
        ),
        "repair_outcome": repair_outcome,
        "finding_calibration": to_jsonable(s6_locals["finding_calibration"]),
        "finding_calibration_source": s6_locals["_finding_calibration_source"],
        "authoritative_candidate": authoritative_candidate,
        "vulnerability_text": vulnerability_text,
        # Batch B8: same additive field as production -- see pipeline.py's
        # S6 finish-block comment. s6_locals["challenger"] is the SAME
        # local var _run_patch_repair_and_calibration() returns from
        # locals() -- final, raw, post-repair-decision.
        "challenger": to_jsonable(s6_locals["challenger"]),
    }
    artifact_path = output_dir / "patch_repair_and_calibration.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    return RunFnResult(outcome=outcome, artifact_path=artifact_path, llm_calls=llm_call_records)


# ---------------------------------------------------------------------------
# patch_review (Stage 7) -- Batch B7. review_patch() is already a pure,
# standalone production function; this adapter uses S6's own AUTHORITATIVE
# candidate (original or accepted-repair, whichever S6 actually selected).
# ---------------------------------------------------------------------------


def _run_replay_patch_review(
    *, repo_root, llm, output_dir: Path, resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s6 = _load_json_artifact(resolved_dependencies[PATCH_REPAIR_AND_CALIBRATION])
    vulnerability_text = s6["vulnerability_text"]
    patch, extra_consumed = _resolve_authoritative_candidate(chain, s6)

    outcome = "skipped_no_candidate_patch"
    review = ""
    llm_call_records: "list[dict]" = []
    if patch and patch.strip():
        with LLMCallCapture() as capture:
            review = review_patch(vulnerability_text, patch, llm)
        llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)
        _assert_llm_ownership(capture.calls, PATCH_REVIEW)
        outcome = "settled"

    artifact_path = output_dir / "patch_review.json"
    artifact_path.write_text(json.dumps({"review": review}, indent=2), encoding="utf-8")

    return RunFnResult(
        outcome=outcome, artifact_path=artifact_path, llm_calls=llm_call_records, extra_consumed=extra_consumed,
    )


# ---------------------------------------------------------------------------
# confidence_scoring (Stage 8) -- Batch B7. score_confidence() plus the
# SAME shared deterministic adjustment production uses
# (pipeline._adjust_confidence_score_for_challenger, extracted verbatim in
# this same batch) -- never a duplicated reimplementation of the 0.4x/0.7x
# adjustment logic.
# ---------------------------------------------------------------------------


def _run_replay_confidence_scoring(
    *, repo_root, llm, output_dir: Path, resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s6 = _load_json_artifact(resolved_dependencies[PATCH_REPAIR_AND_CALIBRATION])
    s7 = _load_json_artifact(resolved_dependencies[PATCH_REVIEW])
    vulnerability_text = s6["vulnerability_text"]
    patch, extra_consumed = _resolve_authoritative_candidate(chain, s6)
    # Batch B8 fix: `original_candidate_evaluated.challenger` is the
    # CLASSIFIED shape (_classify_challenger's own keys -- confirmed_defect_
    # count/classified_edge_cases/...), not the RAW shape
    # _adjust_confidence_score_for_challenger() actually reads
    # (still_vulnerable/edge_cases/potential_issues) -- using it here always
    # silently fell through to "no adjustment" regardless of the real
    # Challenger verdict. `s6["challenger"]` (added this batch for S9's own
    # need) is the FINAL, RAW, post-repair-decision challenger -- the
    # correct input, matching what production's own S8 call reads.
    challenger = s6["challenger"]
    review = s7["review"]

    outcome = "skipped_no_candidate_patch"
    score_text = ""
    llm_call_records: "list[dict]" = []
    orig_score = None
    adjusted_score = None
    if patch and patch.strip():
        with LLMCallCapture() as capture:
            score_text = score_confidence(vulnerability_text, patch, review, llm, code_context="")
        llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)
        _assert_llm_ownership(capture.calls, CONFIDENCE_SCORING)
        adj = _adjust_confidence_score_for_challenger(score_text, challenger)
        orig_score = adj["orig_score"]
        adjusted_score = adj["adjusted_score"]
        score_text = adj["score_text"]
        outcome = "settled"

    artifact = {"score_text": score_text, "orig_score": orig_score, "adjusted_score": adjusted_score}
    artifact_path = output_dir / "confidence_scoring.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    return RunFnResult(
        outcome=outcome,
        artifact_path=artifact_path,
        llm_calls=llm_call_records,
        extra_stage_fields={
            # Known, honest limitation: CONFIDENCE_SCORING's declared
            # dependencies are (patch_repair_and_calibration, patch_review)
            # only (stage_registry) -- production's own code_context choice
            # for this call (challenger_context vs. plain code_context,
            # gated on post-patch-evidence staleness) is Stage-4-derived
            # state this stage does not canonically depend on, so replay
            # uses "" rather than reaching into a non-canonical dependency.
            # The deterministic 0.4x/0.7x adjustment (this stage's own
            # decision) is identical to production either way -- it never
            # reads code_context, only `challenger`.
            "replay_limitations": {"code_context": "empty -- see run_fn docstring"},
        },
        extra_consumed=extra_consumed,
    )


# ---------------------------------------------------------------------------
# impact_and_behavior_analysis (Stage 9) -- Batch B8. Calls the SAME shared
# executor production uses (pipeline._run_impact_and_behavior_analysis,
# extracted verbatim from pipeline.run() in this same batch). Depends ONLY
# on patch_repair_and_calibration (stage_registry.STAGE_DEPENDENCIES),
# matching the real dataflow: both analyzers read only S6-settled
# `patch`/`challenger`, never patch_review/confidence_scoring. No LLM work
# -- both analyzers are purely deterministic.
# ---------------------------------------------------------------------------


def _run_replay_impact_and_behavior_analysis(
    *, repo_root, llm, output_dir: Path, resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s6 = _load_json_artifact(resolved_dependencies[PATCH_REPAIR_AND_CALIBRATION])
    patch, extra_consumed = _resolve_authoritative_candidate(chain, s6)
    challenger = s6["challenger"]

    s9_locals = _run_impact_and_behavior_analysis(patch=patch, challenger=challenger, repo_root=repo_root)

    artifact = {
        "impact": to_jsonable(s9_locals["impact_dict"]),
        "behavior": to_jsonable(s9_locals["behavior"]),
        "detected_language": s9_locals["_detected_language"],
    }
    artifact_path = output_dir / "impact_and_behavior_analysis.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    return RunFnResult(
        outcome="settled", artifact_path=artifact_path, llm_calls=[], extra_consumed=extra_consumed,
    )


# ---------------------------------------------------------------------------
# existing_test_comparison (Stage 11) -- Batch B8.
# evaluate_existing_test_comparison_with_plan() is already a pure,
# standalone production function (the COMPARISON half of the Batch B5
# discovery/comparison split) -- this adapter resolves S10's own resolved
# plan and S6's own settled patch, and calls it directly. It MUST NOT call
# discover_test_plan/discover_test_plan_for_comparison itself -- doing so
# would rediscover S10's plan instead of consuming the one already
# resolved, which is exactly the bug the B5 split exists to prevent.
#
# `executor=None`: an already-supported, real production code path (see
# evaluate_existing_test_comparison_with_plan's own docstring -- "When
# omitted... this function selects and preflights its own, same as before
# this module's discovery/comparison split") -- NOT a replay-only
# simplification. The ALREADY-preflighted executor discover_test_plan_for_
# comparison() builds is a live process/Docker handle, never JSON-
# serializable, so it cannot be threaded through S10's persisted artifact
# -- this costs one extra (harmless) preflight call, nothing else.
#
# When S10 was itself REJECTED (no plan discovered), production's S11
# truthfully never attempts comparison (the fused function's own original
# behavior) -- this handler replicates that via the SAME not_verified_
# result() constructor pipeline.py itself uses for its early-exit checks,
# never inventing a new "skipped" shape.
#
# LLM Test Failure Evidence Distillation: `llm=llm` is passed straight
# through to the SAME production function, wrapped in LLMCallCapture()
# exactly like every other LLM-owning stage's replay handler below --
# evaluate_existing_test_comparison_with_plan() itself decides, from the
# SAME deterministic gate production uses, whether a distillation call
# happens at all (see that function's own docstring). This stage newly
# owns the "test_failure_distillation" LLM tag (stage_registry.py) as of
# this feature.
# ---------------------------------------------------------------------------


def _run_replay_existing_test_comparison(
    *, repo_root, llm, output_dir: Path, resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s2 = _load_json_artifact(resolved_dependencies[REMEDIATION_STRATEGY])
    s6 = _load_json_artifact(resolved_dependencies[PATCH_REPAIR_AND_CALIBRATION])
    s10 = _load_json_artifact(resolved_dependencies[TEST_ANALYSIS_AND_PLAN])
    patch = s6["authoritative_candidate"]["patch"]
    strategy_result = from_jsonable(RemediationStrategyResult, s2.get("strategy_result"))
    security_invariant = strategy_result.security_invariant if strategy_result is not None else None

    if "setup_commands" not in s10:
        # S10 was rejected (no TestExecutionPlan) -- matches production's
        # "no plan -> S11 truthfully never attempts comparison" branch.
        # No test execution happens at all in this branch, so there is
        # nothing an LLM Test Failure Evidence Distillation/Existing Test
        # Amendment call could ever be given -- capturing calls here would
        # be pure overhead for a branch that structurally cannot produce
        # any.
        reason = s10.get("reason") or "no test execution plan was discovered"
        result = not_verified_result(reason)
        outcome = "skipped_no_plan"
        llm_call_records: "list[dict]" = []
        amendment_outcome = None
    else:
        plan = from_jsonable(TestExecutionPlan, s10)
        # LLMCallCapture wraps this the same way _run_test_analysis_and_
        # plan does: the SAME shared orchestrator production uses
        # (evaluate_existing_test_comparison_with_amendment) is called
        # here too -- distillation and/or amendment fire or don't based on
        # the SAME deterministic gates production uses, never a
        # replay-only decision. capture.calls is simply empty when neither
        # gate fires, exactly like production would make zero LLM calls in
        # that case too.
        with LLMCallCapture() as capture:
            amendment_outcome = evaluate_existing_test_comparison_with_amendment(
                repo_root, patch, plan, security_invariant=security_invariant, executor=None, llm=llm,
            )
        result = amendment_outcome.result
        patch = amendment_outcome.patch
        llm_call_records = _write_llm_calls_for_stage(capture.calls, output_dir)
        _assert_llm_ownership(capture.calls, EXISTING_TEST_COMPARISON)
        outcome = "settled"

    artifact = to_jsonable(result)
    if amendment_outcome is not None:
        # Additive-only fields -- same shape as pipeline.py's own S11
        # artifact (see run()'s S11 finish-block comment) -- kept
        # byte-for-byte consistent between production and replay.
        artifact["test_amendment"] = {
            "status": amendment_outcome.amendment.status,
            "reason": amendment_outcome.amendment.reason,
            "accepted": amendment_outcome.accepted,
            "grounded_files": list(amendment_outcome.amendment.grounded_files),
            "ungrounded_ids": list(amendment_outcome.amendment.ungrounded_ids),
        }
        if amendment_outcome.pre_amendment_result is not None:
            artifact["pre_amendment_result"] = to_jsonable(amendment_outcome.pre_amendment_result)
        artifact["authoritative_candidate"] = {
            "source": "existing_test_amendment" if amendment_outcome.accepted else "original",
            "patch": patch,
        }
    artifact_path = output_dir / "existing_test_comparison.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")

    return RunFnResult(outcome=outcome, artifact_path=artifact_path, llm_calls=llm_call_records)


# ---------------------------------------------------------------------------
# report_generation -- Batch B8. ONE COMBINED replay unit for the current
# terminal tail (trust_signals_and_recommendation + report_generation),
# per this batch's explicit instruction: _build_report()'s own internals
# fuse Trust Signals/Recommendation computation with pure rendering too
# deeply to cleanly separate as two canonical executions (see B6's
# investigation) -- rather than force an artificial split, this handler
# reconstructs a REAL PipelineResult from every upstream stage's own
# persisted artifact and calls _build_report() DIRECTLY, UNMODIFIED. No
# recommendation-policy or report-rendering logic is duplicated here --
# _compute_trust_signals/_build_recommendation_v1/every render_* helper
# are invoked exactly once, inside _build_report() itself.
#
# Registered under report_generation ONLY (not also trust_signals_and_
# recommendation) -- there is no real, separate execution of "just the
# trust signals half" to replay; report_generation's own approved
# dependency set (stage_registry.STAGE_DEPENDENCIES: all 12 other stages)
# is also the only one broad enough to honestly cover every artifact this
# reconstruction actually reads. This is "the smallest honest
# representation" of one fused unit, not two pretended-independent ones.
#
# Batch B8 correction: stage_registry._REPO_ACCESS[REPORT_GENERATION] was
# changed True (see that module) -- _build_report() DOES read the
# repository (tests_for_file(), Suggested Tests section) whenever
# repo_root is not None, exactly like every other repo-accessing stage.
#
# Fields NEVER read by _build_report() (verified by exhaustive grep of
# `result.<field>` across pipeline.py) get an honest None here, never a
# fabricated value: relocation_telemetry, edit_readiness, edit_acquisition,
# guided_acquisition, patch_target_conformance, post_patch_recovery. Only
# `security_invariant` (read by build_validation_plan) needs S2's artifact
# among the "observability-only slice" fields.
#
# constraint_signals/remediation_signals: recomputed via the SAME
# production functions (pipeline._run_constraint_signals/
# _run_remediation_signals) directly on the final `patch` + `repo_root` --
# cheap, deterministic, no LLM -- exactly as production's own call site
# does; never persisted anywhere upstream, so recomputation (not
# duplication of POLICY, just of a pure function call) is the honest
# option, matching the S1 constraint/remediation-signals rationale used
# elsewhere in this batch.
# ---------------------------------------------------------------------------


def _run_replay_report_generation(
    *, repo_root, llm, output_dir: Path, resolved_dependencies: dict,
    chain=None,
) -> RunFnResult:
    s1 = _load_json_artifact(resolved_dependencies[REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING])
    s2 = _load_json_artifact(resolved_dependencies[REMEDIATION_STRATEGY])
    s4 = _load_json_artifact(resolved_dependencies[PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION])
    s6 = _load_json_artifact(resolved_dependencies[PATCH_REPAIR_AND_CALIBRATION])
    s7 = _load_json_artifact(resolved_dependencies[PATCH_REVIEW])
    s8 = _load_json_artifact(resolved_dependencies[CONFIDENCE_SCORING])
    s9 = _load_json_artifact(resolved_dependencies[IMPACT_AND_BEHAVIOR_ANALYSIS])

    # existing_test_comparison is genuinely OPTIONAL (compare_existing_tests
    # defaults False in production) -- resolved directly via `chain` (the
    # SAME lineage.resolve_effective() every declared dependency above
    # already used), never through handler.dependencies, so its absence
    # never fails this replay -- matches production's own `None` default.
    s11 = None
    if chain is not None:
        s11_resolution = lineage.resolve_effective(chain, EXISTING_TEST_COMPARISON, {})
        if s11_resolution.is_resolved:
            s11 = _load_json_artifact(s11_resolution)

    strategy_result = from_jsonable(RemediationStrategyResult, s2.get("strategy_result"))
    grounding = from_jsonable(RepositoryGroundingResult, s1.get("grounding"))

    authoritative = s6["authoritative_candidate"]
    # THE shared rule for which candidate patch wins (S6's original/internally
    # -repaired candidate, or S11's accepted existing-test-amended one) -- see
    # _resolve_authoritative_candidate's own docstring. `repair_succeeded`
    # below stays S6-sourced on purpose: it answers "did the Challenger-driven
    # repair loop replace S6's own candidate", a different, S6-only question
    # from "which candidate is authoritative NOW".
    patch, extra_consumed = _resolve_authoritative_candidate(chain, s6)
    repair_succeeded = authoritative["source"] == "internal_repair"
    repair_regeneration = s6.get("repair_regeneration")
    repair_rechallenge = s6.get("repair_rechallenge")
    original_challenger_defect_count = s6["original_candidate_evaluated"]["challenger"]["confirmed_defect_count"]

    post_patch_observations = (
        [from_jsonable(AnchorObservation, o) for o in s4["post_patch_observations"]]
        if s4.get("post_patch_observations") is not None else None
    )
    post_patch_coverage = (
        from_jsonable(CoverageResult, s4["post_patch_coverage"])
        if s4.get("post_patch_coverage") is not None else None
    )

    existing_test_comparison = from_jsonable(ExistingTestComparisonResult, s11) if s11 else None

    constraint_signals = None
    remediation_signals = None
    if _STATIC_SIGNALS_AVAILABLE and repo_root:
        try:
            constraint_signals = _run_constraint_signals(patch, Path(repo_root))
        except Exception:
            pass
        try:
            remediation_signals = _run_remediation_signals(patch, Path(repo_root))
        except Exception:
            pass

    result = PipelineResult(
        vulnerability_text=s6["vulnerability_text"],
        patch=patch,
        review=s7["review"],
        score_text=s8["score_text"],
        challenger=s6["challenger"],
        impact=s9.get("impact"),
        final_score=s8.get("adjusted_score"),
        orig_score=s8.get("orig_score"),
        behavior=s9.get("behavior"),
        repo_root=Path(repo_root) if repo_root else None,
        hygiene=authoritative.get("hygiene_findings"),
        applicability=authoritative.get("applicability_result"),
        original_patch=s4.get("original_patch", ""),
        retry_patch=s4.get("retry_patch"),
        retry_attempted=bool(s4.get("retry_attempted")),
        retry_succeeded=bool(s4.get("retry_succeeded")),
        retry_failed_file=s4.get("retry_failed_file"),
        retry_error_before=s4.get("retry_error_before"),
        repair_attempted=bool(s6.get("repair_attempted")),
        repair_succeeded=repair_succeeded,
        repair_patch=repair_regeneration.get("patch") if repair_regeneration else None,
        repair_challenger=repair_rechallenge.get("challenger") if repair_rechallenge else None,
        repair_defect_count=repair_rechallenge.get("confirmed_defect_count", 0) if repair_rechallenge else 0,
        repair_rechallenged=repair_rechallenge is not None,
        original_challenger_defect_count=original_challenger_defect_count,
        constraint_signals=constraint_signals,
        remediation_signals=remediation_signals,
        detected_language=s9.get("detected_language") or "python",
        finding_calibration=s6.get("finding_calibration"),
        grounding=grounding,
        repository_understanding=from_jsonable(RepositoryUnderstanding, s1.get("repository_understanding")),
        post_patch_observations=post_patch_observations,
        post_patch_investigated_patch=s4.get("investigated_patch"),
        post_patch_coverage=post_patch_coverage,
        # Never read by _build_report() -- see this run_fn's own docstring.
        relocation_telemetry=None,
        source_verification=None,
        existing_test_comparison=existing_test_comparison,
        edit_readiness=None,
        edit_acquisition=None,
        guided_acquisition=None,
        patch_target_conformance=None,
        post_patch_recovery=None,
        security_invariant=(strategy_result.security_invariant if strategy_result else None),
    )

    report_markdown = _build_report(result)

    artifact = {"report_markdown": report_markdown, "pipeline_result": to_jsonable(result)}
    artifact_path = output_dir / "report_generation.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    (output_dir / "report.md").write_text(report_markdown, encoding="utf-8")

    return RunFnResult(
        outcome="settled",
        artifact_path=artifact_path,
        llm_calls=[],
        extra_stage_fields={
            "canonical_contract_scope": "combined_trust_signals_and_recommendation+report_generation",
            "replay_limitations": {
                "relocation_telemetry": "not reconstructed (None) -- never persisted, never read by _build_report()",
                "source_verification": "not reconstructed (None) -- never persisted upstream; observability-only, not read by _build_recommendation_v1",
                "edit_readiness/edit_acquisition/guided_acquisition/patch_target_conformance/post_patch_recovery": "not reconstructed (None) -- never read by _build_report() (verified by exhaustive grep)",
            },
        },
        extra_consumed=extra_consumed,
    )


REPLAY_HANDLERS: "dict[str, ReplayHandler]" = {
    TEST_ANALYSIS_AND_PLAN: ReplayHandler(
        run_fn=_run_test_analysis_and_plan,
        # Narrower than the approved final {patch_repair_and_calibration,
        # impact_and_behavior_analysis} -- see module docstring.
        dependencies=(),
    ),
    # Batch B8: S1 (genesis stage -- no declared dependency; resolves its
    # own prior execution via `chain`, see run_fn docstring) and S2 (thin
    # adapter around the already-standalone generate_remediation_strategy).
    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: ReplayHandler(
        run_fn=_run_replay_repository_analysis_and_remediation_planning,
        dependencies=(),
    ),
    REMEDIATION_STRATEGY: ReplayHandler(
        run_fn=_run_replay_remediation_strategy,
        dependencies=(REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,),
    ),
    GUIDED_CONTEXT_ACQUISITION: ReplayHandler(
        run_fn=_run_replay_guided_context_acquisition,
        dependencies=(REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING, REMEDIATION_STRATEGY),
    ),
    # Batch B7: full approved dependency sets (stage_registry.
    # STAGE_DEPENDENCIES) -- all now genuinely resolvable, since S1-S3's
    # own persisted artifacts carry what these handlers need.
    PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION: ReplayHandler(
        run_fn=_run_replay_patch_generation_and_investigation,
        dependencies=(REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING, REMEDIATION_STRATEGY, GUIDED_CONTEXT_ACQUISITION),
    ),
    CHALLENGER: ReplayHandler(
        run_fn=_run_replay_challenger,
        dependencies=(PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,),
    ),
    PATCH_REPAIR_AND_CALIBRATION: ReplayHandler(
        run_fn=_run_replay_patch_repair_and_calibration,
        dependencies=(PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION, CHALLENGER),
    ),
    PATCH_REVIEW: ReplayHandler(
        run_fn=_run_replay_patch_review,
        dependencies=(PATCH_REPAIR_AND_CALIBRATION,),
    ),
    CONFIDENCE_SCORING: ReplayHandler(
        run_fn=_run_replay_confidence_scoring,
        dependencies=(PATCH_REPAIR_AND_CALIBRATION, PATCH_REVIEW),
    ),
    # Batch B8.
    IMPACT_AND_BEHAVIOR_ANALYSIS: ReplayHandler(
        run_fn=_run_replay_impact_and_behavior_analysis,
        dependencies=(PATCH_REPAIR_AND_CALIBRATION,),
    ),
    EXISTING_TEST_COMPARISON: ReplayHandler(
        run_fn=_run_replay_existing_test_comparison,
        # REMEDIATION_STRATEGY added for the Existing Test Amendment
        # feature -- see stage_registry.STAGE_DEPENDENCIES[
        # EXISTING_TEST_COMPARISON]'s own comment.
        dependencies=(PATCH_REPAIR_AND_CALIBRATION, TEST_ANALYSIS_AND_PLAN, REMEDIATION_STRATEGY),
    ),
    # Batch B8: ONE combined replay unit for the current fused
    # trust_signals_and_recommendation + report_generation terminal tail --
    # see _run_replay_report_generation's own docstring for why this is
    # registered under report_generation only.
    REPORT_GENERATION: ReplayHandler(
        run_fn=_run_replay_report_generation,
        dependencies=(
            REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
            REMEDIATION_STRATEGY,
            PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
            PATCH_REPAIR_AND_CALIBRATION,
            PATCH_REVIEW,
            CONFIDENCE_SCORING,
            IMPACT_AND_BEHAVIOR_ANALYSIS,
            # existing_test_comparison is DELIBERATELY not declared here --
            # it is a genuinely OPTIONAL upstream (compare_existing_tests
            # defaults False in production; most runs never record a real
            # execution of it at all) -- see _run_replay_report_generation's
            # own docstring for how it resolves this stage optionally, via
            # the same `chain` every other run_fn already receives, never
            # failing the whole replay when it is legitimately absent.
        ),
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
        # `chain` is the SAME lineage.build_chain(source_run) object used to
        # resolve every declared dependency above -- handed to run_fn ONLY so
        # a genesis-like stage (repository_analysis_and_remediation_planning,
        # which has NO upstream canonical dependency of its own) can look up
        # its own nearest prior execution via lineage.resolve_effective(),
        # to re-derive the run-level input (vulnerability_text) it was
        # originally seeded with. This is not a new dependency-resolution
        # mechanism -- it is the existing resolver, called on a stage's own
        # name instead of one of its declared dependencies, which is why it
        # cannot go through handler.dependencies (validated as a strict
        # subset of stage_registry.STAGE_DEPENDENCIES -- a stage is never
        # its own dependency there). Every run_fn accepts and may ignore it.
        chain=chain,
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

    # Mandatory dependencies (handler.dependencies, always resolved above --
    # fails the whole replay if any is missing) PLUS any optional, run_fn-
    # self-resolved extras (see RunFnResult.extra_consumed) -- e.g.
    # EXISTING_TEST_COMPARISON, resolved only when a downstream stage's
    # run_fn actually found and used its accepted amendment. The two never
    # overlap in practice (an optional extra is, by construction, never
    # also declared in handler.dependencies -- see stage_registry.py's own
    # comment on why EXISTING_TEST_COMPARISON stays out of PATCH_REVIEW/
    # CONFIDENCE_SCORING's canonical dependencies); mandatory entries win on
    # the rare chance of a key collision, since they are already fail-closed
    # guaranteed to exist.
    consumed = {dep: res.as_identity_dict() for dep, res in run_result.extra_consumed.items()}
    consumed.update({dep: res.as_identity_dict() for dep, res in resolved_dependencies.items()})

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
