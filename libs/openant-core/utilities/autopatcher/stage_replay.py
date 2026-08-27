"""Single-stage Auto Patcher debug replay -- Phase 1.

Lets a developer rerun exactly ONE pipeline stage's CURRENT production
implementation against the UPSTREAM STATE recorded by a prior
utilities/autopatcher/tools/run_traced.py source trace, without rerunning
any earlier or later stage, and without calling
``utilities.autopatcher.pipeline.run()`` at all.

Phase 1 supports exactly one stage: ``test_plan_discovery``
(``discover_test_plan``, see ``test_plan_discovery.py``) -- it is the only
pipeline stage whose entire input is a filesystem path plus an LLM client
(no remediation plan, candidate patch, or Challenger result needed), so it
is replayable with zero reconstruction of any other stage's state and zero
risk of re-running an earlier LLM call.

This module deliberately does NOT import ``utilities.autopatcher.pipeline``
or any other stage module (``remediation_planner``, ``patch_generator``,
``patch_challenger``, ``finding_calibration``, ``patch_reviewer``,
``confidence_scorer``) -- the import graph itself is a structural
guarantee that a single-stage replay can never trigger another stage's LLM
call, on top of the runtime call-count assertions in
tests/patch/test_stage_replay.py.

Design notes (see utilities/autopatcher/tools/TRACING_AND_DEBUGGING.md's
replay section for the full rationale):

  - CURRENT code, OLD upstream state: this module never resends a captured
    ``*.prompt.txt`` to an LLM. It reconstructs ``discover_test_plan``'s
    real inputs (a repo_root at a verified commit, plus a freshly
    constructed LLM client) and calls the real, unmodified, CURRENTLY
    imported ``discover_test_plan`` -- so a code/prompt change under
    active development is exactly what gets exercised.
  - checkpoints.jsonl is not touched or read by this module -- it remains
    exactly what the earlier investigation established it to be: a
    per-LLM-call index/history over the source trace's prompt/response
    files, not a source of reconstructable stage state.
  - No generic replay framework: one small dispatch table
    (``SUPPORTED_STAGES`` / ``run_stage.py``'s ``_STAGE_DISPATCH``), one
    registered stage, one loader. Earn a bigger abstraction later by
    adding more replayable stages, not now.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .llm_call_tracing import LLMCallCapture
from .llm_client import LLMClient, ensure_provider_configured
from .run_metadata import collect_full_commit_sha, find_openant_root, is_worktree_clean
from .test_plan_discovery import discover_test_plan

# Phase 1: exactly one registered stage. Extending this set to a second
# stage is future work (see the module docstring) -- run_stage.py checks
# membership in this set BEFORE any file I/O or LLM work, so requesting an
# unregistered stage fails immediately with a clear, actionable message.
SUPPORTED_STAGES = frozenset({"test_plan_discovery"})

# replay_manifest.json's own schema version -- independent of
# run_traced.py's run_manifest.json _REPLAY_SCHEMA_VERSION (a different
# file, a different producer). Bump only if this shape changes.
_REPLAY_MANIFEST_SCHEMA_VERSION = 1

# run_manifest.json schema_version values this module knows how to read
# via the structured path (see resolve_source_provenance). A manifest with
# no "schema_version" key at all is treated as legacy (bounded Run
# Metadata fallback, never this set).
#
# Extended to include 2, then 3, alongside the pre-existing 1 as
# utilities.autopatcher.lineage's unified full-run/replay manifest bumped
# its OWN schema_version (2 for the unified manifest, Batch A cleanup; 3
# for the execution-based "executions" list replacing "stages", Batch B1)
# -- all three versions carry target_repository/openant/llm in the
# identical structured shape this module has always read; lineage.py's
# newer schema_versions only add/change top-level keys ("kind"/"parent"/
# "executions") this module has no need to know about. The two modules
# independently interpret the SAME top-level "schema_version" field for
# two different, non-conflicting questions -- see lineage.py's module
# docstring.
_SUPPORTED_SOURCE_SCHEMA_VERSIONS = frozenset({1, 2, 3})


class StageReplayError(RuntimeError):
    """Raised whenever a single-stage replay cannot proceed -- always
    BEFORE any LLM call. The message is the actual, user-facing
    explanation (run_stage.py prints ``str(exc)`` verbatim), so every
    raise site here writes a complete, specific sentence rather than a
    generic label.
    """


# ---------------------------------------------------------------------------
# Part 3 / lifecycle steps 2-3: resolve + load the source trace
# ---------------------------------------------------------------------------


def resolve_source_trace_dir(source_trace: "Path | str") -> Path:
    """Resolve a user-supplied ``--source-trace`` path to the directory
    that actually contains ``run_manifest.json``.

    Accepts either the natural run root a developer thinks of (e.g.
    ``/tmp/minimist-trace``, ``run_traced.py``'s ``--output``) or that
    run's ``trace/`` subdirectory directly -- deterministic, exact-name
    resolution only, never a recursive or fuzzy search.
    """
    source_trace = Path(source_trace)
    direct = source_trace / "run_manifest.json"
    if direct.is_file():
        return source_trace
    nested = source_trace / "trace" / "run_manifest.json"
    if nested.is_file():
        return source_trace / "trace"
    raise StageReplayError(
        f"Cannot replay: no run_manifest.json found at {direct} or {nested}. "
        f"--source-trace must point at a run_traced.py output directory "
        f"(the run root, or its trace/ subdirectory)."
    )


def load_source_manifest(trace_dir: Path) -> dict:
    """Read and parse ``run_manifest.json`` from an already-resolved trace
    directory. Never mutates it."""
    manifest_path = trace_dir / "run_manifest.json"
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StageReplayError(
            f"Cannot replay: {manifest_path} is not valid JSON ({exc})."
        ) from exc
    except OSError as exc:
        raise StageReplayError(f"Cannot replay: could not read {manifest_path} ({exc}).") from exc


# ---------------------------------------------------------------------------
# Source provenance: structured manifest > bounded legacy fallback > fail closed
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceProvenance:
    """Normalized source-run provenance, regardless of whether it came
    from a schema_version-bearing structured manifest or the bounded
    legacy Trust Report fallback."""

    repo_root: str
    repo_commit: str
    repo_commit_is_short: bool  # True only for the legacy fallback path
    patcher_commit: "str | None"
    llm_provider: "str | None"
    llm_model: "str | None"
    input_type: "str | None"
    input_id: "str | None"
    source: str  # "structured_manifest" | "legacy_trust_report_fallback"


def resolve_source_provenance(trace_dir: Path, manifest: dict) -> SourceProvenance:
    """Priority, per the architectural clarification: structured
    run_manifest.json fields > bounded legacy Run Metadata fallback > fail
    closed. Never falls back silently -- a legacy trace that also can't
    produce a usable fallback fails with a specific reason.
    """
    schema_version = manifest.get("schema_version")

    if schema_version is None:
        return _legacy_provenance_from_trust_report(manifest)

    if schema_version not in _SUPPORTED_SOURCE_SCHEMA_VERSIONS:
        raise StageReplayError(
            f"Cannot replay: source trace's run_manifest.json declares "
            f"schema_version={schema_version!r}, which this version of "
            f"run_stage.py does not support (supported: "
            f"{sorted(_SUPPORTED_SOURCE_SCHEMA_VERSIONS)}). Regenerate the "
            f"trace with a compatible run_traced.py, or use a newer "
            f"run_stage.py."
        )

    target_repository = manifest.get("target_repository") or {}
    repo_root = target_repository.get("repo_root") or manifest.get("repo_root")
    if not repo_root:
        raise StageReplayError(
            "Cannot replay: source trace's run_manifest.json has no "
            "target_repository.repo_root recorded."
        )

    repo_commit = target_repository.get("repo_commit")
    if not repo_commit:
        raise StageReplayError(
            "Cannot replay: source trace's run_manifest.json has "
            "target_repository.repo_commit=null -- the target repository's "
            "commit was never recorded for this run (e.g. its repo_root "
            "was not a valid git repository at trace time), so no repo "
            "identity check can be performed."
        )

    openant = manifest.get("openant") or {}
    llm = manifest.get("llm") or {}
    return SourceProvenance(
        repo_root=repo_root,
        repo_commit=repo_commit,
        repo_commit_is_short=False,
        patcher_commit=openant.get("patcher_commit"),
        llm_provider=llm.get("provider"),
        llm_model=llm.get("model"),
        input_type=manifest.get("input_type"),
        input_id=manifest.get("input_id"),
        source="structured_manifest",
    )


# Bounded: only ever searched within the "## Run Metadata" section of a
# Trust Report, using this fixed set of known row labels -- never general
# Markdown/prose parsing. See run_metadata.render_metadata_section for the
# exact table this is reading back.
_RUN_METADATA_HEADING_RE = re.compile(r"^## Run Metadata\s*$", re.MULTILINE)
_NEXT_HEADING_RE = re.compile(r"^##\s", re.MULTILINE)
_LEGACY_FIELD_PATTERNS = {
    "repo_commit": re.compile(r"^\|\s*Repo commit\s*\|\s*(.+?)\s*\|\s*$", re.MULTILINE),
    "patcher_commit": re.compile(r"^\|\s*Auto-patcher\s*\|\s*(.+?)\s*\|\s*$", re.MULTILINE),
    "llm_provider": re.compile(r"^\|\s*LLM provider\s*\|\s*(.+?)\s*\|\s*$", re.MULTILINE),
    "llm_model": re.compile(r"^\|\s*LLM model\s*\|\s*(.+?)\s*\|\s*$", re.MULTILINE),
}


def _legacy_provenance_from_trust_report(manifest: dict) -> SourceProvenance:
    """Bounded compatibility fallback for a trace produced before this
    feature existed (no "schema_version" key at all). Reads ONLY the
    fixed-shape "## Run Metadata" table inside the Trust Report this run
    already wrote -- never any other part of the report, and never a
    general prose scan. Fails closed on anything missing or ambiguous.
    """
    repo_root = manifest.get("repo_root")
    if not repo_root:
        raise StageReplayError(
            "Cannot replay: legacy source trace's run_manifest.json (no "
            "schema_version) has no repo_root recorded either -- there is "
            "no structured target_repository field, and no repo_root to "
            "even locate the target repository."
        )

    trust_report_path = manifest.get("trust_report_path")
    if not trust_report_path or not Path(trust_report_path).is_file():
        raise StageReplayError(
            "Cannot replay: legacy source trace (no schema_version) has no "
            "trust_report_path pointing at an existing Trust Report to use "
            "as the bounded compatibility fallback. This trace cannot be "
            "used for replay."
        )

    text = Path(trust_report_path).read_text(encoding="utf-8")
    heading_match = _RUN_METADATA_HEADING_RE.search(text)
    if not heading_match:
        raise StageReplayError(
            f"Cannot replay: {trust_report_path} has no '## Run Metadata' "
            f"section to use as the bounded legacy compatibility fallback."
        )
    section_start = heading_match.end()
    next_heading = _NEXT_HEADING_RE.search(text, section_start)
    section = text[section_start : next_heading.start() if next_heading else len(text)]

    def _extract(field: str) -> "str | None":
        matches = _LEGACY_FIELD_PATTERNS[field].findall(section)
        if len(matches) != 1:
            return None  # absent or ambiguous -- caller decides what's required
        return matches[0].strip()

    repo_commit = _extract("repo_commit")
    if not repo_commit or repo_commit.lower() == "unknown":
        raise StageReplayError(
            "Cannot replay: legacy source trace's Run Metadata section has "
            "no usable 'Repo commit' value (missing, ambiguous, or "
            "'unknown') -- the target repository's commit was never "
            "recorded, so no repo identity check can be performed."
        )

    return SourceProvenance(
        repo_root=repo_root,
        repo_commit=repo_commit,
        repo_commit_is_short=True,
        patcher_commit=_extract("patcher_commit"),
        llm_provider=_extract("llm_provider"),
        llm_model=_extract("llm_model"),
        input_type=manifest.get("input_type"),
        input_id=manifest.get("input_id"),
        source="legacy_trust_report_fallback",
    )


# ---------------------------------------------------------------------------
# Part 4: target-repository identity + clean-state safety gate
# ---------------------------------------------------------------------------


def validate_target_repository(
    repo_root_override: "str | None", provenance: SourceProvenance, *, stage: str
) -> Path:
    """The most important deterministic safety boundary. Purely
    observational -- never runs `git checkout`/`reset`/`clean`, never
    mutates the target repository in any way. Raises StageReplayError,
    BEFORE any LLM call, on any failure.
    """
    repo_root = Path(repo_root_override) if repo_root_override else Path(provenance.repo_root)

    if not repo_root.exists():
        raise StageReplayError(f"Cannot replay {stage}: target repository does not exist: {repo_root}")
    if not repo_root.is_dir():
        raise StageReplayError(f"Cannot replay {stage}: target repository path is not a directory: {repo_root}")
    if not (repo_root / ".git").exists():
        raise StageReplayError(f"Cannot replay {stage}: target repository is not a git repository: {repo_root}")

    actual_sha = collect_full_commit_sha(repo_root)
    if actual_sha is None:
        raise StageReplayError(
            f"Cannot replay {stage}: could not read current HEAD of target repository: {repo_root}"
        )

    expected = provenance.repo_commit
    matches = actual_sha.startswith(expected) if provenance.repo_commit_is_short else actual_sha == expected
    if not matches:
        raise StageReplayError(
            f"Cannot replay {stage}: target repository HEAD does not match source trace.\n"
            f"Expected: {expected}\n"
            f"Actual:   {actual_sha}"
        )

    clean = is_worktree_clean(repo_root)
    if clean is None:
        raise StageReplayError(
            f"Cannot replay {stage}: could not determine working-tree state of target repository: {repo_root}"
        )
    if not clean:
        raise StageReplayError(
            f"Cannot replay {stage}: target repository contains uncommitted changes. "
            f"Replay requires a clean checkout at the recorded commit."
        )

    return repo_root


# ---------------------------------------------------------------------------
# Part 9: output-directory safety (never overlaps the source trace)
# ---------------------------------------------------------------------------


def _validate_output_dir_is_safe(source_trace: Path, output_dir: Path) -> None:
    src = source_trace.resolve()
    out = output_dir.resolve()

    if out == src:
        raise StageReplayError(
            f"Cannot replay: --output must not be the same path as --source-trace ({src})."
        )
    if out in src.parents or out == src:
        raise StageReplayError(
            f"Cannot replay: --output ({out}) contains --source-trace ({src}); "
            f"this could contaminate or overwrite the source trace. Choose a separate directory."
        )
    if src in out.parents or src == out:
        raise StageReplayError(
            f"Cannot replay: --output ({out}) is nested inside --source-trace ({src}); "
            f"this could contaminate or overwrite the source trace. Choose a separate directory."
        )


# ---------------------------------------------------------------------------
# Part 7 / 8 / 11-14: the replay lifecycle for test_plan_discovery
#
# LLM call capture during the replayed stage itself uses the shared
# LLMCallCapture (llm_call_tracing.py) with no on_call callback -- at most
# one call ever happens here (discover_test_plan makes zero or one), and
# this module writes prompt/response files only after that call completes,
# so there's nothing to protect against a partial run the way
# tools/run_traced.py's per-call incremental writes do.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StageReplayResult:
    outcome: str  # "accepted" | "rejected"
    manifest: dict
    output_dir: Path


def replay_test_plan_discovery(
    *,
    source_trace: "Path | str",
    output_dir: "Path | str",
    repo_root_override: "str | None" = None,
) -> StageReplayResult:
    """Rerun exactly the current ``discover_test_plan(repo_root, llm)`` --
    the real, unmodified production function -- using the target
    repository recorded (and identity-verified) from ``source_trace``.

    Never calls ``utilities.autopatcher.pipeline.run()`` or any other
    stage. Makes at most ONE LLM call (``discover_test_plan`` itself makes
    zero calls when there is no repository evidence to reason from --
    that is a legitimate, current-implementation "rejected" outcome, not
    an error). Raises StageReplayError, before any LLM call, for every
    infrastructure/provenance/identity failure.
    """
    stage = "test_plan_discovery"
    source_trace = Path(source_trace)
    output_dir = Path(output_dir)
    started_at = datetime.now(timezone.utc)

    # Part 9 -- output-directory safety, checked before any other I/O.
    _validate_output_dir_is_safe(source_trace, output_dir)

    # Lifecycle steps 2-5: resolve + load source trace, structured-first
    # with bounded legacy fallback, schema validated.
    trace_dir = resolve_source_trace_dir(source_trace)
    manifest = load_source_manifest(trace_dir)
    provenance = resolve_source_provenance(trace_dir, manifest)

    # Part 4: target-repository identity + clean-state safety gate.
    repo_root = validate_target_repository(repo_root_override, provenance, stage=stage)

    # Part 5: OpenAnt provenance -- recorded on both sides, source vs.
    # replay never required to match. Dirty-tree check reused from the
    # same is_worktree_clean helper Part 4 uses for the TARGET repo, but
    # here it is purely informational and never blocks replay.
    openant_root = find_openant_root()
    replay_patcher_commit = collect_full_commit_sha(openant_root) if openant_root else None
    replay_openant_dirty = None if openant_root is None else (is_worktree_clean(openant_root) is False)

    # Part 6: LLM configuration -- through the SAME canonical resolution
    # path core.patch.py uses, never hand-rolled here. Fails closed,
    # before ANY stage execution, if unresolvable.
    ensure_provider_configured()
    api_key = os.environ.get("OPENAI_API_KEY", "")
    llm = LLMClient(api_key=api_key)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Lifecycle steps 8-11: install tracing around CURRENT LLM call,
    # invoke the CURRENT production discover_test_plan, capture
    # prompt+response, persist the parsed plan or rejection reason.
    rejection_reason: "list[str]" = []
    with LLMCallCapture() as capture:
        plan = discover_test_plan(repo_root, llm, rejection_reason=rejection_reason)
    finished_at = datetime.now(timezone.utc)

    import utilities.autopatcher.llm_client as _llm_module

    # Same "mock never populates _cached_model" special case as
    # run_traced.py's _replay_provenance (see its comment) and
    # core/patch.py's own post-hoc provider/model lookup.
    replay_provider = _llm_module._cached_provider
    if replay_provider == "mock":
        replay_model = "mock"
    else:
        replay_model = _llm_module._cached_model.get(replay_provider) if replay_provider else None

    for call in capture.calls:
        seq = call["seq"]
        (output_dir / f"{seq:03d}_{stage}.prompt.txt").write_text(call["prompt"], encoding="utf-8")
        (output_dir / f"{seq:03d}_{stage}.response.txt").write_text(call["response"] or "", encoding="utf-8")

    if plan is not None:
        outcome = "accepted"
        (output_dir / "parsed_result.json").write_text(
            json.dumps(dataclasses.asdict(plan), indent=2), encoding="utf-8"
        )
    else:
        outcome = "rejected"
        reason = rejection_reason[0] if rejection_reason else "unknown (no rejection reason captured)"
        (output_dir / "rejection_reason.json").write_text(
            json.dumps({"reason": reason}, indent=2), encoding="utf-8"
        )

    replay_manifest = {
        "schema_version": _REPLAY_MANIFEST_SCHEMA_VERSION,
        "stage": stage,
        "outcome": outcome,
        "source_trace": str(trace_dir),
        "source_provenance_origin": provenance.source,
        "source_run": {"input_type": provenance.input_type, "input_id": provenance.input_id},
        "target_repository": {"repo_root": str(repo_root), "repo_commit": provenance.repo_commit},
        "openant": {
            "source_patcher_commit": provenance.patcher_commit,
            "replay_patcher_commit": replay_patcher_commit,
            "replay_openant_dirty": replay_openant_dirty,
        },
        "llm": {
            "source_provider": provenance.llm_provider,
            "source_model": provenance.llm_model,
            "replay_provider": replay_provider,
            "replay_model": replay_model,
        },
        "llm_call_count": len(capture.calls),
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": (finished_at - started_at).total_seconds(),
    }
    (output_dir / "replay_manifest.json").write_text(
        json.dumps(replay_manifest, indent=2), encoding="utf-8"
    )

    return StageReplayResult(outcome=outcome, manifest=replay_manifest, output_dir=output_dir)
