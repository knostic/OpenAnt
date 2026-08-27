"""Unified full-run/replay manifest model + dependency-aware lineage
resolution -- Auto Patcher stage-replay foundation.

This module is deliberately small: a manifest is a plain JSON dict on disk
(``run_manifest.json``), a "lineage" is nothing more than a chain of such
manifests linked by a ``parent`` pointer, and "resolving" a stage's
effective artifact in that lineage is a closest-ancestor walk with a
freshness check at each candidate -- no database, no branch-management
object, no generic cache-invalidation framework. See the architecture
report (Batch A / Foundation) for the full design rationale.

Manifest shape (additive across ``kind``):

    {
      "schema_version": 2,
      "kind": "full_run" | "replay",
      "parent": "<path to source run/replay>" | null,
      "replaces_stage": "<canonical stage name>" | null,   # only for replays
      "target_repository": {"repo_root": ..., "repo_commit": ...},
      "openant": {...},
      "llm": {...},
      "stages": {
        "<canonical stage name>": {
          "status": "produced" | "not_persisted" | "legacy",
          "artifact_path": "<absolute path>" | null,
          "dependencies_checked": ["<dep stage name>", ...],
          "consumed_dependencies": {"<dep>": {"run": "<dir>", "stage": "<dep>"}},
          "llm_calls": [...],
          "outcome": "..." | null,
          "timing": {...} | null
        }
      }
    }

SCHEMA VERSIONING (bumped 1 -> 2 for this unified manifest; see the
architecture report's cleanup batch for why): this module's own
``schema_version`` interpretation is DELIBERATELY three-tiered, and is
independent of -- but reads the SAME top-level field as --
stage_replay.resolve_source_provenance's older, narrower check (whether
target_repository/openant/llm are present in structured form at all,
which has been true since v1 and is unchanged by v2; see
stage_replay._SUPPORTED_SOURCE_SCHEMA_VERSIONS, extended to {1, 2}):

  - schema_version == 2 (_CANONICAL_SCHEMA_VERSIONS): the current unified
    shape. "kind"/"parent"/"replaces_stage"/"stages" are trusted AS
    WRITTEN -- never synthesized or overridden.
  - schema_version == 1 (_LEGACY_SCHEMA_VERSIONS), or no "schema_version"
    key at all: bounded legacy compatibility. Neither era of manifest
    ever had a trustworthy "kind"/"parent"/"stages" -- this module
    synthesizes kind="full_run", parent=None, and EVERY canonical stage
    marked status="legacy" (see legacy_stage_entries()). "legacy" is
    RESERVED for exactly this case: a run/trace that predates structured
    per-stage artifacts entirely. It is a different, OLDER concept than
    "not_persisted" (see below).
  - any other schema_version: fails closed immediately with LineageError,
    before any LLM/external work -- see load_manifest().

STATUS VALUES -- "legacy" vs. "not_persisted" vs. "produced": all three
mean "no artifact_path to actually read here" EXCEPT "produced", but they
are not interchangeable and must never be confused:

  - "legacy": this ENTIRE MANIFEST predates the unified schema (v1 or
    older) -- applied uniformly to all 13 canonical stages by
    load_manifest()'s bounded compatibility path, never written by a v2
    writer.
  - "not_persisted": a NEW (v2) full run's HONEST acknowledgment that this
    canonical stage exists in the registry but its production code has
    not yet been migrated to persist a structured artifact for it (see
    not_persisted_stage_entries(), written by run_traced.py today for
    every one of the 13 stages, since NONE of pipeline.run() is refactored
    onto the stage registry yet). This status will start disappearing,
    stage by stage, as Batch B/C migrate each stage's production code to
    persist a real artifact -- at which point that stage's entry becomes
    "produced" instead, in newly-written full runs, without any change to
    this module.
  - "produced": a real, resolvable structured artifact exists at
    artifact_path.

PERSISTED != REPLAYABLE -- an explicit architectural requirement for
Batch B, tested here even though not yet implemented: resolve_effective()
below only ever inspects a stage entry's status ("produced" or not) --
it has NO knowledge of, and no dependency on, which stages currently have
a replay_engine.REPLAY_HANDLERS entry. This means a future full run can
mark e.g. "patch_repair_and_calibration" status="produced" (once its
production code persists a real structured artifact) LONG BEFORE that
stage itself gains a replay handler -- which is exactly what
test_analysis_and_plan's FINAL contract needs: it depends on
patch_repair_and_calibration and impact_and_behavior_analysis, so a full
run must persist THEIR artifacts before test_analysis_and_plan's full
contract can resolve them, independent of whether patch_repair_and_
calibration itself is ever replayed. See
tests/patch/test_lineage.py::test_produced_artifact_resolves_even_when_stage_has_no_replay_handler
for the proof, and replay_engine.py's module docstring for the full
Batch B requirement this sets up.

"dependencies_checked" is deliberately part of each STAGE ENTRY, not read
from the live stage_registry.STAGE_DEPENDENCIES constant, so that
resolution judges a historical artifact by what it ACTUALLY validated at
production time -- this is what makes the closest-ancestor-wins resolver
correct even for a stage whose CURRENTLY REGISTERED replay handler
requires fewer dependencies than its final approved contract (a
transitional migration state; see replay_engine.ReplayHandler.dependencies
and its test_analysis_and_plan entry). Once every stage's handler
implements its full final contract, its manifest entries'
"dependencies_checked" will always equal the registry's declared
dependencies for that stage -- but the resolver itself never needs to
change for that to become true.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .stage_registry import CANONICAL_STAGE_ORDER

# The version THIS module writes for new manifests (new_full_run_manifest /
# new_replay_manifest). Bump only when the shape of "kind"/"parent"/
# "replaces_stage"/"stages" itself changes in a way an existing consumer
# would need to know about -- purely additive new keys elsewhere never
# require a bump.
SCHEMA_VERSION = 2

# Versions readable via the bounded legacy path (see module docstring).
_LEGACY_SCHEMA_VERSIONS = frozenset({1})

# Versions readable as the canonical unified shape, trusted as written.
_CANONICAL_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION})

RESOLVED = "RESOLVED"
STALE = "STALE"
UNRESOLVED = "UNRESOLVED"

STATUS_PRODUCED = "produced"
STATUS_NOT_PERSISTED = "not_persisted"
STATUS_LEGACY = "legacy"


class LineageError(RuntimeError):
    """Raised for any lineage/manifest-loading failure -- always before any
    LLM/external work, mirroring stage_replay.StageReplayError's contract."""


# ---------------------------------------------------------------------------
# Manifest loading -- one canonical resolution rule shared by every caller.
# ---------------------------------------------------------------------------


def resolve_manifest_path(run_dir: "Path | str") -> Path:
    """Resolve a run/replay directory to its actual run_manifest.json path.

    Mirrors stage_replay.resolve_source_trace_dir's dual-shape lookup
    (direct, or nested under trace/) so a full run written by run_traced.py
    (manifest under <root>/trace/) and a replay written by replay_engine.py
    (manifest directly under <root>/) are both addressable the same way,
    including as a later replay's --source-run.
    """
    run_dir = Path(run_dir)
    direct = run_dir / "run_manifest.json"
    if direct.is_file():
        return direct
    nested = run_dir / "trace" / "run_manifest.json"
    if nested.is_file():
        return nested
    raise LineageError(
        f"No run_manifest.json found at {direct} or {nested}. "
        f"--source-run must point at a run_traced.py output directory or a "
        f"prior replay's --output directory."
    )


def load_manifest(run_dir: "Path | str") -> dict:
    """Load and parse a run_manifest.json. Never mutates the file on disk.

    Three-tiered schema_version handling -- see module docstring:
      - missing, or in _LEGACY_SCHEMA_VERSIONS (today: {1}): bounded
        legacy compatibility. "kind"/"parent"/"replaces_stage" default to
        a root full run, and "stages" is SYNTHESIZED (never read from the
        file, which never had it) as every canonical stage marked
        status="legacy".
      - in _CANONICAL_SCHEMA_VERSIONS (today: {2}): the current unified
        shape -- "kind"/"parent"/"replaces_stage"/"stages" are trusted AS
        WRITTEN.
      - anything else: LineageError, immediately, before any LLM/external
        work -- this is a hard failure, not a silent best-effort read.
    """
    manifest_path = resolve_manifest_path(run_dir)
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise LineageError(f"{manifest_path} is not valid JSON ({exc}).") from exc
    except OSError as exc:
        raise LineageError(f"Could not read {manifest_path} ({exc}).") from exc

    schema_version = data.get("schema_version")

    if schema_version is None or schema_version in _LEGACY_SCHEMA_VERSIONS:
        data["kind"] = "full_run"
        data["parent"] = None
        data["replaces_stage"] = None
        data["stages"] = legacy_stage_entries(CANONICAL_STAGE_ORDER)
        return data

    if schema_version not in _CANONICAL_SCHEMA_VERSIONS:
        raise LineageError(
            f"{manifest_path} declares schema_version={schema_version!r}, "
            f"which this version of the lineage resolver does not support "
            f"(supported: legacy {sorted(_LEGACY_SCHEMA_VERSIONS)}, "
            f"canonical {sorted(_CANONICAL_SCHEMA_VERSIONS)}). Regenerate "
            f"the run with a compatible run_traced.py, or use a newer "
            f"lineage.py."
        )

    # Canonical (v2): trust the file's own kind/parent/replaces_stage/
    # stages -- defensive setdefault only, never overriding real content.
    data.setdefault("kind", "full_run")
    data.setdefault("parent", None)
    data.setdefault("replaces_stage", None)
    data.setdefault("stages", {})
    return data


# ---------------------------------------------------------------------------
# Manifest construction helpers
# ---------------------------------------------------------------------------


def _no_artifact_stage_entries(stage_names: "tuple[str, ...]", *, status: str) -> dict:
    return {
        name: {
            "status": status,
            "artifact_path": None,
            "dependencies_checked": [],
            "consumed_dependencies": {},
            "llm_calls": [],
            "outcome": None,
            "timing": None,
        }
        for name in stage_names
    }


def legacy_stage_entries(stage_names: "tuple[str, ...]") -> dict:
    """Stage-entry map for a manifest that predates the unified schema
    entirely (v1 or older) -- used ONLY by load_manifest()'s bounded
    legacy-compatibility path, never written by a v2 writer. Every
    canonical stage is present (so the manifest is honest about which
    stages the registry knows about) but marked status="legacy" with no
    artifact_path. See the module docstring for exactly how this differs
    from not_persisted_stage_entries() below -- NEVER fabricating a
    structured artifact that production did not actually persist, either
    way."""
    return _no_artifact_stage_entries(stage_names, status=STATUS_LEGACY)


def not_persisted_stage_entries(stage_names: "tuple[str, ...]") -> dict:
    """Stage-entry map for a NEW (v2) full run whose production code has
    not been migrated to persist a structured artifact for these stages
    yet -- used by run_traced.py today for all 13 canonical stages (see
    the module docstring's PERSISTED != REPLAYABLE section). As Batch B/C
    migrate a stage's production code to persist a real artifact, that
    stage's entry becomes produced_stage_entry(...) instead in newly
    written full runs -- this helper is for the ones that still aren't."""
    return _no_artifact_stage_entries(stage_names, status=STATUS_NOT_PERSISTED)


def produced_stage_entry(
    *,
    artifact_path: "Path | str | None",
    dependencies_checked: "tuple[str, ...]" = (),
    consumed_dependencies: "Optional[dict]" = None,
    llm_calls: "Optional[list]" = None,
    outcome: "Optional[str]" = None,
    timing: "Optional[dict]" = None,
    extra: "Optional[dict]" = None,
) -> dict:
    """Build a status="produced" stage entry. `consumed_dependencies` must
    have exactly one key per name in `dependencies_checked`, each a
    {"run": <dir>, "stage": <name>} identity dict -- see
    Resolution.as_identity_dict()."""
    entry = {
        "status": STATUS_PRODUCED,
        "artifact_path": str(artifact_path) if artifact_path else None,
        "dependencies_checked": list(dependencies_checked),
        "consumed_dependencies": consumed_dependencies or {},
        "llm_calls": llm_calls or [],
        "outcome": outcome,
        "timing": timing,
    }
    if extra:
        entry.update(extra)
    return entry


def new_full_run_manifest(
    *,
    target_repository: dict,
    openant: dict,
    llm: dict,
    stages: dict,
    extra: "Optional[dict]" = None,
) -> dict:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "full_run",
        "parent": None,
        "replaces_stage": None,
        "target_repository": target_repository,
        "openant": openant,
        "llm": llm,
        "stages": stages,
    }
    if extra:
        manifest.update(extra)
    return manifest


def new_replay_manifest(
    *,
    parent: "Path | str",
    replaces_stage: str,
    target_repository: dict,
    openant: dict,
    llm: dict,
    stages: dict,
    extra: "Optional[dict]" = None,
) -> dict:
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "replay",
        "parent": str(parent),
        "replaces_stage": replaces_stage,
        "target_repository": target_repository,
        "openant": openant,
        "llm": llm,
        "stages": stages,
    }
    if extra:
        manifest.update(extra)
    return manifest


# ---------------------------------------------------------------------------
# Lineage chain -- a flat list of run/replay directories, tip first, walking
# `parent` pointers up to the root full run (parent=None).
# ---------------------------------------------------------------------------


def build_chain(tip_dir: "Path | str") -> "list[Path]":
    """Walk `parent` pointers from `tip_dir` up to the root full run.
    Raises LineageError on a cycle (defensive -- a well-formed lineage
    can never actually contain one, since every replay's parent must
    already exist on disk before the replay is written)."""
    chain: "list[Path]" = []
    seen: "set[str]" = set()
    current: "Path | None" = Path(tip_dir)
    while current is not None:
        key = str(resolve_manifest_path(current))
        if key in seen:
            raise LineageError(f"Cycle detected in replay lineage at {current}.")
        seen.add(key)
        chain.append(current)
        manifest = load_manifest(current)
        parent = manifest.get("parent")
        current = Path(parent) if parent else None
    return chain


# ---------------------------------------------------------------------------
# Artifact identity + resolution states
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArtifactIdentity:
    """The smallest stable identity for a stage artifact: which run/replay
    directory produced it, plus the canonical stage name. No content hash
    -- sufficient for dependency freshness checks because every replay
    directory is itself immutable once written (see replay_engine.py)."""

    run_dir: str
    stage: str


@dataclass(frozen=True)
class Resolution:
    """The result of resolving one canonical stage's effective artifact in
    a lineage. `state` is one of RESOLVED / STALE / UNRESOLVED -- exactly
    the three outcomes the architecture calls for, nothing fancier."""

    state: str
    identity: "Optional[ArtifactIdentity]" = None
    artifact_path: "Optional[str]" = None
    run_dir: "Optional[str]" = None
    reason: "Optional[str]" = None

    @property
    def is_resolved(self) -> bool:
        return self.state == RESOLVED

    def as_identity_dict(self) -> dict:
        """{"run": ..., "stage": ...} -- the exact shape stored in a
        producing stage's own "consumed_dependencies" entry, and compared
        against on a later resolution. Only valid when state == RESOLVED."""
        if not self.is_resolved or self.identity is None:
            raise LineageError(
                f"Cannot build an identity dict for a non-RESOLVED resolution (state={self.state!r})."
            )
        return {"run": self.identity.run_dir, "stage": self.identity.stage}


def resolve_effective(
    chain: "list[Path]",
    stage_name: str,
    cache: "Optional[dict]" = None,
) -> Resolution:
    """Resolve `stage_name`'s effective artifact within `chain` (tip-first,
    as returned by build_chain).

    Closest-ancestor-wins, but ONLY if that closest producer's own
    recorded dependencies ("dependencies_checked" / "consumed_dependencies"
    in its manifest entry) still match what CURRENTLY resolves for each of
    those dependencies in this same lineage -- staleness propagates
    transitively for free because that recursive check is exactly what
    this function does for each dependency too (memoized via `cache`, one
    entry per stage name, shared across the whole resolution of a lineage).

    A stage with NO recorded dependencies (either because its final
    contract has none, e.g. repository_analysis_and_remediation_planning,
    or because the artifact was produced by a transitional implementation
    that has not started checking its full final contract's dependencies
    yet) is valid wherever it is found, with no freshness check to perform.
    """
    if cache is None:
        cache = {}
    if stage_name in cache:
        return cache[stage_name]

    # Cycle guard: a stage that (incorrectly) lists itself, directly or
    # transitively, as its own dependency would otherwise recurse forever.
    # Never true for the approved STAGE_DEPENDENCIES graph (which is
    # acyclic by construction and covered by a dedicated test), but a
    # hand-built manifest fixture could still construct one -- fail
    # closed rather than hang.
    cache[stage_name] = Resolution(
        state=UNRESOLVED, reason=f"cycle detected while resolving {stage_name!r}"
    )

    for run_dir in chain:
        manifest = load_manifest(run_dir)
        entry = manifest.get("stages", {}).get(stage_name)
        if not entry or entry.get("status") != STATUS_PRODUCED:
            continue

        valid = True
        reason = None
        consumed = entry.get("consumed_dependencies", {}) or {}
        for dep in entry.get("dependencies_checked", []) or []:
            dep_resolution = resolve_effective(chain, dep, cache)
            if not dep_resolution.is_resolved:
                valid = False
                reason = (
                    f"dependency {dep!r} is {dep_resolution.state} in this "
                    f"lineage ({dep_resolution.reason})"
                )
                break
            recorded = consumed.get(dep)
            current_identity = dep_resolution.as_identity_dict()
            if recorded != current_identity:
                valid = False
                reason = (
                    f"dependency {dep!r} was produced from {recorded!r} but "
                    f"the current resolved lineage has {current_identity!r} "
                    f"-- {dep!r} was replayed after {stage_name!r} last ran"
                )
                break

        if valid:
            result = Resolution(
                state=RESOLVED,
                identity=ArtifactIdentity(run_dir=str(run_dir), stage=stage_name),
                artifact_path=entry.get("artifact_path"),
                run_dir=str(run_dir),
            )
        else:
            result = Resolution(state=STALE, run_dir=str(run_dir), reason=reason)
        cache[stage_name] = result
        return result

    result = Resolution(
        state=UNRESOLVED,
        reason=f"stage {stage_name!r} was never produced anywhere in this lineage",
    )
    cache[stage_name] = result
    return result


def resolve_lineage(tip_dir: "Path | str", stage_names: "tuple[str, ...]") -> "dict[str, Resolution]":
    """Convenience wrapper: build the chain once, resolve every name in
    `stage_names` against it, sharing one memoization cache."""
    chain = build_chain(tip_dir)
    cache: dict = {}
    return {name: resolve_effective(chain, name, cache) for name in stage_names}
