"""Unified full-run/replay manifest model + dependency-aware lineage
resolution -- Auto Patcher stage-replay foundation.

This module is deliberately small: a manifest is a plain JSON dict on disk
(``run_manifest.json``), a "lineage" is nothing more than a chain of such
manifests linked by a ``parent`` pointer, and "resolving" a canonical
stage's effective execution in that lineage is a closest-ancestor walk
with a freshness check at each candidate -- no database, no branch-
management object, no generic cache-invalidation framework.

STAGE CATALOG vs. STAGE EXECUTION (Batch B1): a canonical stage
(stage_registry.py) is an operation TYPE. A ``StageExecution`` is one
concrete, logical invocation of that type -- a canonical stage may execute
zero, one, or (in a future batch, once production is instrumented) more
than once within a single run/replay lineage (a bounded workflow retry,
e.g. Stage 6 deciding to regenerate the patch, creates a NEW execution of
``patch_generation_and_post_patch_investigation`` -- it does not mutate or
replace the first one). Manifest v2 (Batch A) modeled "one artifact per
canonical stage per manifest," which cannot represent this. v3 replaces it
with an ``executions`` LIST, each entry independently addressable by its
own ``execution_id`` -- see the architecture report for the full design
rationale (the "Final Decision" turn that authorized this rewrite).

Manifest shape (v3, canonical):

    {
      "schema_version": 3,
      "kind": "full_run" | "replay",
      "parent": "<path to source run/replay>" | null,
      "target_repository": {"repo_root": ..., "repo_commit": ...},
      "openant": {...},
      "llm": {...},
      "executions": [
        {
          "execution_id": "<NNN>_<canonical_stage>",
          "canonical_stage": "<canonical stage name>",
          "sequence": <int, monotonic WITHIN this run/replay directory only>,
          "invocation_kind": "initial" | "retry" | "replay",
          "consumed": {"<dep canonical_stage>": {"run": "<dir>", "execution_id": "<id>"}},
          "outcome": "..." | null,
          "replay_of": {"run": "<dir>", "execution_id": "<id>"} | null,
          "invoked_by": {"run": "<dir>", "execution_id": "<id>"} | null,
          "artifact_path": "<path>" | null,
          "llm_calls": [{"seq": ..., "stage": ..., "prompt_file": ..., "response_file": ..., "purpose": "..."?}],
          "external_calls": [...],
          "timing": {...} | null
        }
      ]
    }

There is no ``replaces_stage`` and no ``stages: {name: entry}`` singleton
map in v3 -- both are superseded: "which canonical stage" is per-execution
metadata (``canonical_stage``), and "why does this execution exist" is
``invocation_kind`` + ``replay_of``, which correctly generalizes to a
directory that could (in a future batch) hold more than one new execution.

WHAT "invocation_kind" IS, AND IS NOT: it answers "why does this execution
exist" (initial | retry | replay) -- a universal, provenance-only field on
every execution of every canonical stage. It is deliberately NOT the same
concept as a stage's own WORKFLOW DECISION about what should happen next
(e.g. Stage 6 deciding CONTINUE vs. RETRY_PATCH) -- that decision, when it
exists, belongs inside the deciding stage's OWN structured artifact
(``outcome`` and/or stage-specific fields in ``extra``), not as a second
universal StageExecution field. Only one canonical stage makes such a
decision today (patch_repair_and_calibration, not yet implemented in this
batch) -- inventing a cross-cutting field for it now would be premature;
see the architecture report's "Final Decision 2" for the full reasoning.

SCHEMA VERSIONING -- three readable tiers, one canonical writer:

  - schema_version == 3 (_CANONICAL_SCHEMA_VERSIONS): the current
    execution-based shape above. "kind"/"parent"/"executions" are trusted
    AS WRITTEN -- never synthesized or overridden. Duplicate
    ``execution_id`` values within one manifest are rejected.
  - schema_version == 2 (_V2_SCHEMA_VERSIONS, the Batch-A shape --
    "stages": {name: entry}): bounded compatibility. Only entries with
    status=="produced" become ONE synthetic compatibility execution each
    (invocation_kind="initial", since v2 never recorded retries or
    multiple attempts for a stage -- synthesizing more would fabricate
    history v2 never observed). "not_persisted"/"legacy" v2 entries never
    produce an execution record -- there is nothing to adapt.
  - schema_version == 1, or no "schema_version" key at all: bounded legacy
    compatibility. Neither era of manifest ever recorded ANY structured
    per-stage state -- this module does NOT fabricate placeholder
    execution records for the 13 canonical stages (Batch A did this for
    v1 via ``legacy_stage_entries()``; Batch B1 removes that in favor of
    an honestly empty ``executions: []`` -- resolve_effective() already
    treats "no matching execution in this directory" as UNRESOLVED
    identically whether the list is empty or merely lacks the requested
    stage, so nothing about correctness depended on the placeholder rows).
  - any other schema_version: fails closed immediately with LineageError,
    before any LLM/external work -- see load_manifest().

This module's own ``schema_version`` interpretation is independent of --
but reads the SAME top-level field as -- stage_replay.
resolve_source_provenance's older, narrower check (whether
target_repository/openant/llm are present in structured form at all,
unchanged across v1/v2/v3; see stage_replay._SUPPORTED_SOURCE_SCHEMA_VERSIONS).

HONESTY -- the single non-negotiable rule this module enforces: an
``executions`` list must contain ONLY execution records that were actually
produced/observed through the execution-recording contract (today: only
replay_engine.replay_stage()). It is correct, and expected, for a full
run's v3 manifest to have ``executions: []`` in this batch -- production
pipeline.run() is not yet instrumented to record real StageExecution
instances (see replay_engine.py's module docstring). Do not synthesize
one execution per CANONICAL_STAGE_ORDER entry merely because the catalog
exists, in ANY code path, including compatibility loading.

PERSISTED != REPLAYABLE (unchanged from Batch A, restated for v3):
resolve_effective() below only ever inspects whether a matching execution
exists with a real outcome/artifact -- it has NO knowledge of, and no
dependency on, which stages currently have a replay_engine.REPLAY_HANDLERS
entry. A future full run can mark an execution of e.g.
"patch_repair_and_calibration" long before that stage itself gains a
replay handler.

"consumed" is deliberately part of each EXECUTION RECORD, not read from
the live stage_registry.STAGE_DEPENDENCIES constant, so that resolution
judges a historical execution by what it ACTUALLY consumed at production/
replay time -- this is what makes the closest-ancestor-wins resolver
correct even for a stage whose CURRENTLY REGISTERED replay handler
requires fewer dependencies than its final approved contract (see
replay_engine.ReplayHandler.dependencies and its test_analysis_and_plan
entry).

-----------------------------------------------------------------------
"consumed" vs. "invoked_by" -- DATA provenance vs. CAUSAL provenance
(read this before instrumenting any stage that can execute more than
once within one production run, e.g. a future patch_repair_and_
calibration retry loop)
-----------------------------------------------------------------------
"consumed" has ONE strict, non-negotiable meaning: the EXACT execution(s)
this execution actually read/evaluated as input -- never "whatever later
became authoritative." A future patch_repair_and_calibration execution
that evaluates repair candidate #2 and REJECTS it still records
`consumed` pointing at candidate #2's own patch_generation_and_post_
patch_investigation/challenger executions -- it evaluated them, so
`consumed` says so, full stop. Which candidate becomes AUTHORITATIVE for
continuation (the original, on reject; the new one, on accept) is a
separate concern entirely -- see "AUTHORITATIVE CANDIDATE SELECTION"
below. Conflating the two (an earlier version of this module briefly did,
during Batch B1's correctness review) is wrong: `consumed` describing
anything other than "what was actually read" breaks its use as an
honest, inspectable provenance record.

"invoked_by": {"run": ..., "execution_id": ...} | None -- a SEPARATE,
optional field recording which OTHER execution's workflow decision
caused THIS execution to exist, when that reason is not "the normal next
step in a single pass" (e.g. a repair-triggered second
patch_generation_and_post_patch_investigation execution has
invoked_by=<the patch_repair_and_calibration execution that decided
RETRY_PATCH>). `invoked_by` is CAUSAL/CONTROL provenance, not DATA
provenance -- resolve_effective()'s dependency recursion NEVER reads it,
by design: this is exactly what prevents the cycle a naive "just put the
causing execution in `consumed`" design would create (verified directly
while building this correction -- see "WHY invoked_by EXISTS" below).
Ordinary sequential steps within one pass (e.g. a challenger execution
following the patch_generation execution it consumes) need no
`invoked_by` at all -- their `consumed` edge already fully explains why
they exist. `invoked_by` is reserved for the ENTRY POINT of a workflow-
triggered sub-chain only.

WHY invoked_by EXISTS (the cycle it prevents): if a repair-triggered
patch_generation_and_post_patch_investigation execution recorded its
triggering patch_repair_and_calibration execution inside `consumed`
instead, resolving patch_repair_and_calibration's LATEST execution would
recursively need the CURRENT patch_generation_and_post_patch_
investigation (per that stage's own `consumed`), which -- being the
chronologically later sibling -- would need to resolve patch_repair_and_
calibration again to validate its own (wrongly-placed) consumed entry,
re-entering the very resolution already in progress on the same
memoization cache key. Reproduced directly while building this
correction. Keeping the causal edge in `invoked_by` instead means
resolve_effective() never traverses it, so the cycle cannot occur --
`patch_generation_and_post_patch_investigation`'s `consumed` stays scoped
to its real, approved canonical dependencies (stage_registry.
STAGE_DEPENDENCIES: stages 1-3), exactly as before.

AUTHORITATIVE CANDIDATE SELECTION -- a future patch_repair_and_
calibration execution's decision about what becomes authoritative for
continuation is STAGE-SPECIFIC artifact content, not a universal
StageExecution envelope field: it belongs in that execution's own
`extra` bookkeeping (e.g. {"decision": "CONTINUE", "repair_outcome":
"accepted"|"rejected", "selected_candidate": {"patch_generation_and_
post_patch_investigation": {run, execution_id}, "challenger": {run,
execution_id}}}) or inside the artifact file at `artifact_path` -- never
inside `consumed`, and nothing new was added to the shared
new_execution_record() envelope for it (the existing `extra` parameter
already suffices). A downstream Stage-7 execution still canonically
consumes the LATEST patch_repair_and_calibration execution either way
(`resolve_effective` picking the latest execution of the TARGET stage
being resolved was never the problem -- only the recursive freshness
comparison of ITS dependencies was, and that required no weakening, see
below) -- reading Stage 6's own `selected_candidate` bookkeeping (a
future implementation detail, not built in this batch) is how Stage 6's
real run_fn, when it exists, would know which patch text to actually
carry forward; the generic resolver never needs to know this to
correctly resolve "the latest patch_repair_and_calibration execution".

RESOLVER: freshness comparison remains EXACT {run, execution_id} identity
match -- unchanged from the original Batch A design, restored after a
brief, incorrect same-directory weakening was tried and reverted during
this correction. Two same-canonical-stage executions in ONE directory
(e.g. patch_generation_and_post_patch_investigation's initial pass and
its repair-triggered second pass) are NOT automatically compatible with
each other's dependents merely by sharing a directory -- a dependent
recorded consuming execution #1 stays correctly bound to #1 specifically,
and becomes STALE the moment the branch's current resolution for that
canonical stage is #2 instead, exactly like cross-directory replay
supersession. This is required, not merely permitted: see
tests/patch/test_lineage.py::TestWorkflowInternalMultiExecution for the
worked accepted/rejected-repair proof and the same-directory-
supersession proof.

None of this is implemented in production yet (no stage can execute more
than once within one production run in this batch) -- this section
documents the INVARIANTS future stage implementations (starting with
patch_repair_and_calibration) must uphold, and the resolver/schema
support already in place for them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# The version THIS module writes for new manifests (new_full_run_manifest /
# new_replay_manifest). Bump only when the shape of "kind"/"parent"/
# "executions" itself changes in a way an existing consumer would need to
# know about -- purely additive new keys elsewhere never require a bump.
SCHEMA_VERSION = 3

# Versions readable via the bounded legacy path (see module docstring).
_LEGACY_SCHEMA_VERSIONS = frozenset({1})

# Versions readable via the bounded Batch-A ("stages" singleton map)
# compatibility path.
_V2_SCHEMA_VERSIONS = frozenset({2})

# Versions readable as the canonical execution-based shape, trusted as written.
_CANONICAL_SCHEMA_VERSIONS = frozenset({SCHEMA_VERSION})

RESOLVED = "RESOLVED"
STALE = "STALE"
UNRESOLVED = "UNRESOLVED"

# Retained only for v2-compatibility reading (a v2 "stages" entry's own
# status field) -- v3 execution records have no "status" field at all; an
# execution's mere presence in the list IS "produced."
STATUS_PRODUCED = "produced"

INVOCATION_KIND_INITIAL = "initial"
INVOCATION_KIND_RETRY = "retry"
INVOCATION_KIND_REPLAY = "replay"
_VALID_INVOCATION_KINDS = frozenset(
    {INVOCATION_KIND_INITIAL, INVOCATION_KIND_RETRY, INVOCATION_KIND_REPLAY}
)


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
        legacy compatibility. "kind"/"parent" default to a root full run,
        "executions" is honestly EMPTY (never synthesized placeholder rows
        -- this era of manifest recorded nothing structured to adapt).
      - in _V2_SCHEMA_VERSIONS (today: {2}): bounded Batch-A compatibility.
        "executions" is synthesized ONLY from "stages" entries whose
        status=="produced" -- see _adapt_v2_stages_to_executions().
      - in _CANONICAL_SCHEMA_VERSIONS (today: {3}): the current
        execution-based shape -- "kind"/"parent"/"executions" are trusted
        AS WRITTEN. Duplicate execution_id values are rejected.
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
        data["executions"] = []
        return data

    if schema_version in _V2_SCHEMA_VERSIONS:
        data["kind"] = data.get("kind", "full_run")
        data["parent"] = data.get("parent")
        data["executions"] = _adapt_v2_stages_to_executions(data.get("stages", {}) or {})
        return data

    if schema_version not in _CANONICAL_SCHEMA_VERSIONS:
        raise LineageError(
            f"{manifest_path} declares schema_version={schema_version!r}, "
            f"which this version of the lineage resolver does not support "
            f"(supported: legacy {sorted(_LEGACY_SCHEMA_VERSIONS)}, "
            f"v2-compat {sorted(_V2_SCHEMA_VERSIONS)}, canonical "
            f"{sorted(_CANONICAL_SCHEMA_VERSIONS)}). Regenerate the run "
            f"with a compatible run_traced.py, or use a newer lineage.py."
        )

    # Canonical (v3): trust the file's own kind/parent/executions --
    # defensive setdefault only, never overriding real content.
    data.setdefault("kind", "full_run")
    data.setdefault("parent", None)
    data.setdefault("executions", [])
    _validate_executions(data["executions"], source=str(manifest_path))
    return data


def _adapt_v2_stages_to_executions(stages: dict) -> "list[dict]":
    """Bounded Batch-A (v2) compatibility: adapt a "stages": {name: entry}
    singleton map into a v3-shaped executions list. HONEST by
    construction: only entries with status=="produced" are adapted (never
    "not_persisted"/"legacy" -- there is no artifact to represent), and
    each produced stage becomes EXACTLY ONE execution
    (invocation_kind="initial") -- v2 never recorded retries or multiple
    attempts for a stage, so synthesizing more than one would fabricate
    history that was never observed.

    Sequence is assigned by CANONICAL_STAGE_ORDER position among the
    produced entries -- v2 never recorded true execution order either, so
    this is a deterministic (if arbitrary) total order, not a claim about
    real timing.
    """
    from .stage_registry import CANONICAL_STAGE_ORDER

    produced_names = [
        name for name in CANONICAL_STAGE_ORDER
        if (stages.get(name) or {}).get("status") == STATUS_PRODUCED
    ]
    id_by_stage = {name: make_execution_id(i + 1, name) for i, name in enumerate(produced_names)}

    executions = []
    for i, name in enumerate(produced_names):
        entry = stages[name]
        consumed = {}
        for dep, ref in (entry.get("consumed_dependencies") or {}).items():
            dep_run = (ref or {}).get("run")
            dep_execution_id = id_by_stage.get(dep)
            if dep_execution_id is None and dep_run is not None:
                # The dependency wasn't produced in THIS manifest -- it may
                # still be resolvable in an ancestor directory. Look it up
                # there honestly rather than guessing; never fabricate.
                dep_execution_id = _v2_dependency_execution_id(dep_run, dep)
            if dep_execution_id is None:
                # Genuinely unresolvable from this manifest alone -- omit
                # rather than record a broken/guessed reference. A resolver
                # walking this execution's `consumed` will then correctly
                # see this dependency as absent, not silently valid.
                continue
            consumed[dep] = {"run": dep_run, "execution_id": dep_execution_id}
        executions.append(new_execution_record(
            execution_id=id_by_stage[name],
            canonical_stage=name,
            sequence=i + 1,
            invocation_kind=INVOCATION_KIND_INITIAL,
            consumed=consumed,
            outcome=entry.get("outcome"),
            replay_of=None,
            artifact_path=entry.get("artifact_path"),
            llm_calls=entry.get("llm_calls") or [],
            external_calls=entry.get("external_calls") or [],
            timing=entry.get("timing"),
            extra={"_compat_source": "v2"},
        ))
    return executions


def _v2_dependency_execution_id(dep_run: str, canonical_stage: str) -> "str | None":
    """Best-effort cross-directory lookup for v2 compatibility: what
    execution_id would `dep_run`'s OWN manifest synthesize for
    `canonical_stage`? Loads that directory (recursively -- lineage
    parent chains are acyclic by construction, enforced by build_chain's
    own cycle guard on the overall walk) and checks its already-adapted
    executions. Returns None if unresolvable -- callers must never guess."""
    try:
        dep_manifest = load_manifest(dep_run)
    except LineageError:
        return None
    execution = latest_execution_in_manifest(dep_manifest, canonical_stage)
    return execution["execution_id"] if execution is not None else None


# ---------------------------------------------------------------------------
# Manifest construction helpers
# ---------------------------------------------------------------------------


def make_execution_id(sequence: int, canonical_stage: str) -> str:
    """The smallest deterministic, human-readable execution id: the
    directory-local sequence number (zero-padded) plus the canonical
    stage name -- e.g. "001_test_analysis_and_plan". Matches the on-disk
    prompt/response file naming convention replay_engine.py and
    run_traced.py already use ({seq:03d}_{tag}...), so a directory listing
    stays self-describing without opening the manifest."""
    return f"{sequence:03d}_{canonical_stage}"


def _validate_executions(executions: "list[dict]", *, source: str = "<manifest>") -> None:
    seen: "set[str]" = set()
    for execution in executions:
        execution_id = execution.get("execution_id")
        if execution_id in seen:
            raise LineageError(f"Duplicate execution_id {execution_id!r} in {source}.")
        seen.add(execution_id)
        invocation_kind = execution.get("invocation_kind")
        if invocation_kind not in _VALID_INVOCATION_KINDS:
            raise LineageError(
                f"{source}: execution {execution_id!r} has invalid "
                f"invocation_kind {invocation_kind!r}; must be one of "
                f"{sorted(_VALID_INVOCATION_KINDS)}."
            )


def new_execution_record(
    *,
    execution_id: str,
    canonical_stage: str,
    sequence: int,
    invocation_kind: str,
    consumed: "Optional[dict]" = None,
    outcome: "Optional[str]" = None,
    replay_of: "Optional[dict]" = None,
    invoked_by: "Optional[dict]" = None,
    artifact_path: "Path | str | None" = None,
    llm_calls: "Optional[list]" = None,
    external_calls: "Optional[list]" = None,
    timing: "Optional[dict]" = None,
    extra: "Optional[dict]" = None,
) -> dict:
    """Build one StageExecution record -- the smallest unit v3 persists.

    `consumed` must have exactly one key per canonical stage this
    execution actually READ/EVALUATED as input, each a {"run": <dir>,
    "execution_id": <id>} identity dict -- see Resolution.as_identity_dict().
    This is strict DATA provenance: it never reflects anything other than
    what was actually consumed, regardless of what the execution decided
    to do with it (see module docstring).

    `invoked_by` is a SEPARATE, optional {"run": ..., "execution_id": ...}
    identity dict recording which OTHER execution's workflow decision
    caused this execution to exist (CAUSAL/CONTROL provenance) -- None for
    ordinary executions. It is never read by resolve_effective()'s
    dependency recursion; see module docstring for why that separation is
    required.
    """
    if invocation_kind not in _VALID_INVOCATION_KINDS:
        raise LineageError(
            f"Invalid invocation_kind {invocation_kind!r} for execution "
            f"{execution_id!r}; must be one of {sorted(_VALID_INVOCATION_KINDS)}."
        )
    record = {
        "execution_id": execution_id,
        "canonical_stage": canonical_stage,
        "sequence": sequence,
        "invocation_kind": invocation_kind,
        "consumed": consumed or {},
        "outcome": outcome,
        "replay_of": replay_of,
        "invoked_by": invoked_by,
        "artifact_path": str(artifact_path) if artifact_path else None,
        "llm_calls": llm_calls or [],
        "external_calls": external_calls or [],
        "timing": timing,
    }
    if extra:
        record.update(extra)
    return record


def new_full_run_manifest(
    *,
    target_repository: dict,
    openant: dict,
    llm: dict,
    executions: "Optional[list]" = None,
    extra: "Optional[dict]" = None,
) -> dict:
    executions = list(executions or [])
    _validate_executions(executions, source="new_full_run_manifest")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "full_run",
        "parent": None,
        "target_repository": target_repository,
        "openant": openant,
        "llm": llm,
        "executions": executions,
    }
    if extra:
        manifest.update(extra)
    return manifest


def new_replay_manifest(
    *,
    parent: "Path | str",
    target_repository: dict,
    openant: dict,
    llm: dict,
    executions: "list",
    extra: "Optional[dict]" = None,
) -> dict:
    executions = list(executions)
    _validate_executions(executions, source="new_replay_manifest")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "replay",
        "parent": str(parent),
        "target_repository": target_repository,
        "openant": openant,
        "llm": llm,
        "executions": executions,
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
# Per-directory execution lookup -- shared by resolve_effective() and the
# replay_of provenance lookup, neither of which needs a database: the full
# executions list for one directory is always small and fully in memory.
# ---------------------------------------------------------------------------


def latest_execution_in_manifest(manifest: dict, canonical_stage: str) -> "Optional[dict]":
    """The candidate execution for `canonical_stage` within ONE already-
    loaded manifest: the execution with the highest `sequence` whose
    canonical_stage matches (the most recent attempt in this directory).
    None if this directory never produced that stage at all. `sequence`
    is directory-local by design (see module docstring) -- this is the
    one place that locality is actually used.

    PURELY CHRONOLOGICAL. resolve_effective() below uses it as the
    candidate for BOTH the stage being resolved AND, recursively, for each
    of its dependencies -- with an EXACT identity match required between
    what a candidate execution's own `consumed` recorded for a dependency
    and what that dependency currently resolves to (see resolve_effective
    and the module docstring's "consumed vs. invoked_by" section)."""
    candidates = [e for e in manifest.get("executions", []) if e.get("canonical_stage") == canonical_stage]
    if not candidates:
        return None
    return max(candidates, key=lambda e: e.get("sequence", -1))


def find_latest_execution_identity(chain: "list[Path]", canonical_stage: str) -> "Optional[dict]":
    """Closest-ancestor-wins search for ANY execution of `canonical_stage`
    across `chain`, with NO staleness/consumed-edge validation -- this is
    NOT a data-dependency resolution (see resolve_effective for that); it
    answers "does a prior execution of what I'm about to (re)do exist
    anywhere in this lineage," used only to populate a new execution's
    honest `replay_of` pointer. Returns {"run": ..., "execution_id": ...}
    or None if genuinely never produced anywhere in this lineage -- never
    fabricated.

    HEURISTIC, NOT A GUARANTEE: once a canonical stage can legitimately
    execute more than once within a single directory (not possible yet in
    this batch -- run_stage.py always creates exactly one execution per
    invocation), "the latest one" is only a reasonable DEFAULT guess at
    what a developer means by "replay this stage," not necessarily the
    specific execution they intend to target (they may want to redo an
    EARLIER attempt specifically). Explicit execution selection (e.g. a
    future --of-execution flag) is required before replay of a stage with
    real multiple executions can be considered unambiguous -- this
    function and run_stage.py's CLI do not attempt to solve that here."""
    for run_dir in chain:
        manifest = load_manifest(run_dir)
        execution = latest_execution_in_manifest(manifest, canonical_stage)
        if execution is not None:
            return {"run": str(run_dir), "execution_id": execution["execution_id"]}
    return None


# ---------------------------------------------------------------------------
# Artifact identity + resolution states
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ArtifactIdentity:
    """The smallest stable identity for a stage EXECUTION's artifact:
    which run/replay directory produced it, plus that execution's own id
    (unique within the directory). No content hash -- sufficient for
    dependency freshness checks because every replay directory is itself
    immutable once written (see replay_engine.py). Canonical stage is
    metadata on the execution record itself, not part of identity -- a
    directory may (in a future batch) hold more than one execution of the
    same canonical stage, so identity must key on execution_id, not stage
    name, to stay unambiguous."""

    run_dir: str
    execution_id: str


@dataclass(frozen=True)
class Resolution:
    """The result of resolving one canonical stage's effective execution in
    a lineage. `state` is one of RESOLVED / STALE / UNRESOLVED -- exactly
    the three outcomes the architecture calls for, nothing fancier.

    STALE does not mean invalid, corrupt, or obsolete: it means a
    historical execution exists and remains permanently valid AS HISTORY,
    but its recorded `consumed` identities are incompatible with the
    branch currently being resolved (some upstream dependency was
    replayed after this execution last ran). The historical execution
    itself is never mutated, deleted, or invalidated -- it is simply not
    the compatible input for continuing from THIS branch tip.
    """

    state: str
    identity: "Optional[ArtifactIdentity]" = None
    artifact_path: "Optional[str]" = None
    run_dir: "Optional[str]" = None
    reason: "Optional[str]" = None

    @property
    def is_resolved(self) -> bool:
        return self.state == RESOLVED

    def as_identity_dict(self) -> dict:
        """{"run": ..., "execution_id": ...} -- the exact shape stored in
        a consuming execution's own "consumed" entry, and compared against
        on a later resolution. Only valid when state == RESOLVED."""
        if not self.is_resolved or self.identity is None:
            raise LineageError(
                f"Cannot build an identity dict for a non-RESOLVED resolution (state={self.state!r})."
            )
        return {"run": self.identity.run_dir, "execution_id": self.identity.execution_id}


def resolve_effective(
    chain: "list[Path]",
    stage_name: str,
    cache: "Optional[dict]" = None,
) -> Resolution:
    """Resolve `stage_name`'s effective execution within `chain` (tip-first,
    as returned by build_chain).

    Closest-ancestor-wins: for each directory in the chain, the candidate
    is that directory's own latest_execution_in_manifest() for
    `stage_name` (highest `sequence` in that directory). The FIRST
    directory with any matching execution wins -- but only if that
    execution's own recorded `consumed` identities EXACTLY match
    {"run": ..., "execution_id": ...} what each dependency CURRENTLY
    resolves to in this same lineage. This is an EXACT execution-identity
    comparison, not a directory-scoped one: two executions of the same
    canonical stage sharing one directory (a workflow-internal retry, e.g.
    a repair-triggered second patch_generation_and_post_patch_
    investigation execution) are NOT interchangeable for staleness
    purposes just because they share a directory -- a dependent recorded
    consuming execution #1 specifically stays bound to #1, and is STALE
    the instant the branch's current resolution for that stage is #2
    instead. See the module docstring's "consumed vs. invoked_by" section:
    the field that lets a workflow-triggered execution exist without
    corrupting this exactness is the separate, causal-only `invoked_by`
    field, which this function never reads. Staleness propagates
    transitively for free because that recursive check is exactly what
    this function does for each dependency too (memoized via `cache`, one
    entry per stage name, shared across the whole resolution of a
    lineage).

    An execution with an empty `consumed` dict (either because its final
    contract has no dependencies, e.g.
    repository_analysis_and_remediation_planning, or because it was
    produced by a transitional implementation that has not started
    checking its full final contract's dependencies yet) is valid
    wherever it is found, with no freshness check to perform.
    """
    if cache is None:
        cache = {}
    if stage_name in cache:
        return cache[stage_name]

    # Cycle guard: a stage that (incorrectly) lists itself, directly or
    # transitively, as its own dependency would otherwise recurse forever.
    # Never true for the approved STAGE_DEPENDENCIES graph (acyclic by
    # construction, covered by a dedicated test), but a hand-built
    # manifest fixture could still construct one -- fail closed rather
    # than hang.
    cache[stage_name] = Resolution(
        state=UNRESOLVED, reason=f"cycle detected while resolving {stage_name!r}"
    )

    for run_dir in chain:
        manifest = load_manifest(run_dir)
        execution = latest_execution_in_manifest(manifest, stage_name)
        if execution is None:
            continue

        valid = True
        reason = None
        consumed = execution.get("consumed", {}) or {}
        for dep, recorded in consumed.items():
            dep_resolution = resolve_effective(chain, dep, cache)
            if not dep_resolution.is_resolved:
                valid = False
                reason = (
                    f"dependency {dep!r} is {dep_resolution.state} in this "
                    f"lineage ({dep_resolution.reason})"
                )
                break
            # EXACT execution-identity comparison -- {"run", "execution_id"}
            # both must match. `consumed` is strict data provenance (see
            # module docstring's "consumed vs. invoked_by" section): if
            # this execution's recorded input for `dep` is not EXACTLY the
            # execution the branch currently resolves `dep` to -- whether
            # because `dep` was replayed into a different, closer directory,
            # or because a later sibling execution of `dep` now exists in
            # the SAME directory -- this execution's own consumption of
            # `dep` is stale. Workflow-triggered re-invocation (e.g. a
            # repair loop) is represented via the separate `invoked_by`
            # causal field, which is never read here, so it cannot
            # participate in -- or break -- this comparison.
            current_identity = dep_resolution.as_identity_dict()
            if recorded != current_identity:
                valid = False
                reason = (
                    f"dependency {dep!r} was consumed as {recorded!r} but "
                    f"the current resolved lineage has it at "
                    f"{current_identity!r} -- {dep!r} was superseded after "
                    f"{stage_name!r} last consumed it"
                )
                break

        if valid:
            result = Resolution(
                state=RESOLVED,
                identity=ArtifactIdentity(run_dir=str(run_dir), execution_id=execution["execution_id"]),
                artifact_path=execution.get("artifact_path"),
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
