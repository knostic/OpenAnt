"""Passive StageExecution recording for a REAL production pipeline run --
Batch B2.

This module adds exactly one thing to the Batch B1 execution-graph
foundation (lineage.py/replay_engine.py): a way for pipeline.run() to
record honest StageExecution entries for the canonical stages it actually,
currently instruments (Stages 1-5's initial pass only, as of B2 -- see
pipeline.py's own call sites), while remaining a complete no-op for every
existing caller that doesn't pass a recorder.

DESIGN CONSTRAINT (Final Correction 2 of the B2 planning turn): this class
must NOT open its own LLM-call capture/monkeypatch scope. tools/run_traced.py
already wraps utilities.autopatcher.llm_client.call_llm exactly once (via
LLMCallCapture, see llm_call_tracing.py) for the whole traced run --
production execution instrumentation must not add a second, nested
capture/monkeypatch layer around the LLM client. Instead, ExecutionRecorder
is handed a reference to that ALREADY-EXISTING, already-ordered,
append-only call log (e.g. tools/run_traced.py's LLMCallTracer.calls) and
does nothing but remember a cursor (`len(call_log)`) at start() and slice
`call_log[cursor:end]` at finish(). It never calls call_llm, never patches
anything, never duplicates a call, never reorders one -- purely passive
read access to a list some other, already-active mechanism is already
appending to in real time.

This is deliberately NOT a generic telemetry/workflow framework: two
methods (start/finish), one cursor per open execution, one JSON artifact
write per finished execution. Ordering/branching (which stage runs when,
whether a repair loop fires) stays entirely inside pipeline.py's own,
unmodified control flow -- this module only ever gets TOLD "an execution of
this canonical stage just started/finished," never decides that itself.

RECORDING-SAFETY CORRECTIONS (post-implementation review):

1. LLM OWNERSHIP VALIDATION -- cursor/slice attribution (above) assumes
   every call captured inside a bracket genuinely belongs to that
   canonical stage. finish() now cross-checks every captured call's
   `stage` tag against the authoritative
   stage_registry.STAGE_OWNED_LLM_TAGS[canonical_stage] map before
   accepting the bracket. This is NOT a second attribution mechanism --
   cursor/slice still decides WHICH calls belong to an execution; the
   registry only proves the bracket and canonical ownership AGREE. A
   mismatch means the bracket boundaries are wrong (or a stage made an
   LLM call outside its approved contract) -- either way this must fail
   loudly, before writing a misleading artifact, never silently drop or
   reassign the call.

2. FAIL-CLOSED SERIALIZATION -- to_jsonable() no longer has a str()
   fallback for unsupported types. A canonical StageExecution artifact
   must be exactly reconstructible; a silent str(obj) could turn an
   unsupported/non-deterministic object into a permanently-recorded,
   non-replayable artifact while the execution is still marked produced.
   Only the explicitly supported shapes serialize; anything else raises
   ExecutionRecorderError immediately, before any file is written.

3. ARTIFACT WRITE-ONCE ENFORCEMENT -- finish() now refuses to write over
   an existing `<execution_id>.json`. The sequence/execution_id scheme
   already prevents this in normal operation, but immutability is a core
   B1/B2 invariant and is now enforced at the storage boundary too, not
   only by construction.

Both (2) and (3) are checked BEFORE any file is created or the executions
list is appended to -- a failure here leaves this recorder's state (and
disk) exactly as it was before finish() was called; nothing is partially
written.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Optional

from . import lineage
from .stage_registry import STAGE_OWNED_LLM_TAGS

# Call-record keys NOT copied onto a StageExecution's `llm_calls` -- the
# full prompt/response TEXT is already written to disk by
# tools/run_traced.py's LLMCallTracer as {seq:03d}_{stage}.prompt.txt /
# .response.txt (see that class's `_write_call`); duplicating the full text
# a second time, inline, inside every execution's artifact JSON would bloat
# every artifact file with megabytes of text the trace directory already
# holds. `prompt_file`/`response_file` (added by that same `_write_call`
# hook before this module ever sees the record) are kept as the pointer.
_CALL_RECORD_TEXT_FIELDS = ("prompt", "response")


class ExecutionRecorderError(RuntimeError):
    """Raised for any ExecutionRecorder failure that must abort the run
    rather than silently degrade: an LLM call attributed to a bracket its
    canonical stage does not own (see STAGE_OWNED_LLM_TAGS), an artifact
    value to_jsonable() cannot represent exactly, or an attempt to
    overwrite an already-written execution artifact. Mirrors
    lineage.LineageError / stage_replay.StageReplayError's contract:
    always raised before any (further) file write for the offending
    execution, never after a partial one.
    """


def to_jsonable(obj):
    """Recursively convert a plain-data Python value -- including
    dataclasses and NamedTuples, arbitrarily nested -- into something
    json.dumps can serialize with real, keyed objects at every level.

    Why the dataclass/NamedTuple handling exists: `dataclasses.asdict()`
    alone is NOT sufficient here -- it recurses into nested dataclasses
    correctly, but a NamedTuple nested inside a dataclass field (or another
    NamedTuple) is left as-is, and since a NamedTuple IS a tuple,
    json.dumps then serializes it as a bare positional JSON array, silently
    losing every field name. Several real Auto Patcher stage-output shapes
    mix both (e.g. remediation_planner.EditReadinessResult, a NamedTuple,
    holding lists of ReadyEdit/UnreadyEdit NamedTuples, each wrapping an
    IntendedEdit NamedTuple) -- this function is the one place that
    difference is handled, recursively, so every StageExecution artifact
    this module writes has real field names at every nesting level, not
    just the top.

    FAILS CLOSED: any object that is not one of the explicitly supported
    shapes below raises ExecutionRecorderError -- there is no str()/repr()
    fallback. A canonical StageExecution artifact must be exactly, fully
    reconstructible; silently degrading an unsupported value to a display
    string would produce a non-deterministic, non-replayable artifact
    while the execution is still recorded as produced. Extend this
    function explicitly (a new supported shape) rather than relying on a
    fallback if a real stage output ever needs one.

    Supported: None, str, int, float, bool, Path, dataclass instances,
    NamedTuple instances, dict, list, tuple, set, frozenset (arbitrarily
    nested). set/frozenset are sorted before conversion (falling back to
    sorting by JSON-serialized form if elements aren't natively orderable)
    so the same logical value always serializes identically -- Python's
    own set iteration order is not guaranteed stable across runs/machines.
    """
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Path):
        return str(obj)
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if hasattr(obj, "_asdict"):  # NamedTuple
        return {k: to_jsonable(v) for k, v in obj._asdict().items()}
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        items = [to_jsonable(v) for v in obj]
        try:
            return sorted(items)
        except TypeError:
            # Elements aren't natively orderable (e.g. a set of dicts) --
            # sort by their own JSON form instead, so ordering is still a
            # deterministic function of content, never of hash-seed/
            # insertion order.
            return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    raise ExecutionRecorderError(
        f"to_jsonable() cannot serialize an object of type {type(obj).__name__!r} "
        f"({obj!r}) into a canonical StageExecution artifact -- only "
        f"None/str/int/float/bool/Path/dataclass/NamedTuple/dict/list/tuple/"
        f"set/frozenset are supported (arbitrarily nested). There is no "
        f"str()/repr() fallback: extend to_jsonable() with an explicit case "
        f"for this shape, or stop passing it, rather than recording a "
        f"non-reconstructible artifact."
    )


def _strip_call_record(call: dict) -> dict:
    """One LLM-call record, minus the full prompt/response text -- see
    _CALL_RECORD_TEXT_FIELDS above."""
    return {k: v for k, v in call.items() if k not in _CALL_RECORD_TEXT_FIELDS}


def _validate_llm_ownership(canonical_stage: str, raw_calls: "list[dict]") -> None:
    """Cross-check cursor/slice attribution against the authoritative
    ownership map, stage_registry.STAGE_OWNED_LLM_TAGS. Cursor/slice
    remains the attribution mechanism -- this only PROVES the bracket and
    canonical ownership agree; it never reassigns or reattributes a call.

    A canonical stage with no owned tags at all (an empty tuple, e.g.
    impact_and_behavior_analysis) means ANY captured call is an error --
    falls out of the same `tag not in owned` check with no special case.
    """
    owned = STAGE_OWNED_LLM_TAGS.get(canonical_stage, ())
    for call in raw_calls:
        tag = call.get("stage")
        if tag not in owned:
            raise ExecutionRecorderError(
                f"LLM call with stage tag {tag!r} occurred inside the "
                f"{canonical_stage!r} StageExecution bracket, but "
                f"stage_registry.STAGE_OWNED_LLM_TAGS[{canonical_stage!r}] = "
                f"{owned!r} does not include it. Refusing to attach this "
                f"call to a {canonical_stage!r} execution artifact -- the "
                f"bracket boundaries and canonical LLM ownership disagree. "
                f"Fix the bracket (or the registry) rather than silently "
                f"dropping or reassigning the call."
            )


class ExecutionRecorder:
    """Records real StageExecution entries for a single production run, in
    memory, plus one JSON artifact file per finished execution.

    Not constructed by production `pipeline.run()` itself -- callers that
    want recording construct one (today: only tools/run_traced.py) and
    pass it in as `execution_recorder=`; every other caller (openant/cli.py,
    core/patch.py's own defaults) passes nothing, and `pipeline.run()`
    guards every recorder call with `if execution_recorder is not None:`,
    so this class is never touched by ordinary `openant patch` runs.

    `call_log`: the SAME list object some already-active, already-ordered
    call-capture mechanism (e.g. tools/run_traced.py's
    `LLMCallTracer.calls`) keeps appending LLM-call records to, in call
    order, for the whole traced run. This class only ever reads a slice of
    it -- see the module docstring for why it must not build its own
    capture.

    `run_dir`: the directory a future `--source-run`/`--source-trace` would
    point at for THIS run -- i.e. the same value stage_replay.py's
    resolve_source_trace_dir/lineage.py's resolve_manifest_path already
    expect (the run's outer output directory; the manifest itself may live
    one level deeper, under `trace/`, exactly as full runs already do
    today). Used only to stamp the `run` half of every `{run, execution_id}`
    identity this recorder produces, in `consumed`/`invoked_by` edges
    between executions of ONE run.

    `artifacts_dir`: where each finished execution's own JSON artifact file
    is written, named `<execution_id>.json` (never bare
    `<canonical_stage>.json` -- see the module docstring on why execution_id
    is required in every filename, so a later batch recording more than one
    execution of the same canonical stage in one run cannot collide or
    overwrite an earlier sibling's artifact).
    """

    def __init__(self, call_log: "list[dict]", run_dir: "str | Path", artifacts_dir: "str | Path"):
        self._call_log = call_log
        self.run_dir = str(run_dir)
        self.artifacts_dir = Path(artifacts_dir)
        self.executions: "list[dict]" = []
        self._open: "dict[int, dict]" = {}
        self._next_handle = 0

    def start(
        self,
        canonical_stage: str,
        *,
        invocation_kind: str = lineage.INVOCATION_KIND_INITIAL,
        consumed: "Optional[list[dict]]" = None,
        invoked_by: "Optional[dict]" = None,
    ) -> int:
        """Begin recording one execution of `canonical_stage`. Returns an
        opaque handle to pass to finish().

        `consumed`: an iterable of PRIOR execution records already
        returned by this recorder's own finish() -- not raw
        {run, execution_id} dicts -- so call sites never have to know
        `run_dir`/build identity dicts themselves. Converted here into the
        canonical_stage-keyed `{dep_canonical_stage: {run, execution_id}}`
        shape lineage.py's resolver expects.

        `invoked_by`: likewise, a single prior execution record (or None)
        -- the execution whose workflow decision caused this one to exist.
        Not used in B2 (no stage yet records more than one execution of
        itself), included now only so the field exists honestly (null) on
        every B2 record, matching B1's schema.
        """
        handle = self._next_handle
        self._next_handle += 1
        consumed_dict = {}
        for rec in consumed or ():
            consumed_dict[rec["canonical_stage"]] = {
                "run": self.run_dir,
                "execution_id": rec["execution_id"],
            }
        invoked_by_ref = None
        if invoked_by is not None:
            invoked_by_ref = {"run": self.run_dir, "execution_id": invoked_by["execution_id"]}
        self._open[handle] = {
            "canonical_stage": canonical_stage,
            "invocation_kind": invocation_kind,
            "consumed": consumed_dict,
            "invoked_by": invoked_by_ref,
            "cursor": len(self._call_log),
        }
        return handle

    def finish(
        self,
        handle: int,
        *,
        outcome: "Optional[str]",
        artifact: "Optional[dict]" = None,
        extra: "Optional[dict]" = None,
    ) -> dict:
        """Complete the execution `handle` refers to: slice every LLM call
        made since the matching start() off `call_log` (never more, never
        fewer -- an exact, non-overlapping window, since B2's brackets
        never interleave), validate each call's stage tag against
        STAGE_OWNED_LLM_TAGS, serialize+write `artifact` to its own
        `<execution_id>.json` file (refusing to overwrite one that already
        exists), and append the finished StageExecution record. Returns
        that record so the caller can pass it as a later stage's
        `consumed`/`invoked_by`.

        Every validation/serialization/immutability check below runs
        BEFORE any file is written or `self.executions` is appended to --
        a raised ExecutionRecorderError leaves this recorder's state (and
        disk) exactly as it was before this call.
        """
        opened = self._open.pop(handle)
        end = len(self._call_log)
        raw_calls = self._call_log[opened["cursor"]:end]

        # Correction 1: prove the bracket and canonical LLM ownership
        # agree. Cursor/slice already decided WHICH calls belong here --
        # this only refuses to accept a bracket whose calls disagree with
        # stage_registry's authoritative map.
        _validate_llm_ownership(opened["canonical_stage"], raw_calls)
        llm_calls = [_strip_call_record(c) for c in raw_calls]

        sequence = len(self.executions) + 1
        execution_id = lineage.make_execution_id(sequence, opened["canonical_stage"])

        artifact_path = None
        if artifact is not None:
            # Correction 2: fail closed on serialization -- raises before
            # any file exists if `artifact` contains anything to_jsonable()
            # doesn't explicitly support (idempotent no-op if the caller
            # already ran it through to_jsonable() itself).
            artifact_json = json.dumps(to_jsonable(artifact), indent=2)

            artifact_file = self.artifacts_dir / f"{execution_id}.json"
            # Correction 3: write-once enforcement at the storage boundary
            # -- the sequence/execution_id scheme already prevents this in
            # normal operation, but immutability is a core invariant and
            # must not depend solely on that construction.
            if artifact_file.exists():
                raise ExecutionRecorderError(
                    f"Refusing to overwrite existing execution artifact "
                    f"{artifact_file} -- StageExecution artifacts are "
                    f"immutable once written."
                )
            self.artifacts_dir.mkdir(parents=True, exist_ok=True)
            artifact_file.write_text(artifact_json, encoding="utf-8")
            artifact_path = str(artifact_file)

        record = lineage.new_execution_record(
            execution_id=execution_id,
            canonical_stage=opened["canonical_stage"],
            sequence=sequence,
            invocation_kind=opened["invocation_kind"],
            consumed=opened["consumed"],
            outcome=outcome,
            invoked_by=opened["invoked_by"],
            artifact_path=artifact_path,
            llm_calls=llm_calls,
            extra=extra,
        )
        self.executions.append(record)
        return record
