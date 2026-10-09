#!/usr/bin/env python3
"""
replay_challenger_reparse.py -- zero-LLM deterministic Challenger reparse tool.

Lives at utilities/autopatcher/tools/ -- a normal, tracked, importable
location next to the other Auto Patcher debug tools (run_traced.py,
run_stage.py); see utilities/autopatcher/tools/__init__.py and
TRACING_AND_DEBUGGING.md in this same directory.

What it does, precisely:
  1. Resolves an archived `challenger` stage execution anywhere in
     --source-run's lineage (closest-ancestor-wins, via the same
     lineage.find_latest_execution_identity() helper already used
     elsewhere for replay-provenance lookups) and reads that execution's
     own recorded raw response file VERBATIM -- never re-derived,
     never re-rendered.
  2. Resolves the `patch_generation_and_post_patch_investigation`
     artifact by reading the EXACT {run, execution_id} identity the
     archived `challenger` execution itself recorded as consumed
     (execution["consumed"]["patch_generation_and_post_patch_
     investigation"]) and following that pointer directly via
     lineage.load_manifest() -- never lineage.resolve_effective().
     resolve_effective() answers "what does this stage currently,
     effectively resolve to across the whole lineage" (a freshness/
     staleness check meant for chained replays); this tool instead needs
     the EXACT historical dependency one specific past execution actually
     consumed, which is already recorded data, not something to
     re-derive. Never falls back to a newer/effective/same-stage-
     elsewhere execution if the exact recorded one cannot be resolved.
  3. Runs that EXACT archived response text through
     reparse_challenger_response() below, which calls the production
     patch_challenger.challenge_patch() itself with a replay stub in
     place of the LLM (returning the archived text) and the same
     Challenger inputs the replay engine passes: the S4 artifact's
     shown context, its recorded citation-authority parts, and its
     trusted post-patch definitions. Every decision is therefore made by
     production code; nothing here copies, mirrors, or approximates it.
     Not reproduced: the archived call's own provider stop reason (a
     truncated response is not detected here).
  4. Writes one JSON artifact to --output. Makes no LLM call (no
     LLMClient is ever constructed), runs no other canonical stage, and
     never touches production code.

This is experimental/debug tooling only. It must never be imported by
pipeline.py or any other production code path.

Usage:
    python3 utilities/autopatcher/tools/replay_challenger_reparse.py \\
        --source-run /tmp/some-trace \\
        --output /tmp/some-reparse-control
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# utilities/autopatcher/tools/replay_challenger_reparse.py -> tools ->
# autopatcher -> utilities -> <openant-core root>
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.autopatcher import lineage  # noqa: E402
from utilities.autopatcher.execution_recorder import to_jsonable  # noqa: E402
from utilities.autopatcher.patch_challenger import challenge_patch  # noqa: E402
from utilities.autopatcher.pipeline import _challenger_provenance_context  # noqa: E402
from utilities.autopatcher.stage_registry import (  # noqa: E402
    CHALLENGER,
    PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
)


class ReparseError(RuntimeError):
    """Raised for any input-resolution failure -- always before any
    parsing, mirroring lineage.LineageError's / stage_replay.
    StageReplayError's own contract of failing clearly rather than
    silently producing partial output."""


class _ArchivedResponse:
    """Stands in for the LLM: returns the archived response text, never a
    model call."""

    def __init__(self, text: str) -> None:
        self._text = text

    def complete(self, system_prompt, user_message, stage=None) -> str:
        return self._text


def reparse_challenger_response(
    response_text: str, *, code_context: str, patch: str, vulnerability_text: str,
    provenance_context: "str | None" = None, post_patch_definitions=None,
) -> dict:
    """The production `challenge_patch()` result for an already-obtained
    response string: the same function, with the archived text in place of
    a fresh LLM call. Pass the same `provenance_context` and
    `post_patch_definitions` production passed (see
    replay_challenger_reparse) -- omitting them reparses with no citation
    boundary and no trusted post-patch definitions."""
    return challenge_patch(
        vulnerability_text, patch, _ArchivedResponse(response_text), code_context=code_context,
        provenance_context=provenance_context, post_patch_definitions=post_patch_definitions,
    )


def _find_archived_challenger_response(chain: "list[Path]") -> "tuple[Path, str, dict]":
    """Locate the archived `challenger` stage's own most recent execution
    anywhere in `chain` and read its own recorded raw response file
    verbatim. Returns (response_path, response_text, execution_record)."""
    identity = lineage.find_latest_execution_identity(chain, CHALLENGER)
    if identity is None:
        raise ReparseError(
            f"No archived {CHALLENGER!r} execution found in this lineage."
        )
    run_dir = identity["run"]
    execution_id = identity["execution_id"]
    manifest = lineage.load_manifest(run_dir)
    execution = next(
        (e for e in manifest.get("executions", []) if e.get("execution_id") == execution_id),
        None,
    )
    if execution is None:
        raise ReparseError(
            f"Execution {execution_id!r} not found in {run_dir}'s manifest "
            f"(lineage inconsistency)."
        )

    challenger_calls = [c for c in execution.get("llm_calls", []) or [] if c.get("stage") == CHALLENGER]
    if not challenger_calls:
        raise ReparseError(
            f"Execution {execution_id!r} in {run_dir} has no LLM call tagged "
            f"{CHALLENGER!r} -- cannot locate its raw response."
        )
    call = max(challenger_calls, key=lambda c: c.get("seq", -1))
    response_file = call.get("response_file")
    if not response_file:
        raise ReparseError(
            f"Execution {execution_id!r} in {run_dir}'s {CHALLENGER!r} LLM "
            f"call record has no response_file."
        )

    trace_dir = lineage.resolve_manifest_path(run_dir).parent
    response_path = trace_dir / response_file
    if not response_path.is_file():
        raise ReparseError(f"Archived response file not found: {response_path}")

    return response_path, response_path.read_text(encoding="utf-8"), execution


def _resolve_upstream_evidence(execution: dict) -> "tuple[dict, str]":
    """Resolve the EXACT patch_generation_and_post_patch_investigation
    artifact the archived `challenger` execution itself recorded as
    consumed -- never lineage.resolve_effective()'s current/effective
    resolution, and never any other stand-in. `execution["consumed"]`
    is strict, honest data provenance (see lineage.py's own module
    docstring): it names exactly the {run, execution_id} identity this
    execution actually read, so following it directly -- via
    lineage.load_manifest() plus a plain execution_id lookup, the same
    primitive _find_archived_challenger_response() above already uses to
    locate the challenger execution itself -- recovers the exact
    historical input with no freshness/staleness question to ask.
    Returns (artifact_dict, artifact_path). Raises ReparseError, never
    silently substituting a newer/effective/same-stage-elsewhere
    execution, if any step of this exact lookup fails."""
    consumed = execution.get("consumed") or {}
    dep_identity = consumed.get(PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION)
    if dep_identity is None:
        raise ReparseError(
            f"Archived {CHALLENGER!r} execution {execution.get('execution_id')!r} "
            f"has no recorded consumed dependency for "
            f"{PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION!r} -- cannot "
            f"recover its exact historical input."
        )
    dep_run = dep_identity.get("run") if isinstance(dep_identity, dict) else None
    dep_execution_id = dep_identity.get("execution_id") if isinstance(dep_identity, dict) else None
    if not dep_run or not dep_execution_id:
        raise ReparseError(
            f"Archived {CHALLENGER!r} execution {execution.get('execution_id')!r}'s "
            f"recorded consumed dependency for "
            f"{PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION!r} is malformed "
            f"(expected {{'run': ..., 'execution_id': ...}}, got {dep_identity!r})."
        )

    try:
        dep_manifest = lineage.load_manifest(dep_run)
    except lineage.LineageError as exc:
        raise ReparseError(
            f"Could not load the manifest for recorded dependency run "
            f"{dep_run!r}: {exc}"
        ) from exc

    dep_execution = next(
        (e for e in dep_manifest.get("executions", []) if e.get("execution_id") == dep_execution_id),
        None,
    )
    if dep_execution is None:
        raise ReparseError(
            f"Recorded dependency execution_id {dep_execution_id!r} was not "
            f"found in {dep_run!r}'s manifest -- refusing to substitute a "
            f"different execution."
        )
    if not dep_execution.get("artifact_path"):
        raise ReparseError(
            f"Recorded dependency execution {dep_execution_id!r} in "
            f"{dep_run!r} has no artifact_path."
        )

    artifact_path = Path(dep_execution["artifact_path"])
    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReparseError(f"Could not read upstream artifact {artifact_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReparseError(f"Upstream artifact {artifact_path} is not valid JSON: {exc}") from exc

    for required_key in ("vulnerability_text", "patch"):
        if not artifact.get(required_key):
            raise ReparseError(
                f"Upstream artifact {artifact_path} is missing required key {required_key!r}."
            )
    return artifact, str(artifact_path)


def replay_challenger_reparse(source_run: "Path | str", output_dir: "Path | str") -> dict:
    """Zero-LLM: reparse an archived `challenger` execution's own raw
    response through the CURRENT production parser/derivation. Writes
    challenger_reparse.json to `output_dir` and returns that same dict."""
    chain = lineage.build_chain(source_run)

    response_path, response_text, execution = _find_archived_challenger_response(chain)
    upstream_artifact, upstream_artifact_path = _resolve_upstream_evidence(execution)

    vulnerability_text = upstream_artifact["vulnerability_text"]
    patch = upstream_artifact["patch"]
    challenger_context = upstream_artifact.get("challenger_context") or ""
    # Exactly the replay engine's Challenger inputs (replay_engine.
    # _run_replay_challenger): an artifact predating a field fails closed.
    provenance_parts = upstream_artifact.get("challenger_provenance_parts") or ()

    result = reparse_challenger_response(
        response_text,
        code_context=challenger_context,
        patch=patch,
        vulnerability_text=vulnerability_text,
        provenance_context=_challenger_provenance_context(provenance_parts, challenger_context),
        post_patch_definitions=upstream_artifact.get("challenger_post_patch_definitions") or [],
    )

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "tool": "replay_challenger_reparse",
        "llm_calls_made": 0,
        "source_run": str(Path(source_run)),
        "source_response_path": str(response_path),
        "source_response_execution_id": execution.get("execution_id"),
        "upstream_artifact_path": upstream_artifact_path,
        "schema_version": result.get("schema_version"),
        "result": to_jsonable(result),
    }
    artifact_path = output_dir / "challenger_reparse.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    return artifact


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="replay_challenger_reparse.py",
        description=(
            "Zero-LLM deterministic reparse of an archived `challenger` "
            "stage execution's own raw response through the CURRENT "
            "production patch_challenger.py parser/derivation. Makes no "
            "LLM call and runs no other pipeline stage."
        ),
    )
    parser.add_argument(
        "--source-run",
        required=True,
        dest="source_run",
        help=(
            "Path to a run_traced.py output directory (or a prior "
            "replay's --output directory) containing an archived "
            "`challenger` execution -- either the run root or its "
            "trace/ subdirectory directly. Never modified by this tool."
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output directory for challenger_reparse.json.",
    )
    return parser


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        artifact = replay_challenger_reparse(args.source_run, args.output)
    except (lineage.LineageError, ReparseError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(json.dumps({
        "source_run": artifact["source_run"],
        "source_response_path": artifact["source_response_path"],
        "schema_version": artifact["schema_version"],
        "llm_calls_made": artifact["llm_calls_made"],
        "output_artifact": str(Path(args.output) / "challenger_reparse.json"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
