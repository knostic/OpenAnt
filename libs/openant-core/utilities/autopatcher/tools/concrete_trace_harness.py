#!/usr/bin/env python3
"""
concrete_trace_harness.py -- standalone CLI for the EXPERIMENTAL Concrete
Trace mechanism (utilities/autopatcher/concrete_trace.py).

Lives at utilities/autopatcher/tools/ -- a normal, tracked, importable
location next to the other Auto Patcher debug/experimental tools
(run_traced.py, run_stage.py, replay_challenger_reparse.py,
simple_concern_harness.py, concern_tree_harness.py).

What it does, precisely:
  1. Resolves an archived `challenger` execution's own raw response and
     its exact historical upstream artifact (`vulnerability_text`,
     `patch`, `challenger_context`) from `--source-run`'s lineage --
     reusing, UNMODIFIED, `replay_challenger_reparse._find_archived_
     challenger_response`/`_resolve_upstream_evidence` (the same exact-
     historical-identity resolution already built and approved for the
     zero-LLM reparse tool). Never calls `challenge_patch()`, never re-
     renders a prompt for the full v2 schema, never re-runs any earlier
     pipeline stage.
  2. Extracts ONLY `{concern_number, concern_role, description}` per
     concern from that raw response, reusing, UNMODIFIED, `concern_tree_
     harness.extract_archived_concerns` -- the SAME minimal, fail-closed,
     full-v2-parser-free extraction already built and tested for the
     Concern Tree experiment. This is deliberately NOT `challenge_patch`
     or `_parse_concern_block_v2`: it never derives reachability, never
     runs the override-applicability gate, and is therefore immune to a
     concern that would otherwise fail full v2 parsing.
  3. Isolates each concern to `{concern_role, description}` via this
     module's own `_isolate_concern_input` (asserts no forbidden field
     leaks in -- see concrete_trace.py's own "INPUT ISOLATION"
     docstring), then calls `concrete_trace.resolve_concrete_trace` --
     exactly ONE `llm.complete()` call per concern, no more.
  4. Writes one JSON artifact per run containing, per concern: role,
     description, the validated Concrete Trace result, the raw model
     response, the LLM call count, and enough source-run/execution
     provenance to reproduce the exact run (source_run,
     source_response_path, source_response_execution_id,
     upstream_artifact_path).

This is experimental/debug tooling only. It must never be imported by
pipeline.py, patch_challenger.py, or any other production code path, and
it never constructs or reads anything from a `challenge_patch()` result.

Usage:
    python3 utilities/autopatcher/tools/concrete_trace_harness.py \\
        --source-run /tmp/some-trace \\
        --output /tmp/some-concrete-trace-run

    # Restrict to one specific archived concern (1-indexed, as printed in
    # the archived response):
    python3 utilities/autopatcher/tools/concrete_trace_harness.py \\
        --source-run /tmp/some-trace \\
        --output /tmp/some-concrete-trace-run \\
        --concern-number 2
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# utilities/autopatcher/tools/concrete_trace_harness.py -> tools ->
# autopatcher -> utilities -> <openant-core root>
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.autopatcher import lineage  # noqa: E402
from utilities.autopatcher.concrete_trace import (  # noqa: E402
    _ISOLATION_BOUNDARY_FIELDS,
    resolve_concrete_trace,
)
from utilities.autopatcher.tools.concern_tree_harness import extract_archived_concerns  # noqa: E402
from utilities.autopatcher.tools.replay_challenger_reparse import (  # noqa: E402
    ReparseError,
    _find_archived_challenger_response,
    _resolve_upstream_evidence,
)


class ConcreteTraceHarnessError(RuntimeError):
    """Raised for any input-resolution failure -- always before any LLM
    call, mirroring replay_challenger_reparse.ReparseError's own
    contract of failing clearly rather than silently producing partial
    output."""


def _isolate_concern_input(concern: dict) -> dict:
    """The ONE function that constructs what Concrete Trace is allowed
    to see from an archived, minimally-extracted concern dict. Returns
    ONLY `{"concern_role", "description"}`, built exclusively from
    `concern.get("concern_role")`/`concern.get("description")` -- mirrors
    `concern_tree_harness.strip_to_experimental_input` exactly. Every
    forbidden field name is asserted absent from the result, not merely
    omitted by convention -- a future edit that starts forwarding one of
    them fails loudly here, not silently in a live run."""
    isolated = {
        "concern_role": concern.get("concern_role"),
        "description": concern.get("description", ""),
    }
    leaked = _ISOLATION_BOUNDARY_FIELDS & set(isolated.keys())
    assert not leaked, f"forbidden fields leaked into Concrete Trace input: {leaked}"
    return isolated


def run_concrete_trace_harness(
    source_run: "Path | str", output_dir: "Path | str", llm, concern_number: "int | None" = None,
) -> dict:
    """Resolve archived evidence, run Concrete Trace once per selected
    concern (all extracted concerns, or exactly one when
    `concern_number` is given), and write one JSON artifact. Returns
    that same artifact dict. Raises `lineage.LineageError` or
    `ConcreteTraceHarnessError` before any LLM call on any resolution
    failure -- never a partial artifact on disk."""
    chain = lineage.build_chain(source_run)

    response_path, response_text, execution = _find_archived_challenger_response(chain)
    try:
        upstream_artifact, upstream_artifact_path = _resolve_upstream_evidence(execution)
    except ReparseError as exc:
        raise ConcreteTraceHarnessError(str(exc)) from exc

    concerns, skipped = extract_archived_concerns(response_text)
    if concern_number is not None:
        concerns = [c for c in concerns if c.get("concern_number") == concern_number]
        if not concerns:
            raise ConcreteTraceHarnessError(
                f"No extractable concern numbered {concern_number!r} in the archived response "
                f"(extracted concern numbers: {[c.get('concern_number') for c in concerns]}; "
                f"skipped: {skipped})."
            )
    elif not concerns:
        raise ConcreteTraceHarnessError(
            f"No extractable concerns in the archived response (skipped: {skipped})."
        )

    code_context = upstream_artifact.get("challenger_context") or upstream_artifact.get("code_context") or ""
    patch = upstream_artifact["patch"]

    concern_results = []
    llm_calls_made = 0
    for concern in concerns:
        isolated = _isolate_concern_input(concern)
        result = resolve_concrete_trace(
            concern_role=isolated["concern_role"],
            description=isolated["description"],
            code_context=code_context,
            patch=patch,
            llm=llm,
        )
        llm_calls_made += result["llm_calls_made"]
        concern_results.append({
            "concern_number": concern.get("concern_number"),
            "concern_role": isolated["concern_role"],
            "description": isolated["description"],
            "concrete_trace": {
                "example_scenario": result["example_scenario"],
                "trace_steps": result["trace_steps"],
                "outcome": result["outcome"],
                "blocking_step_index": result["blocking_step_index"],
                "invalid_reason": result["invalid_reason"],
            },
            "raw_response": result["raw_response"],
        })

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "tool": "concrete_trace_harness",
        "policy_authority": False,
        "llm_calls_made": llm_calls_made,
        "source_run": str(Path(source_run)),
        "source_response_path": str(response_path),
        "source_response_execution_id": execution.get("execution_id"),
        "upstream_artifact_path": upstream_artifact_path,
        "skipped_concerns": skipped,
        "concerns": concern_results,
    }
    artifact_path = output_dir / "concrete_trace.json"
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    return artifact


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="concrete_trace_harness.py",
        description=(
            "Run the EXPERIMENTAL, zero-policy-authority Concrete Trace "
            "mechanism against an archived challenger execution's own "
            "evidence -- exactly one LLM call per concern, no other "
            "pipeline stage, never challenge_patch()."
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
        help="Output directory for concrete_trace.json.",
    )
    parser.add_argument(
        "--concern-number",
        type=int,
        default=None,
        help="Restrict to one archived concern by its printed number (1-indexed). Default: all extracted concerns.",
    )
    return parser


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    from utilities.autopatcher.llm_client import LLMClient

    llm = LLMClient(api_key=os.environ.get("OPENAI_API_KEY", ""))

    try:
        artifact = run_concrete_trace_harness(args.source_run, args.output, llm, args.concern_number)
    except (lineage.LineageError, ConcreteTraceHarnessError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(json.dumps({
        "source_run": artifact["source_run"],
        "source_response_path": artifact["source_response_path"],
        "llm_calls_made": artifact["llm_calls_made"],
        "concern_count": len(artifact["concerns"]),
        "output_artifact": str(Path(args.output) / "concrete_trace.json"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
