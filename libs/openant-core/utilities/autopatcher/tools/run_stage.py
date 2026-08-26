#!/usr/bin/env python3
"""
run_stage.py -- single-stage Auto Patcher debug replay tool (Phase 1).

Lives at utilities/autopatcher/tools/ -- a normal, tracked, importable
location next to the Auto Patcher subsystem it debugs -- rather than a
generic gitignored scratch directory. It was relocated there (from a
former scripts/local/run_stage.py) alongside run_traced.py (same
directory) once this tracing/replay capability became a real, versioned
Auto Patcher development capability; see
utilities/autopatcher/tools/__init__.py and TRACING_AND_DEBUGGING.md in
this same directory.

Reruns exactly ONE pipeline stage's CURRENT production implementation
against the upstream state recorded by a prior run_traced.py source
trace, without rerunning any earlier or later stage.

This is the developer workflow this tool exists for:

    1. Run a full traced Auto Patcher evaluation (run_traced.py) --
       produces a replay-capable source trace.
    2. Discover a problem in one stage, e.g. test_plan_discovery.
    3. Modify that stage's current code/prompt.
    4. Rerun ONLY that stage against the SAME upstream/source state, via
       this script.
    5. Inspect the new result to see whether the change fixed it.

Phase 1 supports exactly one stage: test_plan_discovery (see
utilities/autopatcher/stage_replay.py's module docstring for why it's the
correct first target, and why remediation_planning/remediation_strategy/
patch_generation/challenger/finding_calibration/patch_review are NOT
supported yet). Requesting any other --stage fails immediately, before any
file I/O or LLM call, with a clear, actionable message -- it never falls
back to running the full pipeline.

This script does not call utilities.autopatcher.pipeline.run() and does
not import it -- see stage_replay.py's module docstring for why that
import boundary is itself part of the "only one stage's LLM call happens"
guarantee, not just a runtime assertion.

Usage:
    python3.12 utilities/autopatcher/tools/run_stage.py \\
        --source-trace /tmp/minimist-trace \\
        --stage test_plan_discovery \\
        --output /tmp/minimist-test-plan-debug

    # Debugging against a repo checked out somewhere other than where the
    # source trace recorded it (still subject to the same commit-SHA and
    # clean-worktree checks against the recorded commit):
    python3.12 utilities/autopatcher/tools/run_stage.py \\
        --source-trace /tmp/minimist-trace \\
        --stage test_plan_discovery \\
        --output /tmp/minimist-test-plan-debug \\
        --repo-root /tmp/minimist-eval-copy
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# utilities/autopatcher/tools/run_stage.py -> tools -> autopatcher ->
# utilities -> <openant-core root>
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.autopatcher.stage_replay import (  # noqa: E402
    SUPPORTED_STAGES,
    StageReplayError,
    replay_test_plan_discovery,
)

# Phase 1: one entry. Extending replay to a second stage means adding one
# more {name: replay_fn} pair here (plus registering it in
# stage_replay.SUPPORTED_STAGES) -- not a new framework. See
# stage_replay.py's module docstring for what a future stage's replay_fn
# needs to look like.
_STAGE_DISPATCH = {
    "test_plan_discovery": replay_test_plan_discovery,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_stage.py",
        description=(
            "Rerun exactly ONE Auto Patcher pipeline stage's CURRENT "
            "production implementation, using the upstream state recorded "
            "by a prior run_traced.py source trace. Never invokes "
            "pipeline.run() or any other stage. Phase 1 supports exactly "
            "one stage: test_plan_discovery."
        ),
    )
    parser.add_argument(
        "--source-trace",
        required=True,
        help=(
            "Path to a run_traced.py output directory -- either the run "
            "root (e.g. /tmp/minimist-trace, run_traced.py's --output) or "
            "its trace/ subdirectory directly. Never modified by this "
            "tool."
        ),
    )
    parser.add_argument(
        "--stage",
        required=True,
        help=f"Stage to replay. Currently supported: {', '.join(sorted(SUPPORTED_STAGES))}.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Isolated output directory for this replay's artifacts. Must "
            "not be the same as, nested inside, or contain --source-trace."
        ),
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help=(
            "Override the target repository path instead of the one "
            "recorded in the source trace. Still subject to the same "
            "commit-SHA and clean-worktree checks against the SHA the "
            "source trace recorded."
        ),
    )
    return parser


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    if args.stage not in SUPPORTED_STAGES:
        print(
            f"Stage {args.stage!r} is not replayable yet. "
            f"Currently supported: {', '.join(sorted(SUPPORTED_STAGES))}.",
            file=sys.stderr,
        )
        return 2

    replay_fn = _STAGE_DISPATCH[args.stage]

    try:
        result = replay_fn(
            source_trace=args.source_trace,
            output_dir=args.output,
            repo_root_override=args.repo_root,
        )
    except StageReplayError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(json.dumps({
        "stage": args.stage,
        "outcome": result.outcome,
        "output_dir": str(result.output_dir),
        "replay_manifest": str(result.output_dir / "replay_manifest.json"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
