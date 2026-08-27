#!/usr/bin/env python3
"""
run_stage.py -- Auto Patcher single-stage debug replay tool.

Lives at utilities/autopatcher/tools/ -- a normal, tracked, importable
location next to the Auto Patcher subsystem it debugs; see
utilities/autopatcher/tools/__init__.py and TRACING_AND_DEBUGGING.md in
this same directory.

Reruns exactly ONE canonical pipeline stage's CURRENT production
implementation against upstream state resolved from a prior run's lineage
-- either a full run_traced.py source trace, or a PRIOR REPLAY (this
script's own --output from an earlier invocation), so replays chain:

    run_stage.py --source-run /tmp/full-run --stage test_analysis_and_plan \\
        --output /tmp/replay-test-plan
    run_stage.py --source-run /tmp/replay-test-plan --stage existing_test_comparison \\
        --output /tmp/replay-tests   # (once existing_test_comparison is replayable)

The 13 canonical stages are declared in utilities/autopatcher/
stage_registry.py. FOUNDATION BATCH A: every canonical stage is known to
this tool (so an unknown --stage value and a registered-but-not-yet-
replayable --stage value fail with two DIFFERENT, specific messages), but
only ONE stage -- test_analysis_and_plan -- actually has a replay
implementation wired up (a TRANSITIONAL one; see replay_engine.py's module
docstring). Requesting any other --stage fails immediately, before any
file I/O or LLM call, and never falls back to running the full pipeline.

This script does not call utilities.autopatcher.pipeline.run() and does
not import it.

Usage:
    python3.12 utilities/autopatcher/tools/run_stage.py \\
        --source-run /tmp/minimist-trace \\
        --stage test_analysis_and_plan \\
        --output /tmp/minimist-test-plan-debug

    # Debugging against a repo checked out somewhere other than where the
    # source run recorded it (still subject to the same commit-SHA and
    # clean-worktree checks against the recorded commit):
    python3.12 utilities/autopatcher/tools/run_stage.py \\
        --source-run /tmp/minimist-trace \\
        --stage test_analysis_and_plan \\
        --output /tmp/minimist-test-plan-debug \\
        --repo-root /tmp/minimist-eval-copy

--source-trace is accepted as a deprecated alias for --source-run (same
destination) -- a source may now be either a full run OR a prior replay,
so --source-run is the name to use in new commands and documentation.
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

from utilities.autopatcher.replay_engine import (  # noqa: E402
    ReplayEngineError,
    replay_stage,
)
from utilities.autopatcher.stage_registry import CANONICAL_STAGE_ORDER  # noqa: E402
from utilities.autopatcher.stage_replay import StageReplayError  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="run_stage.py",
        description=(
            "Rerun exactly ONE canonical Auto Patcher pipeline stage's "
            "CURRENT production implementation, using upstream state "
            "resolved from --source-run's lineage (a full run, or a prior "
            "replay). Never invokes pipeline.run() or any other stage."
        ),
    )
    parser.add_argument(
        "--source-run",
        "--source-trace",
        dest="source_run",
        required=True,
        help=(
            "Path to a run_traced.py output directory, OR a prior "
            "replay's --output directory -- either the run root or its "
            "trace/ subdirectory directly. Never modified by this tool. "
            "(--source-trace is accepted as a deprecated alias.)"
        ),
    )
    parser.add_argument(
        "--stage",
        required=True,
        help=(
            "Canonical stage to replay. Known stages: "
            f"{', '.join(CANONICAL_STAGE_ORDER)}. Not every known stage is "
            "replayable yet -- see utilities/autopatcher/stage_registry.py."
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        help=(
            "Isolated output directory for this replay's artifacts. Must "
            "not be the same as, nested inside, or contain --source-run."
        ),
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help=(
            "Override the target repository path instead of the one "
            "recorded in the source lineage. Still subject to the same "
            "commit-SHA and clean-worktree checks against the recorded "
            "SHA, for any stage that requires repository access."
        ),
    )
    return parser


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = replay_stage(
            source_run=args.source_run,
            stage_name=args.stage,
            output_dir=args.output,
            repo_root_override=args.repo_root,
        )
    except (ReplayEngineError, StageReplayError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(json.dumps({
        "stage": result.stage,
        "outcome": result.outcome,
        "output_dir": str(result.output_dir),
        "run_manifest": str(result.output_dir / "run_manifest.json"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
