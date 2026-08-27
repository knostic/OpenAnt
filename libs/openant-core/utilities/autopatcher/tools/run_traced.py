#!/usr/bin/env python3
"""
run_traced.py -- local tracing wrapper around OpenAnt's Auto Patcher.

This is a v2 rewrite: an earlier /tmp copy of this script was lost (never
committed) and is NOT reconstructed from memory here. This version is a
thin tracing ADAPTER over the existing, unmodified production API -- it
does not reimplement, redesign, or duplicate any Auto Patcher logic.

Lives at utilities/autopatcher/tools/ -- a normal, tracked, importable
location next to the Auto Patcher subsystem it traces -- rather than a
generic gitignored scratch directory. It was relocated there (from a
former scripts/local/run_traced.py) once this tracing/replay capability
became a real, versioned Auto Patcher development capability rather than
a personal debugging helper; see utilities/autopatcher/tools/__init__.py
and TRACING_AND_DEBUGGING.md in this same directory.

What it does, precisely:
  1. Parses the same --context-budget-policy / --max-context-budget-windows
     flags as `openant patch` (openant/cli.py), reusing that CLI's own
     validator (_positive_int) and the production
     utilities.autopatcher.context_budget constants -- never a
     reimplemented choice list or bound check.
  2. Builds ONE utilities.autopatcher.context_budget.ContextBudgetController
     -- the real production class -- with those values, exactly the way
     openant/cli.py's cmd_patch already does.
  3. Calls core.patch.run_patch()/run_patch_cve() *in-process* (the same
     functions `openant patch` calls) with that controller. Calling
     in-process rather than shelling out to `openant patch` is what lets
     step 4 below see every LLM call the pipeline makes.
  4. Wraps utilities.autopatcher.llm_client.call_llm -- the single choke
     point every pipeline stage's LLMClient.complete() goes through --
     purely to observe and record each call's prompt and raw response to
     disk, in call order, via the shared
     utilities.autopatcher.llm_call_tracing.LLMCallCapture mechanism (also
     used by utilities.autopatcher.stage_replay for single-stage replay).
     The wrapped function still calls the real, unmodified call_llm() for
     the actual request; this changes nothing about provider resolution,
     mock fallback, retries, or content.
  5. Sets AUTOPATCHER_DEBUG=1 for the duration of the run (restoring
     whatever was there before, after) so the pipeline's own existing
     debug-artifact writers -- edit_readiness_*.json,
     relocation_telemetry_*.json, post_patch_recovery_*.json under
     ./reports/debug/, each already embedding a `budget_trace` block via
     ContextBudgetController.to_trace_dict() -- keep firing exactly as
     they do for any other AUTOPATCHER_DEBUG=1 run. This script never
     reads, reformats, or re-derives that budget trace itself; it only
     records which files appeared during this run, as pointers, in its
     own manifest.
  6. Writes structured, versioned replay-provenance fields into
     run_manifest.json (schema_version, target_repository.repo_commit as
     a FULL git SHA, openant.patcher_commit, llm.provider/llm.model) --
     see _replay_provenance() below -- additive to every existing flat
     field, on BOTH the success and failure manifest shapes. This is what
     makes a trace produced by this script "replay-capable by design":
     everything run_stage.py's single-stage replay tool (same directory)
     needs for its target-repository identity check and its OpenAnt/LLM
     provenance record is real, structured JSON here, never only prose
     inside the Trust Report. See utilities/autopatcher/stage_replay.py
     and run_stage.py.

What it deliberately does NOT do:
  - It does not implement policy=ask/always/never decisions itself --
    that's entirely inside ContextBudgetController.request_extension().
  - It does not do TTY handling beyond the one-line default-policy
    expression openant/cli.py's cmd_patch already uses (isatty() check),
    reproduced verbatim as argument-defaulting glue, not a competing
    implementation.
  - It does not enforce the hard window cap -- ContextBudgetController
    does that.
  - It does not generate a second/competing budget-trace format -- it
    only lists the filenames the production pipeline already wrote.
  - It never reads a stdin prompt directly itself.
  - It does not render/compose prerequisite-failure wording itself
    (e.g. for --compare-existing-tests + Docker unavailable) -- that
    message is core.patch.TestComparisonEnvironmentError's own str(),
    printed verbatim with a one-line header; main() only decides to
    catch that ONE specific, expected exception type without re-raising
    it (exit code 2, no traceback), while every other exception keeps
    this script's original developer-oriented re-raise/traceback
    behavior.

Usage:
    # Finding-mode (same shape as `openant patch pipeline_output.json --finding-id ...`)
    python3 utilities/autopatcher/tools/run_traced.py pipeline_output.json \\
        --finding-id VULN-001 --repo-root /path/to/repo --output /tmp/traced-run

    # CVE-mode, fully traced, with the budget-window policy forwarded:
    python3 utilities/autopatcher/tools/run_traced.py --cve CVE-2021-1234 \\
        --repo-root /path/to/urllib3 --output /tmp/traced-run \\
        --context-budget-policy always --max-context-budget-windows 10
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# utilities/autopatcher/tools/run_traced.py -> tools -> autopatcher ->
# utilities -> <openant-core root>
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Reused, not reimplemented: the exact validator and constants
# openant/cli.py's `patch` subcommand already uses.
from openant.cli import _positive_int  # noqa: E402
from utilities.autopatcher.context_budget import (  # noqa: E402
    CONTEXT_BUDGET_POLICIES,
    ContextBudgetController,
    DEFAULT_MAX_CONTEXT_BUDGET_WINDOWS,
)
from utilities.autopatcher.llm_call_tracing import LLMCallCapture  # noqa: E402

# Basenames the production pipeline writes under ./reports/debug/ when
# AUTOPATCHER_DEBUG is set (see utilities/autopatcher/pipeline.py and
# utilities/autopatcher/repo_locator.py's _write_debug_artifact). Listed
# here only so this script can point at whichever of them appeared during
# its own run -- never to regenerate, parse, or reshape their contents.
_DEBUG_ARTIFACT_PREFIXES = (
    "edit_readiness_",
    "relocation_telemetry_",
    "post_patch_recovery_",
    "context_selection_",
)

# run_manifest.json's structured-provenance schema version (see
# _replay_provenance below). A trace with no "schema_version" key at all
# is a legacy trace, produced before this feature existed --
# utilities/autopatcher/stage_replay.py's loader falls back to the bounded
# Trust Report Run Metadata compatibility path for those. Bump this only
# when the SHAPE of the fields below changes in a way that would break an
# existing consumer of this exact version -- purely additive new top-level
# manifest keys elsewhere never require a bump.
#
# Bumped 1 -> 2 -> 3: 2 introduced the unified full-run/replay manifest;
# 3 replaced its "stages": {name: entry} singleton map with an
# execution-based "executions": [...] list (utilities.autopatcher.lineage.
# SCHEMA_VERSION -- kept as a literal here rather than importing that
# constant directly, to avoid coupling this module's own versioning story
# to lineage.py's internals; a dedicated test asserts the two never drift
# apart). See lineage.py's module docstring for the full schema_version
# story (legacy v1 / v2-compat / canonical v3 / unsupported).
_REPLAY_SCHEMA_VERSION = 3


def _replay_provenance(repo_root: "str | None") -> dict:
    """Structured, versioned replay-provenance fields -- merged into BOTH
    the success and the failure manifest shapes, additive to every
    existing flat field (never replacing one). Computed once, after the
    run, so `llm.provider`/`llm.model` reflect whatever this run actually
    resolved (None/None if resolution never happened at all, e.g. an
    early failure before any LLM work started).

    This is the whole mechanism that makes a NEW trace "replay-capable by
    design": everything a single-stage replay's provenance/identity gate
    needs (utilities.autopatcher.stage_replay) is real, structured JSON
    here, never only prose inside the Trust Report's Run Metadata table.
    checkpoints.jsonl remains exactly what it always was -- a per-LLM-call
    index/history, not a source of stage state -- this function does not
    touch it.

    Additionally includes the unified full-run/replay manifest fields
    (utilities.autopatcher.lineage): "kind"="full_run", "parent"=null, and
    an "executions" list -- HONESTLY EMPTY in this batch. Production
    pipeline.run() is NOT yet instrumented to record real StageExecution
    instances (see the architecture report's Batch B1 scope and
    replay_engine.py's module docstring), so this function does not, and
    must not, invent one execution per canonical stage merely because the
    stage catalog exists -- that would fabricate a clean execution history
    production never actually observed. This run's real LLM activity
    remains fully captured exactly as before, in checkpoints.jsonl and the
    flat trace/*.prompt.txt / *.response.txt files LLMCallTracer already
    writes -- it is simply not yet attributed to canonical-stage execution
    records. A replay engine resolving a dependency against a full run
    written by THIS function will correctly see it as UNRESOLVED (no
    matching execution anywhere) for every canonical stage -- never a
    fabricated one.

    BATCH B REQUIREMENT (not implemented here): once a LATER batch
    instruments pipeline.run() itself to record real StageExecution
    instances for the stages it actually executes (starting with
    patch_repair_and_calibration and impact_and_behavior_analysis --
    test_analysis_and_plan's FINAL contract depends on both), THIS
    function's "executions" list should start reflecting them, so a full
    run written after that migration lets a later test_analysis_and_plan
    replay resolve those dependencies. Recording an execution for a stage
    is independent of -- and can land before -- that stage gaining its own
    replay handler; see replay_engine.py's module docstring.
    """
    from utilities.autopatcher import llm_client as _llm
    from utilities.autopatcher import run_metadata as _rm

    openant_root = _rm.find_openant_root()
    patcher_commit = _rm.collect_full_commit_sha(openant_root) if openant_root else None
    repo_commit = _rm.collect_full_commit_sha(Path(repo_root)) if repo_root else None

    # _cached_provider/_cached_model are the SAME session-lifetime cache
    # core.patch.py's own post-hoc provider/model lookup reads (see
    # core/patch.py's RunMetadata construction) -- reused here, not
    # re-resolved, so this can never disagree with what the run actually
    # used. Mirrors core/patch.py's own "mock never populates
    # _cached_model" special case: _resolve_active_provider() sets
    # _cached_provider = "mock" directly without ever writing
    # _cached_model["mock"], since _resolve_model() short-circuits to the
    # literal "mock" for that provider instead of consulting the cache.
    provider = _llm._cached_provider
    if provider == "mock":
        model = "mock"
    else:
        model = _llm._cached_model.get(provider) if provider else None

    return {
        "schema_version": _REPLAY_SCHEMA_VERSION,
        "kind": "full_run",
        "parent": None,
        "target_repository": {"repo_root": repo_root, "repo_commit": repo_commit},
        "openant": {"patcher_commit": patcher_commit},
        "llm": {"provider": provider, "model": model},
        # HONEST, not fabricated -- see the docstring above. A literal
        # empty list, not a call into lineage.py, so it's obvious at a
        # glance this function makes no claim about stage execution
        # history yet.
        "executions": [],
    }


class LLMCallTracer:
    """Records every LLMClient.complete() call's prompt and raw response,
    in call order, to `trace_dir`.

    Thin wrapper around the shared
    utilities.autopatcher.llm_call_tracing.LLMCallCapture mechanism (also
    used by utilities.autopatcher.stage_replay for single-stage replay
    capture): this class owns exactly the two things specific to a FULL
    traced run -- writing each call's prompt/response to disk
    IMMEDIATELY as it happens (via LLMCallCapture's `on_call` hook), so a
    mid-run crash still leaves every already-completed call's trace files
    behind, and checkpoints.jsonl/run_manifest.json's exact shape
    (write_manifest below). LLMCallCapture itself owns only the
    monkeypatch-call_llm mechanics, shared verbatim with stage_replay.py.

    Interception point: LLMClient.complete() (llm_client.py) always ends
    in `return call_llm(combined, model=self.model, stage=stage)`, where
    `call_llm` is looked up from the module's own globals at call time.
    Reassigning `utilities.autopatcher.llm_client.call_llm` before the
    pipeline runs therefore sees every stage that goes through
    LLMClient.complete() -- patch_generation, patch_review, challenger,
    confidence_scorer, guided_context_request, finding_calibration, and
    any future stage added the same way -- with no per-stage wiring
    needed here and no change to call_llm's own behavior.
    """

    def __init__(self, trace_dir: Path):
        self.trace_dir = trace_dir
        self._capture = LLMCallCapture(on_call=self._write_call)

    def _write_call(self, record: dict) -> None:
        """LLMCallCapture's on_call hook: write this one call's prompt/
        response to disk right away, and add the file-pointer/char-count
        fields checkpoints.jsonl needs -- mutates `record` in place (the
        same dict object LLMCallCapture also keeps in `self.calls`)."""
        seq = record["seq"]
        stage = record["stage"]
        prompt_path = self.trace_dir / f"{seq:03d}_{stage}.prompt.txt"
        response_path = self.trace_dir / f"{seq:03d}_{stage}.response.txt"
        prompt_path.write_text(record["prompt"], encoding="utf-8")
        response_path.write_text(record["response"] or "", encoding="utf-8")
        record["prompt_chars"] = len(record["prompt"])
        record["response_chars"] = len(record["response"] or "")
        record["prompt_file"] = prompt_path.name
        record["response_file"] = response_path.name

    def __enter__(self) -> "LLMCallTracer":
        self._capture.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return self._capture.__exit__(exc_type, exc, tb)

    @property
    def calls(self) -> "list[dict]":
        return self._capture.calls

    def write_manifest(self, extra: dict, debug_artifacts: list[str]) -> Path:
        """Writes checkpoints.jsonl (one line per LLM call, in call order --
        the stage/checkpoint ordering trace) and run_manifest.json (a
        pointer-only summary: this run's args, the two production
        artifacts core.patch wrote, and which AUTOPATCHER_DEBUG files
        appeared -- no budget-trace content duplicated here).

        checkpoints.jsonl's schema is unchanged by the LLMCallCapture
        refactor: exactly seq/stage/started_at/finished_at/prompt_chars/
        response_chars/prompt_file/response_file per line -- the full
        prompt/response text LLMCallCapture's records also carry (needed
        by stage_replay.py's use of the same class) is deliberately NOT
        included here, unchanged from before this class existed.
        """
        checkpoints_path = self.trace_dir / "checkpoints.jsonl"
        with open(checkpoints_path, "w", encoding="utf-8") as f:
            for call in self.calls:
                f.write(json.dumps({
                    "seq": call["seq"],
                    "stage": call["stage"],
                    "started_at": call["started_at"],
                    "finished_at": call["finished_at"],
                    "prompt_chars": call["prompt_chars"],
                    "response_chars": call["response_chars"],
                    "prompt_file": call["prompt_file"],
                    "response_file": call["response_file"],
                }) + "\n")

        manifest_path = self.trace_dir / "run_manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    **extra,
                    "llm_call_count": len(self.calls),
                    "checkpoints_file": checkpoints_path.name,
                    "autopatcher_debug_artifacts": debug_artifacts,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return manifest_path


def build_parser() -> argparse.ArgumentParser:
    """Same argument surface as openant/cli.py's `patch` subcommand, plus
    one script-local addition (--trace-dir). --context-budget-policy and
    --max-context-budget-windows use the identical choices/validator/
    defaults as the production CLI -- see the imports above."""
    parser = argparse.ArgumentParser(
        prog="run_traced.py",
        description=(
            "Local tracing wrapper around OpenAnt's Auto Patcher "
            "(core.patch.run_patch/run_patch_cve). Runs the production "
            "API in-process with full LLM prompt/raw-response tracing, "
            "plus the existing AUTOPATCHER_DEBUG artifacts."
        ),
    )
    parser.add_argument(
        "pipeline_output", nargs="?", default=None,
        help="Path to pipeline_output.json (required unless --cve is given)",
    )
    parser.add_argument(
        "--finding-id", help="ID of the finding to remediate (mutually exclusive with --cve)"
    )
    parser.add_argument(
        "--cve", help="CVE identifier to fetch from NVD and remediate (mutually exclusive with --finding-id)"
    )
    parser.add_argument(
        "--repo-root", help="Path to the target repository root (required when using --cve)"
    )
    parser.add_argument("--output", "-o", help="Output directory (default: temp dir)")
    parser.add_argument(
        "--trace-dir",
        help="Directory for LLM prompt/raw-response trace files (default: <output>/trace)",
    )

    # --- forwarded verbatim from openant/cli.py's `patch` subcommand ---
    parser.add_argument(
        "--context-budget-policy",
        choices=list(CONTEXT_BUDGET_POLICIES),
        default=None,
        help=(
            "How to handle a repository source/context acquisition budget "
            "exhausted purely by character capacity (never a safety/"
            "verification failure): 'ask' prompts for another fixed-size "
            "context window (default No; degrades to 'never' when stdin "
            "isn't a TTY), 'always' auto-approves up to "
            "--max-context-budget-windows, 'never' preserves the existing "
            "fail-closed behavior. Default: 'ask' for an interactive run, "
            "'never' otherwise. Identical flag/semantics to "
            "`openant patch --context-budget-policy`."
        ),
    )
    parser.add_argument(
        "--max-context-budget-windows",
        type=_positive_int,
        default=DEFAULT_MAX_CONTEXT_BUDGET_WINDOWS,
        help=(
            "Hard cap on total context-budget windows (initial + approved) "
            "per acquisition stage, even under --context-budget-policy "
            f"always. Must be a positive integer (default: "
            f"{DEFAULT_MAX_CONTEXT_BUDGET_WINDOWS}). Identical flag/"
            "validation to `openant patch --max-context-budget-windows`."
        ),
    )
    parser.add_argument(
        "--compare-existing-tests",
        action="store_true",
        help=(
            "Opt-in, off by default: run Existing Test Comparison "
            "(Docker required). Identical flag/semantics to "
            "`openant patch --compare-existing-tests`."
        ),
    )
    return parser


def resolve_budget_controller(args: argparse.Namespace) -> ContextBudgetController:
    """Argument-defaulting glue only -- mirrors openant/cli.py's cmd_patch
    line for line (policy 'ask' for a TTY run, 'never' otherwise, when
    --context-budget-policy is omitted), then constructs the real
    production ContextBudgetController. No policy decision, TTY-vs-batch
    branching for *approving* an extension, or hard-cap logic lives here
    -- all of that is inside ContextBudgetController itself.
    """
    policy = args.context_budget_policy or ("ask" if sys.stdin.isatty() else "never")
    max_windows = args.max_context_budget_windows or DEFAULT_MAX_CONTEXT_BUDGET_WINDOWS
    return ContextBudgetController(policy=policy, max_windows=max_windows)


def _new_debug_artifacts(debug_dir: Path, since: float) -> list[str]:
    """Filenames under debug_dir matching the production writers' known
    prefixes with an mtime >= `since` -- i.e. the ones this run produced.
    Best-effort, pointer-only: never opens or reformats these files."""
    if not debug_dir.is_dir():
        return []
    found = []
    for entry in debug_dir.iterdir():
        if entry.name.startswith(_DEBUG_ARTIFACT_PREFIXES) and entry.stat().st_mtime >= since:
            found.append(str(entry))
    return sorted(found)


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    finding_id = args.finding_id
    cve = args.cve
    if bool(finding_id) == bool(cve):
        print("error: exactly one of --finding-id or --cve is required", file=sys.stderr)
        return 2
    if cve and not args.repo_root:
        print("error: --cve requires --repo-root", file=sys.stderr)
        return 2
    if finding_id and not args.pipeline_output:
        print("error: pipeline_output is required when using --finding-id", file=sys.stderr)
        return 2

    output_dir = args.output or tempfile.mkdtemp(prefix="openant_patch_traced_")
    os.makedirs(output_dir, exist_ok=True)
    trace_dir = Path(args.trace_dir) if args.trace_dir else Path(output_dir) / "trace"
    trace_dir.mkdir(parents=True, exist_ok=True)

    budget_controller = resolve_budget_controller(args)
    debug_dir = Path.cwd() / "reports" / "debug"
    run_started = datetime.now(timezone.utc).timestamp()

    # Traced run => the existing debug artifacts must fire. Saved/restored
    # rather than overwritten permanently -- no side effect on the calling
    # shell's environment once this process exits.
    _prev_debug = os.environ.get("AUTOPATCHER_DEBUG")
    os.environ["AUTOPATCHER_DEBUG"] = "1"

    from core.patch import TestComparisonEnvironmentError, run_patch, run_patch_cve

    def _failure_extra(exc: Exception) -> dict:
        return {
            "status": "failed",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "context_budget_policy": budget_controller.policy,
            "max_context_budget_windows": budget_controller.max_windows,
            "compare_existing_tests": args.compare_existing_tests,
            **_replay_provenance(args.repo_root),
        }

    try:
        with LLMCallTracer(trace_dir) as tracer:
            try:
                if cve:
                    result = run_patch_cve(
                        cve_id=cve,
                        repo_root=args.repo_root,
                        output_dir=output_dir,
                        budget_controller=budget_controller,
                        compare_existing_tests=args.compare_existing_tests,
                    )
                else:
                    result = run_patch(
                        pipeline_output_path=args.pipeline_output,
                        finding_id=finding_id,
                        output_dir=output_dir,
                        repo_root=args.repo_root,
                        budget_controller=budget_controller,
                        compare_existing_tests=args.compare_existing_tests,
                    )
            except TestComparisonEnvironmentError as exc:
                # Expected, user-correctable prerequisite failure -- NOT
                # an unexpected crash. This is the ONE exception type this
                # wrapper handles specially: record the same failure-
                # manifest shape as any other failure (so the trace still
                # proves llm_call_count == 0 and names what happened),
                # print a short, actionable message (no traceback), and
                # return a non-zero exit code WITHOUT re-raising. Every
                # other exception keeps the existing, unchanged,
                # developer-oriented re-raise behavior below -- this
                # wrapper must never swallow a real bug.
                tracer.write_manifest(
                    extra=_failure_extra(exc),
                    debug_artifacts=_new_debug_artifacts(debug_dir, run_started),
                )
                print(f"Existing Test Comparison cannot start.\n\n{exc}", file=sys.stderr)
                return 2
            except Exception as exc:
                # Preserve a useful partial manifest even though this run
                # failed: every LLM checkpoint already captured by
                # `tracer` up to the failure (write_manifest always
                # writes checkpoints.jsonl from `tracer.calls`, unchanged)
                # plus a run_manifest.json naming exactly what failed --
                # never swallowed, never turned into a success. Re-raised
                # below so the caller sees the identical failure it always
                # has (this wrapper still has no top-level try/except
                # around main() itself for anything but the expected
                # prerequisite failure handled above).
                tracer.write_manifest(
                    extra=_failure_extra(exc),
                    debug_artifacts=_new_debug_artifacts(debug_dir, run_started),
                )
                raise

            manifest_path = tracer.write_manifest(
                extra={
                    "status": "success",
                    "input_type": result.input_type,
                    "input_id": result.input_id,
                    "repo_root": args.repo_root,
                    "output_dir": output_dir,
                    "context_budget_policy": budget_controller.policy,
                    "max_context_budget_windows": budget_controller.max_windows,
                    "compare_existing_tests": args.compare_existing_tests,
                    "vulnerability_path": result.vulnerability_path,
                    "trust_report_path": result.trust_report_path,
                    **_replay_provenance(args.repo_root),
                },
                debug_artifacts=_new_debug_artifacts(debug_dir, run_started),
            )
    finally:
        if _prev_debug is None:
            os.environ.pop("AUTOPATCHER_DEBUG", None)
        else:
            os.environ["AUTOPATCHER_DEBUG"] = _prev_debug

    print(json.dumps({
        "vulnerability_path": result.vulnerability_path,
        "trust_report_path": result.trust_report_path,
        "trace_dir": str(trace_dir),
        "trace_manifest": str(manifest_path),
        "llm_calls": len(tracer.calls),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
