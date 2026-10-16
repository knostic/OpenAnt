#!/usr/bin/env python3
"""
simple_concern_harness.py -- standalone harness that runs the experimental
two-pass Simple Concern Resolver against an already-archived Challenger
run's concerns.

Lives at utilities/autopatcher/tools/ next to concern_tree_harness.py and
run_stage.py. Does NOT call `utilities.autopatcher.pipeline.run()` and does
not import `pipeline.py`. Not imported by any production module.

Reuses the archived-run parsing already built for the Concern Tree's own
harness (`parse_challenger_prompt_trace`, `extract_archived_concerns`,
`strip_to_experimental_input`, `_build_investigation_context`) -- these are
genuinely Tree-independent (none of them reference `concern_tree.py`), so
they are imported directly here rather than duplicated. This module never
imports `concern_tree.py` itself, and `simple_concern_resolver.py` does not
import this harness or `concern_tree_harness.py`.

Only ever runs ONE mode: extract each archived concern's Role+Description
(never any v2 resolution field, never `vulnerability_text`, never a Tree
result artifact) and resolve each through `simple_concern_resolver.
resolve_concern`. There is no baseline-reconstruction arm and no
comparison-artifact mode here -- comparison against an already-collected
Tree result is done OFFLINE, by reading the two JSON artifacts side by
side; this harness itself never reads a Tree result file.

UPSTREAM NARRATIVE FILTER (see `_strip_target_discovery_plan`): the
archived `code_context` this harness extracts is not pure repository
evidence -- it also carries Planning's own prior LLM interpretation,
rendered under the "## Target Discovery Plan (exploratory -- not
authoritative for Patch Generation)" heading (see `remediation_planner.
_render_plan`'s own comment, which already documents this section as
non-authoritative). `run_simple_only` strips exactly that section, by
structural boundary only, before any concern is resolved -- this is the
one and only change this experiment makes; Pass 1, Pass 2, their prompts,
Pass 1->Pass 2 visibility, provenance, and evidence acquisition are all
unchanged.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from utilities.autopatcher.simple_concern_resolver import resolve_concern
from utilities.autopatcher.tools.concern_tree_harness import (
    parse_challenger_prompt_trace,
    extract_archived_concerns,
    strip_to_experimental_input,
    _build_investigation_context,
)


class _MockLLM:
    """Plumbing self-check only -- a well-formed, terminal UNRESOLVED for
    every call, no real LLM call, no real semantic result. Stage-aware
    (unlike `concern_tree_harness._MockLLM`'s single canned response) only
    because Pass 1 and Pass 2 have genuinely different response shapes --
    this still proves the harness's own plumbing (loading, extracting,
    invoking `resolve_concern`, writing the artifact) works end to end,
    now exercising both passes' real parsers instead of tripping Pass 2's
    own malformed-output gate on every mock run."""

    def complete(self, system_prompt, user_message, stage=None, **_kwargs):
        if stage == "simple_concern_pass2":
            return (
                "Challenge result: mock LLM, no real challenge performed\n"
                "Final verdict: UNRESOLVED\nFinal reasoning: mock LLM, no real evaluation performed\n"
                "Citations:\n"
            )
        return (
            "Candidate verdict: UNRESOLVED\nReasoning: mock LLM, no real evaluation performed\n"
            "Citations:\nMissing evidence: none\n"
        )


_TARGET_DISCOVERY_PLAN_HEADING_RE = re.compile(r"^## Target Discovery Plan\b.*$", re.MULTILINE)
_H2_HEADING_RE = re.compile(r"^## ", re.MULTILINE)


def _strip_target_discovery_plan(code_context: str) -> str:
    """Remove the "## Target Discovery Plan (...)" section -- Planning's
    OWN prior LLM interpretation (`remediation_planner._render_plan`
    renders this exact heading; its own comment already documents the
    section as "exploratory... not authoritative for Patch Generation")
    -- from `code_context` before it reaches the Simple Concern
    Resolver's evidence pool.

    Purely STRUCTURAL: locates the exact heading Planning itself renders
    and removes everything up to (never including) the next peer-level
    ("## ") heading -- e.g. the genuinely deterministic "## Final-Target
    Remediation Slice" (`remediation_planner._SLICE_HEADING`) that always
    follows it in production's own context assembly. Never inspects the
    section's own CONTENT -- no phrase-level matching on "Security
    invariant:"/"Explicit unknowns:"/etc., no mechanism-specific strings
    of any kind, only the section boundary.

    If the heading is not present (e.g. an archived run with no Planning
    stage, or already-clean evidence), `code_context` is returned
    byte-for-byte unchanged -- this only ever removes a section it can
    positively identify, never guesses."""
    if not code_context:
        return code_context
    start_match = _TARGET_DISCOVERY_PLAN_HEADING_RE.search(code_context)
    if start_match is None:
        return code_context
    rest = code_context[start_match.end():]
    next_match = _H2_HEADING_RE.search(rest)
    end = start_match.end() + next_match.start() if next_match else len(code_context)
    return code_context[:start_match.start()] + code_context[end:]


def run_simple_only(
    code_context, patch, llm, archived_concerns, *,
    repo_root=None, investigation_context=None,
    challenger_prompt_file: "str | None" = None, challenger_response_file: "str | None" = None,
    skipped_concerns: "list[dict] | None" = None,
) -> dict:
    """Run the Simple Concern Resolver against each ALREADY-ARCHIVED
    concern's own role + description -- no baseline reconstruction, no
    Tree involvement, no v2 semantic result of any kind. The only new LLM
    calls this function makes are the resolver's own, via `llm`, up to 3
    per archived concern (see `simple_concern_resolver`'s complexity
    ceiling). The returned artifact is flat/linear per concern -- no node,
    depth, or child keys anywhere.

    `code_context` has Planning's own upstream narrative interpretation
    stripped (see `_strip_target_discovery_plan`) before ANY concern is
    resolved -- every concern in this call receives the same cleaned
    context; `patch` and each concern's own proposition are passed
    through unchanged."""
    code_context = _strip_target_discovery_plan(code_context)
    concerns_out = []
    for archived in archived_concerns:
        experimental_input = strip_to_experimental_input(archived)
        result = resolve_concern(
            experimental_input["proposition"], code_context, patch, llm,
            repo_root=repo_root, investigation_context=investigation_context,
        )
        concerns_out.append({
            "concern_number": archived.get("concern_number"),
            "concern_role": experimental_input["concern_role"],
            "concern_description": experimental_input["proposition"],
            "final_verdict": result["final_verdict"],
            "unresolved_reason": result["unresolved_reason"],
            "citations": result["citations"],
            "pass1": result["pass1"],
            "acquisition": result["acquisition"],
            "pass1_rerun": result["pass1_rerun"],
            "pass2": result["pass2"],
            "metrics": result["metrics"],
        })

    return {
        "mode": "simple_only",
        "challenger_prompt_file": challenger_prompt_file,
        "challenger_response_file": challenger_response_file,
        "archived_concern_count": len(archived_concerns),
        "skipped_concerns": skipped_concerns or [],
        "concerns": concerns_out,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--challenger-prompt-file", required=True,
        help="Path to an archived NNN_challenger.prompt.txt trace.",
    )
    parser.add_argument(
        "--challenger-response-file", required=True,
        help="Path to the archived NNN_challenger.response.txt from the SAME real Challenger call.",
    )
    parser.add_argument("--repo-root", help="real checked-out repo root, for evidence acquisition")
    parser.add_argument("--output", required=True, help="path to write the JSON artifact")
    parser.add_argument(
        "--mock", action="store_true",
        help="plumbing self-check only -- synthetic evidence path, no real LLM, no real semantic result",
    )
    args = parser.parse_args(argv)

    prompt_text = Path(args.challenger_prompt_file).read_text(encoding="utf-8")
    sections = parse_challenger_prompt_trace(prompt_text)
    archived_response = Path(args.challenger_response_file).read_text(encoding="utf-8")
    archived_concerns, skipped_concerns = extract_archived_concerns(archived_response)

    repo_root = Path(args.repo_root) if args.repo_root else None
    # Constructed ONCE here, before resolving any concern, and reused
    # across every concern's `resolve_concern()` call below -- mirrors
    # `concern_tree_harness.main`'s own construction exactly.
    investigation_context = _build_investigation_context(repo_root) if repo_root is not None else None

    if args.mock:
        llm = _MockLLM()
    else:
        from utilities.autopatcher.llm_client import LLMClient
        llm = LLMClient(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

    result = run_simple_only(
        sections["code_context"], sections["patch"], llm, archived_concerns,
        repo_root=repo_root, investigation_context=investigation_context,
        challenger_prompt_file=args.challenger_prompt_file,
        challenger_response_file=args.challenger_response_file,
        skipped_concerns=skipped_concerns,
    )

    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote simple-resolver artifact: {args.output}")
    print(f"  archived_concern_count: {result['archived_concern_count']}  skipped: {len(result['skipped_concerns'])}")
    for c in result["concerns"]:
        print(
            f"  - #{c['concern_number']} [{c['concern_role']}] final={c['final_verdict']} "
            f"(llm_calls={c['metrics']['llm_calls']}, acquired={c['metrics']['evidence_acquired']})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
