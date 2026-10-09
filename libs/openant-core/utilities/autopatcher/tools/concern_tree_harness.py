#!/usr/bin/env python3
"""
concern_tree_harness.py -- offline A/B comparison harness for the
experimental recursive concern-tree resolver vs. the concerns_v2 baseline.

Lives at utilities/autopatcher/tools/ next to the other standalone,
production-independent debug/experiment tools (see run_stage.py). This
script does NOT call `utilities.autopatcher.pipeline.run()` and does not
import `pipeline.py`. It is not imported by any production module --
`patch_challenger.py`/`pipeline.py` have no knowledge of this file or of
`concern_tree.py`.

PAIRED REPLAY MODE (the correct mode for a real N=5 comparison):

  --challenger-prompt-file + --challenger-response-file together replay a
  SINGLE real Challenger call from an already-completed `run_traced.py`
  execution: the prompt file reconstructs `vulnerability_text`/
  `code_context`/`patch`; the response file is the archived raw LLM text
  that call actually produced. The baseline arm performs ZERO new
  semantic LLM sampling -- `challenge_patch()` (the real, unmodified
  production parser) is called with a `_ReplayLLM` stub that returns the
  archived response byte-for-byte and makes no network/provider call.
  This is REPLAY, not re-sampling: the "baseline" in the comparison
  artifact is the exact result that already happened in the real run,
  reconstructed through the identical production parsing/post-processing
  path -- not an independent second draw from the model.

  The tree arm remains live and probabilistic in every mode: it always
  makes real (or, under --mock, canned) LLM calls of its own, since the
  recursive concern tree has never run for this evidence before.

  `--challenger-response-file` is REQUIRED whenever `--challenger-prompt-
  file` is given -- there is no fallback to a fresh baseline LLM call;
  omitting it fails closed with a clear error rather than silently
  re-sampling.

GENERIC EXPLICIT-INPUT MODE (--vulnerability-text-file/--code-context-file/
--patch-file): useful for ad hoc experimentation with hand-built or
synthetic evidence that was never a real Challenger call to begin with --
there is no archived response to replay, so this mode DOES make a live
baseline LLM call. This is NOT paired replay and must never be mistaken
for it: the comparison artifact's own `baseline_source` field is always
`"live_llm_call_generic_mode"` in this mode (vs.
`"archived_challenger_response"` for paired replay), and this script warns
on stderr when it is used.

TREE-ONLY ARCHIVED-RUN MODE (--tree-only, requires --challenger-prompt-file
+ --challenger-response-file): for when the archived response's own v2
baseline parse is not needed at all (e.g. it is analyzed separately from
the original production Trust Report/trace) -- run the recursive Concern
Tree against EACH concern that actually appeared in the archived response,
using ONLY that concern's own Role + Description, recovered by
`extract_archived_concerns()` (see below) WITHOUT ever calling
`challenge_patch()`, constructing a `_ReplayLLM`, or computing any v2
semantic result (reachability, consequence, verification_status). Zero
Challenger/baseline LLM calls occur in this mode -- the recursive Tree is
the only thing that makes new semantic LLM calls. `vulnerability_text` is
still recovered from the prompt file as an implementation detail of
`parse_challenger_prompt_trace()`, but it is discarded immediately and
never reaches the Tree.

MOCK MODE (--mock): plumbing self-check only -- synthetic evidence, a
canned LLM for both arms, no real evidence and no real semantic result.
`baseline_source` is `"mock"`. May be combined with --tree-only for a
tree-only plumbing self-check against real archived files with no API key.

EVIDENCE ACQUISITION (--repo-root): when given, this script constructs the
SAME production repository-investigation context
(`candidate_enrichment.build_investigation_context`) ONCE per invocation,
read-only against `--repo-root` (parsing writes only to a fresh temp
directory, never into the target repository), and reuses that ONE object
across every concern's Tree evaluation -- never a second/parallel
repository-analysis implementation. Without --repo-root (or if parsing
fails/the language is unsupported), the context stays `None` and every
REQUEST_EVIDENCE legitimately fails closed to `no_repo_root`, exactly as
`concern_tree.py`'s own existing gate already documents -- this wiring
only gives that gate a chance to succeed; it never weakens it.

What every mode does, given its resolved evidence:

  1. Obtains a baseline v2 result for `vulnerability_text`/`code_context`/
     `patch` via the existing, unmodified `challenge_patch()` -- via
     replay (paired mode) or a live call (generic/mock modes), per above.
  2. For EACH discovered concern, builds a clean experimental root
     proposition containing ONLY the concern's own `description` text --
     see `strip_to_experimental_input()` below, the ONE place isolation
     between the two arms is enforced, and
     `tests/patch/test_concern_tree_harness.py`'s own explicit test of it.
     Neither `vulnerability_text` nor the archived raw Challenger response
     text is ever passed to the tree arm.
  3. Runs `evaluate_concern_tree()` (the experimental resolver, always a
     live call) against that clean proposition, using the SAME
     code_context/patch the baseline saw.
  4. Writes one JSON comparison artifact containing both arms' results
     side by side, plus explicit provenance metadata (`baseline_source`
     and, in paired mode, the two source file paths) -- this script does
     not itself judge which arm is "better".

Usage:

    # PAIRED REPLAY (the mode for a real N=5 comparison): baseline is the
    # exact result the real run already produced, replayed through the
    # unmodified production parser -- zero new baseline LLM sampling.
    python3 utilities/autopatcher/tools/concern_tree_harness.py \\
        --challenger-prompt-file /path/to/006_challenger.prompt.txt \\
        --challenger-response-file /path/to/006_challenger.response.txt \\
        --repo-root /path/to/exact/evaluated/repo \\
        --output /tmp/comparison.json

    # Generic explicit inputs (NOT paired replay -- live baseline call):
    python3 utilities/autopatcher/tools/concern_tree_harness.py \\
        --vulnerability-text-file vuln.txt \\
        --code-context-file ctx.txt \\
        --patch-file patch.diff \\
        --output /tmp/comparison.json

    # Plumbing self-check, no real LLM, no real evidence:
    python3 utilities/autopatcher/tools/concern_tree_harness.py --mock \\
        --output /tmp/mock-comparison.json

    # TREE-ONLY archived-run mode: no baseline reconstruction at all, only
    # the recursive Tree runs, against each archived concern's own
    # Role+Description.
    python3 utilities/autopatcher/tools/concern_tree_harness.py \\
        --challenger-prompt-file /path/to/006_challenger.prompt.txt \\
        --challenger-response-file /path/to/006_challenger.response.txt \\
        --repo-root /path/to/exact/evaluated/repo \\
        --output /path/to/tree-results.json \\
        --tree-only

Evidence acquisition can resolve real repository symbols only with
--repo-root pointing at an actual checked-out copy of the evaluated
repository (see "EVIDENCE ACQUISITION" above); without it, every
REQUEST_EVIDENCE fails closed to `no_repo_root`, exactly as
`concern_tree.py`'s own module docstring describes.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# utilities/autopatcher/tools/concern_tree_harness.py -> tools -> autopatcher
# -> utilities -> <openant-core root>
_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from utilities.autopatcher.patch_challenger import challenge_patch  # noqa: E402
from utilities.autopatcher.concern_tree import evaluate_concern_tree  # noqa: E402


# ---------------------------------------------------------------------------
# Captured-evidence loading. Read-only, no repository mutation.
# ---------------------------------------------------------------------------

_CHALLENGER_TRACE_HEADER_RE = re.compile(
    r"^(## Repository evidence \(selected by static analysis\)|## Vulnerability report|## Proposed patch)\s*$",
    re.MULTILINE,
)


def parse_challenger_prompt_trace(text: str) -> "dict[str, str]":
    """Split an archived Challenger `NNN_challenger.prompt.txt`-shaped
    trace (the literal `user_message` `challenge_patch()` sent -- see
    `patch_challenger.challenge_patch`'s own assembly of
    `context_section`/`vulnerability_text`/`patch`) back into its three
    parts. The `## Repository evidence` section is optional (absent when
    the original run supplied no `code_context`); the other two are
    mandatory."""
    parts = _CHALLENGER_TRACE_HEADER_RE.split(text)
    sections = {"code_context": "", "vulnerability_text": "", "patch": ""}
    i = 1
    while i < len(parts) - 1:
        header = parts[i].strip()
        body = parts[i + 1].strip()
        if header.startswith("## Repository evidence"):
            sections["code_context"] = body
        elif header.startswith("## Vulnerability report"):
            sections["vulnerability_text"] = body
        elif header.startswith("## Proposed patch"):
            sections["patch"] = body
        i += 2
    return sections


# ---------------------------------------------------------------------------
# Experimental-arm input isolation. THE load-bearing boundary this harness
# exists to enforce -- see module docstring point 2.
# ---------------------------------------------------------------------------

_V2_ONLY_KEYS = frozenset({
    "default_execution_reachability", "preceding_guard", "guard_default_state",
    "guard_effect", "reentry_state_propagation", "requires_explicit_non_default_action",
    "contract_addresses_override", "consequence", "reachability_facts",
    "malformed", "malformed_reason", "schema_version",
})


def strip_to_experimental_input(concern: dict) -> "dict[str, str]":
    """The ONE function that constructs what the experimental arm is
    allowed to see from a v2-discovered concern. Returns ONLY
    `{"concern_role": ..., "proposition": ...}` -- built exclusively from
    `concern["concern_role"]`/`concern["description"]`. Every v2
    resolution field (`_V2_ONLY_KEYS`) is asserted absent from the
    result, not merely omitted by convention -- a future edit that
    accidentally starts forwarding one of them fails loudly here, not
    silently in production. Note that this function's INPUT is a parsed
    v2 concern dict -- it never sees the raw archived Challenger response
    text at all (see `run_comparison`: that text is consumed entirely
    inside the baseline `challenge_patch()` call, several layers before
    any concern dict exists), so there is no separate leak path for it to
    guard against here."""
    experimental_input = {
        "concern_role": concern.get("concern_role"),
        "proposition": concern.get("description", ""),
    }
    leaked = _V2_ONLY_KEYS & set(experimental_input.keys())
    assert not leaked, f"v2-only fields leaked into experimental input: {leaked}"
    return experimental_input


# ---------------------------------------------------------------------------
# Archived-concern extraction for TREE-ONLY mode -- deliberately the
# smallest possible slice of parsing, never the full v2 semantic parser.
# ---------------------------------------------------------------------------

def extract_archived_concerns(response_text: str) -> "tuple[list[dict], list[dict]]":
    """Minimal, fail-closed extraction of ONLY Role + Description from an
    archived Challenger response, for --tree-only mode.

    Reuses `patch_challenger.py`'s own lexical primitives
    (`_split_sections`/`_split_concern_blocks`/`_extract_concern_field`/
    `CONCERN_ROLES`) exactly as-is -- never a second concern tokenizer,
    never a duplicated field regex. Deliberately NEVER calls
    `_parse_concern_block`/`_parse_concern_block_v2`/`challenge_patch`, so
    this function is structurally immune to the reachability-derivation/
    override-applicability-gate parsing failure those functions can hit:
    Role/Description extraction has zero dependency on reachability
    derivation, provenance validation, or the override/scope gate (a real
    instance of that failure was observed and diagnosed against an actual
    archived urllib3 Challenger response during this feature's design --
    both of that response's concerns failed full v2 parsing, yet both
    extract cleanly here).

    Returns `(concerns, skipped)`:
      concerns -- one `{"concern_number", "concern_role", "description"}`
                  dict per cleanly-extracted concern, in printed order.
                  Keys are chosen to be byte-identical to what
                  `strip_to_experimental_input()` already reads, so that
                  function is reused UNCHANGED for tree-only concerns too.
      skipped  -- one `{"concern_number", "reason"}` dict per concern that
                  could NOT be safely extracted -- never silently dropped,
                  never fabricated. This function never aborts the whole
                  response over one bad block (mirrors `_parse_concerns`'s
                  own per-concern, never per-response, fail-closed
                  discipline).

    Does NOT enforce "exactly one primary concern" -- that is a
    production-verdict rule (`_derive_status_from_concerns`), irrelevant
    to an experiment that only wants to run the Tree against whatever
    concerns actually appeared."""
    from utilities.autopatcher.patch_challenger import (
        _split_sections, _split_concern_blocks, _extract_concern_field, CONCERN_ROLES,
    )

    sections = _split_sections(response_text)
    concerns_body = sections.get("concerns")
    if concerns_body is None:
        return [], [{"concern_number": None, "reason": "no_concerns_section"}]

    blocks = _split_concern_blocks(concerns_body)
    concerns: "list[dict]" = []
    skipped: "list[dict]" = []
    for num in sorted(blocks):
        span = blocks[num]
        if span is None:
            skipped.append({"concern_number": num, "reason": "duplicate_concern_number"})
            continue
        role = _extract_concern_field(span, "Role")
        role = role.strip().lower() if role else None
        if role not in CONCERN_ROLES:
            skipped.append({"concern_number": num, "reason": "invalid_or_missing_role"})
            continue
        description = _extract_concern_field(span, "Description")
        if not description or not description.strip():
            skipped.append({"concern_number": num, "reason": "missing_description"})
            continue
        concerns.append({"concern_number": num, "concern_role": role, "description": description.strip()})
    return concerns, skipped


# ---------------------------------------------------------------------------
# LLM stand-ins.
#
# `_MockLLM` (mock mode, both arms) and `_ReplayLLM` (paired-replay mode,
# BASELINE ARM ONLY) serve entirely different purposes and must not be
# confused: `_MockLLM` fabricates a canned response for plumbing self-
# checks and never claims to represent anything real; `_ReplayLLM`
# reproduces one specific, already-real response exactly, and exists
# precisely so the baseline arm performs zero new semantic sampling.
# ---------------------------------------------------------------------------

class _MockLLM:
    """Returns a well-formed, terminal `UNRESOLVED` for every call --
    proves the harness's own plumbing (loading, stripping, invoking both
    arms, writing the artifact) works end to end without making any real
    LLM call and without claiming any real semantic result."""

    def complete(self, system_prompt, user_message, stage=None, **_kwargs):
        if stage == "challenger":
            return (
                "Verification status: INSUFFICIENT_EVIDENCE\n\n"
                "Concerns:\n\n"
                "1. Role: primary\n"
                "   Description: mock concern for harness plumbing self-check\n"
                "   Default execution reachability: unresolved\n"
                "   Reachability provenance: none\n"
                "   Requires explicit non-default action: not_applicable\n"
                "   Contract addresses override: not_applicable\n\n"
                "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
            )
        return "Action: UNRESOLVED\nReason: mock LLM, no real evaluation performed\n"


class _ReplayLLM:
    """Replays ONE archived raw LLM response byte-for-byte -- makes NO
    network/provider call, ever; there is no adapter, no API key, no
    provider resolution anywhere in this class. Used ONLY for the
    baseline `challenge_patch()` call in paired-replay mode, so that arm
    performs ZERO new semantic sampling: `challenge_patch()` itself
    (production code, unmodified, imported directly) runs its exact
    parsing/derivation/aggregation logic against the SAME text the real
    run's own Challenger call actually produced -- this is replay, not
    re-sampling.

    Fails loudly (`RuntimeError`) if `.complete()` is invoked more than
    once. Paired-replay mode expects EXACTLY one call: the single
    baseline Challenger call being replayed. A second call would mean
    something beyond that one archived response is being asked for --
    e.g. a future change to `challenge_patch()` that makes an additional
    LLM call this replay was never captured to answer -- and silently
    returning the SAME archived text a second time would mask that
    instead of surfacing it."""

    def __init__(self, archived_response: str):
        self._archived_response = archived_response
        self._called = False

    def complete(self, system_prompt, user_message, stage=None, **_kwargs):
        if self._called:
            raise RuntimeError(
                "_ReplayLLM.complete() was called more than once. Paired "
                "replay mode expects exactly one LLM call -- the single "
                "archived baseline Challenger call being replayed. A "
                "second call means something beyond that one archived "
                "response was requested, which this mode must never "
                "silently answer by repeating the same text."
            )
        self._called = True
        return self._archived_response


# ---------------------------------------------------------------------------
# Comparison run.
# ---------------------------------------------------------------------------

def run_comparison(
    vulnerability_text, code_context, patch, *, baseline_llm, tree_llm,
    baseline_source: str, repo_root=None, investigation_context=None, tree_limits=None,
    challenger_prompt_file: "str | None" = None, challenger_response_file: "str | None" = None,
) -> dict:
    """Run both arms against the SAME captured evidence and return the
    comparison artifact. Never mutates the inputs; never writes anything
    itself (the caller decides where/whether to persist the result).

    `baseline_llm`/`tree_llm` are deliberately separate parameters, never
    one shared object: the baseline arm's LLM is a `_ReplayLLM` in paired
    mode (zero new sampling) but the tree arm's LLM is ALWAYS live (or
    `_MockLLM` under --mock) -- conflating them would either force the
    tree to replay too (impossible; the tree has never run before) or
    force the baseline to re-sample (exactly the bug this function exists
    to fix). `baseline_source` is caller-supplied, never inferred here,
    so it is always an explicit, honest record of which of the two ways
    the baseline was actually obtained."""
    baseline = challenge_patch(vulnerability_text, patch, baseline_llm, code_context=code_context)
    concerns = baseline.get("concerns") or []

    experiments = []
    for concern in concerns:
        experimental_input = strip_to_experimental_input(concern)
        tree_result = evaluate_concern_tree(
            experimental_input["proposition"], code_context, patch, tree_llm,
            repo_root=repo_root, investigation_context=investigation_context,
            limits=tree_limits,
        )
        experiments.append({
            "concern_role": experimental_input["concern_role"],
            "concern_description": experimental_input["proposition"],
            "baseline": {
                "default_execution_reachability": concern.get("default_execution_reachability"),
                "consequence": concern.get("consequence"),
                "malformed": concern.get("malformed"),
            },
            "experiment": {
                "root_final_status": tree_result["root_final_status"],
                "trace": tree_result,
                "metrics": {
                    "total_nodes": tree_result["totals"]["total_nodes"],
                    "max_depth_reached": tree_result["totals"]["max_depth_reached"],
                    "semantic_evaluation_calls": tree_result["totals"]["semantic_evaluation_calls"],
                    "evidence_requests": tree_result["totals"]["evidence_requests"],
                    "evidence_acquired": tree_result["totals"]["evidence_acquired"],
                    "invalid_provenance_count": tree_result["totals"]["invalid_provenance_count"],
                },
            },
        })

    return {
        "baseline_source": baseline_source,
        "challenger_prompt_file": challenger_prompt_file,
        "challenger_response_file": challenger_response_file,
        "baseline_verification_status": baseline.get("verification_status"),
        "baseline_schema_version": baseline.get("schema_version"),
        "concern_count": len(concerns),
        "concerns": experiments,
    }


def run_tree_only(
    code_context, patch, tree_llm, archived_concerns, *,
    repo_root=None, investigation_context=None, tree_limits=None,
    challenger_prompt_file: "str | None" = None, challenger_response_file: "str | None" = None,
    skipped_concerns: "list[dict] | None" = None,
) -> dict:
    """Tree-only archived-run mode: run the recursive Concern Tree against
    each ALREADY-ARCHIVED concern's own role + description (see
    `extract_archived_concerns`) -- no baseline reconstruction, no
    `challenge_patch()` call, no `_ReplayLLM`, no v2 semantic result of
    any kind (no reachability/consequence/verification_status ever
    computed). The only new LLM calls this function makes are the Tree's
    own, via `tree_llm`, once per archived concern.

    `archived_concerns` must already be `extract_archived_concerns()`'s
    own output shape -- this function does not parse the archived
    response itself, keeping the same single-responsibility split
    `run_comparison`/`_load_inputs` already follow. There is no
    `"baseline"` key anywhere in the returned artifact."""
    concerns_out = []
    for archived in archived_concerns:
        experimental_input = strip_to_experimental_input(archived)
        tree_result = evaluate_concern_tree(
            experimental_input["proposition"], code_context, patch, tree_llm,
            repo_root=repo_root, investigation_context=investigation_context,
            limits=tree_limits,
        )
        concerns_out.append({
            "concern_number": archived.get("concern_number"),
            "concern_role": experimental_input["concern_role"],
            "concern_description": experimental_input["proposition"],
            "tree": {
                "root_final_status": tree_result["root_final_status"],
                "trace": tree_result,
                "metrics": {
                    "total_nodes": tree_result["totals"]["total_nodes"],
                    "max_depth_reached": tree_result["totals"]["max_depth_reached"],
                    "semantic_evaluation_calls": tree_result["totals"]["semantic_evaluation_calls"],
                    "evidence_requests": tree_result["totals"]["evidence_requests"],
                    "evidence_acquired": tree_result["totals"]["evidence_acquired"],
                    "invalid_provenance_count": tree_result["totals"]["invalid_provenance_count"],
                },
            },
        })

    return {
        "mode": "tree_only",
        "challenger_prompt_file": challenger_prompt_file,
        "challenger_response_file": challenger_response_file,
        "archived_concern_count": len(archived_concerns),
        "skipped_concerns": skipped_concerns or [],
        "concerns": concerns_out,
    }


def _build_investigation_context(repo_root: "Path"):
    """Construct the real production repository-investigation context
    (`candidate_enrichment.build_investigation_context`) ONCE per harness
    invocation, read-only against `repo_root` -- parsing writes only to a
    fresh, harness-owned temp directory; `repo_root` itself is never
    written to. Never a second/parallel repository-analysis
    implementation, never a new evidence resolver: the SAME object this
    returns is reused, by the caller, across every concern's
    `evaluate_concern_tree()` call in this invocation.

    Returns `None` (never raises -- wrapped defensively even though
    `build_investigation_context` already documents itself as never
    raising) on any parse failure or unsupported language, exactly that
    function's own contract. A `None` here changes nothing about
    `concern_tree.py`'s own existing fail-closed gate
    (`repo_root is None or investigation_context is None`) -- every
    REQUEST_EVIDENCE in the run simply keeps failing closed to
    `no_repo_root`, precisely as it already does without this wiring."""
    import tempfile
    from utilities.autopatcher.candidate_enrichment import build_investigation_context

    output_dir = Path(tempfile.mkdtemp(prefix="concern_tree_harness_ctx_"))
    try:
        return build_investigation_context(repo_root, output_dir)
    except Exception:
        return None


class _LoadedInputs:
    def __init__(self, vulnerability_text, code_context, patch, *, archived_response=None, baseline_source):
        self.vulnerability_text = vulnerability_text
        self.code_context = code_context
        self.patch = patch
        self.archived_response = archived_response
        self.baseline_source = baseline_source


def _load_inputs(args) -> _LoadedInputs:
    # --challenger-prompt-file is checked BEFORE --mock: --mock only ever
    # selects which LLM stand-in `main()` uses (see its own branches), never
    # which EVIDENCE is loaded. This lets `--tree-only --mock
    # --challenger-prompt-file ...` extract REAL archived concerns and run
    # them through a canned tree LLM, for a full plumbing self-check against
    # real files with no API key -- `--mock` alone (no prompt file) still
    # falls through to the synthetic fixture exactly as before.
    if args.challenger_prompt_file:
        if not args.challenger_response_file:
            raise SystemExit(
                "--challenger-prompt-file requires --challenger-response-file "
                "(the archived raw response from the SAME real Challenger call "
                "the prompt file came from). Paired replay/tree-only mode must "
                "never silently fall back to a fresh baseline LLM call -- if you "
                "don't have the archived response, use --vulnerability-text-file/"
                "--code-context-file/--patch-file instead, which clearly labels "
                "its baseline as a live call, not a replay."
            )
        text = Path(args.challenger_prompt_file).read_text(encoding="utf-8")
        sections = parse_challenger_prompt_trace(text)
        archived_response = Path(args.challenger_response_file).read_text(encoding="utf-8")
        return _LoadedInputs(
            sections["vulnerability_text"], sections["code_context"], sections["patch"],
            archived_response=archived_response, baseline_source="archived_challenger_response",
        )

    if args.mock:
        return _LoadedInputs(
            "Mock vulnerability report for harness plumbing self-check.",
            "def f():\n    if flag:\n        raise Err()\n    op()\n",
            "",
            baseline_source="mock",
        )

    if not (args.vulnerability_text_file and args.patch_file):
        raise SystemExit(
            "Provide --mock, or --challenger-prompt-file + --challenger-response-file "
            "(paired replay), or both --vulnerability-text-file and --patch-file "
            "(--code-context-file optional; NOT paired replay -- see --help)."
        )
    vulnerability_text = Path(args.vulnerability_text_file).read_text(encoding="utf-8")
    patch = Path(args.patch_file).read_text(encoding="utf-8")
    code_context = Path(args.code_context_file).read_text(encoding="utf-8") if args.code_context_file else ""
    print(
        "warning: --vulnerability-text-file/--code-context-file/--patch-file mode "
        "makes a LIVE baseline LLM call -- this is generic experimentation, NOT "
        "paired replay of a real run. Use --challenger-prompt-file + "
        "--challenger-response-file for a real A/B comparison against an actual "
        "Challenger call.",
        file=sys.stderr,
    )
    return _LoadedInputs(
        vulnerability_text, code_context, patch, baseline_source="live_llm_call_generic_mode",
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--challenger-prompt-file",
        help=(
            "Path to an archived NNN_challenger.prompt.txt trace. PAIRED REPLAY "
            "mode -- requires --challenger-response-file from the SAME real "
            "Challenger call; the baseline arm then performs zero new LLM sampling."
        ),
    )
    parser.add_argument(
        "--challenger-response-file",
        help=(
            "Path to the archived NNN_challenger.response.txt from the SAME real "
            "Challenger call as --challenger-prompt-file. Required whenever "
            "--challenger-prompt-file is given."
        ),
    )
    parser.add_argument(
        "--vulnerability-text-file",
        help="Generic explicit-input mode (NOT paired replay -- makes a live baseline LLM call).",
    )
    parser.add_argument("--code-context-file")
    parser.add_argument("--patch-file")
    parser.add_argument("--repo-root", help="real checked-out repo root, for evidence acquisition")
    parser.add_argument("--output", required=True, help="path to write the JSON comparison/tree-only artifact")
    parser.add_argument(
        "--mock", action="store_true",
        help="plumbing self-check only -- synthetic evidence, no real LLM, no real semantic result",
    )
    parser.add_argument(
        "--tree-only", action="store_true",
        help=(
            "Tree-only archived-run mode: run the recursive Concern Tree against "
            "each concern's archived Role+Description only -- no baseline "
            "reconstruction, no challenge_patch() call, zero Challenger/baseline "
            "LLM calls. Requires --challenger-prompt-file + "
            "--challenger-response-file."
        ),
    )
    args = parser.parse_args(argv)

    if args.tree_only and not args.challenger_prompt_file:
        raise SystemExit(
            "--tree-only requires --challenger-prompt-file (+ --challenger-"
            "response-file) -- there are no archived concerns to run the Tree "
            "against otherwise."
        )

    loaded = _load_inputs(args)

    repo_root = Path(args.repo_root) if args.repo_root else None
    # Constructed ONCE here, before either mode's branch, and reused across
    # every concern's Tree evaluation below -- see _build_investigation_
    # context's own docstring for why this never weakens concern_tree.py's
    # existing fail-closed gate.
    investigation_context = _build_investigation_context(repo_root) if repo_root is not None else None

    if args.tree_only:
        # Tree-only mode constructs ONLY a tree LLM -- no baseline LLM, no
        # _ReplayLLM, no challenge_patch() call anywhere on this path.
        if args.mock:
            tree_llm = _MockLLM()
        else:
            from utilities.autopatcher.llm_client import LLMClient
            import os
            tree_llm = LLMClient(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

        archived_concerns, skipped_concerns = extract_archived_concerns(loaded.archived_response)
        result = run_tree_only(
            loaded.code_context, loaded.patch, tree_llm, archived_concerns,
            repo_root=repo_root, investigation_context=investigation_context,
            challenger_prompt_file=args.challenger_prompt_file,
            challenger_response_file=args.challenger_response_file,
            skipped_concerns=skipped_concerns,
        )

        Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Wrote tree-only artifact: {args.output}")
        print(
            f"  archived_concern_count: {result['archived_concern_count']}  "
            f"skipped: {len(result['skipped_concerns'])}"
        )
        for c in result["concerns"]:
            print(
                f"  - #{c['concern_number']} [{c['concern_role']}] "
                f"tree={c['tree']['root_final_status']} "
                f"(nodes={c['tree']['metrics']['total_nodes']}, "
                f"evals={c['tree']['metrics']['semantic_evaluation_calls']})"
            )
        return 0

    if args.mock:
        baseline_llm = _MockLLM()
        tree_llm = _MockLLM()
    elif loaded.archived_response is not None:
        baseline_llm = _ReplayLLM(loaded.archived_response)
        from utilities.autopatcher.llm_client import LLMClient
        import os
        tree_llm = LLMClient(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
    else:
        from utilities.autopatcher.llm_client import LLMClient
        import os
        live_llm = LLMClient(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
        baseline_llm = live_llm
        tree_llm = live_llm

    result = run_comparison(
        loaded.vulnerability_text, loaded.code_context, loaded.patch,
        baseline_llm=baseline_llm, tree_llm=tree_llm, baseline_source=loaded.baseline_source,
        repo_root=repo_root, investigation_context=investigation_context,
        challenger_prompt_file=args.challenger_prompt_file,
        challenger_response_file=args.challenger_response_file,
    )

    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote comparison artifact: {args.output}")
    print(f"  baseline_source: {result['baseline_source']}")
    print(f"  baseline concerns discovered: {result['concern_count']}")
    for c in result["concerns"]:
        print(
            f"  - [{c['concern_role']}] baseline={c['baseline']['default_execution_reachability']} "
            f"experiment={c['experiment']['root_final_status']} "
            f"(nodes={c['experiment']['metrics']['total_nodes']}, "
            f"evals={c['experiment']['metrics']['semantic_evaluation_calls']})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
