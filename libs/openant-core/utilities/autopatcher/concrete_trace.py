"""
Concrete Trace -- an EXPERIMENTAL, standalone, zero-authority companion to
the production Challenger (patch_challenger.py).

WHAT THIS IS: for one concern, construct ONE minimal concrete scenario and
follow it, citation by citation, through the same repository evidence
Challenger already has, to a REACHED/BLOCKED/UNRESOLVED verdict about THAT
one scenario. This is execution tracing, not property reasoning -- the
existing atomic Challenger asks "what does this guard's condition evaluate
to under default execution"; Concrete Trace instead asks "for this one
specific attempted call, what actually happens, step by step, according to
the evidence."

WHAT THIS IS NOT, DELIBERATELY:
  - not a semantic verifier of the concern or the patch
  - not a second opinion on Challenger's own verdict
  - not recursive, not multi-pass, not an acquisition loop
  - not wired into production: nothing in patch_challenger.py, pipeline.py,
    or any policy function (`_derive_default_execution_reachability`,
    `_concern_consequence`, `_classify_challenger`, final recommendation
    construction) imports or reads anything from this module. This module
    is never imported by any of them, and this file does not import them
    either except for one narrow, explicitly-audited reuse: the citation-
    provenance primitive (`_point_citation_valid`) -- a pure, stateless
    helper with no policy content of its own. Response parsing is this
    module's own (`_parse_concrete_trace_response`).

INPUT ISOLATION (the load-bearing property of this experiment): the public
entry point, `resolve_concrete_trace`, takes ONLY `concern_role`,
`description`, `code_context`, and `patch` as parameters -- there is no
parameter through which `vulnerability_text`, any v2 atomic reachability
fact, `default_execution_reachability`, `requires_explicit_non_default_
action`, `contract_addresses_override`, `consequence`, `hypothesized_
outcome`, or Challenger's own verification status could be passed in, even
by a future caller's mistake. This mirrors (and is directly informed by)
the identical isolation decision already made, independently, by both
`simple_concern_resolver.py` and `utilities/autopatcher/tools/
concern_tree_harness.py`'s `strip_to_experimental_input` -- neither passes
Challenger's own atomic/derived conclusions into its own experimental arm
either, and both treat this as the single most important property to
protect. "Structurally impossible to pass in" (a function signature with no
such parameter) is a strictly stronger guarantee than "asserted absent from
a dict," so that is the primary mechanism here; `_ISOLATION_BOUNDARY_FIELDS`
below exists ONLY as a documented, greppable enumeration of what the
signature already excludes, and as an explicit assertion inside the
harness's own concern-to-input adapter (see concrete_trace_harness.py) --
never as the enforcement mechanism itself.

LLM CALL BUDGET: exactly ONE `llm.complete()` call per `resolve_concrete_
trace()` invocation, always. No retries, no second pass, no evidence
acquisition, no recursion. If the single response cannot establish a valid
result, the result is UNRESOLVED -- never a second call to try again.

AUTHORITY: this module returns a plain dict. Nothing here computes, mutates,
or even receives `reachability`/`consequence`/`verification_status`. A
caller choosing to attach this dict's result onto a concern (e.g. under a
new `concern["concrete_trace"]` key) does so strictly AFTER that concern's
`reachability`/`consequence` are already final -- exactly the same
temporal/textual guarantee already established for `hypothesized_outcome`
in patch_challenger.py. No such attachment happens anywhere in THIS
experiment; it is future work, out of scope here.

KNOWN LIMITATION -- "concern mechanism" vs. "final outcome" (deliberately
NOT deterministically enforced): the concern's own description names a
suspicious behavior/branch/mechanism to exercise; the actually meaningful
question is whether the concrete scenario, followed all the way through,
reaches the FINAL, externally-relevant problematic outcome -- not merely
whether it passes through that named mechanism along the way (a real,
observed failure mode: a trace that stops the instant the named mechanism
fires and reports `REACHED`, without ever checking whether anything later
in the same execution would have prevented the actual outcome). This
distinction is enforced ENTIRELY by `prompts/concrete_trace.md`'s own task
instructions -- it is NOT, and cannot honestly be, verified by
`_validate_concrete_trace` below. Nothing in this module's schema
(`example_scenario`/`trace_steps`/`outcome`/`blocking_step_index`) marks
which step, if any, corresponds to "the named mechanism" versus "the final
outcome" -- doing so would require semantically understanding arbitrary
repository code well enough to classify a citation's role, which is
exactly the kind of mechanism-specific/semantic-verifier capability this
experiment deliberately does not have and is not trying to build. A
response with valid citations that stops exactly at the named mechanism
and still claims `REACHED` will pass `_validate_concrete_trace` --
deterministic validation here checks shape, citation grounding, and
internal consistency (does `blocking_step_index` behave correctly for the
declared outcome), never whether the declared outcome is the RIGHT one for
what the trace actually shows. This is a genuine, acknowledged gap in what
code alone can guarantee, not an oversight -- see the module-level
docstring's own "WHAT THIS IS NOT" list above for why no semantic verifier
is being added to close it.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from utilities.autopatcher.patch_challenger import _point_citation_valid

_PROMPT_PATH = Path(__file__).parent / "prompts" / "concrete_trace.md"

OUTCOME_VALUES = ("REACHED", "BLOCKED", "UNRESOLVED")

# Documentation-only enumeration -- see this module's own docstring
# ("INPUT ISOLATION") for why `resolve_concrete_trace`'s signature, not this
# frozenset, is the actual enforcement mechanism. Used by
# concrete_trace_harness.py's own concern-to-input adapter as a belt-and-
# suspenders assertion, mirroring concern_tree_harness.py's `_V2_ONLY_KEYS`
# pattern.
_ISOLATION_BOUNDARY_FIELDS = frozenset({
    "vulnerability_text",
    "operation_present_in_evidence",
    "preceding_guard",
    "guard_default_state",
    "guard_effect",
    "reentry_state_propagation",
    "default_execution_reachability",
    "requires_explicit_non_default_action",
    "contract_addresses_override",
    "consequence",
    "reachability_facts",
    "hypothesized_outcome",
    "verification_status",
    "still_vulnerable",
    "malformed",
    "malformed_reason",
    "schema_version",
})

# One numbered trace-step header per line, e.g. "1. Citation: ...". Mirrors
# `patch_challenger._CONCERN_BLOCK_HEADER_RE`'s technique (a numbered-block
# boundary marker) for this module's own, much smaller schema. A step runs
# from its header to the next header (or the end of the response).
_TRACE_STEP_HEADER_RE = re.compile(r"^[ \t]*(\d+)\.\s*Citation:", re.MULTILINE)

# A step's structural `Note:` line. The LAST such line in a step is its
# Note, and everything between the header and that line is its Citation:
# repository text can itself contain a line starting with `Note:` (e.g. a
# docstring section), and ending the citation at the FIRST such line would
# leave every later cited line unvalidated. Ending it at the last one means
# the whole citation -- including any earlier `Note:`-looking line, or a
# duplicate structural Note -- must be verbatim evidence to validate.
_TRACE_NOTE_LINE_RE = re.compile(r"^[ \t]*Note:[ \t]*(.*?)[ \t]*$", re.IGNORECASE | re.MULTILINE)

# Any `Citation:` label outside citation contents. Every recognized step
# header carries exactly one, so an extra one is an attempted step the
# header pattern did not recognize (`2) Citation:`, `- Citation:`, ...) --
# which would otherwise be silently dropped, its citation never validated.
_CITATION_LABEL_RE = re.compile(r"\bcitation[ \t]*:", re.IGNORECASE)

# Any structural line that starts like a numbered item (optionally bulleted
# or bolded). Every recognized step header is one, so an extra one is an
# attempted step whose `Citation:` label is missing or unrecognizable
# (`2. \`call()\``, `2. Citaton: ...`) -- which would otherwise be silently
# dropped when it carries no `Note:` line of its own.
_NUMBERED_ITEM_RE = re.compile(r"^[ \t]*(?:[-*+][ \t]+)?(?:\*\*)?\d+[.)]", re.MULTILINE)


def _structural_fields(structural_text: str, label: str) -> "list[str]":
    """Every same-line `<label>: <value>` in the structural text, stripped
    (so a CRLF line ending's `\\r` is not part of the value). The value
    never extends onto the following line, so a blank field stays blank."""
    pattern = rf"^[ \t]*{re.escape(label)}:[ \t]*(.*?)[ \t]*$"
    return [value.strip() for value in re.findall(pattern, structural_text, re.IGNORECASE | re.MULTILINE)]


def _parse_concrete_trace_response(text: str) -> dict:
    """Lexical-only extraction of the raw, UNVALIDATED fields from a
    Concrete Trace response -- makes no judgment about whether any of
    them are actually grounded or self-consistent; that is
    `_validate_concrete_trace`'s job. Never raises: a response missing a
    section simply yields `None`/`[]` for that piece.

    `Example scenario`, `Outcome`, and `Blocking step` are read only from
    the STRUCTURAL text -- the response with every citation's contents
    removed -- so cited repository text can never supply or duplicate one
    of them. A response whose structure is ambiguous (see
    `structural_error`) is reported, never guessed into a shape: step
    numbers other than exactly 1..N, a `Citation:` label or numbered item
    outside any recognized step, a step without a usable Note, or a repeated
    scenario/outcome/blocking-step field."""
    text = text or ""
    headers = list(_TRACE_STEP_HEADER_RE.finditer(text))

    trace_steps = []
    printed_numbers = []
    structural_parts = []
    cursor = 0
    for i, header in enumerate(headers):
        span_end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        notes = list(_TRACE_NOTE_LINE_RE.finditer(text, header.end(), span_end))
        citation_end = notes[-1].start() if notes else span_end
        trace_steps.append({
            "citation": text[header.end():citation_end].strip(),
            "note": notes[-1].group(1).strip() if notes else "",
        })
        printed_numbers.append(int(header.group(1)))
        structural_parts.append(text[cursor:header.end()])
        cursor = citation_end
    structural_parts.append(text[cursor:])
    # Joined on newlines so removing a citation never splices two lines together.
    structural_text = "\n".join(structural_parts)

    scenarios = _structural_fields(structural_text, "Example scenario")
    outcomes = _structural_fields(structural_text, "Outcome")
    blocking_steps = _structural_fields(structural_text, "Blocking step")

    structural_error = None
    if printed_numbers != list(range(1, len(printed_numbers) + 1)):
        structural_error = "trace_step_numbering_invalid"
    elif (
        len(_CITATION_LABEL_RE.findall(structural_text)) != len(headers)
        or len(_NUMBERED_ITEM_RE.findall(structural_text)) != len(headers)
    ):
        structural_error = "unrecognized_trace_step"
    elif any(_is_blank_or_placeholder(step["note"]) for step in trace_steps):
        structural_error = "trace_step_note_missing"
    elif len(scenarios) > 1 or len(outcomes) > 1 or len(blocking_steps) > 1:
        structural_error = "duplicate_terminal_field"

    return {
        "example_scenario": scenarios[0] if scenarios else None,
        "trace_steps": trace_steps,
        "outcome_raw": outcomes[0].upper() if outcomes and outcomes[0] else None,
        "blocking_step_raw": blocking_steps[0] if blocking_steps else None,
        "structural_error": structural_error,
    }


def _is_blank_or_placeholder(value: "Optional[str]") -> bool:
    v = (value or "").strip().lower()
    return not v or v in ("none", "n/a", "unknown")


def _validate_concrete_trace(parsed: dict, code_context: str, patch: str) -> dict:
    """The sole authority over whether a Concrete Trace response is
    ACCEPTED -- the LLM's own `Outcome:` line is never trusted directly;
    every branch below either fully re-derives the returned `outcome`
    from independently-checked evidence or falls through to UNRESOLVED.
    Mirrors `_derive_default_execution_reachability`'s own discipline:
    an unresolved/invalid component at any step propagates, no branch
    reaches REACHED/BLOCKED from an ungrounded or malformed input.

    Returns a dict with exactly the four public schema keys
    (`example_scenario`, `trace_steps`, `outcome`, `blocking_step_index`)
    plus one diagnostic-only key, `invalid_reason` (`None` on success,
    else a short machine-readable reason -- for inspection, never for
    programmatic branching by any other caller).

    NOT checked here, and not checkable here -- see this module's own
    "KNOWN LIMITATION" docstring paragraph: whether a `REACHED`/`BLOCKED`
    verdict actually corresponds to the FINAL problematic outcome, rather
    than merely to the concern's own named intermediate mechanism, is
    enforced entirely by the prompt's task instructions, not by anything
    below. A fully self-consistent, well-cited trace that stops at the
    named mechanism and claims `REACHED` passes every check here."""
    example_scenario = parsed.get("example_scenario")
    trace_steps = parsed.get("trace_steps")
    outcome_raw = parsed.get("outcome_raw")
    blocking_step_raw = parsed.get("blocking_step_raw")

    def unresolved(reason: str) -> dict:
        return {
            "example_scenario": example_scenario,
            "trace_steps": trace_steps if isinstance(trace_steps, list) else [],
            "outcome": "UNRESOLVED",
            "blocking_step_index": None,
            "invalid_reason": reason,
        }

    if parsed.get("structural_error"):
        return unresolved(parsed["structural_error"])

    if not isinstance(example_scenario, str) or _is_blank_or_placeholder(example_scenario):
        return unresolved("example_scenario_blank_or_missing")

    if not isinstance(trace_steps, list):
        return unresolved("trace_steps_wrong_type")
    for step in trace_steps:
        if (
            not isinstance(step, dict)
            or not isinstance(step.get("citation"), str)
            or not isinstance(step.get("note"), str)
        ):
            return unresolved("trace_step_wrong_type")

    if outcome_raw not in OUTCOME_VALUES:
        return unresolved("outcome_outside_enum")

    if outcome_raw == "UNRESOLVED":
        return unresolved("model_reported_unresolved")

    if not trace_steps:
        return unresolved("no_trace_steps")

    # Every step's citation must be mechanically present in the SAME
    # evidence Challenger itself received -- a single ungrounded step
    # anywhere in the chain makes the whole trace untrustworthy,
    # regardless of which step the final verdict hinges on (deliberately
    # stricter than "only the decisive step needs a citation").
    if not all(_point_citation_valid(step["citation"], code_context, patch) for step in trace_steps):
        return unresolved("invalid_trace_citation")

    if outcome_raw == "REACHED":
        if not _is_blank_or_placeholder(blocking_step_raw):
            return unresolved("reached_with_blocking_index")
        return {
            "example_scenario": example_scenario,
            "trace_steps": trace_steps,
            "outcome": "REACHED",
            "blocking_step_index": None,
            "invalid_reason": None,
        }

    # outcome_raw == "BLOCKED"
    if _is_blank_or_placeholder(blocking_step_raw):
        return unresolved("blocked_without_blocking_index")
    try:
        # The model prints 1-indexed step numbers (matching its own
        # `N. Citation:` headers); the returned `blocking_step_index` is
        # 0-indexed into `trace_steps`, the directly usable convention.
        printed_index = int(str(blocking_step_raw).strip())
    except ValueError:
        return unresolved("blocking_index_not_integer")
    index = printed_index - 1
    if index < 0 or index >= len(trace_steps):
        return unresolved("blocking_index_out_of_range")

    return {
        "example_scenario": example_scenario,
        "trace_steps": trace_steps,
        "outcome": "BLOCKED",
        "blocking_step_index": index,
        "invalid_reason": None,
    }


def resolve_concrete_trace(
    *, concern_role: str, description: str, code_context: str, patch: str, llm,
) -> dict:
    """Make EXACTLY ONE `llm.complete()` call and return the deterministically-
    validated Concrete Trace result for one concern.

    Parameters are intentionally exhaustive -- see this module's own
    "INPUT ISOLATION" docstring paragraph: there is no parameter for
    `vulnerability_text` or any Challenger atomic/derived field, so it is
    structurally impossible for a caller to forward one, even by mistake.

    Returns a dict with keys: `example_scenario`, `trace_steps` (list of
    `{"citation", "note"}`), `outcome` (one of `OUTCOME_VALUES`),
    `blocking_step_index` (int or `None`), `invalid_reason` (diagnostic
    only), `raw_response` (the model's own unmodified text, preserved for
    inspection regardless of validation outcome), and `llm_calls_made`
    (always `1` -- this function never calls `llm.complete()` more than
    once, under any input)."""
    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    user_message = (
        "## Concern\n\n"
        f"Role: {concern_role}\n"
        f"Description: {description}\n\n"
        "## Repository evidence\n\n" + (code_context or "") + "\n\n"
        "## Proposed patch\n\n" + (patch or "")
    )
    raw_response = llm.complete(system_prompt, user_message, stage="concrete_trace")

    parsed = _parse_concrete_trace_response(raw_response)
    validated = _validate_concrete_trace(parsed, code_context or "", patch or "")

    validated["raw_response"] = raw_response
    validated["llm_calls_made"] = 1
    return validated
