"""
Patch generator stage.

Loads the patch_generator prompt, builds a user message from the vulnerability
description, calls the LLM, and classifies/extracts a clean unified diff block
from the response against the response contract stated in
prompts/patch_generator.md ("exactly one fenced diff block, nothing else").

Response classification (classify_patch_response) is pure and deterministic
-- no LLM calls, no I/O -- and is kept separate from LLM orchestration on
purpose: a bounded contract-violation retry is a decision about WHETHER to
call the model again, which belongs to a caller (pipeline.py), not to this
module. generate_patch() itself still makes exactly one LLM call, same as
before; generate_patch_raw() is the lower-level primitive a caller can use
directly when it needs to inspect the classification before deciding what to
do next (see pipeline.py's _generate_patch_with_contract_check).
"""

from __future__ import annotations

import datetime
import os
import re
from pathlib import Path
from typing import NamedTuple

from .llm_client import LLMClient

_PROMPT_PATH = Path(__file__).parent / "prompts" / "patch_generator.md"

# The exact fixed strings generate_patch_raw() wraps around vulnerability_text/
# code_context/retry_hint -- shared with compute_patch_generation_capacity()
# below so the overhead a capacity calculation counts and the overhead an
# actual request sends can never independently drift apart (one caller
# computing a ceiling with the actual scaffolding, the request itself
# assembled with a different one, would silently reopen the same
# unders-counted-overhead gap Fix B exists to close).
_VULN_HEADER = "## Vulnerability report\n\n"
_CODE_CONTEXT_HEADER = "\n\n## Repository code context\n\n"
_RETRY_HEADER = "\n\n## Retry instruction\n\n"

# The section label treated as REQUIRED by fit_patch_generation_context() at
# every real call site (pipeline.py) that has one: the Final-Target
# Remediation Slice (or, for Post-Patch Recovery regeneration, its recovered
# replacement occupying the same conceptual slot) -- the one context section
# whose presence is not incidental but is what Edit Readiness/Post-Patch
# Recovery's own existing deterministic gates already require before Patch
# Generation is allowed to run at all (see pipeline.py's `_edit_readiness.
# edit_source_ready` / `_post_patch_recovery.ready_for_regeneration` checks).
# Reused verbatim by every call site so "required" can never mean something
# different at one than at another.
PATCH_GENERATION_REQUIRED_LABEL = "final_target_slice"

# Matches an opening fence line tagged diff, patch, or udiff. Must start at
# column 0 (no leading whitespace) so a diff-prefixed hunk line (" ```",
# "+```", "-```") can never be mistaken for one — every unified-diff
# hunk-body line is required to start with a space/+/-/\ prefix, never a
# bare fence character.
_OPEN_FENCE_RE = re.compile(r"^(`{3,}|~{3,})(diff|patch|udiff)[ \t]*$")


def _matching_close(line: str, fence_char: str, fence_len: int) -> bool:
    """True if line is a valid closer for an opener of fence_char/fence_len.

    Must start at column 0, use the same fence character, be at least as
    long as the opener, and contain nothing else but optional trailing
    spaces/tabs. Column-0 anchoring (no leading-whitespace tolerance) is
    what keeps a diff context line reproducing an unchanged fence (e.g.
    " ```" with its mandatory single leading space) from ever matching.
    """
    content = line.rstrip("\r\n")
    m = re.match(rf"^({re.escape(fence_char)}+)[ \t]*$", content)
    return bool(m) and len(m.group(1)) >= fence_len


class PatchResponseClassification(NamedTuple):
    """Deterministic classification of one raw Patch Generator LLM response
    against the response contract stated in prompts/patch_generator.md
    ("Output one fenced code block tagged diff... Nothing else. No
    alternative patches."). Pure -- no LLM calls, no I/O.

    status:
      "valid"              -- exactly one well-formed fenced diff/patch/udiff
                               block, with only whitespace (if anything)
                               before and after it. `diff` is the body,
                               normalised to a ```diff fence.
      "no_diff"            -- no recognised fenced opener anywhere in the
                               response. `diff` is raw.strip() -- the
                               response may be a genuine unfenced diff, or
                               plain prose (e.g. an honest "no patch is
                               possible"); downstream repair/hygiene/
                               applicability already sorts this out
                               naturally, and retrying a genuine non-answer
                               as if it were a formatting problem risks
                               pressuring a fabricated diff out of a model
                               that had nothing to add. Never retried by
                               callers -- see pipeline.py's
                               _generate_patch_with_contract_check.
      "malformed_fence"    -- a recognised opener exists but is never
                               validly closed: EOF reached with no matching
                               closer, or a second recognised opener appears
                               before the first block's own closer. `diff`
                               is "" -- this is a stronger signal of broken
                               structured output than "no_diff", and a
                               stricter format instruction would not fix a
                               truncated response. Never retried.
      "contract_violation" -- one or more well-formed blocks exist, but the
                               response is not "exactly one clean block with
                               only whitespace around it": either 2+
                               complete blocks (`block_count` > 1 -- e.g.
                               alternative candidates), or exactly one block
                               with non-whitespace text before and/or after
                               it. `diff` is "" -- callers must not treat
                               any candidate body as a patch. This is the
                               ONLY status eligible for a bounded,
                               orchestration-level regeneration retry.

    block_count: number of well-formed, independently-closed blocks found
                 (0 for "no_diff" and "malformed_fence").
    """
    status: str
    diff: str
    block_count: int


def classify_patch_response(raw: str) -> PatchResponseClassification:
    """Classify a raw Patch Generator response — see
    PatchResponseClassification for the four possible states.

    Reuses _OPEN_FENCE_RE/_matching_close (the same column-0, diff-prefix-
    aware fence detection _extract_diff_block has always used) but, unlike
    a single-block scan, keeps scanning after each well-formed block's
    closer instead of returning immediately — so a second (or third)
    complete block is counted rather than silently discarded. A recognised
    opener that never validly closes (EOF, or a second opener appearing
    before ITS OWN closer) still fails the whole response closed as
    "malformed_fence", exactly as before: this is not "close enough" and is
    never merged with, or skipped in favour of, any other block.
    """
    if not raw:
        return PatchResponseClassification("no_diff", raw or "", 0)

    lines = raw.splitlines(keepends=True)
    n = len(lines)
    blocks: list[tuple[int, int, list[str]]] = []  # (opener_idx, closer_idx, body_lines)
    i = 0
    while i < n:
        m = _OPEN_FENCE_RE.match(lines[i].rstrip("\r\n"))
        if not m:
            i += 1
            continue
        fence_run = m.group(1)
        fence_char = fence_run[0]
        fence_len = len(fence_run)
        body_lines: list[str] = []
        closer_idx: int | None = None
        j = i + 1
        while j < n:
            candidate = lines[j].rstrip("\r\n")
            if _matching_close(lines[j], fence_char, fence_len):
                closer_idx = j
                break
            if _OPEN_FENCE_RE.match(candidate):
                # A second recognised opener before this block's own closer
                # — this block is malformed, not "close enough" — and
                # invalidates the whole response, regardless of any earlier
                # well-formed block already collected.
                return PatchResponseClassification("malformed_fence", "", 0)
            body_lines.append(lines[j])
            j += 1
        if closer_idx is None:
            # Recognised opener reached EOF with no matching closer.
            return PatchResponseClassification("malformed_fence", "", 0)
        blocks.append((i, closer_idx, body_lines))
        i = closer_idx + 1

    if not blocks:
        return PatchResponseClassification("no_diff", raw.strip(), 0)

    if len(blocks) > 1:
        return PatchResponseClassification("contract_violation", "", len(blocks))

    opener_idx, closer_idx, body_lines = blocks[0]
    prefix = "".join(lines[:opener_idx])
    suffix = "".join(lines[closer_idx + 1:])
    if prefix.strip() or suffix.strip():
        return PatchResponseClassification("contract_violation", "", 1)

    return PatchResponseClassification("valid", "```diff\n" + "".join(body_lines) + "```", 1)


def _extract_diff_block(raw: str) -> str:
    """Return the single valid fenced diff/patch/udiff block found in raw,
    normalised to a ```diff fence — or "" / raw.strip() for every other
    classification (see classify_patch_response, which this now delegates
    to). Kept as a thin wrapper for backward compatibility with existing
    callers/tests; classify_patch_response is the source of truth.

    Behavior for "no_diff" and "malformed_fence" is byte-identical to
    before this function existed in terms of classification (raw.strip()
    and "" respectively). Behavior for what classify_patch_response calls
    "contract_violation" previously returned the FIRST candidate block
    silently — that was the actual bug this change fixes; it now returns
    "" like any other invalid response, never an arbitrarily-selected
    candidate.
    """
    return classify_patch_response(raw).diff


def generate_patch_raw(
    vulnerability_text: str,
    llm: LLMClient,
    code_context: str = "",
    retry_hint: str = "",
    stage: str = "patch_generation",
) -> str:
    """
    Make exactly one Patch Generator LLM call and return its raw text,
    unclassified. This is generate_patch()'s own body minus the final
    classification/extraction step -- factored out so a caller that needs
    to inspect the classification before deciding what to do next (e.g.
    pipeline.py's bounded contract-violation retry) can do so without
    duplicating the prompt-assembly logic below, and without generate_patch
    itself losing the "makes exactly one call" property.

    Parameters
    ----------
    vulnerability_text, llm, code_context, retry_hint:
        Same meaning as generate_patch().
    stage:
        The `stage` label passed to llm.complete() — purely an observability
        tag for the LLM call tracer (see llm_client.LLMClient.complete);
        it never affects the request or the returned text. Defaults to
        "patch_generation" (identical to generate_patch()'s hardcoded
        value, so every pre-existing caller is unaffected). A caller
        making a second, related call — e.g. a contract-violation retry —
        should pass a distinct value (e.g. "patch_generation_contract_retry")
        so the two calls remain distinguishable in a trace.

    Returns
    -------
    str
        The raw, unclassified LLM response text.
    """
    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    user_message = _VULN_HEADER + vulnerability_text
    if code_context:
        user_message += _CODE_CONTEXT_HEADER + code_context
    if retry_hint:
        user_message += _RETRY_HEADER + retry_hint

    if os.environ.get("AUTOPATCHER_DEBUG"):
        _debug_dir = Path("reports") / "debug"
        _debug_dir.mkdir(parents=True, exist_ok=True)
        _ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        (_debug_dir / f"prompt_{_ts}.txt").write_text(user_message, encoding="utf-8")

    return llm.complete(system_prompt, user_message, stage=stage)


def generate_patch(
    vulnerability_text: str,
    llm: LLMClient,
    code_context: str = "",
    retry_hint: str = "",
    stage: str = "patch_generation",
) -> str:
    """
    Generate a patch for the given vulnerability description.

    Parameters
    ----------
    vulnerability_text:
        The full text from the vulnerability input (description + code context).
    llm:
        An initialised :class:`LLMClient` instance.
    code_context:
        Optional source code extracted from the target repository.  When
        provided, it is appended to the user message so the LLM can produce
        a patch against real code rather than invented placeholders.
    retry_hint:
        When non-empty, appended as a "## Retry instruction" section to the
        user message.  Used by the applicability-aware retry path to tell the
        model what went wrong and to use only the provided code context.
    stage:
        The `stage` label passed to llm.complete() — purely an observability/
        ownership tag for the LLM call tracer (see generate_patch_raw's own
        `stage` parameter, which this forwards to unchanged). Defaults to
        "patch_generation" so every pre-existing caller is unaffected. A
        caller regenerating a patch for a DIFFERENT canonical replay stage
        than the one that owns plain "patch_generation" — e.g. the
        Challenger-driven repair loop, which is
        patch_repair_and_calibration's own regeneration, not
        patch_generation_and_post_patch_investigation's — must pass a
        distinct value so the two stages' LLM calls stay unambiguous in a
        trace and for stage-replay LLM-ownership enforcement. Never changes
        the prompt content or the request itself.

    Returns
    -------
    str
        The single valid unified diff block extracted from the LLM
        response; the raw response stripped if no fenced block is found;
        or "" if the response was structurally invalid — a fence opened
        but never validly closed, OR the response contained more than one
        candidate diff block, OR a single block with non-whitespace prose
        around it (see classify_patch_response). Still exactly one LLM
        call — no retry logic lives here; see pipeline.py's
        _generate_patch_with_contract_check for the bounded
        contract-violation retry built on top of generate_patch_raw().
    """
    raw = generate_patch_raw(vulnerability_text, llm, code_context=code_context, retry_hint=retry_hint, stage=stage)
    return classify_patch_response(raw).diff


# ---------------------------------------------------------------------------
# Fix B: Patch Generation combined-request technical-capacity contract.
#
# generate_patch_raw() sends ONE real request whose total size is
# system_prompt + _VULN_HEADER + vulnerability_text + (_CODE_CONTEXT_HEADER +
# code_context, if code_context) + (_RETRY_HEADER + retry_hint, if
# retry_hint). Every caller that decides what `code_context` may contain
# must size it against what the OTHER pieces of that same request already
# cost -- never against the system prompt and vulnerability_text alone, and
# never independently of whether a retry_hint will also be present. The two
# functions below are the ONE place that computation happens, so the
# initial call and every retry call necessarily share it; see
# utilities.autopatcher.technical_capacity for the underlying per-call
# source-capacity equation this builds on (unchanged, reused as-is).
# ---------------------------------------------------------------------------


def compute_patch_generation_capacity(vulnerability_text, retry_hint="", *, reserved_output_tokens=None):
    """Real remaining capacity (in characters) for `code_context` in the
    ACTUAL Patch Generator request that will be sent -- accounts for every
    fixed string generate_patch_raw() itself sends alongside it: the
    system prompt (`_PROMPT_PATH`), `_VULN_HEADER` + `vulnerability_text`,
    `_CODE_CONTEXT_HEADER`'s own fixed text, and -- only when a retry is
    actually happening -- `_RETRY_HEADER` + the exact `retry_hint` text.
    `retry_hint=""` (the default, matching the initial call) omits that
    last term entirely, exactly mirroring generate_patch_raw()'s own `if
    retry_hint:` guard.

    Returns a `technical_capacity.SourceCapacityResult` -- `.source_capacity_
    chars` is the ceiling `code_context` must fit within to guarantee the
    combined request never exceeds real per-call technical capacity."""
    from .llm_client import resolve_active_model, resolve_max_tokens
    from .technical_capacity import compute_source_capacity

    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    known_overhead_chars = (
        len(system_prompt) + len(_VULN_HEADER) + len(vulnerability_text or "") + len(_CODE_CONTEXT_HEADER)
    )
    if retry_hint:
        known_overhead_chars += len(_RETRY_HEADER) + len(retry_hint)
    provider, model = resolve_active_model()
    return compute_source_capacity(
        provider, model,
        reserved_output_tokens=(resolve_max_tokens() if reserved_output_tokens is None else reserved_output_tokens),
        known_overhead_chars=known_overhead_chars,
    )


class PatchGenerationContextPlan(NamedTuple):
    """Result of fitting Patch Generation's constituent context sections
    (Repository Grounding, Repository Understanding, the Final-Target
    Remediation Slice, etc. -- see pipeline.py's own `_ctx_parts` ordering
    comment) against a real `compute_patch_generation_capacity(...).
    source_capacity_chars` ceiling. Whole-block-or-omit only -- no section's
    text is ever sliced mid-string.

    rendered:          The final "\\n\\n"-joined `code_context` string --
                        exactly what generate_patch_raw() should receive.
    included_sections:  (label, text) pairs actually included, in the SAME
                        relative order they were given -- preserved (not
                        just `included_labels`) so a caller can rebuild a
                        modified section list later (e.g. Post-Patch
                        Recovery swapping the required section's text)
                        without re-parsing the flat `rendered` string.
    included_labels:    Convenience -- just the labels of included_sections.
    omission_reason:    label -> "technical_capacity" for every OPTIONAL
                        section that did not fit.
    omitted_sizes:      label -> that section's full whole-block size, for
                        every entry in omission_reason (and, when
                        `required_missing` is True, for `required_label`
                        too).
    required_missing:   True only when `required_label` was given, its
                        section was non-empty, and it alone did not fit
                        within `max_chars` -- the caller MUST fail closed
                        (never send the request) rather than treat the
                        required section as one more optional omission.
    max_chars, capacity: The ceiling this plan was fit against, and the
                        full `SourceCapacityResult` it came from (or
                        whatever the caller passed), for provenance/tests.
    """
    rendered: str
    included_sections: "tuple[tuple[str, str], ...]"
    included_labels: "tuple[str, ...]"
    omission_reason: "dict[str, str]"
    omitted_sizes: "dict[str, int]"
    required_missing: bool
    max_chars: int
    capacity: "object | None" = None


def fit_patch_generation_context(sections, max_chars, *, required_label=None, capacity=None):
    """Whole-block-or-omit fit of Patch Generation's context sections
    against `max_chars` (see `compute_patch_generation_capacity`).

    `sections`: an ordered list of (label, text) pairs -- pipeline.py's own
    existing section ordering (see its `_ctx_parts` comment: hand-authored
    plan -> grounding -> patterns -> understanding -> plan text -> planner
    evidence -> verified/strategy semantics -> the Final-Target slice ->
    coverage warning). Empty/blank texts are dropped up front and never
    occupy a label.

    `required_label`: when given and its section is present (non-empty),
    that section's whole text is reserved FIRST and is never dropped for
    capacity -- see PATCH_GENERATION_REQUIRED_LABEL. Every OTHER present
    section is optional: included whole, in the SAME order `sections` was
    given, as long as what remains after the required reservation still
    fits it; otherwise omitted whole (never truncated) and recorded in
    `omission_reason`/`omitted_sizes`. No new importance ranking is
    introduced beyond this required/optional split -- optional sections
    compete for remaining room in the exact order the caller already
    renders them in, the same order pipeline.py has always assembled
    `code_context` in; nothing here re-prioritizes them.

    `required_label` given but its section does not fit `max_chars` even
    alone: returns `required_missing=True` with an EMPTY `rendered` -- the
    caller must fail Patch Generation closed for this request, never send
    a request missing evidence Edit Readiness/Post-Patch Recovery already
    established as required."""
    present = [(label, text) for label, text in sections if text and text.strip()]
    required_text = ""
    if required_label is not None:
        required_text = next((text for label, text in present if label == required_label), "")

    if required_text and len(required_text) > max_chars:
        return PatchGenerationContextPlan(
            rendered="", included_sections=(), included_labels=(),
            omission_reason={}, omitted_sizes={required_label: len(required_text)},
            required_missing=True, max_chars=max_chars, capacity=capacity,
        )

    remaining = max_chars - len(required_text)
    have_any = bool(required_text)
    included_labels_seen = {required_label} if required_text else set()
    omission_reason: "dict[str, str]" = {}
    omitted_sizes: "dict[str, int]" = {}
    for label, text in present:
        if label == required_label:
            continue
        cost = len(text) + (2 if have_any else 0)  # "\n\n" join separator
        if cost <= remaining:
            included_labels_seen.add(label)
            remaining -= cost
            have_any = True
        else:
            omission_reason[label] = "technical_capacity"
            omitted_sizes[label] = len(text)

    included_sections = tuple((label, text) for label, text in present if label in included_labels_seen)
    included_labels = tuple(label for label, _ in included_sections)
    rendered = "\n\n".join(text for _, text in included_sections)
    return PatchGenerationContextPlan(
        rendered=rendered, included_sections=included_sections, included_labels=included_labels,
        omission_reason=omission_reason, omitted_sizes=omitted_sizes,
        required_missing=False, max_chars=max_chars, capacity=capacity,
    )
