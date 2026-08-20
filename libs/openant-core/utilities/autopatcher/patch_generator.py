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
    user_message = "## Vulnerability report\n\n" + vulnerability_text
    if code_context:
        user_message += "\n\n## Repository code context\n\n" + code_context
    if retry_hint:
        user_message += "\n\n## Retry instruction\n\n" + retry_hint

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
    raw = generate_patch_raw(vulnerability_text, llm, code_context=code_context, retry_hint=retry_hint)
    return classify_patch_response(raw).diff
