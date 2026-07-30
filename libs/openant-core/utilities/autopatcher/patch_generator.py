"""
Patch generator stage.

Loads the patch_generator prompt, builds a user message from the vulnerability
description, calls the LLM, and extracts the first clean unified diff block
from the response.
"""

from __future__ import annotations

import datetime
import os
import re
from pathlib import Path

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


def _find_fenced_diff_block(raw: str) -> str | None:
    """Scan raw for the first ```/~~~-fenced diff/patch/udiff block.

    Returns the body text between a recognised opener and its matching
    closer. Returns None if no recognised opener exists at all, if a
    recognised opener is found but never properly closed before EOF, OR if
    a second recognised opener appears before the first one's closer —
    these cases are deliberately not distinguished here; the caller decides
    what None means in each case.

    The second case is safe to detect this way (rather than skipping to, or
    merging with, the second block) because a genuine diff/patch/udiff
    fence-marker line reproduced as unified-diff hunk content must carry a
    unified-diff prefix (' ', '+', '-', or '\\') and therefore can never
    match the opener pattern at column 0 — so any column-0 opener seen while
    still scanning for the first block's closer can only be a second,
    independent fenced block, never legitimate content of the first.
    """
    lines = raw.splitlines(keepends=True)
    for i, line in enumerate(lines):
        m = _OPEN_FENCE_RE.match(line.rstrip("\r\n"))
        if not m:
            continue
        fence_run = m.group(1)
        fence_char = fence_run[0]
        fence_len = len(fence_run)
        body_lines: list[str] = []
        for j in range(i + 1, len(lines)):
            candidate = lines[j].rstrip("\r\n")
            if _matching_close(lines[j], fence_char, fence_len):
                return "".join(body_lines)
            if _OPEN_FENCE_RE.match(candidate):
                # A second recognised opener before the first block's closer
                # — the first block is malformed, not "close enough".
                return None
            body_lines.append(lines[j])
        # Recognised opener reached EOF with no matching closer.
        return None
    return None


def _extract_diff_block(raw: str) -> str:
    """Return the first fenced diff/patch/udiff block found in raw.

    The block is normalised to a ```diff fence.

    - No recognised fenced opener at all: falls back to raw.strip() (the
      response is presumably a raw, unfenced diff or plain prose).
    - A recognised opener with a valid closer: returns the body between
      them, normalised to a ```diff fence.
    - A recognised opener with NO valid closer before EOF, OR a second
      recognised opener appearing before the first one's closer
      (malformed/truncated structured output): returns "" rather than
      raw.strip(). This is deliberate and load-bearing, not a stylistic
      choice — repair_hunk_headers and patch_applicability._strip_fences
      both unconditionally strip a leading fence-marker line with no check
      that it was ever closed, so
      handing back raw.strip() here would let those stages silently launder
      truncated-but-syntactically-consistent content into something that
      reports as applicable. An empty string is a no-op in every downstream
      stage (repair_hunk_headers, check_patch, check_applicability all
      special-case falsy/blank input), so it can never be repaired into a
      false "applicable" result.
    """
    if not raw:
        return raw or ""
    body = _find_fenced_diff_block(raw)
    if body is not None:
        return "```diff\n" + body + "```"
    if any(_OPEN_FENCE_RE.match(line.rstrip("\r\n")) for line in raw.splitlines()):
        return ""
    return raw.strip()


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
        The first valid unified diff block extracted from the LLM response,
        the raw response stripped if no fenced block is found, or "" if a
        recognised fence was opened but never closed (see
        ``_extract_diff_block``).
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

    raw = llm.complete(system_prompt, user_message, stage="patch_generation")
    return _extract_diff_block(raw)
