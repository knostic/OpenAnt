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

# Matches the first fenced block tagged diff, patch, or udiff.
# Non-greedy so we stop at the first closing fence.
_FENCE_RE = re.compile(
    r"```(?:diff|patch|udiff)[ \t]*\r?\n(.*?)```",
    re.DOTALL,
)


def _extract_diff_block(raw: str) -> str:
    """Return the first fenced diff/patch/udiff block found in raw.

    The block is normalised to a ```diff fence.
    Falls back to raw.strip() if no fenced block is present.
    """
    if not raw:
        return raw or ""
    m = _FENCE_RE.search(raw)
    if m:
        return "```diff\n" + m.group(1) + "```"
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
        or the raw response stripped if no fenced block is found.
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
