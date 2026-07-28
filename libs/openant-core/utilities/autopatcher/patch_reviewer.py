"""
Patch reviewer stage.

Loads the patch_reviewer prompt, combines the vulnerability description with the
generated patch, and asks the LLM to produce an explanation, list of affected
areas, and validation notes.
"""

from __future__ import annotations

from pathlib import Path

from .llm_client import LLMClient

_PROMPT_PATH = Path(__file__).parent / "prompts" / "patch_reviewer.md"


def review_patch(
    vulnerability_text: str,
    patch: str,
    llm: LLMClient,
) -> str:
    """
    Review a generated patch and return structured analysis.

    Parameters
    ----------
    vulnerability_text:
        The original vulnerability description and code context.
    patch:
        The unified diff patch produced by :func:`patch_generator.generate_patch`.
    llm:
        An initialised :class:`LLMClient` instance.

    Returns
    -------
    str
        The raw LLM response containing explanation, affected areas, and
        validation notes.
    """
    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    user_message = (
        "## Vulnerability report\n\n"
        + vulnerability_text
        + "\n\n## Proposed patch\n\n"
        + patch
    )
    return llm.complete(system_prompt, user_message, stage="patch_review")
