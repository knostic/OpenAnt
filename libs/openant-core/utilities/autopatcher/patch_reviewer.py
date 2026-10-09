"""
Patch reviewer stage.

Loads the patch_reviewer prompt, combines the vulnerability description with the
generated patch, and asks the LLM to produce an explanation, list of affected
areas, and validation notes.
"""

from __future__ import annotations

from pathlib import Path

from .finding_calibration import format_calibration_for_prompt
from .llm_client import LLMClient

_PROMPT_PATH = Path(__file__).parent / "prompts" / "patch_reviewer.md"


def review_patch(
    vulnerability_text: str,
    patch: str,
    llm: LLMClient,
    finding_calibration: "list[dict] | None" = None,
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
    finding_calibration:
        Optional, already-computed output of
        :func:`finding_calibration.calibrate_findings` (a list of
        {"original", "group", "reworded"} dicts). When given, it is
        rendered as a concise, clearly-labeled section appended to the
        prompt so this review builds on the pipeline's own already-
        calibrated conclusions instead of independently re-deriving (and
        potentially contradicting) a concern calibration already
        resolved. Omitted (the default) preserves the exact prior
        prompt -- every existing caller is unaffected.

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
    calibration_section = format_calibration_for_prompt(finding_calibration)
    if calibration_section:
        user_message += "\n\n" + calibration_section
    return llm.complete(system_prompt, user_message, stage="patch_review")
