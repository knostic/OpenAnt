"""
Confidence scorer stage.

Loads the confidence_scorer prompt, sends the full context (vulnerability +
patch + review) to the LLM, and returns a structured confidence assessment.
"""

from __future__ import annotations

from pathlib import Path

from .llm_client import LLMClient

_PROMPT_PATH = Path(__file__).parent / "prompts" / "confidence_scorer.md"


def score_confidence(
    vulnerability_text: str,
    patch: str,
    review: str,
    llm: LLMClient,
    code_context: str = "",
) -> str:
    """
    Assign a confidence score to the generated patch.

    Parameters
    ----------
    vulnerability_text:
        The original vulnerability description and code context.
    patch:
        The unified diff patch.
    review:
        The structured patch review (explanation, affected areas, validation
        notes).
    llm:
        An initialised :class:`LLMClient` instance.
    code_context:
        Optional repository evidence selected by static analysis. When
        provided it is prepended to the user message so the scorer reasons
        from the same evidence the patch generator used.

    Returns
    -------
    str
        The raw LLM response containing the confidence score and reasons.
    """
    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    context_section = (
        "## Repository evidence (selected by static analysis)\n\n"
        + code_context
        + "\n\n"
    ) if code_context else ""
    user_message = (
        context_section
        + "## Vulnerability report\n\n"
        + vulnerability_text
        + "\n\n## Proposed patch\n\n"
        + patch
        + "\n\n## Patch review\n\n"
        + review
    )
    return llm.complete(system_prompt, user_message, stage="confidence_scorer")
