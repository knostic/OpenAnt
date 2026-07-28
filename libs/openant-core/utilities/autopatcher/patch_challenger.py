"""
Adversarial patch challenger.

Provides `challenge_patch(vulnerability_text, patch)` which returns a small
structured dict describing edge cases and potential issues discovered by an
LLM-based adversarial check. Uses `LLMClient` (mock-capable) to make queries.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict

_PROMPT_PATH = Path(__file__).parent / "prompts" / "patch_challenger.md"


def _split_sections(text: str) -> Dict[str, str]:
    # Look for section headers used in the prompt and capture their bodies.
    pattern = re.compile(r"^(Still vulnerable:|Edge cases:|Potential issues:|Summary:)", re.IGNORECASE | re.MULTILINE)
    parts = pattern.split(text)
    # parts will be: [pre, header1, body1, header2, body2, ...]
    sections = {"still_vulnerable": "", "edge_cases": "", "potential_issues": "", "summary": ""}
    i = 1
    while i < len(parts) - 1:
        header = parts[i].strip().lower()
        body = parts[i + 1].strip()
        if header.startswith("still vulnerable"):
            sections["still_vulnerable"] = body.splitlines()[0].strip() if body else ""
        elif header.startswith("edge cases"):
            sections["edge_cases"] = body.strip()
        elif header.startswith("potential issues"):
            sections["potential_issues"] = body.strip()
        elif header.startswith("summary"):
            sections["summary"] = body.strip()
        i += 2
    return sections


def _lines_from_bullets(text: str) -> List[str]:
    if not text:
        return []
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Remove leading bullet markers
        line = re.sub(r"^[-*+]\s*", "", line)
        lines.append(line)
    return lines


def challenge_patch(vulnerability_text: str, patch: str, llm, code_context: str = "") -> dict:
    """
    Run an adversarial challenger against a proposed patch.

    Parameters
    ----------
    vulnerability_text:
        The original vulnerability description.
    patch:
        The unified diff patch.
    llm:
        An initialised :class:`LLMClient` instance.
    code_context:
        Optional repository evidence selected by static analysis. When
        provided it is prepended to the user message so the challenger
        reasons from the same evidence the patch generator and confidence
        scorer used, instead of the diff and vulnerability text alone.

    Returns a dict with keys: `still_vulnerable` (bool), `edge_cases` (list[str]),
    `potential_issues` (list[str]), and `summary` (str).
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
    )

    resp = llm.complete(system_prompt, user_message, stage="challenger")

    sections = _split_sections(resp)

    still_raw = sections.get("still_vulnerable", "no")
    still = bool(re.search(r"\b(yes|true|1)\b", still_raw, re.IGNORECASE))

    edge_cases = _lines_from_bullets(sections.get("edge_cases", ""))
    potential_issues = _lines_from_bullets(sections.get("potential_issues", ""))
    summary = sections.get("summary", resp.strip())

    return {
        "still_vulnerable": still,
        "edge_cases": edge_cases,
        "potential_issues": potential_issues,
        "summary": summary,
    }
