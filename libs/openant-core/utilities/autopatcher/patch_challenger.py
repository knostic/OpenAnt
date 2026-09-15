"""
Adversarial patch challenger.

Provides `challenge_patch(vulnerability_text, patch)` which returns a small
structured dict describing edge cases and potential issues discovered by an
LLM-based adversarial check. Uses `LLMClient` (mock-capable) to make queries.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_PROMPT_PATH = Path(__file__).parent / "prompts" / "patch_challenger.md"

VERIFICATION_STATUSES = ("VERIFIED_FIXED", "RESIDUAL_VULNERABILITY", "INSUFFICIENT_EVIDENCE")
"""The only three states a NEW-format Challenger response may authoritatively
report -- see `_parse_verification`'s docstring for how this interacts with
the legacy `still_vulnerable` boolean and with malformed/missing input."""


def _split_sections(text: str) -> Dict[str, str]:
    # Look for section headers used in the prompt and capture their bodies.
    pattern = re.compile(
        r"^(Verification status:|Still vulnerable:|Edge cases:|Potential issues:|Summary:)",
        re.IGNORECASE | re.MULTILINE,
    )
    parts = pattern.split(text)
    # parts will be: [pre, header1, body1, header2, body2, ...]
    sections = {
        "verification_status": "", "still_vulnerable": "",
        "edge_cases": "", "potential_issues": "", "summary": "",
    }
    i = 1
    while i < len(parts) - 1:
        header = parts[i].strip().lower()
        body = parts[i + 1].strip()
        if header.startswith("verification status"):
            sections["verification_status"] = body.splitlines()[0].strip() if body else ""
        elif header.startswith("still vulnerable"):
            sections["still_vulnerable"] = body.splitlines()[0].strip() if body else ""
        elif header.startswith("edge cases"):
            sections["edge_cases"] = body.strip()
        elif header.startswith("potential issues"):
            sections["potential_issues"] = body.strip()
        elif header.startswith("summary"):
            sections["summary"] = body.strip()
        i += 2
    return sections


def _parse_verification(sections: Dict[str, str]) -> Tuple[Optional[str], bool]:
    """Return `(verification_status, still_vulnerable)` from already-split
    response sections.

    `verification_status` is the authoritative NEW-format signal -- one of
    `VERIFICATION_STATUSES`, or `None` when it cannot be established (no
    "Verification status:" header in the response, an unrecognized value in
    that header, or a purely legacy "Still vulnerable:"-only response).
    `still_vulnerable` is a backward-compatible projection, kept for every
    pre-existing consumer that only knows this boolean.

    Three distinct paths, in order:

    1. NEW-format header present. The first line of its body is matched
       case-insensitively against `VERIFICATION_STATUSES`.
         - Recognized  -> that literal; `still_vulnerable = (literal !=
           "VERIFIED_FIXED")`.
         - Unrecognized (garbage/extra prose/hallucinated value) -> fails
           closed: `(None, True)`. A malformed NEW-format answer must never
           be read as "VERIFIED_FIXED".
    2. NEW-format header absent, LEGACY "Still vulnerable:" header present.
       `verification_status` stays `None` -- an old Yes/No answer cannot be
       reconstructed into the richer tri-state after the fact -- but
       `still_vulnerable` is read directly from that legacy text via the
       ORIGINAL yes/true/1 regex, unchanged from before this function
       existed: legacy "No" -> `(None, False)`, legacy "Yes" -> `(None,
       True)`. This is deliberately NOT computed as `verification_status !=
       "VERIFIED_FIXED"` (that would incorrectly turn a legacy "No" into
       `True`, since `verification_status` is `None` here).
    3. Neither header present at all (empty/fully malformed response) ->
       fails closed: `(None, True)`.
    """
    new_raw = sections.get("verification_status", "")
    if new_raw:
        token = new_raw.strip().upper()
        if token in VERIFICATION_STATUSES:
            return token, token != "VERIFIED_FIXED"
        return None, True  # NEW-format header present but unrecognized body

    legacy_raw = sections.get("still_vulnerable", "")
    if legacy_raw:
        return None, bool(re.search(r"\b(yes|true|1)\b", legacy_raw, re.IGNORECASE))

    return None, True  # neither header present at all


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

    Returns a dict with keys: `verification_status` (one of
    `VERIFICATION_STATUSES`, or `None` -- see `_parse_verification`),
    `still_vulnerable` (bool, a backward-compatible projection derived from
    `verification_status` -- never independently set), `edge_cases`
    (list[str]), `potential_issues` (list[str]), and `summary` (str).
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

    verification_status, still = _parse_verification(sections)

    edge_cases = _lines_from_bullets(sections.get("edge_cases", ""))
    potential_issues = _lines_from_bullets(sections.get("potential_issues", ""))
    summary = sections.get("summary", resp.strip())

    return {
        "verification_status": verification_status,
        "still_vulnerable": still,
        "edge_cases": edge_cases,
        "potential_issues": potential_issues,
        "summary": summary,
    }
