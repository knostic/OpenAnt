"""
Finding calibration — an LLM post-processing stage that classifies and
rewords challenger findings for calibrated certainty before they reach the
report.

Provides `calibrate_findings(vulnerability_text, patch, findings, llm,
code_context)`, which returns one entry per input finding: which of three
epistemic groups it belongs to (Observed / Hypothesis / Hardening), and a
reworded version whose certainty matches that group.

This is additive to the existing challenger/classifier: it does not change
`_classify_finding`'s categories or counts, and its output is read only by
report presentation (`_build_known_findings` / `_render_known_findings`) —
never by `_compute_trust_signals` or `_build_recommendation_v1`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict

_PROMPT_PATH = Path(__file__).parent / "prompts" / "finding_calibration.md"

_VALID_GROUPS = {"observed", "hypothesis", "hardening"}

# Matches "N. Group: <label>\n   Reworded: <text>" blocks, tolerant of
# leading/trailing whitespace and blank lines between blocks.
_BLOCK_RE = re.compile(
    r"^\s*\d+\.\s*Group:\s*(\w+)\s*\n\s*Reworded:\s*(.+?)(?=\n\s*\d+\.\s*Group:|\Z)",
    re.MULTILINE | re.DOTALL,
)


def _parse_response(resp: str, findings: List[str]) -> List[Dict[str, str]]:
    """Parse the calibration response into one entry per input finding.

    Falls back to the original finding text under group "hypothesis" (the
    most epistemically humble default) for any finding whose block is
    missing or unparseable — every finding must survive, never silently
    dropped, and never upgraded to a stronger-sounding group than what was
    reliably parsed.
    """
    blocks = _BLOCK_RE.findall(resp or "")
    results: List[Dict[str, str]] = []
    for i, original in enumerate(findings):
        if i < len(blocks):
            group_raw, reworded = blocks[i]
            group = group_raw.strip().lower()
            reworded = " ".join(reworded.split())
            if group not in _VALID_GROUPS or not reworded:
                group = "hypothesis"
                reworded = original
        else:
            group = "hypothesis"
            reworded = original
        results.append({"original": original, "group": group, "reworded": reworded})
    return results


def calibrate_findings(
    vulnerability_text: str,
    patch: str,
    findings: List[str],
    llm,
    code_context: str = "",
) -> List[Dict[str, str]]:
    """Classify and reword a list of challenger findings.

    Parameters
    ----------
    vulnerability_text, patch:
        Same inputs already given to the challenger, so calibration reasons
        from the same evidence.
    findings:
        Flat list of finding strings (e.g. the challenger's plausible_risk
        and generic classified findings) to calibrate. Findings already
        classified as confirmed_defect or validation_gap are not passed here
        — those already have unambiguous, previously-established framing.
    llm:
        An initialised LLMClient instance.
    code_context:
        Same repository evidence injected into patch generation/challenge,
        so "Observed" vs "Hypothesis" can be judged against what was
        actually shown, not the full repository.

    Returns a list of {"original": str, "group": str, "reworded": str} dicts,
    one per input finding, in the same order. Returns [] for empty input
    without calling the LLM.
    """
    if not findings:
        return []

    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    context_section = (
        "## Repository evidence (selected by static analysis)\n\n" + code_context + "\n\n"
    ) if code_context else ""
    findings_section = "\n".join(f"{i}. {text}" for i, text in enumerate(findings, start=1))
    user_message = (
        context_section
        + "## Vulnerability report\n\n"
        + vulnerability_text
        + "\n\n## Proposed patch\n\n"
        + patch
        + "\n\n## Findings to calibrate\n\n"
        + findings_section
    )

    resp = llm.complete(system_prompt, user_message, stage="finding_calibration")
    return _parse_response(resp, findings)
