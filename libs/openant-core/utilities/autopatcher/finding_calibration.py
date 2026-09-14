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

Structured self-report + deterministic consistency gate
---------------------------------------------------------
The model is required to expose, per finding, the factual dependencies its
conclusion rests on and explicitly mark any of them "Unresolved" (see
prompts/finding_calibration.md). `_parse_response` reads that self-report
and enforces exactly one deterministic invariant on top of it: a finding
cannot remain "Observed" if the model's OWN structured output declares a
required dependency unresolved. This checks internal consistency of the
model's own answer only — it never inspects prose for keywords and never
judges whether cited evidence actually, semantically proves anything; that
remains entirely the model's judgment call, same as before this change.

Parsing is strictly block-local: the response is first split into one text
span per numbered "N. Claims:" block (`_split_blocks_by_number`), and only
then is each span searched for its own "Unresolved:"/"Group:"/"Reworded:"
fields. A malformed or incomplete block's span never contains another
block's text, so it cannot "borrow" fields from a neighboring block —
it simply fails to match and falls back to Hypothesis on its own, without
shifting or corrupting any other finding's result. Blocks are looked up by
their own printed number, not by position in a list, so a missing or
malformed block N never causes block N+1's data to be misattributed to
finding N. A repeated block number is treated the same way as a missing
one -- there is no safe basis for picking one duplicate over the other, so
that finding falls back to Hypothesis rather than adopting either one.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Dict, Optional

_PROMPT_PATH = Path(__file__).parent / "prompts" / "finding_calibration.md"

_VALID_GROUPS = {"observed", "hypothesis", "hardening"}

# Matches a numbered block's opening line, e.g. "2. Claims:", capturing the
# printed number. Used only to find block BOUNDARIES (see
# _split_blocks_by_number) -- never to extract fields itself, so it cannot
# skip past a malformed block the way a single unbounded regex could.
_BLOCK_HEADER_RE = re.compile(r"^[ \t]*(\d+)\.\s*Claims:", re.MULTILINE)

# Matches "   - ...\n   Unresolved: <value>\n   Group: <label>\n
# Reworded: <text>" WITHIN a single block's already-isolated text span (see
# _split_blocks_by_number). Because the span physically ends before the
# next block's header, this can never match fields belonging to a
# different finding -- there is nothing else in the string for it to
# match. The "Claims:" bullet lines themselves are skipped non-greedily
# (`.*?` under DOTALL) rather than individually parsed -- the
# deterministic gate below only needs the "Unresolved:" value, "Group:",
# and "Reworded:"; requiring the model to enumerate Claims: is what forces
# the per-dependency reasoning the gate then checks for internal
# consistency, but the enumerated claim text itself is not retained as
# structured data (see module docstring: this module never judges
# evidence sufficiency, only the model's own consistency).
_BLOCK_FIELDS_RE = re.compile(
    r".*?Unresolved:\s*(.+?)\s*\n"
    r"\s*Group:\s*(\w+)\s*\n"
    r"\s*Reworded:\s*(.+?)\s*\Z",
    re.DOTALL,
)


def _split_blocks_by_number(resp: str) -> "Dict[int, Optional[str]]":
    """Split a raw calibration response into one text span per numbered
    "N. Claims:" block, keyed by the printed number N.

    Each span runs from just after its own "N. Claims:" header up to (but
    not including) the next block's header, or the end of the response for
    the last block. This is what makes field extraction strictly
    block-local: a span cannot contain another block's text, so a
    malformed/incomplete block can never "borrow" a field from its
    neighbor -- _BLOCK_FIELDS_RE simply has nothing else to match against.

    Duplicate block numbers are structurally ambiguous: there is no safe
    basis for picking one duplicate over another as "the" block for that
    finding. A number seen more than once maps to None here rather than to
    either duplicate's text -- _parse_response already treats a None span
    exactly like a missing block, so the finding fails closed to Hypothesis
    with its original text, without picking a side. Other, uniquely
    numbered blocks are unaffected.
    """
    headers = list(_BLOCK_HEADER_RE.finditer(resp))
    spans: "Dict[int, Optional[str]]" = {}
    seen: "set[int]" = set()
    for idx, header in enumerate(headers):
        number = int(header.group(1))
        start = header.end()
        end = headers[idx + 1].start() if idx + 1 < len(headers) else len(resp)
        if number in seen:
            spans[number] = None  # ambiguous: repeated number, no safe tie-break
        else:
            seen.add(number)
            spans[number] = resp[start:end]
    return spans


def _parse_unresolved(raw: "Optional[str]") -> "Optional[List[str]]":
    """Parse one finding's "Unresolved:" field value.

    Returns:
      []            -- the model explicitly wrote "none": every listed
                        dependency is confirmed established.
      [item, ...]   -- one or more unresolved dependencies, split on ";".
      None          -- the value is empty or otherwise not confidently
                        parseable as either of the above. Callers must
                        treat None as "unconfirmed", never as "none" --
                        the whole point of this field is that an
                        `Observed` finding must not be trusted unless the
                        absence of unresolved dependencies is explicit.
    """
    text = (raw or "").strip()
    if not text:
        return None
    if text.lower() == "none":
        return []
    items = [item.strip() for item in text.split(";") if item.strip()]
    return items or None


def _parse_response(resp: str, findings: List[str]) -> List[Dict[str, object]]:
    """Parse the calibration response into one entry per input finding.

    Falls back to the original finding text under group "hypothesis" (the
    most epistemically humble default) for any finding whose block is
    missing or unparseable — every finding must survive, never silently
    dropped, and never upgraded to a stronger-sounding group than what was
    reliably parsed.

    Blocks are matched to findings by their own printed number (see
    _split_blocks_by_number), not by position in a list: the Nth input
    finding (1-indexed, matching the prompt's own numbering) is looked up
    as block N specifically. A missing or malformed block never shifts
    or corrupts a later finding's result — it only ever falls back for
    itself.

    Deterministic consistency gate: if the parsed group is "observed" but
    the model's own "Unresolved:" field names one or more dependencies (or
    could not be confidently parsed as "none" at all), the effective group
    is downgraded to "hypothesis" here, before this function returns —
    every existing caller keys off `entry["group"]` and therefore sees the
    corrected value automatically, with no separate check needed anywhere
    else. `entry["reworded"]` is left exactly as the model wrote it: this
    is a classification correction, not a rewrite, and this module never
    edits prose.

    Each returned entry additionally carries (purely additive, safe for
    every existing caller to ignore):
      unresolved_dependencies        : list[str] -- [] when none, or when
                                        the field was missing/unparseable
                                        (see _parse_unresolved).
      group_before_consistency_check : str -- the group as validly parsed
                                        (after the existing invalid-group-
                                        name fallback, before the new
                                        gate). Equal to the final "group"
                                        whenever the gate did not need to
                                        act; observability only.
    """
    blocks_by_number = _split_blocks_by_number(resp or "")
    results: List[Dict[str, object]] = []
    for i, original in enumerate(findings, start=1):
        block_text = blocks_by_number.get(i)
        fields = _BLOCK_FIELDS_RE.match(block_text) if block_text is not None else None
        if fields is not None:
            unresolved_raw, group_raw, reworded = fields.groups()
            group = group_raw.strip().lower()
            reworded = " ".join(reworded.split())
            if group not in _VALID_GROUPS or not reworded:
                group = "hypothesis"
                reworded = original
            group_before_consistency_check = group
            unresolved = _parse_unresolved(unresolved_raw)
            if unresolved is None:
                # The required unresolved-status field itself could not be
                # confidently read -- never treat an unconfirmed state as
                # "no unresolved dependencies". Fails closed exactly like a
                # fully missing block already does below.
                group = "hypothesis"
                unresolved = []
            elif group == "observed" and unresolved:
                # Deterministic consistency gate: the model's own
                # structured self-report names an unresolved dependency --
                # Observed cannot stand regardless of the label it wrote.
                group = "hypothesis"
        else:
            group = "hypothesis"
            reworded = original
            unresolved = []
            group_before_consistency_check = group
        results.append({
            "original": original,
            "group": group,
            "reworded": reworded,
            "unresolved_dependencies": unresolved,
            "group_before_consistency_check": group_before_consistency_check,
        })
    return results


def calibrate_findings(
    vulnerability_text: str,
    patch: str,
    findings: List[str],
    llm,
    code_context: str = "",
) -> List[Dict[str, object]]:
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

    Returns a list of dicts, one per input finding, in the same order:
    {"original": str, "group": str, "reworded": str, "unresolved_dependencies":
    list[str], "group_before_consistency_check": str} — see _parse_response
    for the last two, purely-additive fields; every pre-existing caller
    reads only the first three and is unaffected. Returns [] for empty
    input without calling the LLM.
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


_GROUP_LABELS = {
    "observed": "Observed (confirmed against evidence already shown)",
    "hypothesis": "Hypothesis (plausible, not confirmed)",
    "hardening": "Hardening (out of scope for this advisory)",
}
_GROUP_ORDER = ("observed", "hypothesis", "hardening")


def format_calibration_for_prompt(finding_calibration: "List[Dict[str, object]] | None") -> str:
    """Render already-computed calibrate_findings() output as a concise,
    clearly-labeled Markdown section for a LATER stage's prompt (Patch
    Review, Confidence Scoring) -- so those stages build on the
    pipeline's own already-calibrated conclusions instead of
    independently re-deriving, and potentially contradicting, a concern
    calibration already resolved.

    Groups entries by their calibrated "group" (Observed / Hypothesis /
    Hardening), using each entry's own "reworded" text (falling back to
    "original" if a entry is missing "reworded"), in input order within
    each group. An entry missing both fields is skipped, never rendered blank.

    Returns "" for None/empty input, or when every entry turned out to
    have no renderable text -- callers must treat "" as "omit the
    section entirely", never render an empty heading.
    """
    if not finding_calibration:
        return ""
    groups: "Dict[str, List[str]]" = {g: [] for g in _GROUP_ORDER}
    for entry in finding_calibration:
        group = entry.get("group") or "hypothesis"
        if group not in groups:
            group = "hypothesis"  # an unrecognized group is never dropped silently
        text = entry.get("reworded") or entry.get("original") or ""
        if not text:
            continue
        groups[group].append(text)

    lines = [
        "## Already-calibrated findings",
        "",
        "*Produced by an earlier pipeline stage from the same evidence given "
        "here. Do not re-derive or re-litigate these from general/prior "
        "knowledge -- build on them.*",
    ]
    any_group = False
    for group in _GROUP_ORDER:
        items = groups.get(group) or []
        if not items:
            continue
        any_group = True
        lines.append("")
        lines.append(f"**{_GROUP_LABELS.get(group, group.title())}:**")
        for item in items:
            lines.append(f"- {item}")
    if not any_group:
        return ""
    return "\n".join(lines) + "\n"
