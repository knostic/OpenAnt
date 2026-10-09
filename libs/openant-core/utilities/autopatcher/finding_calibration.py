"""
Finding calibration — an LLM post-processing stage that classifies and
rewords challenger findings for calibrated certainty before they reach the
report.

Provides `calibrate_findings(vulnerability_text, patch, findings, llm,
code_context)`, which returns one entry per input finding: which of three
epistemic groups it belongs to (Observed / Hypothesis / Hardening), and a
reworded version whose certainty matches that group.

This is additive to the existing challenger/classifier: it does not change
`_classify_finding`'s categories or counts, and its Observed/Hypothesis/
Hardening axis is read only by report presentation (`_build_known_findings` /
`_render_known_findings`) — never by `_compute_trust_signals` or
`_build_recommendation_v1`.

A SECOND, independent structured field — "Remediation impact:" (`entry[
"remediation_impact"]`, one of "proof_required" / "validation_only" /
"unclear") — characterizes, for a finding with a non-empty "Unresolved:"
list, whether resolving that unresolved dependency is necessary to
establish the claimed remediation mechanism ("proof_required") or merely
useful additional validation/hardening evidence ("validation_only"). This
module still only CHARACTERIZES findings — it never decides deployment/
recommendation outcomes itself. A separate, deterministic reconciliation
function in pipeline.py (`_reconcile_verification_status_with_calibration`)
is the only thing authorized to translate this field into remediation-proof
blocking authority, replacing `_classify_challenger`'s former lexical-only
VERIFIED_FIXED + validation_gap_count reconciliation with a semantic one
that treats a materially equivalent unresolved dependency identically
regardless of whether `_classify_finding` happened to bucket the finding as
plausible_risk, validation_gap, or generic.

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

# Second, independent axis (additive -- never replaces _VALID_GROUPS above).
# "unclear" is the fail-closed default: an unrecognized/missing/malformed
# value on this field always parses to "unclear", never to "validation_only"
# -- see _parse_remediation_impact and _parse_response's own fail-closed
# branches. No uncertainty on this field may silently read as non-blocking.
_VALID_IMPACTS = {"proof_required", "validation_only", "unclear"}

# Matches a numbered block's opening line, e.g. "2. Claims:", capturing the
# printed number. Used only to find block BOUNDARIES (see
# _split_blocks_by_number) -- never to extract fields itself, so it cannot
# skip past a malformed block the way a single unbounded regex could.
_BLOCK_HEADER_RE = re.compile(r"^[ \t]*(\d+)\.\s*Claims:", re.MULTILINE)

# Matches "   - ...\n   Unresolved: <value>\n   Remediation impact: <value>\n
# Evidence request: <value>\n   Group: <label>\n   Reworded: <text>" WITHIN
# a single block's already-isolated text span (see
# _split_blocks_by_number). Because the span physically ends before the
# next block's header, this can never match fields belonging to a
# different finding -- there is nothing else in the string for it to
# match. The "Claims:" bullet lines themselves are skipped non-greedily
# (`.*?` under DOTALL) rather than individually parsed -- the
# deterministic gate below only needs the "Unresolved:" value, "Remediation
# impact:", "Evidence request:", "Group:", and "Reworded:"; requiring the
# model to enumerate Claims: is what forces the per-dependency reasoning
# the gate then checks for internal consistency, but the enumerated claim
# text itself is not retained as structured data (see module docstring:
# this module never judges evidence sufficiency, only the model's own
# consistency).
#
# "Remediation impact:" sits between "Unresolved:" and "Group:", and is
# OPTIONAL in this pattern (unlike every other field here): a response in
# the OLD (pre-this-field) format still matches and still parses its
# Group/Reworded/Unresolved fields exactly as before -- only
# `remediation_impact` itself degrades, to "unclear" (see
# _parse_remediation_impact(None) and _parse_response's own handling of a
# missing capture group), matching this field's own "missing field ->
# unclear" fail-closed rule at the FIELD level rather than collapsing the
# whole block the way a missing Group:/Reworded: already does (those two
# remain mandatory, unchanged).
#
# "Evidence acquirability:" sits between "Remediation impact:" and
# "Evidence request:", and is REGEX-OPTIONAL here for the same reason
# every other later-added field is: a response missing the line entirely
# must still match and parse every OTHER field exactly as before. It is
# not optional at the CONTRACT level for a proof_required finding (see
# prompts/finding_calibration.md's "Critical consistency contract") --
# that requirement is enforced deterministically in Python, by
# _parse_evidence_acquirability/_reconcile_acquirability_and_request
# below, never by the regex itself.
#
# "Evidence request:" (post-calibration evidence-acquisition loop) sits
# between "Evidence acquirability:" and "Group:", and is likewise
# REGEX-optional: a response with no such line (every pre-existing
# response, and every `validation_only`/`unclear` finding under the new
# contract too) still matches and still parses every other field exactly
# as before -- only `evidence_request` itself degrades to None (see
# _parse_evidence_request and _parse_response's own handling of a
# missing capture group).
_BLOCK_FIELDS_RE = re.compile(
    r".*?Unresolved:\s*(.+?)\s*\n"
    r"(?:\s*Remediation impact:\s*(.+?)\s*\n)?"
    r"(?:\s*Evidence acquirability:\s*(.+?)\s*\n)?"
    r"(?:\s*Evidence request:\s*(.+?)\s*\n)?"
    r"\s*Group:\s*(\w+)\s*\n"
    r"\s*Reworded:\s*(.+?)\s*\Z",
    re.DOTALL,
)

# Closed vocabulary for the mandatory-when-proof_required "Evidence
# acquirability:" declaration -- see prompts/finding_calibration.md.
# "unclear" is the fail-closed default (mirrors _VALID_IMPACTS' own
# "unclear"): a missing/malformed/unrecognized declaration on a
# proof_required finding always parses to "unclear", never silently to
# one of the three legitimate declared states.
_VALID_ACQUIRABILITY = {"actionable", "not_expressible", "conceptual_scope"}

# Reused verbatim from Planning's own evidence-request vocabulary
# (remediation_planner.PLANNING_REQUEST_TYPES) -- deliberately duplicated
# as a plain tuple literal here rather than imported, so this module keeps
# its existing zero-cross-module-import shape (pipeline.py, which already
# imports both modules, is where the two vocabularies are cross-checked --
# see test_finding_calibration.py's own parity test against the Planning
# constant). Never a third, independently-invented request-type set.
_EVIDENCE_REQUEST_TYPES = ("file_source", "symbol_definition")


def _parse_evidence_request(raw: "Optional[str]", impact: str) -> "Optional[Dict[str, Optional[str]]]":
    """Parse one finding's optional "Evidence request:" field value.

    Returns None (no actionable request) for: an absent/blank line, an
    unrecognized `request_type`, a `file_source` request missing its file,
    a `symbol_definition` request missing its file or symbol, any part
    count other than 2 (file_source) or 3 (symbol_definition), or --
    structurally, regardless of what the model wrote -- any finding whose
    `impact` is not exactly "proof_required". This last rule is a
    deterministic consistency gate, the same shape as `_parse_response`'s
    existing Unresolved/Remediation-impact gates: the prompt already
    instructs the model never to attach an Evidence request to a
    validation_only/unclear finding, but this function never trusts that
    instruction alone -- an evidence request is only ever structurally
    retained when the SAME response's own Remediation impact field
    independently says proof_required.

    Never repairs a malformed request into a valid one (e.g. never guesses
    a missing symbol, never drops an extra part) -- anything not exactly
    one of the two accepted shapes fails closed to None, identically to
    every other field in this module."""
    if impact != "proof_required":
        return None
    text = (raw or "").strip()
    if not text:
        return None
    parts = [p.strip() for p in text.split("|")]
    if len(parts) not in (2, 3):
        return None
    request_type = parts[0].lower()
    if request_type not in _EVIDENCE_REQUEST_TYPES:
        return None
    file_hint = parts[1]
    symbol = parts[2] if len(parts) == 3 else ""
    if not file_hint:
        return None
    if request_type == "file_source":
        if symbol:
            # A file_source request never carries a third (symbol) part --
            # fail closed rather than silently discarding the extra part.
            return None
        symbol = None
    else:  # symbol_definition
        if not symbol:
            return None
    return {"request_type": request_type, "file_hint": file_hint, "symbol": symbol}


def _parse_evidence_acquirability(raw: "Optional[str]", impact: str) -> "Optional[str]":
    """Parse one finding's "Evidence acquirability:" field value.

    Returns None when `impact` is not "proof_required" -- the concept is
    meaningless outside a proof_required finding (mirrors `_parse_
    evidence_request`'s own impact-gated shape exactly; a validation_
    only/unclear finding never carries either field, structurally).

    For a proof_required finding, this field is MANDATORY (see prompts/
    finding_calibration.md's "Critical consistency contract"): returns
    exactly one of "actionable", "not_expressible", "conceptual_scope"
    when the model wrote exactly one of those three words, and "unclear"
    for anything else -- missing, blank, malformed, or unrecognized.
    "unclear" here is a REAL, distinct fail-closed signal (not merely
    "absent"): a proof_required finding that never declared its
    acquirability state at all is exactly as untrustworthy, for this
    axis, as one that declared something unrecognized. Never inferred
    from Claims/Unresolved/Reworded prose -- only this field's own
    explicit text."""
    if impact != "proof_required":
        return None
    value = (raw or "").strip().lower()
    return value if value in _VALID_ACQUIRABILITY else "unclear"


def _reconcile_acquirability_and_request(acquirability: "Optional[str]", evidence_request: "Optional[Dict]") -> "tuple[Optional[str], Optional[Dict]]":
    """The ONE place the mandatory declaration/request consistency
    contract (prompts/finding_calibration.md's "Critical consistency
    contract") is enforced. The only two authoritative combinations for a
    proof_required finding are `actionable` + exactly one valid request,
    or `not_expressible`/`conceptual_scope` + no request. Every other
    combination fails closed to `("unclear", None)`:
      - `actionable` with no valid request (missing OR malformed --
        `_parse_evidence_request` already returns None for both) --
        an `actionable` declaration is only trustworthy when it is
        actually backed by the request it claims exists.
      - `not_expressible`/`conceptual_scope` with a request attached
        anyway -- these two declarations forbid a request by definition;
        one being present contradicts the declaration itself, so neither
        may be trusted as-is.
      - an already-"unclear" declaration (missing/malformed at the
        single-field level -- see `_parse_evidence_acquirability`) never
        acquires a request regardless of what text happened to follow
        it.
      - `acquirability is None` (a non-proof_required finding) passes
        through unchanged -- `evidence_request` is already None for
        every such finding via `_parse_evidence_request`'s own gate, so
        this is a no-op, never a second place that gate is enforced.

    Never invents, repairs, or infers a request from anything -- this
    only cross-checks two already-independently-parsed, closed-
    vocabulary fields against each other."""
    if acquirability == "actionable":
        if evidence_request is not None:
            return "actionable", evidence_request
        return "unclear", None
    if acquirability in ("not_expressible", "conceptual_scope"):
        if evidence_request is None:
            return acquirability, None
        return "unclear", None
    # acquirability is None (not proof_required) or "unclear" (missing/
    # malformed declaration) -- a request must never survive attached to
    # either.
    return acquirability, None


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


def _parse_remediation_impact(raw: "Optional[str]") -> str:
    """Parse one finding's "Remediation impact:" field value.

    Fails closed to "unclear" for anything not EXACTLY one of the three
    accepted values (`_VALID_IMPACTS`) -- missing, empty, malformed, or any
    unrecognized word. Never inferred from the finding's own prose/keywords
    in Python -- this reads only the model's own explicit, separately
    labeled field, exactly like `_parse_unresolved`/the `Group:` field
    above it."""
    value = (raw or "").strip().lower()
    return value if value in _VALID_IMPACTS else "unclear"


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
      remediation_impact             : str -- "proof_required" /
                                        "validation_only" / "unclear"
                                        (_VALID_IMPACTS). A SECOND,
                                        independent axis from `group` above
                                        -- see _parse_remediation_impact and
                                        the module docstring. Fails closed
                                        to "unclear" on any missing block,
                                        missing/malformed/unrecognized
                                        field, or duplicate-block ambiguity
                                        -- exactly the same fail-closed
                                        shape as `group`'s own "hypothesis"
                                        fallback, just for this axis's own
                                        strictest value. Never inferred from
                                        `unresolved_dependencies` itself or
                                        from any prose here -- Python makes
                                        no attempt to guess this value from
                                        Claims/Reworded text; only the
                                        model's own explicit field does. The
                                        ONE exception is purely structural,
                                        not semantic: when `unresolved_
                                        dependencies` successfully parses to
                                        an empty list (a validly-written
                                        "Unresolved: none", not the
                                        fail-closed default above), this
                                        field is deterministically
                                        normalized to "validation_only"
                                        regardless of what the model wrote
                                        -- an empty Unresolved list leaves
                                        nothing for this axis to block on,
                                        per the prompt's own contract.
      evidence_acquirability          : "actionable" | "not_expressible" |
                                        "conceptual_scope" | "unclear" |
                                        None -- see _parse_evidence_
                                        acquirability. None whenever the
                                        FINAL `remediation_impact` is not
                                        "proof_required" (the concept is
                                        meaningless there); "unclear" is a
                                        real, distinct fail-closed value
                                        for a proof_required finding whose
                                        declaration was missing, malformed,
                                        or inconsistent with its own
                                        Evidence request (see
                                        _reconcile_acquirability_and_
                                        request) -- never silently
                                        collapsed into one of the three
                                        legitimate declared states.
      evidence_request                : dict{"request_type", "file_hint",
                                        "symbol"} | None -- see
                                        _parse_evidence_request, then
                                        _reconcile_acquirability_and_
                                        request (the final authority).
                                        None whenever the model wrote no
                                        such line, wrote one that does not
                                        parse as exactly one of the two
                                        valid shapes, wrote one for a
                                        finding whose FINAL `remediation_
                                        impact` is not "proof_required",
                                        or wrote one alongside a
                                        `not_expressible`/`conceptual_
                                        scope`/missing/malformed
                                        `evidence_acquirability` (any of
                                        which forbids a request). Only
                                        ever non-None alongside
                                        `evidence_acquirability ==
                                        "actionable"`. This module never
                                        acts on either field -- see
                                        pipeline.py's bounded post-
                                        calibration evidence-acquisition
                                        orchestration, the only consumer.
      calibration_failed              : bool -- True when this finding's
                                        block was missing/unparseable or its
                                        Unresolved field could not be read
                                        (the fail-closed defaults above). Such
                                        an entry carries NO calibration
                                        answer: pipeline.py treats it exactly
                                        like a finding calibration never saw,
                                        never as "examined, nothing
                                        unresolved".
    """
    blocks_by_number = _split_blocks_by_number(resp or "")
    results: List[Dict[str, object]] = []
    for i, original in enumerate(findings, start=1):
        block_text = blocks_by_number.get(i)
        fields = _BLOCK_FIELDS_RE.match(block_text) if block_text is not None else None
        calibration_failed = fields is None
        if fields is not None:
            (
                unresolved_raw, impact_raw, acquirability_raw, evidence_request_raw, group_raw, reworded,
            ) = fields.groups()
            group = group_raw.strip().lower()
            reworded = " ".join(reworded.split())
            impact = _parse_remediation_impact(impact_raw)
            if group not in _VALID_GROUPS or not reworded:
                group = "hypothesis"
                reworded = original
            group_before_consistency_check = group
            unresolved = _parse_unresolved(unresolved_raw)
            if unresolved is None:
                # The required unresolved-status field itself could not be
                # confidently read -- never treat an unconfirmed state as
                # "no unresolved dependencies". Fails closed exactly like a
                # fully missing block already does below -- same reasoning
                # now applies to `impact`, an equally structured field.
                group = "hypothesis"
                unresolved = []
                impact = "unclear"
                calibration_failed = True
            else:
                if group == "observed" and unresolved:
                    # Deterministic consistency gate: the model's own
                    # structured self-report names an unresolved
                    # dependency -- Observed cannot stand regardless of
                    # the label it wrote.
                    group = "hypothesis"
                if not unresolved:
                    # Deterministic consistency normalization: Unresolved
                    # successfully parsed to "none" (an empty list, not the
                    # fail-closed default above) leaves nothing on the
                    # remediation-impact axis to block on -- a
                    # "proof_required"/"unclear" value here would
                    # contradict the model's own Unresolved field, exactly
                    # the contract violation prompts/finding_calibration.md
                    # already forbids ("Whenever Unresolved: none applies,
                    # Remediation impact: must be validation_only"). Purely
                    # structural: reads only the already-parsed
                    # `unresolved` list's own emptiness, never Claims/
                    # Reworded prose -- and never reached from the
                    # fail-closed `unresolved is None` branch above, so an
                    # unparseable Unresolved field still keeps its own
                    # "unclear" impact, never "validation_only".
                    impact = "validation_only"
            # Parsed only from the FINAL `impact` value, after every
            # consistency gate above has already settled it -- neither
            # the acquirability declaration nor the Evidence request can
            # ever survive alongside a finding that isn't, in its FINAL
            # form, proof_required, even if it started that way in the
            # model's raw text before being normalized/downgraded above.
            acquirability = _parse_evidence_acquirability(acquirability_raw, impact)
            evidence_request = _parse_evidence_request(evidence_request_raw, impact)
            # The mandatory declaration/request consistency contract --
            # see _reconcile_acquirability_and_request's own docstring.
            # Never skipped: a "proof_required" finding whose declaration
            # and request contradict each other (or whose declaration is
            # itself missing/malformed) must never surface either as
            # authoritative.
            acquirability, evidence_request = _reconcile_acquirability_and_request(acquirability, evidence_request)
        else:
            group = "hypothesis"
            reworded = original
            unresolved = []
            impact = "unclear"
            group_before_consistency_check = group
            # A missing/unparseable block never acquires an authoritative
            # acquirability state either -- impact is "unclear" here (not
            # "proof_required"), so _parse_evidence_acquirability's own
            # impact gate would already return None; set directly since
            # there are no raw field strings to parse in this branch.
            acquirability = None
            evidence_request = None
        results.append({
            "original": original,
            "group": group,
            "reworded": reworded,
            "unresolved_dependencies": unresolved,
            "group_before_consistency_check": group_before_consistency_check,
            "remediation_impact": impact,
            "evidence_acquirability": acquirability,
            "evidence_request": evidence_request,
            "calibration_failed": calibration_failed,
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
        Flat list of finding strings to calibrate -- this module does not
        care which lexical category (`_classify_finding`) a caller's own
        filter selected findings from; plausible_risk, validation_gap, and
        generic findings are all valid input here (see pipeline.py's own
        calibration-input filters, which intentionally admit all three so
        the "Remediation impact" axis below is available to an unresolved
        dependency regardless of which lexical bucket it happened to land
        in). confirmed_defect/behavioral_defect findings may also be passed
        (see pipeline.py's repair-gated calibration call) -- this module
        treats every input finding identically regardless of category.
    llm:
        An initialised LLMClient instance.
    code_context:
        Same repository evidence injected into patch generation/challenge,
        so "Observed" vs "Hypothesis" can be judged against what was
        actually shown, not the full repository.

    Returns a list of dicts, one per input finding, in the same order:
    {"original": str, "group": str, "reworded": str, "unresolved_dependencies":
    list[str], "group_before_consistency_check": str, "remediation_impact":
    str} — see _parse_response for the last three, purely-additive fields;
    every pre-existing caller reads only the first three and is unaffected.
    Returns [] for empty input without calling the LLM.
    """
    if not findings:
        return []

    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    context_section = (
        _EVIDENCE_HEADER + code_context + "\n\n"
    ) if code_context else ""
    findings_section = _render_findings_section(findings)
    user_message = (
        context_section
        + _VULN_HEADER
        + vulnerability_text
        + _PATCH_HEADER
        + patch
        + _FINDINGS_HEADER
        + findings_section
    )

    resp = llm.complete(system_prompt, user_message, stage="finding_calibration")
    return _parse_response(resp, findings)


# ---------------------------------------------------------------------------
# Post-calibration evidence-acquisition loop: Finding Calibration's own
# combined-request technical-capacity contract (Fix B).
#
# The exact fixed strings calibrate_findings() wraps around code_context/
# vulnerability_text/patch/findings -- shared with compute_finding_
# calibration_capacity() below so the overhead a capacity calculation
# counts and the overhead an actual request sends can never independently
# drift apart, exactly the same discipline patch_generator.py's
# compute_patch_generation_capacity already established for Patch
# Generation's own request.
# ---------------------------------------------------------------------------

_EVIDENCE_HEADER = "## Repository evidence (selected by static analysis)\n\n"
_VULN_HEADER = "## Vulnerability report\n\n"
_PATCH_HEADER = "\n\n## Proposed patch\n\n"
_FINDINGS_HEADER = "\n\n## Findings to calibrate\n\n"


def _render_findings_section(findings: List[str]) -> str:
    return "\n".join(f"{i}. {text}" for i, text in enumerate(findings, start=1))


def compute_finding_calibration_capacity(
    vulnerability_text: str, patch: str, findings: "List[str]", *, reserved_output_tokens=None,
):
    """Real remaining capacity (in characters) for `code_context` in the
    ACTUAL Finding Calibration request that will be sent -- accounts for
    every fixed string calibrate_findings() itself sends alongside it: the
    system prompt (`_PROMPT_PATH`), `_VULN_HEADER` + `vulnerability_text`,
    `_PATCH_HEADER` + `patch`, `_FINDINGS_HEADER` + the rendered findings
    list, and `_EVIDENCE_HEADER`'s own fixed text (code_context itself is
    the one variable this contract is sizing, so its own length is never
    part of the overhead).

    Returns a `technical_capacity.SourceCapacityResult` -- `.source_
    capacity_chars` is the ceiling the COMBINED (existing + newly
    acquired) `code_context` must fit within."""
    from .llm_client import resolve_active_model, resolve_max_tokens
    from .technical_capacity import compute_source_capacity

    system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")
    findings_section = _render_findings_section(findings or [])
    known_overhead_chars = (
        len(system_prompt) + len(_EVIDENCE_HEADER)
        + len(_VULN_HEADER) + len(vulnerability_text or "")
        + len(_PATCH_HEADER) + len(patch or "")
        + len(_FINDINGS_HEADER) + len(findings_section)
    )
    provider, model = resolve_active_model()
    return compute_source_capacity(
        provider, model,
        reserved_output_tokens=(resolve_max_tokens() if reserved_output_tokens is None else reserved_output_tokens),
        known_overhead_chars=known_overhead_chars,
    )


def fit_calibration_evidence(existing_code_context: str, new_blocks, max_chars: int, *, capacity=None):
    """Whole-block-or-omit fit of newly acquired evidence blocks alongside
    the code_context Calibration #1 already used, against `max_chars` (see
    `compute_finding_calibration_capacity`).

    `existing_code_context` is treated as the one REQUIRED section --
    Calibration #1 already relied on it, so it is reserved first and is
    never itself dropped for capacity (see `patch_generator.
    fit_patch_generation_context`'s own `required_label` semantics, which
    this reuses directly rather than a second whole-block-fitting
    implementation). `new_blocks`: an ordered list of (label, text) pairs
    -- each included whole, in the given order, only as room remains
    after `existing_code_context`; otherwise omitted whole (never
    truncated) and recorded in the returned plan's own `omission_reason`/
    `omitted_sizes`.

    If `existing_code_context` alone does not fit `max_chars` (a rare,
    defensive edge case -- Calibration #1's own capacity call already
    should have prevented this), the returned plan's `required_missing`
    is True and `rendered` is empty -- the caller must treat this as "no
    rerun possible", never send an emptied-out request in its place."""
    from .patch_generator import fit_patch_generation_context

    _EXISTING_LABEL = "__existing_calibration_code_context__"
    sections = [(_EXISTING_LABEL, existing_code_context)] + list(new_blocks)
    return fit_patch_generation_context(
        sections, max_chars, required_label=_EXISTING_LABEL, capacity=capacity,
    )


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
