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
the legacy `still_vulnerable` boolean and with malformed/missing input.

For a response using the structured `Concerns:` schema (see
`_parse_concerns`/`_derive_status_from_concerns` below), these three
strings are instead DERIVED deterministically from the concern facts --
never read directly from a `Verification status:` header, which becomes
report-only text for such a response. `_parse_verification` and this
constant are unchanged and remain the sole authority for any response
that does not contain a `Concerns:` section at all (see `challenge_patch`'s
own new-schema/legacy branch)."""

CONCERN_ROLES = ("primary", "additional")
"""The only two values a concern block's `Role:` field may carry. Exactly
one `primary` concern (the mandatory assessment of the originally-
described vulnerability mechanism) is required per structured response;
`additional` concerns are open-ended, zero or more, freely discovered --
the schema is not a whitelist of vulnerability mechanisms, and a concern
whose mechanism is genuinely novel is still represented this way, with its
own facts resolved or left `unresolved`, never dropped."""

REACHABILITY_VALUES = ("reachable", "blocked", "unresolved")
"""`Default execution reachability:` -- reachability of THIS concern's own
alleged operation under the relevant default execution, per the supplied
repository/diff evidence. `unresolved` when that evidence does not
establish the answer -- never inferred from a parameter's name or a
plausible guard's assumed behavior (see `_parse_concern_block`)."""

OVERRIDE_VALUES = ("true", "false", "unresolved", "not_applicable")
"""`Requires explicit non-default action:` -- applicable ONLY when
`default_execution_reachability == "blocked"`; `not_applicable` is the
only valid value otherwise. A response that violates this gate (e.g.
`reachable` paired with `true`/`false`/`unresolved`, or `blocked` paired
with `not_applicable`) is treated as a malformed concern, never silently
corrected -- see `_parse_concern_block`'s applicability checks."""

SCOPE_VALUES = ("explicitly_included", "explicitly_excluded", "silent", "unresolved", "not_applicable")
"""`Contract addresses override:` -- applicable ONLY when
`requires_explicit_non_default_action == "true"`; `not_applicable`
otherwise, under the same fail-closed applicability discipline as
OVERRIDE_VALUES above.

The ONLY authoritative source for this field is the complete
`vulnerability_text` supplied to THIS Challenger run -- never repository
evidence, the diff, Planning/Strategy prose, or any `security_invariant`
field. `silent` and `explicitly_excluded` are kept as distinct values even
though the deterministic policy below maps both to the same NON_BLOCKING
consequence: they require materially different provenance (a point
citation for exclusion, a whole-document marker for silence -- never
interchangeable, see `_parse_concern_block`) and carry different
evidentiary weight for a human reviewer, so collapsing them would lose
real audit value for no policy benefit."""

_WHOLE_DOCUMENT_MARKER = "whole document"
"""The exact (case-insensitive) marker `Scope provenance:` must carry for
a `silent` determination. Silence is an absence claim -- no local quote
can prove the complete document does not mention something elsewhere --
so a quoted span offered here fails closed instead of being accepted (see
`_whole_document_marker_valid`)."""

# ---------------------------------------------------------------------------
# concerns_v2 -- atomic default-execution-reachability decomposition.
#
# Replaces a single directly-asserted `Default execution reachability:`
# value with five small, independently-citable facts, each demoted to
# `unresolved` (never trusted, never malformed) on ungrounded provenance --
# deterministic code (`_derive_default_execution_reachability`) then derives
# the SAME three-value `reachable|blocked|unresolved` result these facts
# used to assert directly. Every downstream consumer of that value
# (`_concern_consequence`, `_derive_status_from_concerns`, and everything
# beyond) is unmodified and unaware which schema version produced it.
#
# A response is routed through this schema ONLY when its `Concerns:` body
# contains the `Preceding guard:` field label (see
# `_response_uses_v2_schema`) -- a label that cannot appear in any
# `concerns_v1` response, archived or new, since it did not exist before
# this schema. This keeps replay of an archived v1 trace byte-identical:
# re-parsing the SAME stored raw text at replay time makes the SAME
# routing decision it made originally, with no external flag involved.
# ---------------------------------------------------------------------------

OPERATION_PRESENCE_VALUES = ("present", "unresolved")
"""`Operation present in evidence:` -- whether THIS concern's own alleged
operation is quoted in the evidence Challenger actually received. `present`
means only that -- never "globally reachable", never "exists somewhere in
the repository", never "reachable under defaults". There is deliberately
NO `false`/`absent` value: Challenger receives a SELECTED SLICE of the
repository, never a complete one, so "not found in what I was shown" can
never legitimately become "does not exist" -- that would be exactly the
kind of unbounded absence claim `_point_citation_valid`'s whole design
already refuses to accept for any other field. Failing to find the
operation is `unresolved`, not a value this enum can express as a
resolved fact."""

PRECEDING_GUARD_VALUES = ("present", "absent", "unresolved", "not_applicable")
"""`Preceding guard:` -- applicable only when `operation_present_in_evidence
== present` (`not_applicable` otherwise, under the same fail-closed
applicability discipline as `OVERRIDE_VALUES`/`SCOPE_VALUES`: a mismatch is
a malformed concern, never silently corrected).

`present`: a protective conditional relevant to the alleged operation is
cited, and (see `_citation_precedes_within_one_block`) its citation's
first occurrence is textually before the operation citation's first
occurrence within ONE rendered evidence block (a fenced source block, a
grounding excerpt, or a single diff hunk) -- never by positions across
blocks or sources --
a NECESSARY, not sufficient, signal: it catches a citation that is
textually backwards, but proves nothing about branches, helper calls, or
alternate paths that might bypass the guard. No CFG analyzer is
implemented here; anything the model cannot confidently rule out from the
supplied evidence alone must be `unresolved`, never guessed.

`absent`: no such guard is present in the COMPLETE containing-function
evidence -- a BOUNDED absence claim, scoped explicitly to that one
function, never to the repository as a whole. The `whole function` marker
and a grounded `Function provenance:` citation are NECESSARY but never
SUFFICIENT to accept this by themselves: `_parse_concern_block_v2` also
requires `_absence_mechanically_verified_complete` to independently prove
completeness against an EXISTING, unmodified repository-evidence
renderer's own deterministic "this is a complete file/symbol" contract
(see that function's own module comment) -- never the model's own claim,
and never invented by this module. Absent such a block in the supplied
evidence, `absent` fails closed to `unresolved`, exactly like every other
ungrounded v2 claim."""

GUARD_DEFAULT_STATE_VALUES = (
    "condition_true_under_default", "condition_false_under_default", "unresolved", "not_applicable",
)
"""`Guard default state:` -- applicable only when `preceding_guard ==
present`. Citable to exactly ONE genuinely default-valued/configurable
term of the guard's condition -- e.g. `assert_same_host: bool = True` --
never a compound expression treated as if it were one atomic fact. A
scenario-given predicate (e.g. `not self.is_same_host(url)`, true because
THIS concern is specifically about a cross-origin case) is never this
field's evidence -- that belongs to the concern's own `Description`, not
to something "default execution" resolves. If establishing the condition
genuinely requires two or more independently-configurable terms this
bounded schema cannot safely reduce to one citation, the honest answer is
`unresolved` -- this module does not attempt compound-condition
decomposition."""

GUARD_EFFECT_VALUES = (
    "prevents_operation", "neutralizes_operation", "no_effect", "unresolved", "not_applicable",
)
"""`Guard effect:` -- applicable only when `guard_default_state ==
condition_true_under_default`. `prevents_operation`: a hard control
transfer (raise/return/equivalent) stops the operation outright.
`neutralizes_operation`: the operation may still execute, but the guard
first changes the specific state/input that would produce the concern --
stripping, sanitizing, filtering, replacing, or deleting the relevant
data before the operation proceeds -- a real, common remediation shape
this value exists specifically to represent, not a blocking one.
`no_effect`: the condition is true but nothing about the operation or its
relevant input changes. Both `prevents_operation` and `neutralizes_
operation` deny the concern's alleged effect and are treated identically
by `_derive_default_execution_reachability`; only `no_effect` leaves the
concern's operation reachable."""

REENTRY_PROPAGATION_VALUES = ("preserved", "reset_or_bypassed", "not_applicable", "unresolved")
"""`Reentry state propagation:` -- applicable only when `guard_effect` is
`prevents_operation` or `neutralizes_operation`; unlike every other v2
field's gate, `not_applicable` remains a REAL, legitimate answer even
when that condition holds (see rule 8 of
`_derive_default_execution_reachability`) -- it means the operation is
reached within the SAME single guard evaluation, no separate/subsequent
invocation involved at all, which is the common, non-recursive case.
When a subsequent invocation of the SAME guard-evaluating scope IS
relevant -- recursion, a loop iteration, or an explicit re-call, never a
cross-function helper/callback/async boundary (out of scope; must fail
closed to `unresolved` instead) -- `preserved` means the guard's
protective state/binding is threaded through unchanged; `reset_or_
bypassed` means that subsequent invocation changes, resets, or omits it."""

_WHOLE_FUNCTION_MARKER = "whole function"
"""The exact (case-insensitive) marker `Guard provenance:` must carry for
a `preceding_guard == absent` determination -- the bounded, function-
scoped sibling of `_WHOLE_DOCUMENT_MARKER`, never proof by itself (see
`PRECEDING_GUARD_VALUES`'s own docstring). `_parse_concern_block_v2` also
requires a real `Function provenance:` citation AND
`_absence_mechanically_verified_complete`'s own independent completeness
proof -- this marker is necessary but never sufficient on its own, and
the model's own assertion of it is never trusted as completeness."""

_CONCERN_BLOCK_HEADER_RE = re.compile(r"^[ \t]*(\d+)\.\s*Role:", re.MULTILINE)


def _split_sections(text: str) -> Dict[str, str]:
    # Look for section headers used in the prompt and capture their bodies.
    pattern = re.compile(
        r"^(Verification status:|Still vulnerable:|Edge cases:|Potential issues:|Concerns:|Summary:)",
        re.IGNORECASE | re.MULTILINE,
    )
    parts = pattern.split(text)
    # parts will be: [pre, header1, body1, header2, body2, ...]
    sections = {
        "verification_status": "", "still_vulnerable": "",
        "edge_cases": "", "potential_issues": "", "summary": "",
        # `None` (not `""`) is the deliberate "header absent" sentinel --
        # see `challenge_patch`'s new-schema/legacy branch, which must
        # distinguish "no Concerns: header at all" (legacy fallback) from
        # "Concerns: header present with an empty/malformed body" (fails
        # closed under the new schema, never silently treated as legacy).
        "concerns": None,
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
        elif header.startswith("concerns"):
            sections["concerns"] = body.strip()
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


# ---------------------------------------------------------------------------
# Structured `Concerns:` schema -- deterministic atomic-fact derivation.
#
# Replaces the free-form `Verification status:` token, for a response using
# this schema, with a pipeline of: LLM discovers a concern (open-ended,
# unconstrained) -> LLM emits a small set of bounded atomic facts + their
# provenance for that concern -> deterministic parsing/validation ->
# deterministic per-concern consequence -> deterministic multi-concern
# aggregation -> a legacy-compatible `(verification_status, still_vulnerable)`
# pair, so every existing downstream consumer (`_classify_challenger`,
# `_compute_trust_signals`, `_build_recommendation_v1`,
# `_reconcile_verification_status_with_calibration`) is unmodified and
# unaware anything changed.
#
# A response containing NO `Concerns:` header at all is untouched by any of
# this -- `_parse_verification` remains the sole authority for it, exactly
# as before this schema existed (see `challenge_patch`'s own branch). A
# response that DOES contain a `Concerns:` header, however malformed its
# body, is NEVER routed through `_parse_verification` -- "new schema absent"
# and "new schema present but malformed" are deliberately different
# outcomes (legitimate legacy fallback vs. fail-closed under the new
# schema), never conflated.
# ---------------------------------------------------------------------------


def _split_concern_blocks(text: str) -> "Dict[int, Optional[str]]":
    """Split a `Concerns:` section body into one text span per numbered
    block, keyed by its own printed number -- mirrors
    finding_calibration._split_blocks_by_number's block-local discipline:
    a block's span physically ends before the next block's own header, so
    a malformed block can never "borrow" a neighboring block's fields, and
    fields are never attributed by position.

    A repeated block number is ambiguous -- there is no safe basis for
    preferring one duplicate over the other -- so it maps to `None`
    (fails closed as one malformed concern for that number), never to
    either duplicate's span."""
    matches = list(_CONCERN_BLOCK_HEADER_RE.finditer(text or ""))
    blocks: "Dict[int, Optional[str]]" = {}
    for i, m in enumerate(matches):
        num = int(m.group(1))
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        span = text[start:end]
        if num in blocks:
            blocks[num] = None
        else:
            blocks[num] = span
    return blocks


def _extract_concern_field(block: str, label: str) -> "Optional[str]":
    """First line matching `<label>: <value>` within an already-isolated
    concern block span -- block-local by construction, so this can never
    read a value belonging to a different concern.

    `Role:` shares its line with the block's own leading "N." (see
    `_CONCERN_BLOCK_HEADER_RE`, e.g. "1. Role: primary") -- the optional
    `\\d+\\.\\s*` prefix here accounts for that one line without requiring
    every other field's line to tolerate it too."""
    m = re.search(rf"^[ \t]*(?:\d+\.\s*)?{re.escape(label)}:\s*(.+?)\s*$", block, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def _strip_quote_wrapping(s: "Optional[str]") -> str:
    s = (s or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'`":
        return s[1:-1].strip()
    return s


def _normalize_for_provenance(text: str) -> str:
    """Collapse whitespace-only differences between a model's quoted
    citation and the real evidence source, so a code citation that is
    otherwise identical validates regardless of how it was linebroken.

    Two, and only two, transformations are applied: (1) a literal
    backslash-n escape sequence (the model writing out "\\n" as two
    characters, having collapsed a multi-line quote onto one line) is
    treated as equivalent to a real newline; (2) every run of whitespace
    (spaces, tabs, real newlines alike) collapses to a single space, so
    indentation and line-break placement never matter.

    This is NOT semantic normalization: every non-whitespace token and
    its exact order is preserved untouched, so a citation with different
    words, a different constant name, or reordered tokens still fails to
    match -- only formatting/whitespace equivalence is granted, never
    content equivalence."""
    normalized = (text or "").replace("\\n", "\n")
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()


def _point_citation_valid(raw: "Optional[str]", *sources: str) -> bool:
    """A resolved fact's citation is only trustworthy when the cited text
    is mechanically present in evidence this Challenger run actually
    received -- never a semantic check that the citation proves the
    claimed fact (that remains the model's own judgment), only that it is
    not fabricated and comes from an eligible source. Containment is
    checked on whitespace-normalized text (see `_normalize_for_provenance`)
    so a real multi-line quote, a literal-backslash-n-collapsed quote, and
    a whitespace-collapsed quote of the SAME underlying tokens all
    validate identically -- a materially different quote (different
    tokens, different order, or a genuinely absent citation) still fails,
    and a citation naming content omitted upstream for technical capacity
    still fails, since omitted content is never concatenated into the
    strings Challenger receives in the first place -- no separate
    omission-ledger lookup is needed."""
    quoted = _strip_quote_wrapping(raw)
    if not quoted or quoted.lower() in ("none", "n/a", "unknown"):
        return False
    normalized_quote = _normalize_for_provenance(quoted)
    if not normalized_quote:
        return False
    return any(normalized_quote in _normalize_for_provenance(source) for source in sources if source)


def _whole_document_marker_valid(raw: "Optional[str]") -> bool:
    """`silent` is an absence claim -- no local quote can prove the
    complete document does not mention something elsewhere. The only
    valid provenance is this exact structural marker; a quoted span
    offered here (mistaking silence for a point-citable claim) fails
    closed instead of being accepted."""
    return (raw or "").strip().lower() == _WHOLE_DOCUMENT_MARKER


def _whole_function_marker_valid(raw: "Optional[str]") -> bool:
    """The bounded, function-scoped sibling of `_whole_document_marker_valid`
    -- see `_WHOLE_FUNCTION_MARKER`'s own docstring for why this marker
    alone is never accepted as sufficient (`_parse_concern_block_v2` also
    requires a real `Function provenance:` citation)."""
    return (raw or "").strip().lower() == _WHOLE_FUNCTION_MARKER


def _citation_offset_pair(earlier_raw: "Optional[str]", later_raw: "Optional[str]", *sources: str):
    """Return `(offset_earlier, offset_later)` within the FIRST supplied
    source whose normalized text contains BOTH citations, or `None` if no
    single supplied source contains both. Ordering can only be established
    when both citations are anchored to the SAME evidence text -- a guard
    cited only against `code_context` and an operation cited only against
    `patch` (or vice versa) share no common coordinate space to compare
    offsets in, and must never be treated as ordered on that basis."""
    earlier = _normalize_for_provenance(_strip_quote_wrapping(earlier_raw))
    later = _normalize_for_provenance(_strip_quote_wrapping(later_raw))
    if not earlier or not later:
        return None
    for source in sources:
        if not source:
            continue
        normalized_source = _normalize_for_provenance(source)
        off_earlier = normalized_source.find(earlier)
        off_later = normalized_source.find(later)
        if off_earlier != -1 and off_later != -1:
            return off_earlier, off_later
    return None


def _citation_precedes(earlier_raw: "Optional[str]", later_raw: "Optional[str]", *sources: str) -> bool:
    """True only when both citations are anchored to the SAME supplied
    evidence text AND the earlier one's offset is strictly before the
    later one's. A NECESSARY, not sufficient, signal for control-flow
    ordering (see `PRECEDING_GUARD_VALUES`'s own docstring): it proves
    nothing about branches, helper calls, or alternate paths, and no CFG
    analyzer is implemented here -- it only catches a citation that is
    textually backwards, which can never be a preceding guard (or, for
    `Function provenance:`, a containing function whose citation appears
    after the operation it supposedly contains)."""
    offsets = _citation_offset_pair(earlier_raw, later_raw, *sources)
    return offsets is not None and offsets[0] < offsets[1]


# ---------------------------------------------------------------------------
# Block-local ordering for `preceding_guard == present`.
#
# The evidence corpus this module receives is a CONCATENATION of separately
# rendered evidence blocks (pipeline._challenger_provenance_context joins
# them), and the same function's source routinely appears in several of
# them (pre-change copies from different renderers, plus the complete
# post-change copy). A global first-occurrence comparison over that
# concatenation is therefore meaningless: it can order a guard in one block
# against an operation in an unrelated block, or compare against the WRONG
# copy of a duplicated line. Ordering is instead established only inside
# ONE rendered block, using that block's own first occurrences:
#   - each fenced source block (```...```, every deterministic source
#     renderer's shape, including `Post-patch definition`),
#   - each repository-grounding excerpt (`# <path> (lines a-b)` /
#     `(full file, N lines)` / bare `# <path>`, repo_locator's unfenced
#     shape), ending at the next excerpt or markdown section heading,
#   - each diff hunk (`@@ ... @@`) inside any of the above, or inside the
#     patch itself.
# Text outside every recognized block (section prose) is never an ordering
# unit. A source with no recognized block structure at all (a plain
# evidence string from a direct caller) is itself exactly one block.
# Citation PRESENCE is validated exactly as before (`_point_citation_valid`
# over the whole authoritative corpus); only ORDERING is block-local.
# ---------------------------------------------------------------------------

_FENCED_EVIDENCE_BLOCK_RE = re.compile(r"^```[^\n`]*\n(.*?)\n```[ \t]*$", re.MULTILINE | re.DOTALL)
_GROUNDING_EXCERPT_HEADER_RE = re.compile(
    r"^# (?:\S+ \((?:lines [0-9][0-9, -]*|full file, [0-9]+ lines)\)|[^\s()]+\.[A-Za-z0-9_]+)[ \t]*$",
    re.MULTILINE,
)
_MARKDOWN_SECTION_HEADING_RE = re.compile(r"^#{2,6} ", re.MULTILINE)
_DIFF_HUNK_HEADER_RE = re.compile(r"^@@ [^\n]*@@[^\n]*$", re.MULTILINE)


def _split_diff_hunks(block: str) -> "List[str]":
    """One unit per `@@` hunk body; a block with no hunk header is one unit."""
    headers = list(_DIFF_HUNK_HEADER_RE.finditer(block))
    if not headers:
        return [block]
    return [
        block[h.end():(headers[i + 1].start() if i + 1 < len(headers) else len(block))]
        for i, h in enumerate(headers)
    ]


def _ordering_blocks(source: "Optional[str]") -> "List[str]":
    """The rendered evidence blocks of one source, each an independent
    ordering unit (see this section's module comment)."""
    if not source:
        return []
    blocks = [m.group(1) for m in _FENCED_EVIDENCE_BLOCK_RE.finditer(source)]
    remainder = _FENCED_EVIDENCE_BLOCK_RE.sub("\n", source)
    headers = list(_GROUNDING_EXCERPT_HEADER_RE.finditer(remainder))
    for i, header in enumerate(headers):
        body = remainder[header.end():(headers[i + 1].start() if i + 1 < len(headers) else len(remainder))]
        section = _MARKDOWN_SECTION_HEADING_RE.search(body)
        blocks.append(body[:section.start()] if section else body)
    if not blocks:
        blocks = [source]
    units: "List[str]" = []
    for block in blocks:
        units.extend(_split_diff_hunks(block))
    return units


def _citation_precedes_within_one_block(
    earlier_raw: "Optional[str]", later_raw: "Optional[str]", *sources: str,
) -> bool:
    """True only when some ONE rendered block (see `_ordering_blocks`) of
    some ONE supplied source contains both citations, with the earlier
    citation's first occurrence strictly before the later citation's
    first occurrence WITHIN that block. Never compares positions across
    blocks or sources, and a duplicate copy of either line in another
    block can neither establish nor defeat a block's own ordering. Still
    only the NECESSARY textual-order signal `_citation_precedes`
    documents -- never control-flow proof."""
    earlier = _normalize_for_provenance(_strip_quote_wrapping(earlier_raw))
    later = _normalize_for_provenance(_strip_quote_wrapping(later_raw))
    if not earlier or not later:
        return False
    for source in sources:
        for unit in _ordering_blocks(source):
            normalized_unit = _normalize_for_provenance(unit)
            off_earlier = normalized_unit.find(earlier)
            off_later = normalized_unit.find(later)
            if off_earlier != -1 and off_later != -1 and off_earlier < off_later:
                return True
    return False


# ---------------------------------------------------------------------------
# Mechanical completeness proof for `preceding_guard == absent`.
#
# `_WHOLE_FUNCTION_MARKER`/`_whole_function_marker_valid` and a grounded
# `Function provenance:` citation are NECESSARY but were never sufficient on
# their own -- neither can prove the evidence patch_challenger.py received
# actually contains the COMPLETE containing function, as opposed to a
# windowed/partial excerpt that simply happens not to show a guard within
# its own bounds. This module NEVER invents that proof, and NEVER accepts
# the model's own claim as a substitute for it (that would just relabel the
# same trust problem).
#
# What it reuses instead: `remediation_planner.py` already renders certain
# repository-evidence blocks under a small, fixed set of deterministic
# headings -- produced by Python code, never by the LLM, and already part
# of the plain `code_context` string this module has always received (no
# new pipeline/context plumbing is added here):
#   - `_render_full_file_block`      -> "#### Full file (last resort): ..."
#   - `_render_definition_block`     -> "#### Target definition: ..."
#                                        (default heading_label)
#                                     -> "#### Related definition (context
#                                        only, not an approved edit
#                                        target): ..." (_CATEGORY2_HEADING_
#                                        LABEL; still a resolved symbol's
#                                        own declared span -- this heading
#                                        only disclaims edit-target
#                                        AUTHORITY, never span completeness)
# A block rendered under any of these three headings is, by that renderer's
# own contract, either an entire file's real on-disk content or a resolved
# symbol's own complete declared source -- never a padded or truncated
# window. Deliberately NOT trusted: "#### Discovered consumer: ..." blocks
# (a DIFFERENT renderer, for usage windows around a call site -- a
# deliberately partial view by design, not a definition).
#
# `preceding_guard == absent` is accepted only when BOTH the containing-
# function citation and the operation citation are point-citable against
# THE SAME one such block's own fenced source -- never against
# `code_context` as an undifferentiated whole -- with the function's own
# citation textually preceding the operation's within that block. Absent
# such a block, `absent` fails closed to `unresolved`, exactly as every
# other ungrounded v2 claim already does.
# ---------------------------------------------------------------------------

_MECHANICALLY_VERIFIED_COMPLETE_BLOCK_RE = re.compile(
    r"^####[ \t]+(?:"
    r"Full file \(last resort\)"
    r"|Target definition"
    r"|Related definition \(context only, not an approved edit target\)"
    r")[ \t]*:[ \t]*`[^`\n]*`[ \t]*\([^)\n]*\)\n\n```python\n(.*?)\n```",
    re.MULTILINE | re.DOTALL,
)


def _mechanically_verified_complete_blocks(code_context: "Optional[str]"):
    """Yield the fenced source text of every block in `code_context`
    already rendered under one of the trusted deterministic headings (see
    this section's own module comment above) -- a generator over
    Python-produced structure already present in a string this module has
    always received, never a new signal invented here."""
    for match in _MECHANICALLY_VERIFIED_COMPLETE_BLOCK_RE.finditer(code_context or ""):
        yield match.group(1)


def _absence_mechanically_verified_complete(
    function_prov: "Optional[str]", op_prov: "Optional[str]", code_context: "Optional[str]",
) -> bool:
    """The independent, mechanical completeness proof `preceding_guard ==
    absent` requires (see this section's own module comment). True only
    when BOTH `function_prov` and `op_prov` are point-citable against the
    SAME trusted block's own source text, with `function_prov`'s offset
    strictly before `op_prov`'s WITHIN that one block -- never mixed
    across two different blocks, and never against `code_context` as a
    whole (which would let a citation from one file/symbol's trusted
    block "borrow" completeness for an unrelated citation elsewhere)."""
    for block_source in _mechanically_verified_complete_blocks(code_context):
        if _point_citation_valid(function_prov, block_source) and _point_citation_valid(op_prov, block_source):
            if _citation_precedes(function_prov, op_prov, block_source):
                return True
    return False


def _malformed_concern(reason: str) -> dict:
    return {
        "concern_role": None,
        "description": "",
        "default_execution_reachability": None,
        "requires_explicit_non_default_action": None,
        "contract_addresses_override": None,
        "malformed": True,
        "malformed_reason": reason,
        "consequence": "UNRESOLVED",
    }


def _concern_consequence(reachability: str, override: str, scope: str) -> str:
    """Deterministic per-concern policy -- the frozen Challenger scope
    policy applied to one already-validated concern's effective (post
    provenance-gating) fact values. Monotonic and fail-closed: every
    branch is either a positive derivation from an already-validated fact
    or an explicit fall-through to UNRESOLVED; no branch can reach
    NON_BLOCKING from a missing, invalid, or ungrounded fact."""
    if reachability == "unresolved":
        return "UNRESOLVED"
    if reachability == "reachable":
        return "BLOCKING"
    # reachability == "blocked"
    if override == "unresolved":
        return "UNRESOLVED"
    if override == "false":
        return "NON_BLOCKING"
    # override == "true"
    if scope == "explicitly_included":
        return "BLOCKING"
    if scope in ("explicitly_excluded", "silent"):
        return "NON_BLOCKING"
    return "UNRESOLVED"  # scope == "unresolved"


def _extract_override_scope_fields(block: str):
    """Extract the four override/scope fields' raw text from an already-
    isolated concern block -- identical regardless of schema version
    (v1-direct or v2-derived reachability), since neither field's own
    meaning or gating ever depended on HOW reachability was established,
    only on its final value. Shared by `_parse_concern_block` (v1) and
    `_parse_concern_block_v2` so this logic exists in exactly one place."""
    override = _extract_concern_field(block, "Requires explicit non-default action")
    override_prov = _extract_concern_field(block, "Override provenance")
    scope = _extract_concern_field(block, "Contract addresses override")
    scope_prov = _extract_concern_field(block, "Scope provenance")
    return (
        override.strip().lower() if override is not None else None,
        override_prov,
        scope.strip().lower() if scope is not None else None,
        scope_prov,
    )


def _validate_and_resolve_override_scope(
    reachability: str, override, override_prov, scope, scope_prov, code_context: str, patch: str, vulnerability_text: str,
):
    """Given an ALREADY-DETERMINED `reachability` (v1-direct or
    v2-derived -- this function never cares which) and the block's raw
    override/scope field values, apply the existing applicability gates
    and provenance-gating exactly as `_parse_concern_block` always has.
    Returns `(effective_override, effective_scope)` on success, or a
    malformed-reason string on any applicability-gate violation -- the
    caller wraps that string in `_malformed_concern`."""
    if reachability == "blocked":
        if override not in ("true", "false", "unresolved"):
            return "override_applicability_violated"
    else:
        if override != "not_applicable":
            return "override_applicability_violated"

    if override == "true":
        if scope not in ("explicitly_included", "explicitly_excluded", "silent", "unresolved"):
            return "scope_applicability_violated"
    else:
        if scope != "not_applicable":
            return "scope_applicability_violated"

    effective_override = override
    if override == "true" and not _point_citation_valid(override_prov, code_context, patch):
        effective_override = "unresolved"

    effective_scope = scope
    if scope in ("explicitly_included", "explicitly_excluded"):
        if not _point_citation_valid(scope_prov, vulnerability_text):
            effective_scope = "unresolved"
    elif scope == "silent":
        if not _whole_document_marker_valid(scope_prov):
            effective_scope = "unresolved"

    return effective_override, effective_scope


def _parse_concern_block(
    block: str, code_context: str, patch: str, vulnerability_text: str,
) -> dict:
    """Parse and deterministically validate ONE already-isolated concern
    block. Never raises on malformed input -- every failure mode fails
    closed to `consequence: "UNRESOLVED"`.

    Validation order, each gate independent of the model's own free-text
    wording:
      1. `Role:` must be exactly one of CONCERN_ROLES.
      2. `Default execution reachability:` must be exactly one of
         REACHABILITY_VALUES.
      3. `Requires explicit non-default action:` applicability -- must be
         one of true/false/unresolved when reachability == "blocked", and
         must be exactly `not_applicable` otherwise. A mismatch is
         malformed, never silently corrected or ignored.
      4. `Contract addresses override:` applicability -- the symmetric
         gate keyed on the override field.
    Any gate failure fails the WHOLE concern closed to UNRESOLVED; the
    per-concern policy function is never reached with an internally
    inconsistent combination.

    Only once every gate above passes does provenance-gating run: a
    resolved reachability/override claim without a citation mechanically
    present in the repository/diff evidence this run received, or a scope
    claim without a citation mechanically present in the complete
    `vulnerability_text` this run received (in the shape its own value
    requires), is demoted to `"unresolved"` for that one fact -- a
    demotion, never a schema violation, and never silently trusted."""
    role = _extract_concern_field(block, "Role")
    description = _extract_concern_field(block, "Description") or ""
    reachability = _extract_concern_field(block, "Default execution reachability")
    reach_prov = _extract_concern_field(block, "Reachability provenance")

    role = role.strip().lower() if role is not None else None
    reachability = reachability.strip().lower() if reachability is not None else None

    if role not in CONCERN_ROLES:
        return _malformed_concern("invalid_or_missing_role")
    if reachability not in REACHABILITY_VALUES:
        return _malformed_concern("invalid_or_missing_reachability")

    effective_reachability = reachability
    if reachability in ("reachable", "blocked") and not _point_citation_valid(reach_prov, code_context, patch):
        effective_reachability = "unresolved"

    # The applicability gate is checked against the RAW, directly-asserted
    # `reachability` (never `effective_reachability`) -- self-consistency
    # of the model's own answer is a separate concern from whether that
    # answer's own citation later grounds it; a "blocked" claim that gets
    # provenance-demoted to unresolved must not retroactively make its
    # own override field's shape wrong (unchanged from pre-refactor
    # behavior -- see _validate_and_resolve_override_scope's own docstring).
    override, override_prov, scope, scope_prov = _extract_override_scope_fields(block)
    resolved = _validate_and_resolve_override_scope(
        reachability, override, override_prov, scope, scope_prov, code_context, patch, vulnerability_text,
    )
    if isinstance(resolved, str):
        return _malformed_concern(resolved)
    effective_override, effective_scope = resolved

    consequence = _concern_consequence(effective_reachability, effective_override, effective_scope)

    return {
        "concern_role": role,
        "description": description,
        "default_execution_reachability": effective_reachability,
        "requires_explicit_non_default_action": effective_override,
        "contract_addresses_override": effective_scope,
        "malformed": False,
        "malformed_reason": None,
        "consequence": consequence,
    }


# ---------------------------------------------------------------------------
# concerns_v2 -- deterministic derivation + atomic-fact block parser.
# ---------------------------------------------------------------------------


def _derive_default_execution_reachability(facts: "Dict[str, str]") -> str:
    """Pure, deterministic derivation of `reachable|blocked|unresolved`
    from the five already-validated, already-provenance-gated v2 atomic
    facts (see `PRECEDING_GUARD_VALUES` and siblings for each field's own
    meaning/applicability). Bounded (11 explicit rules), fail-closed (an
    `unresolved` component at any hop propagates -- no branch reaches
    `reachable`/`blocked` from an ungrounded input), and vulnerability-
    agnostic (no domain-specific concept anywhere in this function).

    Callers must supply EFFECTIVE values only (post applicability-gating
    and post provenance-demotion, exactly as `_parse_concern_block_v2`
    computes them) -- this function performs no validation of its own and
    trusts its input's shape completely; any combination not explicitly
    matched below (including a value outside its field's own enum) falls
    through to the same `unresolved` catch-all every other fail-closed
    gate in this module uses."""
    operation = facts.get("operation_present_in_evidence")
    guard = facts.get("preceding_guard")
    default_state = facts.get("guard_default_state")
    effect = facts.get("guard_effect")
    reentry = facts.get("reentry_state_propagation")

    if operation != "present":
        return "unresolved"  # rule 1 (and any other non-"present" value)

    if guard == "unresolved":
        return "unresolved"  # rule 2
    if guard == "absent":
        # De-escalated (was "reachable"): `_absence_mechanically_verified_
        # complete` only proves the cited span is the COMPLETE function --
        # it never verifies that "no guard" is semantically true of that
        # span's content. A bounded-absence claim is still an unverified
        # LLM semantic assertion, categorically weaker than a positively-
        # cited fact (`guard == "present"`, below), so it must not, by
        # itself, license the same "reachable" conclusion a positive
        # citation chain can. Fails closed to "unresolved" until some
        # independently authoritative mechanism (out of scope for this
        # module) corroborates it.
        return "unresolved"  # rule 3
    if guard != "present":
        return "unresolved"  # catch-all: malformed/impossible guard value

    if default_state == "unresolved":
        return "unresolved"  # rule 4
    if default_state == "condition_false_under_default":
        return "reachable"  # rule 5
    if default_state != "condition_true_under_default":
        return "unresolved"  # catch-all: malformed/impossible default_state

    if effect == "unresolved":
        return "unresolved"  # rule 6
    if effect == "no_effect":
        return "reachable"  # rule 7
    if effect not in ("prevents_operation", "neutralizes_operation"):
        return "unresolved"  # catch-all: malformed/impossible effect

    if reentry == "not_applicable":
        return "blocked"  # rule 8
    if reentry == "unresolved":
        return "unresolved"  # rule 9
    if reentry == "reset_or_bypassed":
        return "reachable"  # rule 10
    if reentry == "preserved":
        return "blocked"  # rule 11

    return "unresolved"  # catch-all: malformed/impossible reentry value


def _normalize_v2_override_scope(
    reachability: str, override, override_prov, scope, scope_prov, code_context: str, patch: str, vulnerability_text: str,
):
    """v2-only override/scope applicability normalization -- deliberately
    NOT `_validate_and_resolve_override_scope` (v1, and its own history,
    left completely UNCHANGED by this function's existence -- see that
    function's own docstring and the regression tests protecting it).

    In v1, the model directly asserts `reachability` itself, so a
    contradiction between its own `Requires explicit non-default action`
    and its own `Default execution reachability` is genuine model self-
    contradiction with full information available -- `_validate_and_
    resolve_override_scope`'s strict reject-the-whole-concern behavior is
    correct and intentional there.

    In v2, `reachability` is instead DERIVED, deterministically, from
    five separately-reported atomic facts (`_derive_default_execution_
    reachability`) -- a formula the model is explicitly told never to
    compute or report. A mismatch between the model's own applicability
    GUESS for `Requires explicit non-default action`/`Contract addresses
    override` and the actual derived `reachability` is therefore not
    model self-contradiction; it is, at most, a wrong guess about a value
    the model was never given the formula for. Discarding the whole
    concern (all five atomic facts, `hypothesized_outcome`, `description`)
    over that alone is a strictly harsher failure mode than the
    information gap warrants, especially since `_concern_consequence`
    already never reads `override`/`scope` at all unless `reachability ==
    "blocked"` -- making the override field provably inert to the final
    outcome in every OTHER branch regardless of what the model wrote.

    Semantics:
      - `reachability != "blocked"`: override/scope are not applicable at
        all -- forced to `"not_applicable"` unconditionally, regardless
        of the model's raw guess. Never malformed for this alone.
      - `reachability == "blocked"`: override IS applicable. A raw value
        outside `{true, false, unresolved}` (including `not_applicable`
        -- a real archived-response shape) fails closed to `"unresolved"`
        for that ONE fact, exactly mirroring this module's own provenance-
        demotion discipline elsewhere -- never a whole-concern malform.
      - `scope`'s applicability is evaluated against the EFFECTIVE
        (normalized) override, never the model's raw one, so the same
        shape of bug cannot reappear one field downstream. Once override
        is genuinely, effectively `"true"`, scope's own domain and
        provenance requirements are UNCHANGED from `_validate_and_
        resolve_override_scope` -- that remaining validation depends only
        on a value the model itself directly asserted (now confirmed
        true), so it stays fully coherent and is not weakened.

    Returns `(effective_override, effective_scope)` on success, or a
    malformed-reason string (only ever `"scope_applicability_violated"`,
    for a genuinely-applicable-but-invalid scope value) -- the caller
    wraps that string in `_malformed_concern`, exactly like
    `_validate_and_resolve_override_scope`'s own contract."""
    if reachability != "blocked":
        return "not_applicable", "not_applicable"

    effective_override = override if override in ("true", "false", "unresolved") else "unresolved"
    if effective_override == "true" and not _point_citation_valid(override_prov, code_context, patch):
        effective_override = "unresolved"

    if effective_override != "true":
        return effective_override, "not_applicable"

    if scope not in ("explicitly_included", "explicitly_excluded", "silent", "unresolved"):
        return "scope_applicability_violated"

    effective_scope = scope
    if scope in ("explicitly_included", "explicitly_excluded"):
        if not _point_citation_valid(scope_prov, vulnerability_text):
            effective_scope = "unresolved"
    elif scope == "silent":
        if not _whole_document_marker_valid(scope_prov):
            effective_scope = "unresolved"

    return effective_override, effective_scope


def _parse_concern_block_v2(
    block: str, code_context: str, patch: str, vulnerability_text: str,
) -> dict:
    """Parse and deterministically validate ONE already-isolated
    `concerns_v2` concern block: five atomic reachability facts (each
    independently gated and provenance-checked) feed
    `_derive_default_execution_reachability`, whose OUTPUT then flows into
    `_normalize_v2_override_scope` (see its own docstring for exactly why
    this is NOT the same `_validate_and_resolve_override_scope` function
    `_parse_concern_block` (v1) uses -- v2's `reachability` is derived,
    never model-asserted, so a v1-shaped strict reject-on-mismatch gate
    is the wrong contract here) and then into the SAME, untouched
    `_concern_consequence` every schema version shares.

    Never raises on malformed input -- like `_parse_concern_block`, every
    failure mode fails closed: an atomic-fact applicability-gate mismatch
    (the five reachability facts above) produces a malformed concern
    (`consequence: "UNRESOLVED"`); an ungrounded provenance claim demotes
    only that ONE fact to `unresolved` (never the whole concern
    malformed); a `Requires explicit non-default action`/`Contract
    addresses override` mismatch against the now-known `reachability` is
    NORMALIZED by `_normalize_v2_override_scope`, not rejected -- see its
    own docstring. This exactly mirrors `_parse_concern_block`'s own
    `effective_reachability`/`effective_override`/`effective_scope`
    discipline.

    AUTHORITY BOUNDARY: `description` and `hypothesized_outcome` (see its
    own extraction comment below) are both explanatory/non-authoritative
    free text, returned for human readability only. Neither one is read
    by `_derive_default_execution_reachability` or `_concern_consequence`
    -- both are computed, from the five gated atomic facts alone, before
    either string is ever extracted -- so neither can participate in,
    promote, demote, or otherwise influence `reachability`/`consequence`
    in any way. `hypothesized_outcome` exists so a concern MAY distinguish
    "what the structured atomic facts establish" from "a possible
    implication that goes beyond them" -- but that distinction is for a
    human reader, not for this function's own policy: the field's
    presence, absence, or content changes nothing about the returned
    `reachability`/`consequence` values."""
    role = _extract_concern_field(block, "Role")
    description = _extract_concern_field(block, "Description") or ""
    role = role.strip().lower() if role is not None else None
    if role not in CONCERN_ROLES:
        return _malformed_concern("invalid_or_missing_role")

    # `Hypothesized outcome:` -- OPTIONAL, informational-only text (see
    # this function's own docstring, "AUTHORITY BOUNDARY" paragraph, above).
    # Absent from the block entirely, or the literal value `none`, both
    # normalize to `None` -- neither is a malformed-concern condition,
    # unlike every gated atomic field above. Deliberately NOT passed to
    # `_derive_default_execution_reachability` or `_concern_consequence`,
    # NOT provenance-gated, and NOT given an enum/status of any kind --
    # it carries exactly zero policy authority in this release, same as
    # `description`.
    hypothesized_outcome = _extract_concern_field(block, "Hypothesized outcome")
    if hypothesized_outcome is not None:
        hypothesized_outcome = hypothesized_outcome.strip()
        if not hypothesized_outcome or hypothesized_outcome.lower() in ("none", "n/a"):
            hypothesized_outcome = None

    op_present = _extract_concern_field(block, "Operation present in evidence")
    op_prov = _extract_concern_field(block, "Operation provenance")
    guard = _extract_concern_field(block, "Preceding guard")
    guard_prov = _extract_concern_field(block, "Guard provenance")
    function_prov = _extract_concern_field(block, "Function provenance")
    default_state = _extract_concern_field(block, "Guard default state")
    default_state_prov = _extract_concern_field(block, "Guard default state provenance")
    effect = _extract_concern_field(block, "Guard effect")
    effect_prov = _extract_concern_field(block, "Guard effect provenance")
    reentry = _extract_concern_field(block, "Reentry state propagation")
    reentry_prov = _extract_concern_field(block, "Reentry provenance")

    op_present = op_present.strip().lower() if op_present is not None else None
    guard = guard.strip().lower() if guard is not None else None
    default_state = default_state.strip().lower() if default_state is not None else None
    effect = effect.strip().lower() if effect is not None else None
    reentry = reentry.strip().lower() if reentry is not None else None

    # --- Applicability gates, sequential and fail-closed -- a mismatch at
    # any hop is a malformed concern, never silently corrected, exactly
    # mirroring OVERRIDE_VALUES/SCOPE_VALUES's own discipline. ---
    if op_present not in OPERATION_PRESENCE_VALUES:
        return _malformed_concern("invalid_or_missing_operation_present")

    if op_present == "present":
        if guard not in ("present", "absent", "unresolved"):
            return _malformed_concern("invalid_or_missing_preceding_guard")
    else:
        if guard != "not_applicable":
            return _malformed_concern("preceding_guard_applicability_violated")

    if guard == "present":
        if default_state not in (
            "condition_true_under_default", "condition_false_under_default", "unresolved",
        ):
            return _malformed_concern("guard_default_state_applicability_violated")
    else:
        if default_state != "not_applicable":
            return _malformed_concern("guard_default_state_applicability_violated")

    if default_state == "condition_true_under_default":
        if effect not in ("prevents_operation", "neutralizes_operation", "no_effect", "unresolved"):
            return _malformed_concern("guard_effect_applicability_violated")
    else:
        if effect != "not_applicable":
            return _malformed_concern("guard_effect_applicability_violated")

    if effect in ("prevents_operation", "neutralizes_operation"):
        if reentry not in ("preserved", "reset_or_bypassed", "not_applicable", "unresolved"):
            return _malformed_concern("reentry_propagation_applicability_violated")
    else:
        if reentry != "not_applicable":
            return _malformed_concern("reentry_propagation_applicability_violated")

    # --- Provenance gating: demote (never malform) an ungrounded resolved
    # claim to `unresolved` for that ONE fact -- mirrors
    # `_parse_concern_block`'s own effective_reachability/effective_
    # override/effective_scope discipline exactly. ---
    effective_op_present = op_present
    if op_present == "present" and not _point_citation_valid(op_prov, code_context, patch):
        effective_op_present = "unresolved"

    effective_guard = guard
    if effective_op_present != "present":
        effective_guard = "not_applicable"
    elif guard == "present":
        if not _point_citation_valid(guard_prov, code_context, patch):
            effective_guard = "unresolved"
        elif not _citation_precedes_within_one_block(guard_prov, op_prov, code_context, patch):
            # Necessary-but-not-sufficient ordering check (see
            # _citation_precedes_within_one_block) -- a guard citation not
            # textually before the operation's own citation, inside ONE
            # rendered evidence block, can never establish a PRECEDING guard.
            effective_guard = "unresolved"
    elif guard == "absent":
        # Bounded-absence rule: the `whole function` marker and a grounded
        # Function provenance citation are NECESSARY but never SUFFICIENT
        # by themselves -- neither can prove the evidence shown is the
        # COMPLETE containing function rather than a partial/windowed
        # excerpt. `_absence_mechanically_verified_complete` is the
        # independent, mechanical proof this fact actually requires: BOTH
        # citations must be found in the SAME block an existing
        # repository-evidence renderer already marks, deterministically,
        # as complete (see that function's own module comment). Never
        # inferred from the model's own claim, and never invented here.
        if not _whole_function_marker_valid(guard_prov):
            effective_guard = "unresolved"
        elif not _absence_mechanically_verified_complete(function_prov, op_prov, code_context):
            effective_guard = "unresolved"

    effective_default_state = default_state
    if effective_guard != "present":
        effective_default_state = "not_applicable"
    elif default_state in ("condition_true_under_default", "condition_false_under_default"):
        if not _point_citation_valid(default_state_prov, code_context, patch):
            effective_default_state = "unresolved"

    effective_effect = effect
    if effective_default_state != "condition_true_under_default":
        effective_effect = "not_applicable"
    elif effect in ("prevents_operation", "neutralizes_operation", "no_effect"):
        if not _point_citation_valid(effect_prov, code_context, patch):
            effective_effect = "unresolved"

    effective_reentry = reentry
    if effective_effect not in ("prevents_operation", "neutralizes_operation"):
        effective_reentry = "not_applicable"
    elif reentry in ("preserved", "reset_or_bypassed"):
        if not _point_citation_valid(reentry_prov, code_context, patch):
            effective_reentry = "unresolved"

    facts = {
        "operation_present_in_evidence": effective_op_present,
        "preceding_guard": effective_guard,
        "guard_default_state": effective_default_state,
        "guard_effect": effective_effect,
        "reentry_state_propagation": effective_reentry,
    }
    reachability = _derive_default_execution_reachability(facts)

    override, override_prov, scope, scope_prov = _extract_override_scope_fields(block)
    resolved = _normalize_v2_override_scope(
        reachability, override, override_prov, scope, scope_prov, code_context, patch, vulnerability_text,
    )
    if isinstance(resolved, str):
        return _malformed_concern(resolved)
    effective_override, effective_scope = resolved

    consequence = _concern_consequence(reachability, effective_override, effective_scope)

    return {
        "concern_role": role,
        "description": description,
        "default_execution_reachability": reachability,
        "requires_explicit_non_default_action": effective_override,
        "contract_addresses_override": effective_scope,
        "malformed": False,
        "malformed_reason": None,
        "consequence": consequence,
        # Additive only -- no existing consumer reads this key. Surfaces
        # WHICH atomic fact the derived reachability actually rests on,
        # for observability/debugging and as the natural anchor point for
        # a future (explicitly out-of-scope here) evidence-acquisition
        # layer keyed on the first-unresolved fact.
        "reachability_facts": facts,
        # Additive only, informational -- see the field's own extraction
        # comment above. Never read by `reachability`/`consequence` above,
        # already computed by the time this dict is built.
        "hypothesized_outcome": hypothesized_outcome,
    }


_V2_DISCRIMINATOR_RE = re.compile(r"^[ \t]*(?:\d+\.\s*)?Preceding guard:\s*", re.IGNORECASE | re.MULTILINE)


def _response_uses_v2_schema(concerns_body: "Optional[str]") -> bool:
    """Whether this `Concerns:` body uses the `concerns_v2` atomic-
    reachability field set -- detected purely from the RAW RESPONSE TEXT,
    never an external flag, so an ARCHIVED `concerns_v1` trace, replayed
    by re-parsing its own stored text, is routed identically at replay
    time as it was at original parse time. The `Preceding guard:` field
    label did not exist before this schema, so no legacy v1 response --
    archived or hypothetical -- can ever match this.

    This is a single, response-level decision, never a per-block fallback:
    once a response is routed to v2 (this returns True), EVERY concern
    block in it goes through `_parse_concern_block_v2` (see
    `_parse_concerns`) -- a block that does not itself carry the v2 fields
    fails closed on its own missing/invalid fields there, rather than
    being silently reinterpreted as a legacy v1 block."""
    return bool(_V2_DISCRIMINATOR_RE.search(concerns_body or ""))


def _parse_concerns(
    concerns_body: "Optional[str]", code_context: str, patch: str, vulnerability_text: str,
) -> "List[dict]":
    if not concerns_body:
        return []
    blocks = _split_concern_blocks(concerns_body)
    use_v2 = _response_uses_v2_schema(concerns_body)
    concerns: "List[dict]" = []
    for num in sorted(blocks):
        span = blocks[num]
        if span is None:
            concerns.append(_malformed_concern("duplicate_concern_number"))
        elif use_v2:
            concerns.append(_parse_concern_block_v2(span, code_context, patch, vulnerability_text))
        else:
            concerns.append(_parse_concern_block(span, code_context, patch, vulnerability_text))
    return concerns


def _derive_status_from_concerns(
    concerns: "List[dict]", legacy_prose_present: bool,
) -> "Tuple[str, bool]":
    """Deterministic run-level aggregation from already-scored concerns to
    the legacy-compatible `(verification_status, still_vulnerable)` pair --
    frozen precedence BLOCKING > UNRESOLVED > NON_BLOCKING, plus two
    fail-closed gates the per-concern policy alone cannot express:

    - `legacy_prose_present`: a response using the `Concerns:` schema must
      never ALSO carry substantive free-form content in `Edge cases:`,
      `Potential issues:`, OR `Summary:` -- ANY of the three, not only the
      first two (see `challenge_patch`'s own computation of this flag,
      which folds in `Summary:` for exactly this reason: a verdict-
      relevant concern described only in a free-form summary paragraph,
      never given its own `Concerns:` block, would otherwise be able to
      vanish from adjudication entirely while every structured concern
      computes clean). There is no safe, non-semantic-guessing way to
      match unstructured prose back to a structured concern block, so
      rather than guess, ANY substantive content in any of these three
      sections alongside a `Concerns:` section forces the whole run
      closed -- every verdict-relevant concern must be represented
      structurally once this schema is in use.
    - Exactly one `primary` concern is mandatory; zero, more than one, or
      a completely unparseable `Concerns:` body (every block malformed or
      absent) all converge on this same `count(primary) != 1` gate -- no
      separate "totally malformed schema" special case is needed."""
    if legacy_prose_present:
        return "INSUFFICIENT_EVIDENCE", True

    primaries = [c for c in concerns if c.get("concern_role") == "primary"]
    if len(primaries) != 1:
        return "INSUFFICIENT_EVIDENCE", True

    consequences = [c["consequence"] for c in concerns]
    if "BLOCKING" in consequences:
        return "RESIDUAL_VULNERABILITY", True
    if "UNRESOLVED" in consequences:
        return "INSUFFICIENT_EVIDENCE", True
    return "VERIFIED_FIXED", False


_PLACEHOLDER_VALUES = ("", "none", "n/a")
"""Shared "this section is intentionally empty" vocabulary for every
legacy free-text section (`Edge cases:`, `Potential issues:`, `Summary:`)
in a new-schema response -- see `challenge_patch`'s structural-violation
check. A bare placeholder is not "content" for this purpose; anything
else is, regardless of what it says -- this is a presence/shape check,
never a reading of what the text means."""

_PLACEHOLDER_BULLET_RE = re.compile(r"^[-*+]\s*")
"""A single leading bullet marker, exactly like `_lines_from_bullets`
strips from `Edge cases:`/`Potential issues:` entries. `Summary:` is a
free-text section (not bullet-parsed by `_split_sections`), so its own
placeholder check must strip this same, single, formatting-only marker
itself -- the prompt teaches `- none`/`* none` as the documented way to
leave ANY of the three sections empty, so a placeholder wrapped in that
syntax must be recognized as empty everywhere, not only in the two
sections that already happen to go through `_lines_from_bullets`."""


def _is_placeholder(text: "Optional[str]") -> bool:
    """Whether `text` is the documented "intentionally empty" marker,
    tolerant of a single leading list-formatting bullet (`-`/`*`/`+`) and
    surrounding whitespace -- a purely syntactic strip, applied at most
    once, never a semantic reading. `"- none"` and `"none"` are the same
    placeholder; `"- none, but also X"` is not a placeholder at all (the
    bullet strip does not consume anything past the marker itself, so any
    real content immediately after `none`/`n/a` still fails this check
    and is correctly treated as substantive)."""
    stripped = (text or "").strip()
    stripped = _PLACEHOLDER_BULLET_RE.sub("", stripped, count=1)
    return stripped.strip().lower() in _PLACEHOLDER_VALUES


def _synthesize_summary_from_concerns(concerns: "List[dict]", structural_violation: bool) -> str:
    """Deterministically build the report-facing `summary` string for a
    new-schema response from already-validated `concerns` alone -- the
    model's own free-form `Summary:` text is never used here, by design
    (see `challenge_patch`): a summary built this way cannot contain any
    claim beyond what deterministic aggregation already accounted for,
    so it can never mislead a report reader about what the (fail-closed)
    machine decision was actually based on."""
    if structural_violation:
        return (
            "Structural contract violation: substantive free-form content was present "
            "in Edge cases, Potential issues, or Summary alongside a structured Concerns "
            "response; this run failed closed and is not summarized further."
        )
    if not concerns:
        return "No concerns were reported."
    parts = []
    for c in concerns:
        role_label = "Primary concern" if c.get("concern_role") == "primary" else "Additional concern"
        description = c.get("description") or "(no description provided)"
        parts.append(f"{role_label}: {description} ({c.get('consequence', 'UNRESOLVED')}).")
    return " ".join(parts)


def challenge_patch(
    vulnerability_text: str, patch: str, llm, code_context: str = "",
    provenance_context: "Optional[str]" = None,
) -> dict:
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
    provenance_context:
        Citation-authority boundary. The corpus against which every
        repository/diff provenance citation in a structured `Concerns:`
        response is validated (together with `patch`), in place of
        `code_context`. `code_context` is what the model is SHOWN; it can
        also carry model-authored narrative (Planner/Strategy prose), and
        a quote must never become trusted repository evidence merely
        because it appears there. Callers that know which shown sections
        are repository-derived pass exactly those here (see
        pipeline._challenger_provenance_context). `None` keeps the
        previous behavior (validate against `code_context`) for callers
        that do not supply one. Scope citations are unaffected: they are
        still validated against `vulnerability_text` only.

    Returns a dict with keys: `verification_status` (one of
    `VERIFICATION_STATUSES`, or `None` -- see `_parse_verification`),
    `still_vulnerable` (bool, a backward-compatible projection derived from
    `verification_status` -- never independently set), `edge_cases`
    (list[str]), `potential_issues` (list[str]), and `summary` (str).

    A response containing a `Concerns:` section (see `_parse_concerns`)
    additionally gets two keys, absent from every other response so no
    pre-existing caller/test asserting the legacy 5-key shape is affected:
    `concerns` (list[dict], the parsed/validated per-concern facts) and
    `schema_version` (`"concerns_v1"` when each concern block directly
    asserts `Default execution reachability:`, or `"concerns_v2"` when the
    block instead carries the atomic `Preceding guard:` fact set that
    `_derive_default_execution_reachability` derives that same value from
    -- see `_response_uses_v2_schema`; a per-response, text-only decision
    that keeps replay of an archived v1 trace byte-identical). For such a response,
    `verification_status`/`still_vulnerable` are DERIVED deterministically
    from `concerns` (`_derive_status_from_concerns`) -- a `Verification
    status:` header the model also writes is report-only text and is
    never read for the decision. `summary` is ALSO replaced for such a
    response -- deterministically synthesized from `concerns`
    (`_synthesize_summary_from_concerns`), never the model's own free-form
    `Summary:` text -- because a verdict-relevant concern described only
    in prose, with no corresponding structured block, must not be able to
    silently escape adjudication; any substantive (non-placeholder)
    content in `Summary:` (exactly like `Edge cases:`/`Potential issues:`)
    instead forces the whole run closed. A response with NO `Concerns:`
    header at all is completely unaffected: `_parse_verification` remains
    its sole authority and `summary` remains the model's own raw text,
    byte-for-byte identical to before this schema existed.
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

    edge_cases = _lines_from_bullets(sections.get("edge_cases", ""))
    potential_issues = _lines_from_bullets(sections.get("potential_issues", ""))
    summary = sections.get("summary", resp.strip())

    if sections.get("concerns") is not None:
        concerns_body = sections["concerns"]
        citation_corpus = code_context if provenance_context is None else provenance_context
        concerns = _parse_concerns(concerns_body, citation_corpus, patch, vulnerability_text)
        # A bare placeholder (see _PLACEHOLDER_VALUES) is the prompt's own
        # documented way to leave a legacy section empty -- it must count
        # as empty here too, never as real, unstructured content that
        # trips the structural-violation gate below. `summary` is checked
        # on exactly the same footing as `edge_cases`/`potential_issues`:
        # a verdict-relevant concern described only in a free-form summary
        # paragraph -- never given its own `Concerns:` block -- must not
        # be able to vanish from adjudication while every structured
        # concern computes clean. There is no safe, non-semantic-guessing
        # way to tell a "substantive new claim" apart from "a bland
        # restatement" in prose, so no attempt is made to -- ANY
        # non-placeholder content in ANY of the three sections forces the
        # whole run closed, regardless of what it says. `_is_placeholder`
        # (not a bare string-equality check) is what recognizes the
        # prompt's own documented `- none`/`* none` bullet-formatted
        # placeholder as empty -- a real N=5 regression run showed every
        # response correctly writing `Summary:\n- none` and still failing
        # this gate, because `summary` (unlike edge_cases/potential_issues)
        # is never passed through `_lines_from_bullets`.
        structural_violation = (
            any(not _is_placeholder(line) for line in edge_cases + potential_issues)
            or not _is_placeholder(sections.get("summary"))
        )
        verification_status, still = _derive_status_from_concerns(concerns, structural_violation)
        # The model's own free-form `Summary:` text is never returned as
        # the report-facing summary for a new-schema response -- see
        # `_synthesize_summary_from_concerns`'s own docstring for why.
        summary = _synthesize_summary_from_concerns(concerns, structural_violation)
        # The documented placeholder (`- none`) is the contract's way of
        # leaving these legacy sections EMPTY (see _is_placeholder and the
        # structural-violation gate above); it is never a finding, so it
        # must not reach downstream finding classification, calibration,
        # or Validation Actions. Substantive lines are kept unchanged.
        return {
            "verification_status": verification_status,
            "still_vulnerable": still,
            "edge_cases": [line for line in edge_cases if not _is_placeholder(line)],
            "potential_issues": [line for line in potential_issues if not _is_placeholder(line)],
            "summary": summary,
            "concerns": concerns,
            "schema_version": "concerns_v2" if _response_uses_v2_schema(concerns_body) else "concerns_v1",
        }

    verification_status, still = _parse_verification(sections)

    return {
        "verification_status": verification_status,
        "still_vulnerable": still,
        "edge_cases": edge_cases,
        "potential_issues": potential_issues,
        "summary": summary,
    }
