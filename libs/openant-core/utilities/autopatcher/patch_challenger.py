"""
Adversarial patch challenger.

Provides `challenge_patch(vulnerability_text, patch)` which returns a small
structured dict describing edge cases and potential issues discovered by an
LLM-based adversarial check. Uses `LLMClient` (mock-capable) to make queries.
"""

from __future__ import annotations

import bisect
import re
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

from .llm_client import get_call_history
from .run_metadata import _TRUNCATION_STOP_REASONS

_PROMPT_PATH = Path(__file__).parent / "prompts" / "patch_challenger.md"

VERIFICATION_STATUSES = ("VERIFIED_FIXED", "RESIDUAL_VULNERABILITY", "INSUFFICIENT_EVIDENCE")
"""The only three states a NEW-format Challenger response may authoritatively
report -- see `_parse_verification`'s docstring for how this interacts with
the legacy `still_vulnerable` boolean and with malformed/missing input.

For a response using the structured `Concerns:` schema (see
`_parse_concerns`/`_derive_status_from_concerns` below), these three
strings are instead DERIVED deterministically from the concern facts --
never read directly from a `Verification status:` header. The header can
never raise the derived status; a NEGATIVE header can only fail a
VERIFIED_FIXED derivation closed (see `_self_contradiction`). A response without a `Concerns:`
section is not decided by its own stated status either: `challenge_patch`
fails it closed (RB-1). `_parse_verification` is kept for diagnostic
tooling that re-reads archived responses."""

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
cited, and (see `_post_change_guard_holds`) every occurrence of the
operation citation in post-change evidence (a diff hunk, a `Post-patch
definition`, or evidence of code the patch does not touch) is preceded by
an occurrence of the guard citation within the same unit that the patch
does not remove, with at least one such occurrence -- never by positions
across blocks or sources --
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

# Format-tolerant markers used only to detect structure the strict parser
# above could not account for (RB-2) -- never to parse a concern. A
# concern block whose header is written `2)`, `**2. Role:**`, `- Role:`,
# `Concern 2 - Role:`, ... still carries a `Role` field line; if the
# number of such lines differs from the number of strictly-parsed block
# headers, some concern was not parsed as its own block and the response
# fails closed instead of silently merging or dropping it. `Role` is the
# only field label containing that word (see the prompt's field list).
_LENIENT_ROLE_MARKER_RE = re.compile(
    r"^[^\w\n]*(?:concern[ \t]*)?(?:\d+[ \t]*[.):\]-]*[ \t]*)?[^\w\n]*role[^\w\n]*:",
    re.IGNORECASE | re.MULTILINE,
)
_CONCERN_FIELD_LABELS = (
    "Role", "Description", "Default execution reachability", "Reachability provenance",
    "Requires explicit non-default action", "Override provenance", "Contract addresses override",
    "Scope provenance", "Operation present in evidence", "Operation provenance", "Preceding guard",
    "Guard provenance", "Guard default state", "Guard default state provenance", "Guard effect",
    "Guard effect provenance", "Reentry state propagation", "Reentry provenance",
    "Function provenance", "Hypothesized outcome",
)
"""Every concern field label (v1 and v2). `Description` is mandatory in both
schemas, so each concern carries exactly one; see
`_concern_structure_ambiguous`."""


def _lenient_label_re(label: str) -> "re.Pattern":
    """A `label:` field line in any Markdown dress (`**Label:**`, `- Label:`,
    `2) Label:` ...). Detection only -- never used to read a value."""
    return re.compile(
        rf"^[^\w\n]*(?:\d+[ \t]*[.):\]-]*[ \t]*)?[^\w\n]*{re.escape(label)}[^\w\n]*:",
        re.IGNORECASE | re.MULTILINE,
    )


def _concern_structure_ambiguous(concerns_body: str) -> bool:
    """True when the `Concerns:` body holds concern content the strict
    `N. Role:` block parser cannot account for one block per concern
    (RB-2): a block header written differently is merged into its
    neighbor, so that concern -- possibly BLOCKING -- would otherwise
    vanish. Format-independent signals: the number of `Role` and
    `Description` field lines must equal the number of parsed block
    headers, and no field label may repeat inside one parsed block (two
    concerns merged into one span)."""
    strict_blocks = len(_CONCERN_BLOCK_HEADER_RE.findall(concerns_body))
    if len(_LENIENT_ROLE_MARKER_RE.findall(concerns_body)) != strict_blocks:
        return True
    if len(_lenient_label_re("Description").findall(concerns_body)) != strict_blocks:
        return True
    for span in _split_concern_blocks(concerns_body).values():
        if span is None:
            continue  # duplicate block number: already a malformed concern
        if any(len(_lenient_label_re(label).findall(span)) > 1 for label in _CONCERN_FIELD_LABELS):
            return True
    return False


# A line that is a `Concerns` section header in any Markdown dress
# (`Concerns:`, `**Concerns:**`, `### Concerns`, ...). More than one means
# `_split_sections` kept only the last section (RB-2).
_LENIENT_CONCERNS_HEADER_RE = re.compile(
    r"^[ \t>#*_-]*concerns[*_ \t]*(?::|$)", re.IGNORECASE | re.MULTILINE,
)


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
# A response containing NO `Concerns:` header at all carries no
# citation-checked evidence, so `challenge_patch` fails it closed
# (`(None, True)`) rather than trusting its own stated verdict (RB-1). A
# response that DOES contain a `Concerns:` header, however malformed its
# body, is decided only by the structured path above, which itself fails
# closed on malformed or ambiguous structure (RB-2).
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


_MIN_CITATION_CHARS = 3
# A citation must quote code, not diff punctuation: `+++`, `---`, `@@ -1,4`
# contain no identifier character and occur in every patch.
_CITATION_CONTENT_RE = re.compile(r"[A-Za-z_]")
_WORD_CHAR = r"[A-Za-z0-9_]"

# Diff lines that are never file content: a quote matching only these (or
# only lines the patch REMOVES) cannot evidence the post-change state.
_DIFF_FILE_HEADER_RE = re.compile(
    r"^(?:diff --git |index [0-9a-f]+\.\.|--- (?:a/|/dev/null)|\+\+\+ (?:b/|/dev/null)|"
    r"(?:new|deleted) file mode |similarity index |rename (?:from|to) |old mode |new mode |Binary files )"
)
_DIFF_METADATA_LINE_RE = re.compile(
    r"^(?:diff --git |index [0-9a-f]+\.\.[0-9a-f]+|--- (?:a/|/dev/null)|\+\+\+ (?:b/|/dev/null)|@@ -\d)"
)


def _patch_citation_view(patch: str) -> "Tuple[str, set]":
    """The post-change side of `patch` as a citation haystack: context and
    added lines only. File headers and removed (`-`) lines are dropped, and
    each `@@ ... @@` header is reduced to a bare `@@ @@` separator (it keeps
    the per-hunk ordering units of `_ordering_blocks` but carries nothing
    citable). Also returns the text of every line the patch removes and
    does not keep or re-add, so a pre-change copy of it elsewhere in the
    evidence can be excluded too (see `_without_removed_lines`)."""
    out: "List[str]" = []
    removed: set = set()
    kept: set = set()
    for line in (patch or "").splitlines():
        if _DIFF_FILE_HEADER_RE.match(line):
            continue
        if line.startswith("@@"):
            out.append("@@ @@")
            continue
        if line.startswith("-"):
            removed.add(line[1:].strip())
            continue
        if line.startswith("\\"):
            continue  # "\ No newline at end of file"
        kept.add(line[1:].strip() if line[:1] in ("+", " ") else line.strip())
        out.append(line)
    return "\n".join(out), {r for r in removed - kept if r}


def _without_removed_lines(corpus: str, removed_only: set) -> str:
    """`corpus` with diff metadata lines and every line whose text the patch
    removes (a pre-change copy of the target, or a `-`-prefixed rendering of
    it) blanked: such a line can never ground a post-change fact. Blanked,
    not dropped, so an evidence block's lines keep their file line numbers
    (see `_located_blocks`)."""
    out: "List[str]" = []
    for line in (corpus or "").splitlines():
        stripped = line.strip()
        if _DIFF_METADATA_LINE_RE.match(stripped) or stripped in removed_only or (
            stripped[:1] in "+-" and stripped[1:].strip() in removed_only
        ):
            out.append("")
            continue
        out.append(line)
    return "\n".join(out)


def _citation_pattern(quote: str) -> str:
    pattern = re.escape(quote)
    if re.match(_WORD_CHAR, quote[0]):
        pattern = rf"(?<!{_WORD_CHAR})" + pattern
    if re.match(_WORD_CHAR, quote[-1]):
        pattern += rf"(?!{_WORD_CHAR})"
    return pattern


def _find_citation(haystack: str, quote: str) -> int:
    """Offset of `quote` in `haystack` on token boundaries (never a
    mid-identifier substring such as `ete` inside `delete`), or -1."""
    match = re.search(_citation_pattern(quote), haystack)
    return match.start() if match else -1


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
    omission-ledger lookup is needed.

    A quote shorter than _MIN_CITATION_CHARS non-whitespace characters is
    never a citation: a single letter or a two-character keyword occurs in
    almost any corpus, so its containment proves nothing about provenance.
    Nor is a quote with no identifier character (diff punctuation such as
    `+++` or `@@ -1,4`), or one that only matches inside a longer token."""
    quoted = _strip_quote_wrapping(raw)
    if not quoted or quoted.lower() in ("none", "n/a", "unknown"):
        return False
    normalized_quote = _normalize_for_provenance(quoted)
    if len(re.sub(r"\s", "", normalized_quote)) < _MIN_CITATION_CHARS:
        return False
    if not _CITATION_CONTENT_RE.search(normalized_quote):
        return False
    return any(
        _find_citation(_normalize_for_provenance(source), normalized_quote) != -1
        for source in sources if source
    )


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


# ---------------------------------------------------------------------------
# Post-change scoping of `preceding_guard == present` (PR #763 review).
#
# Citation PRESENCE is text-global, so it cannot tell WHICH occurrence of a
# quoted line the model means: a guard the patch removes from the vulnerable
# function still "exists" when the same text survives as context elsewhere,
# in another file, or is re-added in an unrelated function, a pre-change
# evidence block of the patched function still shows the removed guard before
# the operation, and a different guard in another function or file can
# precede another occurrence of the same operation text. The guard claim is
# therefore decided per OCCURRENCE of the operation, only inside units that
# show the post-change code:
#   - each trusted post-patch definition: a changed function's complete
#     post-change source, received as structured data through
#     `challenge_patch(post_patch_definitions=...)` -- never recognized by a
#     heading in the context text, which repository content could imitate;
#   - each diff hunk, read with its removed lines in place, so removing a
#     guard occurrence is an event at a position, never a text set;
#   - repository evidence blocks, each occurrence placed by the block's own
#     heading (path and pre-change line range) -- see "Call-site identity"
#     below.
# Within a unit, the cited guard is in force after a post-change occurrence
# of it, only for an operation in the same function by indentation
# (`_guard_scope_covers`: no line between them dedented below both, such as
# the next function's header), and stops being in force at a removed
# occurrence. Each operation occurrence is then:
#   supporting    -- the guard is in force (and, when a guard effect is
#                    claimed, the cited effect occurs in post-change text
#                    between that guard occurrence and the operation);
#   contradicting -- the guard was removed before it and not re-added, the
#                    guard is in force but the claimed effect is not between
#                    them, no guard precedes it in a complete function, or
#                    the patch adds this occurrence with no guard before it in
#                    its hunk;
#   neutral       -- an unchanged occurrence before any guard event in a
#                    partial window (hunk or excerpt): whatever guards it lies
#                    outside the window.
# A hunk occurrence whose line lies inside a trusted definition of the same
# file (matched by the hunk header's new-side line number and the line's own
# text) is decided by that complete function instead of the hunk. Any other
# neutral HUNK occurrence counts as contradicting: an operation in code the
# patch changes, whose guard cannot be seen, is never vouched for by a guard
# seen before a different occurrence in another hunk, function or file. A
# neutral occurrence in an excerpt of untouched code stays neutral. A hunk
# that removes a guard occurrence and does not re-add it later in the same
# hunk is contradicting too (the operation it protected may lie outside the
# hunk's context lines). A block in the context text merely HEADED
# `Post-patch definition` is read as a complete function for contradictions
# only -- it can reject, never support. The guard holds only with at least
# one supporting occurrence and no contradicting one; anything less fails
# closed to `unresolved`. This is still textual order, never control flow.
#
# Call-site identity: matching text never says WHICH occurrence of the cited
# operation is the vulnerable one, so every occurrence shown must be
# accounted for. A repository block's occurrence is located by its heading
# and decided by the hunk whose pre-change span holds that line, else by the
# trusted definition holding its post-change line (mapped through the
# diff's hunk offsets), else in its own block, where a guard counts only if
# no changed region lies between guard and operation and an unseen guard
# counts against. A block with no usable location that shares a line with
# the patched code may be a pre-change copy of it: it never supports, and
# an unguarded occurrence in it still counts against.
# ---------------------------------------------------------------------------

_UNTRUSTED_POST_PATCH_DEFINITION_RE = re.compile(
    r"^####[ \t]+Post-patch definition[ \t]*:[^\n]*\n\n```[^\n`]*\n(.*?)\n```",
    re.MULTILINE | re.DOTALL,
)
"""A `Post-patch definition` heading in the context TEXT (see this section's
module comment): untrusted -- repository content can imitate it."""

_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class _Hunk(NamedTuple):
    path: "Optional[str]"
    new_start: "Optional[int]"
    lines: "List[Tuple[str, str]]"
    # pre-change span (`old_len == 0`: a pure insertion after `old_start`)
    old_start: "Optional[int]" = None
    old_len: int = 0
    new_len: int = 0


class _Definition(NamedTuple):
    path: str
    start_line: int
    lines: "List[str]"


def _normalize_repo_path(path: "Optional[str]") -> "Optional[str]":
    path = (path or "").strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path or None


def _diff_target_path(header: str) -> "Optional[str]":
    """The post-change path a `+++ ` or `diff --git ` header names, or None."""
    if header.startswith("+++ "):
        target = header[4:].split("\t")[0].strip()
        if target == "/dev/null":
            return None
        return _normalize_repo_path(target[2:] if target.startswith("b/") else target)
    if header.startswith("diff --git ") and " b/" in header:
        return _normalize_repo_path(header.rsplit(" b/", 1)[1])
    return None


def _diff_hunks(diff: "Optional[str]") -> "List[_Hunk]":
    """Each hunk of `diff`: its post-change file path and new-side start line
    (None when the headers do not state them) and its ordered `(tag, text)`
    lines, tag one of `' '`, `'+'`, `'-'`. A diff without any `@@` header is
    a single hunk."""
    hunks: "List[_Hunk]" = []
    current: "List[Tuple[str, str]]" = []
    path: "Optional[str]" = None
    span: "Tuple" = (None, None, 0, 0)  # (new_start, old_start, old_len, new_len)
    for line in (diff or "").splitlines():
        if line.startswith("@@") or _DIFF_FILE_HEADER_RE.match(line):
            if current:
                hunks.append(_Hunk(path, span[0], current, span[1], span[2], span[3]))
            current = []
            if line.startswith("@@"):
                header = _HUNK_HEADER_RE.match(line)
                span = (
                    int(header.group(3)), int(header.group(1)),
                    int(header.group(2) or 1), int(header.group(4) or 1),
                ) if header else (None, None, 0, 0)
            else:
                span = (None, None, 0, 0)
                if line.startswith(("+++ ", "diff --git ")):
                    path = _diff_target_path(line)
            continue
        if line.startswith("\\"):
            continue  # "\ No newline at end of file"
        if line[:1] in ("+", "-"):
            current.append((line[0], line[1:]))
        else:
            current.append((" ", line[1:] if line.startswith(" ") else line))
    if current:
        hunks.append(_Hunk(path, span[0], current, span[1], span[2], span[3]))
    return hunks


def _trusted_post_patch_definitions(
    definitions, shown: "Optional[str]", corpus: "Optional[str]",
) -> "List[_Definition]":
    """The well-formed `post_patch_definitions` records whose complete source
    the Challenger was shown and may cite (present in both `shown` and
    `corpus`). A malformed or unshown record is dropped, never repaired."""
    trusted: "List[_Definition]" = []
    shown_text = _normalize_for_provenance(shown)
    corpus_text = _normalize_for_provenance(corpus)
    for record in definitions or ():
        try:
            path, start, end, source = record["path"], record["start_line"], record["end_line"], record["source"]
        except (KeyError, TypeError, IndexError):
            continue
        if not isinstance(path, str) or not isinstance(source, str) or not source.strip():
            continue
        if not all(isinstance(n, int) and not isinstance(n, bool) for n in (start, end)) or not 1 <= start <= end:
            continue
        lines = source.splitlines()
        normalized_path = _normalize_repo_path(path)
        normalized_source = _normalize_for_provenance(source)
        if normalized_path is None or len(lines) > end - start + 1:
            continue
        if normalized_source not in shown_text or normalized_source not in corpus_text:
            continue
        trusted.append(_Definition(normalized_path, start, lines))
    return trusted


def _occurrence_lines(lines: "List[str]", quote: str) -> "List[Tuple[int, int, int]]":
    """`(offset, first_line, last_line)` of every token-bounded occurrence of
    the normalized `quote` in the normalized concatenation of `lines`; the
    offsets share one coordinate space per `lines` list."""
    parts: "List[str]" = []
    starts: "List[int]" = []
    ids: "List[int]" = []
    pos = 0
    for idx, line in enumerate(lines):
        normalized = _normalize_for_provenance(line)
        if not normalized:
            continue
        starts.append(pos)
        ids.append(idx)
        parts.append(normalized)
        pos += len(normalized) + 1
    found = []
    for match in re.finditer(_citation_pattern(quote), " ".join(parts)):
        first = ids[bisect.bisect_right(starts, match.start()) - 1]
        last = ids[bisect.bisect_right(starts, max(match.end() - 1, match.start())) - 1]
        found.append((match.start(), first, last))
    return found


def _indentation(text: str) -> int:
    expanded = text.expandtabs(8)
    return len(expanded) - len(expanded.lstrip())


def _guard_scope_covers(unit: "List[Tuple[str, str]]", guard_line: int, op_line: int) -> bool:
    """Whether the guard line and the operation line lie in one function by
    indentation: on the same line, or with no post-change line in between
    (blank lines aside) dedented below both. Such a line is a boundary
    neither sits inside -- the next function or method's header, or a
    closing brace. A guard or operation nested in a block (the other one
    outside it) is not rejected: whether that block runs is control flow,
    not textual order. At column 0 no dedent can show a boundary, so there
    the guard and operation must both stay at column 0, with every line in
    between."""
    if guard_line == op_line:
        return True
    guard_depth, op_depth = _indentation(unit[guard_line][1]), _indentation(unit[op_line][1])
    between = [_indentation(text) for tag, text in unit[guard_line + 1:op_line] if tag != "-" and text.strip()]
    depth = min(guard_depth, op_depth)
    if depth == 0:
        return guard_depth == 0 and op_depth == 0 and all(d == 0 for d in between)
    return all(d >= depth for d in between)


def _unit_verdicts(
    unit: "List[Tuple[str, str]]", guard: str, op: str, effect: "Optional[str]", complete: bool,
) -> "Tuple[List[Tuple[int, str, Optional[int]]], bool]":
    """One `(unit line index, verdict, guard line index)` per operation
    occurrence in one unit -- verdict `supporting`/`contradicting`/`neutral`
    (see this section's module comment); the guard line is set only for a
    supporting verdict -- and whether the unit ends with the cited guard
    removed. `complete` marks a whole-function unit. A guard is in force for
    an operation only within its own indented scope (`_guard_scope_covers`)."""
    post = [i for i, (tag, _t) in enumerate(unit) if tag != "-"]
    pre = [i for i, (tag, _t) in enumerate(unit) if tag != "+"]
    post_text = [unit[i][1] for i in post]
    pre_text = [unit[i][1] for i in pre]
    events = []  # (unit line, post offset, kind, payload)
    for off, first, _last in _occurrence_lines(post_text, guard):
        events.append((post[first], off, 1, None))
    for _off, first, last in _occurrence_lines(pre_text, guard):
        removed = [pre[k] for k in range(first, last + 1) if unit[pre[k]][0] == "-"]
        if removed:
            events.append((removed[0], -1, 0, None))
    for off, first, last in _occurrence_lines(post_text, op):
        added = any(unit[post[k]][0] == "+" for k in range(first, last + 1))
        events.append((post[first], off, 2, added))
    effect_offsets = [off for off, _f, _l in _occurrence_lines(post_text, effect)] if effect else []

    verdicts: "List[Tuple[int, str, Optional[int]]]" = []
    state = "absent" if complete else "unknown"
    guard_off, guard_line = -1, None
    for line, off, kind, added in sorted(events, key=lambda e: (e[0], e[1], e[2])):
        if kind == 0:
            state = "removed"
        elif kind == 1:
            state, guard_off, guard_line = "in_force", off, line
        elif state == "in_force" and not _guard_scope_covers(unit, guard_line, line):
            # the guard seen belongs to another scope: as if none were seen
            verdicts.append((line, "contradicting" if complete or added else "neutral", None))
        elif state == "in_force" and (effect is None or any(guard_off <= e < off for e in effect_offsets)):
            verdicts.append((line, "supporting", guard_line))
        elif state != "unknown" or added:
            verdicts.append((line, "contradicting", None))
        else:
            verdicts.append((line, "neutral", None))
    return verdicts, state == "removed"


def _definition_decides(
    path: "Optional[str]", line_number: "Optional[int]", text: str, definitions: "List[Tuple[_Definition, set]]",
) -> bool:
    """Whether a trusted definition of `path` holds an operation occurrence on
    post-change line `line_number`, whose text is `text`."""
    if path is None or line_number is None:
        return False
    normalized = _normalize_for_provenance(text)
    for definition, op_lines in definitions:
        offset = line_number - definition.start_line
        if (
            definition.path == path and 0 <= offset < len(definition.lines) and offset in op_lines
            and _normalize_for_provenance(definition.lines[offset]) == normalized
        ):
            return True
    return False


def _decided_by_definition(
    hunk: _Hunk, index: int, definitions: "List[Tuple[_Definition, set]]",
) -> bool:
    """Whether the operation occurrence starting on `hunk.lines[index]` lies,
    by the hunk header's new-side numbering and the line's own text, at an
    operation occurrence of a trusted definition of the same file."""
    if hunk.new_start is None or hunk.lines[index][0] == "-":
        return False
    line_number = hunk.new_start + sum(1 for tag, _t in hunk.lines[:index] if tag != "-")
    return _definition_decides(hunk.path, line_number, hunk.lines[index][1], definitions)


# Location of a repository evidence block (pre-change coordinates): a
# deterministic `#### <kind>: `path[:label]` (lines a-b[, note])` /
# `(full file, N lines)` / `(N lines)` heading over a fenced block, or a
# grounding excerpt `# path (lines a-b)` / `(full file, N lines)`. A
# discovered-usage window may skip lines with an explicit
# `# ... (N line(s) omitted: lines a-b) ...` marker. The older marker form
# without the range under-counted when a window ended in blank lines, so
# lines after it carry no trusted number. Anything else is unlocated.
_LOCATED_FENCED_BLOCK_RE = re.compile(
    r"^####([^\n`]*)`([^`\n]+)`[ \t]*\(([^)\n]*)\)[ \t]*\n\n```[^\n`]*\n(.*?)\n```", re.MULTILINE | re.DOTALL,
)
_LOCATED_GROUNDING_HEADER_RE = re.compile(
    r"^# (\S+) \((?:lines (\d+)-\d+|full file, \d+ lines)\)[ \t]*$", re.MULTILINE,
)
_OMITTED_LINES_RE = re.compile(r"^# \.\.\. \((\d+) line\(s\) omitted(?:: lines (\d+)-(\d+))?\) \.\.\.$")


def _located_block_span(meta: str) -> "Optional[Tuple[int, int]]":
    """`(first line, last line)` a heading's location states, or None."""
    meta = meta.strip()
    single_range = re.match(r"lines (\d+)\s*[\u2013-]\s*(\d+)(?:,\s*[^\d\s].*)?$", meta)
    if single_range:
        return int(single_range.group(1)), int(single_range.group(2))
    whole = re.match(r"(?:full file, )?(\d+) lines$", meta)
    return (1, int(whole.group(1))) if whole else None


def _located_blocks(corpus: "Optional[str]") -> "List[Tuple[str, List[Tuple[Optional[Tuple[int, int]], str]]]]":
    """`(path, [(line interval or None, text), ...])` for every evidence block
    of `corpus` with a parseable single-range location (see above). A line's
    interval `(lo, hi)` bounds its file line number: exact (`lo == hi`)
    except after an older-form omitted-lines marker, which only ever
    under-counted -- the heading's last line bounds the total shortfall. A
    marker line is None. `Post-patch definition` blocks are excluded:
    post-change text, handled separately."""
    blocks = []

    def numbered(path, span, body):
        rows, number, legacy = [], span[0], False
        for text in body.splitlines():
            omitted = _OMITTED_LINES_RE.match(text.strip())
            if omitted:
                if omitted.group(3) and not legacy:
                    number = int(omitted.group(3)) + 1
                else:
                    number, legacy = number + int(omitted.group(1)), True
                rows.append((None, legacy, text))
            else:
                rows.append((number, legacy, text))
                number += 1
        shortfall = span[1] - (number - 1)
        if shortfall < 0:
            return  # numbering inconsistent with the heading: no usable location
        blocks.append((path, [
            (None if n is None else (n, n + shortfall if uncertain else n), text) for n, uncertain, text in rows
        ]))

    text = corpus or ""
    for match in _LOCATED_FENCED_BLOCK_RE.finditer(text):
        span = _located_block_span(match.group(3))
        if "Post-patch definition" in match.group(1) or span is None:
            continue
        path = match.group(2)
        path = _normalize_repo_path(path[:path.rfind(":")] if ":" in path else path)
        if path:
            numbered(path, span, match.group(4))
    remainder = _LOCATED_FENCED_BLOCK_RE.sub("\n", text)
    headers = list(_LOCATED_GROUNDING_HEADER_RE.finditer(remainder))
    for i, header in enumerate(headers):
        body = remainder[header.end():(headers[i + 1].start() if i + 1 < len(headers) else len(remainder))]
        section = _MARKDOWN_SECTION_HEADING_RE.search(body)
        body = (body[:section.start()] if section else body)
        body = body[1:] if body.startswith("\n") else body
        span = _located_block_span(header.group(0)[header.group(0).index("(") + 1:header.group(0).rindex(")")])
        path = _normalize_repo_path(header.group(1))
        if path and span and body.strip():
            numbered(path, span, body.rstrip("\n"))
    return blocks


def _hunk_spans_line(hunk: _Hunk, line: int) -> bool:
    return hunk.old_len > 0 and hunk.old_start <= line < hunk.old_start + hunk.old_len


def _hunk_before_line(hunk: _Hunk, line: int) -> bool:
    if hunk.old_len == 0:
        return hunk.old_start < line
    return hunk.old_start + hunk.old_len <= line


def _hunk_touches_span(hunk: _Hunk, first: int, last: int) -> bool:
    if hunk.old_len == 0:
        return first <= hunk.old_start < last
    return hunk.old_start <= last and hunk.old_start + hunk.old_len - 1 >= first


def _post_change_guard_holds(
    guard_raw: "Optional[str]", op_raw: "Optional[str]", corpus: "Optional[str]", diff: "Optional[str]",
    effect_raw: "Optional[str]" = None, definitions: "Sequence[_Definition]" = (),
) -> bool:
    """Whether the cited guard precedes the cited operation in the
    post-change code, per occurrence (see this section's module comment).
    `diff` is the RAW patch, removed lines included; `corpus` is the
    repository evidence the citations are checked against; `definitions`
    are the trusted complete post-change functions."""
    guard = _normalize_for_provenance(_strip_quote_wrapping(guard_raw))
    op = _normalize_for_provenance(_strip_quote_wrapping(op_raw))
    effect = _normalize_for_provenance(_strip_quote_wrapping(effect_raw)) if effect_raw is not None else None
    if not guard or not op or guard == op or effect == "":
        return False

    supporting = contradicting = 0

    def tally(verdict: str) -> None:
        nonlocal supporting, contradicting
        if verdict == "supporting":
            supporting += 1
        elif verdict != "ignored":
            contradicting += 1  # contradicting, or neutral: its guard is not in evidence

    decided: "List[Tuple[_Definition, set]]" = []
    for definition in definitions:
        verdicts, _removed = _unit_verdicts([(" ", line) for line in definition.lines], guard, op, effect, True)
        decided.append((definition, {line for line, _v, _g in verdicts}))
        for _line, verdict, _guard_line in verdicts:
            tally(verdict)

    hunks = _diff_hunks(diff)
    for hunk in hunks:
        verdicts, removed_at_end = _unit_verdicts(hunk.lines, guard, op, effect, False)
        for line, verdict, _guard_line in verdicts:
            if not _decided_by_definition(hunk, line, decided):
                tally(verdict)
        if removed_at_end:
            contradicting += 1

    untrusted_definitions = [
        m.group(1) for m in _UNTRUSTED_POST_PATCH_DEFINITION_RE.finditer(corpus or "")
    ]
    for body in untrusted_definitions:
        verdicts, _removed = _unit_verdicts([(" ", line) for line in body.splitlines()], guard, op, effect, True)
        contradicting += sum(1 for _line, verdict, _g in verdicts if verdict == "contradicting")
    skip_sources = {_normalize_for_provenance(body) for body in untrusted_definitions}
    skip_sources |= {_normalize_for_provenance("\n".join(d.lines)) for d in definitions}

    # Repository evidence: every occurrence of the operation is a call site
    # the claim must account for. Located by its block's heading, it is
    # decided by the hunk that spans it, else by the trusted definition of
    # its post-change line, else in its own block -- where a guard counts
    # only if no changed region lies between them. Its location is never
    # inferred from matching text.
    real_hunks = [h for h in hunks if h.new_start is not None]
    locatable = all(h.path and h.old_start is not None for h in real_hunks) and not any(
        h.new_start is None and any(tag != " " for tag, _t in h.lines) for h in hunks
    )
    located_texts = []
    for path, lines in (_located_blocks(corpus) if locatable else []):
        located_texts.append(_normalize_for_provenance("\n".join(text for _n, text in lines)))
        if located_texts[-1] in skip_sources:
            continue
        file_hunks = [h for h in real_hunks if h.path == path]
        file_definitions = [d for d, _lines in decided if d.path == path]

        def decided_elsewhere(number):
            if any(_hunk_spans_line(h, number) for h in file_hunks):
                return True  # this call site's post-change state is in that hunk
            post = number + sum(h.new_len - h.old_len for h in file_hunks if _hunk_before_line(h, number))
            # a trusted complete function judges every occurrence in its span
            return any(d.start_line <= post < d.start_line + len(d.lines) for d in file_definitions)

        verdicts, _removed = _unit_verdicts([(" ", text) for _n, text in lines], guard, op, effect, False)
        for line, verdict, guard_line in verdicts:
            low, high = lines[line][0]
            if high - low <= 200 and all(decided_elsewhere(n) for n in range(low, high + 1)):
                continue
            guard_interval = lines[guard_line][0] if guard_line is not None else None
            if verdict == "supporting" and (low != high or guard_interval is None or any(
                _hunk_touches_span(h, guard_interval[0], high) for h in file_hunks
            )):
                # an uncertain location may be a stale copy; a changed region
                # between guard and operation voids this block's ordering
                verdict = "contradicting" if low == high else "ignored"
            tally(verdict)

    # Fallback for evidence with no usable location: a block sharing a line
    # with the patched code may be a pre-change copy of it, so it never
    # supports; any unguarded occurrence anywhere still counts against.
    patched_lines = {
        normalized for hunk in hunks for tag, text in hunk.lines
        if tag != "+" and (normalized := _normalize_for_provenance(text))
    }
    for block in _ordering_blocks(corpus):
        normalized_block = _normalize_for_provenance(block)
        if normalized_block in skip_sources or any(normalized_block in t for t in located_texts):
            continue
        maybe_stale = any(_find_citation(normalized_block, line) != -1 for line in patched_lines)
        verdicts, _removed = _unit_verdicts([(" ", line) for line in block.splitlines()], guard, op, effect, False)
        for _line, verdict, _guard_line in verdicts:
            if not (maybe_stale and verdict == "supporting"):
                tally(verdict)
    return supporting > 0 and contradicting == 0


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
    block: str, code_context: str, patch: str, vulnerability_text: str, diff: "Optional[str]" = None,
    definitions: "Sequence[_Definition]" = (),
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
    `reachability`/`consequence` values. (The run-level
    `_self_contradiction` gate in `challenge_patch` reads the PRIMARY
    concern's two strings only to fail a VERIFIED_FIXED run closed.)"""
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

    # The guard-ORDERING rules (_post_change_guard_holds) verify a positive
    # claim: they gate only a chain that can derive `blocked`. A chain the
    # model reports as leading to `reachable` (the guard is false by default,
    # has no effect, or is reset on re-entry) is never demoted by them -- its
    # facts still need valid citations below, and whatever they demote to,
    # such a chain can never derive `blocked`.
    reports_reachable_chain = default_state == "condition_false_under_default" or (
        default_state == "condition_true_under_default" and (
            effect == "no_effect"
            or (effect in ("prevents_operation", "neutralizes_operation") and reentry == "reset_or_bypassed")
        )
    )

    effective_guard = guard
    if effective_op_present != "present":
        effective_guard = "not_applicable"
    elif guard == "present":
        if not _point_citation_valid(guard_prov, code_context, patch):
            effective_guard = "unresolved"
        elif not reports_reachable_chain and not _post_change_guard_holds(
            guard_prov, op_prov, code_context, patch if diff is None else diff, definitions=definitions,
        ):
            # Necessary-but-not-sufficient ordering check, scoped per
            # occurrence to post-change evidence (see _post_change_guard_holds):
            # a removed guard, or one whose only surviving copy is elsewhere,
            # can never establish a PRECEDING guard.
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
        elif effect != "no_effect" and not reports_reachable_chain and not _post_change_guard_holds(
            guard_prov, op_prov, code_context, patch if diff is None else diff, effect_raw=effect_prov,
            definitions=definitions,
        ):
            # A protective effect must be the cited guard's own: present in
            # post-change text between that guard and the operation (a
            # removed `raise` surviving elsewhere is not this guard's effect).
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
    diff: "Optional[str]" = None, definitions: "Sequence[_Definition]" = (),
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
            concerns.append(_parse_concern_block_v2(span, code_context, patch, vulnerability_text, diff, definitions))
        else:
            concerns.append(_parse_concern_block(span, code_context, patch, vulnerability_text))
    return concerns


def _unscoped_v1_blocked_to_unresolved(concern: dict) -> dict:
    """A `concerns_v1` concern whose effective reachability is `blocked`,
    demoted to `unresolved` (see the call site in `challenge_patch`)."""
    if concern.get("malformed") or concern.get("default_execution_reachability") != "blocked":
        return concern
    return {
        **concern,
        "default_execution_reachability": "unresolved",
        "consequence": _concern_consequence(
            "unresolved", concern.get("requires_explicit_non_default_action"),
            concern.get("contract_addresses_override"),
        ),
    }


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


# ---------------------------------------------------------------------------
# Self-contradicting structured responses (PR #763 review).
#
# The concern facts alone decide a structured response's verdict, but a
# response must never be read as MORE favorable than it reads itself: when
# the model's own text explicitly concludes that the vulnerability is not
# fixed while its facts would compute VERIFIED_FIXED, the run fails closed to
# INSUFFICIENT_EVIDENCE. Monotonic: this only ever demotes VERIFIED_FIXED,
# never establishes BLOCKING or anything positive, so the deterministic
# policy remains the only path to a favorable outcome.
# ---------------------------------------------------------------------------

_NEGATIVE_STATUS_RE = re.compile(r"\b(RESIDUAL_VULNERABILITY|INSUFFICIENT_EVIDENCE)\b", re.IGNORECASE)
"""A non-positive answer in the model's own `Verification status:` header."""

_STILL_EXPLOITABLE_RE = re.compile(
    r"\b(?:remains?|still)\s+(?:(?:fully|readily|trivially|directly|potentially)\s+)?(?:exploitable|vulnerable)\b"
    r"|\b(?:can|could|may)\s+still\s+(?:be\s+)?(?:exploit(?:ed)?|bypass(?:ed)?)\b",
    re.IGNORECASE,
)
"""An explicit assertion that the vulnerability still occurs ("remains
exploitable", "is still vulnerable", "can still be bypassed")."""

_QUESTION_LEAD_RE = re.compile(
    r"^[\W_]*(?:whether|if|when|unless|does|do|is|are|can|could|would|will|should|has|have)\b",
    re.IGNORECASE,
)
_NEGATION_RE = re.compile(r"\b(?:not|no|never|nothing|none|cannot)\b|n't\b", re.IGNORECASE)


def _asserts_still_exploitable(text: "Optional[str]") -> bool:
    """Whether `text` contains a DECLARATIVE sentence asserting the
    vulnerability still occurs. A question or conditional ("Whether the
    issue is still exploitable ...", "If a caller passes ...") and a
    negated form ("no longer exploitable", "is not still vulnerable") are
    not such assertions. A lexical presence check, used only to fail a run
    closed (`_self_contradiction`), never to establish anything."""
    for sentence in re.split(r"(?<=[.!?;])\s+", text or ""):
        sentence = sentence.strip()
        if not sentence or sentence.endswith("?") or _QUESTION_LEAD_RE.match(sentence):
            continue
        for match in _STILL_EXPLOITABLE_RE.finditer(sentence):
            if not _NEGATION_RE.search(sentence[max(0, match.start() - 24):match.start()]):
                return True
    return False


def _self_contradiction(sections: dict, concerns: "List[dict]") -> "Optional[str]":
    """Why a structured response contradicts a VERIFIED_FIXED derivation of
    its own concern facts, or None. Two explicit negative conclusions count:
    the model's `Verification status:` (or legacy `Still vulnerable: yes`)
    header, and a declarative "still exploitable" statement in the PRIMARY
    concern's own text -- the primary concern is, by definition, the
    originally-described vulnerability under default execution. Additional
    concerns' text is deliberately not read: it routinely describes
    non-default or out-of-scope paths that the deterministic override/scope
    policy classifies non-blocking by design."""
    header = _NEGATIVE_STATUS_RE.search(sections.get("verification_status") or "")
    if header:
        return f"the Challenger's own Verification status header says {header.group(1).upper()}"
    if re.match(r"^\W*yes\b", sections.get("still_vulnerable") or "", re.IGNORECASE):
        return "the Challenger's own Still vulnerable header says yes"
    for concern in concerns:
        if concern.get("concern_role") != "primary":
            continue
        for key, label in (("description", "Description"), ("hypothesized_outcome", "Hypothesized outcome")):
            if _asserts_still_exploitable(concern.get(key)):
                return f"the Challenger's primary concern {label} states that the vulnerability remains exploitable"
    return None


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
    post_patch_definitions: "Optional[Sequence[dict]]" = None,
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
    post_patch_definitions:
        Trusted complete post-change functions, as pipeline-produced records
        `{"path", "start_line", "end_line", "source"}` (see
        post_patch_evaluation.post_patch_definitions). The only evidence
        treated as a complete function when ordering a guard before the
        operation: a `Post-patch definition` heading inside the context
        text is never trusted, since repository content can imitate it. A
        record whose source the model was not shown (or may not cite) is
        ignored. `None`/empty: no complete post-change evidence.

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
    instead forces the whole run closed, as does a `Concerns:` structure
    the strict block parser cannot fully account for (RB-2). A response
    with NO `Concerns:` header at all always fails closed --
    `verification_status` None, `still_vulnerable` True -- whatever verdict
    it states (RB-1); its `summary` remains the model's own raw text.
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

    calls_before = len(get_call_history().get("challenger", []))
    resp = llm.complete(system_prompt, user_message, stage="challenger")
    # RB-5: the provider's own stop signal, as llm_client records it for
    # THIS call only (entries added by the call above -- never a stale one
    # from an earlier call). A response cut off by the output limit is
    # incomplete, so its parsed absence of concerns proves nothing. No
    # recorded metadata (a client that records none) keeps prior behavior.
    truncated = any(
        (call.get("stop_reason") or "").lower() in _TRUNCATION_STOP_REASONS
        for call in get_call_history().get("challenger", [])[calls_before:]
    )

    sections = _split_sections(resp)

    edge_cases = _lines_from_bullets(sections.get("edge_cases", ""))
    potential_issues = _lines_from_bullets(sections.get("potential_issues", ""))
    summary = sections.get("summary", resp.strip())

    if sections.get("concerns") is not None:
        concerns_body = sections["concerns"]
        citation_corpus = code_context if provenance_context is None else provenance_context
        # Citations ground facts about the PATCHED code: only the diff's
        # post-change side, and evidence minus the lines the patch removes
        # (a removed guard must never read as a present one).
        citation_patch, removed_only = _patch_citation_view(patch)
        concerns = _parse_concerns(
            concerns_body, _without_removed_lines(citation_corpus, removed_only),
            citation_patch, vulnerability_text, diff=patch,
            definitions=_trusted_post_patch_definitions(post_patch_definitions, code_context, citation_corpus),
        )
        # A legacy `concerns_v1` `blocked` claim rests on ONE quote with no
        # operation or ordering, so it cannot be tied to the vulnerable code
        # location (any surviving line, anywhere in the evidence, grounds it).
        # It fails closed to `unresolved`; a `reachable` claim is unaffected.
        if not _response_uses_v2_schema(concerns_body):
            concerns = [_unscoped_v1_blocked_to_unresolved(c) for c in concerns]
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
        # RB-2: structure the strict parser could not account for -- a
        # concern block whose header differs from `N. Role:` (it would be
        # merged into its neighbor, its own consequence lost), or a second
        # `Concerns` section (`_split_sections` keeps only the last) --
        # fails closed rather than being read as fewer concerns.
        concerns_ambiguous = (
            _concern_structure_ambiguous(concerns_body)
            or len(_LENIENT_CONCERNS_HEADER_RE.findall(resp)) > 1
        )
        verification_status, still = _derive_status_from_concerns(
            concerns, structural_violation or concerns_ambiguous or truncated,
        )
        # A response that itself concludes the vulnerability is not fixed is
        # never read as VERIFIED_FIXED (see `_self_contradiction`).
        verdict_conflict = None
        if verification_status == "VERIFIED_FIXED":
            verdict_conflict = _self_contradiction(sections, concerns)
            if verdict_conflict:
                verification_status, still = "INSUFFICIENT_EVIDENCE", True
        # The model's own free-form `Summary:` text is never returned as
        # the report-facing summary for a new-schema response -- see
        # `_synthesize_summary_from_concerns`'s own docstring for why.
        if verdict_conflict:
            summary = (
                f"Self-contradicting Challenger response: {verdict_conflict}, while the concern "
                "facts alone would compute VERIFIED_FIXED; this run failed closed. "
                + _synthesize_summary_from_concerns(concerns, False)
            )
        elif truncated:
            summary = (
                "Truncated Challenger response: the provider reported the output was cut off "
                "at its length limit, so concerns may be missing; this run failed closed and is "
                "not summarized further."
            )
        elif concerns_ambiguous and not structural_violation:
            summary = (
                "Unparseable Concerns structure: the response contained concern blocks or "
                "Concerns sections that could not each be parsed as one numbered block; this "
                "run failed closed and is not summarized further."
            )
        else:
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
            # Present only when the run failed closed for self-contradiction.
            **({"verdict_conflict": verdict_conflict} if verdict_conflict else {}),
        }

    # RB-1: no structured `Concerns:` section (missing, legacy-format, or a
    # header the strict parser did not recognize) means there is no
    # citation-checked evidence to derive a verdict from. The model's own
    # `Verification status:`/`Still vulnerable:` answer must never decide
    # the outcome, so this fails closed whatever it states -- the same
    # `(None, True)` shape `_parse_verification` already uses for an
    # unrecognized answer.
    return {
        "verification_status": None,
        "still_vulnerable": True,
        "edge_cases": edge_cases,
        "potential_issues": potential_issues,
        "summary": summary,
    }
