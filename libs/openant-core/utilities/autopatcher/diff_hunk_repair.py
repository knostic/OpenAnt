"""Deterministic unified diff hunk header repair.

LLMs frequently generate unified diffs with arithmetically wrong @@ -a,b +c,d @@
counts. This module recomputes b and d from the actual hunk body lines, and
recomputes c as old_start + cumulative_prior_net_delta within the same file.

The old start line (a) is the LLM's positional anchor. When `repo_root` is
supplied, `a` is no longer trusted blindly either: the hunk's own OLD-side
content (context + removed lines) is searched for in the real target file
via content_relocation.find_unique_occurrence, and `a` is corrected to that
location when a unique match is found. This is the same failure mode
impact_surface.py's module docstring documents independently -- an
LLM-generated hunk can be anchored at a drifted line number even when its
content is byte-identical to the real file -- fixed here at the point that
actually matters for `git apply`, not only for impact analysis. When no
`repo_root` is given, or the match is absent or ambiguous, `a` is left
exactly as the LLM wrote it, same as before this capability existed.

It also structurally REBUILDS the diff so every file appears exactly once —
one "--- a/X"/"+++ b/X" header pair followed by ALL of that file's hunks, in
their original relative order. LLMs sometimes emit a file's hunks split
across multiple, non-contiguous header-pair sections (interleaved with
another file's section in between, or simply repeated) — each section
parses fine on its own, but splits what should be one cumulative per-file
line-offset delta into several independently-reset deltas, and produces a
file/hunk layout git considers malformed for a single coherent multi-file
patch. Rebuilding never changes file order (first-appearance order),
never changes hunk order within a file, and never changes a single changed
line — only which header a hunk is filed under and where in the output it
appears.

Public API:
    repair_hunk_headers(patch: str, repo_root: Path | str | None = None) -> tuple[str, RepairResult]

RepairResult fields:
    normalization_applied : bool  — True if any @@ line was changed, or any
                                     file's hunks were consolidated from more
                                     than one header-pair section
    hunks_rewritten       : int   — number of @@ headers with corrected values
    files_rewritten       : int   — number of distinct filenames with ≥1 rewrite
    hunks_relocated       : int   — number of hunks whose old-side line number
                                     was corrected by content relocation
                                     (subset of hunks_rewritten; 0 whenever
                                     repo_root is omitted)
    relocations           : list[HunkRelocationRecord] — one entry per hunk,
                                     observability only (see class docstring)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .content_relocation import find_unique_occurrence, locate_occurrence, old_side_anchors

# check_applicability and semantic_delta are deliberately NOT imported here at
# module level, unlike content_relocation's primitives above. Every test
# suite in this codebase mocks check_applicability via
# mock.patch("...patch_applicability.check_applicability", ...) (string-based
# patching of the ATTRIBUTE on that module). diff_hunk_repair is imported
# lazily everywhere else in the codebase (inside function bodies, never at
# another module's top level) -- if this module bound check_applicability at
# import time, the FIRST time anything imports diff_hunk_repair could land
# inside an unrelated test's mock.patch(...) context, permanently capturing
# that mock into this module's namespace for the rest of the process (mock.patch
# only restores the attribute on the module it patched, never a name some
# OTHER module already copied via `from X import Y`). Importing both lazily,
# inside reconstruct_hunk_context() itself, guarantees a fresh, correct
# lookup on every call instead.


_HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)"
)
_FENCE_OPEN_RE = re.compile(r"^```")


@dataclass(frozen=True)
class HunkRelocationRecord:
    """Observability-only record of one hunk's relocation attempt.

    Never consulted by any decision logic — the actual relocation decision
    (whether/where to move `hunk_old_start`) is made entirely by the
    existing `find_unique_occurrence` call in `_repair`'s `flush_hunk`;
    this record is populated alongside it, from a separate
    `locate_occurrence` call, purely so a caller can report what happened.

    relocation_reason: "unique_match" | "ambiguous" | "no_match" | "skipped"
      "skipped" covers every case relocation was never attempted at all —
      no repo_root, a new-file hunk (old_start == 0), the target file
      couldn't be read, or the hunk has no old-side anchors to search for
      (a pure-insertion hunk).
    relocated_hunk_start: set whenever a unique match was found, even when
      it equals original_hunk_start (the LLM's claim was already correct —
      no correction was needed, but the position was confirmed). None for
      ambiguous/no_match/skipped.
    """
    file: str
    relocation_attempted: bool
    relocation_performed: bool
    relocation_reason: str
    original_hunk_start: int
    relocated_hunk_start: "int | None"


@dataclass
class RepairResult:
    normalization_applied: bool = False
    hunks_rewritten: int = 0
    files_rewritten: int = 0
    hunks_relocated: int = 0
    relocations: "list[HunkRelocationRecord]" = field(default_factory=list)


def repair_hunk_headers(patch: str, repo_root: "Path | str | None" = None) -> tuple[str, RepairResult]:
    """Recompute unified diff hunk header counts from body content, and —
    when `repo_root` is given — correct each hunk's old-side line number by
    locating its actual content in the real target file (see module
    docstring and content_relocation.py). `repo_root` is optional and
    defaults to None, preserving prior behavior for existing callers that
    don't pass it (position is left exactly as the LLM wrote it).

    Returns (repaired_patch, RepairResult).
    Never raises — on any unexpected error returns (original_patch, RepairResult()).
    """
    meta = RepairResult()
    if not patch or not patch.strip():
        return patch, meta
    try:
        open_fence, clean, close_fence = _strip_md_fences(patch)
        repaired, meta = _repair(clean, meta, Path(repo_root) if repo_root else None)
        return open_fence + repaired + close_fence, meta
    except Exception:
        return patch, meta


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _strip_md_fences(patch: str) -> tuple[str, str, str]:
    """Extract markdown code fences surrounding a patch string.

    Returns (open_fence, clean_patch, close_fence).
    Concatenating the three parts always reconstructs the original string.
    """
    lines = patch.splitlines(keepends=True)
    open_fence = ""
    close_fence = ""
    if lines and _FENCE_OPEN_RE.match(lines[0]):
        open_fence = lines.pop(0)
    if lines and lines[-1].rstrip() in ("```", "~~~"):
        close_fence = lines.pop()
    return open_fence, "".join(lines), close_fence


def strip_markdown_fences(patch: str) -> str:
    """Public wrapper around ``_strip_md_fences`` -- returns just the
    fence-free body, discarding the (possibly empty) opening/closing fence
    lines. Generic, no diff-semantic knowledge: only recognizes a fence as
    the literal first/last line of `patch`, exactly like `_strip_md_fences`
    and patch_applicability._strip_fences already do independently.

    Exists so a caller that needs to COMPOSE two diff fragments (e.g.
    generated_patch_processing.py's fence-safe concatenation) can strip a
    fence from one fragment without pulling in markdown-parsing logic of
    its own -- reuses this module's existing, single implementation rather
    than a third copy of the same four-line check."""
    _, clean, _ = _strip_md_fences(patch)
    return clean


@dataclass
class _FileSection:
    header_a: str  # the "--- a/X" line, exactly as first seen for this file
    header_b: str  # the "+++ b/X" line, exactly as first seen for this file
    hunks: list = field(default_factory=list)  # list of (header_line, body_lines)


def _repair(patch: str, meta: RepairResult, repo_root: "Path | None" = None) -> tuple[str, RepairResult]:
    lines = patch.splitlines(keepends=True)

    # Lazily-loaded, per-file cache of the CURRENT (pre-patch) target file's
    # lines, keyed the same way `sections`/`file_delta` are keyed below (the
    # new-side path, or the old-side path for a deletion). None is cached
    # for a file that can't be read (missing, renamed, repo_root omitted) so
    # every hunk in that file skips relocation without re-attempting the
    # read each time.
    _file_lines_cache: dict[str, "list[str] | None"] = {}

    def _load_file_lines(key: str) -> "list[str] | None":
        if key in _file_lines_cache:
            return _file_lines_cache[key]
        result: "list[str] | None" = None
        if repo_root is not None:
            try:
                # `key` comes from the LLM-authored diff header, same trust
                # level as the rest of the patch text -- resolve and require
                # it stays inside repo_root before reading (same guard
                # remediation_planner._verify_file uses for the same reason).
                resolved_root = repo_root.resolve()
                candidate = (resolved_root / key).resolve()
                candidate.relative_to(resolved_root)
                if candidate.is_file():
                    result = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                result = None
        _file_lines_cache[key] = result
        return result

    # Content that appears before the first recognised file header (or,
    # for pathological/non-diff input, everything — see the final-assembly
    # fallback below). Also the catch-all for a handful of edge cases that
    # were unconditional `output.append(line)` passthroughs before this
    # function grouped hunks by file: a malformed `@@` line whose header
    # doesn't parse, and any line that appears outside a hunk while no
    # file header has been recognised yet.
    preamble: list[str] = []

    file_order: list[str] = []               # first-appearance order, deduplicated
    sections: dict[str, _FileSection] = {}   # keyed the same way, one entry per file
    file_delta: dict[str, int] = {}          # cumulative net-line delta, PER FILE,
    # persists across every section seen for that file — this is the exact
    # bookkeeping a repeated/interleaved header pattern used to reset to 0
    # on every new section, corrupting every subsequent hunk's new_start
    # for that file.

    files_touched: set[str] = set()
    repeated_section_seen = False

    current_key: str | None = None
    hunk_orig_header: str | None = None
    hunk_old_start: int = 0
    hunk_claimed_new_start: int = 0
    hunk_suffix: str = ""
    hunk_body: list[str] = []
    in_hunk: bool = False

    def flush_hunk() -> None:
        nonlocal in_hunk, hunk_orig_header, hunk_body, hunk_old_start

        if not in_hunk:
            return

        old_count, new_count = _count_body(hunk_body)

        if current_key is None:
            # A hunk with no recognised file header at all (malformed
            # input) has nowhere structurally correct to go. Preserve it,
            # unrewritten, in its original relative position rather than
            # losing it -- this only ever happens on already-pathological
            # input no test relies on the exact shape of.
            preamble.append(hunk_orig_header)
            preamble.extend(hunk_body)
            in_hunk = False
            hunk_orig_header = None
            hunk_body = []
            return

        # Content-based relocation (Candidate 1): the LLM's claimed
        # old_start is a positional guess that can drift from the real file
        # even when the hunk's own content is byte-identical to it (see
        # module docstring). Confirm/correct that guess by finding where
        # the hunk's OLD-side lines actually, uniquely occur in the real
        # target file -- never for a new-file hunk (old_start == 0, there
        # is no old file to search), and never when the match is absent or
        # ambiguous (leave the claimed position untouched rather than
        # guess). Purely textual: no AST, no language-specific parsing.
        #
        # Telemetry (observability only): the four `_telemetry_*` locals
        # below record what happened for HunkRelocationRecord. They are
        # populated alongside the decision, never instead of it -- the
        # actual decision (whether/where to move `hunk_old_start`) is made
        # entirely by the `find_unique_occurrence` call and its `if` below,
        # byte-for-byte the same as before telemetry existed. The
        # `locate_occurrence` call exists only to classify *why*, via a
        # separate function (see its docstring), and its own return value
        # is read here only for the telemetry record, never for the decision.
        _telemetry_original_start = hunk_old_start
        _telemetry_attempted = False
        _telemetry_performed = False
        _telemetry_reason = "skipped"
        _telemetry_relocated_start: "int | None" = None
        if hunk_old_start != 0:
            file_lines = _load_file_lines(current_key)
            if file_lines is not None:
                anchors = old_side_anchors(hunk_body)
                if anchors:
                    _telemetry_attempted = True
                    _located_for_telemetry, _telemetry_reason = locate_occurrence(anchors, file_lines)
                    if _located_for_telemetry is not None:
                        _telemetry_relocated_start = _located_for_telemetry + 1

                located = find_unique_occurrence(anchors, file_lines)
                if located is not None and located + 1 != hunk_old_start:
                    hunk_old_start = located + 1  # 1-indexed
                    meta.hunks_relocated += 1
                    _telemetry_performed = True

        meta.relocations.append(HunkRelocationRecord(
            file=current_key,
            relocation_attempted=_telemetry_attempted,
            relocation_performed=_telemetry_performed,
            relocation_reason=_telemetry_reason,
            original_hunk_start=_telemetry_original_start,
            relocated_hunk_start=_telemetry_relocated_start,
        ))

        delta = file_delta.get(current_key, 0)
        # New-file sentinel: old_start=0 means the old file doesn't exist.
        # The delta formula doesn't apply; preserve the original new_start
        # (conventionally 1 for a new non-empty file, 0 for an empty one).
        if hunk_old_start == 0:
            correct_new_start = hunk_claimed_new_start
        else:
            correct_new_start = hunk_old_start + delta
        rewritten = (
            f"@@ -{hunk_old_start},{old_count}"
            f" +{correct_new_start},{new_count}"
            f" @@{hunk_suffix}\n"
        )

        if rewritten != hunk_orig_header:
            meta.hunks_rewritten += 1
            meta.normalization_applied = True
            files_touched.add(current_key)

        sections[current_key].hunks.append((rewritten, list(hunk_body)))
        file_delta[current_key] = delta + (new_count - old_count)

        in_hunk = False
        hunk_orig_header = None
        hunk_body = []

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.rstrip("\n")

        if stripped.startswith("@@ "):
            flush_hunk()
            m = _HUNK_RE.match(stripped)
            if not m:
                preamble.append(line)  # malformed — pass through unchanged
                i += 1
                continue
            hunk_old_start = int(m.group(1))
            hunk_claimed_new_start = int(m.group(3))
            hunk_suffix = m.group(5)   # text after second @@, e.g. " function setKey"
            hunk_orig_header = line
            hunk_body = []
            in_hunk = True
            i += 1
            continue

        # A real file header is a "--- "/"+++ " PAIR on adjacent lines, not
        # merely a line that starts with one of those prefixes — a
        # removed/added hunk-body line whose text is "-- foo" or "++ foo"
        # produces the raw line "--- foo" / "+++ foo" too. Requiring the
        # very next line to complete the pair is what tells apart a genuine
        # file boundary from coincidental body content: two unrelated body
        # lines almost never line up to form both halves of the pair.
        if (
            stripped.startswith("--- ")
            and i + 1 < n
            and lines[i + 1].rstrip("\n").startswith("+++ ")
        ):
            flush_hunk()
            a_line, b_line = line, lines[i + 1]
            a_raw = stripped[4:].split("\t")[0].strip()
            b_raw = b_line.rstrip("\n")[4:].split("\t")[0].strip()
            a_path = a_raw[2:] if a_raw.startswith("a/") else a_raw
            b_path = b_raw[2:] if b_raw.startswith("b/") else b_raw
            # Prefer the new-side path as the grouping key: for a new file
            # the old side is always the literal "/dev/null" regardless of
            # which new file it is, so keying on it would wrongly merge two
            # unrelated new files in the same patch into one section.
            key = b_path if b_path != "/dev/null" else a_path

            if key not in sections:
                sections[key] = _FileSection(header_a=a_line, header_b=b_line)
                file_order.append(key)
                file_delta[key] = 0
            else:
                repeated_section_seen = True
            current_key = key
            i += 2
            continue

        if in_hunk:
            hunk_body.append(line)
            i += 1
            continue

        if current_key is None:
            preamble.append(line)  # preamble before any file header at all
        # else: stray non-hunk, non-header content between sections of an
        # already-malformed diff (e.g. injected prose) — not valid diff
        # syntax either way, and rebuilding a valid structure has no
        # correct place to put it; dropped rather than re-introducing the
        # exact kind of misplaced content this function exists to repair.
        i += 1

    flush_hunk()
    meta.files_rewritten = len(files_touched)
    if repeated_section_seen:
        meta.normalization_applied = True

    output: list[str] = list(preamble)
    for key in file_order:
        section = sections[key]
        output.append(section.header_a)
        output.append(section.header_b)
        for header, body in section.hunks:
            output.append(header)
            output.extend(body)

    return "".join(output), meta


def _count_body(body: list[str]) -> tuple[int, int]:
    """Return (old_count, new_count) by walking hunk body lines.

    old_count = context lines + removed lines
    new_count = context lines + added lines
    The '\\' No newline marker is excluded from both counts.
    """
    old_count = 0
    new_count = 0
    for raw in body:
        line = raw.rstrip("\n")
        if line.startswith("\\"):
            # \\ No newline at end of file — metadata marker, not a content line
            continue
        if line.startswith("-") and not line.startswith("---"):
            old_count += 1
        elif line.startswith("+") and not line.startswith("+++"):
            new_count += 1
        else:
            # Context: leading space, empty line, or any other non-marker content
            old_count += 1
            new_count += 1
    return old_count, new_count


# ---------------------------------------------------------------------------
# Deterministic context reconstruction
#
# repair_hunk_headers (above) fixes arithmetically-wrong @@ counts and, with
# repo_root, relocates a drifted old_start by content. Both can succeed —
# the hunk becomes positionally and arithmetically correct — and the hunk
# can STILL fail real `git apply --check`, because its body itself carries
# too little surrounding context (e.g. one line of leading context and none
# trailing). This is a distinct failure from either count corruption or
# positional drift, and neither existing mechanism addresses it.
#
# reconstruct_hunk_context() is the deterministic fix for exactly that gap:
# given a patch that has ALREADY been through repair_hunk_headers and has
# ALREADY failed check_applicability, it adds up to 3 lines of repository-
# VERBATIM context around each context-starved hunk (never touching an
# existing '+'/'-' line), then re-validates with the real, existing
# check_applicability — never a new git code path.
#
# Strict safety boundary: this is diff-structure reconstruction, not a
# semantic patch generator. It may only:
#   - preserve every existing '+'/'-' line exactly;
#   - add ' '-prefixed context lines read verbatim from the real target
#     file, at a position already proven unique by find_unique_occurrence;
#   - recompute hunk header metadata (start/count) to match.
# It must never invent, alter, or drop a semantic addition/removal — this
# is enforced, not just documented: reconstruct_hunk_context refuses to
# adopt any result whose semantic_delta() differs from the input's.
#
# semantic_delta() is the safety invariant for the patch shapes this
# function actually accepts -- it is NOT relied on for file-deletion
# sections ("+++ /dev/null"), which diff_parsing.parse_diff never
# recognises as a file header at all (its removed lines are invisible to
# semantic_delta on both sides of any comparison). Rather than reconstruct
# against a shape the safety gate can't verify, a patch containing any
# file-deletion section refuses the WHOLE attempt atomically, before any
# hunk is inspected (skipped_reason="unsupported_file_deletion").
# ---------------------------------------------------------------------------

_MAX_CONTEXT_LINES = 3


@dataclass(frozen=True)
class ContextExpansionResult:
    """Observability-only result of one reconstruct_hunk_context() call.

    attempted      : True once the (already-failed) whole-patch check has
                      been inspected at all — set as soon as repo_root and a
                      non-empty patch are both present, regardless of outcome.
    succeeded      : True only when a reconstructed patch was produced, its
                      semantic_delta matched the input's, and it passed the
                      real, final check_applicability(whole_patch, repo_root).
    hunks_expanded : number of hunks that gained repository-verbatim context.
    hunks_unchanged: number of hunks left byte-for-byte untouched because
                      they already applied standalone.
    skipped_reason : set whenever attempted is True but succeeded is False —
                      a short, closed-set reason for observability:
                      "unsupported_file_deletion" | "unparseable_structure" |
                      "file_unreadable" | "no_old_side_anchors" |
                      "anchor_ambiguous" | "anchor_no_match" |
                      "no_safe_headroom" |
                      "hunk_still_not_applicable_after_expansion" |
                      "no_hunks_needed_expansion" | "semantic_delta_mismatch" |
                      "whole_patch_still_not_applicable" | "internal_error".
    """
    attempted: bool = False
    succeeded: bool = False
    hunks_expanded: int = 0
    hunks_unchanged: int = 0
    skipped_reason: "str | None" = None


@dataclass
class _RHunk:
    """One hunk, parsed from an already-repaired patch. `raw_header` is the
    exact string to emit for the '@@ ... @@' line — the ORIGINAL line for a
    hunk left untouched (guaranteeing byte-for-byte reuse), or a freshly
    formatted one for a hunk that was expanded."""
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    suffix: str
    raw_header: str
    body: "list[str]"  # raw lines, keepends=True, marker-prefixed


@dataclass
class _RSection:
    header_a: str
    header_b: str
    file_key: str
    hunks: "list[_RHunk]"
    is_deletion: bool = False  # "+++ /dev/null" -- see reconstruct_hunk_context's
    # unsupported_file_deletion guard: semantic_delta() cannot see a deletion
    # section's removed lines at all (parse_diff only recognises "+++ b/..."
    # as a file header), so it cannot provide the safety invariant
    # reconstruction requires for this shape. Detected here, at parse time,
    # from the same b_path already computed for file_key -- not a second
    # parse.


def _format_hunk_header(old_start: int, old_count: int, new_start: int, new_count: int, suffix: str) -> str:
    return f"@@ -{old_start},{old_count} +{new_start},{new_count} @@{suffix}\n"


def _parse_repaired_sections(patch: str) -> "list[_RSection] | None":
    """Parse an ALREADY repair_hunk_headers()-normalized patch (fences
    already stripped by the caller) into ordered per-file sections.

    Deliberately separate from `_repair`'s own parser: this assumes the
    single-header-pair-per-file, non-interleaved, explicit-count structure
    repair_hunk_headers already guarantees, so it can be much simpler — but
    it never guesses. Any structure it doesn't recognise (a repeated file
    section, a malformed '@@' line, stray content outside any hunk) makes it
    return None rather than a best-effort parse, so the caller fails closed
    instead of reconstructing against a misunderstood shape. Uses the exact
    same "--- " + next-line "+++ " pairing check as `_repair` for the same
    reason documented there (F-36/F-41/F-45): a removed/added body line
    whose own text happens to start with "-- "/"++ " must never be mistaken
    for a real file-header line.
    """
    lines = patch.splitlines(keepends=True)
    sections: "list[_RSection]" = []
    seen_keys: set = set()
    current: "_RSection | None" = None

    in_hunk = False
    hunk_match: "re.Match | None" = None
    hunk_header_line = ""
    hunk_body: "list[str]" = []

    def flush_hunk() -> bool:
        nonlocal in_hunk, hunk_match, hunk_header_line, hunk_body
        if not in_hunk:
            return True
        if current is None:
            return False
        old_count, new_count = _count_body(hunk_body)
        current.hunks.append(_RHunk(
            old_start=int(hunk_match.group(1)),
            old_count=old_count,
            new_start=int(hunk_match.group(3)),
            new_count=new_count,
            suffix=hunk_match.group(5),
            raw_header=hunk_header_line,
            body=list(hunk_body),
        ))
        in_hunk = False
        hunk_match = None
        hunk_header_line = ""
        hunk_body = []
        return True

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.rstrip("\n")

        if stripped.startswith("@@ "):
            if not flush_hunk():
                return None
            m = _HUNK_RE.match(stripped)
            if not m:
                return None
            hunk_match = m
            hunk_header_line = line
            hunk_body = []
            in_hunk = True
            i += 1
            continue

        if (
            stripped.startswith("--- ")
            and i + 1 < n
            and lines[i + 1].rstrip("\n").startswith("+++ ")
        ):
            if not flush_hunk():
                return None
            a_line, b_line = line, lines[i + 1]
            a_raw = stripped[4:].split("\t")[0].strip()
            b_raw = b_line.rstrip("\n")[4:].split("\t")[0].strip()
            a_path = a_raw[2:] if a_raw.startswith("a/") else a_raw
            b_path = b_raw[2:] if b_raw.startswith("b/") else b_raw
            key = b_path if b_path != "/dev/null" else a_path
            if key in seen_keys:
                return None  # repeated section -- not the post-repair shape this assumes
            seen_keys.add(key)
            current = _RSection(
                header_a=a_line, header_b=b_line, file_key=key, hunks=[],
                is_deletion=(b_path == "/dev/null"),
            )
            sections.append(current)
            i += 2
            continue

        if in_hunk:
            hunk_body.append(line)
            i += 1
            continue

        # Anything else (stray content outside any hunk/header) is not the
        # clean, already-repaired shape this parser assumes -- fail closed.
        return None

    if not flush_hunk():
        return None
    return sections


def _render_section(sec: "_RSection") -> str:
    out = [sec.header_a, sec.header_b]
    for h in sec.hunks:
        out.append(h.raw_header)
        out.extend(h.body)
    return "".join(out)


def _render_sections(sections: "list[_RSection]") -> str:
    return "".join(_render_section(s) for s in sections)


def _single_hunk_patch(sec: "_RSection", h: "_RHunk") -> str:
    """A minimal, standalone one-hunk patch for this file -- used only to
    scope which hunks are already sufficient vs. context-starved via the
    real, existing check_applicability. This is scoping only: the final
    accept/reject decision is always the whole reconstructed patch's own
    check_applicability result (see reconstruct_hunk_context)."""
    return sec.header_a + sec.header_b + h.raw_header + "".join(h.body)


def _load_raw_file_lines(repo_root: Path, key: str) -> "list[str] | None":
    """Read the real target file's lines, preserving line endings (needed
    to reuse them verbatim as diff context) -- separate from
    repair_hunk_headers._load_file_lines, which drops line endings because
    its callers only ever compare whitespace-normalized text."""
    try:
        resolved_root = repo_root.resolve()
        candidate = (resolved_root / key).resolve()
        candidate.relative_to(resolved_root)
        if not candidate.is_file():
            return None
        return candidate.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    except Exception:
        return None


def reconstruct_hunk_context(patch: str, repo_root: "Path | str | None") -> tuple[str, ContextExpansionResult]:
    """Deterministically add repository-verbatim context to context-starved
    hunks in an already header-repaired patch, so it can pass real
    `git apply --check` without an LLM retry.

    Intended call site: pipeline.py, only after repair_hunk_headers() has
    already run AND the resulting patch has already failed
    check_applicability(patch, repo_root) once. Never call this before that
    check — it exists to recover from that specific failure, not to
    preempt it.

    Out of scope, explicitly: any patch containing a file-deletion section
    ("+++ /dev/null") refuses the WHOLE attempt immediately, before any
    hunk is inspected -- diff_parsing.parse_diff (and therefore
    semantic_delta, see point 1 below) never recognises "+++ /dev/null" as
    a file header, so a deletion section's removed lines are invisible to
    the safety gate this function depends on. semantic_delta is the safety
    invariant for the patch shapes actually accepted below; file-deletion
    sections are rejected before ever reaching that gate, not verified by
    it.

    Scoping (which hunks get touched) uses check_applicability on a minimal
    single-hunk sub-patch per hunk -- real git, not stderr parsing -- so a
    hunk that already applies standalone is left completely untouched.
    Reconstruction of a context-starved hunk requires its old-side content
    to have a UNIQUE match in the real file (find_unique_occurrence); on any
    ambiguous/absent match, any unreadable file, or any hunk with no
    old-side anchors at all (pure insertion, new file), the WHOLE attempt
    is abandoned -- there is no partial adoption.

    Added context is capped at 3 lines per side (the conventional unified-
    diff default), bounded by the file's own boundaries and by an
    order-independent split of the gap to the nearest neighboring hunk in
    the same file, so two hunks' added context can never overlap regardless
    of which is processed/expanded first.

    Before adopting ANY result, this function requires, in order:
      1. diff_parsing.semantic_delta(input) == semantic_delta(reconstructed)
         -- the reconstructed patch's complete set of '+'/'-' lines, per
         file, in order, is byte-identical to the input's. This is enforced
         here, not only asserted in tests. (Only meaningful for the patch
         shapes accepted above -- see the file-deletion exclusion.)
      2. check_applicability(reconstructed_whole_patch, repo_root) reports
         applicable is True -- the SAME real check the pipeline already
         uses, run once, on the whole patch. Per-hunk standalone checks
         above are scoping only; they never authorize adoption on their own.
    Failing either check discards the reconstruction atomically and returns
    the original patch completely unchanged.

    Never raises -- on any unexpected error returns (original_patch,
    ContextExpansionResult(attempted=True, skipped_reason="internal_error")).
    """
    if not patch or not patch.strip() or not repo_root:
        return patch, ContextExpansionResult()

    try:
        from .diff_parsing import semantic_delta
        from .patch_applicability import check_applicability

        root = Path(repo_root)
        open_fence, clean, close_fence = _strip_md_fences(patch)

        sections = _parse_repaired_sections(clean)
        if sections is None:
            return patch, ContextExpansionResult(attempted=True, skipped_reason="unparseable_structure")

        # File-deletion sections ("+++ /dev/null") are explicitly out of
        # scope, not merely unhandled: parse_diff (and therefore
        # semantic_delta) never recognises "+++ /dev/null" as a file header
        # at all, so a deletion section's removed lines are invisible to the
        # semantic-delta safety gate below -- it would report {} for that
        # file on BOTH sides of any comparison, providing no real protection.
        # Rather than reconstruct against a shape the safety gate can't
        # verify, refuse the WHOLE attempt atomically the moment any section
        # in the patch is a deletion -- even if other files in the same
        # patch would otherwise reconstruct safely on their own.
        if any(sec.is_deletion for sec in sections):
            return patch, ContextExpansionResult(attempted=True, skipped_reason="unsupported_file_deletion")

        hunks_expanded = 0
        hunks_unchanged = 0
        new_sections: "list[_RSection]" = []

        for sec in sections:
            real_idx = [i for i, h in enumerate(sec.hunks) if h.old_start != 0]
            file_lines: "list[str] | None" = None
            file_ends_without_nl = False
            if real_idx:
                file_lines = _load_raw_file_lines(root, sec.file_key)
                if file_lines:
                    file_ends_without_nl = not file_lines[-1].endswith("\n")

            new_hunks = list(sec.hunks)

            for rank, idx in enumerate(real_idx):
                h = sec.hunks[idx]

                standalone = check_applicability(_single_hunk_patch(sec, h), root)
                if standalone.get("applicable") is True:
                    hunks_unchanged += 1
                    continue  # already sufficient -- left byte-for-byte untouched

                if file_lines is None:
                    return patch, ContextExpansionResult(attempted=True, skipped_reason="file_unreadable")

                anchors = old_side_anchors(h.body)
                if not anchors:
                    return patch, ContextExpansionResult(attempted=True, skipped_reason="no_old_side_anchors")

                normalized_file = [l.rstrip("\n") for l in file_lines]
                anchor_pos, reason = locate_occurrence(anchors, normalized_file)
                if reason != "unique_match" or anchor_pos is None:
                    return patch, ContextExpansionResult(
                        attempted=True, skipped_reason=f"anchor_{reason}",
                    )

                anchor_start = anchor_pos
                anchor_end = anchor_pos + len(anchors) - 1

                # Order-independent neighbor-safe budget: split the real gap
                # to each neighbor so this hunk's added context and a
                # neighbor's can never overlap, regardless of expansion order.
                if rank > 0:
                    prev_h = sec.hunks[real_idx[rank - 1]]
                    prev_old_end = (prev_h.old_start - 1) + prev_h.old_count - 1
                    gap = (h.old_start - 1) - prev_old_end - 1
                    lead_cap = max(0, gap // 2)
                else:
                    lead_cap = anchor_start
                if rank < len(real_idx) - 1:
                    next_h = sec.hunks[real_idx[rank + 1]]
                    next_old_start = next_h.old_start - 1
                    gap2 = next_old_start - anchor_end - 1
                    trail_cap = max(0, gap2 // 2)
                else:
                    trail_cap = (len(file_lines) - 1) - anchor_end

                ends_with_no_newline_marker = bool(h.body) and h.body[-1].rstrip("\n").startswith("\\")

                n_lead = max(0, min(_MAX_CONTEXT_LINES, anchor_start, lead_cap))
                max_trail_available = (len(file_lines) - 1) - anchor_end
                if file_ends_without_nl:
                    # Never select the file's true final (no-newline) line
                    # as new trailing context -- it would need its own
                    # "\ No newline at end of file" marker, which this
                    # mechanism does not synthesize.
                    max_trail_available -= 1
                n_trail = 0 if ends_with_no_newline_marker else max(
                    0, min(_MAX_CONTEXT_LINES, max_trail_available, trail_cap),
                )

                if n_lead == 0 and n_trail == 0:
                    return patch, ContextExpansionResult(attempted=True, skipped_reason="no_safe_headroom")

                lead_lines = [" " + file_lines[k] for k in range(anchor_start - n_lead, anchor_start)]
                trail_lines = [" " + file_lines[k] for k in range(anchor_end + 1, anchor_end + 1 + n_trail)]
                new_body = lead_lines + list(h.body) + trail_lines
                new_old_start = h.old_start - n_lead
                new_new_start = h.new_start - n_lead
                new_old_count, new_new_count = _count_body(new_body)
                new_hunk = _RHunk(
                    old_start=new_old_start, old_count=new_old_count,
                    new_start=new_new_start, new_count=new_new_count,
                    suffix=h.suffix,
                    raw_header=_format_hunk_header(
                        new_old_start, new_old_count, new_new_start, new_new_count, h.suffix,
                    ),
                    body=new_body,
                )

                recheck = check_applicability(_single_hunk_patch(sec, new_hunk), root)
                if not recheck.get("applicable"):
                    return patch, ContextExpansionResult(
                        attempted=True, skipped_reason="hunk_still_not_applicable_after_expansion",
                    )

                new_hunks[idx] = new_hunk
                hunks_expanded += 1

            new_sections.append(_RSection(
                header_a=sec.header_a, header_b=sec.header_b,
                file_key=sec.file_key, hunks=new_hunks,
            ))

        if hunks_expanded == 0:
            return patch, ContextExpansionResult(
                attempted=True, hunks_unchanged=hunks_unchanged,
                skipped_reason="no_hunks_needed_expansion",
            )

        reconstructed_clean = _render_sections(new_sections)

        if semantic_delta(clean) != semantic_delta(reconstructed_clean):
            return patch, ContextExpansionResult(attempted=True, skipped_reason="semantic_delta_mismatch")

        reconstructed = open_fence + reconstructed_clean + close_fence
        final = check_applicability(reconstructed, root)
        if not final.get("applicable"):
            return patch, ContextExpansionResult(attempted=True, skipped_reason="whole_patch_still_not_applicable")

        return reconstructed, ContextExpansionResult(
            attempted=True, succeeded=True,
            hunks_expanded=hunks_expanded, hunks_unchanged=hunks_unchanged,
        )

    except Exception:
        return patch, ContextExpansionResult(attempted=True, skipped_reason="internal_error")
