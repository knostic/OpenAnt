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
