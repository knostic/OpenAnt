"""Deterministic unified diff hunk header repair.

LLMs frequently generate unified diffs with arithmetically wrong @@ -a,b +c,d @@
counts. This module recomputes b and d from the actual hunk body lines, and
recomputes c as old_start + cumulative_prior_net_delta within the same file.
The old start line (a) is preserved as-is — it is the LLM's positional anchor
and requires knowledge of the original file to validate independently.

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
    repair_hunk_headers(patch: str) -> tuple[str, RepairResult]

RepairResult fields:
    normalization_applied : bool  — True if any @@ line was changed, or any
                                     file's hunks were consolidated from more
                                     than one header-pair section
    hunks_rewritten       : int   — number of @@ headers with corrected values
    files_rewritten       : int   — number of distinct filenames with ≥1 rewrite
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


_HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)"
)
_FENCE_OPEN_RE = re.compile(r"^```")


@dataclass
class RepairResult:
    normalization_applied: bool = False
    hunks_rewritten: int = 0
    files_rewritten: int = 0


def repair_hunk_headers(patch: str) -> tuple[str, RepairResult]:
    """Recompute unified diff hunk header counts from body content.

    Returns (repaired_patch, RepairResult).
    Never raises — on any unexpected error returns (original_patch, RepairResult()).
    """
    meta = RepairResult()
    if not patch or not patch.strip():
        return patch, meta
    try:
        open_fence, clean, close_fence = _strip_md_fences(patch)
        repaired, meta = _repair(clean, meta)
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


def _repair(patch: str, meta: RepairResult) -> tuple[str, RepairResult]:
    lines = patch.splitlines(keepends=True)

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
        nonlocal in_hunk, hunk_orig_header, hunk_body

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
