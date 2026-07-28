"""Deterministic unified diff hunk header repair.

LLMs frequently generate unified diffs with arithmetically wrong @@ -a,b +c,d @@
counts. This module recomputes b and d from the actual hunk body lines, and
recomputes c as old_start + cumulative_prior_net_delta within the same file.
The old start line (a) is preserved as-is — it is the LLM's positional anchor
and requires knowledge of the original file to validate independently.

Public API:
    repair_hunk_headers(patch: str) -> tuple[str, RepairResult]

RepairResult fields:
    normalization_applied : bool  — True if any @@ line was changed
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
    if lines and lines[-1].strip() in ("```", "~~~"):
        close_fence = lines.pop()
    return open_fence, "".join(lines), close_fence


def _repair(patch: str, meta: RepairResult) -> tuple[str, RepairResult]:
    lines = patch.splitlines(keepends=True)
    output: list[str] = []

    # Per-file accumulator: sum of (new_count - old_count) for prior hunks
    file_delta: int = 0
    current_file: str | None = None
    files_touched: set[str] = set()

    # Per-hunk state
    hunk_orig_header: str | None = None
    hunk_old_start: int = 0
    hunk_claimed_new_start: int = 0
    hunk_suffix: str = ""
    hunk_body: list[str] = []
    in_hunk: bool = False

    def flush_hunk() -> None:
        nonlocal file_delta, in_hunk, hunk_orig_header, hunk_body

        if not in_hunk:
            return

        old_count, new_count = _count_body(hunk_body)

        # New-file sentinel: old_start=0 means the old file doesn't exist.
        # The delta formula doesn't apply; preserve the original new_start
        # (conventionally 1 for a new non-empty file, 0 for an empty one).
        if hunk_old_start == 0:
            correct_new_start = hunk_claimed_new_start
        else:
            correct_new_start = hunk_old_start + file_delta
        rewritten = (
            f"@@ -{hunk_old_start},{old_count}"
            f" +{correct_new_start},{new_count}"
            f" @@{hunk_suffix}\n"
        )

        if rewritten != hunk_orig_header:
            meta.hunks_rewritten += 1
            meta.normalization_applied = True
            if current_file is not None:
                files_touched.add(current_file)

        output.append(rewritten)
        output.extend(hunk_body)

        file_delta += new_count - old_count
        in_hunk = False
        hunk_orig_header = None
        hunk_body = []

    for line in lines:
        stripped = line.rstrip("\n")

        if stripped.startswith("--- "):
            flush_hunk()
            file_delta = 0
            # Track filename for metadata (strip a/ prefix when present)
            raw = stripped[4:].split("\t")[0].strip()
            current_file = raw[2:] if raw.startswith("a/") else raw
            output.append(line)

        elif stripped.startswith("+++ "):
            output.append(line)

        elif stripped.startswith("@@ "):
            flush_hunk()
            m = _HUNK_RE.match(stripped)
            if not m:
                output.append(line)  # malformed — pass through unchanged
                continue
            hunk_old_start = int(m.group(1))
            hunk_claimed_new_start = int(m.group(3))
            hunk_suffix = m.group(5)   # text after second @@, e.g. " function setKey"
            hunk_orig_header = line
            hunk_body = []
            in_hunk = True

        elif in_hunk:
            hunk_body.append(line)

        else:
            output.append(line)  # preamble, diff --git lines, etc.

    flush_hunk()
    meta.files_rewritten = len(files_touched)
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
