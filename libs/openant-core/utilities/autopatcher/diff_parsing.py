"""Generic unified-diff parsing.

Extracted from impact_surface.py: this parser understands only the
language-agnostic unified-diff conventions (`--- a/...`, `+++ b/...`, `@@ ... @@`
hunk headers, and ' '/'+'/'-' prefixed body lines). It has no Python-specific
behavior — symbol resolution, AST parsing, and everything else that depends on
a particular language stays in impact_surface.py and consumes this module's
output.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class DiffHunk:
    """One hunk's raw body lines, each still prefixed with its diff marker
    (' ', '+', or '-'). `new_start`/`new_count` are kept only for
    diagnostic/debugging purposes — symbol resolution does not use them,
    by design (see impact_surface.py's module docstring)."""
    new_start: int
    new_count: int
    lines: List[str] = field(default_factory=list)


def parse_diff(diff: str) -> Tuple[List[str], Dict[str, List[DiffHunk]]]:
    """Parse a unified diff and return list of changed files and hunks per file.

    Unlike a purely line-range-based parse, this keeps each hunk's actual
    body lines (context/added/removed), which symbol resolution needs to
    relocate the hunk by content rather than by trusting its header.
    """
    changed_files: List[str] = []
    file_hunks: Dict[str, List[DiffHunk]] = {}
    cur_file: Optional[str] = None
    cur_hunk: Optional[DiffHunk] = None

    def flush() -> None:
        nonlocal cur_hunk
        if cur_hunk is not None and cur_file is not None:
            file_hunks[cur_file].append(cur_hunk)
        cur_hunk = None

    for line in diff.splitlines():
        if line.startswith("--- "):
            flush()
            continue
        if line.startswith("+++ b/"):
            flush()
            cur_file = line[6:].strip()
            if cur_file not in changed_files:
                changed_files.append(cur_file)
                file_hunks[cur_file] = []
            continue
        if line.startswith("@@") and cur_file is not None:
            flush()
            m = re.search(r"\+([0-9]+)(?:,([0-9]+))?", line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) else 1
                cur_hunk = DiffHunk(new_start=start, new_count=count)
            continue
        if cur_hunk is not None and line[:1] in (" ", "+", "-"):
            cur_hunk.lines.append(line)
    flush()
    return changed_files, file_hunks


def semantic_delta(patch: str) -> Dict[str, Tuple[List[str], List[str]]]:
    """Return, per changed file, the ordered sequence of every '+' (addition)
    and '-' (removal) line's raw content — the diff's complete semantic
    delta, independent of hunk headers and unchanged (' '-prefixed) context
    lines.

    Built strictly on ``parse_diff``'s own output — no separate parser.
    Two diffs with an identical ``semantic_delta()`` differ, if at all, only
    in hunk metadata and/or context lines, never in what they actually add
    or remove.

    Used both as a production fail-closed safety gate
    (``diff_hunk_repair.reconstruct_hunk_context``) and as the shared test
    invariant proving deterministic context reconstruction never touches a
    semantic addition/removal.

    Safe against parse_diff's own "+++ "/"--- " body-line ambiguity (see
    that function's F-36/F-41/F-45-style edge case) for this specific use:
    that ambiguity only ever arises for an ADDED/REMOVED line whose own
    content starts with "++ "/"-- " (marker + content forms "+++ "/"--- ");
    a CONTEXT line's leading ' ' marker always shifts any such content one
    character to the right, so it can never collide with that prefix check.
    Since context reconstruction only ever inserts context lines, it can
    never introduce this ambiguity — only pre-existing +/- lines could, and
    this function reports them identically before and after either way.
    """
    _, file_hunks = parse_diff(patch)
    return {
        f: (
            [l for h in hunks for l in h.lines if l.startswith("+") and not l.startswith("+++")],
            [l for h in hunks for l in h.lines if l.startswith("-") and not l.startswith("---")],
        )
        for f, hunks in file_hunks.items()
    }


def semantic_delta_preserved(
    original: str, candidate: str, unguarded_files: "Optional[List[str]]" = None,
) -> bool:
    """True if `candidate`'s semantic_delta() matches `original`'s for
    every file EXCEPT those named in `unguarded_files`.

    The bounded safety gate an LLM-driven patch regeneration (e.g. an
    applicability-aware retry) can be checked against before its output
    is accepted, reusing the exact same semantic_delta() invariant
    `diff_hunk_repair.reconstruct_hunk_context` already uses to guard its
    own deterministic reconstruction (see that function's own module
    docstring) — applied here to an LLM's output instead.

    A file present on only one side is treated as having an empty delta
    ([], []) on the other -- so a file that disappears entirely from
    `candidate`, or a brand-new file that appears in `candidate` but was
    never in `original` and is not itself unguarded, both count as a
    change and fail this check, exactly like an in-place edit to that
    file's existing hunk would.

    `unguarded_files` names the file(s) the caller EXPECTS -- and
    permits -- to differ (e.g. the file(s) an applicability retry was
    actually asked to repair); every other file's additions/removals
    must be identical, in order, or this returns False.
    """
    orig = semantic_delta(original)
    cand = semantic_delta(candidate)
    unguarded = set(unguarded_files or ())
    empty: Tuple[List[str], List[str]] = ([], [])
    for f in set(orig) | set(cand):
        if f in unguarded:
            continue
        if orig.get(f, empty) != cand.get(f, empty):
            return False
    return True
