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
