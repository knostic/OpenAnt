"""Language-agnostic, deterministic content-based hunk relocation.

Given a unified-diff hunk's OLD-side lines (context + removed) and the
current, unpatched target file's lines, finds the exact contiguous location
in the file where those lines occur -- never by trusting the hunk header's
own claimed line number, which an LLM can get wrong even when the hunk's
actual content is byte-identical to the real file (see
diff_hunk_repair.py's ``repair_hunk_headers``, which uses this module to
correct exactly that case).

A prior, independent instance of the same relocation technique already
exists in this codebase, in impact_surface.py, for a different consumer
(Python-only symbol resolution via ``ast`` + ``difflib.SequenceMatcher``
fuzzy matching). This module is deliberately a separate, smaller
implementation rather than a reuse of that one, for two reasons:

- impact_surface.py's matching is fuzzy (longest common subsequence) and
  Python-specific in what it feeds into `ast` afterward. Patch relocation
  must be exact and language-agnostic (see below) -- a "best effort" fuzzy
  match is the wrong contract when the result feeds `git apply`, which
  needs the OLD side to match verbatim anyway.
- impact_surface.py's line-normalization function strips one leading
  character whenever a line happens to start with ' ', '+', or '-' --
  harmless for its hunk-body-line inputs (which always carry a real diff
  marker there) but WRONG when applied to a raw repository file line: many
  languages have legitimate lines whose first non-whitespace character is
  '-' or '+' (SQL/Lua `--` comments, YAML/Markdown '- ' list items, unary
  expressions), and this module must not corrupt those.

No AST, no tokenizer, no language keywords, no comment/string awareness --
every line is treated as opaque text, so this applies identically to
Python, JavaScript, Go, Rust, Java, or any other source file.
"""

from __future__ import annotations


def normalize_diff_line(line: str) -> str:
    """Strip a unified-diff hunk body line's leading marker (one of
    ' ', '+', '-') then strip surrounding whitespace.

    Every hunk body line carries exactly one such marker by construction
    (unified-diff format), so slicing it off never touches real content --
    only the diff-format prefix.
    """
    if line[:1] in (" ", "+", "-"):
        line = line[1:]
    return line.strip()


def normalize_file_line(line: str) -> str:
    """Strip surrounding whitespace from a raw repository file line.

    Deliberately does NOT slice off a leading character the way
    ``normalize_diff_line`` does for diff body lines: a real source line
    has no diff marker to remove, and many languages have legitimate lines
    whose first non-whitespace character is '-' or '+' -- slicing one off
    would corrupt the comparison for exactly the multi-language inputs this
    relocation must support.
    """
    return line.strip()


def old_side_anchors(hunk_body: "list[str]") -> "list[str]":
    """The hunk's OLD-side lines -- context (' ') and removed ('-') --
    normalized.

    These are exactly the lines that must already exist, verbatim
    (module-whitespace-normalized), in the current (pre-patch) file for
    `git apply` to accept the hunk. Added ('+') lines are never part of
    this: they are new content and need not exist anywhere yet. A
    '\\ No newline at end of file' marker line (leading '\\') is excluded
    naturally, the same way diff_hunk_repair._count_body excludes it --
    neither ' ' nor '-' matches its own first character.
    """
    return [normalize_diff_line(line) for line in hunk_body if line[:1] in (" ", "-")]


def find_unique_occurrence(anchors: "list[str]", file_lines: "list[str]") -> "int | None":
    """Return the 0-indexed line in `file_lines` where `anchors` occurs as
    an exact, contiguous, whitespace-normalized match.

    Returns None when there is no such match, or when there is more than
    one -- an absent match and an ambiguous match are reported identically
    as "cannot relocate", never as a best guess. The caller must leave the
    hunk's claimed position untouched in either case rather than relocate
    it speculatively.
    """
    n = len(anchors)
    if n == 0 or n > len(file_lines):
        return None
    normalized_file = [normalize_file_line(line) for line in file_lines]
    matches = [
        i
        for i in range(len(normalized_file) - n + 1)
        if normalized_file[i : i + n] == anchors
    ]
    return matches[0] if len(matches) == 1 else None


def locate_occurrence(anchors: "list[str]", file_lines: "list[str]") -> "tuple[int | None, str]":
    """Classify *why* a hunk can or cannot be relocated, for observability
    (telemetry) only.

    Returns (position_or_None, reason), where reason is one of
    "unique_match", "ambiguous", or "no_match" (an empty `anchors` list
    also reports "no_match" here; the caller classifies that case as
    "skipped" instead, since it never reaches this function at all).

    This performs the exact same matching as `find_unique_occurrence`,
    deliberately duplicated rather than shared: `find_unique_occurrence`
    is the function actually consulted for relocation decisions elsewhere
    in this codebase, and must never change as a side effect of adding
    this classification. Nothing here feeds back into any decision --
    it exists only so a caller can report which of the three cases
    occurred without re-deriving it from `find_unique_occurrence`'s
    single boolean-shaped return value.
    """
    n = len(anchors)
    if n == 0 or n > len(file_lines):
        return None, "no_match"
    normalized_file = [normalize_file_line(line) for line in file_lines]
    matches = [
        i
        for i in range(len(normalized_file) - n + 1)
        if normalized_file[i : i + n] == anchors
    ]
    if len(matches) == 1:
        return matches[0], "unique_match"
    if len(matches) == 0:
        return None, "no_match"
    return None, "ambiguous"
