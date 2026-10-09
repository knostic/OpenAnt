"""Deterministic patch hygiene checker.

Runs three lightweight checks on a unified diff string — no AST, no parsing
library, no external dependencies.

Checks:
  A. empty_hunk          — file appears in diff but has no changed lines
  B. duplicate_assignment — ALL_CAPS constant added without removing existing one
  C. unused_import        — Python import added but imported name unused in
                           the visible diff (or the pre-patch file, when a
                           repo_root is given)

Returns a list of finding dicts: {severity, check, detail}.
Never raises. An internal error is reported as a MEDIUM `hygiene_check_failed`
finding, never as [] -- an empty list means "checked and clean", so it must
not also stand for "could not check" (it would read as integrity=Clean).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from utilities.file_io import read_repo_file


# ---------------------------------------------------------------------------
# Internal data model
# ---------------------------------------------------------------------------

@dataclass
class _FilePatch:
    filename: str
    is_new_file: bool        # True when --- /dev/null
    added_lines: list[str]   # raw text of each added line (without leading +)
    removed_lines: list[str] # raw text of each removed line (without leading -)
    context_lines: list[str] # raw text of each unchanged line shown in the diff


# ---------------------------------------------------------------------------
# Diff parser
# ---------------------------------------------------------------------------

def _parse_file_patches(patch: str) -> list[_FilePatch]:
    """Split a unified diff into per-file sections."""
    patches: list[_FilePatch] = []
    from_path: str | None = None
    to_path: str | None = None
    added: list[str] = []
    removed: list[str] = []
    context: list[str] = []

    def _flush() -> None:
        if to_path is not None:
            is_new = from_path is not None and (
                from_path == "/dev/null" or from_path.endswith("/dev/null")
            )
            patches.append(_FilePatch(
                filename=to_path,
                is_new_file=is_new,
                added_lines=added[:],
                removed_lines=removed[:],
                context_lines=context[:],
            ))

    # Split on "\n" only (dropping a CRLF's "\r"), exactly like
    # diff_parsing.parse_diff: str.splitlines() also breaks on \f, \x85,
    # U+2028 etc., cutting one diff line in two.
    lines = [l[:-1] if l.endswith("\r") else l for l in patch.split("\n")]
    i = 0
    n = len(lines)
    in_hunk = False
    while i < n:
        line = lines[i]

        # A real file header is a "--- "/"+++ " PAIR on adjacent lines, not
        # merely a line that starts with one of those prefixes — a
        # removed/added hunk-body line whose text is "-- foo" or "++ foo"
        # produces the raw line "--- foo" / "+++ foo" too. Requiring the
        # very next line to complete the pair tells apart a genuine file
        # boundary from coincidental body content. Resolving the pair in one
        # step also flushes the PREVIOUS file using its own from_path/to_path
        # before either is overwritten, instead of leaking the next file's
        # from_path into the previous file's is_new_file computation. Inside a
        # hunk the pair alone is not enough (a removed "-- x" line followed by
        # an added "++ y" line forms the same raw pair), so there a genuine
        # header must also be followed by its own "@@" line -- the rule
        # diff_parsing.parse_diff and diff_hunk_repair use (F-14).
        if line.startswith("diff --git "):
            in_hunk = False
        if (
            line.startswith("--- ")
            and i + 1 < n
            and lines[i + 1].startswith("+++ ")
            and (not in_hunk or (i + 2 < n and lines[i + 2].startswith("@@")))
        ):
            _flush()
            raw = line[4:].split("\t")[0].strip()
            from_path = raw[2:] if raw.startswith("a/") else raw
            raw2 = lines[i + 1][4:].split("\t")[0].strip()
            to_path = raw2[2:] if raw2.startswith("b/") else raw2
            added = []
            removed = []
            context = []
            in_hunk = False
            i += 2
            continue

        if to_path is not None and line.startswith("@@"):
            in_hunk = True

        if to_path is not None:
            # A genuine "+++ "/"--- " header line would already have been
            # consumed by the pair check above (and skipped via `continue`),
            # so any "+"/"-"-prefixed line reaching this point is body
            # content — even one whose text itself starts with "++ "/"-- "
            # (raw "+++ .../--- ..."). Excluding those here would silently
            # drop legitimate added/removed content.
            if line.startswith("+"):
                added.append(line[1:])
            elif line.startswith("-"):
                removed.append(line[1:])
            elif line.startswith(" "):
                context.append(line[1:])

        i += 1

    _flush()
    return patches


# ---------------------------------------------------------------------------
# Check A — empty / no-op file hunks
# ---------------------------------------------------------------------------

def _check_empty_hunks(fps: list[_FilePatch]) -> list[dict]:
    findings = []
    for fp in fps:
        if not fp.added_lines and not fp.removed_lines:
            findings.append({
                "severity": "HIGH",
                "check": "empty_hunk",
                "detail": (
                    f"`{fp.filename}` appears in the diff but has no changed lines — "
                    "this hunk is a no-op and should be removed"
                ),
            })
    return findings


# ---------------------------------------------------------------------------
# Check B — duplicate ALL_CAPS constant assignment
# ---------------------------------------------------------------------------

_CONST_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]{2,})\s*=")


def _check_duplicate_assignments(fps: list[_FilePatch]) -> list[dict]:
    """Diff-local co-occurrence heuristic only.

    Flags a name that is both added and visible as an unchanged assignment
    within the same diff, with no matching removal. This does not infer
    file-wide duplication, execution order, runtime shadowing, or that the
    added assignment is ineffective — it only observes that both lines are
    visible in the diff as shown, which is why a match here is MEDIUM
    (needs a human look) rather than a confirmed defect.
    """
    findings = []
    for fp in fps:
        if fp.is_new_file:
            continue  # a new file legitimately defines constants without removing them
        added_names: set[str] = set()
        removed_names: set[str] = set()
        context_names: set[str] = set()
        for line in fp.added_lines:
            m = _CONST_RE.match(line)
            if m:
                added_names.add(m.group(1))
        for line in fp.removed_lines:
            m = _CONST_RE.match(line)
            if m:
                removed_names.add(m.group(1))
        for line in fp.context_lines:
            m = _CONST_RE.match(line)
            if m:
                context_names.add(m.group(1))
        suspicious = (added_names & context_names) - removed_names
        for name in sorted(suspicious):
            findings.append({
                "severity": "MEDIUM",
                "check": "duplicate_assignment",
                "detail": (
                    f"`{fp.filename}`: `{name}` is added, and an unchanged "
                    "assignment with the same name is also visible in this "
                    "diff — both are present as shown; please verify manually"
                ),
            })
    return findings


# ---------------------------------------------------------------------------
# Check C — unused import added
# ---------------------------------------------------------------------------

_IMPORT_RE = re.compile(
    r"^(?:import\s+(\S+)|from\s+\S+\s+import\s+(.+))"
)


def _imported_names(line: str) -> list[str]:
    """Return the local names introduced by an import line."""
    m = _IMPORT_RE.match(line.strip())
    if not m:
        return []
    # `import a.b as c, d.e` — local names are aliases or FIRST components;
    # `from X import Y, Z as W` — local names are aliases or LAST identifiers
    is_from = not m.group(1)
    body = m.group(2) if is_from else line.strip().split(None, 1)[1]
    names = []
    for part in body.strip().strip("()\\").split(","):
        part = part.strip()
        if " as " in part:
            names.append(part.split(" as ")[-1].strip())
        else:
            names.append(part.split(".")[-1 if is_from else 0].strip())
    return [n for n in names if n and re.match(r"^[A-Za-z_]\w*$", n)]


_PYTHON_SUFFIXES = (".py", ".pyi")


def _pre_patch_lines(repo_root, filename: str) -> list[str]:
    """The pre-patch file's lines, as extra usage evidence -- or [] when it
    cannot be read safely (outside repo_root, symlink, FIFO, oversize,
    missing, undecodable). [] only means "no extra evidence": the caller
    then falls back to the diff-only check, which still flags."""
    if repo_root is None:
        return []
    try:
        root = Path(repo_root).resolve()
        path = (root / filename).resolve()
        if not path.is_relative_to(root):
            return []
        text = read_repo_file(path, oversize="truncate")
    except Exception:  # noqa: BLE001 -- unsafe/unreadable file: no extra evidence
        return []
    return text.splitlines() if text else []


def _check_unused_imports(fps: list[_FilePatch], repo_root=None) -> list[dict]:
    findings = []
    for fp in fps:
        # The import grammar below is Python's; other languages' import
        # lines (`import { x } from`, `import "fmt"`) are not checked.
        if not fp.filename.endswith(_PYTHON_SUFFIXES):
            continue
        # Usage lookup: every non-import line visible in the diff (added AND
        # unchanged context), plus the pre-patch file when it is readable.
        removed = {r.strip() for r in fp.removed_lines}
        visible = fp.added_lines + fp.context_lines
        if not fp.is_new_file:
            # Lines the patch removes are not usage after the patch.
            visible = visible + [
                line for line in _pre_patch_lines(repo_root, fp.filename)
                if line.strip() not in removed
            ]
        non_import_added = "\n".join(
            line for line in visible
            if not _IMPORT_RE.match(line.strip())
        )
        for line in fp.added_lines:
            if line.strip() in removed:
                continue  # a moved/re-added import, not a newly added one
            names = _imported_names(line)
            if not names:
                continue
            for name in names:
                if not re.search(rf"\b{re.escape(name)}\b", non_import_added):
                    findings.append({
                        "severity": "MEDIUM",
                        "check": "unused_import",
                        "detail": (
                            f"`{fp.filename}`: `{line.strip()}` — "
                            f"`{name}` is not used in any other line of the diff or file"
                        ),
                    })
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

HYGIENE_CHECK_FAILED = {
    "severity": "MEDIUM",
    "check": "hygiene_check_failed",
    "detail": "The hygiene check failed internally; patch hygiene was not verified",
}


def check_patch(patch: str, repo_root=None) -> list[dict]:
    """Run all hygiene checks on a unified diff string.

    Returns a list of finding dicts with keys: severity, check, detail.
    Returns an empty list if the patch is empty or has no file sections.
    `repo_root`, when given, lets the unused-import check also look for a
    usage in the pre-patch file (read via read_repo_file, confined to
    repo_root). Never raises: an internal error returns
    [HYGIENE_CHECK_FAILED] (MEDIUM -> integrity "Minor Issues", never
    "Clean").
    """
    if not patch or not patch.strip():
        return []
    try:
        fps = _parse_file_patches(patch)
        if not fps:
            return []
        findings: list[dict] = []
        findings.extend(_check_empty_hunks(fps))
        findings.extend(_check_duplicate_assignments(fps))
        findings.extend(_check_unused_imports(fps, repo_root))
        return findings
    except Exception:  # noqa: BLE001 -- fail closed, never "clean"
        return [dict(HYGIENE_CHECK_FAILED)]
