"""Deterministic patch hygiene checker.

Runs three lightweight checks on a unified diff string — no AST, no parsing
library, no external dependencies.

Checks:
  A. empty_hunk          — file appears in diff but has no changed lines
  B. duplicate_assignment — ALL_CAPS constant added without removing existing one
  C. unused_import        — import added but imported name unused in changed lines

Returns a list of finding dicts: {severity, check, detail}.
Never raises — callers may rely on it returning [] on any error.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Internal data model
# ---------------------------------------------------------------------------

@dataclass
class _FilePatch:
    filename: str
    is_new_file: bool        # True when --- /dev/null
    added_lines: list[str]   # raw text of each added line (without leading +)
    removed_lines: list[str] # raw text of each removed line (without leading -)


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
            ))

    for line in patch.splitlines():
        if line.startswith("--- "):
            raw = line[4:].split("\t")[0].strip()
            from_path = raw[2:] if raw.startswith("a/") else raw
        elif line.startswith("+++ "):
            _flush()
            raw = line[4:].split("\t")[0].strip()
            to_path = raw[2:] if raw.startswith("b/") else raw
            added = []
            removed = []
        elif to_path is not None:
            if line.startswith("+") and not line.startswith("+++"):
                added.append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                removed.append(line[1:])

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
    findings = []
    for fp in fps:
        if fp.is_new_file:
            continue  # a new file legitimately defines constants without removing them
        added_names: set[str] = set()
        removed_names: set[str] = set()
        for line in fp.added_lines:
            m = _CONST_RE.match(line)
            if m:
                added_names.add(m.group(1))
        for line in fp.removed_lines:
            m = _CONST_RE.match(line)
            if m:
                removed_names.add(m.group(1))
        for name in sorted(added_names - removed_names):
            findings.append({
                "severity": "HIGH",
                "check": "duplicate_assignment",
                "detail": (
                    f"`{fp.filename}`: `{name}` is added but the existing "
                    "definition is not removed — likely duplicates it"
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
    if m.group(1):
        # `import a.b.c` — local name is the first component
        return [m.group(1).split(".")[0]]
    # `from X import Y, Z as W` — local names are aliases or last identifiers
    names = []
    for part in m.group(2).split(","):
        part = part.strip()
        if " as " in part:
            names.append(part.split(" as ")[-1].strip())
        else:
            names.append(part.split(".")[-1].strip())
    return [n for n in names if n and re.match(r"^[A-Za-z_]\w*$", n)]


def _check_unused_imports(fps: list[_FilePatch]) -> list[dict]:
    findings = []
    for fp in fps:
        # Collect non-import added lines for usage lookup
        non_import_added = "\n".join(
            line for line in fp.added_lines
            if not _IMPORT_RE.match(line.strip())
        )
        for line in fp.added_lines:
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
                            f"`{name}` is not used in any other changed line"
                        ),
                    })
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_patch(patch: str) -> list[dict]:
    """Run all hygiene checks on a unified diff string.

    Returns a list of finding dicts with keys: severity, check, detail.
    Returns an empty list if the patch is empty or unparseable.
    Never raises.
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
        findings.extend(_check_unused_imports(fps))
        return findings
    except Exception:
        return []
