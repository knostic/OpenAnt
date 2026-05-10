"""
Diff-based unit filter for incremental (PR-diff) scanning.

Consumes a diff_manifest.json produced by the Go CLI
(apps/openant-cli/internal/git) and annotates each unit in the dataset with
`diff_selected: bool`. Downstream pipeline stages skip units where
`diff_selected is False` — units without the field (pre-diff datasets) are
processed unchanged.

Manifest contract (see internal/git/manifest.go):

    {
      "base_ref": "origin/main",
      "base_sha": "...",
      "head_sha": "...",
      "scope": "changed_functions",      # or "changed_files" | "callers"
      "pr_number": 123,                   # optional, 0 means none
      "changed_files": ["a.py", "b.py"],
      "hunks": {                          # omitted for changed_files scope
        "a.py": [[42, 78], [110, 115]]
      }
    }

Scopes:
  - changed_files      -> all units in a changed file
  - changed_functions  -> units whose [start_line, end_line] overlaps a hunk
  - callers            -> changed_functions plus any unit whose direct_calls
                          contains a selected unit id (1-hop)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, asdict

from utilities.file_io import read_json


# Scope constants (must match internal/git/manifest.go).
SCOPE_CHANGED_FILES = "changed_files"
SCOPE_CHANGED_FUNCTIONS = "changed_functions"
SCOPE_CALLERS = "callers"
_VALID_SCOPES = (SCOPE_CHANGED_FILES, SCOPE_CHANGED_FUNCTIONS, SCOPE_CALLERS)


@dataclass
class DiffStats:
    """Summary of what apply_diff_filter selected.

    Attached to the parse step report so users see scope impact at a glance.
    """
    total: int = 0
    selected: int = 0
    scope: str = ""
    base_ref: str = ""
    base_sha: str = ""
    head_sha: str = ""
    pr_number: int = 0
    changed_files: int = 0
    fallback_file_match: int = 0   # units that lacked line info, matched by file only
    callers_added: int = 0          # units added by the 1-hop callers pass

    def to_dict(self) -> dict:
        return asdict(self)


def load_manifest(path: str) -> dict:
    """Read and minimally validate a diff manifest file."""
    m = read_json(path)
    scope = m.get("scope")
    if scope not in _VALID_SCOPES:
        raise ValueError(
            f"invalid scope {scope!r} in {path}; expected one of {_VALID_SCOPES}"
        )
    if not isinstance(m.get("changed_files"), list):
        raise ValueError(f"manifest {path} missing or invalid 'changed_files' list")
    return m


def apply_diff_filter(units: list[dict], manifest: dict) -> DiffStats:
    """Annotate each unit in `units` with `diff_selected: bool` per manifest.

    Mutates the list in place (adds a field to each unit dict). Returns
    DiffStats for the step report.
    """
    scope = manifest["scope"]
    if scope not in _VALID_SCOPES:
        raise ValueError(f"invalid scope {scope!r}")

    changed_files = set(_norm_path(p) for p in manifest.get("changed_files", []))
    hunks = {
        _norm_path(k): v
        for k, v in (manifest.get("hunks") or {}).items()
    }

    stats = DiffStats(
        total=len(units),
        scope=scope,
        base_ref=manifest.get("base_ref", ""),
        base_sha=manifest.get("base_sha", ""),
        head_sha=manifest.get("head_sha", ""),
        pr_number=int(manifest.get("pr_number") or 0),
        changed_files=len(changed_files),
    )

    # First pass: mark units based on file + (for function/callers) hunk overlap.
    for unit in units:
        unit_file = _resolve_unit_file(unit)
        if not unit_file or unit_file not in changed_files:
            unit["diff_selected"] = False
            continue

        if scope == SCOPE_CHANGED_FILES:
            unit["diff_selected"] = True
            continue

        start, end = _resolve_line_range(unit)
        if start is None or end is None:
            # No line info — safest behavior is to include (avoid false
            # negatives). Log once per unit to stderr so users know.
            print(
                f"[diff_filter] unit {unit.get('id')!r} in {unit_file} "
                f"has no start/end line; falling back to file-level match",
                file=sys.stderr,
            )
            unit["diff_selected"] = True
            stats.fallback_file_match += 1
            continue

        file_hunks = hunks.get(unit_file, [])
        unit["diff_selected"] = _any_overlap(start, end, file_hunks)

    # Second pass: callers scope adds 1-hop reverse (units whose direct_calls
    # point at a selected unit).
    if scope == SCOPE_CALLERS:
        selected_ids = {
            u.get("id") for u in units if u.get("diff_selected") and u.get("id")
        }
        if selected_ids:
            for unit in units:
                if unit.get("diff_selected"):
                    continue
                calls = _unit_direct_calls(unit)
                if any(c in selected_ids for c in calls):
                    unit["diff_selected"] = True
                    stats.callers_added += 1

    stats.selected = sum(1 for u in units if u.get("diff_selected"))
    return stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _norm_path(p: str) -> str:
    if p.startswith("./"):
        return p[2:]
    return p


def _resolve_unit_file(unit: dict) -> str | None:
    """Return the file path for a unit, trying the known shapes in order."""
    code = unit.get("code") or {}
    origin = code.get("primary_origin")
    if isinstance(origin, dict) and origin.get("file_path"):
        return _norm_path(origin["file_path"])

    # Fallback: top-level primary_origin (older parsers)
    origin = unit.get("primary_origin")
    if isinstance(origin, dict) and origin.get("file_path"):
        return _norm_path(origin["file_path"])

    # Last resort: split id on the last ':' — format "path/file.py:func"
    unit_id = unit.get("id") or ""
    if ":" in unit_id:
        # rsplit handles ids like "C:/Users/... :func" on Windows only if we
        # assume repo paths are POSIX; openant repos always are.
        return _norm_path(unit_id.rsplit(":", 1)[0])
    return None


def _resolve_line_range(unit: dict) -> tuple[int | None, int | None]:
    """Return (start_line, end_line) for a unit, trying the known shapes."""
    code = unit.get("code") or {}
    origin = code.get("primary_origin")
    if isinstance(origin, dict):
        s, e = origin.get("start_line"), origin.get("end_line")
        if isinstance(s, int) and isinstance(e, int):
            return s, e

    origin = unit.get("primary_origin")
    if isinstance(origin, dict):
        s, e = origin.get("start_line"), origin.get("end_line")
        if isinstance(s, int) and isinstance(e, int):
            return s, e

    meta = unit.get("metadata") or {}
    s, e = meta.get("start_line"), meta.get("end_line")
    if isinstance(s, int) and isinstance(e, int):
        return s, e

    return None, None


def _unit_direct_calls(unit: dict) -> list:
    """Return the unit's direct_calls list (supports both snake_case and camelCase)."""
    meta = unit.get("metadata") or {}
    calls = meta.get("direct_calls")
    if calls is None:
        calls = meta.get("directCalls")
    return calls or []


def _any_overlap(start: int, end: int, hunks: list) -> bool:
    """Whether [start, end] overlaps any [a, b] pair in hunks."""
    for h in hunks:
        if len(h) != 2:
            continue
        a, b = h[0], h[1]
        if end < a or start > b:
            continue
        return True
    return False
