"""#521 finding 1: the declared-runtime channel (the mechanical input).

The #519 policy tells the model to prefer the scanned target's DECLARED
runtime (go.mod / .python-version / requires-python / engines) — but no
code ever read those manifests into the prompt: the declared branch was
dead input, reachable only via a version cue that happens to sit in the
finding text. This module derives the declarations from the repo root
and the prompt interpolates one allowlist-fenced line per language.

Security posture (the prompt's output is EXECUTED — docker build/run):
manifest content is repo-author-controlled. Every derived value must
match a strict version grammar; anything else is OMITTED entirely (never
interpolated, never raised — a raise at the derivation site would abort
the whole dynamic-test step before any finding is tested). This is
strictly TIGHTER than the existing inline surface (nine collapsed free-
text lines): the derived lines carry zero free-text capacity.
"""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Optional

# The version grammar — the ONLY thing that can ride the prompt line.
# A version string has no business carrying free text.
_VERSION_RE = re.compile(r"^\d+(\.\d+){0,2}(-[A-Za-z0-9.]+)?$")
_MAX_MANIFEST_BYTES = 65_536  # bounded read: a manifest is KB-scale, not MB


def _clean_version(raw: object) -> Optional[str]:
    """A value that matches the version grammar, or None (omit)."""
    if not isinstance(raw, str):
        return None
    v = raw.strip()
    if not v or len(v) > 32 or not _VERSION_RE.match(v):
        return None
    return v


def _read_bounded(path: Path) -> Optional[str]:
    # The fable gate: a manifest under a scanned repo is attacker-controlled
    # — a SYMLINK to /dev/zero reads unbounded (st_size 0, infinite stream)
    # and a FIFO/device wedges the step. Use the repo's own read_repo_file
    # (lstat-before-open, symlink/device refusal, bounded read — the same
    # guard every other repo-file loader uses), degraded to absent on refusal.
    from utilities.file_io import read_repo_file
    try:
        return read_repo_file(path, max_bytes=_MAX_MANIFEST_BYTES)
    except Exception:
        # read_repo_file raises UnsafeRepoFile (symlink/device/oversize — the
        # #258 guard classes); the declared channel degrades to ABSENT, never
        # raises (a raise here would abort the dynamic-test step).
        return None


def _from_go_mod(text: str) -> Optional[str]:
    # the `go` directive: 'go 1.24' (module Go version)
    m = re.search(r"(?m)^\s*go\s+(\d+(?:\.\d+){0,2})\s*$", text)
    return m.group(1) if m else None


def _from_pyproject(text: str) -> Optional[str]:
    # requires-python lower bound only: '>=3.11' (never the upper bound —
    # a '<4' ceiling is not a runtime choice the test needs)
    try:
        req = tomllib.loads(text).get("project", {}).get("requires-python", "")
    except (tomllib.TOMLDecodeError, AttributeError):
        return None
    if not isinstance(req, str):
        return None
    m = re.search(r">=\s*(\d+(?:\.\d+){0,2})", req)
    return m.group(1) if m else None


def _from_python_version(text: str) -> Optional[str]:
    # .python-version: one bare version per line
    for line in text.splitlines():
        v = line.strip()
        if v and not v.startswith("#"):
            return _clean_version(v)
    return None


def _from_package_json(text: str) -> Optional[str]:
    # engines.node lower bound: '>=20' (the node runtime declaration)
    try:
        engines = json.loads(text).get("engines", {})
    except (json.JSONDecodeError, AttributeError, RecursionError, ValueError):
        # RecursionError: deeply-nested hostile json (64KB of "[[[[") blows
        # the stdlib's parser stack — degrade to absent, never abort the step.
        return None
    node = engines.get("node") if isinstance(engines, dict) else None
    if not isinstance(node, str):
        return None
    m = re.search(r">=\s*(\d+(?:\.\d+){0,2})", node)
    return m.group(1) if m else None


def _from_tool_versions(text: str) -> dict[str, str]:
    # .tool-versions: '<tool> <version>' per line (golang 1.24 / python 3.12)
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) == 2:
            tool, ver = parts[0].lower(), _clean_version(parts[1])
            if ver:
                out[tool] = ver
    return out


def derive_declared_runtimes(repo_path: Optional[str]) -> dict[str, str]:
    """Declared runtime versions from the repo root manifests.

    Returns {language: version} with language keys 'go' / 'python' /
    'node'. Degrades to {} on anything unreadable/unparseable/non-grammar
    — NEVER raises (a raise at the call site would abort the whole
    dynamic-test step before any finding is tested).
    """
    declared: dict[str, str] = {}
    if not repo_path:
        return declared
    root = Path(repo_path)

    def _first(paths, parse):
        for rel in paths:
            text = _read_bounded(root / rel)
            if text is not None:
                v = parse(text)
                if v:
                    return v
        return None

    go = _first(("go.mod",), _from_go_mod)
    py = (_first(("pyproject.toml",), _from_pyproject)
          or _first((".python-version",), _from_python_version))
    node = _first(("package.json",), _from_package_json)

    tools = _first((".tool-versions",), _from_tool_versions) or {}
    go = go or tools.get("golang")
    py = py or tools.get("python")
    node = node or tools.get("node")

    if go:
        declared["go"] = go
    if py:
        declared["python"] = py
    if node:
        declared["node"] = node
    return declared
