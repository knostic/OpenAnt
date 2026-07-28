"""Minimal repository-language detection for gating Python-only signals.

This is not a language analyzer. It is a best-effort dominant-extension
count used only to decide whether Python-tuned deterministic signals
(test discovery, impact surface, vulnerability sink scanning) are
meaningful for a given target repository — so those signals can say
"Not Applicable" instead of silently rendering an empty/clean result
that looks like a real finding.
"""

from __future__ import annotations

from pathlib import Path

_EXTENSION_LANGUAGE = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".rb": "ruby",
    ".java": "java",
    ".php": "php",
    ".cs": "csharp",
}

_IGNORED_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    "site-packages", "dist-packages", "build", "dist", ".tox",
}

NOT_APPLICABLE = "Not Applicable — language not supported by this signal yet"


def detect_language(repo_root: "Path | str | None") -> str:
    """Best-effort dominant source language under repo_root, by extension count.

    Returns "unknown" when repo_root is missing, doesn't exist, or contains
    no recognized source extensions. Never raises.
    """
    if not repo_root:
        return "unknown"
    root = Path(repo_root)
    if not root.exists():
        return "unknown"

    counts: dict[str, int] = {}
    try:
        for p in root.rglob("*"):
            if p.is_dir():
                continue
            if any(part in _IGNORED_DIRS for part in p.parts):
                continue
            lang = _EXTENSION_LANGUAGE.get(p.suffix.lower())
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    except Exception:
        return "unknown"

    if not counts:
        return "unknown"
    return max(counts, key=counts.get)


def is_python_repo(repo_root: "Path | str | None") -> bool:
    """True only when Python is confidently the dominant detected language."""
    return detect_language(repo_root) == "python"
