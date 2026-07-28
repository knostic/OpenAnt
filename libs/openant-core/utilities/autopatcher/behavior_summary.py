"""Minimal deterministic behavior summary analyzer.

Produces a tiny BehaviorReport dict with a single function (or file fallback),
one-line summary, and 2-4 primary behaviors to validate.
"""
from __future__ import annotations

import re
from typing import List


def _pick_purpose_and_behaviors(name_tokens: List[str], path_tokens: List[str]):
    tokens = set(t.lower() for t in name_tokens + path_tokens)

    # Simple deterministic mapping
    if any(t in tokens for t in ("auth", "authenticate", "login", "logout")):
        purpose = "authentication"
        behaviors = ["valid login", "invalid login", "malformed/injection-style input"]
    elif any(t in tokens for t in ("validate", "sanitize", "clean", "normalize")):
        purpose = "input validation"
        behaviors = ["valid input acceptance", "invalid/malformed input rejection"]
    elif any(t in tokens for t in ("db", "query", "execute", "insert", "update", "delete", "cursor")):
        purpose = "database operations"
        behaviors = ["query correctness", "parameterization vs raw queries"]
    elif any(t in tokens for t in ("api", "request", "handler", "route", "view")):
        purpose = "request/handler logic"
        behaviors = ["happy-path response", "error handling paths"]
    else:
        purpose = "application logic"
        behaviors = ["normal flow", "edge-case handling"]

    # Limit to 4
    return purpose, behaviors[:4]


class BehaviorAnalyzer:
    """Very small deterministic analyzer for Behavior Summary.

    analyze(patch_diff, repo_context=None) -> dict
    """

    # Accept diff markers like '+' at line start (e.g. '+def foo(')
    FUNC_RE = re.compile(r"^[\+\-\s]*def\s+([A-Za-z0-9_]+)\s*\(")

    def analyze(self, patch_diff: str, repo_context=None) -> dict:
        # 1) find first changed file
        file_path = "unknown"
        for line in patch_diff.splitlines():
            if line.startswith("+++ b/"):
                file_path = line[6:].strip()
                break

        # 2) find first function definition in diff hunks
        func_name = ""
        for line in patch_diff.splitlines():
            m = self.FUNC_RE.match(line)
            if m:
                func_name = m.group(1)
                break

        # derive tokens
        name_tokens = func_name.replace("_", " ").split() if func_name else []
        path_tokens = [p for p in re.split(r"[/_.\\]+", file_path) if p]

        purpose, behaviors = _pick_purpose_and_behaviors(name_tokens, path_tokens)

        if func_name:
            summary = f"This patch likely affects {purpose} in {file_path}."
        else:
            summary = f"This patch likely affects {purpose} in {file_path}."

        # limit behaviors to 2-4 deterministic choices
        primary_behaviors = behaviors[:4]

        return {
            "function": func_name,
            "file": file_path,
            "summary": summary,
            "primary_behaviors": primary_behaviors,
        }
