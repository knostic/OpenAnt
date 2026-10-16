"""Minimal deterministic behavior summary analyzer.

Produces a tiny BehaviorReport dict with a single function (or file fallback),
one-line summary, and 2-4 primary behaviors to validate.
"""
from __future__ import annotations

import re
from typing import List


def _pick_purpose_and_behaviors(name_tokens: List[str], path_tokens: List[str]):
    tokens = set(t.lower() for t in name_tokens + path_tokens)

    # Simple deterministic mapping. `is_generic` is True only for the final
    # fallback branch (no keyword matched anything about the changed
    # function/file) — exposed explicitly so callers can suppress
    # boilerplate content derived only from this fallback (e.g. the
    # "Validate behavior: normal flow, edge-case handling" Validation
    # Action and its matching Suggested Tests) without fuzzy text matching
    # on "application logic" / "normal flow" / "edge-case handling".
    if any(t in tokens for t in ("auth", "authenticate", "login", "logout")):
        purpose = "authentication"
        behaviors = ["valid login", "invalid login", "malformed/injection-style input"]
        is_generic = False
    elif any(t in tokens for t in ("validate", "sanitize", "clean", "normalize")):
        purpose = "input validation"
        behaviors = ["valid input acceptance", "invalid/malformed input rejection"]
        is_generic = False
    elif any(t in tokens for t in ("db", "query", "execute", "insert", "update", "delete", "cursor")):
        purpose = "database operations"
        behaviors = ["query correctness", "parameterization vs raw queries"]
        is_generic = False
    elif any(t in tokens for t in ("api", "request", "handler", "route", "view")):
        purpose = "request/handler logic"
        behaviors = ["happy-path response", "error handling paths"]
        is_generic = False
    else:
        purpose = "application logic"
        behaviors = ["normal flow", "edge-case handling"]
        is_generic = True

    # Limit to 4
    return purpose, behaviors[:4], is_generic


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

        purpose, behaviors, is_generic = _pick_purpose_and_behaviors(name_tokens, path_tokens)

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
            # True only when no purpose keyword matched (see
            # _pick_purpose_and_behaviors) -- callers use this to suppress
            # boilerplate content derived only from the generic fallback.
            "is_generic": is_generic,
        }
