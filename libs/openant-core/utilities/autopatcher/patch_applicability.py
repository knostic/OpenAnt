"""Deterministic patch applicability check using git apply --check.

Feeds the raw unified diff to `git apply --check` via stdin against the
target repository. Never modifies the working tree — --check is read-only.

Result dict schema:
  applicable    : bool | None  — True/False, or None when skipped/error
  skipped       : bool         — True when the check cannot run
  skipped_reason: str | None   — human-readable skip reason
  error         : str | None   — set on unexpected errors including timeout
  exit_code     : int | None   — git's return code (None when not run)
  stderr        : str          — git stderr, truncated to 20 lines / 2000 chars
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from utilities.file_io import run_utf8

_MAX_STDERR_LINES = 20
_MAX_STDERR_CHARS = 2_000
_TIMEOUT_SECONDS = 10


def _strip_fences(patch: str) -> str:
    """Remove Markdown fences while preserving the patch body byte-for-byte.

    This preserves trailing whitespace and context lines required by unified
    diffs. Mirrors the technique used by diff_hunk_repair._strip_md_fences.
    """
    lines = patch.splitlines(keepends=True)
    if lines and re.match(r"^```", lines[0]):
        lines = lines[1:]
    if lines and lines[-1].strip() in ("```", "~~~"):
        lines = lines[:-1]
    return "".join(lines)


def _truncate_stderr(stderr: str) -> str:
    """Limit stderr to 20 lines and 2000 chars."""
    lines = stderr.splitlines()
    if len(lines) > _MAX_STDERR_LINES:
        dropped = len(lines) - _MAX_STDERR_LINES
        lines = lines[:_MAX_STDERR_LINES] + [f"[… {dropped} more line(s) truncated]"]
    result = "\n".join(lines)
    if len(result) > _MAX_STDERR_CHARS:
        result = result[:_MAX_STDERR_CHARS] + "\n[… truncated]"
    return result


def check_applicability(patch: str, repo_root: "Path | str | None") -> dict:
    """Check whether the patch applies cleanly to repo_root.

    Uses ``git apply --check -`` (stdin). Never modifies the working tree.

    Returns a result dict with keys:
      applicable, skipped, skipped_reason, error, exit_code, stderr.
    """
    # --- Pre-flight: skip conditions ---
    if not repo_root:
        return {
            "applicable": None, "skipped": True,
            "skipped_reason": "no repo_root provided",
            "error": None, "exit_code": None, "stderr": "",
        }

    repo_root = Path(repo_root)
    if not (repo_root / ".git").exists():
        return {
            "applicable": None, "skipped": True,
            "skipped_reason": "not a git repository",
            "error": None, "exit_code": None, "stderr": "",
        }

    raw_diff = _strip_fences(patch)
    if not raw_diff.strip():
        return {
            "applicable": None, "skipped": True,
            "skipped_reason": "empty diff after stripping fences",
            "error": None, "exit_code": None, "stderr": "",
        }

    # --- Run git apply --check ---
    try:
        result = run_utf8(
            ["git", "apply", "--check", "--whitespace=nowarn", "-"],
            input=raw_diff if raw_diff.endswith("\n") else raw_diff + "\n",
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
        return {
            "applicable": result.returncode == 0,
            "skipped": False,
            "skipped_reason": None,
            "error": None,
            "exit_code": result.returncode,
            "stderr": _truncate_stderr(result.stderr),
        }

    except FileNotFoundError:
        return {
            "applicable": None, "skipped": True,
            "skipped_reason": "git executable not found",
            "error": None, "exit_code": None, "stderr": "",
        }

    except subprocess.TimeoutExpired:
        return {
            "applicable": None, "skipped": False,
            "skipped_reason": None,
            "error": f"git apply --check timed out after {_TIMEOUT_SECONDS}s",
            "exit_code": None, "stderr": "",
        }

    except Exception as exc:  # noqa: BLE001
        return {
            "applicable": None, "skipped": False,
            "skipped_reason": None,
            "error": str(exc),
            "exit_code": None, "stderr": "",
        }
