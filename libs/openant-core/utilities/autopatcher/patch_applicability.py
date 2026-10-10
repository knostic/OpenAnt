"""Deterministic patch applicability check and application, via git apply.

``check_applicability`` feeds the raw unified diff to `git apply --check`
via stdin against the target repository. Never modifies the working tree
— --check is read-only. Returns a plain dict (established, existing API —
not migrated by this module's later addition of a typed result type).

Both run git with a configuration the analyzed repository does not control
(``_isolated_git_env``): its ``.git/config`` can define filter drivers --
shell commands git runs when it reads (clean) or writes (smudge) a file --
and nothing from an analyzed repository may execute (PR #763 HUNT U1).

``apply_patch`` runs the same diff through `git apply` (no --check) and
DOES mutate the working tree — callers must pass a disposable workspace,
e.g. from ``utilities.autopatcher.patch_workspace.temporary_repo_copy``,
never a repository they care about. Returns ``PatchApplicationResult``.

check_applicability result dict schema:
  applicable    : bool | None  — True/False, or None when skipped/error
  skipped       : bool         — True when the check cannot run
  skipped_reason: str | None   — human-readable skip reason
  error         : str | None   — set on unexpected errors including timeout
  exit_code     : int | None   — git's return code (None when not run)
  stderr        : str          — git stderr, truncated to 20 lines / 2000 chars
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
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
    if lines and lines[-1].rstrip() in ("```", "~~~"):
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


def _isolated_git_env(scratch: Path) -> "dict[str, str]":
    """An environment in which git reads no configuration the analyzed
    repository (or the inherited environment) controls: every inherited
    ``GIT_*`` variable is dropped (``GIT_CONFIG_PARAMETERS``,
    ``GIT_CONFIG_COUNT``/``_KEY_n``/``_VALUE_n``, ``GIT_DIR``, ...), system
    and global configuration and system attributes are off, and the global
    configuration is an empty file. The caller then points ``GIT_DIR`` at a
    fresh, empty repository, so the analyzed repository's ``.git/config``
    and ``.git/info/attributes`` are never read. An in-tree
    ``.gitattributes`` can still name a filter driver, but no configuration
    defines one, so git passes the content through unchanged."""
    empty_config = scratch / "empty.gitconfig"
    empty_config.write_bytes(b"")
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": str(empty_config),
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


_LINE_ENDING_SETTINGS = {
    "core.autocrlf": {"true", "false", "input"},
    "core.eol": {"lf", "crlf", "native"},
}
"""The only configuration carried from the analyzed repository into the
isolated run: git's built-in line-ending policy (a closed vocabulary, never
a command). Without it a canonical LF patch would stop matching a CRLF
checkout (``core.autocrlf=true``, the Git for Windows system default)."""


def _line_ending_settings(repo: Path) -> "list[tuple[str, str]]":
    """The analyzed checkout's effective line-ending settings, each value
    checked against git's own vocabulary. ``git config --get`` only reads
    configuration; it runs no filter, hook or other configured command.
    A ``core.autocrlf`` value outside the canonical spellings (``yes``,
    ``on``, ``1``, an empty value, a bare key ...) is read as git itself
    reads it, through ``git config --type=bool`` (PR #763 HUNT B-4)."""
    settings = []
    for key, allowed in _LINE_ENDING_SETTINGS.items():
        value = _git_config_value(repo, key)
        if key == "core.autocrlf" and value is not None and value not in allowed:
            value = _git_config_value(repo, key, "--type=bool")
        if value in allowed:
            settings.append((key, value))
    return settings


def _git_config_value(repo: Path, key: str, *options: str) -> "str | None":
    """``git config [options] --get key`` in `repo`, lower-cased, or None when
    unset, invalid for `options`, or git cannot run."""
    try:
        found = subprocess.run(
            ["git", "config", *options, "--get", key], cwd=str(repo), capture_output=True, timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if found.returncode != 0:
        return None
    return found.stdout.decode("utf-8", errors="replace").strip().lower()


def _set_config(env: "dict[str, str]", settings: "list[tuple[str, str]]") -> None:
    """Pass `settings` to git through ``GIT_CONFIG_COUNT``/``_KEY_n``/``_VALUE_n``
    (the only configuration an isolated run reads besides its own empty
    files)."""
    env["GIT_CONFIG_COUNT"] = str(len(settings))
    for i, (key, value) in enumerate(settings):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = key, value


def _empty_git_dir(path: Path) -> Path:
    """A minimal empty repository directory (what ``git init`` writes, minus
    hooks and templates): an unborn ``HEAD``, empty ``objects``/``refs`` and
    an empty ``config``. Written directly, so no command runs to create it."""
    for sub in ("objects", "refs/heads", "refs/tags"):
        (path / sub).mkdir(parents=True)
    (path / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (path / "config").write_bytes(b"")
    return path


def _run_git_apply(extra_args: "list[str]", raw_diff: str, cwd: Path) -> "tuple[int, str]":
    """Run ``git apply [extra_args] --whitespace=nowarn -`` with the diff on stdin.

    The diff is sent as strict UTF-8 bytes, never via text-mode stdin:
    text mode on Windows rewrites ``\\n`` as ``\\r\\n``, which turns a bare
    blank context line into ``\\r`` ("corrupt patch"). Line-ending matching
    against the working tree is left to git's own autocrlf/attributes.
    Strict encoding: an unencodable diff raises (caller fails closed)
    rather than being silently altered. Returns (returncode, stderr).

    Git runs in ``_isolated_git_env`` against a fresh, empty repository
    (``GIT_DIR``, see ``_empty_git_dir``) with ``cwd`` as its work tree,
    never with the analyzed repository's own ``.git``; only its line-ending
    policy is carried over (``_line_ending_settings``). If that environment
    cannot be created this raises; callers report an error -- the check is
    never skipped.
    """
    payload = (raw_diff if raw_diff.endswith("\n") else raw_diff + "\n").encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="openant-git-") as scratch:
        env = _isolated_git_env(Path(scratch))
        env["GIT_DIR"] = str(_empty_git_dir(Path(scratch) / "isolated.git"))
        env["GIT_WORK_TREE"] = str(cwd)
        _set_config(env, _line_ending_settings(cwd))
        result = run_utf8(
            ["git", "apply", *extra_args, "--whitespace=nowarn", "-"],
            input=payload,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            timeout=_TIMEOUT_SECONDS,
        )
    return result.returncode, result.stderr.decode("utf-8", errors="replace")


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
        returncode, stderr = _run_git_apply(["--check"], raw_diff, repo_root)
        return {
            "applicable": returncode == 0,
            "skipped": False,
            "skipped_reason": None,
            "error": None,
            "exit_code": returncode,
            "stderr": _truncate_stderr(stderr),
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


@dataclass(frozen=True)
class PatchApplicationResult:
    """Result of a mutating ``git apply`` attempt against a workspace.

    ``error_kind`` is a closed, small set of reasons — set only where the
    code path already knows unambiguously what happened (which branch ran),
    never inferred after the fact by parsing ``error``/``stderr`` text:
      invalid_input      — no workspace_root, or an empty/fence-only diff
      not_git_repository — workspace_root has no .git
      git_not_found      — the git executable isn't available
      timeout            — git apply exceeded _TIMEOUT_SECONDS
      apply_rejected     — git ran and returned a nonzero exit code
      unexpected_error   — any other exception
    ``error_kind`` is ``None`` exactly when ``applied`` is ``True``.
    """
    applied: bool
    exit_code: "int | None"
    error: "str | None"
    error_kind: "str | None" = None
    stderr: str = ""


def apply_patch(patch: str, workspace_root: "Path | str | None") -> PatchApplicationResult:
    """Apply a unified diff to workspace_root via ``git apply``.

    Unlike ``check_applicability``, this MUTATES the working tree at
    ``workspace_root``. Callers MUST pass a disposable copy — e.g. from
    ``utilities.autopatcher.patch_workspace.temporary_repo_copy`` — never a
    repository the caller cares about preserving.
    """
    if not workspace_root:
        return PatchApplicationResult(
            applied=False, exit_code=None,
            error="no workspace_root provided", error_kind="invalid_input",
        )

    workspace_root = Path(workspace_root)
    if not (workspace_root / ".git").exists():
        return PatchApplicationResult(
            applied=False, exit_code=None,
            error="not a git repository", error_kind="not_git_repository",
        )

    raw_diff = _strip_fences(patch)
    if not raw_diff.strip():
        return PatchApplicationResult(
            applied=False, exit_code=None,
            error="empty diff after stripping fences", error_kind="invalid_input",
        )

    try:
        returncode, stderr = _run_git_apply([], raw_diff, workspace_root)
        applied = returncode == 0
        return PatchApplicationResult(
            applied=applied,
            exit_code=returncode,
            error=None,
            error_kind=None if applied else "apply_rejected",
            stderr=_truncate_stderr(stderr),
        )

    except FileNotFoundError:
        return PatchApplicationResult(
            applied=False, exit_code=None,
            error="git executable not found", error_kind="git_not_found",
        )

    except subprocess.TimeoutExpired:
        return PatchApplicationResult(
            applied=False, exit_code=None,
            error=f"git apply timed out after {_TIMEOUT_SECONDS}s", error_kind="timeout",
        )

    except Exception as exc:  # noqa: BLE001
        return PatchApplicationResult(
            applied=False, exit_code=None,
            error=str(exc), error_kind="unexpected_error",
        )
