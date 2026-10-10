"""Run metadata collection and rendering for Auto Patcher reports."""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from utilities.autopatcher.patch_applicability import (
    _empty_git_dir, _isolated_git_env, _line_ending_settings, _set_config,
)
from utilities.file_io import run_utf8


@dataclass
class RunMetadata:
    timestamp: str      # "2026-06-16 18:35:42 UTC"
    input_source: str   # "GHSA-v845-jxx5-vc9f" or "examples/vulnerability.md"
    repo_root: str      # "/tmp/urllib3-eval" or ""
    repo_commit: str    # short SHA or "unknown"
    llm_provider: str   # "anthropic" | "openai" | "mock" | "unknown"
    llm_model: str      # resolved model id (see utilities.model_config) | "mock" | "unknown"
    llm_mode: str       # "LIVE" | "MOCK"
    output_path: str    # final resolved output path
    patcher_commit: str # short SHA of auto-patcher project
    max_tokens_configured: Optional[int] = None   # resolved LLM_MAX_TOKENS for this run
    stage_stop_reasons: Optional[dict] = None     # {"patch_generation": "end_turn", ...}
    # input_type/advisory_id/advisory_source: additive fields distinguishing a
    # CVE-seeded run from an OpenAnt-Finding-seeded one. Default "finding"
    # renders no extra content in render_metadata_section -- existing
    # Finding-mode call sites that don't pass these keep byte-identical
    # output.
    input_type: str = "finding"                   # "finding" | "cve"
    advisory_id: Optional[str] = None             # e.g. "CVE-2022-25883"
    advisory_source: Optional[str] = None         # e.g. "NVD"


def collect_git_info(path: Path) -> str:
    """Return the short HEAD SHA for the git repo at path.

    Returns 'unknown' on any failure — missing git, non-repo path, etc.
    ``rev-parse`` reads the SHA without ``git log``'s formatting machinery,
    which honours repository settings that run commands (``log.showSignature``
    makes it run ``gpg.program``; PR #763 HUNT B-1); see ``_isolated_git``.
    """
    try:
        result = _isolated_git(path, "rev-parse", "--short", "HEAD")
        if result.returncode == 0:
            return result.stdout.strip() or "unknown"
    except Exception:
        pass
    return "unknown"


def find_openant_root() -> "Path | None":
    """Walk up from this file to the OpenAnt repo root (contains
    libs/openant-core). Returns None if not found (e.g. installed as a
    wheel outside a git checkout) -- collect_git_info/collect_full_commit_sha
    already degrade gracefully in that case.

    Shared by core.patch (the Trust Report's ``patcher_commit`` row) and by
    trace/replay tooling (utilities.autopatcher.tools.run_traced,
    utilities.autopatcher.stage_replay) so there is exactly one "find the
    OpenAnt checkout root" implementation, walked from wherever this
    module itself lives -- any file inside libs/openant-core resolves to
    the same root.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "libs" / "openant-core").is_dir():
            return parent
    return None


def collect_full_commit_sha(path: Path) -> "str | None":
    """Return the FULL (40-char) HEAD SHA for the git repo at ``path``, or
    None on any failure (missing git, non-repo path, unborn HEAD, ...).

    Distinct from ``collect_git_info``'s short SHA, which exists purely
    for human-readable report display: replay provenance (see
    ``utilities.autopatcher.stage_replay``) needs the unambiguous full SHA
    for an exact-match identity check, not a short, potentially-ambiguous
    prefix. Returns ``None`` rather than the sentinel string ``"unknown"``
    -- structured/JSON provenance fields use ``None``/``null`` for "could
    not determine," never a string that could be mistaken for a real
    (if oddly-named) commit-ish.
    """
    try:
        result = _isolated_git(path, "rev-parse", "HEAD")
        if result.returncode == 0:
            sha = result.stdout.strip()
            return sha or None
    except Exception:
        pass
    return None


def is_worktree_clean(path: Path) -> "bool | None":
    """Return True if the git repo at ``path`` has no uncommitted changes
    (tracked or untracked), False if it does, or None if this could not be
    determined (missing git, non-repo path, ...).

    Used by single-stage replay's target-repository safety gate
    (``stage_replay.validate_target_repository``), by ``run_traced`` to
    record whether the analyzed tree was clean, and by replay provenance
    to note whether the OpenAnt checkout itself is dirty -- never by report
    rendering.

    The analyzed repository's own configuration is never read (PR #763
    HUNT B-1/B-5): ``git status`` runs against a fresh repository directory
    holding only a copy of the index, the HEAD commit (its objects reached
    through ``alternates``) and ``info/exclude``, with no configuration but
    the line-ending policy and ``core.filemode``. So nothing the repository configures can run
    (``core.fsmonitor``, filter drivers) or hide untracked files
    (``status.showUntrackedFiles``), and the repository's ``.git/index`` is
    never refreshed or written. A filter-converted file whose raw content
    differs from the index reads as changed (fails toward "dirty").
    Submodule contents are not inspected (``--ignore-submodules=dirty``),
    since that would run git inside each submodule with its own
    configuration; a submodule moved to another commit still counts.
    """
    try:
        paths = _isolated_git(
            path, "rev-parse", "--path-format=absolute",
            "--git-path", "objects", "--git-path", "index", "--git-path", "info/exclude",
        )
        if paths.returncode != 0:
            return None
        objects, index, exclude = (Path(p) for p in paths.stdout.splitlines()[:3])
        head = _isolated_git(path, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
        with tempfile.TemporaryDirectory(prefix="openant-git-") as scratch:
            git_dir = _empty_git_dir(Path(scratch) / "status.git")
            (git_dir / "objects" / "info").mkdir()
            # Bytes, not text mode: on Windows text mode writes "\r\n", and git
            # reads the "\r" as part of the alternate's path ("objects\r does
            # not exist"), so status fails and cleanliness reads as unknown.
            (git_dir / "objects" / "info" / "alternates").write_bytes(f"{objects}\n".encode("utf-8"))
            if head.returncode == 0 and head.stdout.strip():
                (git_dir / "HEAD").write_bytes((head.stdout.strip() + "\n").encode("utf-8"))
            if index.is_file():
                shutil.copyfile(index, git_dir / "index")
            if exclude.is_file():
                (git_dir / "info").mkdir()
                shutil.copyfile(exclude, git_dir / "info" / "exclude")
            env = _isolated_git_env(Path(scratch))
            env.update({"GIT_DIR": str(git_dir), "GIT_WORK_TREE": str(path)})
            _set_config(env, _line_ending_settings(Path(path)) + _filemode_setting(path) + _user_excludes())
            result = run_utf8(
                ["git", "-c", "core.fsmonitor=false", "--no-optional-locks", "status", "--porcelain",
                 "--untracked-files=all", "--ignore-submodules=dirty"],
                cwd=str(path), env=env, capture_output=True, text=True, timeout=30,
            )
        if result.returncode == 0:
            return result.stdout.strip() == ""
    except Exception:
        pass
    return None


def _isolated_git(path: Path, *args: str):
    """Run a read-only ``git`` metadata command in the repository at `path`
    with no inherited ``GIT_*`` environment and no system or global
    configuration (``patch_applicability._isolated_git_env``) and with
    ``core.fsmonitor`` off. ``rev-parse`` runs no filter, hook, signature
    program or other configured command."""
    with tempfile.TemporaryDirectory(prefix="openant-git-") as scratch:
        return run_utf8(
            ["git", "-c", "core.fsmonitor=false", *args],
            cwd=str(path), env=_isolated_git_env(Path(scratch)), capture_output=True, text=True, timeout=5,
        )


def _filemode_setting(path: Path) -> "list[tuple[str, str]]":
    """The checkout's ``core.filemode`` (``false`` where the filesystem cannot
    record the executable bit, the Git for Windows default), carried into the
    isolated status so a lost executable bit is not read as a change. A
    boolean read with ``--type=bool``, never a command."""
    found = _isolated_git(path, "config", "--type=bool", "--get", "core.filemode")
    value = found.stdout.strip().lower() if found.returncode == 0 else ""
    return [("core.filemode", value)] if value in ("true", "false") else []


def _user_excludes() -> "list[tuple[str, str]]":
    """The invoking user's own global ignore file, carried into the isolated
    status as plain ignore patterns (the isolated run reads no global
    configuration, so files the user ignores everywhere -- ``.DS_Store``,
    say -- would otherwise read as untracked). The analyzed repository's
    own ``core.excludesFile`` setting is deliberately not carried: it could
    hide files from the cleanliness check."""
    try:
        found = run_utf8(
            ["git", "config", "--global", "--path", "--get", "core.excludesFile"],
            cwd=tempfile.gettempdir(), capture_output=True, text=True, timeout=5,
        )
        configured = found.stdout.strip() if found.returncode == 0 else ""
    except Exception:
        configured = ""
    if configured:
        candidate = Path(configured).expanduser()
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        candidate = Path(base) / "git" / "ignore"
    return [("core.excludesFile", str(candidate))] if candidate.is_file() else []


def auto_output_path(
    timestamp: datetime,
    ghsa_id: Optional[str],
    vuln_file: Optional[str],
    repo_root: Optional[str],
) -> str:
    """Generate a timestamped output path under reports/.

    Format:
      GHSA mode : reports/YYYYMMDD-HHMMSS-{repo_slug}-{ghsa_slug}.md
      File mode : reports/YYYYMMDD-HHMMSS-{file_stem}.md
      Fallback  : reports/YYYYMMDD-HHMMSS-report.md
    """
    ts = timestamp.strftime("%Y%m%d-%H%M%S")

    repo_slug = Path(repo_root).name.lower() if repo_root else ""

    if ghsa_id:
        id_slug = ghsa_id.lower()
        parts = [p for p in [ts, repo_slug, id_slug] if p]
        filename = "-".join(parts) + ".md"
    elif vuln_file:
        file_slug = Path(vuln_file).stem.lower()
        parts = [p for p in [ts, repo_slug, file_slug] if p]
        filename = "-".join(parts) + ".md"
    else:
        filename = f"{ts}-report.md"

    return f"reports/{filename}"


_STAGE_LABELS = [
    ("patch_generation", "Patch generation"),
    ("patch_review", "Patch review"),
    ("challenger", "Challenger"),
    ("confidence_scorer", "Confidence scorer"),
]

# Provider-specific stop-reason strings that indicate the output was cut off
# by the token limit rather than ending naturally (Anthropic: "max_tokens",
# OpenAI: "length").
_TRUNCATION_STOP_REASONS = {"max_tokens", "length"}


def render_metadata_section(meta: RunMetadata) -> str:
    """Render the run metadata as a Markdown table with optional warnings.

    When meta.input_type == "cve", an additional disclosure block and table
    row make the report's provenance explicit: the input was a public
    advisory, not an OpenAnt Finding, and advisory claims (description, CWE,
    CVSS, affected products) are not equivalent to repository verification.
    The Recommendation/Trust Signals a caller renders alongside this section
    are computed upstream from evidence this pipeline run actually collected
    against the given repository -- this function does not compute or alter
    them, only states in the report that advisory metadata is not a
    substitute for that evidence. For meta.input_type == "finding" (the
    default), nothing here changes: this whole block renders as "".
    """
    warning = ""
    if meta.llm_mode == "MOCK":
        warning = (
            "> ⚠️ **MOCK MODE** — This report was generated with mock LLM responses "
            "and must not be used as benchmark evidence.\n\n"
        )

    stage_reasons = meta.stage_stop_reasons or {}
    any_truncated = any(
        (reason or "").lower() in _TRUNCATION_STOP_REASONS for reason in stage_reasons.values()
    )
    if any_truncated:
        warning += (
            "> ⚠️ **TRUNCATED OUTPUT DETECTED** — one or more pipeline stages hit "
            "the configured token limit (see Stage Stop Reasons below). Do not "
            "treat completeness-related findings in this report as conclusive.\n\n"
        )

    disclosure = ""
    if meta.input_type == "cve":
        advisory_label = meta.advisory_id or "unknown"
        source_label = meta.advisory_source or "an unspecified source"
        disclosure = (
            f"> ℹ️ **Input Source: CVE ({advisory_label})** — this run was seeded from a "
            f"public advisory ({source_label}), not an OpenAnt-detected Finding. Advisory "
            "claims (description, CWE, CVSS, affected products) are contextual evidence "
            "only and have not been verified against this repository's actual code or "
            "dependency versions. This report's outcome — and its Recommendation and Trust "
            "Signals, when present — is based only on the evidence this pipeline run actually "
            "collected against the given repository, not on the advisory's own severity or "
            "CVSS score.\n\n"
        )

    max_tokens_display = (
        str(meta.max_tokens_configured) if meta.max_tokens_configured is not None else "—"
    )

    input_type_row = (
        f"| Input type | CVE ({meta.advisory_id or 'unknown'}, "
        f"{meta.advisory_source or 'unknown source'}) |\n"
        if meta.input_type == "cve"
        else ""
    )

    table = f"""\
## Run Metadata

| Field | Value |
|---|---|
| Generated | {meta.timestamp} |
| Input | {meta.input_source} |
""" + input_type_row + f"""| Repository | {meta.repo_root or "—"} |
| Repo commit | {meta.repo_commit} |
| LLM provider | {meta.llm_provider} |
| LLM model | {meta.llm_model} |
| LLM mode | {meta.llm_mode} |
| Max output tokens | {max_tokens_display} |
| Output | {meta.output_path} |
| Auto-patcher | {meta.patcher_commit} |
"""

    if stage_reasons:
        stage_table = "\n### Stage Stop Reasons\n\n| Stage | Stop reason |\n|---|---|\n"
        for key, label in _STAGE_LABELS:
            reason = stage_reasons.get(key)
            if reason is None:
                display = "—"
            elif reason.lower() in _TRUNCATION_STOP_REASONS:
                display = f"⚠️ {reason}"
            else:
                display = reason
            stage_table += f"| {label} | {display} |\n"
        table += stage_table

    return warning + disclosure + table
