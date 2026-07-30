"""Run metadata collection and rendering for Auto Patcher reports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

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


def collect_git_info(path: Path) -> str:
    """Return the short HEAD SHA for the git repo at path.

    Returns 'unknown' on any failure — missing git, non-repo path, etc.
    """
    try:
        result = run_utf8(
            ["git", "log", "-1", "--format=%h"],
            cwd=str(path),
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip() or "unknown"
    except Exception:
        pass
    return "unknown"


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
    """Render the run metadata as a Markdown table with optional warnings."""
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

    max_tokens_display = (
        str(meta.max_tokens_configured) if meta.max_tokens_configured is not None else "—"
    )

    table = f"""\
## Run Metadata

| Field | Value |
|---|---|
| Generated | {meta.timestamp} |
| Input | {meta.input_source} |
| Repository | {meta.repo_root or "—"} |
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

    return warning + table
