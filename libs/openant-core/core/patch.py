"""
Patch-trust wrapper.

Loads a Finding from pipeline_output.json, checks it is eligible for
remediation, renders it into a vulnerability description, and runs it
through the merged Auto Patcher engine (``utilities.autopatcher``) to
produce a Trust Report. Mirrors core/dynamic_tester.py's shape: a thin
wrapper around a heavier ``utilities.*`` engine.

The Trust Report is treated as an opaque artifact: this module never parses
its Recommendation or Trust Signals, only the path it was written to.
"""

import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from core.verdict_taxonomy import PATCH_ELIGIBLE
from utilities.file_io import read_json, normalize_results


@dataclass
class PatchStepResult:
    """Result of `openant patch`."""
    finding_id: str
    vulnerability_path: str
    trust_report_path: str

    def to_dict(self) -> dict:
        return asdict(self)


def find_finding_by_id(findings: list, finding_id: str) -> dict:
    """Return the finding dict with the given id, or raise ValueError."""
    for f in findings:
        if isinstance(f, dict) and f.get("id") == finding_id:
            return f
    raise ValueError(f"no finding with id {finding_id!r} in pipeline_output.json")


def effective_verdict(finding: dict) -> str:
    """The verdict that governs eligibility: stage2_verdict if set, else stage1_verdict."""
    return finding.get("stage2_verdict") or finding.get("stage1_verdict") or ""


def check_eligible(finding: dict) -> None:
    """Raise ValueError if finding's effective verdict is not patch-eligible.

    Deliberately an explicit allowlist (PATCH_ELIGIBLE), not a denylist, so
    an empty, unknown, or future verdict value fails closed.
    """
    verdict = effective_verdict(finding)
    if verdict not in PATCH_ELIGIBLE:
        raise ValueError(
            f"finding {finding.get('id')} has verdict {verdict!r}, which is not "
            f"eligible for remediation (eligible: {', '.join(sorted(PATCH_ELIGIBLE))})"
        )


def render_vulnerability_markdown(finding: dict) -> str:
    """Render a Finding into deterministic Markdown for the patch engine's input.

    suggested_fix and rejection_reason are never read here: feeding OpenAnt's
    own suggested fix into the patch engine could bias its independently
    generated candidate patch.
    """
    location = finding.get("location") or {}
    lines = [
        f"# {finding.get('name', '')}",
        "",
        "## Vulnerability description",
        "",
        f"- **Finding ID:** {finding.get('id', '')}",
        f"- **CWE:** CWE-{finding.get('cwe_id', '')} ({finding.get('cwe_name', '')})",
        f"- **Location:** {location.get('file', '')} ({location.get('function', '')})",
        f"- **Verdict:** {effective_verdict(finding)}",
    ]

    description = finding.get("description")
    if description:
        lines += ["", description]

    vulnerable_code = finding.get("vulnerable_code")
    if vulnerable_code:
        lines += ["", "## Vulnerable code", "", "```", vulnerable_code, "```"]

    impact = finding.get("impact") or []
    if impact:
        lines += ["", "## Impact", ""]
        lines += [f"- {item}" for item in impact]

    steps = finding.get("steps_to_reproduce") or []
    if steps:
        lines += ["", "## Attack scenario", ""]
        lines += [f"{i + 1}. {step}" for i, step in enumerate(steps)]

    return "\n".join(lines) + "\n"


def _find_openant_root() -> Path | None:
    """Walk up from this file to the OpenAnt repo root (contains libs/openant-core),
    for the Run Metadata report's commit row. Returns None if not found (e.g.
    installed as a wheel outside a git checkout) -- collect_git_info already
    degrades to 'unknown' in that case."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "libs" / "openant-core").is_dir():
            return parent
    return None


def run_patch(
    pipeline_output_path: str,
    finding_id: str,
    output_dir: str,
    repo_root: str | None = None,
) -> PatchStepResult:
    """Generate and evaluate a candidate remediation for one finding.

    Requires LLM_PROVIDER to be set explicitly in the environment: Auto
    Patcher's engine silently falls back to a deterministic mock LLM when
    LLM_PROVIDER is unset and stdin is non-interactive (always true when
    invoked from OpenAnt's Go CLI). An OpenAnt-triggered run must never
    silently produce a mock Trust Report that looks real -- LLM_PROVIDER=mock
    is allowed, it just must have been explicitly chosen.

    Writes two artifacts under ``{output_dir}/patch/``:
        {finding_id}-vulnerability.md  -- the rendered input (for transparency)
        {finding_id}-trust-report.md   -- the engine's opaque Trust Report

    Raises:
        RuntimeError: if LLM_PROVIDER is unset.
        FileNotFoundError: if pipeline_output_path doesn't exist.
        ValueError: if finding_id is unknown or ineligible.
    """
    if not os.environ.get("LLM_PROVIDER"):
        raise RuntimeError(
            "LLM_PROVIDER is not set. The patch engine requires an explicit "
            "provider (e.g. LLM_PROVIDER=anthropic) so a run triggered by "
            "OpenAnt never silently falls back to mock mode. Set "
            "LLM_PROVIDER=mock only if you intentionally want a mock run."
        )

    if not os.path.exists(pipeline_output_path):
        raise FileNotFoundError(f"pipeline_output.json not found: {pipeline_output_path}")

    pipeline_data = read_json(pipeline_output_path)
    if "findings" in pipeline_data:
        normalize_results(pipeline_data, "findings")
    findings = pipeline_data.get("findings", [])

    finding = find_finding_by_id(findings, finding_id)
    check_eligible(finding)

    patch_dir = os.path.join(output_dir, "patch")
    os.makedirs(patch_dir, exist_ok=True)

    vulnerability_text = render_vulnerability_markdown(finding)
    vulnerability_path = os.path.join(patch_dir, f"{finding_id}-vulnerability.md")
    with open(vulnerability_path, "w", encoding="utf-8") as f:
        f.write(vulnerability_text)

    from utilities.autopatcher import llm_client as _llm
    from utilities.autopatcher import run_metadata as _rm
    from utilities.autopatcher.pipeline import run as _run_pipeline

    # Reset per-run LLM call metadata -- module-level state that would
    # otherwise leak a stale stage entry from a prior run in this process.
    _llm.clear_call_metadata()

    timestamp = datetime.now(timezone.utc)
    openant_root = _find_openant_root()
    patcher_commit = _rm.collect_git_info(openant_root) if openant_root else "unknown"
    repo_commit = _rm.collect_git_info(Path(repo_root)) if repo_root else "-"

    api_key = os.environ.get("OPENAI_API_KEY", "")
    report_body = _run_pipeline(
        vulnerability_text=vulnerability_text,
        api_key=api_key,
        repo_root=repo_root,
    )

    provider = _llm._cached_provider or os.environ.get("LLM_PROVIDER", "unknown")
    if provider and provider != "unknown":
        model = _llm._cached_model.get(provider, "unknown")
    else:
        model = "unknown"
    if provider == "mock":
        model = "mock"

    llm_mode = "MOCK" if _llm.LLMClient(api_key=api_key).is_mock else "LIVE"

    call_metadata = _llm.get_call_metadata()
    stage_stop_reasons = {stage: info.get("stop_reason") for stage, info in call_metadata.items()}
    max_tokens_configured = next(
        (
            info.get("max_tokens_configured")
            for info in call_metadata.values()
            if info.get("max_tokens_configured") is not None
        ),
        None,
    )

    trust_report_path = os.path.join(patch_dir, f"{finding_id}-trust-report.md")
    meta = _rm.RunMetadata(
        timestamp=timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        input_source=vulnerability_path,
        repo_root=repo_root or "",
        repo_commit=repo_commit,
        llm_provider=provider,
        llm_model=model,
        llm_mode=llm_mode,
        output_path=trust_report_path,
        patcher_commit=patcher_commit,
        max_tokens_configured=max_tokens_configured,
        stage_stop_reasons=stage_stop_reasons,
    )
    full_report = report_body + "\n---\n\n" + _rm.render_metadata_section(meta)

    with open(trust_report_path, "w", encoding="utf-8") as f:
        f.write(full_report)

    return PatchStepResult(
        finding_id=finding_id,
        vulnerability_path=vulnerability_path,
        trust_report_path=trust_report_path,
    )
