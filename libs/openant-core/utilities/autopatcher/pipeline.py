"""
Pipeline orchestrator.

Ties together the patch_generator, patch_reviewer, patch_challenger, and
confidence_scorer stages and produces a formatted Markdown report.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from .confidence_scorer import score_confidence
from .finding_calibration import calibrate_findings
from .llm_client import LLMClient
from .patch_challenger import challenge_patch
from .patch_generator import generate_patch
from .patch_reviewer import review_patch
from .testing_support import discover_tests, tests_for_file, score_test_support
from .test_suggester import extract_findings, suggest_tests
from .impact_surface import LightweightImpactAnalyzer
from .behavior_summary import BehaviorAnalyzer
from .language_support import detect_language
from pathlib import Path as _Path
from .evidence_fusion import RepositoryUnderstanding
from .repository_grounding_models import RepositoryCandidate, RepositoryGroundingResult
from .post_patch_evaluation import AnchorObservation, CoverageResult, render_post_patch_investigation

# Static patch signals
try:
    from scripts.constraint_signals import run_constraint_signals as _run_constraint_signals
    from scripts.remediation_signals import run_remediation_signals as _run_remediation_signals
    _STATIC_SIGNALS_AVAILABLE = True
except ImportError:
    _STATIC_SIGNALS_AVAILABLE = False
    def _run_constraint_signals(*a, **k): return []  # type: ignore
    def _run_remediation_signals(*a, **k): return []  # type: ignore


# Minimal TargetRepoContext for routing repo-relative file reads.
# Keep this intentionally small: resolve, read_file, exists only.
class TargetRepoContext:
    def __init__(self, repo_root: _Path):
        self.repo_root = _Path(repo_root).resolve()

    def resolve(self, relative_path: str) -> _Path:
        rel = str(relative_path).lstrip("/")
        candidate = (self.repo_root / rel).resolve(strict=False)
        # Use is_relative_to when available, fallback to string containment
        if hasattr(candidate, "is_relative_to"):
            if not candidate.is_relative_to(self.repo_root):
                raise ValueError("path outside repo root")
        else:
            if str(self.repo_root) not in str(candidate):
                raise ValueError("path outside repo root")
        return candidate

    def read_file(self, relative_path: str) -> str:
        p = self.resolve(relative_path)
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    def exists(self, relative_path: str) -> bool:
        try:
            return self.resolve(relative_path).exists()
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class PipelineResult:
    vulnerability_text: str
    patch: str
    review: str
    score_text: str
    challenger: dict
    impact: dict | None = None
    final_score: float | None = None
    behavior: dict | None = None
    repo_root: _Path | None = None
    hygiene: list | None = None
    applicability: dict | None = None
    orig_score: float | None = None
    original_patch: str = ""
    retry_patch: str | None = None
    retry_attempted: bool = False
    retry_succeeded: bool = False
    retry_failed_file: str | None = None
    retry_error_before: str | None = None
    # Challenger-driven repair (Phase C)
    repair_attempted: bool = False
    repair_succeeded: bool = False
    repair_patch: str | None = None
    repair_challenger: dict | None = None
    repair_defect_count: int = 0
    repair_rechallenged: bool = False
    original_challenger_defect_count: int = 0
    # Deterministic static signals (Phase I)
    constraint_signals: list[dict] | None = None
    remediation_signals: list[dict] | None = None
    # Language guardrail: dominant detected language of repo_root, used to
    # gate Python-only signals (Test Support, Impact Surface, sink scanning).
    detected_language: str = "python"
    # Finding calibration (evidence-quality pass): one entry per
    # plausible_risk/generic classified finding — {"original", "group",
    # "reworded"}. None when calibration wasn't run at all (e.g. no
    # findings to calibrate); _build_known_findings falls back to the
    # uncalibrated classifier text when this is None or empty, so a
    # calibration failure never loses a finding.
    finding_calibration: list[dict] | None = None
    # Repository Grounding (surfaced in the report as "Repository Context").
    grounding: RepositoryGroundingResult | None = None
    # Deterministic Repository Understanding (candidate selection + enrichment
    # + fusion) -- retained for later reporting work; not yet surfaced in the
    # Trust Report. None when investigation didn't run or found nothing to
    # select (see CandidateSelection.used_fallback).
    repository_understanding: RepositoryUnderstanding | None = None
    # Post-Patch Vulnerability Investigation (Phase 4): deterministic
    # re-evaluation of pre-patch Anchors against an isolated, patched copy
    # of repo_root. None when the investigation didn't run (no repo_root,
    # no anchors, or an internal failure -- see stderr). Whatever patch
    # string the observations actually describe is recorded in
    # post_patch_investigated_patch; if it no longer equals `patch` above
    # (the repair loop replaced it), the evidence is stale and
    # _build_report must not render it as current.
    post_patch_observations: list[AnchorObservation] | None = None
    post_patch_investigated_patch: str | None = None
    # Deterministic Coverage Analysis (see post_patch_evaluation.compute_coverage):
    # how much of `patch`'s diff is tracked by at least one pre-patch Anchor.
    # Computed alongside post_patch_observations, from the same patch and
    # anchors, so it shares that field's staleness gate -- no separate
    # "coverage_investigated_patch" field exists or is needed.
    post_patch_coverage: "CoverageResult | None" = None
    # Candidate 1 relocation telemetry (observability only -- see
    # relocation_telemetry.py). Never read by _compute_trust_signals,
    # _build_recommendation_v1, or any other decision logic; not currently
    # rendered into the Markdown Trust Report either. None whenever there
    # was no repo_root/patch to measure, or the telemetry probe failed.
    relocation_telemetry: "object | None" = None
    # Evidence Sufficiency Gate (Phase 1) -- see source_verification.py.
    # A Trust-signal-shaped dict ({"value", "label", "notes"}), derived from
    # RepairResult.relocations for whichever repair pass produced the FINAL
    # `patch` above. _build_report merges this into the Trust Signals dict
    # (as a NEW key, "source_verification") so it is surfaced in the Trust
    # Report and made available to Recommendation Policy's inputs --
    # deliberately NOT read by _build_recommendation_v1 today; that is an
    # explicit, separate, later decision. None when unavailable (no
    # repo_root, no patch, or the classification itself failed) -- callers
    # must fall back to "Not Verified", never infer "Confirmed".
    source_verification: "dict | None" = None
    # Edit Readiness Gate (Slice 1) -- see remediation_planner.EditReadinessResult
    # / check_edit_readiness. Observability + the actual gating signal
    # _skip_patch_generation was set from; never read by
    # _compute_trust_signals/_build_recommendation_v1 -- no Recommendation
    # Policy change. None when Final Strategy never ran, named no targets,
    # or the Slice/Gate computation itself failed (best-effort, same as
    # every other optional pipeline section). When Slice 2 and/or Slice 3
    # acquisition ran (see edit_acquisition/guided_acquisition below), this
    # is the FINAL, RECALCULATED readiness after both -- still the same
    # final gating signal, just possibly improved by newly-acquired source.
    edit_readiness: "object | None" = None
    # Slice 2 (Deterministic Pre-Patch Retrieval) -- see
    # remediation_planner.AcquisitionResult / run_deterministic_
    # acquisition. Observability only, same as edit_readiness above:
    # never read by _compute_trust_signals/_build_recommendation_v1. None
    # whenever acquisition never ran at all (initial readiness was
    # already complete, or the Edit Readiness Gate itself never ran).
    edit_acquisition: "object | None" = None
    # Slice 3 (Bounded LLM-guided pre-patch context retrieval) -- see
    # remediation_planner.GuidedAcquisitionResult / run_guided_
    # acquisition. Observability only, same as edit_acquisition above:
    # never read by _compute_trust_signals/_build_recommendation_v1. None
    # whenever guided acquisition never ran at all (Slice 2 already made
    # readiness complete, or the Edit Readiness Gate itself never ran).
    guided_acquisition: "object | None" = None
    # Slice 4 (Post-Patch Target Conformance and Recovery) -- see
    # remediation_planner.PatchConformanceReport/PostPatchRecoveryResult.
    # Observability only, same as every earlier slice's own field: never
    # read by _compute_trust_signals/_build_recommendation_v1. patch_
    # target_conformance is None only when Patch Generation produced no
    # patch at all, or ran with no Edit Readiness context to compare
    # against (no Final Strategy). post_patch_recovery is None whenever
    # recovery never triggered (conformance was already fine, or
    # conformance/recovery itself never ran).
    patch_target_conformance: "object | None" = None
    post_patch_recovery: "object | None" = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_score(score_text: str) -> str:
    """Pull the numeric score out of the scorer's response."""
    match = re.search(r"confidence score[^0-9]*([0-9]+(?:\.[0-9]+)?)", score_text, re.IGNORECASE)
    return match.group(1) if match else "N/A"


def _extract_summary(vulnerability_text: str) -> str:
    """Return the first non-empty line of the vulnerability file as a summary."""
    for line in vulnerability_text.splitlines():
        line = line.strip().lstrip("#").strip()
        if line:
            return line
    return "No summary available."


def _split_review(review: str) -> dict[str, str]:
    """
    Split the review text into its three expected sections.

    Returns a dict with keys: explanation, affected_areas, validation_notes.
    Falls back to the full review text for each key if parsing fails.
    """
    sections: dict[str, str] = {
        "explanation": "",
        "affected_areas": "",
        "validation_notes": "",
    }

    # Match section headers (### Explanation, **Explanation**, etc.)
    pattern = re.compile(
        r"(?:#{1,3}\s*|\*\*)(Explanation|Affected areas|Validation notes)(?:\*\*)?[:\s]*",
        re.IGNORECASE,
    )
    parts = pattern.split(review)

    # parts = [pre_text, header1, body1, header2, body2, ...]
    i = 1
    while i < len(parts) - 1:
        header = parts[i].lower().replace(" ", "_")
        body = re.sub(r"^\*{1,2}\s*", "", parts[i + 1]).strip()
        if "explanation" in header:
            sections["explanation"] = body
        elif "affected" in header:
            sections["affected_areas"] = body
        elif "validation" in header:
            sections["validation_notes"] = body
        i += 2

    # If parsing failed, populate all sections with the full review
    if not any(sections.values()):
        full = review.strip()
        sections = {k: full for k in sections}

    return sections


def enhance_findings_with_impact(challenger: dict, impact_report: dict | None) -> None:
    """Apply deterministic textual augmentation to adversarial challenger notes

    This helper does not alter impact analysis results — it only appends
    human-readable sentences into the challenger dict under
    'impact_annotations' so the report can surface them.

    Rules (deterministic):
      - high -> append propagation sentence
      - medium -> append validation sentence
      - low -> append nothing
    """
    if not impact_report:
        return
    level = (impact_report.get("impact_level") or "").lower()
    ann = challenger.get("impact_annotations") or []
    if level == "high":
        ann.append("This issue may propagate across multiple flows due to widespread usage of the affected function.")
    elif level == "medium":
        ann.append("This issue affects multiple components and should be validated across flows.")
    # low -> do nothing
    if ann:
        challenger["impact_annotations"] = ann


def build_recommendation(challenger: dict, final_score: float | None, rating: str, impact: dict | None) -> dict:
    """Deterministic recommendation builder.

    Returns a dict: {"decision": str, "reason": str}
    Decision is one of: "Safe to deploy", "Deploy with caution", "Do not deploy yet".
    The reason is a single human-readable sentence (<=120 chars) that focuses on
    adversarial findings, impact, and test support. It must NOT mention numeric
    confidence or raw labels like "impact: MEDIUM".
    """
    # Normalize inputs
    impact_level = (impact.get("impact_level") if impact else "low") or "low"
    impact_level = impact_level.lower()
    rating_norm = (rating or "None").strip()

    still = bool(challenger and challenger.get("still_vulnerable"))
    edge_cases = (challenger.get("edge_cases") or []) if challenger else []
    potential = (challenger.get("potential_issues") or []) if challenger else []
    adv_exist = bool(edge_cases or potential)

    # Rule: Do not deploy yet (evaluate first)
    if still:
        decision = "Do not deploy yet"
    elif final_score is not None and isinstance(final_score, (int, float)) and final_score < 0.5:
        decision = "Do not deploy yet"
    elif impact_level == "high" and rating_norm.lower() == "none":
        # Explicit override: high impact + no tests -> do not mark safe
        decision = "Do not deploy yet"
    else:
        # Deploy with caution conditions
        if adv_exist or impact_level in ("medium", "high") or rating_norm == "None" or (
            final_score is not None and final_score < 0.75
        ):
            decision = "Deploy with caution"
        else:
            # Safe to deploy only when clear of adversarial findings, good tests, high score, and low impact
            if (not adv_exist) and final_score is not None and final_score >= 0.75 and rating_norm in ("Some", "Good") and impact_level == "low":
                decision = "Safe to deploy"
            else:
                decision = "Deploy with caution"

    # Build reason fragments (do NOT mention numeric score)
    phrases: list[str] = []
    if adv_exist:
        phrases.append("adversarial findings remain")
    if impact_level == "high":
        phrases.append("impact is high")
    elif impact_level == "medium":
        phrases.append("impact is medium")
    # Test support phrasing
    if rating_norm == "None":
        phrases.append("direct test coverage is missing")
    elif rating_norm == "Some":
        phrases.append("direct test coverage is limited")

    # If no focused phrase, provide a minimal neutral reason
    if not phrases:
        if decision == "Safe to deploy":
            reason = "No adversarial findings, impact is low, and direct tests provide reasonable coverage."
        else:
            reason = "No adversarial findings, but please verify impact and test coverage before deploying."
    else:
        # Compose a single natural sentence
        # Join with commas and a final conjunction if appropriate
        if len(phrases) == 1:
            reason_core = phrases[0]
        elif len(phrases) == 2:
            reason_core = f"{phrases[0]} and {phrases[1]}"
        else:
            reason_core = ", ".join(phrases[:-1]) + ", and " + phrases[-1]
        reason = reason_core[0].upper() + reason_core[1:] + "."

    # Enforce single sentence, <=120 chars, no bullets
    reason = re.sub(r"\s+", " ", reason).strip()
    if len(reason) > 120:
        # Truncate safely at word boundary
        cut = reason[:120]
        if " " in cut:
            cut = cut.rsplit(" ", 1)[0]
        reason = cut.rstrip("., ") + "."

    # Ensure no bullet characters
    reason = reason.replace("-", "").replace("*", "")

    return {"decision": decision, "reason": reason}


# ---------------------------------------------------------------------------
# Trust Package V1 helpers
# ---------------------------------------------------------------------------

# Explicit exploitability patterns — always Confirmed Defect regardless of context.
# These assert the CURRENT STATE of exploitability of the primary vulnerability and
# are unambiguous: no scope qualifier can make "still vulnerable" a limitation.
_EXPLICIT_DEFECT_RE = re.compile(
    r"\b(still\s+(vulnerable|exploitable)"
    r"|attack\s+(still|remains|continues)"
    r"|(can|could)\s+(be\s+)?bypass\w*"  # active exploit: can bypass, can be bypassed
    r"|allow\w*\s+(be\s+)?bypass\w*"     # active exploit: allows bypass
    r"|can\s+still\s+be\s+(exploited|attacked)"
    r"|attack\s+vector\s+remains"
    r"|remain[s]?\s+exploitable)\b",
    re.IGNORECASE,
)

# "does not fix/address/prevent/close" — CONTEXTUAL pattern.
# Primary fix failure if no scope marker is present; scope limitation otherwise.
_DOES_NOT_RE = re.compile(
    r"\bdoes\s+not\s+(fix|address|prevent|close)\b",
    re.IGNORECASE,
)

# Version markers — version numbers, legacy/older release references.
# Presence alongside _DOES_NOT_RE indicates a scope limitation, not a primary failure.
_VERSION_MARKER_RE = re.compile(
    r"v?\d+\.\d+[\.\d]*\b"                  # v1.26.x, 2.0.6, v1.x (numeric major.minor)
    r"|\d+\.x\b"                             # 1.x, 26.x (wildcard minor)
    r"|\bversion\s+\d"                       # version 1, version 2
    r"|\bolder\s+(versions?|releases?)\b"
    r"|\blegacy\s+(versions?|branch|releases?)\b"
    r"|\bprevious\s+(versions?|releases?)\b"
    r"|\bv\d+\s+(branch|releases?)\b",        # v1 branch
    re.IGNORECASE,
)

# User/configuration/scope markers — conditional, optional, or orthogonal scope.
# Presence alongside _DOES_NOT_RE indicates a scope limitation, not a primary failure.
_SCOPE_MARKER_RE = re.compile(
    r"\bif\s+users?\b"
    r"|\busers?\s+who\b"                                         # "users who configure/override"
    r"|\bfor\s+users?\s+(who|running|using|with|on)\b"          # "for users running 1.26.x"
    r"|\bwhen\s+(configured|enabled|disabled|set|using)\b"
    r"|\bunless\b"
    r"|\bonly\s+(when|if|for|with)\b"
    r"|\ba\s+separate\s+(fix|patch|commit)\b"
    r"|\b(in\s+addition|additionally)\s+(needs?|requires?|should)\b"
    r"|\bout(\s*-?\s*)of\s+scope\b"
    r"|\bnot\s+in\s+scope\b",
    re.IGNORECASE,
)

_VALIDATION_GAP_RE = re.compile(
    r"\b(cannot\s+(verify|confirm|test|validate)|without\s+(running|testing|executing)"
    r"|can'?t\s+(verify|confirm|test)|needs?\s+(test|verif|validat)"
    r"|no\s+tests?\s+(run|executed)|should\s+be\s+tested|unverified|untested"
    r"|requires?\s+(testing|validation)|unable\s+to\s+(verify|confirm))\b",
    re.IGNORECASE,
)
_GENERIC_RE = re.compile(
    r"\b(tests?\s+should|consider\s+(adding|using)|recommend|performance\s+impact"
    r"|documentation|changelog|code\s+style|best\s+practice)\b",
    re.IGNORECASE,
)

_BENEFIT_VERB_RE = re.compile(
    r"\b(fix(es)?|prevent(s)?|add(s)?|block(s)?|strip(s)?|remov(es)?|"
    r"resolve(s)?|ensure(s)?|protect(s)?|mitigat(es)?|eliminat(es)?|"
    r"address(es)?|patch(es)?|close(s)?)\b",
    re.IGNORECASE,
)


def _classify_finding(text: str) -> str:
    """Classify a single challenger finding into one of four categories.

    Returns: 'confirmed_defect' | 'plausible_risk' | 'validation_gap' | 'generic'

    Priority order:
    1. Explicit exploitability patterns (still vulnerable, bypass, attack vector remains…)
       → always confirmed_defect; scope markers do not override these.
    2. "does not fix/address/prevent/close" WITH a version or scope marker
       → plausible_risk (scope limitation, not a primary fix failure).
    3. "does not fix/address/prevent/close" WITHOUT any scope marker
       → confirmed_defect (the primary fix is being claimed as non-functional).
    4. Validation gap patterns → validation_gap.
    5. Generic observation patterns → generic.
    6. Default → plausible_risk (conservative).
    """
    if not text:
        return "generic"
    # Step 1: explicit current-exploitability language — unambiguous confirmed defect.
    if _EXPLICIT_DEFECT_RE.search(text):
        return "confirmed_defect"
    # Step 2: "does not fix/address/prevent/close" — contextual two-step check.
    if _DOES_NOT_RE.search(text):
        if _VERSION_MARKER_RE.search(text) or _SCOPE_MARKER_RE.search(text):
            return "plausible_risk"   # finding describes a scope / version limitation
        return "confirmed_defect"     # no scope qualifier → primary fix failure
    # Step 3: validation gap.
    if _VALIDATION_GAP_RE.search(text):
        return "validation_gap"
    # Step 4: generic observation.
    if _GENERIC_RE.search(text):
        return "generic"
    return "plausible_risk"


def _classify_challenger(challenger: dict) -> dict:
    """Return an augmented challenger dict with per-finding classifications and counts."""
    result = dict(challenger) if challenger else {}

    classified_edge: list[dict] = []
    for finding in (challenger or {}).get("edge_cases") or []:
        classified_edge.append({"text": finding, "category": _classify_finding(finding)})
    result["classified_edge_cases"] = classified_edge

    classified_issues: list[dict] = []
    for finding in (challenger or {}).get("potential_issues") or []:
        classified_issues.append({"text": finding, "category": _classify_finding(finding)})
    result["classified_potential_issues"] = classified_issues

    all_classified = classified_edge + classified_issues
    result["confirmed_defect_count"] = sum(1 for f in all_classified if f["category"] == "confirmed_defect")
    result["plausible_risk_count"] = sum(1 for f in all_classified if f["category"] == "plausible_risk")
    result["validation_gap_count"] = sum(1 for f in all_classified if f["category"] == "validation_gap")
    return result


def _extract_security_gain(explanation: str) -> str:
    """Extract the concrete security benefit statement from the reviewer explanation.

    Looks for the first sentence containing a security action verb (fix, prevent,
    add, strip, etc.) that is long enough to be meaningful.  Falls back to the
    first 250 characters of the explanation.
    """
    if not explanation:
        return ""
    sentences = re.split(r"(?<=[.!?])\s+", explanation.strip())
    for sentence in sentences:
        if _BENEFIT_VERB_RE.search(sentence) and len(sentence.strip()) >= 40:
            return sentence.strip()
    # Fallback: first paragraph, truncated
    first_para = explanation.split("\n\n", 1)[0].strip()
    first_para = re.sub(r"\s+", " ", first_para)
    if len(first_para) > 250:
        first_para = first_para[:250].rsplit(" ", 1)[0] + "…"
    return first_para


# ---------------------------------------------------------------------------
# Primary Vulnerability References
#
# Presentation-only text extraction, not a new data source: ghsa_to_vuln_text
# / cve_to_vuln_text (advisory_converter.py / cve_converter.py) already
# render a "**Advisory:** <id>" line and a "## References" URL list into
# vulnerability_text for both --ghsa and --cve input modes. This parses that
# already-present text the same way _extract_summary parses other blocks —
# no network call, no new fetch, no semantic classifier.
# ---------------------------------------------------------------------------

_ADVISORY_LINE_RE = re.compile(r"^\*\*Advisory:\*\*\s*(.+)$", re.MULTILINE)
_GHSA_ID_RE = re.compile(r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}")
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def _extract_primary_references(vulnerability_text: str) -> dict:
    """Extract GHSA/CVE identifiers already embedded in vulnerability_text.
    Returns None for any field not found — file-mode input (a hand-written
    vulnerability.md) has no guaranteed structure, so every field degrades
    gracefully rather than assuming GHSA/CVE input.

    'advisory_url' is constructed from the identifier using GitHub's/NVD's
    well-known, stable URL convention — not fetched or independently
    verified, and labeled as such by the caller.

    Deliberately does not extract upstream fix/remediation references (e.g.
    a "referenced commit" from the advisory's References list): those imply
    the generated patch was informed by an existing upstream fix, which the
    reviewer report must not suggest. That data has no place here at all —
    not even computed-but-hidden — since nothing in this pipeline persists
    it elsewhere; it belongs only in benchmark/evaluation artifacts, which
    are produced and reviewed separately from this report.
    """
    text = vulnerability_text or ""

    ghsa_id = None
    cve_id = None
    advisory_match = _ADVISORY_LINE_RE.search(text)
    if advisory_match:
        line = advisory_match.group(1)
        m = _GHSA_ID_RE.search(line)
        if m:
            ghsa_id = m.group(0)
        m = _CVE_ID_RE.search(line)
        if m:
            cve_id = m.group(0)
    if not ghsa_id:
        m = _GHSA_ID_RE.search(text)
        if m:
            ghsa_id = m.group(0)
    if not cve_id:
        m = _CVE_ID_RE.search(text)
        if m:
            cve_id = m.group(0)

    advisory_url = None
    if ghsa_id:
        advisory_url = f"https://github.com/advisories/{ghsa_id}"
    elif cve_id:
        advisory_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "advisory_url": advisory_url,
    }


def _render_primary_references(refs: dict) -> str:
    """Render the Vulnerability Sources section as a compact table (own
    leading rule) — easier to scan than a bullet list.

    Keeps only GHSA / CVE / Advisory URL, each linked where a URL is known.
    Deliberately excludes any upstream fix/remediation reference — those
    belong only in benchmark/evaluation artifacts, never in a reviewer
    report, since showing them here could imply the generated patch was
    copied from an existing upstream fix.

    Degrades to a single line for file-mode input, where neither a GHSA nor
    a CVE identifier is present in the vulnerability text at all.
    """
    ghsa_id = refs.get("ghsa_id")
    cve_id = refs.get("cve_id")
    advisory_url = refs.get("advisory_url")

    lines: list[str] = ["---\n", "## Vulnerability Sources\n"]

    if not ghsa_id and not cve_id:
        lines.append("User-provided vulnerability description.\n")
        return "\n".join(lines) + "\n"

    ghsa_cell = f"[{ghsa_id}]({advisory_url})" if ghsa_id and advisory_url else (ghsa_id or "*(not applicable)*")
    cve_url = advisory_url if (cve_id and not ghsa_id) else (f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None)
    cve_cell = f"[{cve_id}]({cve_url})" if cve_id and cve_url else (cve_id or "*(not applicable / no associated CVE)*")
    advisory_cell = f"[{advisory_url}]({advisory_url})" if advisory_url else "*(not stated in the advisory text)*"

    lines.append("| Type | Value |")
    lines.append("|---|---|")
    lines.append(f"| GHSA | {ghsa_cell} |")
    lines.append(f"| CVE | {cve_cell} |")
    lines.append(f"| Advisory URL | {advisory_cell} |")
    lines.append("")

    if advisory_url:
        lines.append("*Advisory URL is constructed from the identifier above, not independently fetched.*")
        lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Repository Context (Repository Grounding, surfaced in the report)
#
# "Selected because" — one phrase per semantic reason kind. Literal lookup
# only: does not change which reason kind a candidate carries.
# ---------------------------------------------------------------------------
_GROUNDING_REASON_PHRASES = {
    "explicit_path": "Explicitly referenced in the security advisory",
    "symbol_definition": "Defines the exact symbol named in the advisory",
    "symbol_search": "References a symbol named in the advisory",
    "cwe_keywords": "Contains terminology associated with this vulnerability type",
}

# "Used for" — one phrase per GroundingDecision.outcome. Literal lookup only:
# does not change which outcome find_code_context() selects.
_GROUNDING_USED_FOR_PHRASES = {
    "primary_full_file": "Primary reference (full file)",
    "primary_snippet": "Primary reference (excerpt)",
    "secondary_snippet": "Supporting reference (excerpt)",
}


# ---------------------------------------------------------------------------
# Adapter: the only place that understands Repository Grounding internals
# (DiscoveryEvidence, best_tier, evidence ordering, tier matching, selection
# mechanics). Everything downstream — the renderer included — sees only a
# semantic reason kind (a key into _GROUNDING_REASON_PHRASES), never a
# RepositoryCandidate's evidence list directly.
# ---------------------------------------------------------------------------
def _selected_reason_kind(candidate: "RepositoryCandidate | None") -> "str | None":
    """Return the semantic reason kind that best explains why `candidate`
    was selected: the DiscoveryEvidence.pass_name whose tier produced the
    candidate's best_tier (the tier that actually drove ranking/selection).
    Falls back to the first evidence entry's pass_name for class-definition-
    supplement-only candidates, where best_tier is None by construction."""
    if not candidate or not candidate.evidence:
        return None
    if candidate.best_tier is not None:
        for e in candidate.evidence:
            if e.tier == candidate.best_tier:
                return e.pass_name
    return candidate.evidence[0].pass_name


def _render_repository_context_section(grounding: "RepositoryGroundingResult | None") -> str:
    """Render the Repository Context section (own leading rule).

    Shows only the repository locations find_code_context() actually
    selected (decision.outcome != "rejected") — no candidate counts, no
    rejected locations. None-safe: renders the zero-selection sentence when
    grounding is None or nothing was selected. Preserves the order
    grounding.decisions already comes in — no additional sorting.
    """
    lines: list[str] = ["---\n", "## Repository Context\n"]

    selected = [d for d in (grounding.decisions if grounding else []) if d.outcome != "rejected"]
    if not selected:
        lines.append(
            "No repository locations were identified to provide context for "
            "this vulnerability.\n"
        )
        return "\n".join(lines) + "\n"

    lines.append(
        "The following repository locations were selected to provide context "
        "for patch generation and review. These locations were selected "
        "**before** the patch was generated — for evidence gathered from the "
        "final patch diff itself, see Post-Patch Investigation.\n"
    )

    candidates_by_path = {c.path: c for c in grounding.candidates}

    entries = []
    for dec in selected:
        candidate = candidates_by_path.get(dec.path)
        kind = _selected_reason_kind(candidate)
        reason = _GROUNDING_REASON_PHRASES.get(kind, "Identified during repository grounding")
        used_for = _GROUNDING_USED_FOR_PHRASES.get(dec.outcome, dec.outcome)
        entries.append(
            f"**`{dec.path}`**\n\nSelected because\n- {reason}\n\nUsed for\n- {used_for}"
        )

    lines.append("\n\n---\n\n".join(entries))
    lines.append("")
    return "\n".join(lines) + "\n"


def _build_known_findings(classified_challenger: dict, finding_calibration: list[dict] | None = None) -> dict:
    """Group already-classified challenger findings into report-facing
    epistemic categories for the Known Findings section.

    This reuses the four categories _classify_challenger already computes
    (confirmed_defect / plausible_risk / validation_gap / generic) — no new
    classification, no change to the counts _compute_trust_signals and
    _build_recommendation_v1 read.

      confirmed_defect  -> potential_remaining_risks   (presented as heuristic
                           adversarial-review concerns, not confirmed facts,
                           since the challenger is LLM analysis, not
                           deterministic verification)
      validation_gap    -> validation_gaps             ("things we did not verify")
      plausible_risk,
      generic           -> split three ways by the finding_calibration stage
                           (evidence-quality pass): observed_implementation_notes,
                           validation_hypotheses, future_hardening_ideas.

    finding_calibration is the (optional) output of
    finding_calibration.calibrate_findings — a list of {"original", "group",
    "reworded"} dicts covering the plausible_risk/generic findings. When a
    finding has no matching calibration entry (calibration wasn't run, or
    failed, or omitted this specific finding), it falls back to a
    conservative default rather than being dropped: plausible_risk ->
    Validation Hypotheses (already a hedge), generic -> Future Hardening
    Ideas (already a suggestion) — the same mapping this project used before
    calibration existed, so a calibration failure degrades to prior behavior
    rather than losing information.

    Returns a plain dict of five lists so the renderer (and tests) can
    address each category directly. Rendering/suppression decisions (e.g.
    whether an empty category renders at all) belong to the caller, not here.
    """
    all_findings = (
        list(classified_challenger.get("classified_edge_cases") or [])
        + list(classified_challenger.get("classified_potential_issues") or [])
    )

    potential_remaining_risks = [f["text"] for f in all_findings if f["category"] == "confirmed_defect"]

    validation_gaps: list[str] = []
    for f in all_findings:
        if f["category"] == "validation_gap" and len(validation_gaps) < 3:
            validation_gaps.append(f["text"])

    calibration_by_original = {
        entry.get("original"): entry for entry in (finding_calibration or [])
    }

    observed_implementation_notes: list[str] = []
    validation_hypotheses: list[str] = []
    future_hardening_ideas: list[str] = []

    for f in all_findings:
        if f["category"] not in ("plausible_risk", "generic"):
            continue
        entry = calibration_by_original.get(f["text"])
        if entry and entry.get("reworded"):
            group = entry.get("group")
            text = entry["reworded"]
        else:
            group = "hypothesis" if f["category"] == "plausible_risk" else "hardening"
            text = f["text"]

        if group == "observed":
            observed_implementation_notes.append(text)
        elif group == "hardening":
            future_hardening_ideas.append(text)
        else:
            validation_hypotheses.append(text)

    return {
        "potential_remaining_risks": potential_remaining_risks,
        "validation_gaps": validation_gaps,
        "observed_implementation_notes": observed_implementation_notes,
        "validation_hypotheses": validation_hypotheses,
        "future_hardening_ideas": future_hardening_ideas,
    }


# ---------------------------------------------------------------------------
# Recommendation Policy Invariants
#
# _compute_trust_signals and _build_recommendation_v1 below implement these
# invariants. Every branch in both functions must be traceable to one of
# them by its inline `# In` tag — a branch with no tag, or one that
# contradicts its tag, is a policy bug. Do not add a fallthrough branch
# that isn't justified here first.
#
# State model
#   applicability        ∈ {APPLIES, REJECTED, UNAVAILABLE}
#     UNAVAILABLE = applicable is None. Subsumes pre-flight skip (no repo,
#     no .git, empty diff, git missing), subprocess timeout, and unexpected
#     exception — these are policy-equivalent (only their notes/reason text
#     differs); none may be distinguished from another when deciding a
#     signal value.
#   impact_level          ∈ {low, medium, high, not_applicable, unavailable}
#     unavailable = impact analysis raised and was swallowed (result.impact
#     is None) — distinct from, and never conflated with, a genuine "low"
#     result.
#   patch_integrity        ∈ {Clean, Minor Issues, Not Verified,
#                              Does Not Apply, Critical Issues}
#   security_improvement   ∈ {None, Unknown, Low, Medium, High}
#   deployment_safety       ∈ {Low Risk, Medium Risk, High Risk, Not Verified}
#
# I1 — No positive inference from missing applicability evidence.
#      UNAVAILABLE applicability maps to patch_integrity=Not Verified and
#      security_improvement=Unknown — never to Clean/Does Not Apply, and
#      never to Low/Medium/High. Holds identically for skip, timeout, and
#      exception.
#
# I2 — No positive inference from missing impact evidence.
#      impact_level ∈ {not_applicable, unavailable} maps to
#      deployment_safety=Not Verified — never to Low Risk.
#
# I3 — Deploy After Validation requires positive evidence on every
#      mandatory gate, expressed as an explicit whitelist, never as a
#      "not-the-bad-value" blacklist, and never inferred from "didn't hit
#      the hard-block gate" — absence of a block is not evidence of a
#      verified-clean state. It requires ALL of:
#        integrity              == Clean          (exactly — see below)
#        alignment               != Misaligned
#        NOT (still_vulnerable AND defect_count == 0)
#        security_improvement   IN {High, Medium}
#        deployment_safety       IN {Low Risk, Medium Risk}
#      "Minor Issues" is deliberately excluded from the integrity allowlist:
#      it reports an actual observed hygiene defect in the patch (currently
#      only "unused_import" — a real, if low-severity, code-quality problem,
#      not a missing-evidence placeholder), and the report itself already
#      renders it as "⚠️ Needs review", never "✅ Good" — so treating it as
#      verified-positive here would contradict what the system already tells
#      the reader. Every condition above must be spelled out as an explicit
#      membership test against known-good values. A condition shaped as
#      `x != BAD_VALUE` is a policy bug by construction — it silently admits
#      Unknown/Not Verified/any future value. New signal values default to
#      Manual Review Required until explicitly added to a whitelist here.
#
# I4 — Do Not Apply requires explicit, deterministic negative evidence only
#      (git-apply / hygiene via patch_integrity) — never from heuristic
#      challenger findings alone.
#
# I5 — Inconclusive evidence defaults to Manual Review Required. Any state
#      not explicitly covered by I3 or I4 — including Unknown, Not
#      Verified, still_vulnerable-with-no-confirmed-defect, and
#      Misaligned — resolves to Manual Review Required. No silent default
#      resolves to a stronger decision than the evidence supports.
#
# I6 — Never communicate more certainty than the evidence supports.
#      Not Verified / Unknown / None are always weaker than their positive
#      counterparts and never appear in a positive whitelist.
# ---------------------------------------------------------------------------


def _applicability_unavailable_reason(applicability: dict) -> str | None:
    """Returns a human-readable reason when applicability is UNAVAILABLE
    (applicable is None — covers skip, timeout, and unexpected exception
    identically per I1), else None.
    """
    if applicability.get("applicable") is not None:
        return None
    return (
        applicability.get("skipped_reason")
        or applicability.get("error")
        or "applicability check did not complete"
    )


def _resolve_impact_level(impact: dict | None) -> str:
    """Map a (possibly absent) impact-analysis result to an impact_level
    string. `impact is None` means the analysis raised and was swallowed
    (see pipeline.run()'s impact-analysis try/except) — that is distinct
    from, and must never be read as, a genuine "low" result (I2).
    """
    if impact is None:
        return "unavailable"
    return impact.get("impact_level") or "low"


def _compute_trust_signals(
    hygiene: list | None,
    applicability: dict | None,
    classified_challenger: dict,
    testing_rating: str,
    impact_level: str,
) -> dict:
    """Compute the six Trust Package signals from existing deterministic pipeline outputs.

    Returns a dict mapping signal keys to {value, label, notes} dicts.
    All logic is deterministic — no LLM score is used. See the Recommendation
    Policy Invariants block above; each branch below is tagged with the
    invariant it exists to satisfy.
    """
    hygiene = hygiene or []
    applicability = applicability or {}
    impact_level = (impact_level or "low").lower()

    high_hygiene = [h for h in hygiene if h.get("severity") == "HIGH"]
    med_hygiene = [h for h in hygiene if h.get("severity") == "MEDIUM"]

    defect_count = classified_challenger.get("confirmed_defect_count", 0)
    risk_count = classified_challenger.get("plausible_risk_count", 0)
    gap_count = classified_challenger.get("validation_gap_count", 0)
    still_vulnerable = bool((classified_challenger or {}).get("still_vulnerable"))

    # --- Patch Integrity ---
    _unavailable_reason = _applicability_unavailable_reason(applicability)
    if high_hygiene:
        int_val = "Critical Issues"  # I4: deterministic negative evidence
        int_notes = f"HIGH: {high_hygiene[0].get('detail', '')[:80]}"
    elif applicability.get("applicable") is False:
        int_val = "Does Not Apply"  # I4: deterministic negative evidence
        stderr = (applicability.get("stderr") or "").replace("\n", " ")[:60]
        int_notes = stderr if stderr else "rejected by git apply"
    elif _unavailable_reason is not None:
        int_val = "Not Verified"  # I1: UNAVAILABLE never reads as positive
        int_notes = _unavailable_reason
    elif med_hygiene:
        int_val = "Minor Issues"
        int_notes = f"MEDIUM: {med_hygiene[0].get('detail', '')[:80]}"
    else:
        int_val = "Clean"
        int_notes = "Applies cleanly · no hygiene issues"

    # --- Security Improvement (fully deterministic, no LLM score) ---
    if applicability.get("applicable") is False:
        imp_val = "None"
        imp_notes = "Patch does not apply to repository"
    elif _unavailable_reason is not None:
        imp_val = "Unknown"  # I1: UNAVAILABLE never reads as High/Medium/Low
        imp_notes = _unavailable_reason
    elif high_hygiene:
        imp_val = "Low"
        imp_notes = "Critical hygiene issue — patch may be a no-op"
    elif defect_count > 0:
        imp_val = "Low"
        imp_notes = f"{defect_count} review finding(s) flagged as high-confidence heuristic risk"
    elif not still_vulnerable:
        imp_val = "High"
        imp_notes = "Adversarial review found no remaining exploit path"
    elif still_vulnerable and risk_count == 0:
        # still_vulnerable=True but only due to validation gaps, not high-confidence findings
        imp_val = "High"
        imp_notes = f"No high-confidence heuristic risk identified · {gap_count} verification gap(s)"
    else:
        imp_val = "Medium"
        total = risk_count + gap_count
        imp_notes = f"No high-confidence heuristic risk identified · {total} review finding(s) remain open"

    # --- Remediation Alignment ---
    if defect_count > 0:
        aln_val = "Misaligned"
        aln_notes = "Confirmed alternate exploit path identified"
    elif not still_vulnerable:
        aln_val = "Aligned"
        aln_notes = "Adversarial review confirms fix approach"
    elif still_vulnerable and risk_count == 0:
        aln_val = "Likely Aligned"
        aln_notes = "Correct mechanism · runtime verification pending"
    else:
        aln_val = "Partial"
        aln_notes = f"still_vulnerable flag set · {risk_count} plausible risk(s)"

    # --- Coverage Confidence ---
    if defect_count > 0:
        cov_val = "Low"
        cov_notes = f"{defect_count} review finding(s) flagged as high-confidence heuristic risk"
    elif risk_count > 0 or gap_count > 0:
        total = risk_count + gap_count
        cov_val = "Medium"
        cov_notes = (
            f"{total} review finding(s) · no deterministic blocker identified — "
            "none rose to a confirmed, high-confidence defect during adversarial review"
        )
    else:
        cov_val = "High"
        cov_notes = "No gaps identified by adversarial analysis"

    # --- Test Availability (replaces Validation Evidence) ---
    if testing_rating in ("Good", "Some"):
        tst_val = "Tests Available"
        tst_notes = f"{testing_rating} — test files cover this module"
    elif testing_rating == "Not Applicable":
        tst_val = "Not Verified"
        tst_notes = "Test discovery is not supported for this language yet"
    elif testing_rating == "Not Verified":
        tst_val = "Not Verified"
        tst_notes = "No repository root was provided"
    else:
        tst_val = "No Tests Found"
        tst_notes = "No test files cover this module"

    # --- Deployment Safety ---
    # I2: "Low Risk" is only reached for the explicit, genuine "low" value.
    # Every other impact_level — including "not_applicable" (language
    # guardrail skipped symbol/usage analysis) and "unavailable" (impact
    # analysis raised and was swallowed), and any unrecognized/malformed
    # value — falls to the final "Not Verified" branch rather than to a
    # reassuring default. Whitelist, not blacklist: only genuinely observed
    # levels earn a Low/Medium/High Risk label.
    if impact_level == "high" or high_hygiene:
        saf_val = "High Risk"
        saf_notes = f"{impact_level.upper()} impact surface"
    elif impact_level == "medium":
        saf_val = "Medium Risk"
        saf_notes = "Moderate impact surface"
    elif impact_level == "low":
        saf_val = "Low Risk"
        saf_notes = "Localized change · low regression risk"
    elif impact_level == "not_applicable":
        saf_val = "Not Verified"  # I2
        saf_notes = "Impact analysis is not supported for this language yet"
    else:
        saf_val = "Not Verified"  # I2: covers "unavailable" and any unrecognized value
        saf_notes = "Impact analysis did not complete or returned an unrecognized result"

    # Icon mapping
    _icons = {
        "Clean": "✓", "High": "✓", "Aligned": "✓", "Low Risk": "✓",
        "Likely Aligned": "◑", "Medium": "◑", "Partial": "◑",
        "Medium Risk": "◑", "Tests Available": "◑", "Minor Issues": "⚠",
        "Low": "⚠", "No Tests Found": "○",
        "Critical Issues": "✗", "Does Not Apply": "✗", "Misaligned": "✗",
        "High Risk": "✗", "None": "✗", "Unknown": "?", "Not Verified": "?",
    }

    def _label(val: str) -> str:
        return f"{_icons.get(val, '')} {val}".strip()

    return {
        "patch_integrity":       {"value": int_val, "label": _label(int_val), "notes": int_notes},
        "security_improvement":  {"value": imp_val, "label": _label(imp_val), "notes": imp_notes},
        "remediation_alignment": {"value": aln_val, "label": _label(aln_val), "notes": aln_notes},
        "coverage_confidence":   {"value": cov_val, "label": _label(cov_val), "notes": cov_notes},
        "test_availability":     {"value": tst_val, "label": _label(tst_val), "notes": tst_notes},
        "deployment_safety":     {"value": saf_val, "label": _label(saf_val), "notes": saf_notes},
    }


# I3: the only signal values a mandatory gate may treat as positive
# evidence. Named and centralized so each gate is a membership test against
# a whitelist, never a `!= BAD_VALUE` blacklist that silently admits
# Unknown/Not Verified/any future value.
#
# _POSITIVE_INTEGRITY is deliberately {"Clean"} only — "Minor Issues" means
# _compute_trust_signals found a real hygiene defect (currently only
# "unused_import"), not a verified-clean patch; it is excluded even though
# it does not hard-block via _BLOCKING_INTEGRITY. Not-blocked is not the
# same claim as positive-evidence; see I3 above _compute_trust_signals.
_POSITIVE_INTEGRITY = frozenset({"Clean"})
_POSITIVE_IMPROVEMENT = frozenset({"High", "Medium"})
_POSITIVE_SAFETY = frozenset({"Low Risk", "Medium Risk"})
_BLOCKING_INTEGRITY = frozenset({"Does Not Apply", "Critical Issues"})


def _build_recommendation_v1(
    signals: dict,
    still_vulnerable: bool = False,
    defect_count: int = 0,
) -> dict:
    """Produce a Trust Package recommendation from the six trust signals.

    Returns {decision: str, reason: str}.  Decisions use the new V1 vocabulary:
    'Deploy After Validation' | 'Deploy With Caution' | 'Manual Review Required'
    | 'Do Not Apply'

    Implements the Recommendation Policy Invariants (I1-I6) documented above
    _compute_trust_signals. Each branch below is tagged with the invariant
    it satisfies:
      I4 → Do Not Apply requires deterministic integrity failure only; pure
           heuristic evidence (challenger findings, incl. alignment=
           Misaligned) must never produce Do Not Apply on its own.
      I5 → still_vulnerable=True with defect_count==0, OR alignment=
           Misaligned (confirmed_defect_count > 0) — both heuristic-only —
           land at Manual Review Required, never Do Not Apply, never higher.
      I3 → Deploy After Validation only when integrity, improvement, AND
           safety are each explicitly in their own positive whitelist (not
           merely "not the one excluded bad value", and not merely "did not
           hit the Do Not Apply gate above" — integrity=Minor Issues clears
           that gate but is still excluded here, since it is not the same
           claim as verified-clean).
      I5 → everything else (including Unknown/Not Verified on either axis)
           falls through to Manual Review Required.
    """
    integrity = signals["patch_integrity"]["value"]
    improvement = signals["security_improvement"]["value"]
    alignment = signals["remediation_alignment"]["value"]
    safety = signals["deployment_safety"]["value"]

    if integrity in _BLOCKING_INTEGRITY:  # I4
        return {
            "decision": "Do Not Apply",
            "reason": "Patch has critical issues or does not apply to the target repository.",
        }
    if alignment == "Misaligned":  # I5
        return {
            "decision": "Manual Review Required",
            "reason": (
                "Adversarial review flagged findings classified as high-confidence risk "
                "indicators; this is unresolved heuristic evidence, not a verified exploit — "
                "manual review is required before deployment."
            ),
        }
    if still_vulnerable and defect_count == 0:  # I5
        return {
            "decision": "Manual Review Required",
            "reason": (
                "Challenger flagged unverified risks but found no confirmed exploit path; "
                "see Review Results below before deploying."
            ),
        }
    if (
        integrity in _POSITIVE_INTEGRITY
        and improvement in _POSITIVE_IMPROVEMENT
        and safety in _POSITIVE_SAFETY
    ):  # I3
        return {
            "decision": "Deploy After Validation",
            "reason": (
                "Patch addresses the attack vector described by the advisory and applies cleanly. "
                "Run the listed validation actions before deployment."
            ),
        }
    if improvement == "Low" and safety == "Low Risk":
        return {
            "decision": "Deploy With Caution",
            "reason": "Patch provides limited or uncertain security improvement. Manual security review recommended.",
        }
    if safety == "High Risk":  # I5
        return {
            "decision": "Manual Review Required",
            "reason": "Change has high deployment risk; regression testing across affected callers required.",
        }
    return {  # I5 / I6: catch-all for Unknown/Not Verified and any other inconclusive state
        "decision": "Manual Review Required",
        "reason": "Patch requires manual security review before deployment.",
    }


# ---------------------------------------------------------------------------
# Slice 1 — Decision Consistency
#
# Goal: a confident-sounding recommendation must never sit beside evidence,
# already displayed elsewhere in the same report, that undercuts it without
# saying so. This function only reads signals that are already computed and
# already rendered in the Trust Signals table — it adds no new evidence and
# never changes `decision`.
# ---------------------------------------------------------------------------

# Decisions that read as confident enough to require this check. The other
# two decisions (Manual Review Required, Do Not Apply) already read as
# cautious and do not need further hedging here.
_TOP_TIER_DECISIONS = frozenset({"Deploy After Validation", "Deploy With Caution"})


def _build_consistency_caveat(lead: str, notes: str) -> str:
    """Compose one caveat sentence from a lead-in and an existing signal's notes.

    Reuses the notes text already shown in the Trust Signals table rather
    than inventing new wording, so the caveat is traceable to evidence the
    reader has already seen.
    """
    notes = (notes or "").strip()
    if not notes:
        return f"{lead}."
    if notes[-1] not in ".!?":
        notes += "."
    return f"{lead} — {notes}"


def _decision_relevant_finding_count(known_findings: dict) -> int:
    """Count Known Findings entries that bear on deployment confidence.

    Coverage Confidence answers "how thoroughly did we explore the solution
    space?" — Future Hardening Ideas are genuine evidence of that and must
    keep counting there (see _compute_trust_signals, unchanged). This
    function answers a different, narrower question — "should this
    recommendation itself be discounted?" — so it deliberately excludes
    future_hardening_ideas: those are explicitly out of the current
    advisory's scope and are not reasons to distrust this deployment
    recommendation, even though they're real findings worth knowing about.
    """
    return len(
        known_findings.get("potential_remaining_risks", [])
        + known_findings.get("validation_gaps", [])
        + known_findings.get("observed_implementation_notes", [])
        + known_findings.get("validation_hypotheses", [])
    )


def _check_recommendation_consistency(signals: dict, decision: str, known_findings: dict) -> list[str]:
    """Surface already-displayed evidence that a top-tier recommendation does
    not acknowledge on its own.

    Deterministic; no LLM calls beyond what finding_calibration already ran.
    Never alters `decision`. Returns an empty list when the decision is not
    top-tier, or when neither weak-evidence condition applies.

    "Not Verified" (the language-guardrail state for `test_availability`) is
    intentionally excluded from the "No Tests Found" check — it means the
    check could not run for this repository's language, not that tests are
    confirmed absent. Treating the two as equivalent would recreate, inside
    this fix, the exact kind of misleading conflation this fix exists to
    remove.

    The second caveat is intentionally NOT driven by coverage_confidence's
    own value/notes (unlike before) — Coverage Confidence answers "how much
    did we look" and legitimately includes Future Hardening Ideas; this
    caveat answers "should this recommendation be discounted" and must not,
    so it computes its own decision-relevant count from `known_findings`
    instead of reusing the Trust Signal's broader one.
    """
    if decision not in _TOP_TIER_DECISIONS:
        return []

    caveats: list[str] = []

    test_sig = signals.get("test_availability") or {}
    if test_sig.get("value") == "No Tests Found":
        caveats.append(
            _build_consistency_caveat(
                "This recommendation currently has no automated test coverage",
                test_sig.get("notes", ""),
            )
        )

    decision_relevant_count = _decision_relevant_finding_count(known_findings)
    if decision_relevant_count > 0:
        caveats.append(
            _build_consistency_caveat(
                "This recommendation's adversarial coverage is heuristic, not deterministically "
                "confirmed — see Review Results below for the validation questions and remaining "
                "uncertainties",
                f"{decision_relevant_count} decision-relevant finding(s) remain open",
            )
        )

    return caveats


# Presentation-only: the same rank convention build_validation_plan's own
# local `rank_map` already uses (HIGH=3, MEDIUM=2, LOW=1) — reused here, not
# reintroduced, purely to pick which already-computed item to echo.
_ACTION_PRIORITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _select_top_action(validation_actions: list[dict] | None) -> "dict | None":
    """Return the highest-priority item already in `validation_actions`, or
    None when the list is empty.

    Presentation only — does not reorder, filter, or recompute
    `validation_actions` itself (build_validation_plan's own order,
    priority, and count are untouched). This exists because index [0] is
    not reliably the highest-priority entry: build_validation_plan
    unconditionally prepends a MEDIUM-priority behavior-driven action ahead
    of any HIGH-priority item already present (see its own "behavior"
    block), so a naive `validation_actions[0]` can under-represent the true
    top priority. `max()` returns the first item on a tie, so display order
    for same-priority items still matches the list's own existing order.
    """
    if not validation_actions:
        return None
    return max(validation_actions, key=lambda a: _ACTION_PRIORITY_RANK.get(a.get("priority"), 0))


def _render_top_action_line(validation_actions: list[dict] | None) -> str:
    """Render a single "Top action" line for display immediately under
    Recommendation — the concise title only, never the action's reason or
    next_step (those already render in full, once, in Validation Actions
    below); this line exists only so a reader isn't required to scroll past
    Explanation to see the single most important next step. Returns ""
    when there is no meaningful action to show.
    """
    top = _select_top_action(validation_actions)
    if not top or not top.get("title"):
        return ""
    return f"\n**Top action:** {top['title']} — see Validation Actions below for the full list.\n"


def _render_manual_review_scope_note(decision: str, known_findings: dict) -> str:
    """Presentation-only scope note for Manual Review Required: surfaces the
    same decision-relevant finding count `_check_recommendation_consistency`
    already computes for the top two decisions (see
    `_decision_relevant_finding_count`), so a reader triaging Manual Review
    Required doesn't have to scroll to Review Results just to learn whether
    one item or several are open.

    Deliberately NOT the "Evidence check" caveat mechanism, and deliberately
    different wording from it: that mechanism exists to flag that a
    CONFIDENT-sounding recommendation may be undercut by evidence the reader
    hasn't seen yet. Manual Review Required already reads as cautious — this
    is scope information, not a warning, and never describes the open items
    as defects. Returns "" when the decision isn't Manual Review Required or
    when the count is zero (nothing to add beyond the reason already shown).
    """
    if decision != "Manual Review Required":
        return ""
    count = _decision_relevant_finding_count(known_findings)
    if count == 0:
        return ""
    noun = "item" if count == 1 else "items"
    verb = "remains" if count == 1 else "remain"
    return f"\n{count} decision-relevant review {noun} {verb} open — see Review Results below for details.\n"


def _render_recommendation_block(
    recommendation: dict,
    caveats: list[str] | None = None,
    scope_note: str = "",
    top_action_line: str = "",
) -> str:
    """Render just the Recommendation section (no leading rule — the caller's
    preceding block is expected to end with one, matching prior layout)."""
    lines: list[str] = []
    lines.append("## Recommendation\n")
    lines.append(f"**{recommendation['decision']}**\n")
    lines.append(f"{recommendation['reason']}\n")

    if top_action_line:
        lines.append(top_action_line)

    if scope_note:
        lines.append(scope_note)

    if caveats:
        for c in caveats:
            lines.append(f"> **Evidence check:** {c}")
        lines.append("")

    return "\n".join(lines) + "\n"


def _render_known_findings(findings: dict) -> str:
    """Render the Review Results section (includes its own leading rule).

    Five subsections, one per epistemic category from _build_known_findings.
    Only populated categories render; the whole section is omitted when all
    five are empty. Each subsection carries a one-line disclaimer stating its
    certainty level explicitly, so a reviewer never has to guess whether a
    bullet is a confirmed fact, a repository-backed observation, an unvalidated
    hypothesis, or an out-of-scope suggestion.
    """
    risks = findings.get("potential_remaining_risks") or []
    gaps = findings.get("validation_gaps") or []
    observed = findings.get("observed_implementation_notes") or []
    hypotheses = findings.get("validation_hypotheses") or []
    hardening = findings.get("future_hardening_ideas") or []

    if not (risks or gaps or observed or hypotheses or hardening):
        return ""

    lines: list[str] = ["---\n", "## Review Results\n"]
    lines.append(
        "*The bullet count below is not a count of confirmed defects — it "
        "reflects how many observations the review produced. Confirmed "
        "Observations, Validation Questions, and Future Improvements below "
        "carry different confidence levels; see each subsection's own note.*\n"
    )

    if risks:
        lines.append("### Potential Remaining Risks\n")
        lines.append(
            "*Flagged by heuristic adversarial review — not independently "
            "reproduced or deterministically confirmed.*\n"
        )
        for r in risks:
            lines.append(f"- {r}")
        lines.append("")

    if gaps:
        lines.append("### Validation Gaps\n")
        lines.append(
            "*Behaviors the challenger flagged as not yet verified — independent "
            "of whether the repository already has pre-existing tests for this "
            "module (see Trust Signals above; both can be true at once).*\n"
        )
        for g in gaps:
            lines.append(f"- {g}")
        lines.append("")

    if observed:
        lines.append("### Confirmed Observations\n")
        lines.append(
            "*Directly backed by the repository evidence or patch diff shown "
            "to the reviewer — not merely inferred.*\n"
        )
        for o in observed:
            lines.append(f"- {o}")
        lines.append("")

    if hypotheses:
        lines.append("### Validation Questions\n")
        lines.append(
            "*Plausible behaviors inferred from analysis, not directly observed "
            "in the evidence shown to the reviewer — these describe conditions "
            "under which something could happen, not confirmed outcomes, and "
            "should be validated.*\n"
        )
        for h in hypotheses:
            lines.append(f"- {h}")
        lines.append("")

    if hardening:
        lines.append("### Future Improvements\n")
        lines.append(
            "*Unrelated to the current advisory — these do not reduce confidence "
            "in the recommendation above.*\n"
        )
        for h in hardening:
            lines.append(f"- {h}")
        lines.append("")

    return "\n".join(lines) + "\n"


# Trust Signals v2 — question-style rows with one consistent status
# vocabulary (✅/⚠️/❌/?), replacing the old six-row table where "good"
# pointed in different directions per row (High vs. Low Risk) and three
# rows (security_improvement, remediation_alignment, coverage_confidence)
# were peer-displayed duplicates of the same underlying challenger counts.
#
# Display only: _compute_trust_signals still computes all six keys exactly
# as before (including security_improvement, which _build_recommendation_v1
# still reads directly) — this only changes which keys get their own row
# and how each value's status is worded.
# Fourth element per row: the section that holds this row's detail, or
# None when there isn't one. Only referenced when status isn't good — a row
# that's already fine has nothing further to send the reader to.
_TRUST_SIGNALS_V2_ROWS = [
    ("Does the patch apply?", "patch_integrity", {
        "Clean": "✅ Good",
        "Minor Issues": "⚠️ Needs review",
        "Critical Issues": "❌ Blocked",
        "Does Not Apply": "❌ Blocked",
        "Not Verified": "? Not verified",
    }, "Patch Applicability"),
    ("Does it address the vulnerability?", "remediation_alignment", {
        "Aligned": "✅ Good",
        "Likely Aligned": "⚠️ Needs review",
        "Partial": "⚠️ Needs review",
        "Misaligned": "❌ Blocked",
    }, "Review Results"),
    ("Are there unresolved concerns?", "coverage_confidence", {
        "High": "✅ Good",
        "Medium": "⚠️ Needs review",
        "Low": "❌ Blocked",
    }, "Review Results"),
    ("Do relevant tests already exist?", "test_availability", {
        "Tests Available": "✅ Good",
        "No Tests Found": "⚠️ Needs review",
        "Not Verified": "? Not verified",
    }, "Test Support"),
    ("Is deployment risk low?", "deployment_safety", {
        "Low Risk": "✅ Good",
        "Medium Risk": "⚠️ Needs review",
        "High Risk": "❌ Blocked",
        "Not Verified": "? Not verified",
    }, "Impact Surface"),
    # Evidence Sufficiency Gate (Phase 1, source_verification.py). Display
    # only, same as every other row here -- deliberately does NOT use "❌
    # Blocked" wording for "Unverified": unlike patch_integrity/
    # remediation_alignment, this signal does not yet drive
    # _build_recommendation_v1 (explicit product decision, see
    # source_verification.py's module docstring), so its status wording
    # describes what was observed rather than implying a policy consequence
    # that doesn't exist yet. No target_section: there is no dedicated
    # report section with hunk-level detail today, so this row's `notes`
    # (built in classify_source_verification) carry the detail inline
    # instead of pointing elsewhere.
    ("Was the edited content verified against the repository?", "source_verification", {
        "Confirmed": "✅ Good",
        "Position Unconfirmed": "⚠️ Needs review",
        "Unverified": "❌ Content not found",
        "Not Verified": "? Not verified",
    }, None),
]

def _render_trust_signals_table(signals: dict, known_findings_rendered: bool = True) -> str:
    """Render the Trust Signals table (includes its own leading rule).

    Every row whose status is not "✅ Good" gets an explicit pointer to the
    existing section heading that holds its detail, so "see below" always
    names a real destination. A row that's already good gets no pointer —
    there's nothing further to send the reader to.

    known_findings_rendered must reflect whether the Review Results section
    will actually render (see _build_known_findings) — remediation_alignment
    can still be non-good even when no finding list is populated (e.g.
    "Likely Aligned"), so the pointer to Review Results is suppressed for
    that row rather than risk a reference to a section that isn't there.

    The "Do relevant tests already exist?" row always carries a fixed bridge
    note, regardless of status: it answers only whether the repository
    already has related tests (Existing Test Coverage) — a separate question
    from whether the new patched behavior itself is validated (see Review
    Results -> Validation Gaps). Without this, "✅ Good" here can visually
    contradict a "no test validates this behavior" finding elsewhere, even
    though both are true and answer different questions.
    """
    lines: list[str] = []
    lines.append("---\n")
    lines.append("## Trust Signals\n")
    lines.append(
        "*Patch Integrity, Test Availability, and Deployment Risk are deterministic "
        "checks. Remediation Alignment and Coverage Confidence are derived from "
        "heuristic adversarial review, not independent verification.*\n"
    )
    lines.append("| Question | Status | Notes |")
    lines.append("|---|---|---|")
    for question, key, status_map, target_section in _TRUST_SIGNALS_V2_ROWS:
        sig = signals[key]
        value = sig["value"]
        status = status_map.get(value, "? Not verified")
        notes = sig["notes"].rstrip()
        effective_target = target_section
        if target_section == "Review Results" and not known_findings_rendered:
            effective_target = None
        if key == "test_availability":
            # Points at "Review Results" as a whole, not specifically its
            # Validation Gaps subsection: the challenger's own phrasing
            # determines which Review Results category a given "this isn't
            # validated" observation lands in (e.g. "no test appears to be
            # added validating X" classifies as a Behavior Note today, not a
            # Validation Gap) — verified against a real live challenger run,
            # not assumed. Naming a specific subsection here would risk
            # pointing at one that's empty while the relevant content sits
            # in another.
            bridge = "existing repository coverage only — new-behavior validation is tracked separately, see Review Results below"
            if status != "✅ Good" and effective_target:
                bridge += f"; see {effective_target} section below for existing coverage detail"
            notes = f"{notes} ({bridge})" if notes else bridge.capitalize()
        elif status != "✅ Good" and effective_target:
            notes = f"{notes} — see {effective_target} section below" if notes else \
                f"See {effective_target} section below"
        lines.append(f"| {question} | {status} | {notes} |")
    lines.append("")

    return "\n".join(lines) + "\n"


def _render_validation_actions_section(validation_actions: list[dict], decision: str = "") -> str:
    """Render Validation Actions (includes its own leading rule). Empty string
    when there are no actions, same as before the split.

    This is now the single, canonical checklist section — it includes each
    action's Reason as well as its Next step. A separate "Validation Plan"
    section used to repeat these same (already-capped-at-3) items lower in
    the report with Reason added; verified there was no other unique data
    in it, so it was removed rather than kept as a second name for the same
    checklist.

    `decision` only changes a leading note's wording (added when "Do Not
    Apply") — it does not change which actions are computed, their order,
    priority, or count.
    """
    if not validation_actions:
        return ""

    lines: list[str] = []
    lines.append("---\n")
    lines.append("## Validation Actions\n")
    if decision == "Do Not Apply":
        lines.append(
            "*This patch is not recommended for deployment. The items below "
            "apply only if a corrected patch is produced — not to this one.*\n"
        )
    for i, action in enumerate(validation_actions[:3], start=1):
        priority = action.get("priority", "")
        title = action.get("title", "")
        reason = action.get("reason", "")
        next_step = action.get("next_step", "")
        lines.append(f"{i}. **[{priority}]** {title}  ")
        if reason:
            lines.append(f"   Reason: {reason}  ")
        if next_step:
            lines.append(f"   Next step: {next_step}")
        lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Decision Card (Report Structure v2, Phase 1) — first-screen summary
#
# Renders only values already computed elsewhere (trust_rec, patch_integrity
# signal, validation_actions count, files_changed count). Adds no new
# analysis, no new signals, and does not alter recommendation policy,
# trust signal computation, or classification.
# ---------------------------------------------------------------------------

_DECISION_CARD_EMOJI = {
    "Deploy After Validation": "🟢",
    "Deploy With Caution": "🟡",
    "Manual Review Required": "🟠",
    "Do Not Apply": "🔴",
}

# Composed as "Patch {label}." — lowercase, verb-first, so it reads as a
# grammatical sentence in the Hero Banner (this is the "existing patch
# applicability label", reused, not a new signal).
_DECISION_CARD_PATCH_LABEL = {
    "Clean": "applies cleanly",
    "Minor Issues": "applies, with minor hygiene issues",
    "Critical Issues": "has critical issues",
    "Does Not Apply": "does not apply",
    "Not Verified": "was not verified",
}


def _render_decision_card(
    recommendation: dict,
    signals: dict,
    validation_actions: list[dict],
    files_changed: list[str],
) -> str:
    """Render the Decision Card as a first-screen Hero Banner.

    The large decision line (emoji + decision, as a heading) is the first
    visible content after the report title — it doubles as the anchor for
    tests/tooling, so no separate "## Decision Card" label is needed. Every
    field below it is read from a value the pipeline already computed
    elsewhere in this module — no new evidence gathering, no new signal
    derivation, no independent "confidence" judgment.
    """
    decision = recommendation["decision"]
    emoji = _DECISION_CARD_EMOJI.get(decision, "⚪")

    patch_value = signals["patch_integrity"]["value"]
    patch_label = _DECISION_CARD_PATCH_LABEL.get(patch_value, patch_value.lower())

    # Wording deliberately does not name a section — the Hero Banner must
    # stay valid even if section names or positions change elsewhere in the
    # report (they already have, more than once).
    action_count = len(validation_actions or [])
    if decision == "Do Not Apply":
        # "Before deployment" is actively misleading here — there is no
        # deployment to validate toward. These are the same already-computed
        # validation_actions, just described as applying to a future,
        # corrected patch rather than this one.
        if action_count == 0:
            validation_line = "This patch should not be deployed."
        elif action_count == 1:
            validation_line = (
                "This patch should not be deployed. "
                "The item below applies only to a corrected patch, not this one."
            )
        else:
            validation_line = (
                "This patch should not be deployed. "
                "The items below apply only to a corrected patch, not this one."
            )
    elif decision == "Manual Review Required":
        # Reviewer-experience fix: this previously fell through to the same
        # "before deployment" phrasing as Deploy After Validation / Deploy
        # With Caution, differing only by the headline word above — a
        # skim-only reader could easily read this banner as a near-green-
        # light. Manual Review Required means the policy could not
        # determine deployability from the evidence collected; deployment
        # is explicitly not the next step regardless of action_count.
        validation_line = (
            "This is not a signal to deploy — a human reviewer must "
            "resolve the open questions below first."
        )
    elif action_count == 0:
        validation_line = "No additional validation actions identified."
    elif action_count == 1:
        validation_line = "Complete the recommended validation check before deployment."
    else:
        validation_line = "Complete the recommended validation checks before deployment."

    lines = [
        f"## {emoji} {decision.upper()}\n",
        f"Patch {patch_label}.  ",
        f"{validation_line}  ",
        f"Files changed: {len(files_changed)}",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def _render_no_patch_card(files_changed: list[str]) -> str:
    """First-screen execution-outcome card for a run that produced no
    final candidate patch. Deliberately NOT a Recommendation Policy
    decision (see _build_recommendation_v1, left untouched) -- a report
    stating there is nothing to deploy, review, or validate must never
    reuse _render_decision_card's signals-driven wording, which would
    otherwise render a misleading "Patch was not verified." line for a
    patch that does not exist.
    """
    lines = [
        "## ⚫ NO PATCH PRODUCED\n",
        "The pipeline did not produce a final candidate patch.  ",
        "No patch is available for deployment or review.  ",
        f"Files changed: {len(files_changed)}",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def _render_deterministic_signals(
    constraint_signals: list[dict] | None,
    remediation_signals: list[dict] | None,
) -> str:
    """Render Deterministic Signals section as a Markdown string.

    Returns empty string when both signal lists are absent or empty.
    """
    all_signals = list(constraint_signals or []) + list(remediation_signals or [])
    if not all_signals:
        return ""

    _STATUS_ICON = {
        "green": "✓",
        "red": "✗",
        "n/a": "—",
        "yellow": "⚠",
        "violations": "⚠",
        "see evidence": "◑",
        "unknown": "◑",
    }

    def _icon(status: str) -> str:
        return _STATUS_ICON.get(status.lower().split()[0], "◑")

    lines: list[str] = ["---\n", "## Deterministic Signals\n"]
    lines.append("| Signal | Status |")
    lines.append("|--------|--------|")
    evidence_blocks: list[tuple[str, list[str]]] = []
    for sig in all_signals:
        name = sig.get("name", "")
        status = sig.get("status", "")
        icon = _icon(status)
        lines.append(f"| {name} | {icon} {status} |")
        # Collect evidence for RED / violation signals
        if status.lower().startswith("red") or "violation" in status.lower():
            ev = sig.get("evidence") or []
            if ev:
                evidence_blocks.append((name, ev))
    lines.append("")

    for name, ev in evidence_blocks:
        lines.append(f"**{name} — Evidence**\n")
        for item in ev[:5]:
            lines.append(f"- {item}")
        lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------


def _render_repair_notice(result: PipelineResult) -> str:
    """Return a short Markdown blockquote about the repair attempt, or empty string.

    Renders only what was actually observed. `repair_defect_count` is only a
    real, re-challenge-derived number when `repair_rechallenged` is True — it
    is otherwise an untouched default and must never be printed as if it were
    a finding.
    """
    if not result.repair_attempted:
        return ""
    if result.repair_succeeded:
        return (
            f"\n> **Auto-repaired:** Original patch had "
            f"{result.original_challenger_defect_count} confirmed defect(s). "
            f"A repair was generated and accepted — re-challenge found 0 confirmed defect(s).\n"
        )
    if result.repair_rechallenged:
        return (
            f"\n> **Repair attempted:** Challenger found "
            f"{result.original_challenger_defect_count} confirmed defect(s). "
            f"Repair patch still had {result.repair_defect_count} confirmed defect(s); "
            f"original recommendation stands.\n"
        )
    return (
        f"\n> **Repair attempted:** Challenger found "
        f"{result.original_challenger_defect_count} confirmed defect(s). "
        f"The repair patch did not reach re-challenge (it failed to apply, or the "
        f"repair loop encountered an unexpected error) — no repair defect count is "
        f"available; original recommendation stands.\n"
    )


def _render_retry_notice(result: PipelineResult) -> str:
    """Return a short Markdown blockquote about the applicability-aware retry
    attempt, or empty string when no retry occurred.

    Renders only the already-computed retry_attempted/retry_succeeded fields —
    does not re-derive, trigger, or otherwise affect retry behavior.
    """
    if not result.retry_attempted:
        return ""
    if result.retry_succeeded:
        outcome = "Retry succeeded — patch now applies cleanly."
    else:
        outcome = "Retry failed to produce an applicable patch."
    return (
        "\n\n> **Applicability-aware retry**\n"
        "> - Initial patch did not apply.\n"
        "> - Applicability-aware retry was attempted.\n"
        f"> - Outcome: {outcome}"
    )


def _build_report(result: PipelineResult) -> str:
    # === [A] Extract and prepare data ===
    summary = _extract_summary(result.vulnerability_text)
    review_sections = _split_review(result.review)
    challenger = result.challenger or {}
    behavior = result.behavior

    # Files touched by the unified diff — used by the Hero Banner's "Files
    # changed" count. "Impact Summary" and "Testing Notes" (which used to be
    # built here as restatements of Explanation/Known Findings/Reviewer
    # Notes) were removed as duplicated storytelling — each of their three-
    # to-four subsections repeated content already shown elsewhere verbatim
    # or near-verbatim.
    files_changed = []
    for line in (result.patch or "").splitlines():
        if line.startswith("+++ b/"):
            files_changed.append(line[6:].strip())

    # Report-level execution outcome -- NOT a Recommendation Policy value
    # (see _build_recommendation_v1, left untouched below). When the FINAL
    # result.patch is empty, there is nothing to deploy, review, or
    # validate, regardless of what the (still-computed) Recommendation
    # Policy signals say.
    no_patch = not (result.patch and result.patch.strip())

    # Build Patch Hygiene section
    hygiene_findings = result.hygiene or []
    if hygiene_findings:
        hygiene_lines = []
        for f in hygiene_findings:
            sev = f.get("severity", "?")
            detail = f.get("detail", "")
            hygiene_lines.append(f"- [{sev}] {detail}")
        hygiene_section = "\n".join(hygiene_lines)
    else:
        hygiene_section = "No obvious hygiene issues detected."

    # Build Patch Applicability section
    app = result.applicability or {}
    if not app or app.get("skipped"):
        reason = (app.get("skipped_reason") or "applicability check did not run")
        applicability_section = f"*(Skipped — {reason}.)*"
    elif app.get("error"):
        applicability_section = f"**Result:** ⚠ Error — {app['error']}"
    elif app.get("applicable") is True:
        applicability_section = "**Result:** ✓ Patch applies cleanly to the target repository."
    elif app.get("applicable") is False:
        stderr = (app.get("stderr") or "").strip()
        applicability_section = "**Result:** ✗ Patch does not apply cleanly."
        if stderr:
            applicability_section += f"\n\n```\n{stderr}\n```"
    else:
        applicability_section = "*(Applicability unknown.)*"

    # -----------------------
    # Hoist: Suggested Tests + Test Support + Validation Actions
    # (needed before Trust Package computation)
    # -----------------------
    adv_parts_early = []
    if challenger:
        for e in (challenger.get("edge_cases") or []):
            adv_parts_early.append(f"- {e}")
        for p in (challenger.get("potential_issues") or []):
            adv_parts_early.append(f"- {p}")
    adv_text_early = "\n".join(adv_parts_early).strip()
    findings_early = extract_findings(adv_text_early) if adv_text_early else []
    suggestions = suggest_tests(findings_early, behavior=behavior) if (findings_early or behavior) else []

    # F-01: no Path.cwd() fallback — when no repository root was provided,
    # this repository-dependent signal is skipped entirely rather than
    # analyzing whatever directory the process happens to run in.
    ts_root = result.repo_root
    target_file_display = "unknown"
    target_path_obj = None
    m = re.search(r"^\+\+\+ b/(.+)$", result.patch or "", re.MULTILINE)
    if m:
        target_rel = m.group(1).strip()
        target_file_display = target_rel
        if ts_root is not None:
            target_path_obj = ts_root / target_rel
    _report_language = result.detected_language or "python"
    matches: list = []
    rating = "None"
    delta = -0.15
    metadata: dict = {}
    total_tests_found = 0
    if ts_root is not None:
        all_tests = discover_tests(ts_root)
        total_tests_found = len(all_tests)
        if target_path_obj is not None:
            matches = tests_for_file(ts_root, target_path_obj)
        rating, delta, metadata = score_test_support(matches, language=_report_language)
    else:
        rating = "Not Verified"

    # -----------------------
    # Validation Actions (definition hoisted here)
    # -----------------------
    def build_validation_plan(challenger: dict, suggestions: list[dict], matches: list[dict], rating: str, impact: dict | None, behavior: dict | None = None) -> list[dict]:
        """Build up to 3 deterministic validation actions.

        Returns list of action dicts: {priority,title,reason,next_step}
        """
        actions: list[dict] = []

        def short_reason(text: str) -> str:
            if not text:
                return ""
            s = text.split(".", 1)[0].strip()
            s = re.sub(r"\s+", " ", s)
            return s[:120].rstrip("., ")

        def normalize_title_from_text(t: str) -> str:
            lt = (t or "").lower()
            if any(k in lt for k in ("db", "driver", "placeholder")):
                return "Verify database driver compatibility"
            if any(k in lt for k in ("unicode", "encoding", "binary")):
                return "Validate input handling edge cases"
            if any(k in lt for k in ("auth", "authenticate", "login", "token", "access", "permission")):
                return "Review authentication flow"
            parts = (t or "").split()
            return "Add targeted tests for " + " ".join(parts[:3])

        impact_level = (impact.get("impact_level") if impact else "low")
        impact_level = (impact_level or "low").lower()

        def compute_priority(base_medium=False) -> str:
            if impact_level == "high":
                return "HIGH"
            if impact_level == "medium" or base_medium:
                return "MEDIUM"
            return "LOW"

        # Suggested tests -> up to 2
        for s in (suggestions or [])[:2]:
            topic = s.get("name") or s.get("reason", "")
            title = normalize_title_from_text(topic)
            reason = short_reason(s.get("reason", "Suggested test")) or "Add targeted tests."
            base_medium = False
            if challenger and (challenger.get("edge_cases") or challenger.get("potential_issues")):
                base_medium = True
            if rating == "None":
                base_medium = True
            actions.append({"priority": compute_priority(base_medium), "title": title, "reason": reason, "next_step": "Add targeted tests for the identified behavior."})

        # Adversarial items -> up to 2
        adv_items = []
        if challenger:
            adv_items.extend(challenger.get("edge_cases", []) or [])
            adv_items.extend(challenger.get("potential_issues", []) or [])
        for item in adv_items[:2]:
            title = normalize_title_from_text(item)
            reason = short_reason(item) or "Adversarial finding requires validation."
            actions.append({"priority": compute_priority(True), "title": title, "reason": reason, "next_step": "Validate the finding via focused unit tests or manual review."})

        # Test support candidate -> max 1
        if rating != "Good":
            if rating == "None":
                reason = "No directly matching unit tests found for the patched module."
            else:
                reason = f"Test support rating: {rating}."
            actions.append({"priority": compute_priority(True if rating == "None" else False), "title": ("Improve validation coverage" if rating == "None" else "Increase targeted test coverage"), "reason": short_reason(reason), "next_step": "Add targeted tests exercising the patched behavior."})

        # Ensure a HIGH action exists for high impact
        if impact_level == "high" and not any(a["priority"] == "HIGH" for a in actions):
            imp_sum = short_reason(impact.get("impact_summary", "")) if impact else "High-impact change."
            title = "Review impacted flows"
            reason = ("High-impact: " + imp_sum)[:120]
            actions.append({"priority": "HIGH", "title": title, "reason": reason, "next_step": "Perform a targeted code review of affected flows."})

        rank_map = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        actions_sorted = sorted(actions, key=lambda a: (-rank_map.get(a["priority"], 1)))

        final: list[dict] = []
        type_counts = {"test": 0, "verify": 0, "review": 0, "other": 0}

        def action_type_from_title(t: str) -> str:
            lt = (t or "").lower()
            if "test" in lt:
                return "test"
            if any(k in lt for k in ("verify", "validate")):
                return "verify"
            if any(k in lt for k in ("review", "investigate")):
                return "review"
            return "other"

        for a in actions_sorted:
            if len(final) >= 3:
                break
            atype = action_type_from_title(a["title"])
            if type_counts.get(atype, 0) >= 2:
                continue
            final.append(a)
            type_counts[atype] = type_counts.get(atype, 0) + 1

        # Fallback only when no anchors
        if not final:
            no_suggestions = not (suggestions or [])
            no_adversarial = not (challenger and (challenger.get("edge_cases") or challenger.get("potential_issues")))
            if no_suggestions and no_adversarial and rating == "Good":
                final = [{"priority": "LOW", "title": "Perform quick manual review", "reason": "No automated anchors available; brief manual inspection advised.", "next_step": "Manually review the changed logic and adjacent call sites."}]

        for a in final:
            a["reason"] = short_reason(a.get("reason", ""))

        # Map next_step to more specific actions for known titles
        def specific_next_step(title: str, default: str) -> str:
            lt = (title or "").lower()
            if "database" in lt or "driver" in lt or "placeholder" in lt:
                return "Confirm the database driver placeholder style and add a focused compatibility test if needed."
            if "unicode" in lt or "encoding" in lt or "binary" in lt:
                return "Add targeted tests for unicode and binary username inputs."
            if title == "Improve validation coverage" or "validation coverage" in lt:
                return "Add focused tests that exercise the patched function/module."
            return default

        for a in final:
            a["next_step"] = specific_next_step(a.get("title"), a.get("next_step"))

        # If a behavior summary is provided, ensure a single behavior-driven
        # validation action is prepended. Keep this minimal and deterministic.
        if behavior:
            try:
                pbs = behavior.get("primary_behaviors") or []
                # comma-separated first 4 primary behaviors
                next_step = "Verify: " + ", ".join(pbs[:4]) if pbs else "Verify: (behavior validation)"
                beh_reason = short_reason(behavior.get("summary", ""))
                beh_action = {"priority": "MEDIUM", "title": "Validate behavior", "reason": beh_reason, "next_step": next_step}
                # Prepend but keep final limited to 3 actions by trimming the end
                final = [beh_action] + final
                if len(final) > 3:
                    final = final[:3]
            except Exception:
                # Non-fatal: ignore behavior-driven action on errors
                pass

        return final

    validation_actions = build_validation_plan(
        challenger, suggestions, matches, rating, result.impact, behavior
    )
    if no_patch:
        # Nothing to validate, deploy, or review for this outcome -- emptying
        # here (rather than special-casing every renderer that consumes this
        # list) means the existing "no validation actions" fallbacks already
        # in this module -- no Top Action, no Validation Actions section --
        # apply for free, with no changes to those renderers.
        validation_actions = []

    # -----------------------
    # Trust Package computation (uses hoisted data above)
    # -----------------------
    classified_challenger = _classify_challenger(challenger)
    impact_level_str = _resolve_impact_level(result.impact)  # I2
    signals = _compute_trust_signals(
        result.hygiene, result.applicability, classified_challenger, rating, impact_level_str
    )
    # Evidence Sufficiency Gate (Phase 1) -- merged in as a NEW key, separate
    # from _compute_trust_signals itself, so that function's own six-signal
    # computation and its I1-I6 Recommendation Policy invariants are never
    # touched by this addition. Falls back to a safe "Not Verified" default
    # (never "Confirmed") when the field is absent -- e.g. a hand-built
    # PipelineResult in a test, or a run with no repo_root.
    signals["source_verification"] = result.source_verification or {
        "value": "Not Verified", "label": "? Not Verified",
        "notes": "No source-verification data available for this run",
    }
    trust_rec = _build_recommendation_v1(
        signals,
        still_vulnerable=classified_challenger.get("still_vulnerable", False),
        defect_count=classified_challenger.get("confirmed_defect_count", 0),
    )
    # Demo polish: surface the already-computed decision on stdout the moment
    # it's known. Reuses the existing decision->emoji mapping (Hero Banner) —
    # no new value, no new classification.
    print(f"[pipeline] Recommendation:\n{_DECISION_CARD_EMOJI.get(trust_rec['decision'], '⚪')} {trust_rec['decision']}", file=sys.stderr)
    security_gain = _extract_security_gain(review_sections.get("explanation", ""))
    known_findings = _build_known_findings(classified_challenger, result.finding_calibration)
    # Gate the Trust Signals table's forward pointer on the same finding
    # categories that back remediation_alignment/coverage_confidence
    # (risks/hypotheses/observed/gaps) — Future Hardening Ideas isn't
    # relevant to either signal, so it doesn't justify pointing a reader there.
    known_findings_relevant = bool(
        known_findings["potential_remaining_risks"]
        or known_findings["observed_implementation_notes"]
        or known_findings["validation_hypotheses"]
        or known_findings["validation_gaps"]
    )
    consistency_caveats = _check_recommendation_consistency(signals, trust_rec["decision"], known_findings)
    manual_review_scope_note = _render_manual_review_scope_note(trust_rec["decision"], known_findings)
    top_action_line = _render_top_action_line(validation_actions)
    if no_patch:
        # Execution outcome, not a Recommendation Policy presentation --
        # _build_recommendation_v1's result (trust_rec, computed above) is
        # intentionally not read here; the normal Manual Review Required /
        # Deploy / Do Not Apply bottom line must never appear for an empty
        # final patch.
        decision_card = _render_no_patch_card(files_changed)
        recommendation_block = ""
    else:
        decision_card = _render_decision_card(trust_rec, signals, validation_actions, files_changed)
        recommendation_block = _render_recommendation_block(
            trust_rec,
            caveats=consistency_caveats,
            scope_note=manual_review_scope_note,
            top_action_line=top_action_line,
        )
    trust_signals_block = _render_trust_signals_table(signals, known_findings_rendered=known_findings_relevant)
    known_findings_block = _render_known_findings(known_findings)
    validation_actions_block = _render_validation_actions_section(validation_actions, trust_rec["decision"])
    primary_refs_block = _render_primary_references(_extract_primary_references(result.vulnerability_text))

    # -----------------------
    # Assemble report
    #
    # Order (reviewer-experience redesign): Hero Banner, Vulnerability
    # Summary, Primary Vulnerability References, Proposed Patch, Patch
    # Hygiene, Patch Applicability, Trust Signals, Recommendation,
    # Explanation, Validation Actions, Review Results, Repository Context,
    # Impact Surface, Appendices. Run Metadata / Stage Stop Reasons are
    # appended by main.py after this function returns — not rendered here.
    #
    # Repository Context answers "which repository locations informed this
    # work, and why?" — deliberately independent of Trust Signals ("how much
    # evidence supports trusting this patch?"). Placed immediately before
    # Impact Surface, sourced from ground_repository(), not from the
    # find_code_context() call already feeding LLM prompts.
    #
    # Rationale: a reviewer first wants to know what is broken and what
    # patch is proposed — only then do Trust Signals become meaningful.
    # Trust Signals moved after the patch instead of leading, reversing the
    # previous redesign's placement. Patch Hygiene and Patch Applicability
    # (the report's only two fully deterministic checks) were promoted from
    # Appendices to sit directly beside the diff they describe — a reviewer
    # who trusts deterministic evidence over LLM narrative should not have to
    # scroll past Explanation/Validation Actions/Review Results to reach the
    # actual git-apply result.
    #
    # "Impact Summary" and "Testing Notes" are gone entirely — both were
    # restatements of Explanation / Review Results / Reviewer Notes, not
    # unique content (verified against a real generated report: "Why it
    # matters" was byte-identical to Explanation's own text). Reviewer Notes
    # moved into Appendices — it is supplementary reviewer advice, not part
    # of the core "understand this in 30 seconds" flow.
    #
    # This reorders, relabels, and removes duplicated content only: no
    # change to how `patch`, `challenger`, `signals`, `trust_rec`, or
    # `classified_challenger` are computed. `validation_actions` and the
    # Hero Banner/Recommendation presentation are the two exceptions,
    # overridden for the `no_patch` execution-outcome state above.
    # -----------------------

    # §1: Header + Hero Banner
    report = f"""\
# Auto Patcher MVP — Security Patch Report

{decision_card}
"""

    # §2: Vulnerability Summary
    report += f"""## Vulnerability summary

{summary}

"""

    # §3: Primary Vulnerability References
    report += primary_refs_block

    # §4: Proposed Patch
    report += f"""## Proposed patch

{"*No final candidate patch was produced.*" if no_patch else result.patch.strip()}

"""

    # §4b: Promoted deterministic evidence — Patch Hygiene and Patch
    # Applicability (plus the retry/repair notices that describe attempts to
    # fix applicability) are the only two fully deterministic checks in this
    # report. Promoted here from Appendices so they sit next to the diff they
    # describe, rather than after ~200 lines of heuristic narrative (Trust
    # Signals' own "Does the patch apply?" row already points here).
    report += f"""## Patch Hygiene

{hygiene_section}

## Patch Applicability

{applicability_section}"""

    # Applicability-aware retry notice — rendered only when a retry actually
    # occurred; resolves to "" otherwise.
    report += _render_retry_notice(result)
    report += "\n"

    # Repair notice (Phase C)
    repair_notice = _render_repair_notice(result)
    if repair_notice:
        report += repair_notice
    report += "\n"

    # §5: Trust Signals
    report += trust_signals_block

    # §6: Recommendation
    report += recommendation_block

    # §7: Explanation — absorbs Known Security Gain as a lead-in. security_gain
    # is itself an extracted sentence from this same explanation text (or, on
    # the fallback path, a truncated first paragraph of it) — kept as a
    # callout rather than dropped. When it's a verbatim match (the common
    # case), that one copy is stripped from the body below so the sentence
    # isn't shown twice; the fallback (truncated, non-verbatim) copy is left
    # in place since it isn't a duplicate of the full text. A standing
    # disclaimer states the epistemic status of this whole section once,
    # rather than requiring per-sentence hedging of LLM-generated prose this
    # pipeline cannot rewrite without a new semantic classifier.
    report += "---\n\n## Explanation\n\n"
    report += (
        "*This explanation reflects the reviewer LLM's analysis of the advisory, "
        "diff, and any injected code context — not independent execution or "
        "testing against the target repository.*\n\n"
    )
    explanation_text = review_sections["explanation"]
    if security_gain:
        report += f"**Security gain:** {security_gain}\n\n"
        # security_gain is extracted verbatim from this same explanation
        # text (see _extract_security_gain) — drop that one copy from the
        # body so the sentence isn't shown twice.
        if security_gain in explanation_text:
            explanation_text = explanation_text.replace(security_gain, "", 1)
            explanation_text = re.sub(r"^[ \t]+", "", explanation_text, flags=re.MULTILINE)
            # Rendering-only fix: when the stripped sentence was the entire
            # body of a numbered/bulleted list item, removing it leaves a
            # bare marker behind (e.g. a dangling "1." with nothing after
            # it). Drop such now-empty marker lines — a list marker with no
            # body is never meaningful output, regardless of why it emptied.
            explanation_text = re.sub(r"^[ \t]*(?:\d+\.|[-*])[ \t]*\n", "", explanation_text, flags=re.MULTILINE)
            explanation_text = re.sub(r"\n{3,}", "\n\n", explanation_text).strip()
    report += f"""{explanation_text}

"""

    # §8: Validation Actions
    report += validation_actions_block

    # §9: Review Results
    report += known_findings_block

    # §9b: Repository Context (Repository Grounding)
    if result.repo_root is None:
        # F-01: grounding was never attempted here (no repo to search) --
        # distinct from _render_repository_context_section(None)'s
        # zero-selection sentence, which describes a search that ran and
        # selected nothing. Reusing that sentence would read as if a
        # repository search happened and came up empty.
        report += (
            "---\n\n## Repository Context\n\n"
            "*Not evaluated — no repository root was provided.*\n\n"
        )
    else:
        report += _render_repository_context_section(result.grounding)

    # §9c: Post-Patch Investigation
    if result.post_patch_observations is None:
        # Distinct wording from the "no repository root was provided" guard
        # above (F-01, §9b/§10/Test Support) -- reusing that exact string
        # here would inflate its count in tests that assert on it, and it
        # also isn't the only reason this section can be unevaluated (no
        # anchors, or an internal failure, both also land here).
        report += (
            "---\n\n## Post-Patch Investigation\n\n"
            "*Not evaluated for this run (no repository root, no anchors "
            "to re-evaluate, or the investigation itself did not "
            "complete).*\n\n"
        )
    elif result.patch != result.post_patch_investigated_patch:
        report += (
            "---\n\n## Post-Patch Investigation\n\n"
            "*Not shown — the patch was revised after this evidence was "
            "computed, and it no longer describes the reported patch.*\n\n"
        )
    else:
        report += "---\n\n" + render_post_patch_investigation(
            result.post_patch_observations, result.post_patch_coverage
        ) + "\n"

    # §10: Impact Surface
    if result.impact:
        try:
            imp = result.impact
            report += "---\n\n## Impact Surface\n\n"
            report += (
                "*Static, AST-based usage analysis — does not execute the code, and may not "
                "fully represent dynamic dispatch, reflection, or other runtime-only behavior.*\n\n"
            )
            report += f"**Summary:** {imp.get('impact_summary', '')}\n\n"
            report += f"- Changed files: {len(imp.get('changed_files', []))}\n"
            report += f"- Affected files: {len(imp.get('affected_files', []))}\n"
            report += f"- Impact level: {imp.get('impact_level', 'unknown').upper()}\n"
            recs = imp.get('recommendations', [])
            if recs:
                report += f"- Recommendations: {', '.join(recs)}\n"
            ums = imp.get('usage_matches', []) or []
            if ums:
                report += "\n**Top evidence:**\n"
                for u in ums[:3]:
                    report += f"- {u.get('symbol')} — {u.get('file')}:{u.get('line')} — {u.get('snippet')}\n"
            report += "\n"
        except Exception:
            pass
    elif result.repo_root is None:
        # F-01: state the gap explicitly rather than silently omitting the
        # section — a reader must not mistake "not shown" for "clean".
        report += "---\n\n## Impact Surface\n\n"
        report += "*Not evaluated — no repository root was provided.*\n\n"

    # §11: Appendices — diagnostics, supplementary reviewer notes, and legacy
    # sections, consolidated. Patch Hygiene and Patch Applicability (plus
    # their retry/repair notices) moved out of here to sit next to the diff
    # (§4b above) — they are deterministic evidence, not supplementary.
    report += "---\n\n## Appendices\n\n"

    # Deterministic signals section (Phase I)
    det_section = _render_deterministic_signals(result.constraint_signals, result.remediation_signals)
    if det_section:
        report += "\n" + det_section

    # Language Coverage — only rendered when a Python-only signal was skipped.
    if _report_language != "python":
        try:
            from .vulnerability_patterns import classify_vuln_class, sink_scanning_supported

            _gaps = [
                "Test Support (test-file discovery only recognizes `test_*.py` / `*_test.py`)",
                "Impact Surface (changed-symbol and usage-impact analysis only supports Python source)",
            ]
            if classify_vuln_class(result.vulnerability_text) and not sink_scanning_supported(_report_language):
                _gaps.append(
                    "Vulnerability-pattern sink-checklist scanning "
                    "(only recognizes Python `def` syntax and `*.py` files)"
                )
            report += "\n### Language Coverage\n\n"
            report += f"**Detected repository language:** {_report_language}\n\n"
            report += (
                "The following deterministic signals are Python-only and do not "
                "yet support this language. They are marked Not Applicable in the "
                "Test Support and Impact Surface sections below, and must not be "
                "read as a clean or verified result:\n\n"
            )
            for _gap in _gaps:
                report += f"- {_gap}\n"
            report += "\n"
        except Exception:
            pass

    # Test Support
    if result.repo_root is None:
        # F-01: state the gap explicitly rather than silently omitting the
        # section — a reader must not mistake "not shown" for "clean".
        test_support_md = (
            "\n### Test Support\n\n"
            "*Not evaluated — no repository root was provided.*\n\n"
        )
    else:
        test_support_md = (
            "\n### Test Support\n\n"
            "*This section reports existing repository tests, not behavioral "
            "validation of the proposed patch.*\n\n"
            f"- Target file: {target_file_display}\n"
            f"- Total test files found: {total_tests_found}\n"
            f"- Rating: {rating}\n"
            "\n#### Matching tests\n"
        )
        if matches:
            has_direct = any(m.get("proximity") in ("same-file", "same-module") for m in matches)
            if not has_direct:
                test_support_md += "- No tests directly matched the patched file/module.\n"
            for m in matches:
                prox_label = m['proximity'] if m['proximity'] != 'repo' else 'repo (context)'
                test_support_md += f"- {m['path']} — {prox_label} — {m['reason']}\n"
        else:
            test_support_md += "- No matching tests found.\n"
    report += test_support_md

    # Behavior Summary
    if behavior:
        try:
            report += "\n### Behavior Summary\n\n"
            # behavior["function"] is a regex-based `def` scan over the diff
            # and is empty for non-function edits (e.g. a class-level
            # constant). Fall back to the AST-resolved changed_symbols from
            # Impact Surface — the same data already shown in that section —
            # before omitting the sentence entirely.
            func = behavior.get("function") or ""
            if not func:
                changed_symbols = (result.impact or {}).get("changed_symbols") or []
                if changed_symbols:
                    func = changed_symbols[0]
            bfile = behavior.get("file") or ""
            if func and bfile:
                report += f"This patch appears to modify `{func}` in `{bfile}`.\n\n"
            report += behavior.get("summary", "") + "\n\n"
            pbs = behavior.get("primary_behaviors") or []
            if pbs:
                report += "Primary behaviors to validate:\n"
                for p in pbs:
                    report += f"- {p}\n"
            report += "\n"
        except Exception:
            pass

    # Affected areas — a distinct reviewer-LLM output field, not duplicated
    # elsewhere in the report.
    report += f"""
### Affected areas

{review_sections["affected_areas"]}
"""

    # Reviewer Notes — reviewer-specific advice not captured by Explanation,
    # Validation Actions, or Known Findings. Moved into Appendices: it is
    # supplementary, not part of the core "understand this in 30 seconds" flow.
    report += f"""
### Reviewer Notes

*Reviewer-LLM guidance, not independently verified evidence.*

{review_sections["validation_notes"]}
"""

    # ("Validation Plan" stays removed — it repeated the same ≤3 items
    # already shown in full, with Reason included, in the Validation
    # Actions section near the top of the report.)

    # Suggested Tests
    adv_parts: list[str] = []
    if challenger:
        if challenger.get("edge_cases"):
            adv_parts.append("Edge cases:")
            for e in challenger.get("edge_cases", []):
                adv_parts.append(f"- {e}")
        if challenger.get("potential_issues"):
            adv_parts.append("Potential issues:")
            for p in challenger.get("potential_issues", []):
                adv_parts.append(f"- {p}")

    # Presentation-only: name, reason, and suggested filename only — the
    # generated pytest skeleton bodies are not rendered here (still the same
    # `suggestions` list; nothing about what's suggested or how many changed,
    # only how much of each one is printed).
    suggested_md = "\n### Suggested Tests\n\n"
    suggested_md += "Generated from adversarial findings. Not automatically written to the repo.\n\n"
    if not suggestions:
        suggested_md += "- No actionable adversarial findings found.\n"
    else:
        for s in suggestions:
            test_name = s.get("name")
            s_reason = s.get("reason")
            suggested_file = f"tests/suggested/{test_name}.py"
            suggested_md += f"- **{test_name}** — {suggested_file}\n"
            suggested_md += f"  Based on finding: \"{s_reason}\"\n"
    report += suggested_md

    return report


# ---------------------------------------------------------------------------
# Applicability-aware retry helpers
# ---------------------------------------------------------------------------

_PATCH_FAILED_RE = re.compile(r"^error: patch failed: (.+?):\d+", re.MULTILINE)
_DOES_NOT_APPLY_RE = re.compile(r"^error: (.+?): patch does not apply", re.MULTILINE)
_PLUS_PLUS_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)
_RETRY_CONTENT_LIMIT = 50_000
_RETRY_STDERR_LINES = 6


def _extract_failed_files(stderr: str) -> list[str]:
    """Every file named in git-apply failure stderr, in stderr order,
    de-duplicated (a file matched by both regexes appears once). Patch-failed
    matches are collected before does-not-apply matches, so the priority
    established by the old single-file `_extract_failed_file` is preserved.
    """
    stderr = stderr or ""
    names = [m.group(1).strip() for m in _PATCH_FAILED_RE.finditer(stderr)]
    names += [m.group(1).strip() for m in _DOES_NOT_APPLY_RE.finditer(stderr)]
    return list(dict.fromkeys(names))


def _extract_failed_file(stderr: str) -> str | None:
    files = _extract_failed_files(stderr)
    return files[0] if files else None


def _extract_patch_target(patch: str) -> str | None:
    lines = (patch or "").splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    m = _PLUS_PLUS_RE.search("\n".join(lines))
    return m.group(1).strip() if m else None


def _build_repair_hint(confirmed_texts: list[str]) -> str:
    """Build a repair instruction for the patch generator from confirmed defect texts."""
    items = "\n".join(f"- {t}" for t in confirmed_texts)
    return (
        "The previous patch has the following confirmed security gap(s) identified "
        "by adversarial review:\n\n"
        f"{items}\n\n"
        "Regenerate the patch to address these specific gaps.\n"
        "Do not use a perimeter validation check (such as startswith or a normpath guard) "
        "if the correct fix requires changing the dangerous operation itself.\n"
        "If the vulnerability requires a helper function, the same patch must call that "
        "helper from every vulnerable code path — not a subset of them.\n"
        "Use the repository code context shown above as the ground truth for the code.\n"
        "Keep the same minimal-diff approach: change only what is necessary."
    )


def _build_retry_hint(stderr: str, failed_file: str) -> str:
    excerpt_lines = (stderr or "").splitlines()[:_RETRY_STDERR_LINES]
    excerpt = "\n".join(excerpt_lines)
    return (
        f"The previous patch attempt failed to apply to `{failed_file}`.\n\n"
        f"Git error:\n```\n{excerpt}\n```\n\n"
        "The patch context lines did not match the actual file content.\n"
        "Regenerate the patch using **only** the code shown in the "
        "\"Repository code context\" section above.\n"
        "Do not use your training-data memory of this file — "
        "the code above is the ground truth.\n"
        "Keep the same fix logic; only update the surrounding context lines "
        "to match the actual code exactly."
    )


# ---------------------------------------------------------------------------
# Phase E experiment — hand-written plan loader
# ---------------------------------------------------------------------------

_PHASE_E_PLANS_DIR = Path(__file__).parent.parent / "evaluation" / "phase_e"
_GHSA_RE = re.compile(r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}")


def _load_experiment_plan(vulnerability_text: str) -> str:
    """Phase E experiment: return hand-written plan markdown for a known GHSA, or ''.

    Appended as the final context block before generate_patch(). Never raises.
    Has no effect when no plan file exists for the matched GHSA.
    """
    m = _GHSA_RE.search(vulnerability_text)
    if not m:
        return ""
    plan_path = _PHASE_E_PLANS_DIR / f"{m.group(0)}.md"
    if not plan_path.exists():
        return ""
    try:
        text = plan_path.read_text(encoding="utf-8")
        print(f"[pipeline] Phase E plan loaded for {m.group(0)} ({len(text)} chars).", file=sys.stderr)
        return text
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Post-Patch Recovery -> ReadyEdit reconciliation (Slice 4)
#
# Post-Patch Recovery's own certification that a target now has verified,
# patch-ready source must reach the SECOND (post-regeneration) Patch Target
# Conformance check, or a regenerated patch re-targeting the very file
# recovery just verified fails closed unconditionally regardless of match
# quality. This promotes a recovery attempt to a real ReadyEdit -- the
# exact shape check_edit_readiness itself already produces -- rather than
# passing the attempt object through structurally: check_patch_target_
# conformance currently reads only `.file` off each ready_edits element,
# but this must keep working even if that ever reads `.symbol` too.
# ---------------------------------------------------------------------------


def _recovered_ready_edit(attempt):
    """Promote one Post-Patch Recovery attempt to a real ReadyEdit, using
    ONLY its deterministically verified recovery identity
    (resolved_file/resolved_target) -- never the original, possibly-
    unexpected `attempt.file`. Returns None when the attempt does not
    clear every verification bar (success, patch_ready, a real
    resolved_file) -- a partial or failed attempt is never promoted."""
    if not (attempt.success and attempt.patch_ready and attempt.resolved_file is not None):
        return None
    from .remediation_planner import IntendedEdit, ReadyEdit
    edit = IntendedEdit(file=attempt.resolved_file, symbol=attempt.resolved_target)
    return ReadyEdit(
        edit=edit, role="edit_target",
        file=attempt.resolved_file, symbol=attempt.resolved_target,
    )


def _prior_supported_target_files(plan_result, strategy_result) -> "set[str]":
    """Files with prior support BEFORE Patch Generation ran -- Target
    Discovery's own (unverified) target_files, or Final Strategy's
    deterministically re-verified target_files. File-level only: this is
    the evidence floor a recovered target's resolved FILE must clear to be
    promoted (see _recovered_ready_edit) -- it deliberately does not also
    require the exact recovered SYMBOL to have been named up front, since
    recovery discovering a better symbol inside an already-supported file
    is exactly what this slice exists to allow (a file already named by
    Target Discovery or Final Strategy, with the wrong symbol initially
    proposed inside it, where recovery later finds the real one -- the
    file itself was never a new, unsupported target)."""
    return (
        set(plan_result.target_files if plan_result is not None else [])
        | set(strategy_result.target_files if strategy_result is not None else [])
    )


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------


def run(
    vulnerability_text: str,
    api_key: str = "",
    repo_root: str | Path | None = None,
    investigation_output_dir: str | Path | None = None,
    budget_controller: "object | None" = None,
) -> str:
    """
    Execute the full patching pipeline.

    Parameters
    ----------
    vulnerability_text:
        The vulnerability description as a string (Markdown).  The caller is
        responsible for reading a file or fetching an advisory before calling
        this function.
    api_key:
        Optional OpenAI API key.  When empty the pipeline uses mock responses.
    investigation_output_dir:
        Optional run-scoped directory for the deterministic Repository
        Understanding investigation's parser artifacts (candidate_enrichment.
        build_investigation_context's analyzer_output.json/call_graph.json).
        When omitted, investigation still runs (selection + fusion +
        rendering) but candidate enrichment degrades to its existing
        file/test/sink-only mode -- no parse/call-graph/reachability -- same
        as when candidate_enrichment.enrich_candidates() is given
        context=None. Callers that don't pass this (all existing callers)
        are unaffected beyond that graceful degradation.
    budget_controller:
        Optional utilities.autopatcher.context_budget.ContextBudgetController,
        threaded unmodified into Slices 2/3/4's own acquisition/recovery
        calls (run_deterministic_acquisition/run_guided_acquisition/
        recover_post_patch_source) -- the ONLY thing that lets a soft
        character budget exhausted purely by capacity (never a safety/
        verification failure) be extended by one more fixed-size window,
        with the user's approval, instead of failing the run closed. This
        is the CLI's responsibility to build (see openant/cli.py's `patch`
        command --context-budget-policy/--max-context-budget-windows) --
        `None` (every existing caller, and any library caller) preserves
        the pre-existing fixed-budget behavior exactly, with zero
        interactive prompts from this module.

    Returns
    -------
    str
        The formatted Markdown report.
    """

    # Ensure downstream challenger reads the same API key if provided.
    os.environ.setdefault("OPENAI_API_KEY", api_key or os.environ.get("OPENAI_API_KEY", ""))

    llm = LLMClient(api_key=api_key)
    mode = "MOCK" if llm.is_mock else "LIVE"
    print(f"[pipeline] LLM mode: {mode}", file=sys.stderr)

    # Experiment H1: plan first, then repo code, then vulnerability pattern guidance.
    # Previously: repo code → vuln patterns → plan.
    # H1 hypothesis: placing plan constraints before repo code reduces prior-override failures.
    _plan_text = _load_experiment_plan(vulnerability_text)

    # Locate relevant code from the target repository (best-effort).
    _repo_code = ""
    _grounding: RepositoryGroundingResult | None = None
    if repo_root:
        from .repo_locator import ground_repository
        _grounding = ground_repository(vulnerability_text, Path(repo_root))
        _repo_code = _grounding.rendered_context
        if _repo_code:
            print(f"[pipeline] Code context found ({len(_repo_code)} chars); injecting into patch prompt.", file=sys.stderr)
        else:
            print("[pipeline] No code context found in repo; patch will be best-effort.", file=sys.stderr)

    # Phase C.5: inject vulnerability class guidance (canonical patterns + sink coverage).
    # Pass _repo_code (not the accumulated context) so sink detection scans only source code.
    _pattern_ctx = ""
    try:
        from .vulnerability_patterns import build_vulnerability_pattern_context
        _pattern_ctx = build_vulnerability_pattern_context(
            vulnerability_text, _repo_code, Path(repo_root) if repo_root else None
        )
        if _pattern_ctx:
            print(f"[pipeline] Vulnerability class guidance injected ({len(_pattern_ctx)} chars).", file=sys.stderr)
    except Exception:
        pass

    # Deterministic Repository Understanding: bounded candidate selection +
    # enrichment + fusion, reusing the same _grounding computed above (no
    # second ground_repository() call, no second candidate set). Best-effort
    # -- any failure degrades to today's existing repo_code/pattern_ctx
    # context rather than aborting the run. Rendered only when selection
    # actually found something to select (CandidateSelection.used_fallback
    # documents this as the caller's cue to fall back to existing behavior).
    _repository_understanding: RepositoryUnderstanding | None = None
    _repository_understanding_ctx = ""
    _pre_patch_anchors: list | None = None
    _investigation_context = None  # InvestigationContext | None -- only set below when
    # investigation_output_dir is provided and grounding/selection succeed; kept as a
    # top-level local so the Post-Patch Investigation block below (which reuses it for
    # Coverage Analysis) can safely check it without a NameError on every other path.
    if _grounding is not None:
        try:
            from .candidate_enrichment import build_investigation_context, enrich_candidates
            from .candidate_selection import select_candidates
            from .evidence_fusion import fuse_evidence, render_repository_understanding

            _selection = select_candidates(_grounding)
            if not _selection.used_fallback:
                _investigation_context = None
                if investigation_output_dir:
                    _investigation_context = build_investigation_context(
                        Path(repo_root), Path(investigation_output_dir)
                    )
                enrich_candidates(_selection, Path(repo_root), vulnerability_text, _investigation_context)
                _repository_understanding = fuse_evidence(
                    _selection, investigation_context_available=_investigation_context is not None
                )
                _repository_understanding_ctx = render_repository_understanding(_repository_understanding)
                if _repository_understanding_ctx:
                    print(
                        f"[pipeline] Repository Understanding rendered "
                        f"({len(_repository_understanding_ctx)} chars).",
                        file=sys.stderr,
                    )

                from .post_patch_investigation import derive_pre_patch_anchors
                _pre_patch_anchors = derive_pre_patch_anchors(_repository_understanding)
        except Exception as exc:
            print(
                f"[pipeline] Repository Understanding unavailable: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )

    # Experimental: Remediation Planner. One bounded LLM call that asks the
    # model to commit to a narrow remediation strategy before Patch
    # Generation runs, using exactly the evidence already assembled above.
    # Not verified against the repository by itself -- an intentionally
    # minimal proof-of-concept, not a trust boundary on its own. Skipped
    # when a hand-authored plan (_plan_text) already exists. Best-effort:
    # any failure degrades to no plan, same as every other optional
    # context section.
    _plan_ctx = ""
    _planner_evidence_ctx = ""
    _plan_result = None  # set below only when the Planner actually runs; read again
    # much further down (as a source of "files already connected via Planner
    # evidence") by the Final-Target Remediation Slice builder.
    if not _plan_text:
        try:
            from .remediation_planner import build_planner_evidence, generate_remediation_plan
            _evidence_so_far = "\n\n".join(
                p for p in [_repo_code, _pattern_ctx, _repository_understanding_ctx] if p and p.strip()
            )
            _plan_result = generate_remediation_plan(vulnerability_text, llm, code_context=_evidence_so_far)
            _plan_ctx = _plan_result.rendered
            if _plan_ctx:
                print(f"[pipeline] Remediation plan generated ({len(_plan_ctx)} chars).", file=sys.stderr)

            # Deterministic bridge: verify the Planner's proposed files/symbols
            # against the real repository, then run only what verifies through
            # the SAME enrich_candidates/fuse_evidence/render_repository_
            # understanding chain already used above -- reusing
            # _investigation_context as-is, never rebuilding it. No new LLM
            # call happens here. Kept in its own try/except so a failure here
            # can never suppress the plan text itself, gathered just above.
            try:
                _planner_evidence_ctx = build_planner_evidence(
                    _plan_result, repo_root, vulnerability_text, _investigation_context
                )
                if _planner_evidence_ctx:
                    print(
                        f"[pipeline] Planner-proposed candidate evidence rendered "
                        f"({len(_planner_evidence_ctx)} chars).",
                        file=sys.stderr,
                    )
            except Exception as exc:
                print(f"[pipeline] Planner candidate evidence unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        except Exception as exc:
            print(f"[pipeline] Remediation planning unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)

    # Final Strategy: a second, distinct Planner call (stage
    # "remediation_strategy") that runs only once verified Planner evidence
    # exists -- it receives materially new evidence (the verified structural
    # facts and source excerpts above) the first call never saw, and is not
    # a blind retry of it. Skipped entirely (no LLM call) when
    # _planner_evidence_ctx is empty -- generate_remediation_strategy enforces
    # this itself. Best-effort: any failure here leaves the Target Discovery
    # Plan and Planner-Proposed Candidate Evidence exactly as already
    # gathered, and the pipeline continues without a Final Strategy section.
    _strategy_ctx = ""
    _strategy_result = None  # read again below by the Final-Target Remediation Slice builder
    if _planner_evidence_ctx:
        try:
            from .remediation_planner import generate_remediation_strategy
            _strategy_result = generate_remediation_strategy(
                vulnerability_text, llm, repo_root, _investigation_context,
                repo_grounding_ctx=_repo_code,
                repository_understanding_ctx=_repository_understanding_ctx,
                discovery_plan_ctx=_plan_ctx,
                planner_evidence_ctx=_planner_evidence_ctx,
            )
            _strategy_ctx = _strategy_result.rendered
            if _strategy_ctx:
                print(
                    f"[pipeline] Final remediation strategy generated "
                    f"({len(_strategy_ctx)} chars).",
                    file=sys.stderr,
                )
            if _strategy_result.warnings:
                print(
                    f"[pipeline] Final strategy dropped unverified item(s): "
                    f"{_strategy_result.warnings}",
                    file=sys.stderr,
                )
        except Exception as exc:
            print(f"[pipeline] Final remediation strategy unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)

    # Final-Target Remediation Slice: deterministic, bounded exact source
    # built ONLY from generate_remediation_strategy()'s VERIFIED result --
    # never the earlier, exploratory Target Discovery candidates, so
    # source budget is never spent on a candidate the Final Strategy
    # already rejected. No new LLM call (build_final_target_slice takes no
    # `llm` parameter), no new repository parse -- reuses
    # _investigation_context as-is. Best-effort: any failure degrades to a
    # short note and the pipeline continues with whatever context already
    # exists; only a genuinely ZERO-coverage Final Strategy result (one
    # that named targets but produced no usable verified source for any of
    # them) skips the Patch Generator call itself, per the coverage
    # contract below -- this never fails the run and never introduces a
    # new recommendation category.
    _slice_ctx = ""
    _coverage_warning_ctx = ""
    _skip_patch_generation = False
    _edit_readiness = None  # EditReadinessResult | None -- see PipelineResult.edit_readiness
    _edit_acquisition = None  # AcquisitionResult | None -- see PipelineResult.edit_acquisition
    _guided_acquisition = None  # GuidedAcquisitionResult | None -- see PipelineResult.guided_acquisition
    # Minimal compatibility pre-inits for Slice 4 (Patch Target Conformance
    # Gate + Post-Patch Recovery, much further below in this function): both
    # are otherwise only ever assigned inside the `if _strategy_result is
    # not None...` block below, so a run with no Final Strategy (or one
    # naming no targets) would leave them undefined by the time Slice 4
    # reads them -- never actually reassigned above, only guaranteed defined.
    _slice_result = None  # FinalTargetSliceResult | None
    _intended_edits = []  # list[IntendedEdit]
    if _strategy_result is not None and (_strategy_result.target_files or _strategy_result.target_symbols):
        try:
            from .remediation_planner import build_final_target_slice
            _planner_evidence_files = list(_plan_result.target_files) if _plan_result is not None else []
            _slice_result = build_final_target_slice(
                _strategy_result, repo_root, _investigation_context,
                planner_evidence_files=_planner_evidence_files,
            )
            _slice_ctx = _slice_result.rendered
            _coverage_warning_ctx = _slice_result.warning_text
            if _slice_ctx:
                print(
                    f"[pipeline] Final-Target Remediation Slice built "
                    f"({len(_slice_ctx)} chars); covered files={_slice_result.covered_target_files}, "
                    f"covered symbols={_slice_result.covered_target_symbols}.",
                    file=sys.stderr,
                )
            if not _slice_result.coverage_complete:
                print(
                    f"[pipeline] Final-target source coverage incomplete -- "
                    f"uncovered files={_slice_result.uncovered_target_files}, "
                    f"uncovered symbols={_slice_result.uncovered_target_symbols}.",
                    file=sys.stderr,
                )

            # Edit Readiness Gate (Slice 1) -- replaces the coarse
            # "has_any_coverage == safe to generate" assumption with a
            # decision made separately for every intended edit. Reuses only
            # data build_final_target_slice() already computed above; no
            # new repository read, no new resolution, no new LLM call.
            from .remediation_planner import build_intended_edits, check_edit_readiness
            _intended_edits = build_intended_edits(_strategy_result, _slice_result)
            _initial_edit_readiness = check_edit_readiness(_intended_edits, _slice_result)
            print(
                f"[pipeline] Edit Readiness Gate: strategy_ready={_initial_edit_readiness.strategy_ready}, "
                f"edit_source_ready={_initial_edit_readiness.edit_source_ready}, "
                f"{len(_initial_edit_readiness.ready_edits)}/{len(_initial_edit_readiness.intended_edits)} "
                f"intended edit(s) ready"
                + (f", failure_reasons={_initial_edit_readiness.failure_reasons}"
                   if _initial_edit_readiness.unready_edits else ""),
                file=sys.stderr,
            )

            # Slice 2 -- Deterministic Pre-Patch Retrieval: attempt
            # additional verified repository source for whatever is still
            # unready, deterministically and bounded (see
            # remediation_planner.run_deterministic_acquisition). No-op
            # (0 rounds) when the initial readiness above was already
            # complete. Best-effort: any failure here leaves the initial
            # readiness/slice exactly as already computed.
            _edit_readiness = _initial_edit_readiness
            if not _initial_edit_readiness.edit_source_ready:
                try:
                    from .remediation_planner import run_deterministic_acquisition
                    _edit_acquisition = run_deterministic_acquisition(
                        _strategy_result, repo_root, _investigation_context,
                        _slice_result, _initial_edit_readiness,
                        budget_controller=budget_controller,
                    )
                    if _edit_acquisition.rounds_used > 0:
                        _slice_result = _edit_acquisition.slice_result
                        _slice_ctx = _slice_result.rendered
                        _coverage_warning_ctx = _slice_result.warning_text
                        _edit_readiness = check_edit_readiness(_intended_edits, _slice_result)
                        print(
                            f"[pipeline] Deterministic Pre-Patch Retrieval: "
                            f"{_edit_acquisition.rounds_used} round(s), "
                            f"{len(_edit_acquisition.attempts)} attempt(s); "
                            f"edit_source_ready now={_edit_readiness.edit_source_ready} "
                            f"({len(_edit_readiness.ready_edits)}/{len(_edit_readiness.intended_edits)} "
                            f"intended edit(s) ready)"
                            + (f", failure_reasons={_edit_readiness.failure_reasons}"
                               if _edit_readiness.unready_edits else ""),
                            file=sys.stderr,
                        )
                except Exception as exc:
                    print(
                        f"[pipeline] Deterministic Pre-Patch Retrieval unavailable: "
                        f"{type(exc).__name__}: {exc}",
                        file=sys.stderr,
                    )

            # Snapshot for the debug artifact's own "readiness_after_
            # deterministic_acquisition" key -- BEFORE Slice 3 (below) can
            # reassign _edit_readiness again.
            _readiness_after_deterministic = _edit_readiness

            # Slice 3 -- Bounded LLM-guided pre-patch context retrieval:
            # runs ONLY when Slice 2 above still leaves readiness
            # incomplete (see remediation_planner.run_guided_acquisition).
            # At most MAX_GUIDED_ACQUISITION_ROUNDS narrow LLM calls
            # (stage "guided_context_request") -- never the Patch
            # Generator, never a Planner/Final Strategy rerun, never the
            # Challenger. Best-effort: any failure here leaves the
            # Slice-2 readiness/slice exactly as already computed.
            if not _edit_readiness.edit_source_ready:
                try:
                    from .remediation_planner import run_guided_acquisition
                    _deterministic_attempts = _edit_acquisition.attempts if _edit_acquisition is not None else []
                    _guided_acquisition = run_guided_acquisition(
                        _strategy_result, vulnerability_text, llm, repo_root, _investigation_context,
                        _slice_result, _edit_readiness, _deterministic_attempts,
                        budget_controller=budget_controller,
                    )
                    if _guided_acquisition.rounds_used > 0:
                        _slice_result = _guided_acquisition.slice_result
                        _slice_ctx = _slice_result.rendered
                        _coverage_warning_ctx = _slice_result.warning_text
                        _edit_readiness = _guided_acquisition.readiness
                        print(
                            f"[pipeline] Guided Context Retrieval: "
                            f"{_guided_acquisition.rounds_used} round(s), "
                            f"{len(_guided_acquisition.attempts)} request(s); "
                            f"edit_source_ready now={_edit_readiness.edit_source_ready} "
                            f"({len(_edit_readiness.ready_edits)}/{len(_edit_readiness.intended_edits)} "
                            f"intended edit(s) ready)"
                            + (f", failure_reasons={_edit_readiness.failure_reasons}"
                               if _edit_readiness.unready_edits else ""),
                            file=sys.stderr,
                        )
                except Exception as exc:
                    print(
                        f"[pipeline] Guided Context Retrieval unavailable: "
                        f"{type(exc).__name__}: {exc}",
                        file=sys.stderr,
                    )

            if os.environ.get("AUTOPATCHER_DEBUG"):
                try:
                    import datetime as _dt
                    import json as _json

                    def _readiness_doc(r):
                        if r is None:
                            return None
                        return {
                            "strategy_ready": r.strategy_ready,
                            "edit_source_ready": r.edit_source_ready,
                            "intended_edits": [{"file": e.file, "symbol": e.symbol} for e in r.intended_edits],
                            "ready_edits": [
                                {"file": rd.file, "symbol": rd.symbol, "role": rd.role} for rd in r.ready_edits
                            ],
                            "unready_edits": [
                                {"file": u.edit.file, "symbol": u.edit.symbol, "reason": u.reason}
                                for u in r.unready_edits
                            ],
                            "failure_reasons": r.failure_reasons,
                        }

                    # Explicit even when Slice 2 never ran at all (initial
                    # readiness was already complete, or it failed) -- a
                    # present `null`/empty-list value, never an omitted key.
                    _deterministic_doc = None
                    if _edit_acquisition is not None:
                        _deterministic_doc = {
                            "rounds": _edit_acquisition.rounds_used,
                            "source_added": any(a.success for a in _edit_acquisition.attempts),
                            "attempts": [
                                {
                                    "round": a.round,
                                    "file": a.intended_edit.file,
                                    "symbol": a.intended_edit.symbol,
                                    "retrieval_strategy": a.retrieval_strategy,
                                    "resolved_file": a.resolved_file,
                                    "resolved_symbol": a.resolved_symbol,
                                    "start_line": a.start_line,
                                    "end_line": a.end_line,
                                    "source_kind": a.source_kind,
                                    "source_chars": a.source_chars,
                                    "success": a.success,
                                    "failure_reason": a.failure_reason,
                                }
                                for a in _edit_acquisition.attempts
                            ],
                        }

                    # Same explicitness rule for Slice 3: present (as null)
                    # even when Slice 2 alone already made readiness
                    # complete, so guided acquisition never ran.
                    _guided_doc = None
                    if _guided_acquisition is not None:
                        _guided_doc = {
                            "rounds": _guided_acquisition.rounds_used,
                            "source_added": any(a.verified and a.source_chars > 0 for a in _guided_acquisition.attempts),
                            "requests": [
                                {
                                    "round": a.round,
                                    "request_type": a.request.request_type,
                                    "file_hint": a.request.file_hint,
                                    "symbol": a.request.symbol,
                                    "identifier": a.request.identifier,
                                    "reason": a.request.reason,
                                    "attributed_file": a.request.intended_edit.file if a.request.intended_edit else None,
                                    "attributed_symbol": a.request.intended_edit.symbol if a.request.intended_edit else None,
                                }
                                for a in _guided_acquisition.attempts
                            ],
                            "verification_results": [
                                {
                                    "round": a.round,
                                    "schema_valid": a.schema_valid,
                                    "verified": a.verified,
                                    "failure_reason": a.failure_reason,
                                    "resolved_file": a.resolved_file,
                                    "resolved_symbol": a.resolved_symbol,
                                    "start_line": a.start_line,
                                    "end_line": a.end_line,
                                    "source_kind": a.source_kind,
                                    "source_chars": a.source_chars,
                                    "readiness_improved": a.readiness_improved,
                                }
                                for a in _guided_acquisition.attempts
                            ],
                        }

                    _debug_dir = Path("reports") / "debug"
                    _debug_dir.mkdir(parents=True, exist_ok=True)
                    _ts = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
                    _doc = {
                        "initial_edit_readiness": _readiness_doc(_initial_edit_readiness),
                        "deterministic_acquisition": _deterministic_doc,
                        "readiness_after_deterministic_acquisition": _readiness_doc(_readiness_after_deterministic),
                        "guided_acquisition": _guided_doc,
                        "final_edit_readiness": _readiness_doc(_edit_readiness),
                        "patch_generation_skipped": not _edit_readiness.edit_source_ready,
                        # Best-effort only -- see ContextBudgetController.to_trace_dict();
                        # None whenever no controller was supplied (policy="never"-equivalent
                        # library use, or a CLI run that never built one).
                        "budget_trace": budget_controller.to_trace_dict() if budget_controller is not None else None,
                    }
                    (_debug_dir / f"edit_readiness_{_ts}.json").write_text(
                        _json.dumps(_doc, indent=2), encoding="utf-8"
                    )
                except Exception:
                    pass

            if not _edit_readiness.edit_source_ready:
                _skip_patch_generation = True
                print(
                    "[pipeline] Not every intended edit has verified, patch-ready repository "
                    f"source -- skipping Patch Generation for this run. "
                    f"failure_reasons={_edit_readiness.failure_reasons}",
                    file=sys.stderr,
                )
        except Exception as exc:
            print(f"[pipeline] Final-Target Remediation Slice unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)

    # Assemble final context, in order: hand-authored Patch Plan → original
    # Repository Grounding → vuln patterns → ordinary Repository
    # Understanding → Target Discovery Plan (exploratory) → Planner-Proposed
    # Candidate Evidence (deterministically verified) → Final
    # Evidence-Backed Remediation Strategy → Final-Target Remediation Slice
    # (the last source-bearing section before Patch Generation) →
    # final-target source coverage warning, only when incomplete.
    _ctx_parts = [
        p for p in [
            _plan_text, _repo_code, _pattern_ctx, _repository_understanding_ctx,
            _plan_ctx, _planner_evidence_ctx, _strategy_ctx, _slice_ctx, _coverage_warning_ctx,
        ]
        if p and p.strip()
    ]
    code_context = "\n\n".join(_ctx_parts)

    if _skip_patch_generation:
        print("[pipeline] Step 1/4 – Patch Generation skipped (no verified final-target source).", file=sys.stderr)
        patch = ""
    else:
        print("[pipeline] Step 1/4 – Generating patch …", file=sys.stderr)
        patch = generate_patch(vulnerability_text, llm, code_context=code_context)

    # Hunk header repair — recompute @@ counts from body, and (with repo_root)
    # relocate a drifted old-side line number by content; never blocks the pipeline
    _raw_patch_for_telemetry = patch  # captured BEFORE repair, for the telemetry block below
    # Tracks the RepairResult (and therefore .relocations) belonging to
    # whichever repair pass actually produced the CURRENT `patch` — reassigned
    # below whenever the retry or challenger-repair loop replaces `patch`, so
    # the Evidence Sufficiency Gate signal computed further down always
    # describes the patch that's actually being reported on, never a
    # superseded earlier attempt.
    _final_repair_meta = None
    try:
        from .diff_hunk_repair import repair_hunk_headers
        patch, _repair_meta = repair_hunk_headers(patch, repo_root=repo_root)
        _final_repair_meta = _repair_meta
        if _repair_meta.normalization_applied:
            print(
                f"[pipeline] Hunk headers repaired: "
                f"{_repair_meta.hunks_rewritten} hunk(s) in "
                f"{_repair_meta.files_rewritten} file(s)"
                f" ({_repair_meta.hunks_relocated} relocated by content)"
            , file=sys.stderr)
    except Exception:
        pass

    # Candidate 1 relocation telemetry — observability only. Independently
    # recomputes both a WITHOUT-relocation and a WITH-relocation variant of
    # the same raw patch and checks `git apply --check` against each, so it
    # can never mutate or influence `patch`/`applicability_result` above or
    # below (see relocation_telemetry.py's module docstring). Read-only,
    # deterministic, never blocks the pipeline, never consulted by the
    # retry loop, the repair loop, or the Recommendation Policy below.
    _relocation_telemetry = None
    try:
        from .relocation_telemetry import build_relocation_telemetry, summarize as _summarize_relocation
        _relocation_telemetry = build_relocation_telemetry(_raw_patch_for_telemetry, repo_root)
        print(f"[pipeline] Relocation telemetry: {_summarize_relocation(_relocation_telemetry)}", file=sys.stderr)
        if os.environ.get("AUTOPATCHER_DEBUG") and _relocation_telemetry is not None:
            import datetime as _dt
            import json as _json
            _debug_dir = Path("reports") / "debug"
            _debug_dir.mkdir(parents=True, exist_ok=True)
            _ts = _dt.datetime.now().strftime("%Y%m%dT%H%M%S")
            (_debug_dir / f"relocation_telemetry_{_ts}.json").write_text(
                _json.dumps(_relocation_telemetry.to_dict(), indent=2), encoding="utf-8"
            )
    except Exception as exc:
        print(f"[pipeline] Relocation telemetry unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)

    # Slice 4 -- Patch Target Conformance Gate + Post-Patch Recovery: the
    # final deterministic gate, catching a generated patch that edits a
    # DIFFERENT repository target than the one Edit Readiness actually
    # approved -- something no earlier slice can catch, since Slices 1-3
    # only validate/acquire source for targets known BEFORE Patch
    # Generation runs. Runs only when there IS an Edit Readiness context
    # to compare against (a Final Strategy ran) and a non-empty patch was
    # actually generated. Reuses _final_repair_meta.relocations (already
    # computed above, as a side effect of repair_hunk_headers' own repair
    # pass over THIS `patch`) for old-side verification -- no second
    # relocation mechanism, no new git call. Best-effort: any failure here
    # leaves `patch` exactly as already computed.
    _patch_target_conformance = None        # initial conformance (this section's own PipelineResult field)
    _regenerated_patch_target_conformance = None  # only set if regeneration actually ran
    _post_patch_recovery = None
    _initial_patch_before_slice4 = patch     # captured for the trace artifact below, regardless of outcome
    if patch and patch.strip() and repo_root and _edit_readiness is not None:
        try:
            from .remediation_planner import (
                build_post_patch_recovery_hint, check_patch_target_conformance,
                post_patch_recovery_trigger_reasons, recover_post_patch_source,
            )
            _patch_target_conformance = check_patch_target_conformance(
                patch, _final_repair_meta.relocations if _final_repair_meta is not None else [],
                _edit_readiness.ready_edits, _slice_result,
            )
            _recovery_reasons = post_patch_recovery_trigger_reasons(_patch_target_conformance)
            print(
                f"[pipeline] Patch Target Conformance: all_conformant={_patch_target_conformance.all_conformant}, "
                f"edited files={_patch_target_conformance.edited_files}"
                + (f", trigger_reasons={_recovery_reasons}" if _recovery_reasons else ""),
                file=sys.stderr,
            )

            if _recovery_reasons:
                _post_patch_recovery = recover_post_patch_source(
                    _strategy_result, repo_root, _investigation_context,
                    _slice_result, _patch_target_conformance, patch,
                    budget_controller=budget_controller,
                )
                print(
                    f"[pipeline] Post-Patch Recovery: targets={_post_patch_recovery.recovery_targets}, "
                    f"ready_for_regeneration={_post_patch_recovery.ready_for_regeneration}"
                    + (f", failure_reason={_post_patch_recovery.failure_reason}"
                       if _post_patch_recovery.failure_reason else ""),
                    file=sys.stderr,
                )

                if not _post_patch_recovery.ready_for_regeneration:
                    print("[pipeline] Post-Patch Recovery: insufficient recovered evidence — failing closed.", file=sys.stderr)
                    patch = ""
                else:
                    _recovery_hint = build_post_patch_recovery_hint(_patch_target_conformance, _post_patch_recovery, patch)
                    _recovery_context = code_context
                    _recovered_rendered = (
                        _post_patch_recovery.slice_result.rendered if _post_patch_recovery.slice_result else ""
                    )
                    if _recovered_rendered:
                        _recovery_context = (code_context + "\n\n" if code_context else "") + _recovered_rendered

                    try:
                        _regenerated_raw = generate_patch(
                            vulnerability_text, llm, code_context=_recovery_context, retry_hint=_recovery_hint,
                        )
                    except Exception:
                        _regenerated_raw = ""

                    if not _regenerated_raw or not _regenerated_raw.strip():
                        print(
                            "[pipeline] Post-Patch Recovery: regeneration produced an empty/malformed "
                            "patch — failing closed.", file=sys.stderr,
                        )
                        patch = ""
                    else:
                        from .diff_hunk_repair import repair_hunk_headers as _repair_regenerated
                        _regenerated_patch, _regen_meta = _repair_regenerated(_regenerated_raw, repo_root=repo_root)
                        # Reconcile Post-Patch Recovery's own verified identity into the
                        # ready-edit set used for THIS (second, post-regeneration) check
                        # only -- the first check above, and any target that never went
                        # through recovery, are unaffected. Deduplicated conservatively
                        # by (file, symbol); a recovered attempt is only ever promoted via
                        # _recovered_ready_edit's own strict gate (success, patch_ready, a
                        # real resolved_file) -- never merely `attempt.file`.
                        #
                        # Evidence-floor guard (security): _recovered_ready_edit's checks
                        # prove the recovered SOURCE is real and patch-ready, but not that
                        # the FILE had any support before Patch Generation ran. Without
                        # this, Patch Generation could invent a brand-new target file with
                        # zero prior evidence and have recovery "launder" it into an
                        # approved target merely because the file happens to exist and its
                        # source can be read. Reuses Target Discovery's own (unverified)
                        # target_files and Final Strategy's deterministically re-verified
                        # target_files -- no new retrieval, no LLM call, no Markdown
                        # parsing. File-level only: recovery refining WHICH symbol inside
                        # an already-supported file is exactly what this slice exists to
                        # allow -- a file already named by Target Discovery/Final
                        # Strategy, with the wrong symbol initially proposed inside it,
                        # where recovery later finds the real one in that same,
                        # already-supported file.
                        _prior_supported_files = _prior_supported_target_files(_plan_result, _strategy_result)
                        _reconciled_ready_edits = list(_edit_readiness.ready_edits)
                        _reconciled_ready_keys = {(e.file, e.symbol) for e in _reconciled_ready_edits}
                        for _attempt in _post_patch_recovery.attempts:
                            _promoted = _recovered_ready_edit(_attempt)
                            if _promoted is None or _promoted.file not in _prior_supported_files:
                                continue
                            _key = (_promoted.file, _promoted.symbol)
                            if _key not in _reconciled_ready_keys:
                                _reconciled_ready_edits.append(_promoted)
                                _reconciled_ready_keys.add(_key)
                        _regen_conformance = check_patch_target_conformance(
                            _regenerated_patch, _regen_meta.relocations,
                            _reconciled_ready_edits, _post_patch_recovery.slice_result,
                        )
                        _regenerated_patch_target_conformance = _regen_conformance
                        _regen_ok = _regen_conformance.all_conformant and not _regen_conformance.unexpected_files
                        print(
                            f"[pipeline] Post-Patch Recovery: regeneration_performed=True, "
                            f"regenerated all_conformant={_regen_conformance.all_conformant}, "
                            f"accepted={_regen_ok}",
                            file=sys.stderr,
                        )
                        if _regen_ok:
                            patch = _regenerated_patch
                            _final_repair_meta = _regen_meta
                            _slice_result = _post_patch_recovery.slice_result
                            _patch_target_conformance = _regen_conformance
                        else:
                            print(
                                "[pipeline] Post-Patch Recovery: regenerated patch still fails target "
                                "conformance — failing closed.", file=sys.stderr,
                            )
                            patch = ""
        except Exception as exc:
            print(f"[pipeline] Patch Target Conformance unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)

    if os.environ.get("AUTOPATCHER_DEBUG"):
        try:
            import datetime as _dt4
            import json as _json4

            def _conformance_doc(c):
                if c is None:
                    return None
                return {
                    "all_conformant": c.all_conformant,
                    "edited_files": c.edited_files,
                    "unexpected_files": c.unexpected_files,
                    "uncovered_files": c.uncovered_files,
                    "no_match_files": c.no_match_files,
                    "results": [
                        {
                            "file": r.file, "hunk_index": r.hunk_index,
                            "target_coverage": r.target_coverage,
                            "old_side_status": r.old_side_status,
                            "conformant": r.conformant,
                        }
                        for r in c.results
                    ],
                }

            def _recovery_doc(rec):
                if rec is None:
                    return None
                return {
                    "triggered": rec.triggered,
                    "trigger_reasons": rec.trigger_reasons,
                    "recovery_targets": rec.recovery_targets,
                    "ready_for_regeneration": rec.ready_for_regeneration,
                    "failure_reason": rec.failure_reason,
                    "attempts": [
                        {
                            "file": a.file, "trigger_reason": a.trigger_reason,
                            "identifiers_considered": a.identifiers_considered,
                            "resolved_file": a.resolved_file,
                            "start_line": a.start_line, "end_line": a.end_line,
                            "source_kind": a.source_kind, "source_chars": a.source_chars,
                            "success": a.success, "failure_reason": a.failure_reason,
                        }
                        for a in rec.attempts
                    ],
                }

            try:
                from .diff_parsing import parse_diff as _parse_diff_for_trace
                _initial_changed_files, _initial_file_hunks = _parse_diff_for_trace(_initial_patch_before_slice4 or "")
            except Exception:
                _initial_changed_files, _initial_file_hunks = [], {}

            _debug_dir4 = Path("reports") / "debug"
            _debug_dir4.mkdir(parents=True, exist_ok=True)
            _ts4 = _dt4.datetime.now().strftime("%Y%m%dT%H%M%S")
            _post_patch_doc = {
                "initial_patch_files": _initial_changed_files,
                "initial_patch_hunks": {f: len(hs) for f, hs in _initial_file_hunks.items()},
                "approved_intended_targets": [
                    {"file": e.file, "symbol": e.symbol}
                    for e in (_edit_readiness.ready_edits if _edit_readiness is not None else [])
                ],
                "target_conformance_results": _conformance_doc(_patch_target_conformance),
                "recovery_triggered": _post_patch_recovery.triggered if _post_patch_recovery is not None else False,
                "recovery_reasons": _post_patch_recovery.trigger_reasons if _post_patch_recovery is not None else [],
                "recovery_targets": _post_patch_recovery.recovery_targets if _post_patch_recovery is not None else [],
                "post_patch_recovery": _recovery_doc(_post_patch_recovery),
                "regeneration_performed": _regenerated_patch_target_conformance is not None,
                "regenerated_target_conformance_results": _conformance_doc(_regenerated_patch_target_conformance),
                "final_recovery_state": (
                    "not_triggered" if _post_patch_recovery is None or not _post_patch_recovery.triggered
                    else "regenerated_and_accepted" if patch and patch.strip() and _regenerated_patch_target_conformance is not None
                    else "failed_closed"
                ),
                "patch_generation_skipped": not bool(patch and patch.strip()),
                # Best-effort only -- see ContextBudgetController.to_trace_dict();
                # None whenever no controller was supplied.
                "budget_trace": budget_controller.to_trace_dict() if budget_controller is not None else None,
            }
            (_debug_dir4 / f"post_patch_recovery_{_ts4}.json").write_text(
                _json4.dumps(_post_patch_doc, indent=2), encoding="utf-8"
            )
        except Exception:
            pass

    # Patch hygiene — deterministic, best-effort, never blocks the pipeline
    try:
        from .patch_hygiene import check_patch
        hygiene_findings = check_patch(patch)
    except Exception:
        hygiene_findings = []

    # Patch applicability — git apply --check, read-only, best-effort
    try:
        from .patch_applicability import check_applicability
        applicability_result = check_applicability(patch, repo_root)
    except Exception:
        applicability_result = {
            "applicable": None, "skipped": False, "skipped_reason": None,
            "error": "applicability check failed unexpectedly",
            "exit_code": None, "stderr": "",
        }

    # Applicability-aware retry — triggered only on applicable=False with a known repo_root
    original_patch = patch
    retry_patch = None
    retry_attempted = False
    retry_succeeded = False
    retry_failed_file = None
    retry_error_before = None

    if applicability_result.get("applicable") is False and repo_root:
        stderr = applicability_result.get("stderr", "")
        failed_files = _extract_failed_files(stderr)
        if not failed_files:
            _target = _extract_patch_target(patch)
            if _target:
                failed_files = [_target]

        if failed_files:
            failed_file = failed_files[0]
            print(f"[pipeline] Applicability failed — `{failed_file}` did not apply; attempting retry …", file=sys.stderr)
            retry_failed_file = failed_file
            retry_error_before = stderr
            try:
                repo_ctx = TargetRepoContext(Path(repo_root))
                # True only once a *successfully-read* file's block actually lands in
                # `blocks` (not `omitted_files`). Gating on this — rather than on "was
                # any read attempt successful" — matters because a large-but-readable
                # file can itself exceed the budget and land in `omitted_files` while
                # an unrelated unreadable file's small "(could not be read)" note still
                # fits and lands in `blocks`; without this distinction the retry would
                # proceed with a code_context containing zero real source.
                included_real_content = False
                blocks: list[str] = []
                omitted_files: list[str] = []
                running = 0
                for f in failed_files:
                    is_real_content = False
                    try:
                        f_content = repo_ctx.read_file(f)
                        is_real_content = True
                        n_lines = len(f_content.splitlines())
                        block = f"# {f} (full file, {n_lines} lines)\n{f_content}\n"
                    except Exception:
                        block = f"### {f}\n\n(could not be read — likely deleted or renamed)\n"
                    if running + len(block) <= _RETRY_CONTENT_LIMIT:
                        blocks.append(block)
                        running += len(block)
                        included_real_content = included_real_content or is_real_content
                    else:
                        omitted_files.append(f)

                if not included_real_content:
                    print(
                        f"[pipeline] Retry skipped — no real content for the failed "
                        f"file(s) ({', '.join(failed_files)}) could be included "
                        f"(missing, unreadable, or over the {_RETRY_CONTENT_LIMIT}-character budget).",
                        file=sys.stderr,
                    )
                else:
                    actual_content = "\n".join(blocks)
                    if omitted_files:
                        actual_content += (
                            f"\n\n*({len(omitted_files)} file(s) omitted to stay within the "
                            f"{_RETRY_CONTENT_LIMIT}-character budget: {', '.join(omitted_files)})*\n"
                        )
                    retry_attempted = True
                    hint = _build_retry_hint(stderr, failed_file)
                    r_patch_raw = generate_patch(
                        vulnerability_text, llm,
                        code_context=actual_content,
                        retry_hint=hint,
                    )
                    if not r_patch_raw or not r_patch_raw.strip():
                        print("[pipeline] Retry produced an empty patch; keeping original.", file=sys.stderr)
                    else:
                        _r_repair_meta = None
                        try:
                            from .diff_hunk_repair import repair_hunk_headers
                            r_patch_raw, _r_repair_meta = repair_hunk_headers(r_patch_raw, repo_root=repo_root)
                        except Exception:
                            pass
                        r_hygiene: list = []
                        try:
                            from .patch_hygiene import check_patch
                            r_hygiene = check_patch(r_patch_raw)
                        except Exception:
                            pass
                        from .patch_applicability import check_applicability
                        r_app = check_applicability(r_patch_raw, repo_root)
                        retry_patch = r_patch_raw
                        if r_app.get("applicable") is True:
                            retry_succeeded = True
                            patch = r_patch_raw
                            hygiene_findings = r_hygiene
                            applicability_result = r_app
                            if _r_repair_meta is not None:
                                _final_repair_meta = _r_repair_meta
                            print("[pipeline] Retry succeeded — patch applies cleanly.", file=sys.stderr)
                        else:
                            print("[pipeline] Retry did not apply; keeping original patch.", file=sys.stderr)
            except Exception as exc:
                print(f"[pipeline] Retry failed unexpectedly: {exc}", file=sys.stderr)
        else:
            print("[pipeline] Applicability failed — target file not identified; retry skipped.", file=sys.stderr)

    # Post-Patch Vulnerability Investigation: re-evaluate the pre-patch
    # Anchors against an isolated, patched copy of repo_root. Runs once,
    # here -- right after the applicability-retry loop settles and before
    # the FIRST challenge_patch() call below -- so its evidence can reach
    # that call, not just the Trust Report. The Challenger-driven repair
    # loop further down is single-shot (fires at most once, per its own
    # comment); if it replaces `patch`, this evidence describes a patch
    # that no longer exists. The staleness guard after that loop (comparing
    # `patch` against `_investigated_patch`) keeps it out of
    # calibrate_findings()/score_confidence() in that case. Never re-run
    # inside the repair loop itself -- extending fresh evidence to that
    # path is an explicitly separate, later decision.
    _post_patch_observations: list | None = None
    _post_patch_coverage: "CoverageResult | None" = None
    _post_patch_ctx = ""
    _investigated_patch: str | None = None
    if repo_root and _pre_patch_anchors:
        try:
            from .patch_workspace import temporary_repo_copy
            from .patch_applicability import apply_patch
            from .candidate_enrichment import build_investigation_context
            from .post_patch_evaluation import compute_coverage, derive_patch_touched_anchors, evaluate_anchors

            _investigated_patch = patch
            _resolved_repo_root = Path(repo_root).resolve()
            # Candidate-selection-independent gap fix: derive_patch_touched_anchors
            # resolves the FINAL patch's own diff directly against the pre-patch
            # InvestigationContext (repo-wide, built before Candidate Selection
            # ever ran) -- catching a semantic element (e.g. a literal constant)
            # the patch touches even when no selected candidate ever surfaced it.
            # _pre_patch_anchors itself is never mutated; this only concatenates a
            # disjoint, already-deduplicated list of net-new, origin="patch_touched"
            # anchors onto it for evaluation/coverage purposes below.
            _patch_touched_anchors = derive_patch_touched_anchors(
                _investigated_patch, _resolved_repo_root, _investigation_context, _pre_patch_anchors
            )
            _all_anchors = _pre_patch_anchors + _patch_touched_anchors
            with temporary_repo_copy(_resolved_repo_root) as _workspace_root:
                _apply_result = apply_patch(_investigated_patch, _workspace_root)
                _post_patch_context = None
                if _apply_result.applied:
                    _investigation_output_dir = _workspace_root.parent / "investigation"
                    _post_patch_context = build_investigation_context(_workspace_root, _investigation_output_dir)
                _post_patch_observations = evaluate_anchors(_all_anchors, _post_patch_context)
                # Coverage Analysis reuses the PRE-patch InvestigationContext (the
                # diff's context/removed lines describe that state) and the same
                # repo_root -- unrelated to the isolated post-patch workspace above,
                # so it runs regardless of whether patch application succeeded.
                # Fed the merged list so "uncovered" means "genuinely unsupported
                # element type", not "Candidate Selection didn't pick this file."
                _post_patch_coverage = compute_coverage(
                    _investigated_patch, _all_anchors, _resolved_repo_root, _investigation_context
                )
                _post_patch_ctx = render_post_patch_investigation(_post_patch_observations, _post_patch_coverage)
            if _post_patch_ctx:
                print(
                    f"[pipeline] Post-Patch Investigation rendered "
                    f"({len(_post_patch_ctx)} chars).",
                    file=sys.stderr,
                )
        except Exception as exc:
            print(
                f"[pipeline] Post-Patch Investigation unavailable: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            _post_patch_observations = None
            _post_patch_coverage = None
            _post_patch_ctx = ""
            _investigated_patch = None

    challenger_context = code_context + (("\n\n" + _post_patch_ctx) if _post_patch_ctx.strip() else "")

    print("[pipeline] Step 2/4 – Challenging patch …", file=sys.stderr)
    challenger = challenge_patch(vulnerability_text, patch, llm, code_context=challenger_context)

    # Phase C: Challenger-driven repair loop.
    # Fires once when the patch applies cleanly but has confirmed security defects.
    _repair_classified = _classify_challenger(challenger)
    _orig_defect_count = _repair_classified["confirmed_defect_count"]

    repair_attempted = False
    repair_succeeded = False
    repair_patch_content: str | None = None
    repair_challenger_result: dict | None = None
    repair_defect_count = 0
    repair_rechallenged = False

    if (
        applicability_result.get("applicable") is True
        and _orig_defect_count > 0
    ):
        try:
            repair_attempted = True
            _confirmed_texts = [
                f["text"]
                for f in (
                    _repair_classified["classified_edge_cases"]
                    + _repair_classified["classified_potential_issues"]
                )
                if f["category"] == "confirmed_defect"
            ]
            print(
                f"[pipeline] Repair loop – {_orig_defect_count} confirmed defect(s) found; "
                "attempting one repair …"
            , file=sys.stderr)
            _r_hint = _build_repair_hint(_confirmed_texts)
            _r_raw = generate_patch(
                vulnerability_text, llm,
                code_context=code_context,
                retry_hint=_r_hint,
            )
            _repair_loop_meta = None
            try:
                from .diff_hunk_repair import repair_hunk_headers
                _r_raw, _repair_loop_meta = repair_hunk_headers(_r_raw, repo_root=repo_root)
            except Exception:
                pass
            _r_hygiene: list = []
            try:
                from .patch_hygiene import check_patch
                _r_hygiene = check_patch(_r_raw)
            except Exception:
                pass
            from .patch_applicability import check_applicability as _check_app
            _r_app = _check_app(_r_raw, repo_root)
            repair_patch_content = _r_raw
            if _r_app.get("applicable") is True:
                _r_challenger = challenge_patch(vulnerability_text, _r_raw, llm, code_context=code_context)
                _r_classified = _classify_challenger(_r_challenger)
                repair_defect_count = _r_classified["confirmed_defect_count"]
                repair_rechallenged = True
                repair_challenger_result = _r_challenger
                if repair_defect_count == 0:
                    repair_succeeded = True
                    patch = _r_raw
                    challenger = _r_challenger
                    hygiene_findings = _r_hygiene
                    applicability_result = _r_app
                    if _repair_loop_meta is not None:
                        _final_repair_meta = _repair_loop_meta
                    print("[pipeline] Repair succeeded – 0 confirmed defects after re-challenge.", file=sys.stderr)
                else:
                    print(
                        f"[pipeline] Repair rejected – {repair_defect_count} confirmed defect(s) "
                        "remain; keeping original."
                    , file=sys.stderr)
            else:
                print("[pipeline] Repair patch does not apply; keeping original.", file=sys.stderr)
        except Exception as exc:
            print(f"[pipeline] Repair loop failed unexpectedly: {exc}", file=sys.stderr)

    # Evidence Sufficiency Gate (Phase 1) -- a deterministic Trust Signal,
    # computed here because everything above (the retry and challenger-repair
    # loops) has now settled and `_final_repair_meta` reflects whichever
    # repair pass actually produced the FINAL `patch`. Derived entirely from
    # data Candidate 1 already computes (RepairResult.relocations) -- no new
    # git calls, no new LLM calls. Deliberately observability-only: this
    # signal is exposed in the Trust Report and in relocation telemetry, and
    # made available in the Trust Signals dict, but is NOT read by
    # _build_recommendation_v1 -- current Recommendation Policy behavior is
    # unchanged by this signal's presence. See source_verification.py.
    _source_verification_signal = None
    try:
        from .source_verification import classify_source_verification
        _source_verification_signal = classify_source_verification(
            _final_repair_meta.relocations if _final_repair_meta is not None else []
        )
    except Exception:
        pass

    # Post-Patch Investigation staleness guard: if the repair loop above
    # replaced `patch`, the evidence computed before the first Challenger
    # call describes a patch that no longer exists. Never let it leak into
    # calibrate_findings()/score_confidence() below in that case -- they
    # must fall back to the plain code_context, same as if the feature
    # never ran.
    _post_patch_evidence_current = (
        _post_patch_observations is not None and patch == _investigated_patch
    )

    # Deterministic patch signals — run on final patch after any repair loop changes
    _c_signals: list[dict] | None = None
    _r_signals: list[dict] | None = None
    if _STATIC_SIGNALS_AVAILABLE and repo_root:
        try:
            _c_signals = _run_constraint_signals(patch, _Path(repo_root))
        except Exception as _exc:
            print(f"[pipeline] Constraint signals failed (non-fatal): {_exc}", file=sys.stderr)
        try:
            _r_signals = _run_remediation_signals(patch, _Path(repo_root))
        except Exception as _exc:
            print(f"[pipeline] Remediation signals failed (non-fatal): {_exc}", file=sys.stderr)

    # Finding calibration (evidence-quality pass) — classifies and rewords
    # the plausible_risk/generic findings from the FINAL challenger result
    # (post-repair, if a repair was accepted) so calibration reasons about
    # the patch that will actually be reported. confirmed_defect and
    # validation_gap findings are not sent here — those already have
    # unambiguous framing from earlier report-presentation work. Best-effort:
    # any failure leaves finding_calibration as None, and report rendering
    # falls back to the uncalibrated classifier text rather than losing
    # findings or crashing the run.
    _final_classified = _classify_challenger(challenger)
    _calibration_inputs = [
        f["text"]
        for f in (
            _final_classified["classified_edge_cases"]
            + _final_classified["classified_potential_issues"]
        )
        if f["category"] in ("plausible_risk", "generic")
    ]
    finding_calibration: list[dict] | None = None
    if _calibration_inputs:
        try:
            finding_calibration = calibrate_findings(
                vulnerability_text, patch, _calibration_inputs, llm,
                code_context=(challenger_context if _post_patch_evidence_current else code_context),
            )
        except Exception as _exc:
            print(f"[pipeline] Finding calibration failed (non-fatal): {_exc}", file=sys.stderr)

    print("[pipeline] Step 3/4 – Reviewing patch …", file=sys.stderr)
    review = review_patch(vulnerability_text, patch, llm)

    print("[pipeline] Step 4/4 – Evaluating Trust Signals…", file=sys.stderr)
    score_text = score_confidence(
        vulnerability_text, patch, review, llm,
        code_context=(challenger_context if _post_patch_evidence_current else code_context),
    )

    # Adjust the numeric score based on adversarial challenger results
    orig_score_str = _extract_score(score_text)
    try:
        orig_score = float(orig_score_str)
    except Exception:
        orig_score = None

    adjusted_score = orig_score
    try:
        still = bool(challenger.get("still_vulnerable"))
        edge_cases = challenger.get("edge_cases", []) or []
        potential_issues = challenger.get("potential_issues", []) or []
    except Exception:
        still = False
        edge_cases = []
        potential_issues = []

    if orig_score is not None:
        if still:
            adjusted_score = orig_score * 0.4
            reason_lines = [
                "Challenger indicates the vulnerability may still exist; applied strong reduction (0.4x).",
            ]
        elif edge_cases or potential_issues:
            adjusted_score = orig_score * 0.7
            reason_lines = [
                "Challenger found edge cases or potential issues; applied moderate reduction (0.7x).",
            ]
        else:
            adjusted_score = orig_score
            reason_lines = ["No adversarial issues found; score unchanged."]

        adjusted_score_str = f"{adjusted_score:.2f}"
        orig_score_display = f"{orig_score:.2f}"

        # Build a new score_text that places the adjusted score first so
        # _extract_score() picks it up when building the report.
        adjustment_text = (
            f"**Confidence score:** {adjusted_score_str}\n\n"
            f"**Original score:** {orig_score_display}\n\n"
            "**Adjustment reasoning:**\n"
            + "\n".join(f"- {l}" for l in reason_lines)
            + "\n\n"
        )

        # Prepend adjustment summary to the original scorer output for context
        score_text = adjustment_text + score_text
    # Run Impact Surface analysis (lightweight, deterministic).
    # Repository-dependent: skipped entirely when no repo_root is known
    # (F-01) instead of substituting Path.cwd(). impact_dict stays None,
    # which _resolve_impact_level() already reads as "unavailable" and the
    # existing trust policy (F-23/F-24) already renders as Not Verified
    # rather than a false-positive "low risk".
    impact_dict = None
    behavior = None
    _detected_language = "python"
    if repo_root:
        try:
            repo_root_for_context = Path(repo_root)
            repo_context = TargetRepoContext(repo_root_for_context)
            _detected_language = detect_language(repo_root_for_context)

            analyzer = LightweightImpactAnalyzer()
            impact = analyzer.analyze(
                patch,
                adversarial_findings=challenger,
                repo_context=repo_context,
                repo_language=_detected_language,
            )
            # attach deterministic annotations to challenger for reporting
            enhance_findings_with_impact(challenger, impact.to_dict())
            impact_dict = impact.to_dict()
        except Exception:
            pass

    # Behavior summary (minimal deterministic analyzer) -- operates purely
    # on the diff text (see behavior_summary.py: it never reads repository
    # files despite accepting a repo_context parameter), so unlike Impact
    # Surface above it is not repository-dependent and always runs.
    try:
        behavior = BehaviorAnalyzer().analyze(patch)
    except Exception:
        behavior = None

    result = PipelineResult(
        vulnerability_text=vulnerability_text,
        patch=patch,
        review=review,
        score_text=score_text,
        challenger=challenger,
        impact=impact_dict,
        final_score=adjusted_score,
        orig_score=orig_score,
        behavior=behavior,
        repo_root=_Path(repo_root) if repo_root else None,
        hygiene=hygiene_findings,
        applicability=applicability_result,
        original_patch=original_patch,
        retry_patch=retry_patch,
        retry_attempted=retry_attempted,
        retry_succeeded=retry_succeeded,
        retry_failed_file=retry_failed_file,
        retry_error_before=retry_error_before,
        repair_attempted=repair_attempted,
        repair_succeeded=repair_succeeded,
        repair_patch=repair_patch_content,
        repair_challenger=repair_challenger_result,
        repair_defect_count=repair_defect_count,
        repair_rechallenged=repair_rechallenged,
        original_challenger_defect_count=_orig_defect_count,
        constraint_signals=_c_signals,
        remediation_signals=_r_signals,
        detected_language=_detected_language,
        finding_calibration=finding_calibration,
        grounding=_grounding,
        repository_understanding=_repository_understanding,
        post_patch_observations=_post_patch_observations,
        post_patch_investigated_patch=_investigated_patch,
        post_patch_coverage=_post_patch_coverage,
        relocation_telemetry=_relocation_telemetry,
        source_verification=_source_verification_signal,
        edit_readiness=_edit_readiness,
        edit_acquisition=_edit_acquisition,
        guided_acquisition=_guided_acquisition,
        patch_target_conformance=_patch_target_conformance,
        post_patch_recovery=_post_patch_recovery,
    )
    return _build_report(result)
