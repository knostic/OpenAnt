"""
Output schemas for OpenAnt CLI.

All CLI commands produce a JSON envelope on stdout:
    { "status": "success|error", "data": {...}, "errors": [...] }

Human-readable progress goes to stderr.

Each pipeline step also writes a {step}.report.json file with
standardized metadata (timing, cost, inputs, outputs).
"""

import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

from utilities.file_io import write_json


# ---------------------------------------------------------------------------
# JSON Envelope
# ---------------------------------------------------------------------------

def success(data: dict) -> dict:
    """Create a success response envelope."""
    return {"status": "success", "data": data, "errors": []}


def error(message: str, data: dict | None = None, errors: list[str] | None = None) -> dict:
    """Create an error response envelope."""
    return {
        "status": "error",
        "data": data or {},
        "errors": errors or [message],
    }


# ---------------------------------------------------------------------------
# Result types for each command
# ---------------------------------------------------------------------------

@dataclass
class ParseResult:
    """Result of `open-ant parse`."""
    dataset_path: str
    analyzer_output_path: str | None = None
    units_count: int = 0
    language: str = "unknown"
    processing_level: str = "all"
    # --- multi-language (additive) -------------------------------------
    # `language` above stays scalar and means THE PRIMARY language: it is
    # serialized into JSON the Go CLI unmarshals, so widening its type would be
    # a cross-language breaking change. These fields sit beside it, following
    # the same convention as skipped_steps / skipped_step_reasons.
    languages: list = field(default_factory=list)
    language_stats: dict = field(default_factory=dict)
    per_language: dict = field(default_factory=dict)
    parse_errors: list = field(default_factory=list)
    # Languages detected but deliberately not scanned, with the reason.
    # Carried on the result so a coverage gap is inspectable after the fact,
    # not only visible in a stderr line that CI discards.
    excluded_languages: dict = field(default_factory=dict)
    # Which path supplied the application context: "threat_model" (a file in
    # the scanned repo), "repo_manual" (an OPENANT.json/OPENANT.md committed
    # by the scanned repo — #322: a distinct source so the provenance banner
    # discloses it), "generated" (the built-in LLM generator), or "none".
    # Recorded because a scan run under the WRONG security model looks
    # identical to a correct one unless the source is stated.
    context_source: str = "none"
    # #322: the manual-override exclusion volume + warnings (the R5 pattern:
    # stderr is discarded by CI; the artifact is the receipt). Carried when
    # context_source == "repo_manual".
    manual_exclusions: int | None = None
    manual_override_warnings: list = field(default_factory=list)
    # the OVERRIDE FILE that actually matched (OPENANT.json / .openant.md /
    # ...) — the banner names the file present in the repo, not a guess.
    manual_override_filename: str = ""

    @property
    def degraded(self) -> bool:
        """Whether any requested language failed to parse.

        Derived rather than stored so it cannot disagree with parse_errors.
        """
        return bool(self.parse_errors)

    def to_dict(self) -> dict:
        d = asdict(self)
        # ``degraded`` is a @property, which asdict() omits — include it explicitly so
        # the parse envelope carries it like ScanResult.to_dict does.
        d["degraded"] = self.degraded
        return d


@dataclass
class UsageInfo:
    """Token usage and cost summary."""
    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    # #216: the cost figure is incomplete when any dispatched model had no
    # pricing record (tokens counted, dollars $0). Deterministic advisory —
    # flows into step reports and scan.report.json via tracking.get_usage.
    cost_incomplete: bool = False
    unpriced_models: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalysisMetrics:
    """Metrics from vulnerability analysis."""
    total: int = 0
    vulnerable: int = 0
    bypassable: int = 0
    inconclusive: int = 0
    protected: int = 0
    safe: int = 0
    errors: int = 0
    # Stage 2 metrics (optional)
    verified: int = 0
    stage2_agreed: int = 0
    stage2_disagreed: int = 0
    # PR #69 F5: findings whose Stage-2 verification could not COMPLETE
    # (degenerate path or adapter error). These are preserved Stage-1
    # potential vulnerabilities awaiting manual review — they must NOT be
    # folded into ``safe``.
    needs_review: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnalyzeResult:
    """Result of `open-ant analyze`."""
    results_path: str
    metrics: AnalysisMetrics = field(default_factory=AnalysisMetrics)
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        return {
            "results_path": self.results_path,
            "metrics": self.metrics.to_dict(),
            "usage": self.usage.to_dict(),
        }


@dataclass
class ReportResult:
    """Result of `open-ant report`."""
    output_path: str
    format: str = "html"
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        return {
            "output_path": self.output_path,
            "format": self.format,
            "usage": self.usage.to_dict(),
        }


@dataclass
class ScanResult:
    """Result of `open-ant scan` (all-in-one)."""
    output_dir: str
    dataset_path: str | None = None
    enhanced_dataset_path: str | None = None
    # #285: the scan-level status (worst per-step: error > partial > skipped
    # > success) and the aggregate errors — carried so the envelope / webui /
    # CLI consumers see a degraded scan without re-reading scan.report.json.
    scan_status: str = "success"
    scan_errors: list = field(default_factory=list)
    analyzer_output_path: str | None = None
    app_context_path: str | None = None
    results_path: str | None = None
    verified_results_path: str | None = None
    pipeline_output_path: str | None = None
    report_path: str | None = None
    summary_path: str | None = None
    dynamic_test_path: str | None = None
    units_count: int = 0
    language: str = "unknown"
    metrics: AnalysisMetrics = field(default_factory=AnalysisMetrics)
    usage: UsageInfo = field(default_factory=UsageInfo)
    step_reports: list = field(default_factory=list)
    skipped_steps: list = field(default_factory=list)
    # Disambiguated skip cause per skipped step. ADDITIVE / non-breaking:
    # `skipped_steps` stays a flat bare list of step names (telemetry consumers
    # read it). This map records WHY each step was skipped (e.g. 'verify' ->
    # 'no_candidates' for an auto-skip vs 'not_requested' for an opt-out).
    skipped_step_reasons: dict = field(default_factory=dict)

    # --- multi-language (additive) -------------------------------------
    # `language` above stays scalar and means THE PRIMARY language: it is
    # serialized into JSON the Go CLI unmarshals, so widening its type would be
    # a cross-language breaking change. These fields sit beside it, following
    # the same convention as skipped_steps / skipped_step_reasons.
    languages: list = field(default_factory=list)
    language_stats: dict = field(default_factory=dict)
    per_language: dict = field(default_factory=dict)
    parse_errors: list = field(default_factory=list)
    # Languages detected but deliberately not scanned, with the reason.
    # Carried on the result so a coverage gap is inspectable after the fact,
    # not only visible in a stderr line that CI discards.
    excluded_languages: dict = field(default_factory=dict)
    # Which path supplied the application context: "threat_model" (a file in
    # the scanned repo), "repo_manual" (an OPENANT.json/OPENANT.md committed
    # by the scanned repo — #322: a distinct source so the provenance banner
    # discloses it), "generated" (the built-in LLM generator), or "none".
    # Recorded because a scan run under the WRONG security model looks
    # identical to a correct one unless the source is stated.
    context_source: str = "none"
    # #322: the manual-override exclusion volume + warnings (the R5 pattern:
    # stderr is discarded by CI; the artifact is the receipt). Carried when
    # context_source == "repo_manual".
    manual_exclusions: int | None = None
    manual_override_warnings: list = field(default_factory=list)
    # the OVERRIDE FILE that actually matched (OPENANT.json / .openant.md /
    # ...) — the banner names the file present in the repo, not a guess.
    manual_override_filename: str = ""
    # Provenance for a repo-supplied threat model (context_source ==
    # "threat_model"). sha256 is over the raw file bytes so a scan can be tied
    # to the exact file that shaped it; None (never the empty-string hash) when
    # no threat model was loaded. permissive_warnings carries the previously
    # discarded warn_permissive_threat_model output so an over-permissive model
    # is visible in the artifact, not only on stderr.
    threat_model_sha256: str | None = None
    threat_model_warnings: list = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        """Whether any requested language failed to parse.

        Derived rather than stored so it cannot disagree with parse_errors.
        """
        return bool(self.parse_errors)

    def to_dict(self) -> dict:
        return {
            "output_dir": self.output_dir,
            "scan_status": self.scan_status,
            "scan_errors": self.scan_errors,
            "dataset_path": self.dataset_path,
            "enhanced_dataset_path": self.enhanced_dataset_path,
            "analyzer_output_path": self.analyzer_output_path,
            "app_context_path": self.app_context_path,
            "results_path": self.results_path,
            "verified_results_path": self.verified_results_path,
            "pipeline_output_path": self.pipeline_output_path,
            "report_path": self.report_path,
            "summary_path": self.summary_path,
            "dynamic_test_path": self.dynamic_test_path,
            "units_count": self.units_count,
            "language": self.language,
            "metrics": self.metrics.to_dict(),
            "usage": self.usage.to_dict(),
            "step_reports": self.step_reports,
            "skipped_steps": self.skipped_steps,
            "skipped_step_reasons": self.skipped_step_reasons,
            "languages": self.languages,
            "language_stats": self.language_stats,
            "per_language": self.per_language,
            "parse_errors": self.parse_errors,
            "excluded_languages": self.excluded_languages,
            "context_source": self.context_source,
            "threat_model_sha256": self.threat_model_sha256,
            "threat_model_warnings": self.threat_model_warnings,
            # #322 (wave r3): the manual-override receipt reaches the machine-
            # readable JSON envelope too (the R5 pattern — the threat-model
            # analogues above are here; the manual ones were dropped by this
            # hand-maintained dict). Present-only: None/empty stays absent.
            **({"manual_exclusions": self.manual_exclusions}
               if self.manual_exclusions is not None else {}),
            **({"manual_override_warnings": self.manual_override_warnings}
               if self.manual_override_warnings else {}),
            **({"manual_override_filename": self.manual_override_filename}
               if self.manual_override_filename else {}),
            "degraded": self.degraded,
        }


# ---------------------------------------------------------------------------
# Enhance result
# ---------------------------------------------------------------------------

@dataclass
class EnhanceResult:
    """Result of `open-ant enhance`."""
    enhanced_dataset_path: str
    units_enhanced: int = 0
    error_count: int = 0
    error_summary: dict = field(default_factory=dict)
    classifications: dict = field(default_factory=dict)
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        result = {
            "enhanced_dataset_path": self.enhanced_dataset_path,
            "units_enhanced": self.units_enhanced,
            "error_count": self.error_count,
            "classifications": self.classifications,
            "usage": self.usage.to_dict(),
        }
        if self.error_summary:
            result["error_summary"] = self.error_summary
        return result


# ---------------------------------------------------------------------------
# Verify result
# ---------------------------------------------------------------------------

def verify_step_summary(result: "VerifyResult") -> dict:
    """The verify step-report summary (issue #300; ten fields since #302).

    Shared by every construction site — core/scanner.py (the pipeline),
    openant/cli.py's chained analyze --verify, and standalone openant
    verify — so the sites cannot drift. The reconciliation counters bound:
    agreed + disagreed + disagreed_inconclusive + needs_review +
    error_count accounts for every findings_input finding except the
    disagreed-but-still-vulnerable case, which increments only
    confirmed_vulnerabilities (see core/verifier.py
    _count_verification_outcomes) — the counters are therefore a bound
    (<=), not exact equality. #509: ``disagreed_inconclusive`` is the
    disagreement arm whose corrected finding is ``inconclusive`` — the
    verifier could NOT confirm it, so it must never fold into ``safe``.
    """
    return {
        "findings_input": result.findings_input,
        "findings_verified": result.findings_verified,
        "agreed": result.agreed,
        "disagreed": result.disagreed,
        "disagreed_inconclusive": result.disagreed_inconclusive,
        "confirmed_vulnerabilities": result.confirmed_vulnerabilities,
        "needs_review": result.needs_review,
        "error_count": result.error_count,
        "units_analyzed_total": result.units_analyzed_total,
        # downgraded/upgraded are NOT a partition of disagreed: agreed records
        # whose finding was rewritten by the consistency pass also count
        # direction, and a vulnerable->bypassable disagreement counts BOTH
        # confirmed_vulnerabilities and downgraded.
        "downgraded": result.downgraded,
        "upgraded": result.upgraded,
    }


@dataclass
class VerifyResult:
    """Result of `open-ant verify`."""
    verified_results_path: str
    findings_input: int = 0
    findings_verified: int = 0
    agreed: int = 0
    disagreed: int = 0
    # #509: disagreements whose corrected finding is ``inconclusive`` —
    # the verifier explicitly could NOT confirm the finding. Counted
    # separately so the scanner threads them into ``inconclusive`` and
    # they never fold into ``safe`` (the ->inconclusive arm of the
    # #374/#381 family).
    disagreed_inconclusive: int = 0
    confirmed_vulnerabilities: int = 0
    # PR #69 F5: findings whose Stage-2 verification could not COMPLETE
    # (degenerate path or adapter error). Counted separately so the scanner
    # never folds them into ``safe``.
    needs_review: int = 0
    error_count: int = 0
    # #302: Stage 2's SCOPE — the denominator (all analyzed units; only
    # Stage-1 positives enter) and the direction of its changes
    # (structurally one-way: a Stage-1 negative is never re-examined, so
    # no upgrade path exists for it). Persisted so the artifacts state
    # "adjudicated N of M" instead of implying whole-codebase adjudication.
    units_analyzed_total: int = 0
    downgraded: int = 0
    upgraded: int = 0
    usage: UsageInfo = field(default_factory=UsageInfo)

    def step_summary(self) -> dict:
        """The verify step-report summary (issue #300): the shared
        construction every site uses (ten fields since #302)."""
        return verify_step_summary(self)

    def to_dict(self) -> dict:
        return {
            "verified_results_path": self.verified_results_path,
            "findings_input": self.findings_input,
            "findings_verified": self.findings_verified,
            "agreed": self.agreed,
            "disagreed": self.disagreed,
            "confirmed_vulnerabilities": self.confirmed_vulnerabilities,
            "needs_review": self.needs_review,
            "error_count": self.error_count,
            "units_analyzed_total": self.units_analyzed_total,
            "downgraded": self.downgraded,
            "upgraded": self.upgraded,
            "usage": self.usage.to_dict(),
        }


# ---------------------------------------------------------------------------
# Dynamic test result
# ---------------------------------------------------------------------------

@dataclass
class DynamicTestStepResult:
    """Result of `open-ant dynamic-test`."""
    results_json_path: str
    results_md_path: str | None = None
    findings_tested: int = 0
    confirmed: int = 0
    not_reproduced: int = 0
    blocked: int = 0
    inconclusive: int = 0
    errors: int = 0
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Step Report — written as {step}.report.json by every pipeline step
# ---------------------------------------------------------------------------

@dataclass
class StepReport:
    """Standardized report written by each pipeline step.

    Written as ``{step}.report.json`` in the output directory.
    """
    step: str
    status: str = "success"
    timestamp: str = ""
    duration_seconds: float = 0.0
    cost_usd: float = 0.0
    token_usage: dict = field(default_factory=lambda: {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
    })
    summary: dict = field(default_factory=dict)
    inputs: dict = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def to_dict(self) -> dict:
        return asdict(self)

    def write(self, output_dir: str) -> str:
        """Write ``{step}.report.json`` to *output_dir*. Returns the path."""
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, f"{self.step}.report.json")
        write_json(path, self.to_dict())
        return path
