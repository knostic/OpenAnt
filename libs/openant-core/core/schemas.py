"""
Output schemas for OpenAnt CLI.

All CLI commands produce a JSON envelope on stdout:
    { "status": "success|error", "data": {...}, "errors": [...] }

Human-readable progress goes to stderr.

Each pipeline step also writes a {step}.report.json file with
standardized metadata (timing, cost, inputs, outputs).
"""

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


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

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class UsageInfo:
    """Token usage and cost summary."""
    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0

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

    def to_dict(self) -> dict:
        return {
            "output_dir": self.output_dir,
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

@dataclass
class VerifyResult:
    """Result of `open-ant verify`."""
    verified_results_path: str
    findings_input: int = 0
    findings_verified: int = 0
    agreed: int = 0
    disagreed: int = 0
    confirmed_vulnerabilities: int = 0
    usage: UsageInfo = field(default_factory=UsageInfo)

    def to_dict(self) -> dict:
        return {
            "verified_results_path": self.verified_results_path,
            "findings_input": self.findings_input,
            "findings_verified": self.findings_verified,
            "agreed": self.agreed,
            "disagreed": self.disagreed,
            "confirmed_vulnerabilities": self.confirmed_vulnerabilities,
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
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path
