"""
Pipeline Output Schema - validates input data for report generation.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Finding:
    """A single vulnerability finding from the pipeline."""
    id: str
    name: str
    short_name: str
    location: dict  # {"file": str, "function": str}
    cwe_id: int
    cwe_name: str
    stage1_verdict: str
    stage2_verdict: str
    dynamic_testing: dict | bool = False
    description: Optional[str] = None
    vulnerable_code: Optional[str] = None
    vulnerable_code_section: Optional[str] = None
    impact: Optional[list] = None
    suggested_fix: Optional[str] = None
    steps_to_reproduce: Optional[list] = None
    rejection_reason: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Create Finding from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            short_name=data["short_name"],
            location=data["location"],
            cwe_id=data["cwe_id"],
            cwe_name=data["cwe_name"],
            stage1_verdict=data["stage1_verdict"],
            stage2_verdict=data["stage2_verdict"],
            dynamic_testing=data.get("dynamic_testing", False),
            description=data.get("description"),
            vulnerable_code=data.get("vulnerable_code"),
            vulnerable_code_section=data.get("vulnerable_code_section"),
            impact=data.get("impact"),
            suggested_fix=data.get("suggested_fix"),
            steps_to_reproduce=data.get("steps_to_reproduce"),
            rejection_reason=data.get("rejection_reason"),
        )


@dataclass
class PipelineOutput:
    """Complete pipeline output data."""
    repository: dict  # {"name": str, "url": str, ...}
    analysis_date: str
    application_type: str
    pipeline_stats: dict
    results: dict  # {"vulnerable": int, "safe": int, ...}
    findings: list[Finding]
    false_positives: Optional[list] = None

    @classmethod
    def from_dict(cls, data: dict) -> "PipelineOutput":
        """Create PipelineOutput from dictionary."""
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(
            repository=data["repository"],
            analysis_date=data["analysis_date"],
            application_type=data["application_type"],
            pipeline_stats=data["pipeline_stats"],
            results=data["results"],
            findings=findings,
            false_positives=data.get("false_positives"),
        )


class ValidationError(Exception):
    """Raised when pipeline output fails validation."""
    pass


def validate_pipeline_output(data: dict) -> PipelineOutput:
    """
    Validate pipeline output data and return typed object.

    Raises:
        ValidationError: If required fields are missing or malformed.
    """
    required_fields = ["repository", "analysis_date", "application_type", "pipeline_stats", "results", "findings"]

    for field in required_fields:
        if field not in data:
            raise ValidationError(f"Missing required field: {field}")

    if "name" not in data["repository"]:
        raise ValidationError("repository.name is required")

    if not isinstance(data["findings"], list):
        raise ValidationError("findings must be a list")

    finding_required = ["id", "name", "short_name", "location", "cwe_id", "cwe_name", "stage1_verdict", "stage2_verdict"]
    for i, finding in enumerate(data["findings"]):
        for field in finding_required:
            if field not in finding:
                raise ValidationError(f"Finding {i}: missing required field '{field}'")

        if "file" not in finding["location"] or "function" not in finding["location"]:
            raise ValidationError(f"Finding {i}: location must have 'file' and 'function'")

    return PipelineOutput.from_dict(data)
