"""Data models for dynamic testing results."""

from dataclasses import dataclass, field


# Valid test result statuses
VALID_STATUSES = {"CONFIRMED", "NOT_REPRODUCED", "BLOCKED", "INCONCLUSIVE", "ERROR"}


@dataclass
class TestEvidence:
    """A single piece of evidence from a dynamic test."""
    type: str       # "file_read", "http_response", "command_output", "network_capture"
    content: str

    def to_dict(self) -> dict:
        return {"type": self.type, "content": self.content}


@dataclass
class DynamicTestResult:
    """Result from dynamically testing a single finding."""
    finding_id: str
    status: str         # CONFIRMED, NOT_REPRODUCED, BLOCKED, INCONCLUSIVE, ERROR
    details: str
    evidence: list[TestEvidence] = field(default_factory=list)
    test_code: str = ""       # Generated test script (for reproducibility)
    dockerfile: str = ""      # Generated Dockerfile
    docker_compose: str = ""  # Generated docker-compose.yml (if multi-service)
    elapsed_seconds: float = 0.0
    generation_cost_usd: float = 0.0
    generation_input_tokens: int = 0
    generation_output_tokens: int = 0
    retry_count: int = 0

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "status": self.status,
            "details": self.details,
            "evidence": [e.to_dict() for e in self.evidence],
            "test_code": self.test_code,
            "dockerfile": self.dockerfile,
            "docker_compose": self.docker_compose,
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "generation_cost_usd": round(self.generation_cost_usd, 6),
            "generation_input_tokens": self.generation_input_tokens,
            "generation_output_tokens": self.generation_output_tokens,
            "retry_count": self.retry_count,
        }
