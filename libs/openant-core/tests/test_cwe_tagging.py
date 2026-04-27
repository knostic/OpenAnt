"""Regression tests for CWE tagging in pipeline output.

Stage 1 never asked for CWE, so pipeline_output.json had cwe:null, cwe_id:0
for every finding. The fix adds cwe_id/cwe_name to the Stage 1 prompt schema
and preserves them through normalization.
"""

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub
_anth = sys.modules["anthropic"]
if not hasattr(_anth, "RateLimitError"):
    _anth.RateLimitError = type("RateLimitError", (Exception,), {})
if not hasattr(_anth, "AuthenticationError"):
    _anth.AuthenticationError = type("AuthenticationError", (Exception,), {})


# ---------------------------------------------------------------------------
# Stage 1 prompt must ask for CWE
# ---------------------------------------------------------------------------

def test_stage1_prompt_includes_cwe_fields():
    """The Stage 1 analysis prompt JSON schema must require cwe_id and cwe_name."""
    from prompts.vulnerability_analysis import get_analysis_prompt
    prompt = get_analysis_prompt(
        code="def foo(): pass",
        language="python",
        route="test.py:foo",
    )
    assert "cwe_id" in prompt, "Stage 1 prompt must ask for cwe_id"
    assert "cwe_name" in prompt, "Stage 1 prompt must ask for cwe_name"


# ---------------------------------------------------------------------------
# _normalize_result must preserve CWE through normalization
# ---------------------------------------------------------------------------

def test_normalize_result_preserves_cwe():
    from experiment import _normalize_result
    result = {
        "finding": "vulnerable",
        "reasoning": "SQL injection",
        "attack_vector": "GET /user?id=1",
        "confidence": 0.95,
        "cwe_id": 89,
        "cwe_name": "SQL Injection",
    }
    normalized = _normalize_result(result)
    assert normalized["cwe_id"] == 89
    assert normalized["cwe_name"] == "SQL Injection"


def test_normalize_result_defaults_cwe_when_missing():
    from experiment import _normalize_result
    result = {
        "finding": "vulnerable",
        "reasoning": "some vuln",
        "attack_vector": "payload",
        "confidence": 0.9,
    }
    normalized = _normalize_result(result)
    assert "cwe_id" in normalized, "cwe_id should be set even if LLM omitted it"
    assert "cwe_name" in normalized, "cwe_name should be set even if LLM omitted it"


# ---------------------------------------------------------------------------
# pipeline_output.json must carry non-null CWE from results
# ---------------------------------------------------------------------------

@pytest.fixture
def results_with_cwe(tmp_path: Path) -> Path:
    results = {
        "dataset": "cwe-test",
        "results": [
            {
                "unit_id": "test.py:foo",
                "route_key": "test.py:foo",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "attack_vector": "GET /foo?id=1",
                "reasoning": "SQL injection",
                "cwe_id": 89,
                "cwe_name": "SQL Injection",
            },
        ],
        "code_by_route": {"test.py:foo": "def foo(): pass"},
        "confirmed_findings": [
            {
                "unit_id": "test.py:foo",
                "route_key": "test.py:foo",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "cwe_id": 89,
                "cwe_name": "SQL Injection",
            },
        ],
        "metrics": {"total": 1, "vulnerable": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


def test_pipeline_output_carries_cwe(tmp_path, results_with_cwe):
    from core.reporter import build_pipeline_output
    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(results_with_cwe),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text())
    finding = data["findings"][0]
    assert finding["cwe_id"] == 89, f"expected 89, got {finding['cwe_id']}"
    assert finding["cwe_name"] == "SQL Injection"
