"""Regression tests for silent 401 on bad API key.

A user who runs `openant scan --verify` with an invalid API key should see
a loud warning in the scan summary, not "No vulnerabilities found, Cost: $0.00"
which could be mistaken for a clean repo.
"""

import io
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
    sys.modules["anthropic"] = _stub
_anth = sys.modules["anthropic"]
if not hasattr(_anth, "RateLimitError"):
    _anth.RateLimitError = type("RateLimitError", (Exception,), {})
if not hasattr(_anth, "AuthenticationError"):
    _anth.AuthenticationError = type("AuthenticationError", (Exception,), {})

from core.schemas import ScanResult, AnalysisMetrics, UsageInfo  # noqa: E402


# ---------------------------------------------------------------------------
# Prong B — _print_summary must warn when zero tokens + all errors
# ---------------------------------------------------------------------------

@pytest.fixture
def all_errors_result() -> ScanResult:
    """ScanResult mimicking a scan where every API call returned 401."""
    result = ScanResult(output_dir="/tmp/fake")
    result.metrics = AnalysisMetrics(total=7, errors=7)
    result.usage = UsageInfo(
        total_calls=0,
        total_input_tokens=0,
        total_output_tokens=0,
        total_tokens=0,
        total_cost_usd=0.0,
    )
    return result


@pytest.fixture
def normal_result() -> ScanResult:
    """ScanResult from a successful scan — should NOT trigger warning."""
    result = ScanResult(output_dir="/tmp/fake")
    result.metrics = AnalysisMetrics(total=7, vulnerable=6, safe=1)
    result.usage = UsageInfo(
        total_calls=7,
        total_input_tokens=50000,
        total_output_tokens=10000,
        total_tokens=60000,
        total_cost_usd=0.85,
    )
    return result


def _capture_print_summary(result: ScanResult) -> str:
    """Call _print_summary and capture stderr output."""
    from core.scanner import _print_summary
    captured = io.StringIO()
    old_stderr = sys.stderr
    sys.stderr = captured
    try:
        _print_summary(result)
    finally:
        sys.stderr = old_stderr
    return captured.getvalue()


def test_print_summary_warns_on_zero_tokens_all_errors(all_errors_result):
    output = _capture_print_summary(all_errors_result)
    assert "No API calls succeeded" in output, (
        "scan summary must warn loudly when all calls failed"
    )
    assert "api key" in output.lower(), (
        "warning should mention API key as a likely cause"
    )


def test_print_summary_no_warning_on_normal_scan(normal_result):
    output = _capture_print_summary(normal_result)
    assert "No API calls succeeded" not in output, (
        "normal scan should not show the auth-failure warning"
    )


# ---------------------------------------------------------------------------
# Note: the previous "analyze_sync surfaces AuthenticationError" test was
# removed when the AnthropicClient wrapper was deleted (issue #65). The
# equivalent contract — "an auth failure surfaces as LLMAuthError, not
# swallowed" — is now enforced by ``test_llm_adapter_contract.py`` for
# every registered adapter, and by ``test_llm_anthropic_adapter.py`` at
# the Anthropic SDK boundary specifically.
# ---------------------------------------------------------------------------
