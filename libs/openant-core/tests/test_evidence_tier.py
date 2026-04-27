"""Regression tests for evidence-tier reporting in summaries and disclosures.

Summary template and disclosure footer must reflect the highest evidence tier:
dynamic > verified (Stage 2) > static.
"""

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


def test_summary_prompt_has_three_tier_verified():
    """Summary template INSTRUCTIONS must mention 'verified' as a middle tier."""
    from report.generator import load_prompt
    prompt = load_prompt("summary")
    assert "verified" in prompt.lower(), "summary prompt must mention 'verified' tier"
    # Must NOT say "else static" without mentioning stage2
    # The instruction should reference stage2_verdict
    assert "stage2" in prompt.lower() or "stage 2" in prompt.lower(), (
        "summary prompt must reference stage2_verdict for the middle tier"
    )


def test_disclosure_footer_is_evidence_tier_aware():
    """Disclosure footer must not unconditionally say 'static analysis'."""
    from report.generator import load_prompt
    prompt = load_prompt("disclosure")
    # Must NOT have unconditional "Discovered via static analysis."
    assert "Discovered via static analysis." not in prompt or "stage2" in prompt.lower(), (
        "disclosure footer must not unconditionally say 'static analysis'"
    )
