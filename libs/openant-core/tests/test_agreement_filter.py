"""Regression tests for the agreement filter dropping real vulnerabilities.

When Stage 2 disagrees on the REASON (e.g. different CWE) but agrees on the
VERDICT (vulnerable), the finding must still be emitted. The old filter checked
`verification.agree` instead of the final `finding` field, dropping findings
where Stage 2 said "disagree but still vulnerable."
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
# Test 1: Disagree on reason, agree on verdict → MUST be emitted
# ---------------------------------------------------------------------------

@pytest.fixture
def disagree_reason_results(tmp_path: Path) -> Path:
    """Stage 1 says CWE-798, Stage 2 says CWE-307. Both say vulnerable.
    Stage 2 sets agree=False because it disagrees with the reasoning.
    experiment.py already updated finding to verification.correct_finding.
    """
    results = {
        "dataset": "agreement-test",
        "results": [
            {
                "unit_id": "app.py:login",
                "route_key": "app.py:login",
                "verdict": "VULNERABLE",
                "finding": "vulnerable",  # already updated by experiment.py:758
                "attack_vector": "timing attack on == operator",
                "reasoning": "hardcoded credentials",
                "cwe_id": 798,
                "cwe_name": "Hardcoded Credentials",
                "verification": {
                    "agree": False,  # disagrees on REASON, not verdict
                    "correct_finding": "vulnerable",
                    "explanation": "The real issue is timing side-channel, not hardcoded creds",
                },
            },
        ],
        "code_by_route": {"app.py:login": "def login(): ..."},
        "metrics": {"total": 1, "vulnerable": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


def test_disagree_reason_still_emitted(tmp_path, disagree_reason_results):
    """A finding where Stage 2 disagrees on reason but agrees on verdict
    must appear in pipeline_output.json."""
    from core.reporter import build_pipeline_output
    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(disagree_reason_results),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 1, (
        f"expected 1 finding (login), got {len(data['findings'])}. "
        "The agreement filter is dropping findings where agree=False "
        "but correct_finding=vulnerable."
    )
    assert "login" in data["findings"][0]["location"]["function"]


# ---------------------------------------------------------------------------
# Test 2: Disagree on verdict → MUST be dropped
# ---------------------------------------------------------------------------

@pytest.fixture
def disagree_verdict_results(tmp_path: Path) -> Path:
    """Stage 1 says vulnerable. Stage 2 says safe. agree=False, correct_finding=safe.
    experiment.py updated finding to 'safe'. This must NOT be emitted.
    """
    results = {
        "dataset": "agreement-test-drop",
        "results": [
            {
                "unit_id": "app.py:requests_example",
                "route_key": "app.py:requests_example",
                "verdict": "SAFE",  # updated by experiment.py
                "finding": "safe",  # updated by experiment.py:758
                "attack_vector": None,
                "reasoning": "hardcoded URL, no user input",
                "verification": {
                    "agree": False,
                    "correct_finding": "safe",
                    "explanation": "Stage 1 was wrong, this is safe",
                },
            },
        ],
        "code_by_route": {"app.py:requests_example": "def requests_example(): ..."},
        "metrics": {"total": 1, "safe": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


def test_disagree_verdict_dropped(tmp_path, disagree_verdict_results):
    """A finding where Stage 2 changed the verdict to safe must NOT appear."""
    from core.reporter import build_pipeline_output
    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(disagree_verdict_results),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 0, (
        "finding changed to safe by Stage 2 must not appear in pipeline_output"
    )


# ---------------------------------------------------------------------------
# Test 3: Normal agreement → still works (regression guard)
# ---------------------------------------------------------------------------

@pytest.fixture
def normal_agree_results(tmp_path: Path) -> Path:
    """Standard case: Stage 2 agrees with Stage 1. agree=True."""
    results = {
        "dataset": "agreement-test-normal",
        "results": [
            {
                "unit_id": "app.py:unserialize",
                "route_key": "app.py:unserialize",
                "verdict": "VULNERABLE",
                "finding": "vulnerable",
                "attack_vector": "POST /unserialize with pickle payload",
                "reasoning": "pickle.loads on untrusted input",
                "cwe_id": 502,
                "cwe_name": "Deserialization",
                "verification": {
                    "agree": True,
                    "correct_finding": "vulnerable",
                    "explanation": "Confirmed: pickle.loads is exploitable",
                },
            },
        ],
        "code_by_route": {"app.py:unserialize": "def unserialize(): ..."},
        "metrics": {"total": 1, "vulnerable": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


def test_normal_agreement_emitted(tmp_path, normal_agree_results):
    """Standard agreement case must still be emitted (regression guard)."""
    from core.reporter import build_pipeline_output
    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(normal_agree_results),
        output_path=str(out),
        language="python",
    )
    data = json.loads(out.read_text())
    assert len(data["findings"]) == 1
    assert "unserialize" in data["findings"][0]["location"]["function"]


# ---------------------------------------------------------------------------
# Test 4: _write_verified_results confirmed_findings filter
# ---------------------------------------------------------------------------

def test_verifier_confirmed_findings_includes_disagree_vulnerable():
    """The confirmed_findings list in results_verified.json must include
    findings where agree=False but correct_finding=vulnerable."""
    from core.verifier import _write_verified_results
    import tempfile, os

    experiment = {"dataset": "test", "metrics": {}}
    merged = [
        {
            "route_key": "app.py:login",
            "finding": "vulnerable",
            "verification": {"agree": False, "correct_finding": "vulnerable"},
        },
        {
            "route_key": "app.py:safe_fn",
            "finding": "safe",
            "verification": {"agree": True, "correct_finding": "safe"},
        },
    ]
    # verified_only = findings that went through Stage 2
    verified_only = merged

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        path = f.name

    try:
        _write_verified_results(path, experiment, merged, verified_only)
        data = json.loads(open(path).read())
        confirmed = data["confirmed_findings"]
        assert len(confirmed) == 1, f"expected 1 confirmed (login), got {len(confirmed)}"
        assert confirmed[0]["route_key"] == "app.py:login"
    finally:
        os.unlink(path)
