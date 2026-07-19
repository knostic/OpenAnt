"""Regression: run_dynamic_tests must enforce the DYNAMIC_TESTABLE filter.

core/dynamic_tester.py computes a DYNAMIC_TESTABLE filter for reporting, but
the actual per-finding loop lives in utilities/dynamic_tester/run_dynamic_tests.
Without enforcement AT that loop, findings whose stage2_verdict is NOT in
DYNAMIC_TESTABLE (e.g. "rejected") get a Docker reproduction attempt anyway.
"""

import json
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

if "anthropic" not in sys.modules:
    _stub = types.ModuleType("anthropic")
    _stub.Anthropic = MagicMock()
    _stub.RateLimitError = type("RateLimitError", (Exception,), {})
    _stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    sys.modules["anthropic"] = _stub


def _fake_registry():
    from utilities.llm import PhaseBinding, PhaseRegistry

    class _NoopAdapter:
        name = "anthropic"
        supports_tools = True

        def complete(self, **kwargs):  # pragma: no cover - mocked away
            raise AssertionError("should not reach the adapter")

        def validate(self, model):
            pass

    adapter = _NoopAdapter()
    bindings = {
        phase: PhaseBinding(
            phase=phase, adapter=adapter, model="test-model",
            provider_name="anthropic",
        )
        for phase in ("analyze", "enhance", "verify", "report",
                      "dynamic_test", "llm_reach", "app_context")
    }
    return PhaseRegistry(bindings=bindings, config_name="filter-test-config")


def test_non_testable_finding_is_not_dynamically_tested(tmp_path, monkeypatch):
    """A finding whose stage2_verdict is not in DYNAMIC_TESTABLE must be
    skipped by the execution loop, not handed to generate_test/Docker."""
    po = {
        "repository": {"name": "test", "language": "python"},
        "application_type": "web_app",
        "findings": [
            {
                "id": "TESTABLE-1",
                "name": "confirmed vuln",
                "short_name": "vuln",
                "location": {"file": "app.py", "function": "app.py:vuln"},
                "cwe_id": 79,
                "cwe_name": "XSS",
                "stage1_verdict": "vulnerable",
                "stage2_verdict": "confirmed",   # in DYNAMIC_TESTABLE
            },
            {
                "id": "NOT-TESTABLE-1",
                "name": "rejected finding",
                "short_name": "rej",
                "location": {"file": "app.py", "function": "app.py:safe"},
                "cwe_id": 79,
                "cwe_name": "XSS",
                "stage1_verdict": "vulnerable",
                "stage2_verdict": "rejected",    # NOT in DYNAMIC_TESTABLE
            },
        ],
    }
    po_path = tmp_path / "pipeline_output.json"
    po_path.write_text(json.dumps(po))

    tested_ids = []

    def mock_generate_test(finding, repo_info, binding, tracker):
        tested_ids.append(finding.get("id"))
        return {
            "dockerfile": "FROM python:3.11\nCMD echo hi",
            "test_script": "print('ok')",
            "test_filename": "test_exploit.py",
        }

    def mock_run_single_container(generation, finding_id, source_file=None, **kwargs):
        from utilities.dynamic_tester.docker_executor import DockerExecutionResult
        result = DockerExecutionResult()
        result.stdout = '{"status": "CONFIRMED", "details": "t", "evidence": []}'
        result.exit_code = 0
        return result

    monkeypatch.setattr("utilities.dynamic_tester.generate_test", mock_generate_test)
    monkeypatch.setattr("utilities.dynamic_tester.run_single_container",
                        mock_run_single_container)

    from utilities.dynamic_tester import run_dynamic_tests
    results = run_dynamic_tests(
        pipeline_output_path=str(po_path),
        output_dir=str(tmp_path / "out"),
        max_retries=0,
        registry=_fake_registry(),
    )

    assert tested_ids == ["TESTABLE-1"], (
        "non-testable finding must NOT be handed to the dynamic tester; "
        f"generate_test was called for {tested_ids}"
    )
    assert {r.finding_id for r in results} == {"TESTABLE-1"}
