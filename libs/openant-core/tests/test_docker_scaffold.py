"""Regression tests for Dockerfile scaffold pre-staging.

The dynamic-test scaffold must stage the vulnerable source file into the
Docker build context BEFORE asking the LLM to write the Dockerfile, so
`COPY VulnerablePythonScript.py .` works on the first try.
"""

import os
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


def test_write_test_files_stages_source(tmp_path):
    """_write_test_files must copy the vulnerable source into the work dir."""
    from utilities.dynamic_tester.docker_executor import _write_test_files

    # Create a fake source file to stage
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    source = repo_dir / "app.py"
    source.write_text("def vuln(): pass")

    generation = {
        "dockerfile": "FROM python:3.11\nCOPY app.py .\nCMD python app.py",
        "test_script": "print('test')",
        "test_filename": "test_exploit.py",
        "requirements": "flask",
    }

    finding = {
        "location": {"file": "app.py", "function": "app.py:vuln"},
    }

    work_dir = str(tmp_path / "work")
    os.makedirs(work_dir)

    _write_test_files(work_dir, generation, source_file=str(source))

    staged = os.path.join(work_dir, "app.py")
    assert os.path.exists(staged), "source file must be staged into work_dir"
    assert open(staged).read() == "def vuln(): pass"


def test_write_test_files_works_without_source(tmp_path):
    """Backward compat: _write_test_files must not fail when no source_file is given."""
    from utilities.dynamic_tester.docker_executor import _write_test_files

    generation = {
        "dockerfile": "FROM python:3.11\nCMD echo hi",
        "test_script": "print('test')",
        "test_filename": "test_exploit.py",
    }

    work_dir = str(tmp_path / "work")
    os.makedirs(work_dir)

    # Must not raise
    _write_test_files(work_dir, generation)


# ---------------------------------------------------------------------------
# Link 3: orchestrator resolves source_file and passes it to run_single_container
# ---------------------------------------------------------------------------

def test_orchestrator_passes_source_file(tmp_path, monkeypatch):
    """run_dynamic_tests must resolve source_file from repo_path + finding.location.file
    and pass it through to run_single_container."""
    import json

    # Create a fake repo with a source file
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def vuln(): pass")

    # Create a minimal pipeline_output.json
    po = {
        "repository": {"name": "test", "language": "python"},
        "application_type": "web_app",
        "findings": [{
            "id": "VULN-001",
            "name": "test vuln",
            "short_name": "vuln",
            "location": {"file": "app.py", "function": "app.py:vuln"},
            "cwe_id": 79,
            "cwe_name": "XSS",
            "stage1_verdict": "vulnerable",
            "stage2_verdict": "confirmed",
        }],
    }
    po_path = tmp_path / "pipeline_output.json"
    po_path.write_text(json.dumps(po))

    # Track what run_single_container receives
    captured_kwargs = {}

    def mock_generate_test(finding, repo_info, tracker):
        return {
            "dockerfile": "FROM python:3.11\nCMD echo hi",
            "test_script": "print('ok')",
            "test_filename": "test_exploit.py",
        }

    def mock_run_single_container(generation, finding_id, source_file=None, **kwargs):
        captured_kwargs["source_file"] = source_file
        from utilities.dynamic_tester.docker_executor import DockerExecutionResult
        result = DockerExecutionResult()
        result.stdout = '{"status": "CONFIRMED", "details": "test", "evidence": []}'
        result.exit_code = 0
        return result

    monkeypatch.setattr("utilities.dynamic_tester.generate_test", mock_generate_test)
    monkeypatch.setattr("utilities.dynamic_tester.run_single_container", mock_run_single_container)

    from utilities.dynamic_tester import run_dynamic_tests
    run_dynamic_tests(
        pipeline_output_path=str(po_path),
        output_dir=str(tmp_path / "out"),
        max_retries=0,
        repo_path=str(repo),
    )

    assert captured_kwargs.get("source_file") is not None, (
        "orchestrator must pass source_file to run_single_container"
    )
    assert captured_kwargs["source_file"].endswith("app.py")
    assert os.path.isfile(captured_kwargs["source_file"])


def test_orchestrator_works_without_repo_path(tmp_path, monkeypatch):
    """Backward compat: when repo_path is None, source_file should be None."""
    import json

    po = {
        "repository": {"name": "test", "language": "python"},
        "application_type": "web_app",
        "findings": [{
            "id": "VULN-001",
            "name": "test",
            "short_name": "vuln",
            "location": {"file": "app.py", "function": "app.py:vuln"},
            "cwe_id": 79,
            "cwe_name": "XSS",
            "stage1_verdict": "vulnerable",
            "stage2_verdict": "confirmed",
        }],
    }
    po_path = tmp_path / "pipeline_output.json"
    po_path.write_text(json.dumps(po))

    captured_kwargs = {}

    def mock_generate_test(finding, repo_info, tracker):
        return {
            "dockerfile": "FROM python:3.11\nCMD echo hi",
            "test_script": "print('ok')",
            "test_filename": "test_exploit.py",
        }

    def mock_run_single_container(generation, finding_id, source_file=None, **kwargs):
        captured_kwargs["source_file"] = source_file
        from utilities.dynamic_tester.docker_executor import DockerExecutionResult
        result = DockerExecutionResult()
        result.stdout = '{"status": "CONFIRMED", "details": "test", "evidence": []}'
        result.exit_code = 0
        return result

    monkeypatch.setattr("utilities.dynamic_tester.generate_test", mock_generate_test)
    monkeypatch.setattr("utilities.dynamic_tester.run_single_container", mock_run_single_container)

    from utilities.dynamic_tester import run_dynamic_tests
    run_dynamic_tests(
        pipeline_output_path=str(po_path),
        output_dir=str(tmp_path / "out"),
        max_retries=0,
    )

    assert captured_kwargs.get("source_file") is None, (
        "without repo_path, source_file must be None (backward compat)"
    )


# ---------------------------------------------------------------------------
# Link 4 + prompt: existing tests
# ---------------------------------------------------------------------------

def test_finding_prompt_includes_source_basename():
    """_build_finding_prompt must tell the LLM the staged filename."""
    from utilities.dynamic_tester.test_generator import _build_finding_prompt

    finding = {
        "id": "VULN-001",
        "name": "Command Injection",
        "cwe_id": 78,
        "cwe_name": "Command Injection",
        "location": {"file": "VulnerablePythonScript.py", "function": "ping"},
        "stage1_verdict": "vulnerable",
        "stage2_verdict": "agreed",
        "vulnerable_code": "def ping(): ...",
    }
    repo_info = {"name": "test", "language": "python", "application_type": "web_app"}

    prompt = _build_finding_prompt(finding, repo_info)
    assert "VulnerablePythonScript.py" in prompt, (
        "prompt must mention the staged source filename so the LLM references it in COPY"
    )
