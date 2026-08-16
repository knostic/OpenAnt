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


def _fake_registry():
    """Build a PhaseRegistry whose adapter never probes the network.

    The orchestrator tests below mock ``generate_test`` and
    ``run_single_container`` so the adapter is never actually called.
    But ``run_dynamic_tests`` still builds a registry when none is
    passed in, which probes Anthropic at startup. Pre-issue-#65 the
    test relied on an ``ANTHROPIC_API_KEY`` happening to be in env;
    that's no longer reliable. Injecting a fake registry removes the
    env dependency entirely.
    """
    from utilities.llm import PhaseBinding, PhaseRegistry

    class _NoopAdapter:
        name = "anthropic"
        supports_tools = True

        def complete(self, **kwargs):  # pragma: no cover - mocked away
            raise AssertionError("orchestrator tests should not reach the adapter")

        def validate(self, model):
            pass

    adapter = _NoopAdapter()
    bindings = {
        phase: PhaseBinding(
            phase=phase,
            adapter=adapter,
            model="test-model",
            provider_name="anthropic",
        )
        for phase in ("analyze", "enhance", "verify", "report", "dynamic_test", "llm_reach", "app_context")
    }
    return PhaseRegistry(bindings=bindings, config_name="docker-test-config")


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

    def mock_generate_test(finding, repo_info, binding, tracker):
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
        registry=_fake_registry(),
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

    def mock_generate_test(finding, repo_info, binding, tracker):
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
        registry=_fake_registry(),
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


# ---------------------------------------------------------------------------
# Staging path-traversal confinement (host-write + host-read escapes)
#
# The generation dict is LLM output influenced by the scanned repo, and
# finding.location.file is an LLM-emitted structured field. Neither may be
# used as a filesystem path without confining it to the staging root:
#   * generation['test_filename'] / ['requirements_filename'] are joined to
#     work_dir and written -> a `..`/absolute name is a HOST-WRITE escape.
#   * finding.location.file is joined to repo_path and copied into the build
#     context -> a `..`/absolute value is a HOST-READ/exfil escape.
# The staging happens on the host BEFORE any container runs, so the container
# runtime hardening (#253) does not cover it.
# ---------------------------------------------------------------------------

def test_write_test_files_confines_traversal_test_filename(tmp_path):
    """A `..`-traversal generation['test_filename'] must not write outside work_dir."""
    from utilities.dynamic_tester.docker_executor import _write_test_files

    work_dir = str(tmp_path / "work")
    os.makedirs(work_dir)
    escape_target = tmp_path / "PWNED_test.py"  # sibling of work_dir, outside it

    generation = {
        "dockerfile": "FROM python:3.11\nCMD echo hi",
        "test_script": "print('pwn')",
        "test_filename": "../PWNED_test.py",  # escapes work_dir
    }
    _write_test_files(work_dir, generation)

    assert not escape_target.exists(), (
        f"test_filename traversal escaped work_dir -> host-write at {escape_target}"
    )
    # Content is confined to a bare leaf inside work_dir.
    assert (tmp_path / "work" / "PWNED_test.py").exists()


def test_write_test_files_confines_absolute_requirements_filename(tmp_path):
    """An absolute generation['requirements_filename'] must not write to a host path."""
    from utilities.dynamic_tester.docker_executor import _write_test_files

    work_dir = str(tmp_path / "work")
    os.makedirs(work_dir)
    escape_target = tmp_path / "PWNED_reqs.txt"

    generation = {
        "dockerfile": "FROM python:3.11\nCMD echo hi",
        "test_script": "print('ok')",
        "test_filename": "test_exploit.py",
        "requirements": "flask",
        "requirements_filename": str(escape_target),  # absolute path outside work_dir
    }
    _write_test_files(work_dir, generation)

    assert not escape_target.exists(), (
        f"requirements_filename absolute path escaped work_dir -> host-write at {escape_target}"
    )


def test_orchestrator_rejects_out_of_repo_source(tmp_path, monkeypatch):
    """A `..`-traversal finding.location.file must not resolve OUTSIDE repo_path.

    Otherwise a host file (secret) outside the scanned repo is copied into the
    Docker build context and can be exfiltrated by the LLM-authored test script.
    """
    import json

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("def vuln(): pass")
    # A host secret OUTSIDE the repo the attacker tries to reach via traversal.
    secret = tmp_path / "SECRET.txt"
    secret.write_text("top-secret")

    po = {
        "repository": {"name": "test", "language": "python"},
        "application_type": "web_app",
        "findings": [{
            "id": "VULN-001", "name": "t", "short_name": "vuln",
            "location": {"file": "../SECRET.txt", "function": "x"},
            "cwe_id": 79, "cwe_name": "XSS",
            "stage1_verdict": "vulnerable", "stage2_verdict": "confirmed",
        }],
    }
    po_path = tmp_path / "pipeline_output.json"
    po_path.write_text(json.dumps(po))

    captured = {}

    def mock_generate_test(finding, repo_info, binding, tracker):
        return {
            "dockerfile": "FROM python:3.11\nCMD echo hi",
            "test_script": "print('ok')",
            "test_filename": "test_exploit.py",
        }

    def mock_run_single_container(generation, finding_id, source_file=None, **kwargs):
        captured["source_file"] = source_file
        from utilities.dynamic_tester.docker_executor import DockerExecutionResult
        r = DockerExecutionResult()
        r.stdout = '{"status": "CONFIRMED", "details": "t", "evidence": []}'
        r.exit_code = 0
        return r

    monkeypatch.setattr("utilities.dynamic_tester.generate_test", mock_generate_test)
    monkeypatch.setattr("utilities.dynamic_tester.run_single_container", mock_run_single_container)

    from utilities.dynamic_tester import run_dynamic_tests
    run_dynamic_tests(
        pipeline_output_path=str(po_path),
        output_dir=str(tmp_path / "out"),
        max_retries=0,
        repo_path=str(repo),
        registry=_fake_registry(),
    )

    assert captured.get("source_file") is None, (
        f"traversal location.file escaped repo_path -> host-read/exfil: {captured.get('source_file')!r}"
    )
