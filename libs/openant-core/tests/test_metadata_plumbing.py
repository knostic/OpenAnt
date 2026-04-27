"""Regression tests for repo-metadata plumbing into pipeline output.

build_pipeline_output() must carry repo_name, repo_url, commit_sha, and
language into pipeline_output.json when provided by the caller.
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


@pytest.fixture
def minimal_results(tmp_path: Path) -> Path:
    results = {
        "dataset": "test",
        "results": [{
            "unit_id": "app.py:foo",
            "route_key": "app.py:foo",
            "verdict": "vulnerable",
            "finding": "vulnerable",
            "cwe_id": 79,
            "cwe_name": "XSS",
        }],
        "code_by_route": {"app.py:foo": "def foo(): pass"},
        "confirmed_findings": [{
            "unit_id": "app.py:foo",
            "route_key": "app.py:foo",
            "verdict": "vulnerable",
            "finding": "vulnerable",
        }],
        "metrics": {"total": 1, "vulnerable": 1},
    }
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return path


def test_pipeline_output_carries_repo_metadata(tmp_path, minimal_results):
    from core.reporter import build_pipeline_output
    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(minimal_results),
        output_path=str(out),
        repo_name="example/vulnerable-test-app",
        repo_url="https://github.com/example/vulnerable-test-app",
        commit_sha="3804a18ae66",
        language="python",
    )
    data = json.loads(out.read_text())
    repo = data["repository"]

    assert repo["name"] == "example/vulnerable-test-app"
    assert repo["url"] == "https://github.com/example/vulnerable-test-app"
    assert repo["commit_sha"] == "3804a18ae66"
    assert repo["language"] == "python"


def test_pipeline_output_no_not_provided_when_metadata_given(tmp_path, minimal_results):
    """No field in the repository section should be empty or null when all inputs are provided."""
    from core.reporter import build_pipeline_output
    out = tmp_path / "po.json"
    build_pipeline_output(
        results_path=str(minimal_results),
        output_path=str(out),
        repo_name="org/repo",
        repo_url="https://github.com/org/repo",
        commit_sha="abc123",
        language="python",
    )
    data = json.loads(out.read_text())
    repo = data["repository"]
    for key, value in repo.items():
        assert value, f"repository.{key} is empty/null: {value!r}"
