"""PR #763 review: AUTOPATCHER_DEBUG must not write into the analyzed repository.

The debug writers resolve `./reports/debug` against the working directory, so
`cd <repo> && openant patch ...` with AUTOPATCHER_DEBUG=1 used to drop full
prompts (repository source included) inside the analyzed working copy. The
debug content and its opt-in are unchanged; only where it lands, and only
when the working directory is inside the analyzed repository.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.patch import run_patch
from utilities.autopatcher.debug_output import DEBUG_DIR_ENV, debug_dir, resolve_debug_dir

_FINDING = {
    "id": "VULN-001", "name": "Command injection in run_cmd",
    "cwe_id": "78", "cwe_name": "OS Command Injection",
    "stage1_verdict": "confirmed", "stage2_verdict": "confirmed",
    "location": {"file": "app/auth.py", "function": "run_cmd"},
    "description": "User input reaches os.system without validation.",
    "vulnerable_code": "def run_cmd(x):\n    os.system(x)\n",
}


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "auth.py").write_text("import os\n\n\ndef run_cmd(x):\n    os.system(x)\n", encoding="utf-8")
    (repo / "pipeline_output.json").write_text(json.dumps({"findings": [_FINDING]}), encoding="utf-8")
    return repo


def _debug_files(directory: Path) -> "list[str]":
    return sorted(p.name for p in directory.glob("*")) if directory.is_dir() else []


@pytest.fixture
def debug_on(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setenv("AUTOPATCHER_DEBUG", "1")
    monkeypatch.delenv(DEBUG_DIR_ENV, raising=False)


def _run(repo: Path, out: Path):
    return run_patch(str(repo / "pipeline_output.json"), "VULN-001", str(out), repo_root=str(repo))


class TestDebugOutputLocation:
    def test_run_from_inside_the_analyzed_repository_writes_nothing_into_it(self, tmp_path, monkeypatch, debug_on):
        repo, out = _repo(tmp_path), tmp_path / "out"
        monkeypatch.chdir(repo)
        _run(repo, out)
        assert not (repo / "reports").exists()
        written = _debug_files(out / "debug")
        assert any(name.startswith("prompt_") for name in written), written
        assert os.environ.get(DEBUG_DIR_ENV) is None  # restored after the run

    def test_run_from_outside_the_repository_keeps_the_working_directory_location(
        self, tmp_path, monkeypatch, debug_on,
    ):
        """The established location (run_cve_batch gives every attempt its own
        working directory outside the checkout) is unchanged."""
        repo, out, cwd = _repo(tmp_path), tmp_path / "out", tmp_path / "cwd"
        cwd.mkdir()
        monkeypatch.chdir(cwd)
        _run(repo, out)
        assert any(name.startswith("prompt_") for name in _debug_files(cwd / "reports" / "debug"))
        assert not (out / "debug").exists()
        assert not (repo / "reports").exists()

    def test_explicit_debug_directory_is_honored(self, tmp_path, monkeypatch, debug_on):
        repo, out, explicit = _repo(tmp_path), tmp_path / "out", tmp_path / "chosen"
        monkeypatch.setenv(DEBUG_DIR_ENV, str(explicit))
        monkeypatch.chdir(repo)
        _run(repo, out)
        assert any(name.startswith("prompt_") for name in _debug_files(explicit))
        assert not (repo / "reports").exists()


class TestResolveDebugDir:
    def test_default_is_the_working_directory_location(self, tmp_path, monkeypatch):
        monkeypatch.delenv(DEBUG_DIR_ENV, raising=False)
        monkeypatch.chdir(tmp_path)
        assert debug_dir() == Path("reports") / "debug"
        assert resolve_debug_dir(tmp_path / "elsewhere", tmp_path / "out") == Path("reports") / "debug"

    def test_inside_the_repository_resolves_to_the_run_output(self, tmp_path, monkeypatch):
        monkeypatch.delenv(DEBUG_DIR_ENV, raising=False)
        (tmp_path / "repo" / "sub").mkdir(parents=True)
        monkeypatch.chdir(tmp_path / "repo" / "sub")
        assert resolve_debug_dir(tmp_path / "repo", tmp_path / "out") == tmp_path / "out" / "debug"

    def test_explicit_setting_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv(DEBUG_DIR_ENV, str(tmp_path / "chosen"))
        monkeypatch.chdir(tmp_path)
        assert debug_dir() == tmp_path / "chosen"
        assert resolve_debug_dir(tmp_path, tmp_path / "out") == tmp_path / "chosen"
