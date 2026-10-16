"""PR #763 HUNT U1: git configuration from the analyzed repository (filter
drivers in `.git/config` selected by `.git/info/attributes` or an in-tree
`.gitattributes`) or from the inherited environment must never execute during
`git apply --check` or the workspace `git apply`.

Every repository, filter script and marker file lives under pytest's
`tmp_path`; the filter "command" is a benign script that only appends a word
to a marker file there and passes the content through.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from utilities.autopatcher import patch_applicability as pa
from utilities.autopatcher.patch_workspace import temporary_repo_copy

PATCH = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,3 @@\n def f(x):\n+    x = int(x)\n     return x\n"
BAD_PATCH = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,3 @@\n def g(y):\n+    y = int(y)\n     return y\n"
_GIT = ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false"]


def _git(repo: Path, *args: str, env=None) -> subprocess.CompletedProcess:
    return subprocess.run([*_GIT, *args], cwd=repo, check=True, capture_output=True, env=env)


@pytest.fixture
def marker(tmp_path: Path) -> Path:
    return tmp_path / "MARKER"


def _filter_command(tmp_path: Path, marker: Path, word: str) -> str:
    script = tmp_path / "filter_probe.py"
    script.write_text(
        "import sys\n"
        "with open(sys.argv[2], 'a') as fh:\n"
        "    fh.write(sys.argv[1] + '\\n')\n"
        "sys.stdout.write(sys.stdin.read())\n"
    )
    return f'"{Path(sys.executable).as_posix()}" "{script.as_posix()}" {word} "{marker.as_posix()}"'


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "app.py").write_text("def f(x):\n    return x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


def _arm_local_filter(repo: Path, tmp_path: Path, marker: Path, via: str = "info") -> None:
    """Configure the filter AFTER the commit, so committing never runs it."""
    if via == "info":
        (repo / ".git" / "info").mkdir(exist_ok=True)
        (repo / ".git" / "info" / "attributes").write_text("*.py filter=probe\n")
    else:
        (repo / ".gitattributes").write_text("*.py filter=probe\n")
        _git(repo, "add", ".gitattributes")
        _git(repo, "commit", "-qm", "attrs")
    _git(repo, "config", "filter.probe.clean", _filter_command(tmp_path, marker, "clean"))
    _git(repo, "config", "filter.probe.smudge", _filter_command(tmp_path, marker, "smudge"))


def _snapshot(root: Path) -> dict:
    return {
        str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
        for p in root.rglob("*") if p.is_file()
    }


class TestPreconditionTheFilterIsLive:
    def test_plain_git_apply_runs_the_repository_filter(self, tmp_path, marker):
        """Control: the configuration really executes under a plain
        `git apply --check` in the analyzed repository (the pre-fix call)."""
        repo = _repo(tmp_path)
        _arm_local_filter(repo, tmp_path, marker)
        subprocess.run(["git", "apply", "--check", "-"], cwd=repo, input=PATCH.encode(), check=True,
                       capture_output=True)
        assert marker.read_text().split() == ["clean"]


class TestNoRepositoryConfigurationExecutes:
    @pytest.mark.parametrize("via", ["info", "in-tree"])
    def test_check_applicability(self, tmp_path, marker, via):
        repo = _repo(tmp_path)
        _arm_local_filter(repo, tmp_path, marker, via)
        before = _snapshot(repo)
        result = pa.check_applicability(PATCH, repo)
        assert result["applicable"] is True, result
        assert not marker.exists()
        assert _snapshot(repo) == before, "the analyzed repository must not be written"

    @pytest.mark.parametrize("via", ["info", "in-tree"])
    def test_workspace_apply(self, tmp_path, marker, via):
        repo = _repo(tmp_path)
        _arm_local_filter(repo, tmp_path, marker, via)
        with temporary_repo_copy(repo) as workspace:
            applied = pa.apply_patch(PATCH, workspace)
            content = (workspace / "app.py").read_text()
        assert applied.applied, applied
        assert content == "def f(x):\n    x = int(x)\n    return x\n"
        assert not marker.exists()

    def test_repository_fsmonitor_hook_does_not_run(self, tmp_path, marker):
        repo = _repo(tmp_path)
        _git(repo, "config", "core.fsmonitor", _filter_command(tmp_path, marker, "fsmonitor"))
        assert pa.check_applicability(PATCH, repo)["applicable"] is True
        assert not marker.exists()


class TestNoInheritedConfigurationExecutes:
    @pytest.fixture
    def attributed_repo(self, tmp_path):
        repo = _repo(tmp_path)
        (repo / ".git" / "info").mkdir(exist_ok=True)
        (repo / ".git" / "info" / "attributes").write_text("*.py filter=probe\n")
        return repo

    def test_git_config_count_environment(self, tmp_path, marker, attributed_repo, monkeypatch):
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "filter.probe.clean")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", _filter_command(tmp_path, marker, "env"))
        assert pa.check_applicability(PATCH, attributed_repo)["applicable"] is True
        assert not marker.exists()

    def test_git_config_parameters_environment(self, tmp_path, marker, attributed_repo, monkeypatch):
        command = _filter_command(tmp_path, marker, "params").replace("'", "")
        monkeypatch.setenv("GIT_CONFIG_PARAMETERS", f"'filter.probe.clean={command}'")
        assert pa.check_applicability(PATCH, attributed_repo)["applicable"] is True
        assert not marker.exists()

    def test_global_configuration_file(self, tmp_path, marker, attributed_repo, monkeypatch):
        global_config = tmp_path / "global.gitconfig"
        global_config.write_text(f"[filter \"probe\"]\n\tclean = {_filter_command(tmp_path, marker, 'global')}\n")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
        monkeypatch.setenv("HOME", str(tmp_path))
        assert pa.check_applicability(PATCH, attributed_repo)["applicable"] is True
        assert not marker.exists()

    def test_inherited_git_dir_is_ignored(self, tmp_path, marker, attributed_repo, monkeypatch):
        """A GIT_DIR in the environment pointing at the armed repository
        must not bring its configuration back."""
        _git(attributed_repo, "config", "filter.probe.clean", _filter_command(tmp_path, marker, "gitdir"))
        monkeypatch.setenv("GIT_DIR", str(attributed_repo / ".git"))
        assert pa.check_applicability(PATCH, attributed_repo)["applicable"] is True
        assert not marker.exists()


class TestApplicabilityIsPreserved:
    def test_a_patch_that_does_not_apply_is_still_rejected(self, tmp_path):
        repo = _repo(tmp_path)
        result = pa.check_applicability(BAD_PATCH, repo)
        assert result["applicable"] is False and result["skipped"] is False

    def test_rejected_workspace_apply(self, tmp_path):
        repo = _repo(tmp_path)
        with temporary_repo_copy(repo) as workspace:
            result = pa.apply_patch(BAD_PATCH, workspace)
        assert not result.applied and result.error_kind == "apply_rejected"

    def test_crlf_and_new_file_patches_still_apply(self, tmp_path):
        repo = _repo(tmp_path)
        new_file = "--- /dev/null\n+++ b/pkg/new.py\n@@ -0,0 +1,2 @@\n+def g():\n+    return 1\n"
        assert pa.check_applicability(new_file, repo)["applicable"] is True
        with temporary_repo_copy(repo) as workspace:
            assert pa.apply_patch(new_file, workspace).applied
            assert (workspace / "pkg" / "new.py").read_text() == "def g():\n    return 1\n"

    def test_isolation_failure_is_an_error_never_a_skip(self, tmp_path, monkeypatch):
        repo = _repo(tmp_path)

        def refuse(path):
            raise OSError("cannot create the isolated git directory")

        monkeypatch.setattr(pa, "_empty_git_dir", refuse)
        result = pa.check_applicability(PATCH, repo)
        assert result["applicable"] is None and result["skipped"] is False
        assert "isolated git directory" in (result["error"] or "")
        with temporary_repo_copy(repo) as workspace:
            applied = pa.apply_patch(PATCH, workspace)
        assert not applied.applied and applied.error_kind == "unexpected_error"
