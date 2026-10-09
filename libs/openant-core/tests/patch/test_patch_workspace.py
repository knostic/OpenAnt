"""Tests for patch_workspace.temporary_repo_copy."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def _make_git_repo(tmp_path: Path) -> Path:
    """Init a minimal git repo with one committed file."""
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=tmp_path, capture_output=True)
    (tmp_path / "auth.py").write_text(
        "def authenticate(u, p):\n    return True\n", encoding="utf-8"
    )
    subprocess.run(["git", "add", "auth.py"], cwd=tmp_path, capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-m", "init"],
        cwd=tmp_path, capture_output=True, check=True,
    )
    return tmp_path


class TestTemporaryRepoCopy:
    def test_copy_contains_same_files(self, tmp_path):
        from utilities.autopatcher.patch_workspace import temporary_repo_copy
        repo = _make_git_repo(tmp_path)
        with temporary_repo_copy(repo) as workspace_root:
            assert (workspace_root / "auth.py").exists()
            assert (workspace_root / "auth.py").read_text(encoding="utf-8") == (repo / "auth.py").read_text(encoding="utf-8")

    def test_copy_is_a_different_path(self, tmp_path):
        from utilities.autopatcher.patch_workspace import temporary_repo_copy
        repo = _make_git_repo(tmp_path)
        with temporary_repo_copy(repo) as workspace_root:
            assert workspace_root != repo
            assert str(workspace_root) != str(repo)

    def test_git_directory_included(self, tmp_path):
        """`.git` must survive the copy so git-based tooling (apply_patch)
        works against the copy unmodified."""
        from utilities.autopatcher.patch_workspace import temporary_repo_copy
        repo = _make_git_repo(tmp_path)
        with temporary_repo_copy(repo) as workspace_root:
            assert (workspace_root / ".git").exists()

    def test_original_repo_never_modified(self, tmp_path):
        from utilities.autopatcher.patch_workspace import temporary_repo_copy
        repo = _make_git_repo(tmp_path)
        original_content = (repo / "auth.py").read_text(encoding="utf-8")
        with temporary_repo_copy(repo) as workspace_root:
            (workspace_root / "auth.py").write_text("mutated in the copy\n", encoding="utf-8")
            (workspace_root / "new_file.py").write_text("new\n", encoding="utf-8")
        # Original repo untouched, both during and after the context.
        assert (repo / "auth.py").read_text(encoding="utf-8") == original_content
        assert not (repo / "new_file.py").exists()

    def test_cleanup_removes_temp_dir_on_normal_exit(self, tmp_path):
        from utilities.autopatcher.patch_workspace import temporary_repo_copy
        repo = _make_git_repo(tmp_path)
        captured_root = None
        with temporary_repo_copy(repo) as workspace_root:
            captured_root = workspace_root
            assert captured_root.exists()
        assert not captured_root.exists()
        assert not captured_root.parent.exists()

    def test_cleanup_removes_temp_dir_on_exception(self, tmp_path):
        from utilities.autopatcher.patch_workspace import temporary_repo_copy
        repo = _make_git_repo(tmp_path)
        captured_root = None
        with pytest.raises(RuntimeError):
            with temporary_repo_copy(repo) as workspace_root:
                captured_root = workspace_root
                raise RuntimeError("boom")
        assert captured_root is not None
        assert not captured_root.exists()

    def test_ignores_pycache_and_node_modules(self, tmp_path):
        from utilities.autopatcher.patch_workspace import temporary_repo_copy
        repo = _make_git_repo(tmp_path)
        (repo / "__pycache__").mkdir()
        (repo / "__pycache__" / "x.pyc").write_text("junk", encoding="utf-8")
        (repo / "node_modules").mkdir()
        (repo / "node_modules" / "pkg.js").write_text("junk", encoding="utf-8")
        with temporary_repo_copy(repo) as workspace_root:
            assert not (workspace_root / "__pycache__").exists()
            assert not (workspace_root / "node_modules").exists()
            assert (workspace_root / "auth.py").exists()

    def test_multiple_concurrent_copies_are_independent(self, tmp_path):
        from utilities.autopatcher.patch_workspace import temporary_repo_copy
        repo = _make_git_repo(tmp_path)
        with temporary_repo_copy(repo) as workspace_root_1, temporary_repo_copy(repo) as workspace_root_2:
            assert workspace_root_1 != workspace_root_2
            (workspace_root_1 / "auth.py").write_text("copy one\n", encoding="utf-8")
            (workspace_root_2 / "auth.py").write_text("copy two\n", encoding="utf-8")
            assert (workspace_root_1 / "auth.py").read_text(encoding="utf-8") == "copy one\n"
            assert (workspace_root_2 / "auth.py").read_text(encoding="utf-8") == "copy two\n"
