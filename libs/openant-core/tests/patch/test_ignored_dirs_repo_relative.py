"""Ignored-directory names ("build", "node_modules", ".venv", ...) must be
matched against a file's path RELATIVE to the repository root, never its
absolute path: a checkout that merely lives under e.g. /srv/build/repo must
not have every one of its files ignored. Directories with those names
INSIDE the repository must still be ignored (positive control)."""

from __future__ import annotations

from pathlib import Path

import pytest

from utilities.autopatcher.language_support import detect_language
from utilities.autopatcher.repo_locator import RepositoryPathResolver, _find_symbol_definitions, _grep_repo
from utilities.autopatcher.testing_support import discover_tests
from utilities.autopatcher.vulnerability_patterns import extract_repo_sinks

_PARENTS = ["plain", "build", "node_modules", ".venv", "dist"]


def _make_repo(base: Path, parent: str) -> Path:
    repo = base / parent / "repo"
    (repo / "app" / "sub").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "app" / "sub" / "files.py").write_text(
        "import os\n\ndef serve_file(name):\n    return open(os.path.normpath('/srv/' + name))\n"
    )
    (repo / "app" / "views.py").write_text(
        "from app.sub.files import serve_file\n\ndef view(n):\n    return serve_file(n)\n"
    )
    (repo / "tests" / "test_files.py").write_text(
        "from app.sub.files import serve_file\n\ndef test_x():\n    assert serve_file\n"
    )
    return repo


def _add_in_repo_ignored_dirs(repo: Path) -> None:
    """Copies of the same source under in-repo ignored directories -- these
    must keep being skipped."""
    for name in ("build", "node_modules", ".venv"):
        d = repo / name / "pkg"
        d.mkdir(parents=True)
        (d / "files.py").write_text((repo / "app" / "sub" / "files.py").read_text())
        (d / "test_vendored.py").write_text("def test_v():\n    pass\n")


@pytest.mark.parametrize("parent", _PARENTS)
class TestRepoUnderIgnoredNamedParent:
    def test_detect_language(self, tmp_path, parent):
        assert detect_language(_make_repo(tmp_path, parent)) == "python"

    def test_discover_tests(self, tmp_path, parent):
        repo = _make_repo(tmp_path, parent)
        assert [p.name for p in discover_tests(repo)] == ["test_files.py"]

    def test_grep_repo(self, tmp_path, parent):
        repo = _make_repo(tmp_path, parent)
        assert len(_grep_repo(repo, ["serve_file"])) == 2

    def test_find_symbol_definitions(self, tmp_path, parent):
        repo = _make_repo(tmp_path, parent)
        hits = _find_symbol_definitions("The function `serve_file` in app/sub/files.py is vulnerable.", repo)
        assert [p.relative_to(repo).as_posix() for p, _, _ in hits] == ["app/sub/files.py"]

    def test_path_resolver_suffix_match(self, tmp_path, parent):
        repo = _make_repo(tmp_path, parent)
        resolution = RepositoryPathResolver(repo).resolve("sub/files.py")
        assert resolution.strategy == "suffix"
        assert resolution.path == repo / "app" / "sub" / "files.py"

    def test_extract_repo_sinks(self, tmp_path, parent):
        repo = _make_repo(tmp_path, parent)
        assert [s["file"] for s in extract_repo_sinks(repo, "PATH_TRAVERSAL")] == ["app/sub/files.py"]


class TestInRepoIgnoredDirsStillIgnored:
    """Positive control: the fix is repo-relative, not a removal of the
    ignore lists."""

    def test_vendored_copies_never_surface(self, tmp_path):
        repo = _make_repo(tmp_path, "build")
        _add_in_repo_ignored_dirs(repo)
        # discover_tests' own list has build/.venv but not node_modules.
        found = {p.relative_to(repo.resolve()).as_posix() for p in discover_tests(repo)}
        assert "tests/test_files.py" in found
        assert not {f for f in found if f.startswith(("build/", ".venv/"))}
        assert {p.relative_to(repo).as_posix() for p, _, _ in _grep_repo(repo, ["serve_file"], limit=10)} == {
            "app/sub/files.py", "app/views.py",
        }
        defs = _find_symbol_definitions("The function `serve_file` in app/sub/files.py is vulnerable.", repo)
        assert [p.relative_to(repo).as_posix() for p, _, _ in defs] == ["app/sub/files.py"]
        assert RepositoryPathResolver(repo).resolve("sub/files.py").strategy == "suffix"
        assert RepositoryPathResolver(repo).resolve("pkg/files.py").strategy == "unresolved"
        assert [s["file"] for s in extract_repo_sinks(repo, "PATH_TRAVERSAL")] == ["app/sub/files.py"]

    def test_language_counts_skip_in_repo_ignored_dirs(self, tmp_path):
        repo = tmp_path / "repo"
        (repo / "node_modules" / "x").mkdir(parents=True)
        for i in range(5):
            (repo / "node_modules" / "x" / f"m{i}.js").write_text("module.exports = 1\n")
        (repo / "main.py").write_text("print(1)\n")
        assert detect_language(repo) == "python"
