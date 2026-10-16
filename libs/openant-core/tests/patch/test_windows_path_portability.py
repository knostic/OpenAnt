"""Windows portability regressions, simulated deterministically on any host.

- Repository-relative logical paths must use "/" on every host OS. On
  Windows ``str(p.relative_to(root))`` yields ``app\\x.py``; the
  ``_WinRelPath`` stand-in below reproduces exactly that, so these tests
  drive the real production code paths (Impact Surface's usage scan,
  Remediation Planner's ``_verify_file``) with Windows separator behavior.
- Git writes ``.git/objects`` files read-only, and on Windows ``os.unlink``
  refuses read-only files. ``_windows_unlink`` reproduces that, so cleanup
  of a real git repository copy is exercised with Windows semantics.
"""

from __future__ import annotations

import os
import stat
import subprocess
import textwrap
from pathlib import Path, PureWindowsPath

import pytest

from utilities.autopatcher import pipeline as pl
from utilities.autopatcher.impact_surface import LightweightImpactAnalyzer


class _WinRelPath(type(Path())):
    """A host-native Path whose relative_to() behaves like Windows: the
    result stringifies with backslashes (and as_posix() gives "/")."""

    def relative_to(self, *args, **kwargs):
        return PureWindowsPath(super().relative_to(*args, **kwargs).as_posix())


def test_simulation_is_faithful():
    rel = _WinRelPath("/r/app/x.py").relative_to(_WinRelPath("/r"))
    assert str(rel) == "app\\x.py"
    assert rel.as_posix() == "app/x.py"


# ---------------------------------------------------------------------------
# Impact Surface (W1)
# ---------------------------------------------------------------------------

class _WindowsRepoContext:
    """repo_context whose traversal root yields Windows-style relative paths.
    read_file accepts either separator, as Windows itself does."""

    def __init__(self, root: Path):
        self.repo_root = _WinRelPath(root)
        self._root = root

    def read_file(self, rel: str) -> str:
        return (self._root / PureWindowsPath(rel).as_posix()).read_text(encoding="utf-8")


def _repo(tmp_path, files):
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text), encoding="utf-8")
    return tmp_path


def _impact_windows(repo, diff):
    return LightweightImpactAnalyzer().analyze(diff, repo_context=_WindowsRepoContext(repo))


LONELY_REPO = {"app/__init__.py": "", "app/lonely.py": "def lonely(x):\n    return x\n"}


@pytest.mark.parametrize("name,diff", [
    ("attributed_body_change_without_callers", (
        "--- a/app/lonely.py\n+++ b/app/lonely.py\n@@ -1,2 +1,2 @@\n"
        " def lonely(x):\n-    return x\n+    return x + 1\n"
    )),
    ("import_line_plus_attributed_body_change", (
        "--- a/app/lonely.py\n+++ b/app/lonely.py\n@@ -1,2 +1,3 @@\n+import os\n"
        " def lonely(x):\n-    return x\n+    return os.fspath(x)\n"
    )),
])
def test_changed_file_is_not_its_own_caller_and_low_stays_low(tmp_path, name, diff):
    report = _impact_windows(_repo(tmp_path, LONELY_REPO), diff)
    assert report.affected_files == [], name
    assert all("\\" not in m.file for m in report.usage_matches), name
    assert report.impact_level == "low", name
    assert pl._resolve_impact_level(report.to_dict()) == "low"


def test_sensitive_auth_stays_medium_not_high(tmp_path):
    repo = _repo(tmp_path, {"app/auth.py": "def authenticate(user, pwd):\n    return True\n"})
    diff = "+++ b/app/auth.py\n@@ -1,1 +1,3 @@\n+def authenticate(user, pwd):\n+    return True\n"
    report = _impact_windows(repo, diff)
    assert report.affected_files == []
    assert report.impact_level == "medium"


def test_real_external_caller_still_counted_with_posix_path(tmp_path):
    repo = _repo(tmp_path, {
        **LONELY_REPO,
        "lib/user.py": "from app.lonely import lonely\n\n\ndef f(x):\n    return lonely(x)\n",
    })
    diff = (
        "--- a/app/lonely.py\n+++ b/app/lonely.py\n@@ -1,2 +1,2 @@\n"
        " def lonely(x):\n-    return x\n+    return x + 1\n"
    )
    report = _impact_windows(repo, diff)
    assert report.affected_files == ["lib/user.py"]
    assert report.impact_level != "low"


@pytest.mark.parametrize("name,files,diff", [
    ("decorator_only",
     {"app/views.py": "def login_required(f):\n    return f\n\n\ndef delete_user(request):\n    return request\n"},
     "--- a/app/views.py\n+++ b/app/views.py\n@@ -4,2 +4,3 @@\n\n+@login_required\n def delete_user(request):\n"),
    ("non_python_file",
     {"src/decode.c": "int decode(char *s) {\n    return s[0];\n}\n"},
     "--- a/src/decode.c\n+++ b/src/decode.c\n@@ -1,3 +1,3 @@\n int decode(char *s) {\n"
     "-    return s[0];\n+    return s ? s[0] : 0;\n }\n"),
    ("deleted_file",
     LONELY_REPO,
     "--- a/app/lonely.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-def lonely(x):\n-    return x\n"),
])
def test_unattributed_change_is_still_unavailable_not_low(tmp_path, name, files, diff):
    report = _impact_windows(_repo(tmp_path, files), diff)
    assert report.impact_level == "unavailable", name
    assert pl._resolve_impact_level(report.to_dict()) == "unavailable"


# ---------------------------------------------------------------------------
# Remediation Planner (W2)
# ---------------------------------------------------------------------------

def _make_context(functions=None, constants=None):
    from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.autopatcher.candidate_enrichment import InvestigationContext

    functions = functions or {}
    return InvestigationContext(
        index=RepositoryIndex({"functions": functions}),
        call_graph={}, reverse_call_graph={},
        reachability=ReachabilityAnalyzer(functions, {}, set()),
        constants=constants or {},
    )


def _retry_repo(tmp_path):
    target = tmp_path / "src" / "util" / "retry.py"
    target.parent.mkdir(parents=True)
    target.write_text(
        "class Retry:\n    DEFAULT_REMOVE_HEADERS_ON_REDIRECT = frozenset(['Authorization'])\n",
        encoding="utf-8",
    )
    return _WinRelPath(tmp_path)


def test_verified_file_is_canonical_posix(tmp_path):
    from utilities.autopatcher.remediation_planner import _verify_file

    verified = _verify_file("src/util/retry.py", _retry_repo(tmp_path))
    assert verified == "src/util/retry.py"
    assert "/" in verified and "\\" not in verified


def test_verified_file_unchanged_on_native_path(tmp_path):
    from utilities.autopatcher.remediation_planner import _verify_file

    _retry_repo(tmp_path)
    assert _verify_file("src/util/retry.py", tmp_path) == "src/util/retry.py"


def test_file_symbol_pair_resolves_through_index(tmp_path):
    from utilities.autopatcher.remediation_planner import _resolve_symbol

    context = _make_context(functions={
        "src/util/retry.py:Retry.method": {
            "name": "method", "startLine": 12, "endLine": 20, "className": "Retry",
        },
    })
    result = _resolve_symbol("src/util/retry.py:Retry.method", _retry_repo(tmp_path), context)
    assert result == ("src/util/retry.py", "Retry.method", 12)


def test_file_symbol_pair_resolves_through_constants(tmp_path):
    from utilities.autopatcher.remediation_planner import _resolve_symbol

    context = _make_context(constants={
        "src/util/retry.py": {
            "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT": {
                "qualified_name": "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                "class_name": "Retry", "name": "DEFAULT_REMOVE_HEADERS_ON_REDIRECT",
                "line": 2, "end_line": 2,
            },
        },
    })
    result = _resolve_symbol(
        "src/util/retry.py:Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", _retry_repo(tmp_path), context,
    )
    assert result == ("src/util/retry.py", "Retry.DEFAULT_REMOVE_HEADERS_ON_REDIRECT", 2)


# ---------------------------------------------------------------------------
# Read-only cleanup (W4)
# ---------------------------------------------------------------------------

@pytest.fixture
def windows_unlink(monkeypatch):
    """os.unlink with Windows semantics: a file lacking the write bit
    cannot be deleted (PermissionError), whatever its directory allows."""
    real_unlink = os.unlink

    def _windows_unlink(path, *, dir_fd=None):
        st = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
        if not stat.S_ISLNK(st.st_mode) and not st.st_mode & stat.S_IWRITE:
            raise PermissionError(13, "Access is denied", path)
        return real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", _windows_unlink)


def _git_repo(root: Path) -> Path:
    root.mkdir()
    (root / "auth.py").write_text("def authenticate(u, p):\n    return True\n", encoding="utf-8")
    for cmd in (
        ["git", "init"],
        ["git", "config", "user.email", "t@t.com"],
        ["git", "config", "user.name", "T"],
        ["git", "add", "auth.py"],
        ["git", "commit", "-m", "init"],
    ):
        subprocess.run(cmd, cwd=root, capture_output=True, check=True)
    return root


def _read_only_objects(repo: Path) -> list:
    return [
        p for p in (repo / ".git" / "objects").rglob("*")
        if p.is_file() and not p.stat().st_mode & stat.S_IWRITE
    ]


def test_simulated_windows_unlink_defeats_plain_rmtree(tmp_path, windows_unlink):
    import shutil

    repo = _git_repo(tmp_path / "repo")
    assert _read_only_objects(repo), "git should have written read-only object files"
    shutil.rmtree(repo, ignore_errors=True)
    assert repo.exists()  # the exact Windows leak this pass fixes


def test_rmtree_force_removes_read_only_git_objects(tmp_path, windows_unlink):
    from utilities.autopatcher.patch_workspace import rmtree_force

    repo = _git_repo(tmp_path / "repo")
    assert _read_only_objects(repo)
    rmtree_force(repo)
    assert not repo.exists()


def test_rmtree_force_onerror_signature_for_python_311(tmp_path, windows_unlink, monkeypatch):
    import shutil

    from utilities.autopatcher import patch_workspace

    repo = _git_repo(tmp_path / "repo")
    real_rmtree = shutil.rmtree

    def rmtree_311(path, ignore_errors=False, onerror=None, **kwargs):
        assert "onexc" not in kwargs and onerror is not None
        return real_rmtree(path, onexc=lambda f, p, e: onerror(f, p, (type(e), e, e.__traceback__)))

    monkeypatch.setattr(patch_workspace.sys, "version_info", (3, 11, 9))
    monkeypatch.setattr(shutil, "rmtree", rmtree_311)
    patch_workspace.rmtree_force(repo)
    assert not repo.exists()


def test_rmtree_force_still_raises_unrecoverable_errors(tmp_path):
    from utilities.autopatcher.patch_workspace import rmtree_force

    with pytest.raises(FileNotFoundError):
        rmtree_force(tmp_path / "does-not-exist")
    rmtree_force(tmp_path / "does-not-exist", ignore_errors=True)


def test_temporary_repo_copy_cleans_up_read_only_git_objects(tmp_path, windows_unlink):
    from utilities.autopatcher.patch_workspace import temporary_repo_copy

    repo = _git_repo(tmp_path / "repo")
    with temporary_repo_copy(repo) as workspace_root:
        captured = workspace_root
        assert _read_only_objects(captured)
    assert not captured.exists()
    assert not captured.parent.exists()
