"""PR #763 final HUNT round 1 (head 7ca2758): regression tests for B-1/A-1,
B-5, B-4, A-2/B-3, A-3, A-4 and B-2.

Each test reproduces a finding exactly as the independent review executed
it, together with the positive controls that must keep their current
behaviour. Repository-configured commands are benign markers written into
the test's own tmp_path."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.patch.test_challenger_hunt_findings import (
    GUARD, OP, _HEADER, _assert_deployed, _assert_not_deployed, _block, _decide, _reply,
)
from tests.patch.test_patch_git_isolation import _filter_command, _git
from utilities.autopatcher import patch_applicability as pa
from utilities.autopatcher import run_metadata as rm
from utilities.autopatcher.impact_surface import LightweightImpactAnalyzer
from utilities.autopatcher.patch_challenger import _asserts_still_exploitable
from utilities.autopatcher.pipeline import TargetRepoContext

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="shell-script payloads are POSIX-only")


# ---------------------------------------------------------------------------
# B-1/A-1 and B-5 -- metadata git calls never run repository-configured
# commands, never write the analyzed repository, and cannot be told by its
# configuration to hide untracked files.
# ---------------------------------------------------------------------------

def _commit_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "app.py").write_text("def f(x):\n    return x\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


def _sign_head(repo: Path) -> None:
    """Replace HEAD with a commit carrying a gpgsig header, so a git that
    honours log.showSignature runs the configured gpg.program."""
    tree = _git(repo, "rev-parse", "HEAD^{tree}").stdout.decode().strip()
    parent = _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
    body = (
        f"tree {tree}\nparent {parent}\nauthor t <t@t> 1700000000 +0000\ncommitter t <t@t> 1700000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n AAAA\n -----END PGP SIGNATURE-----\n\nsigned\n"
    )
    sha = subprocess.run(["git", "hash-object", "-t", "commit", "-w", "--stdin"], cwd=repo, input=body.encode(),
                         check=True, capture_output=True).stdout.decode().strip()
    branch = _git(repo, "symbolic-ref", "--short", "HEAD").stdout.decode().strip()
    _git(repo, "update-ref", f"refs/heads/{branch}", sha)


def _script(tmp_path: Path, marker: Path, word: str) -> str:
    script = tmp_path / f"{word}.sh"
    script.write_text(f"#!/bin/sh\necho {word} >> '{marker}'\nexit 1\n")
    script.chmod(0o755)
    return str(script)


def _arm(repo: Path, tmp_path: Path, marker: Path) -> None:
    """Every repository-configured command the review executed."""
    _sign_head(repo)
    _git(repo, "config", "log.showSignature", "true")
    _git(repo, "config", "gpg.program", _script(tmp_path, marker, "gpg"))
    _git(repo, "config", "core.fsmonitor", _script(tmp_path, marker, "fsmonitor"))


@pytest.fixture
def marker(tmp_path: Path) -> Path:
    return tmp_path / "MARKER"


@POSIX_ONLY
class TestPreconditionThePayloadsAreLive:
    def test_plain_git_log_and_status_run_them(self, tmp_path, marker):
        repo = _commit_repo(tmp_path)
        _arm(repo, tmp_path, marker)
        subprocess.run(["git", "log", "-1", "--format=%h"], cwd=repo, capture_output=True)
        subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True)
        assert set(marker.read_text().split()) == {"gpg", "fsmonitor"}


@POSIX_ONLY
class TestMetadataRunsNoRepositoryCommand:
    def test_collect_git_info(self, tmp_path, marker):
        repo = _commit_repo(tmp_path)
        _arm(repo, tmp_path, marker)
        expected = _git(repo, "rev-parse", "--short", "HEAD").stdout.decode().strip()
        assert rm.collect_git_info(repo) == expected
        assert not marker.exists()

    def test_collect_full_commit_sha(self, tmp_path, marker):
        repo = _commit_repo(tmp_path)
        _arm(repo, tmp_path, marker)
        assert rm.collect_full_commit_sha(repo) == _git(repo, "rev-parse", "HEAD").stdout.decode().strip()
        assert not marker.exists()

    def test_is_worktree_clean_neither_runs_commands_nor_writes_the_index(self, tmp_path, marker):
        repo = _commit_repo(tmp_path)
        _arm(repo, tmp_path, marker)
        index = repo / ".git" / "index"
        before = (index.read_bytes(), index.stat().st_mtime_ns)
        os.utime(repo / "app.py")  # stat-dirty, content-clean: git would refresh the index
        assert rm.is_worktree_clean(repo) is True
        assert not marker.exists()
        assert (index.read_bytes(), index.stat().st_mtime_ns) == before


class TestCleanTreeFilterDoesNotRun:
    def test_clean_filter_from_repository_attributes(self, tmp_path, marker):
        repo = _commit_repo(tmp_path)
        (repo / ".git" / "info").mkdir(exist_ok=True)
        (repo / ".git" / "info" / "attributes").write_text("*.py filter=probe\n")
        _git(repo, "config", "filter.probe.clean", _filter_command(tmp_path, marker, "clean"))
        os.utime(repo / "app.py")
        assert rm.is_worktree_clean(repo) is True
        assert not marker.exists()


class TestWorktreeCleanSemantics:
    def test_clean(self, tmp_path):
        assert rm.is_worktree_clean(_commit_repo(tmp_path)) is True

    def test_modified_tracked_file(self, tmp_path):
        repo = _commit_repo(tmp_path)
        (repo / "app.py").write_text("def f(x):\n    return -x\n")
        assert rm.is_worktree_clean(repo) is False

    def test_staged_change(self, tmp_path):
        repo = _commit_repo(tmp_path)
        (repo / "new.py").write_text("y = 1\n")
        _git(repo, "add", "new.py")
        assert rm.is_worktree_clean(repo) is False

    def test_untracked_file(self, tmp_path):
        repo = _commit_repo(tmp_path)
        (repo / "extra_handler.py").write_text("y = 1\n")
        assert rm.is_worktree_clean(repo) is False

    def test_untracked_file_hidden_by_repository_config(self, tmp_path):
        """B-5: status.showUntrackedFiles=no must not make a dirty tree clean."""
        repo = _commit_repo(tmp_path)
        (repo / "extra_handler.py").write_text("y = 1\n")
        _git(repo, "config", "status.showUntrackedFiles", "no")
        assert rm.is_worktree_clean(repo) is False

    def test_ignored_file_stays_clean(self, tmp_path):
        repo = _commit_repo(tmp_path)
        (repo / ".gitignore").write_text("*.log\n")
        _git(repo, "add", ".gitignore")
        _git(repo, "commit", "-qm", "ignore")
        (repo / "run.log").write_text("x\n")
        assert rm.is_worktree_clean(repo) is True

    def test_crlf_checkout_with_autocrlf_is_clean(self, tmp_path):
        repo = tmp_path / "crlf"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "core.autocrlf", "true")
        (repo / "app.py").write_bytes(b"def f(x):\r\n    return x\r\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "init")
        assert rm.is_worktree_clean(repo) is True

    @POSIX_ONLY
    @pytest.mark.parametrize("filemode", ["false", "true"])
    def test_lost_executable_bit_follows_core_filemode(self, tmp_path, filemode):
        """core.filemode=false (the Git for Windows default) ignores a lost
        executable bit; with filemode on it is a change. Plain git decides."""
        repo = tmp_path / "fm"
        repo.mkdir()
        _git(repo, "init", "-q")
        (repo / "run.sh").write_text("#!/bin/sh\n")
        (repo / "run.sh").chmod(0o755)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "init")
        _git(repo, "config", "core.filemode", filemode)
        (repo / "run.sh").chmod(0o644)
        plain_clean = _git(repo, "status", "--porcelain").stdout.strip() == b""
        assert plain_clean is (filemode == "false")
        assert rm.is_worktree_clean(repo) is plain_clean

    def test_windows_text_mode_newlines_do_not_break_the_check(self, tmp_path, monkeypatch):
        """Windows text mode writes "\\r\\n" for "\\n"; git reads that "\\r" as
        part of the alternates path, so status failed and every check read
        None on Windows CI. Emulate the translation on any platform."""
        original = Path.write_text

        def windows_write_text(self, data, encoding=None, errors=None, newline=None):
            if newline is None:
                data = data.replace("\n", "\r\n")
            return original(self, data, encoding=encoding, errors=errors, newline="")

        monkeypatch.setattr(Path, "write_text", windows_write_text)
        repo = _commit_repo(tmp_path)
        assert rm.is_worktree_clean(repo) is True
        (repo / "extra.py").write_bytes(b"y = 1\n")
        assert rm.is_worktree_clean(repo) is False

    def test_not_a_repository(self, tmp_path):
        assert rm.is_worktree_clean(tmp_path) is None
        assert rm.collect_git_info(tmp_path) == "unknown"
        assert rm.collect_full_commit_sha(tmp_path) is None


# ---------------------------------------------------------------------------
# B-4 -- git's boolean spellings of core.autocrlf keep applying.
# ---------------------------------------------------------------------------

_CRLF_PATCH = "--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,4 @@\n def f(x):\n+    check(x)\n     y = x\n     return y\n"


@pytest.mark.parametrize("entry, expected", [
    ("autocrlf =", "false"),   # an explicit empty value is false to git
    ("autocrlf", "true"),      # a bare key is true
    ("autocrlf = yes", "true"),
    ("autocrlf = input", "input"),
])
def test_autocrlf_value_is_read_as_git_reads_it(tmp_path, entry, expected):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    with open(repo / ".git" / "config", "a") as fh:
        fh.write(f"[core]\n\t{entry}\n")
    assert dict(pa._line_ending_settings(repo)).get("core.autocrlf") == expected


@pytest.mark.parametrize("value", ["true", "yes", "on", "1", "TRUE", "false", "no", "off", "0", "input", ""])
def test_autocrlf_spelling_matches_plain_git(tmp_path, value):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "core.autocrlf", value)
    (repo / "app.py").write_bytes(b"def f(x):\r\n    y = x\r\n    return y\r\n")
    plain = subprocess.run(["git", "apply", "--check", "-"], cwd=repo, input=_CRLF_PATCH.encode(),
                           capture_output=True).returncode == 0
    assert pa.check_applicability(_CRLF_PATCH, repo)["applicable"] is plain


# ---------------------------------------------------------------------------
# A-2/B-3 -- a negative word that belongs to another verb is not a negation
# of the "still exploitable" assertion.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "No check on the bulk endpoint means account deletion is still exploitable.",
    "Neither added check covers the bulk route that remains exploitable.",
    "No caller other than the bulk endpoint matters and it remains exploitable.",
])
def test_negative_word_of_another_verb_still_asserts(tmp_path, text):
    assert _asserts_still_exploitable(text) is True
    _assert_not_deployed(*_decide(_reply(_block(description=text)), tmp_path=tmp_path))


@pytest.mark.parametrize("text", [
    "Nothing remains exploitable.",
    "No request path remains exploitable.",
    "None of the callers remain exploitable.",
    "Nobody can still exploit it; nothing is still exploitable.",
])
def test_genuine_negative_subject_is_not_an_assertion(text):
    assert _asserts_still_exploitable(text) is False


def test_negative_subject_description_still_deploys(tmp_path):
    _assert_deployed(*_decide(_reply(_block(description="Nothing remains exploitable once the check runs.")),
                              tmp_path=tmp_path))


# ---------------------------------------------------------------------------
# A-3 -- text after the status token on its own line fails closed.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [
    "VERIFIED_FIXED. The bulk endpoint remains exploitable.",
    "VERIFIED_FIXED (the bulk endpoint is still vulnerable)",
    "VERIFIED_FIXED - but see the bulk endpoint",
])
def test_trailing_status_text_fails_closed(tmp_path, status):
    _assert_not_deployed(*_decide(_reply(status=status), tmp_path=tmp_path))


@pytest.mark.parametrize("status", ["VERIFIED_FIXED", "**VERIFIED_FIXED**", "`VERIFIED_FIXED`", "VERIFIED_FIXED."])
def test_bare_status_token_still_deploys(tmp_path, status):
    _assert_deployed(*_decide(_reply(status=status), tmp_path=tmp_path))


# ---------------------------------------------------------------------------
# A-4 -- a callback opened on an if/try line, or string content that starts
# with a keyword, is not the guard's control-flow block.
# ---------------------------------------------------------------------------

_JS_VULN = "# Missing authorization in deleteUser\n\nAny user can delete accounts via deleteUser."
_JS_GUARD = 'if (!user.isAdmin) throw new Error("forbidden");'
_JS_OP = "db.delete(target);"
_JS_HEADER = "diff --git a/app.js b/app.js\nindex 1111111..2222222 100644\n--- a/app.js\n+++ b/app.js\n"
_JS_CTX = ("#### Target definition: `app.js:deleteUser` (lines 1-4)\n\n```javascript\n"
           "function deleteUser(user, target, hooks) {\n    db.delete(target);\n    return true;\n}\n```\n")
_JS_REPLY = _reply(_block(op=_JS_OP, guard=_JS_GUARD, ds_prov="user.isAdmin", eff_prov='throw new Error("forbidden")'))


def _js_callback_patch(opener: str) -> str:
    return (_JS_HEADER + "@@ -1,4 +1,7 @@\n function deleteUser(user, target, hooks) {\n"
            f"+    {opener}\n+        {_JS_GUARD}\n+    }});\n     {_JS_OP}\n     return true;\n }}\n")


def _decide_js(patch, tmp_path):
    return _decide(_JS_REPLY, patch=patch, code_context=_JS_CTX, tmp_path=tmp_path, vuln=_JS_VULN)


@pytest.mark.parametrize("opener", [
    "hooks.push(function () {",
    "if (hooks) hooks.push(function () {",
    "try { setTimeout(function () {",
    "if (hooks) hooks.forEach((h) => {",
])
def test_guard_inside_a_callback_does_not_cover(tmp_path, opener):
    _assert_not_deployed(*_decide_js(_js_callback_patch(opener), tmp_path))


def test_direct_js_guard_still_deploys(tmp_path):
    patch = (_JS_HEADER + "@@ -1,4 +1,5 @@\n function deleteUser(user, target, hooks) {\n"
             f"+    {_JS_GUARD}\n     {_JS_OP}\n     return true;\n }}\n")
    _assert_deployed(*_decide_js(patch, tmp_path))


def _py_nested_patch(middle: "list[str]") -> str:
    body = ["    def later():", *middle, f"        {GUARD}"]
    return (_HEADER + f"@@ -1,3 +1,{3 + len(body)} @@\n def delete_user(user, target):\n"
            + "".join(f"+{line}\n" for line in body) + f"     {OP}\n     return True\n")


@pytest.mark.parametrize("middle", [
    ['        note = "audit"'],
    ['        note = """', '    if the caller is not an admin, refuse', '        """'],
    ['        note = """', '    try this first', '        """'],
])
def test_guard_in_nested_def_does_not_cover(tmp_path, middle):
    _assert_not_deployed(*_decide(_reply(), patch=_py_nested_patch(middle), tmp_path=tmp_path))


# ---------------------------------------------------------------------------
# B-2 -- an import that changes which object an existing module-level name
# is bound to is never attributed to "no symbol".
# ---------------------------------------------------------------------------

def _impact(tmp_path: Path, src: str, diff: str):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ser.py").write_text(src)
    for i in range(4):
        (root / f"caller{i}.py").write_text(f"from ser import parse\n\ndef job{i}(x):\n    return parse(x)\n")
    return LightweightImpactAnalyzer().analyze(diff, repo_context=TargetRepoContext(root), repo_language="python")


_REBINDS = {
    "plain-added": ("from json import loads\n\ndef parse(b):\n    return loads(b)\n",
                    "--- a/ser.py\n+++ b/ser.py\n@@ -1,3 +1,4 @@\n from json import loads\n+from pickle import loads\n \n def parse(b):\n"),
    "reorder": ("from json import loads\nfrom pickle import loads\n\ndef parse(b):\n    return loads(b)\n",
                "--- a/ser.py\n+++ b/ser.py\n@@ -1,4 +1,4 @@\n-from json import loads\n-from pickle import loads\n"
                "+from pickle import loads\n+from json import loads\n \n def parse(b):\n"),
    "tuple-binding": ("import json\nloads, dumps = json.loads, json.dumps\n\ndef parse(b):\n    return loads(b)\n",
                      "--- a/ser.py\n+++ b/ser.py\n@@ -1,2 +1,3 @@\n import json\n loads, dumps = json.loads, json.dumps\n"
                      "+from pickle import loads\n"),
    "try-binding": ("try:\n    from simplejson import loads\nexcept ImportError:\n    from json import loads\n\n"
                    "def parse(b):\n    return loads(b)\n",
                    "--- a/ser.py\n+++ b/ser.py\n@@ -2,3 +2,4 @@\n     from simplejson import loads\n except ImportError:\n"
                    "     from json import loads\n+from pickle import loads\n"),
}


@pytest.mark.parametrize("case", sorted(_REBINDS))
def test_import_rebinding_is_never_low(tmp_path, case):
    src, diff = _REBINDS[case]
    report = _impact(tmp_path, src, diff)
    assert report.impact_level == "unavailable", (case, report.impact_level, report.changed_symbols)


def test_new_unrelated_import_is_not_a_rebinding(tmp_path):
    src = "from json import loads\n\ndef parse(b):\n    return loads(b)\n"
    diff = "--- a/ser.py\n+++ b/ser.py\n@@ -1,3 +1,4 @@\n from json import loads\n+import os\n \n def parse(b):\n"
    assert _impact(tmp_path, src, diff).impact_level != "unavailable"
