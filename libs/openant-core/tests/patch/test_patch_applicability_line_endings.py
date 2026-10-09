"""W3 regression: git apply transport and working-tree line endings.

Invariant: the canonical LF unified diff reaches ``git apply`` byte-for-byte
as strict UTF-8 on binary stdin -- Python performs no newline translation --
and git's own autocrlf/attributes decide how working-tree line endings match.

Historical bug: text-mode stdin on Windows rewrote ``\\n`` as ``\\r\\n``, so a
bare blank context line became ``\\r`` and git reported "corrupt patch".

Fixtures are written with ``write_bytes`` and CRLF working trees are produced
by git itself (an autocrlf=true checkout), never by Python newline handling,
so these tests behave identically on every platform. System/global git config
is isolated so each repo's local ``core.autocrlf`` is the only policy in play.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from utilities.autopatcher.patch_applicability import apply_patch, check_applicability

_SRC = b"def f(x):\n    a = 1\n\n    return a\n"
_EXPECTED = b"def f(x):\n    a = 1\n    check(x)\n\n    return a\n"


def _diff(path: str, blank: str = "\n", a_line: str = "     a = 1\n") -> str:
    """Canonical LF diff inserting ``check(x)``; ``blank`` is how the blank
    context line is spelled (bare ``\\n`` as GNU diff/LLMs emit, or `` \\n``)."""
    return (
        f"--- a/{path}\n+++ b/{path}\n@@ -1,4 +1,5 @@\n"
        f" def f(x):\n{a_line}+    check(x)\n{blank}     return a\n"
    )


@pytest.fixture(autouse=True)
def _isolated_git_config(monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=T", "-c", "user.email=t@t.com", *args],
        cwd=cwd, capture_output=True, check=True,
    )


def _repo(root: Path, files: "dict[str, bytes]", autocrlf: str, attributes: "str | None" = None) -> Path:
    """Commit ``files`` byte-for-byte (no conversion), then set ``autocrlf``
    and re-checkout so git -- not Python -- produces the working tree."""
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "core.autocrlf", "false")
    if attributes is not None:
        (root / ".gitattributes").write_bytes(attributes.encode())
    for name, data in files.items():
        (root / name).write_bytes(data)
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "init")
    _git(root, "config", "core.autocrlf", autocrlf)
    for name in files:
        (root / name).unlink()
    _git(root, "checkout", "--", ".")
    return root


def _crlf(data: bytes) -> bytes:
    return data.replace(b"\n", b"\r\n")


def _check_then_apply(tmp_path: Path, files, autocrlf, patch, attributes=None):
    """Run check_applicability and apply_patch on identical fresh repos and
    assert they agree. Returns (check_result, apply_result, applied_repo)."""
    check_repo = _repo(tmp_path / "check", files, autocrlf, attributes)
    before = {n: (check_repo / n).read_bytes() for n in files}
    checked = check_applicability(patch, check_repo)
    assert {n: (check_repo / n).read_bytes() for n in files} == before, "--check mutated the tree"

    apply_repo = _repo(tmp_path / "apply", files, autocrlf, attributes)
    applied = apply_patch(patch, apply_repo)

    assert checked["skipped"] is False and checked["error"] is None
    assert checked["applicable"] is applied.applied, (checked["stderr"], applied.stderr)
    if not applied.applied:
        assert {n: (apply_repo / n).read_bytes() for n in files} == before
    return checked, applied, apply_repo


# ---------------------------------------------------------------------------
# Transport: exact bytes, no newline translation, check/apply parity
# ---------------------------------------------------------------------------

class TestTransport:
    def _capture_payloads(self, tmp_path, patch):
        (tmp_path / ".git").mkdir()
        calls = []

        def _capture(cmd, **kwargs):
            calls.append((cmd, kwargs))
            result = mock.MagicMock()
            result.returncode = 0
            result.stderr = b""
            return result

        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8", side_effect=_capture):
            check_applicability(patch, tmp_path)
            apply_patch(patch, tmp_path)
        assert len(calls) == 2
        return calls

    def test_payload_is_exact_utf8_bytes_with_no_cr_and_identical_for_check_and_apply(self, tmp_path):
        patch = _diff("f.py") + "+    # café\n"  # bare blank context + non-ASCII
        (check_cmd, check_kw), (apply_cmd, apply_kw) = self._capture_payloads(tmp_path, patch)

        assert isinstance(check_kw["input"], bytes)
        assert check_kw["input"] == patch.encode("utf-8")
        assert b"\r" not in check_kw["input"]
        assert check_kw["input"] == apply_kw["input"]
        for kw in (check_kw, apply_kw):
            assert not kw.get("text") and not kw.get("universal_newlines")
            assert "encoding" not in kw and "errors" not in kw
        assert check_cmd == ["git", "apply", "--check", "--whitespace=nowarn", "-"]
        assert apply_cmd == ["git", "apply", "--whitespace=nowarn", "-"]

    def test_missing_trailing_newline_is_completed_once(self, tmp_path):
        patch = _diff("f.py").rstrip("\n")
        (_, check_kw), (_, apply_kw) = self._capture_payloads(tmp_path, patch)
        assert check_kw["input"] == apply_kw["input"] == (patch + "\n").encode("utf-8")

    def test_unencodable_patch_fails_closed_without_running_git(self, tmp_path):
        (tmp_path / ".git").mkdir()
        patch = _diff("f.py") + "+    x = '\udcff'\n"  # lone surrogate: not valid UTF-8
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8") as run:
            checked = check_applicability(patch, tmp_path)
            applied = apply_patch(patch, tmp_path)
        run.assert_not_called()
        assert checked["applicable"] is None and checked["error"]
        assert applied.applied is False and applied.error_kind == "unexpected_error"

    def test_non_utf8_stderr_is_decoded_with_replacement_for_display(self, tmp_path):
        (tmp_path / ".git").mkdir()
        result = mock.MagicMock()
        result.returncode = 1
        result.stderr = b"error: bad \xff byte"
        with mock.patch("utilities.autopatcher.patch_applicability.run_utf8", return_value=result):
            checked = check_applicability(_diff("f.py"), tmp_path)
        assert checked["applicable"] is False
        assert checked["stderr"] == "error: bad � byte"


# ---------------------------------------------------------------------------
# Real git: LF and CRLF working trees
# ---------------------------------------------------------------------------

_LF = ("false", lambda b: b)        # LF working tree, no conversion
_CRLF = ("true", _crlf)             # CRLF working tree via autocrlf=true checkout
_TREES = pytest.mark.parametrize("autocrlf,eol", [_LF, _CRLF], ids=["lf-tree", "crlf-autocrlf-tree"])


@pytest.mark.skipif(not shutil.which("git"), reason="git not available")
class TestRealGitLineEndings:
    def test_fixture_working_tree_line_endings_come_from_git(self, tmp_path):
        assert (_repo(tmp_path / "lf", {"f.py": _SRC}, "false") / "f.py").read_bytes() == _SRC
        assert (_repo(tmp_path / "crlf", {"f.py": _SRC}, "true") / "f.py").read_bytes() == _crlf(_SRC)

    @_TREES
    @pytest.mark.parametrize("blank", ["\n", " \n"], ids=["bare-blank-context", "space-blank-context"])
    def test_canonical_lf_patch_applies_and_preserves_tree_line_endings(self, tmp_path, autocrlf, eol, blank):
        checked, applied, repo = _check_then_apply(
            tmp_path, {"f.py": _SRC}, autocrlf, _diff("f.py", blank=blank),
        )
        assert checked["applicable"] is True, checked["stderr"]
        assert applied.applied is True, applied.stderr
        assert (repo / "f.py").read_bytes() == eol(_EXPECTED)

    @_TREES
    def test_whitespace_mismatch_still_rejected(self, tmp_path, autocrlf, eol):
        patch = _diff("f.py", a_line=" \ta = 1\n")  # tab where the file has 4 spaces
        checked, applied, _ = _check_then_apply(tmp_path, {"f.py": _SRC}, autocrlf, patch)
        assert checked["applicable"] is False
        assert applied.error_kind == "apply_rejected"
        assert "corrupt patch" not in checked["stderr"]

    @_TREES
    def test_malformed_patch_still_rejected_as_corrupt(self, tmp_path, autocrlf, eol):
        patch = _diff("f.py").replace("@@ -1,4 +1,5 @@", "@@ -1,6 +1,7 @@")
        checked, applied, _ = _check_then_apply(tmp_path, {"f.py": _SRC}, autocrlf, patch)
        assert checked["applicable"] is False
        assert applied.error_kind == "apply_rejected"
        assert "corrupt patch" in checked["stderr"]
        assert "corrupt patch" in applied.stderr

    @_TREES
    def test_multi_file_patch_applies_to_every_file(self, tmp_path, autocrlf, eol):
        files = {"a.py": _SRC, "b.py": _SRC}
        checked, applied, repo = _check_then_apply(
            tmp_path, files, autocrlf, _diff("a.py") + _diff("b.py", blank=" \n"),
        )
        assert checked["applicable"] is True, checked["stderr"]
        assert applied.applied is True, applied.stderr
        assert (repo / "a.py").read_bytes() == eol(_EXPECTED)
        assert (repo / "b.py").read_bytes() == eol(_EXPECTED)

    def test_minus_text_crlf_file_is_not_made_permissive(self, tmp_path):
        """A file outside text conversion (-text) keeps its literal CRLF bytes;
        the LF patch must not match it, and the whole patch is rejected
        atomically -- the convertible file is left untouched too."""
        files = {"a.py": _SRC, "b.bat": _crlf(_SRC)}
        checked, applied, repo = _check_then_apply(
            tmp_path, files, "true", _diff("a.py") + _diff("b.bat"), attributes="*.bat -text\n",
        )
        assert checked["applicable"] is False
        assert applied.error_kind == "apply_rejected"
        assert "b.bat" in checked["stderr"]
        assert (repo / "a.py").read_bytes() == _crlf(_SRC)
        assert (repo / "b.bat").read_bytes() == _crlf(_SRC)

    def test_crlf_file_without_autocrlf_stays_fail_closed(self, tmp_path):
        """CRLF bytes with no conversion policy: git cannot match the
        canonical LF patch, and the result is a rejection, not a guess."""
        checked, applied, repo = _check_then_apply(
            tmp_path, {"f.py": _crlf(_SRC)}, "false", _diff("f.py"),
        )
        assert checked["applicable"] is False
        assert applied.error_kind == "apply_rejected"
        assert (repo / "f.py").read_bytes() == _crlf(_SRC)
