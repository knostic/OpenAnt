"""Issue #766: run output logs never belong in the tracked tree.

``runA-388b.log`` — a 118-byte pytest summary — was committed at the
repository root with #388 (59d50a2) and stayed tracked for seven weeks:
nothing wrote it, nothing read it, and no test guarded the tree, so no run
ever failed because of it. PR #671's review thread named it a deferred
``git rm`` candidate; #766 lands that removal and guards the class:

* the checked-out repository must not carry a ``.log`` path — the tracked
  set *and* the working tree at the root — so the next stray is named the
  moment it happens, ignored or not; and
* a hypothetical stray log must be *ignored* by the ROOT ``.gitignore``
  pattern, so a careless ``pytest ... | tee runX.log`` at the root never
  lands in a future ``git add``.

Both consult git itself — ``ls-files`` answers for the index,
``check-ignore`` answers for the exclude rules — rather than any remembered
list of files, because the enumeration that missed #388's stray would miss
the next one too (the lesson of ``test_no_banned_patterns``). They run
wherever the suite runs from a git checkout (every CI leg) and skip, with
the reason named, outside one, where "tracked" has no meaning.

Scope (deliberate): the lowercase ``.log`` class — the accident's shape.
A ``.LOG`` stray is out of scope (the ``*.log`` pattern itself is
case-sensitive on Linux, so the guard matches the pattern's own
semantics), and non-ASCII names are handled (``-z`` output is never
quoted).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

# A deliberately-tracked .log would fail the sweep; an entry here is the
# escape hatch, mirroring test_no_banned_patterns' allowlist convention.
# Keys are full repo-relative paths for tracked entries ("libs/x/y.log"),
# bare names for root on-disk entries ("scratch.log") — each with a reason.
_ALLOWED_LOGS: dict[str, str] = {}


def _git(*args: str) -> subprocess.CompletedProcess:
    """Run git in the repository root; utf-8 regardless of platform locale."""
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60,
    )


def _require_git_checkout() -> None:
    """The guarantees below are about the *tracked* repository."""
    if shutil.which("git") is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout: tracked-tree guarantees are undefined here")


def test_the_tracked_tree_carries_no_run_output_logs():
    """The #766 defect, asserted against the tree itself.

    ``git ls-files -z`` answers for the index — what a commit would carry,
    repo-wide, NUL-separated so a non-ASCII name is never quoted past the
    filter. The root directory listing answers for the working tree: the
    #388 accident BEGAN as a scratch log sitting on disk at the root — it
    was committed only later — so the guard names the class at that first
    stage, regardless of ignore state. A developer who tees a log at the
    root gets this failure with a clean ``git status`` precisely BECAUSE
    the pattern makes the file invisible to git: the test says what the
    status cannot.
    """
    _require_git_checkout()
    ls = _git("ls-files", "-z")
    assert ls.returncode == 0, ls.stderr
    tracked = sorted(
        l for l in ls.stdout.split("\0")
        if l.endswith(".log") and l not in _ALLOWED_LOGS
    )
    # name-only by design: every form git can hold is covered by the
    # ls-files half (regular files and symlinks), so this half guards the
    # NAME at the root whatever its type — a FIFO or a directory named
    # x.log is root pollution by the same #388 accident shape.
    on_disk = sorted(
        p.name for p in REPO_ROOT.iterdir()
        if p.name.endswith(".log") and p.name not in _ALLOWED_LOGS
    )
    offenders = sorted(set(tracked) | {f"(working tree, root) {n}" for n in on_disk})
    assert not offenders, (
        "run output logs in the tree (tracked, repo-wide) or at the root "
        "(working tree) — the #766 class, nothing reads these, they are "
        "run scratch:\n  " + "\n  ".join(offenders)
        + "\ngit rm the tracked ones and move the scratch out of the root; "
        "the *.log pattern in the root .gitignore keeps them from ever "
        "being committed."
    )


def test_a_stray_root_log_is_ignored_so_it_cannot_reland():
    """The class guard: the ROOT exclude rules refuse the next stray.

    ``check-ignore --no-index -v`` answers for a hypothetical path —
    tracked-ness cannot mask the answer — and the verbose output names
    WHICH rule matched: ``source:linenum:pattern<TAB>path``. Three
    properties must hold for each canonical name:

    * the match comes from the ROOT ``.gitignore`` (never a global
      ``core.excludesFile``, ``.git/info/exclude``, or a nested one);
    * the matched pattern is not a NEGATION — ``check-ignore -v`` exits 0
      for a last-matching ``!pattern`` too (the path is NOT ignored), so
      the pattern column must be read or a ``*.log`` + ``!*.log`` pair
      silently defeats the guard while both asserts stay green; and
    * the exit code says ignored (rc=0).
    """
    _require_git_checkout()
    for name in ("runA-388b.log", "scratch-run.log"):
        res = _git("check-ignore", "-v", "--no-index", "--", name)
        assert res.returncode == 0, (
            f"{name} is not git-ignored: a stray run output at the root can "
            "re-land as a tracked file (issue #766). Keep a *.log pattern "
            "in the root .gitignore."
        )
        matches = []
        for line in res.stdout.splitlines():
            head, _sep, _path = line.partition("\t")
            parts = head.split(":", 2)
            if len(parts) == 3:
                matches.append((parts[0], parts[2]))
        root_matches = [m for m in matches if m[0] == ".gitignore"]
        # the raw -v lines ride along in the failure messages below: a
        # windows drive-letter source ("C:/...") splits oddly under
        # head.split(":", 2) and the raw line keeps the diagnostic readable
        # (the exact-source assert still fails correctly in that branch).
        raw_lines = [l for l in res.stdout.splitlines() if l]
        assert root_matches, (
            f"{name} is ignored, but not by the ROOT .gitignore "
            f"(check-ignore -v lines: {raw_lines}) — the class guard must "
            "live where the #766 fix put it, not in a global exclude or "
            ".git/info/exclude"
        )
        negations = [m for m in root_matches if m[1].startswith("!")]
        assert not negations, (
            f"{name} is negated back into the tree by the ROOT .gitignore "
            f"itself ({negations}; raw lines: {raw_lines}) — the stray-log "
            "class is addable while this test stays green. Remove the "
            "negation (or narrow it with a path that cannot be a run "
            "output)."
        )
