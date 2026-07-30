"""Tree-wide sweeps for defect patterns that have each recurred at multiple sites.

Every rule here exists because the same bug was fixed once and left standing
elsewhere. The tally from this codebase's audit history:

* the ambiguous ``json`` fence regex — fixed at 1 site, found at 2, then 3
* the FIFO/``S_ISREG`` guard — fixed at 1 of 4 repo-file open sites
* the file-boundary marker — fixed at 1 of 8 producers
* the traversal guard — fixed at 1 of 5 scanners, twice
* ``exists()`` on repo-controlled paths — fixed in the loader, left in the writer

The common cause is not carelessness, it is *who enumerates*. A fix, a review, and
a parity test all enumerate from the author's memory of where the pattern lives,
and that memory is reliably short by one. These tests enumerate from the
filesystem, so a site nobody remembered still fails.

Note the direction: each rule asserts the **absence of a defect across the whole
tree**, not the presence of a guard in a remembered list of modules. A
guard-presence test passes on code that has the guard *and* the defect, and fails
on code that was fixed by moving the guard somewhere shared — both of which
happened here within a day.

Adding a rule: when you fix a bug that could plausibly exist elsewhere, add the
sweep in the same commit. An allowlist entry is fine, but it must carry a reason.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

CORE_ROOT = Path(__file__).resolve().parent.parent

# Directories that are not our code, or where a match is discussion rather than use.
_SKIP_DIRS = {".venv", "node_modules", "__pycache__", ".git", "datasets", "bin"}


def _sources(*suffixes: str) -> list[Path]:
    out = []
    for path in CORE_ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        out.append(path)
    return out


def _violations(pattern: re.Pattern, allow: dict[str, str], *suffixes: str):
    """Files matching ``pattern``, minus allowlisted paths (each with a reason)."""
    found = []
    for path in _sources(*suffixes):
        rel = path.relative_to(CORE_ROOT).as_posix()
        if rel in allow:
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                found.append(f"{rel}:{i}: {line.strip()[:100]}")
    return found


def test_no_ambiguous_json_fence_regex():
    """``` ```json\\s*(.*?)\\s*``` ``` backtracks cubically on an unclosed fence.

    4 KB of trailing whitespace took 32.9s and the 1 MiB file cap does not bound
    it. Found and fixed three separate times; this sweep is what makes a fourth
    copy fail on arrival rather than in an audit.
    """
    pattern = re.compile(r"```json\\s\*\(\.\*\?\)\\s\*|json\\s\*\(\.\*\?\)")
    allow = {
        "tests/test_no_banned_patterns.py": "this file names the pattern to ban it",
        "context/threat_model.py": "comment explaining why the pattern is not used",
        "context/application_context.py": "comment explaining why the pattern is not used",
    }
    bad = _violations(pattern, allow, ".py")
    assert not bad, (
        "ambiguous json-fence regex (superlinear backtracking) at:\n  "
        + "\n  ".join(bad)
        + "\nUse r'```json(.*?)```' and .strip() the group instead."
    )


def test_no_bare_exists_check_on_repo_controlled_paths():
    """``Path.exists()`` follows symlinks, so a dangling link reads as *absent*.

    That single fact produced two separate defects: the threat-model loader
    silently downgrading to built-in heuristics, and the writer treating the name
    as free and then following the link out of the repository. Anywhere the answer
    to "is this here?" decides security behaviour, use ``repo_path_state``.
    """
    pattern = re.compile(r"THREAT_MODEL_FILENAME\s*\)?\s*\.exists\(\)|"
                         r"MANUAL_OVERRIDE_FILES.*\.exists\(\)")
    allow = {"tests/test_no_banned_patterns.py": "names the pattern to ban it"}
    bad = _violations(pattern, allow, ".py")
    assert not bad, (
        "exists() used on a repository-controlled path at:\n  " + "\n  ".join(bad)
        + "\nUse utilities.file_io.repo_path_state, which lstats."
    )


def test_language_scanners_do_not_implement_their_own_recursion():
    """Traversal lives in ``core/repo_walk.py`` and nowhere else.

    Four scanners each had their own walk, so each traversal fix reached a subset:
    the symlink guard landed in 2 of 5, the deep-nest fix in 1 of 5. Centralising
    made the class structurally impossible; this keeps it that way. A new parser
    that hand-rolls ``self.scan_directory(...)`` recursion fails here.
    """
    bad = []
    for path in (CORE_ROOT / "parsers").rglob("repository_scanner.py"):
        text = path.read_text(errors="replace")
        rel = path.relative_to(CORE_ROOT).as_posix()
        # A self-recursive call inside the scan body — the shape that resists a
        # depth cap and swallows RecursionError in a caller's bare except.
        if re.search(r"self\.scan_directory\([^)]*entry", text):
            bad.append(f"{rel}: recurses into subdirectories itself")
    assert not bad, (
        "scanner implements its own recursive walk:\n  " + "\n  ".join(bad)
        + "\nUse core.repo_walk.walk_repository, which is iterative, symlink-"
        "guarded and records unreadable subtrees."
    )


def test_no_permissive_adapter_fakes_in_tests():
    """``def complete(self, *a, **k)`` accepts any call, including a wrong one.

    This is why 672 tests were green over a threat-model generator that had never
    executed: production called ``complete(prompt=...)``, the real protocol is
    keyword-only ``complete(*, model, system, messages, max_tokens, tools=None)``,
    and the fake swallowed the difference. A fake looser than the interface it
    stands in for does not test the caller, it excuses it.
    """
    pattern = re.compile(r"def complete\(\s*self\s*,\s*\*a|def complete\(\s*self\s*,\s*\*args")
    allow = {"tests/test_no_banned_patterns.py": "names the pattern to ban it"}
    bad = _violations(pattern, allow, ".py")
    assert not bad, (
        "permissive adapter fake at:\n  " + "\n  ".join(bad)
        + "\nMatch the real keyword-only signature so a wrong call fails the test."
    )


@pytest.mark.parametrize(
    "producer",
    sorted(str(p.relative_to(CORE_ROOT))
           for p in (CORE_ROOT / "parsers").rglob("*")
           if p.is_file() and p.suffix in {".py", ".js", ".go"}
           and "File Boundary" in p.read_text(errors="replace")
           and "__pycache__" not in str(p)),
)
def test_every_file_boundary_producer_neutralizes(producer: str):
    """Discovered from the filesystem, not from a list I maintain.

    The earlier version of this check hardcoded eight producer paths. That is the
    author-enumeration failure the whole file exists to remove: a ninth producer
    would be invisible to it. Anything that emits the marker must also defang
    boundary-shaped lines in the untrusted source it concatenates, or a comment
    line in a scanned repo splits the unit and hides the payload from both stages.
    """
    text = (CORE_ROOT / producer).read_text(errors="replace")
    if "neutraliz" in text.lower():
        return
    # Consumers/definers legitimately mention the marker without concatenating.
    if "split_on_boundary" in text or "BOUNDARY_TEXT =" in text:
        return
    pytest.fail(
        f"{producer} emits the file-boundary marker but never neutralizes "
        "boundary-shaped lines in the source it concatenates. One comment line in "
        "a scanned repository would relabel an attacker's payload as "
        "do-not-analyze context."
    )
