"""Executable safety contract, run against every shipped repository scanner.

This replaces a pair of token-grep parity tests, and the reason it replaces them is
worth recording because the failure was instructive.

Those tests asserted that each parser's *source* contained one of a set of guard
tokens. That proves a string exists. It does not prove the guard executes, executes
before descent, handles deep nesting, or that incompleteness reaches the result.
Both failure directions showed up within a day:

* **False green.** All seven parsers passed the symlink-token check while three of
  them still recursed per directory and silently dropped deeply nested files — an
  unrelated hole the test's name ("this parser is guarded") implied it covered.
* **False red.** After traversal moved into ``core/repo_walk.py``, the compliant
  scanners *stopped* containing the tokens and the test failed for parsers that had
  just become correct.

A token test measures where code lives. The property under test is what code does.

So this file discovers scanners from the shipped language registry and executes each
against hostile repositories. Two consequences are deliberate:

* A newly registered language enters this suite automatically — nobody has to
  remember to add it.
* **A skip is a failure** for a language the registry ships. "Could not test it" and
  "it is safe" must never be the same outcome; that equivalence is how the original
  gap survived review.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from core.language_registry import load_registry

CORE_ROOT = Path(__file__).resolve().parent.parent


def _python_scanner_languages() -> list[str]:
    """Registry languages whose scanner is a Python module we can drive in-process.

    Derived from the registry rather than hardcoded, so language #8 is covered the
    day it is registered. Non-Python scanners (Node, Go) are excluded here because
    this harness drives Python modules in-process; their equivalents live in their
    own runtime's suite — the JS containment test in ``tests/test_js_parser.py``
    (``TestSymlinkContainment``) and the Go test in
    ``parsers/go/go_parser/scanner_symlink_test.go``. NOTE: this claim was once
    false — no such Go/Node containment suite existed, and that false comfort is
    how the Go file-symlink exfiltration hole shipped. Both suites now exist; do
    not remove them without moving the coverage here.
    """
    languages = []
    for name in sorted(load_registry()):
        if (CORE_ROOT / "parsers" / name / "repository_scanner.py").is_file():
            languages.append(name)
    return languages


PYTHON_SCANNERS = _python_scanner_languages()


def _load_scanner(language: str):
    """Import a parser's scanner without mutating ``sys.path``.

    An import failure is raised, never skipped: a scanner the registry ships but
    that cannot be loaded is a broken product, and reporting that as "skipped"
    would restore exactly the blind spot this file exists to remove.
    """
    path = CORE_ROOT / "parsers" / language / "repository_scanner.py"
    spec = importlib.util.spec_from_file_location(f"_contract_{language}", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.RepositoryScanner


def _files(result) -> list[str]:
    if isinstance(result, dict):
        return [str(f.get("path", f)) for f in result.get("files", [])]
    return [str(f) for f in (result or [])]


def _stats(result) -> dict:
    return result.get("statistics", {}) if isinstance(result, dict) else {}


def test_the_registry_yields_scanners_to_test():
    """Guard against the whole suite silently covering nothing.

    If the registry fails to load, ``PYTHON_SCANNERS`` is empty, every
    parametrized test below collects zero cases, and the file reports green while
    testing nothing. That is the same class of vacuous pass this suite replaced.
    """
    assert PYTHON_SCANNERS, (
        "no Python scanners discovered from the language registry — the contract "
        "suite would pass by testing nothing"
    )


@pytest.mark.parametrize("language", PYTHON_SCANNERS)
def test_scanner_does_not_ingest_files_outside_the_repository(language, tmp_path):
    """A directory symlink must not walk the host filesystem into the dataset.

    Whatever a scanner returns is sent to the model provider, so following
    ``vendor -> /`` is both a false-positive source and an exfiltration path.
    """
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)

    # The target must lie beyond the repository's PARENT, not merely outside the
    # repository. Policy allows parent-scoped links so a monorepo package can
    # symlink a sibling; a fixture under `tmp_path` would therefore be permitted
    # and this test would assert nothing. mkdtemp gives an unrelated root.
    outside = Path(tempfile.mkdtemp(prefix="openant-host-"))
    try:
        for ext in (".py", ".c", ".php", ".rb", ".zig", ".js", ".go"):
            (outside / f"host_secret{ext}").write_text("SECRET = 1\n")
        os.symlink(outside, repo / "escape")

        result = _load_scanner(language)(str(repo)).scan()
        leaked = [f for f in _files(result) if "host_secret" in f]
        assert not leaked, (
            f"{language} scanner ingested files from beyond the repository parent: "
            f"{leaked}. Whatever a scanner returns is sent to the model provider."
        )
    finally:
        shutil.rmtree(outside, ignore_errors=True)


@pytest.mark.parametrize("language", PYTHON_SCANNERS)
def test_scanner_terminates_on_a_symlink_loop(language, tmp_path):
    """``loop -> ..`` must not run forever.

    Three sibling loops previously kept a scan at full CPU for minutes on a
    one-file repository, with memory climbing.
    """
    repo = tmp_path / "repo"
    (repo / "sub").mkdir(parents=True)
    for name in ("l1", "l2", "l3"):
        os.symlink("..", repo / "sub" / name)

    result = _load_scanner(language)(str(repo)).scan()  # must simply return
    assert isinstance(_files(result), list)


@pytest.mark.parametrize("language", PYTHON_SCANNERS)
def test_deeply_nested_code_is_scanned_or_recorded_as_a_gap(language, tmp_path):
    """Either see the file, or say you could not.

    The forbidden third outcome is a scan that reports success with a file count
    that silently omits the planted file. On a platform where the path exceeds
    PATH_MAX the file is genuinely unreachable — that is fine, provided the gap is
    recorded in the structured result rather than dropped.
    """
    from tests.test_hostile_repo import build_deep_nest

    repo = tmp_path / "repo"
    repo.mkdir()
    ext = {"python": ".py", "c": ".c", "php": ".php", "ruby": ".rb",
           "zig": ".zig", "javascript": ".js", "go": ".go",
           "swift": ".swift", "rust": ".rs"}.get(language, ".py")
    build_deep_nest(repo / "deep", 600, f"planted{ext}", "x = 1\n")

    try:
        result = _load_scanner(language)(str(repo)).scan()
    except Exception:  # noqa: BLE001 - a loud failure is an acceptable outcome
        return

    if any("planted" in f for f in _files(result)):
        return
    stats = _stats(result)
    gap = (stats.get("directories_unreadable") or stats.get("directories_read_failed"))
    assert gap, (
        f"{language} scanner reported success, omitted the deeply nested file, and "
        f"recorded no coverage gap. statistics={stats}. An unreadable subtree is "
        "code that was never analysed; for a SAST tool a silent omission is worse "
        "than a crash because it manufactures assurance."
    )


@pytest.mark.parametrize("language", PYTHON_SCANNERS)
def test_scanner_records_a_gap_when_a_directory_cannot_be_read(language, tmp_path):
    """Fault injection, because natural fixtures are platform-dependent.

    Deep-path and permission behaviour varies by OS and by whether CI runs as root,
    so the natural cases above can quietly stop exercising the error branch.
    Denying read on a real directory forces it deterministically.
    """
    repo = tmp_path / "repo"
    blocked = repo / "blocked"
    blocked.mkdir(parents=True)
    (blocked / "hidden.py").write_text("x = 1\n")
    os.chmod(blocked, 0o000)
    try:
        if os.access(blocked, os.R_OK):
            pytest.skip("running as root; permissions are not enforced")
        result = _load_scanner(language)(str(repo)).scan()
        stats = _stats(result)
        gap = (stats.get("directories_unreadable")
               or stats.get("directories_read_failed"))
        assert gap, (
            f"{language} scanner could not read {blocked} and recorded no gap; "
            f"statistics={stats}"
        )
    finally:
        os.chmod(blocked, 0o755)
