"""#515: the Python-floor statements cannot drift again.

Three docs stated two different Python floors (3.8+ / 3.10+) while the
authority (pyproject requires-python) says >=3.11 — the doc-floor drift
family found by the closed-renovate-PR audit. This guard derives the
floor from the single source of truth and pins every prose statement
plus the Go runtime's floor constant against it.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

_CORE = Path(__file__).resolve().parent.parent
_REPO_ROOT = _CORE.parent.parent

_DOC_FILES = [
    _CORE / "README.md",
    _CORE / "report" / "README.md",
    _CORE / "PIPELINE_MANUAL.md",
]
_RUNTIME_GO = _REPO_ROOT / "apps" / "openant-cli" / "internal" / "python" / "runtime.go"


def _pyproject_minor() -> int:
    with (_CORE / "pyproject.toml").open("rb") as fh:
        req = tomllib.load(fh)["project"]["requires-python"]
    m = re.search(r">=\s*3\.(\d+)", req)
    assert m, f"unparseable requires-python: {req!r}"
    return int(m.group(1))


def test_doc_floor_statements_agree_with_pyproject():
    minor = _pyproject_minor()
    for doc in _DOC_FILES:
        text = doc.read_text(encoding="utf-8")
        stated = re.findall(r"Python 3\.(\d+)\+", text)
        assert stated, f"{doc.name}: no Python floor statement found (the guard expects one)"
        for st in stated:
            assert int(st) >= minor, (
                f"{doc.name}: states Python 3.{st}+ — below the pyproject floor 3.{minor}+ "
                "(the #515 doc-drift class)")


def test_go_runtime_floor_matches_pyproject():
    """The Go CLI's MinPythonMinor must equal the pyproject floor — the
    managed-venv bootstrap refuses below it, so a mismatch breaks installs."""
    src = _RUNTIME_GO.read_text(encoding="utf-8")
    m = re.search(r"MinPythonMinor\s*=\s*(\d+)", src)
    assert m, "runtime.go: MinPythonMinor constant not found"
    assert int(m.group(1)) == _pyproject_minor(), (
        f"runtime.go MinPythonMinor={m.group(1)} != pyproject floor 3.{_pyproject_minor()}")