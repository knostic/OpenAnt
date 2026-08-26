"""Deterministic pytest command discovery for Existing Test Regression
Validation.

Narrow, MVP-scoped, Python/pytest only. No LLM guessing: a command is
returned only when the repository itself carries explicit, conventional
evidence that pytest is its test runner. Absence of that evidence is not a
failure of this module — it is the correct, honest answer ("we don't know
how to run this repository's tests yet"), surfaced by the caller as
NOT_VERIFIED rather than guessed at.

Precedence (first match wins; all three are equally valid evidence, order
only affects `discovery_reason` wording, never the returned command — the
command is always identical: ``python -m pytest --junitxml=<path>``):

    1. ``pytest.ini`` exists at the repository root.
    2. ``pyproject.toml`` exists and contains a ``[tool.pytest.ini_options]``
       table.
    3. ``setup.cfg`` exists and contains a ``[tool:pytest]`` section.

Deliberately NOT attempted in this slice (see the Auto Patcher regression-
validation plan for the reasoning): a bare ``tests/`` directory with no
pytest configuration, ``tox.ini``, ``noxfile.py``, ``Makefile``-driven test
targets, or any non-Python build system. A future slice may widen this;
doing so is an explicit, separate decision, not a side effect of loosening
this module's parsing.
"""

from __future__ import annotations

import configparser
import tomllib
from dataclasses import dataclass
from pathlib import Path

# The exact argv run inside the container for BOTH the baseline and patched
# side (see existing_test_regression.py) — discovered once, reused
# byte-for-byte, never re-derived per side. `--junitxml` is the only
# addition beyond a bare `python -m pytest` invocation; no markers, paths,
# filters, or xdist flags are ever added, so test selection is identical to
# what the repository's own bare invocation would select.
JUNIT_XML_CONTAINER_PATH = "/tmp/openant-junit.xml"
PYTEST_ARGV: "tuple[str, ...]" = (
    "python", "-m", "pytest", f"--junitxml={JUNIT_XML_CONTAINER_PATH}",
)


@dataclass(frozen=True)
class PytestCommand:
    """A deterministically-discovered pytest invocation.

    ``argv`` is the exact argv to run inside the container — identical for
    both the baseline and patched run of a given Existing Test Regression
    Validation pass (rule: same command before and after).
    """
    argv: "tuple[str, ...]"
    discovery_reason: str


def _has_pytest_ini_options(pyproject_path: Path) -> bool:
    try:
        raw = pyproject_path.read_bytes()
    except OSError:
        return False
    try:
        data = tomllib.loads(raw.decode("utf-8", errors="replace"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return False
    return (
        isinstance(data.get("tool"), dict)
        and isinstance(data["tool"].get("pytest"), dict)
        and "ini_options" in data["tool"]["pytest"]
    )


def _has_tool_pytest_section(setup_cfg_path: Path) -> bool:
    parser = configparser.ConfigParser()
    try:
        text = setup_cfg_path.read_text(encoding="utf-8", errors="replace")
        parser.read_string(text)
    except (OSError, configparser.Error):
        return False
    return "tool:pytest" in parser.sections()


def discover_pytest_command(repo_root: "Path | str") -> "PytestCommand | None":
    """Deterministically discover a pytest invocation for ``repo_root``.

    Returns ``None`` when no recognized pytest configuration is found —
    callers must treat that as NOT_VERIFIED, never as "0 tests, all
    passing." Never raises: a malformed/unreadable config file is treated
    as absent evidence, not an error, so one corrupt file cannot crash the
    whole regression-validation feature.
    """
    root = Path(repo_root)

    pytest_ini = root / "pytest.ini"
    if pytest_ini.is_file():
        return PytestCommand(argv=PYTEST_ARGV, discovery_reason="pytest.ini present at repository root")

    pyproject = root / "pyproject.toml"
    if pyproject.is_file() and _has_pytest_ini_options(pyproject):
        return PytestCommand(
            argv=PYTEST_ARGV,
            discovery_reason="pyproject.toml contains a [tool.pytest.ini_options] table",
        )

    setup_cfg = root / "setup.cfg"
    if setup_cfg.is_file() and _has_tool_pytest_section(setup_cfg):
        return PytestCommand(
            argv=PYTEST_ARGV,
            discovery_reason="setup.cfg contains a [tool:pytest] section",
        )

    return None
