"""No test may hardcode an absolute path to somebody else's machine.

Several tests were committed with a fallback like::

    ROOT = os.environ.get("OPENANT_ROOT", "/Users/<someone>/.../openant-core")

which is worse than a missing file. When that directory happens to exist on the
machine running the suite — a stale scratchpad from an earlier session, say —
the test does not error. It silently asserts against a DIFFERENT, older tree
and reports its findings as if they were about this one. That is exactly how
`test_F3_verdict_taxonomy_shared_constant` came to report `core/reporter.py` as
missing a constant it has imported all along.

The fallback must be derived from ``__file__`` so it always points at the tree
the test actually lives in.
"""

import re
from pathlib import Path

import pytest

TESTS_ROOT = Path(__file__).parent

# Absolute paths that belong to a specific machine/session rather than to the
# repository. A repo-relative path or a tmp_path fixture is always fine.
_MACHINE_PATH = re.compile(
    r"""["'](?:/Users/[^"']+|/home/[^"']+|/private/tmp/[^"']+|/tmp/claude-[^"']+)["']"""
)

# Lines that merely SHOW a command in a docstring are documentation, not
# behaviour. Only executable references matter.
_DOCSTRING_HINT = re.compile(r"^\s*(#|>>>|\$|PY=|\w+=)")


def _python_test_files():
    # This file is exempt from its own rule: it must contain examples of the
    # forbidden pattern in order to verify the matcher still detects them
    # (see test_the_guard_actually_matches_the_bad_pattern).
    return sorted(
        p for p in TESTS_ROOT.rglob("test_*.py") if p.name != Path(__file__).name
    )


def _offending_lines(path: Path) -> list[str]:
    """Executable lines in *path* embedding a machine-specific absolute path."""
    offenders = []
    in_docstring = False
    quote = None

    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()

        # Track triple-quoted blocks so docstring examples are exempt.
        if in_docstring:
            if quote in stripped:
                in_docstring = False
            continue
        for q in ('"""', "'''"):
            if stripped.startswith(q):
                # A one-line docstring opens and closes on the same line.
                if stripped.count(q) == 1:
                    in_docstring, quote = True, q
                break

        if in_docstring or _DOCSTRING_HINT.match(stripped):
            continue
        if _MACHINE_PATH.search(line):
            offenders.append(f"{path.relative_to(TESTS_ROOT)}:{lineno}: {stripped[:110]}")

    return offenders


@pytest.mark.parametrize(
    "test_file", _python_test_files(), ids=lambda p: str(p.relative_to(TESTS_ROOT))
)
def test_no_machine_specific_absolute_paths(test_file):
    offenders = _offending_lines(test_file)
    assert not offenders, (
        "test hardcodes a machine-specific absolute path:\n  "
        + "\n  ".join(offenders)
        + "\n\nDerive it from __file__ instead, e.g.\n"
        "  _DEFAULT_ROOT = str(Path(__file__).resolve().parent.parent)\n"
        "A stale path that still exists on disk makes the test assert against "
        "the WRONG tree instead of failing loudly."
    )


def test_the_guard_actually_matches_the_bad_pattern():
    """Guard against the guard silently going stale."""
    assert _MACHINE_PATH.search('ROOT = "/Users/someone/repo/core"')
    assert _MACHINE_PATH.search('X = "/private/tmp/claude-501/scratch/impl-core"')
    assert not _MACHINE_PATH.search('ROOT = Path(__file__).parent.parent')
    assert not _MACHINE_PATH.search('p = tmp_path / "dataset.json"')
