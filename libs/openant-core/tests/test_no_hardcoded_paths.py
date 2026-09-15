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
    # JS-flavored: a quoted personal path must match; a // comment example must not.
    assert _MACHINE_PATH.search("const R = '/Users/nahumkorda/code/dvna';")
    assert not _MACHINE_PATH.search("// example: /Users/someone/repo".split("//", 1)[0])



# --- Shipped production source (the gap that let a personal path into the wheel) -

_SHIPPED_PKGS = ("core", "utilities", "parsers", "prompts", "context", "report", "openant")
_SRC_ROOT = Path(__file__).resolve().parent.parent


def _shipped_sources():
    out = []
    for pkg in _SHIPPED_PKGS:
        out.extend((_SRC_ROOT / pkg).rglob("*.py"))
    return [p for p in out if "__pycache__" not in p.parts]


_SHIPPED = _shipped_sources()


def _shipped_js_sources():
    # The shipped-source sweep was .py-only, which let personal paths ride into
    # parsers/javascript/*.js unnoticed (dataset_enhancer.js, generate_report.js).
    out = []
    for pkg in _SHIPPED_PKGS:
        out.extend((_SRC_ROOT / pkg).rglob("*.js"))
        out.extend((_SRC_ROOT / pkg).rglob("*.ts"))
    return [
        p for p in out
        if "node_modules" not in p.parts
        and not p.name.endswith((".min.js", ".bundle.js", ".chunk.js"))
    ]


_SHIPPED_JS = _shipped_js_sources()


def test_the_source_sweep_is_not_vacuous():
    """A sweep that scanned nothing would pass while proving nothing.

    The original sweep only covered tests/, which is exactly why a personal path
    in utilities/ shipped in the wheel unnoticed. This floor guards the extension.
    """
    assert len(_SHIPPED) > 100, (
        f"only {len(_SHIPPED)} shipped sources found; the glob has stopped matching"
    )


@pytest.mark.parametrize("src", _SHIPPED, ids=lambda p: str(p.relative_to(_SRC_ROOT)))
def test_no_machine_specific_absolute_paths_in_shipped_source(src):
    """No /Users/<name> or /home/<name> literal in code that ships in the wheel.

    A comment giving an example path is fine; a string literal is not — that is
    what embeds someone's home directory in the distribution.
    """
    for i, line in enumerate(src.read_text(errors="replace").splitlines(), 1):
        code = line.split("#", 1)[0]
        m = _MACHINE_PATH.search(code)
        assert not m, f"{src.relative_to(_SRC_ROOT)}:{i}: machine path {m.group(0)}"


def test_the_js_source_sweep_is_not_vacuous():
    """Same floor as the Python sweep: a broken .js glob must not pass silently."""
    assert len(_SHIPPED_JS) >= 3, (
        f"only {len(_SHIPPED_JS)} shipped JS sources found; the glob has stopped matching"
    )


@pytest.mark.parametrize("src", _SHIPPED_JS, ids=lambda p: str(p.relative_to(_SRC_ROOT)))
def test_no_machine_specific_absolute_paths_in_shipped_js(src):
    """No /Users/<name> or /home/<name> literal in shipped JavaScript/TypeScript.

    Two dead scripts (dataset_enhancer.js, generate_report.js) shipped personal
    paths because this sweep was .py-only; extending it here closes that gap. JS
    line comments use // (not #), so an example path in a // comment is fine.
    """
    for i, line in enumerate(src.read_text(errors="replace").splitlines(), 1):
        code = line.split("//", 1)[0]
        m = _MACHINE_PATH.search(code)
        assert not m, f"{src.relative_to(_SRC_ROOT)}:{i}: machine path {m.group(0)}"
