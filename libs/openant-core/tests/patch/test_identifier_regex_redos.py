"""Code scanning alert #12 (py/redos) regression guard: the CamelCase
identifier shape in `remediation_planner` must stay LINEAR.

The original shape was

    _CAMEL_RE = re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-zA-Z0-9]*)+\b")

whose inner class `[A-Za-z0-9]` can itself match an uppercase letter. Every
uppercase character after the first hump is therefore ambiguous -- it can
either extend the current repetition or open a new one -- so when the
trailing `\b` fails the backtracker explores ~2^k partitions of the k
uppercase characters. The exponent is the uppercase COUNT, not its
consecutiveness, and the input that triggers it is an ORDINARY source line:

    SomeHTTPSERVERCONNECTIONFACTORYBUILDER_DEFAULT = 1   # 50 bytes, 42 uppercase, 0 matches

`_extract_identifiers_from_text` is run per-line over every hunk line
INCLUDING diff context lines, i.e. verbatim source text from the scanned
repository, so no upstream length cap can help (50 bytes suffices).

The fix drops `A-Z` from the inner class, so each repetition starts at
exactly one capital and the partition is unique. greenery proved the two
patterns accept the SAME language (both difference directions empty), so
this is a performance-only change.

WHY A SUBPROCESS AND NOT A WALL-CLOCK ASSERT: on the vulnerable pattern the
match does not finish, so an in-process `time.perf_counter()` assertion
never gets to run its comparison -- it HANGS the whole suite instead of
failing. `signal.setitimer`/`SIGALRM` is not an option either: the CI matrix
includes windows-latest, where `signal.setitimer` does not exist. A child
process with `subprocess.run(..., timeout=...)` is the only shape that fails
(rather than hangs) on a regression and is portable across all three CI
operating systems. For the same reason NO adversarial input is ever fed to
the regex in-process in this file: a future re-arming must not be able to
wedge the test session.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from utilities.autopatcher.remediation_planner import _CAMEL_RE

CORE_ROOT = Path(__file__).resolve().parents[2]

# The shape the fix installs. Pinned literally so that a re-arming edit --
# re-widening the inner class to [A-Za-z0-9], or any other reintroduction of
# an ambiguous repetition start -- fails here even on a machine fast enough,
# or a regex engine smart enough, to hide the blow-up from the timing test.
_LINEAR_CAMEL_PATTERN = r"\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+\b"

# The child imports the REAL compiled object from the REAL module. It must
# never re-declare the pattern literal: a copied literal would keep passing
# against a regressed `remediation_planner`, which is precisely the
# regression this file exists to catch.
_CHILD_PREAMBLE = (
    "import time\n"
    "from utilities.autopatcher.remediation_planner import _CAMEL_RE\n"
)

# 63 bytes, 60 uppercase characters, zero matches. On the vulnerable pattern
# this is ~2^60 partitions; measured on the real module, cost doubles for
# every added uppercase character (k=26 -> 0.9s), so this input does not
# complete in any human timeframe. On the fixed pattern it is instant.
_REDOS_PAYLOAD = '"Aa" + "B"*60 + "_"'

_CHILD_CANONICAL = _CHILD_PREAMBLE + (
    "s = {payload}\n"
    "t = time.perf_counter()\n"
    "n = len(list(_CAMEL_RE.finditer(s)))\n"
    "d = time.perf_counter() - t\n"
    # Printed so the parent can prove the scan actually ran. Without this
    # marker a child that died early (ImportError, a renamed symbol, a
    # broken PYTHONPATH) would exit in milliseconds and the "finished
    # inside the timeout" assertion would pass VACUOUSLY.
    "print('SCANNED len=%d matches=%d seconds=%.4f' % (len(s), n, d))\n"
).format(payload=_REDOS_PAYLOAD)

# The adversarial families from the alert's investigation, all with a
# failing trailing \b: a long uppercase run, an alternating-hump identifier,
# and the non-ASCII terminator (the blow-up is terminated by `_` OR by any
# other word character -- `\u00e9` works just as well, so an ASCII-only
# input filter would not have helped).
_CHILD_FAMILIES = _CHILD_PREAMBLE + (
    "cases = [\n"
    "    ('upper-run-1000', 'Aa' + 'A'*1000 + '_'),\n"
    "    ('alternating-humps', 'Ab'*500 + '_'),\n"
    "    ('unicode-terminator', 'Aa' + 'B'*60 + '\\u00e9'),\n"
    "    ('ordinary-source-line', 'SomeHTTPSERVERCONNECTIONFACTORYBUILDER_DEFAULT = 1'),\n"
    "]\n"
    "for name, s in cases:\n"
    "    t = time.perf_counter()\n"
    "    n = len(list(_CAMEL_RE.finditer(s)))\n"
    "    d = time.perf_counter() - t\n"
    "    print('SCANNED %s len=%d matches=%d seconds=%.4f' % (name, s and len(s), n, d))\n"
)


def _run_child(code, timeout=30):
    """Run `code` in a child interpreter that can import openant-core.

    `subprocess.run` kills the child when the timeout expires (SIGKILL on
    POSIX, TerminateProcess on Windows) -- neither is maskable, and a regex
    match in progress cannot defer either, so a regressed pattern leaves no
    orphaned process behind. The child spawns nothing itself, so the
    post-kill output drain cannot block on an inherited pipe.
    """
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(CORE_ROOT),
        env={
            **{k: v for k, v in os.environ.items() if k != "PYTHONSAFEPATH"},
            "PYTHONPATH": str(CORE_ROOT),
        },
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _assert_scan_completed(code, timeout=30):
    try:
        proc = _run_child(code, timeout=timeout)
    except subprocess.TimeoutExpired:
        pytest.fail(
            "_CAMEL_RE did not finish scanning a {}-byte adversarial input within "
            "{}s -- the CamelCase identifier shape has regressed to a "
            "super-linear (catastrophic-backtracking) form. Expected pattern: "
            "{!r}".format(len(("Aa" + "B" * 60 + "_")), timeout, _LINEAR_CAMEL_PATTERN)
        )
    assert proc.returncode == 0, (
        "the child interpreter failed instead of scanning -- this test would "
        "otherwise pass vacuously.\nstdout:\n{}\nstderr:\n{}".format(proc.stdout, proc.stderr)
    )
    assert "SCANNED" in proc.stdout, (
        "the child produced no scan marker, so no scan is proven to have run.\n"
        "stdout:\n{}\nstderr:\n{}".format(proc.stdout, proc.stderr)
    )
    return proc


def test_camel_identifier_regex_is_not_exponential():
    """The canonical alert-#12 payload must scan to completion promptly.

    RED on the vulnerable pattern = the child is still backtracking when the
    30s timeout kills it. GREEN on the fixed pattern = well under a second.
    """
    proc = _assert_scan_completed(_CHILD_CANONICAL)
    # The payload is a NON-match: proving zero matches shows the cost was
    # spent on the failing trailing \b, which is the blow-up's trigger.
    assert "matches=0" in proc.stdout, proc.stdout


def test_camel_identifier_regex_is_linear_on_adversarial_families():
    """Every family the alert's investigation produced stays prompt.

    A 1000-char uppercase run, an alternating-hump identifier, a non-ASCII
    terminator, and the 51-byte ordinary source line from the alert.
    """
    proc = _assert_scan_completed(_CHILD_FAMILIES)
    assert proc.stdout.count("SCANNED") == 4, proc.stdout


def test_camel_identifier_regex_shape_is_pinned():
    """Structural guard against re-arming.

    greenery proved this pattern and the original accept the same language,
    so restoring `A-Za-z0-9` in the inner class would be a silent
    performance-only regression -- invisible to every extraction test in the
    suite. Pin the shape explicitly.
    """
    assert _CAMEL_RE.pattern == _LINEAR_CAMEL_PATTERN, (
        "_CAMEL_RE changed shape. If this is a deliberate rewrite, re-prove "
        "LINEARITY (not just equivalence) before updating this pin: the "
        "inner repetition must not be able to start at a character the "
        "preceding element could also have consumed."
    )
