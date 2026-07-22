"""The report subprocesses must not let a scanned repo shadow the `report` package.

`core/reporter.py` runs `python -m report.csv_export` / `report.html_report`. `-m`
prepends the process working directory to sys.path[0], and the engine inherits the
user's shell CWD — which in the ordinary `git clone X && cd X && openant report`
flow is INSIDE the scanned, untrusted repository. Without protection, a hostile
`report/__init__.py` in that repo shadows the installed package and executes on
import: repo-authored code execution, the same class as the working-directory
`pip install -e` hole closed earlier.

It was introduced by the wheel-repair commit: the prior form passed
`cwd=_CORE_ROOT`, which existed for script-path resolution but INCIDENTALLY pinned
the child's sys.path away from the untrusted CWD. Removing it to fix the wheel
dropped that accidental invariant. `-P` restores it explicitly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _hostile_report_dir(tmp_path: Path) -> Path:
    """A directory whose `report/` package writes a marker if it ever imports."""
    marker = tmp_path / "PWNED"
    pkg = tmp_path / "report"
    pkg.mkdir()
    (pkg / "__init__.py").write_text(
        f"import pathlib; pathlib.Path({str(marker)!r}).write_text('x')\n")
    (pkg / "csv_export.py").write_text("print('hostile')\n")
    return marker


def test_dash_P_refuses_the_hostile_shadow(tmp_path):
    """Behavioural: the exact command reporter builds, run from a hostile CWD,
    must resolve the INSTALLED report package, not the repo's."""
    marker = _hostile_report_dir(tmp_path)
    r = subprocess.run(
        [sys.executable, "-P", "-m", "report.csv_export"],
        cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert not marker.exists(), (
        "hostile report/__init__.py executed under -P; the CWD is still on sys.path")
    # The installed package's argparse ran instead (missing required args).
    assert "hostile" not in (r.stdout + r.stderr)


def test_without_dash_P_the_shadow_DOES_execute(tmp_path):
    """The control that proves -P is load-bearing, not decorative.

    If this ever stops executing the shadow, the vulnerability has changed shape
    and the guard above is testing nothing.
    """
    marker = _hostile_report_dir(tmp_path)
    subprocess.run([sys.executable, "-m", "report.csv_export"],
                   cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert marker.exists(), (
        "the unguarded command did NOT run the shadow — the CWD-shadow mechanism "
        "this test relies on no longer holds; re-derive the guard")


def test_reporter_builds_the_dash_P_flag_into_both_commands():
    """Structural: couple the behavioural proof to the code under test.

    The behavioural tests above run a hand-built command; this asserts reporter.py
    actually emits -P before -m at both call sites, so the two cannot drift apart.
    """
    src = (Path(__file__).resolve().parent.parent / "core" / "reporter.py").read_text()
    for module in ("report.csv_export", "report.html_report"):
        assert f'"-P", "-m", "{module}"' in src, (
            f"reporter.py invokes {module} without -P; a hostile CWD package can "
            "shadow it")
