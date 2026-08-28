"""Regression tests for issue #288 — tracking hygiene.

Two problems: (1) ``residual-evasion.md`` was cited by six code sites
(including a section identifier "R1/T") but has NEVER existed on any
branch (``git log --all = 0``) — a deferral with no tracker is not a
deferral. (2) ``scan_truncated`` was emitted by the Rust/Zig call-graph
builders with ZERO readers, while the docstring claimed it was "a
MACHINE-READABLE record downstream reachability can consume" — a
compensating control with no reader is documentation, not a control.

Contract locked here:
- the six former ``residual-evasion.md`` citations now point at issue
  #288 (trackable);
- the docstring's claim is downgraded to the honest form ("recorded for
  future consumers; no current reader" — the over-seed implementation is
  a tracked follow-up, not a present behaviour);
- a test enforces the convention: any file path cited as a tracker in a
  ``# See ...`` comment in the parsers and utilities must exist on disk.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def test_no_citations_to_nonexistent_trackers():
    """Any file path cited as a tracker in a 'See <path>' comment in the
    parsers and utilities must exist on disk (the convention #288
    documents: 'a deferral with no tracker is not a deferral')."""
    core = Path(__file__).parent.parent
    missing = []
    for py in core.rglob("*.py"):
        if "/tests/" in str(py) or "/.venv/" in str(py):
            continue
        text = py.read_text(errors="replace")
        for m in re.finditer(r"[Ss]ee\s+`?(residual-evasion[A-Za-z0-9_/.-]*)`?", text):
            cited = m.group(1)
            # strip code formatting
            cited = cited.strip("`")
            if not (core / cited).exists() and not (core.parent / cited).exists():
                missing.append(f"{py.relative_to(core)}: cites nonexistent {cited}")
    assert not missing, (
        f"Files cited as trackers must exist on disk: {missing}"
    )


def test_scan_truncated_docstring_honest():
    """The docstring claims 'a MACHINE-READABLE record downstream
    reachability can consume' — with zero readers, that claim is false.
    It must be downgraded to the honest form until a reader exists."""
    from utilities.scan_budget import bound_macro_scan_text
    doc = bound_macro_scan_text.__doc__ or ""
    assert "MACHINE-READABLE" not in doc, (
        "the un-backed claim must be downgraded until a reader exists"
    )
    assert "future consumers" in doc or "no current reader" in doc, (
        "the docstring must honestly state the current reader status"
    )


def test_citations_point_to_issue():
    """The six former residual-evasion.md citations now point at a
    trackable issue number (#288)."""
    core = Path(__file__).parent.parent
    stale = []
    for py in core.rglob("*.py"):
        if "/tests/" in str(py) or "/.venv/" in str(py):
            continue
        text = py.read_text(errors="replace")
        if "residual-evasion.md" in text:
            stale.append(str(py.relative_to(core)))
    assert not stale, (
        f"residual-evasion.md citations must be redirected to issue #288: {stale}"
    )
