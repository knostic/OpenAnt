"""Regression test for ProgressReporter ETA underflow on retry double-count.

`report()` does an unconditional `self.completed += 1`, so a retried unit re-reports and `completed` can
exceed `total`. `_estimate_remaining` then computes `remaining_units = total - completed` < 0 → a negative
`remaining_secs` → the ETA is rendered as a negative duration (e.g. "~-30s"). Fix: floor remaining at 0.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from core.progress import ProgressReporter  # noqa: E402


def test_eta_never_negative_when_completed_exceeds_total():
    """After more report() calls than `total` (retry double-count), the ETA must not be negative."""
    r = ProgressReporter("Verify", total=2)
    r.report("u1")
    r.report("u1")  # retry of the same unit -> double-count
    r.report("u2")
    assert r.completed > r.total  # precondition: the double-count occurred (3 > 2)
    eta = r._estimate_remaining(10.0)
    assert not eta.lstrip("~").startswith("-"), f"ETA underflowed to a negative duration: {eta!r}"


def test_eta_normal_case_still_positive():
    """Guard: the normal (no over-count) path still produces a sensible positive ETA."""
    r = ProgressReporter("Verify", total=10)
    r.report("u1")
    eta = r._estimate_remaining(5.0)
    assert eta.startswith("~") and not eta.lstrip("~").startswith("-")
