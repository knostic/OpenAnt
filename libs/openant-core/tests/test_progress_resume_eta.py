"""#218: ETA must be based on the per-unit rate of THIS session, not the
cumulative count including checkpoint-restored units.

`_estimate_remaining` computed `avg = elapsed / self.completed`, but on a
checkpoint-resumed run `self.completed` is seeded with the restored count
(`ProgressReporter(..., completed=len(checkpointed))`, analyzer.py) while
`elapsed` is measured from session start — so the average was diluted by units
that took zero session time, making the ETA ~25x too optimistic on the reported
run.

Invariant test (format-independent): two reporters that process the SAME number
of units in the SAME session time and have the SAME number remaining must show
the SAME ETA — one starting fresh, one resumed with a large restored count. On
the buggy cumulative-rate code the resumed reporter's ETA is far smaller.
"""

import re
import time

import pytest

from core.progress import ProgressReporter


def _eta(total, initial_completed, session_units, elapsed):
    p = ProgressReporter("step", total, tracker=None, completed=initial_completed)
    p.completed = initial_completed + session_units
    return p._estimate_remaining(elapsed)


def _eta_via_restore(total, restored, session_units, elapsed):
    """Mirror the Enhance/Verify resume path: construct with NO ``completed=``,
    then apply the restored count via the ``mark_restored`` callback (the way
    enhancer.py / verifier.py do it), not the constructor arg."""
    p = ProgressReporter("step", total, tracker=None)
    p.mark_restored(restored)
    p.completed = restored + session_units
    return p._estimate_remaining(elapsed)


def _finish_avg(capsys, total, restored, session_units, elapsed):
    """The 'avg N.Ns/unit' float that finish() prints for a resumed run."""
    p = ProgressReporter("step", total, tracker=None)
    p.mark_restored(restored)
    p.completed = restored + session_units
    p.start_time = time.monotonic() - elapsed  # pin elapsed deterministically
    capsys.readouterr()
    p.finish()
    m = re.search(r"avg ([\d.]+)s/unit", capsys.readouterr().err)
    assert m, "finish() printed no avg s/unit line"
    return float(m.group(1))


class TestResumeETA:
    def test_eta_depends_on_session_rate_not_restored_count(self):
        # fresh: 0 restored, 10 processed this session, 90 remaining
        fresh = _eta(total=100, initial_completed=0, session_units=10, elapsed=10.0)
        # resumed: 90 restored, 10 processed this session, 90 remaining
        resumed = _eta(total=190, initial_completed=90, session_units=10, elapsed=10.0)
        assert fresh == resumed, (
            f"resumed ETA {resumed!r} != fresh ETA {fresh!r} — the restored "
            "count is still diluting the per-unit rate"
        )

    def test_resumed_eta_reflects_real_session_pace(self):
        # 100 restored, 5 processed in 25s (=5s/unit), 95 remaining → ~475s.
        # The buggy cumulative rate (25/105) would give ~22s.
        eta = _eta(total=200, initial_completed=100, session_units=5, elapsed=25.0)
        # 475s has a minutes component; 22s does not — a clean discriminator.
        assert "m" in eta, f"ETA {eta!r} looks like the diluted cumulative rate"

    def test_no_session_units_yet_is_unknown(self):
        p = ProgressReporter("step", 100, tracker=None, completed=40)
        # nothing processed this session yet
        assert p._estimate_remaining(5.0) == "~?"

    def test_callback_restore_path_excludes_restored_units(self):
        # Enhance/Verify resume via mark_restored (a runtime callback), NOT the
        # completed= constructor arg the Detect path uses. Same invariant: a
        # fresh and a large-restored reporter with the same session work + same
        # units remaining must show the same ETA.
        fresh = _eta_via_restore(total=100, restored=0, session_units=10, elapsed=10.0)
        resumed = _eta_via_restore(total=190, restored=90, session_units=10, elapsed=10.0)
        assert fresh == resumed, (
            f"resumed ETA {resumed!r} != fresh {fresh!r} — mark_restored did not "
            "rebase the session baseline, so restored units still dilute the rate"
        )

    def test_finish_avg_reflects_session_pace_not_cumulative(self, capsys):
        # 100 restored, 5 units in 25s → true session pace 5.0 s/unit; the
        # cumulative rate (25/105) would print ~0.2 s/unit on the Done line.
        avg = _finish_avg(capsys, total=200, restored=100, session_units=5, elapsed=25.0)
        assert avg == pytest.approx(5.0, abs=0.5), (
            f"finish() avg {avg}s/unit is diluted by the restored count"
        )
