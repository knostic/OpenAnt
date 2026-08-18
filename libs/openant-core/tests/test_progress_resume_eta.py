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

from core.progress import ProgressReporter


def _eta(total, initial_completed, session_units, elapsed):
    p = ProgressReporter("step", total, tracker=None, completed=initial_completed)
    p.completed = initial_completed + session_units
    return p._estimate_remaining(elapsed)


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
