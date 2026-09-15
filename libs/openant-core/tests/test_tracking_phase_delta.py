"""#214: a per-phase usage line must report the phase's own usage, not the
cumulative run total.

`log_usage("Stage 2")` printed `get_usage()` — the global cumulative tracker —
so the console "Stage 2:" line summed every prior phase (parse/context/enhance/
Stage 1) and overstated Stage 2's calls/tokens/cost. With a start-of-phase
baseline it reports the delta; without one it stays cumulative (back-compat).
"""

import core.tracking as tracking
from utilities.llm_client import get_global_tracker

_PRICE = {"input": 1.0, "output": 1.0}


def _record(n):
    tr = get_global_tracker()
    for _ in range(n):
        tr.record_call("m", 100, 50, pricing=_PRICE)


class TestPhaseDelta:
    def test_baseline_reports_phase_delta_not_cumulative(self, capsys):
        tracking.reset_tracking()
        _record(3)                       # prior phases: 3 calls
        baseline = tracking.get_usage()  # cumulative-so-far
        _record(2)                       # this phase: 2 calls
        tracking.log_usage("Stage 2", baseline)
        err = capsys.readouterr().err
        assert "Stage 2: 2 API calls" in err, (
            f"expected the phase delta (2), got: {err.strip()!r}"
        )
        assert "5 API calls" not in err   # not the cumulative total

    def test_no_baseline_is_cumulative_backcompat(self, capsys):
        tracking.reset_tracking()
        _record(4)
        tracking.log_usage("Total")
        err = capsys.readouterr().err
        assert "Total: 4 API calls" in err
