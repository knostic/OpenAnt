"""
Progress reporting for long-running pipeline steps.

Prints per-unit progress lines and periodic summaries to stderr,
which the Go CLI streams to the terminal in real-time.
"""

import sys
import threading
import time
from typing import Optional


def _fmt_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m{s:02d}s"
    h, rem = divmod(int(seconds), 3600)
    m, _ = divmod(rem, 60)
    return f"{h}h{m:02d}m"


def _fmt_cost(usd: float) -> str:
    """Format cost in dollars."""
    if usd < 0.01:
        return f"${usd:.4f}"
    if usd < 10:
        return f"${usd:.2f}"
    return f"${usd:,.2f}"


class ProgressReporter:
    """Tracks and prints per-unit progress for a pipeline step.

    Prints one line per unit to stderr, plus periodic summary lines.
    All output goes to stderr so it streams through the Go CLI
    without corrupting the stdout JSON envelope.

    Args:
        step_name: Display name for the step (e.g. "Enhance", "Verify").
        total: Total number of units to process.
        tracker: Optional TokenTracker for cost reporting.
        summary_interval: Print a summary line every N units.
            Defaults to every 50 units or 10% of total, whichever is smaller.
    """

    def __init__(
        self,
        step_name: str,
        total: int,
        tracker=None,
        summary_interval: int | None = None,
        completed: int = 0,
    ):
        self.step_name = step_name
        self.total = total
        self.tracker = tracker
        self.start_time = time.monotonic()
        self.completed = completed
        # Units restored from a checkpoint: they consumed no session time, so
        # they must be excluded from the per-unit rate (#218).
        self._initial_completed = completed
        self._lock = threading.Lock()
        self._last_cost = self._get_cost()  # snapshot for per-unit delta

        # Width for the counter so alignment stays consistent
        self._width = len(str(total))

        # Summary interval: every 50 units or 10% of total, whichever is smaller
        if summary_interval is not None:
            self._summary_interval = summary_interval
        else:
            ten_pct = max(1, total // 10)
            self._summary_interval = min(50, ten_pct)

    def _get_cost(self) -> float:
        """Get current cumulative cost from the tracker."""
        if not self.tracker:
            return 0.0
        totals = self.tracker.get_totals()
        return totals.get("total_cost_usd", 0.0)

    def mark_restored(self, count: int) -> None:
        """Rebase progress to a checkpoint-restored count AFTER construction.

        The Detect phase passes ``completed=`` at construction, but Enhance and
        Verify learn their restored count later via a callback. Set BOTH the
        live counter and the session baseline, so restored units are excluded
        from the per-unit rate exactly as ``completed=`` does — the callback
        path previously set only ``completed`` and left the rate diluted (#218).
        """
        with self._lock:
            self.completed = count
            self._initial_completed = count

    def _session_done(self) -> int:
        """Units processed in THIS session (excludes checkpoint-restored units).

        Every rate/average divides session ``elapsed`` by this, never the
        cumulative ``completed`` — the restored units consumed no session time,
        so cumulative division dilutes the per-unit rate on a resumed run (#218).
        """
        return self.completed - self._initial_completed

    def _estimate_remaining(self, elapsed: float) -> str:
        """Estimate time remaining based on average per-unit time.

        The rate is measured over units processed IN THIS SESSION only. Units
        restored from a checkpoint (``_initial_completed``) consumed none of
        ``elapsed``, so dividing session-elapsed by the cumulative count made a
        resumed run's ETA wildly optimistic (~25x on the reported run, #218).
        """
        session_done = self._session_done()
        if session_done <= 0:
            return "~?"
        avg = elapsed / session_done
        # Floor at 0: retries can double-count `completed` past `total`, which would otherwise
        # make remaining_units negative and render the ETA as a negative duration.
        remaining_units = max(0, self.total - self.completed)
        remaining_secs = avg * remaining_units
        return f"~{_fmt_duration(remaining_secs)}"

    def report(
        self,
        unit_label: str,
        detail: str = "",
        unit_elapsed: float = 0.0,
    ) -> None:
        """Report completion of one unit.

        Call this after each unit finishes processing.

        Args:
            unit_label: Short identifier for the unit (unit_id, route_key, etc.).
            detail: Extra info (e.g. classification, verdict).
            unit_elapsed: How long this specific unit took, in seconds.
        """
        with self._lock:
            self.completed += 1
            elapsed = time.monotonic() - self.start_time
            eta = self._estimate_remaining(elapsed)
            total_cost = self._get_cost()
            unit_cost = total_cost - self._last_cost
            self._last_cost = total_cost

            # Truncate label if too long
            if len(unit_label) > 50:
                unit_label = unit_label[:47] + "..."

            # Build the progress line — show per-unit cost, not cumulative
            parts = [
                f"[{self.step_name}]",
                f"{self.completed:>{self._width}}/{self.total}",
                unit_label,
            ]
            if detail:
                parts.append(detail)
            if unit_elapsed > 0:
                parts.append(f"{unit_elapsed:.1f}s")

            meta = f"(elapsed {_fmt_duration(elapsed)}, ETA {eta}, {_fmt_cost(unit_cost)})"
            parts.append(meta)

            line = "  ".join(parts)
            print(line, file=sys.stderr, flush=True)

            # Periodic summary — shows cumulative total
            if (
                self.completed % self._summary_interval == 0
                and self.completed < self.total
            ):
                self._print_summary(elapsed, total_cost)

    def _print_summary(self, elapsed: float, cost: float) -> None:
        """Print a highlighted summary line."""
        pct = (self.completed / self.total) * 100
        session_done = self._session_done()
        avg = elapsed / session_done if session_done > 0 else 0
        eta = self._estimate_remaining(elapsed)

        line = (
            f"[{self.step_name}] --- "
            f"{self.completed}/{self.total} ({pct:.1f}%) | "
            f"avg {avg:.1f}s/unit | "
            f"elapsed {_fmt_duration(elapsed)} | "
            f"ETA {eta} | "
            f"cost {_fmt_cost(cost)}"
            f" ---"
        )
        print(line, file=sys.stderr, flush=True)

    def finish(self) -> None:
        """Print a final summary line when the step is done."""
        with self._lock:
            elapsed = time.monotonic() - self.start_time
            cost = self._get_cost()
            session_done = self._session_done()
            avg = elapsed / session_done if session_done > 0 else 0

            line = (
                f"[{self.step_name}] Done: "
                f"{self.completed}/{self.total} units in {_fmt_duration(elapsed)} | "
                f"avg {avg:.1f}s/unit | "
                f"cost {_fmt_cost(cost)}"
            )
            print(line, file=sys.stderr, flush=True)
