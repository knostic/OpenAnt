"""
Progress reporting for long-running pipeline steps.

Prints per-unit progress lines and periodic summaries to stderr,
which the Go CLI streams to the terminal in real-time.
"""

import sys
import threading
import time


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
        cost_baseline: Optional MUTABLE ``{"usage": UsageInfo}`` holder — the
            caller's start-of-phase snapshot (``core.tracking.get_usage()``).
            Read LATE, at print time, so the #281 re-snapshot at the
            checkpoint-injection site is picked up without a second callback.
            Omitted (Detect, and every tracker-less test) falls back to a
            snapshot taken here, at construction (#685).
    """

    def __init__(
        self,
        step_name: str,
        total: int,
        tracker=None,
        summary_interval: int | None = None,
        completed: int = 0,
        cost_baseline: dict | None = None,
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
        _start_cost = self._get_cost()
        self._last_cost = _start_cost  # snapshot for per-unit delta
        # #685: the STEP's own baseline. The tracker is per-SCAN
        # (``get_global_tracker()``), so every step-scoped cost line that
        # printed ``_get_cost()`` raw summed the prior steps — the same
        # defect #214 fixed for ``tracking.log_usage`` and #333/PR #458 for
        # the dynamic-test step. ``_start_cost`` is immutable (unlike
        # ``_last_cost``, which every unit overwrites) so repeated
        # ``finish()`` calls — analyzer.py calls it at four sites — keep
        # reporting the same step total.
        self._cost_baseline = cost_baseline
        self._start_cost = _start_cost

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

    def _cost_marker(self) -> str:
        """#786: the completeness marker for this reporter's cost lines."""
        if not self.tracker:
            return ""
        from core.tracking import cost_marker
        return cost_marker(self.tracker.get_totals())

    def _baseline_cost(self) -> float:
        """The scan-cumulative cost at THIS step's start (#685).

        The caller's holder wins and is read HERE, not at construction: the
        enhance/verify reporters are built before their callee injects the
        restored checkpoints' spend (``add_prior_usage`` in
        context_enhancer.py, reached after the reporter exists), and #281
        refreshes the holder at that injection site. ``restored_callback``
        cannot serve as the hook — it fires before the injection.
        A missing/malformed holder falls back to the construction snapshot
        rather than to a fabricated zero (#605's shape) — and never raises:
        this runs inside ``finish()``, at the very end of a step that has
        already paid for its work, so a bad holder must degrade the line,
        never kill the step.
        """
        holder = self._cost_baseline
        if isinstance(holder, dict):
            cost = getattr(holder.get("usage"), "total_cost_usd", None)
            if isinstance(cost, (int, float)):
                return float(cost)
        return self._start_cost

    def _as_step_cost(self, total_cost: float) -> float:
        """Turn an already-read cumulative total into THIS step's own spend.

        Rounded to 6 decimals exactly as ``step_report.py`` rounds its own
        baseline delta, for two reasons: the two figures then agree digit for
        digit (the issue's point — the step report is the correct one), and
        the raw subtraction's float residue would otherwise flip
        ``_fmt_cost``'s $0.01 precision threshold (a $0.01 step printed
        "$0.0100" because the delta landed at 0.00999999999999999).

        Deliberately NOT floored at zero. A negative would mean the baseline
        was taken after some of the step's spend — an ordering regression
        that must stay visible, not a cosmetic artifact like the retry
        double-count ``_estimate_remaining`` floors.
        """
        return round(total_cost - self._baseline_cost(), 6)

    def _step_cost(self) -> float:
        """This step's own spend, read fresh from the tracker."""
        return self._as_step_cost(self._get_cost())

    def mark_restored(self, count: int) -> None:
        """Rebase progress to a checkpoint-restored count AFTER construction.

        The Detect phase passes ``completed=`` at construction, but Enhance and
        Verify learn their restored count later via a callback. Set BOTH the
        live counter and the session baseline, so restored units are excluded
        from the per-unit rate exactly as ``completed=`` does — the callback
        path previously set only ``completed`` and left the rate diluted (#218).

        Deliberately does NOT rebase the COST baseline (#685): this callback
        fires before the checkpoint ``add_prior_usage`` injection
        (context_enhancer.py restores units, calls back, and only then
        injects), so rebasing here would capture a pre-injection total. The
        cost baseline's rebase is the ``cost_baseline`` holder's job, refreshed
        at the injection site itself by #281.
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

            # #786 (T1 round-3 F2): the per-unit line's dollars are
            # UNIT-scoped (total - last_cost) while the tracker set is
            # RUN-cumulative — the honest form is the run-scoped note,
            # never asserting this unit's own cost is an under-count.
            _ids = (self.tracker.cost_incomplete_models()
                    if self.tracker else [])
            _unit_marker = ("" if not _ids else
                            f" (run cost incomplete: {len(_ids)} unpriced "
                            f"model(s) — this unit's figure may exclude their "
                            f"spend)")
            meta = f"(elapsed {_fmt_duration(elapsed)}, ETA {eta}, {_fmt_cost(unit_cost)}{_unit_marker})"
            parts.append(meta)

            line = "  ".join(parts)
            print(line, file=sys.stderr, flush=True)

            # Periodic summary — the step's running total, not per-unit
            # (#685: and not the scan's — it fed _print_summary the raw
            # global total, so a step's interval lines summed every prior
            # step exactly as its Done line did; fixing only one of the two
            # would make the cost appear to DROP between them).
            if (
                self.completed % self._summary_interval == 0
                and self.completed < self.total
            ):
                self._print_summary(elapsed, self._as_step_cost(total_cost))

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
            f"cost {_fmt_cost(cost)}{self._cost_marker()}"
            f" ---"
        )
        print(line, file=sys.stderr, flush=True)

    def finish(self) -> None:
        """Print a final summary line when the step is done."""
        with self._lock:
            elapsed = time.monotonic() - self.start_time
            # #685: this step's own spend. The issue's four stress runs each
            # showed the enhance Done line reporting enhance + app-context.
            cost = self._step_cost()
            session_done = self._session_done()
            avg = elapsed / session_done if session_done > 0 else 0

            line = (
                f"[{self.step_name}] Done: "
                f"{self.completed}/{self.total} units in {_fmt_duration(elapsed)} | "
                f"avg {avg:.1f}s/unit | "
                f"cost {_fmt_cost(cost)}{self._cost_marker()}"
            )
            print(line, file=sys.stderr, flush=True)
