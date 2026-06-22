"""Regression test for the wait_if_needed TOCTOU on the backoff deadline.

wait_if_needed reads _backoff_until under the lock, releases it, then sleeps for the *entry-time* duration.
If another worker extends _backoff_until (via report_rate_limit on a fresh 429) while this worker sleeps, this
worker wakes before the new deadline and issues a request into the still-active backoff window -> more 429s,
thundering herd. Fix: after sleeping, re-check the deadline and keep waiting until it has actually passed.
"""
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

import utilities.rate_limiter as rl  # noqa: E402


def test_wait_if_needed_rechecks_extended_deadline(monkeypatch):
    # Fresh, isolated instance (bypass the singleton) so the test doesn't touch global state.
    limiter = object.__new__(rl.GlobalRateLimiter)
    limiter._lock = threading.Lock()
    limiter._total_waits = 0
    limiter._total_wait_time = 0.0

    clock = {"t": 1000.0}
    monkeypatch.setattr(rl.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(rl.random, "uniform", lambda a, b: 0.0)  # deterministic: no jitter
    limiter._backoff_until = 1005.0  # 5s backoff from t=1000

    sleeps = []
    state = {"extended": False}

    def fake_sleep(d):
        clock["t"] += d
        sleeps.append(d)
        if not state["extended"]:
            # Simulate another worker extending the backoff (a fresh 429) DURING this sleep.
            limiter._backoff_until = clock["t"] + 3.0
            state["extended"] = True

    monkeypatch.setattr(rl.time, "sleep", fake_sleep)

    limiter.wait_if_needed()

    assert clock["t"] >= limiter._backoff_until, (
        f"woke before the extended deadline: t={clock['t']} < backoff_until={limiter._backoff_until}"
    )
    assert len(sleeps) >= 2, f"did not re-check the deadline after it was extended (slept {len(sleeps)}x)"
    # counters increment once per waiting call (not per loop iteration) and accumulate actual slept time
    assert limiter._total_waits == 1, f"expected _total_waits == 1 (once per call), got {limiter._total_waits}"
    assert limiter._total_wait_time == sum(sleeps), "should accumulate total slept time"


def test_wait_if_needed_returns_zero_when_not_in_backoff(monkeypatch):
    """Guard: when not in a backoff window, it returns immediately (0.0) and does not sleep."""
    limiter = object.__new__(rl.GlobalRateLimiter)
    limiter._lock = threading.Lock()
    limiter._total_waits = 0
    limiter._total_wait_time = 0.0
    monkeypatch.setattr(rl.time, "monotonic", lambda: 2000.0)
    limiter._backoff_until = 1000.0  # already past
    slept = []
    monkeypatch.setattr(rl.time, "sleep", lambda d: slept.append(d))
    assert limiter.wait_if_needed() == 0.0
    assert slept == []
    assert limiter._total_waits == 0  # no-wait fast path must not increment the counter
