"""#701: the diagnostic path must never become the failure.

``_record_usage_in_tracker``'s failure handler counts and names the dropped
accounting record — then printed to stderr UNGUARDED. If stderr is closed
or its encoding is broken, the print raises ``OSError`` OUT of the handler:
the diagnostic replaces the completion path it exists to protect. The
sibling handler added by #644 (``agent.py``: the attempt-accounting guard)
wraps BOTH the counter call and the stderr print in their own
``try/except Exception: pass`` and names the class in its comment.

Contract locked here:

- a closed-stderr hand-off logs loudly WITHOUT raising (the falsifier);
- the counter still ticks on a healthy drop (the #605 signal is durable —
  the counting is INDEPENDENT of the printing);
- a healthy stderr still gets BOTH lines (the loudness contract);
- the counter-unavailable fallback's print is guarded too (a poisoned
  ``llm_client`` import + a closed stderr is the worst case — and even
  then the handler returns, never raises).
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm_client import (  # noqa: E402
    _accounting_error_count,
    reset_warning_state,
)


class _ClosedStderr:
    """Every write/flush raises the closed-stderr OSError."""

    def write(self, *a):
        raise OSError("I/O operation on closed file")

    def flush(self, *a):
        raise OSError("I/O operation on closed file")

    @property
    def encoding(self):
        return "utf-8"


class _BrokenEncodingStderr:
    """The encoding-broken class: the print's encode step raises."""

    def write(self, *a):
        raise UnicodeEncodeError("utf-8", "x", 0, 1, "invalid")

    def flush(self, *a):
        pass

    @property
    def encoding(self):
        return "utf-8"


def _drive(capsys, stderr_obj):
    """Drive the hand-off's except path with a poisoned binding and the
    given stderr; return the escaped exception (None when none)."""
    from core import reporter
    real_stderr = sys.stderr
    reset_warning_state()
    sys.stderr = stderr_obj
    try:
        reporter._record_usage_in_tracker(
            {"total_tokens": 5, "input_tokens": 3,
             "output_tokens": 2, "cost_usd": 0.0}, None)
        escaped = None
    except BaseException as e:  # noqa: BLE001 — the escape IS the subject
        escaped = e
    finally:
        sys.stderr = real_stderr
    count = _accounting_error_count()
    reset_warning_state()
    return escaped, count


def test_closed_stderr_never_raises(capsys):
    """The falsifier: a closed-stderr hand-off logs loudly WITHOUT
    raising. Base: the OSError escapes the handler."""
    from core import reporter  # the prod-hunk module (the symbol screen)
    assert reporter._record_usage_in_tracker is not None
    escaped, count = _drive(capsys, _ClosedStderr())
    assert escaped is None, (
        f"the diagnostic print escaped the handler as "
        f"{type(escaped).__name__}: {escaped} — the diagnostic path "
        f"became the failure (the #644 sibling guards exactly this)")
    assert count == 1, (
        "the accounting-error counter must still tick on a healthy drop — "
        "the #605 signal is durable and independent of the printing")


def test_broken_encoding_stderr_never_raises(capsys):
    """The issue's second named class: the encoding is broken — the
    print's encode step raises UnicodeEncodeError out of the handler."""
    from core import reporter  # the prod-hunk module (the symbol screen)
    assert reporter._record_usage_in_tracker is not None
    escaped, count = _drive(capsys, _BrokenEncodingStderr())
    assert escaped is None, (
        f"the encoding-broken stderr escaped as {type(escaped).__name__}")
    assert count == 1


def test_healthy_stderr_still_loud(capsys):
    """The loudness contract: a healthy stderr still gets the failure
    line — the guard may not go silent (a swallowed pass that never
    prints would trade the bug for a silent diagnostic)."""
    from core import reporter
    reset_warning_state()
    reporter._record_usage_in_tracker(
        {"total_tokens": 5, "input_tokens": 3,
         "output_tokens": 2, "cost_usd": 0.0}, None)
    count = _accounting_error_count()
    captured = capsys.readouterr()
    reset_warning_state()
    assert count == 1
    assert "accounting hand-off failed" in captured.err, (
        "the healthy-stderr loudness line vanished")
    assert "AttributeError" in captured.err, (
        "the line names the exception class — the diagnostic's content")


def test_snapshot_usage_sentinel_never_raises(capsys):
    """The fable-r1 F1 twin: _snapshot_usage's failure print is the OTHER
    half of #605 — the sentinel contract (returns (None, None) on failure;
    the caller marks the step accounting-incomplete) must survive a
    closed stderr. Base: the print raised OSError out of the sentinel."""
    from core.step_report import _snapshot_usage
    from core import tracking

    class _PoisonedUsage:
        @property
        def total_cost_usd(self):
            raise KeyError("poisoned totals (a closed tracker hand-off)")

    real = tracking.get_usage
    tracking.get_usage = lambda: _PoisonedUsage()
    real_stderr = sys.stderr
    reset_warning_state()
    sys.stderr = _ClosedStderr()
    try:
        cost, snap = _snapshot_usage()
        escaped = None
    except BaseException as e:  # noqa: BLE001
        escaped = e
    finally:
        sys.stderr = real_stderr
        tracking.get_usage = real
    reset_warning_state()
    assert escaped is None, (
        f"the sentinel path escaped as {type(escaped).__name__}: {escaped} — "
        f"a closed stderr killed the step the (None, None) sentinel exists "
        f"to protect")
    assert cost is None and snap is None, (
        "the sentinel SHAPE must hold: (None, None), never a fabricated "
        "zero snapshot")


def test_snapshot_usage_sentinel_still_loud(capsys):
    """The sentinel's loudness on a healthy stderr — the guard may not go
    silent."""
    from core.step_report import _snapshot_usage
    from core import tracking

    class _PoisonedUsage:
        @property
        def total_cost_usd(self):
            raise KeyError("poisoned totals")

    real = tracking.get_usage
    tracking.get_usage = lambda: _PoisonedUsage()
    try:
        cost, snap = _snapshot_usage()
    finally:
        tracking.get_usage = real
    captured = capsys.readouterr()
    assert cost is None and snap is None
    assert "accounting snapshot failed" in captured.err, (
        "the sentinel's healthy-stderr loudness vanished")


def test_counter_unavailable_fallback_is_loud(capsys, monkeypatch):
    """F-r2-1 (the surviving silence mutant): the fallback line's LOUDNESS
    is pinned — a healthy stderr with the counter unavailable still
    prints the 'AND the counter is unavailable' signal (a silence-mutant
    on the line survived the battery until this pin)."""
    import builtins
    from core import reporter

    real_import = builtins.__import__

    def _poisoned(name, *a, **kw):
        if name == "utilities.llm_client":
            raise ImportError("poisoned registry module")
        return real_import(name, *a, **kw)

    reset_warning_state()
    monkeypatch.setattr(builtins, "__import__", _poisoned)
    try:
        reporter._record_usage_in_tracker(
            {"total_tokens": 5, "input_tokens": 3,
             "output_tokens": 2, "cost_usd": 0.0}, None)
    finally:
        monkeypatch.undo()
    captured = capsys.readouterr()
    reset_warning_state()
    assert "counter is unavailable" in captured.err, (
        "the fallback line went silent — the only remaining signal of the "
        "worst case (the counter mechanism down) died with it")


def test_counter_unavailable_fallback_is_guarded(monkeypatch, capsys):
    """The worst case: the counting mechanism itself is unavailable (a
    poisoned llm_client) AND stderr is closed — the fallback print is
    guarded too, so even this shape returns, never raises."""
    import builtins
    from core import reporter

    real_import = builtins.__import__

    def _poisoned(name, *a, **kw):
        if name == "utilities.llm_client":
            raise ImportError("poisoned registry module")
        return real_import(name, *a, **kw)

    reset_warning_state()
    real_stderr = sys.stderr
    monkeypatch.setattr(builtins, "__import__", _poisoned)
    sys.stderr = _ClosedStderr()
    try:
        reporter._record_usage_in_tracker(
            {"total_tokens": 5, "input_tokens": 3,
             "output_tokens": 2, "cost_usd": 0.0}, None)
        escaped = None
    except BaseException as e:  # noqa: BLE001
        escaped = e
    finally:
        sys.stderr = real_stderr
        monkeypatch.undo()
    reset_warning_state()
    assert escaped is None, (
        f"the counter-unavailable fallback escaped as "
        f"{type(escaped).__name__}: {escaped} — even the worst case "
        f"(poisoned import + closed stderr) must return, never raise")
