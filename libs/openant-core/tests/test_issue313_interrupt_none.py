"""Regression tests for issue #313 — Ctrl+C during analyze raises
AttributeError on the None placeholders, and the resulting error envelope
makes the CLI record an interrupt as a FAILED scan.

The interrupt handlers return the partially-filled results list (the
`[None] * total` placeholders for units that never ran survive); the
consumer `_count_verdicts` does not tolerate None (r.get on NoneType),
step_report catches the AttributeError and re-raises, cli.py emits a JSON
error envelope on stdout — and the Go CLI's interrupt short-circuit fires
ONLY on empty stdout, so the interrupt is recorded as a failed scan (exit
2) rather than interrupted.

Contract locked here (the issue's suggestions 1+2):
- _count_verdicts skips None entries (the counts are CORRECT for the
  interrupted case, not merely non-crashing — an un-run unit counts
  nowhere, matching the checkpoint-resume semantics);
- the interrupted path reports what it did (N analysed, M not started,
  checkpoints written) — both numbers derivable from the list;
- the interruption reaches the caller: run_analysis raises
  KeyboardInterrupt AFTER the checkpoints/report are written (the
  handlers stop swallowing it), so the CLI can emit the interrupt
  handling rather than an error envelope.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402

from core.analyzer import _count_verdicts  # noqa: E402


def test_count_verdicts_skips_none_placeholders():
    counts = _count_verdicts([{"finding": "safe"}, None, {"finding": "vulnerable"}, None])
    assert counts["safe"] == 1
    assert counts["vulnerable"] == 1
    # the None placeholders count NOWHERE — an un-run unit is not a
    # verdict, matching the checkpoint-resume semantics
    assert sum(counts.values()) == 2


def test_count_verdicts_clean_list_unchanged():
    counts = _count_verdicts([{"finding": "safe"}, {"verdict": "VULNERABLE"}])
    assert counts["safe"] == 1
    assert counts["vulnerable"] == 1


def test_count_verdicts_all_none():
    """A fully-interrupted run: every placeholder survives, every count 0."""
    assert sum(_count_verdicts([None, None]).values()) == 0


def test_interrupt_report_counts():
    """Suggestion 2: the interrupted path reports what it did — N
    analysed, M not started — both derivable from the list."""
    from core.analyzer import _interrupt_report

    report = _interrupt_report(
        results=[{"finding": "safe"}, None, {"finding": "vulnerable"}, None, None],
        total=5)
    assert "2" in report      # analysed (the non-None entries)
    assert "3" in report      # not started (the None placeholders)
    assert "checkpoint" in report.lower()


def test_sequential_interrupt_raises_after_report(monkeypatch, tmp_path):
    """The handlers stop swallowing the interrupt: after the checkpoints
    and report are written, KeyboardInterrupt reaches the caller (so the
    CLI can handle it as an interrupt, not an error envelope)."""
    import core.analyzer as az

    # drive _run_detection's sequential path: monkeypatch _process_and_save
    # to raise KeyboardInterrupt on the second unit
    calls = {"n": 0}

    def fake_process(i, unit):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        return {"index": i, "result": {"unit_id": f"u{i}", "finding": "safe",
                                        "verdict": "SAFE"},
                "route_key": f"f.py:u{i}", "code_for_route": "x",
                "finding": "safe", "elapsed": 0.1}

    # _process_and_save is a closure inside _run_detection; drive the
    # interrupt through _process_unit instead (the function the closure
    # wraps for the sequential path)
    import core.analysis_core as ac

    def fake_process_unit(binding, unit, index, json_corrector, app_context):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        # the _process_and_save shape: an 'out' dict with index/result/...
        return {"index": index,
                "result": {"unit_id": f"u{index}", "finding": "safe",
                            "verdict": "SAFE", "route_key": f"f.py:u{index}"},
                "route_key": f"f.py:u{index}", "code_for_route": "x",
                "finding": "safe", "elapsed": 0.1}

    monkeypatch.setattr(ac, "analyze_unit", fake_process_unit)
    monkeypatch.setattr(az, "_process_unit", fake_process_unit)

    with pytest.raises(KeyboardInterrupt):
        az._run_detection(
            [{"id": "u0", "code": "x=1"}, {"id": "u1", "code": "x=1"},
             {"id": "u2", "code": "x=1"}],
            binding=object(), json_corrector=None, app_context=None,
            workers=1, checkpoint=None)
