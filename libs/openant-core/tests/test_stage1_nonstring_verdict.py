"""Regression: run_stage1_consistency_check must not crash on a non-string verdict.

A result dict may carry ``verdict: None`` (before a verdict is assigned) or a
stray int/list. The pre-fix code did ``r.get("verdict", "").upper()`` — the
``""`` default only covers a *missing* key, so a present-but-non-string verdict
reached ``.upper()`` and raised ``AttributeError``, aborting the consistency
check for the whole group.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from utilities.stage1_consistency import run_stage1_consistency_check


def test_none_verdict_does_not_crash():
    results = [
        {"route_key": "r1", "verdict": None},
        {"route_key": "r1", "verdict": "VULNERABLE"},
    ]
    out = run_stage1_consistency_check(results, {}, None, None)
    assert out is not None


def test_int_verdict_does_not_crash():
    results = [
        {"route_key": "r1", "verdict": 1},
        {"route_key": "r1", "verdict": "SAFE"},
    ]
    out = run_stage1_consistency_check(results, {}, None, None)
    assert out is not None
