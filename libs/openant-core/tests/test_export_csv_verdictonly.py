"""Regression test: a verdict-only result must not export a BLANK finding column.

export_csv reads result.get('finding', '') at three sites — the agree branch and the
disagree fallback of get_stage1_verdict(), and stage2_verdict in export_csv(). A result
that carries a 'verdict' key but no 'finding' key (a verdict-only result) therefore
exports an empty finding column instead of its verdict. Fix: fall back to
result.get('verdict', '') at all three sites, preserving the raw casing for display.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

import report.csv_export as ec  # noqa: E402


def test_get_stage1_verdict_falls_back_to_verdict_agree_branch():
    """agree branch (:109): verdict-only result returns its verdict, not ''."""
    assert ec.get_stage1_verdict({'verdict': 'VULNERABLE', 'verification': {'agree': True}}) == 'VULNERABLE'


def test_get_stage1_verdict_falls_back_to_verdict_disagree_fallback():
    """disagree fallback (:114): verdict-only result with no note returns its verdict, not ''."""
    result = {'verdict': 'SAFE', 'verification': {'agree': False}}
    assert ec.get_stage1_verdict(result) == 'SAFE'


def test_export_csv_verdict_only_result_exports_verdict(tmp_path):
    """Integration (:161 + get_stage1_verdict): a verdict-only result exports 'VULNERABLE', not blank."""
    ds = tmp_path / "dataset.json"
    exp = tmp_path / "experiment.json"
    out = tmp_path / "out.csv"
    ds.write_text(
        '{"units": [{"id": "f.py:foo", "code": {"primary_code": "x = 1"},'
        ' "llm_context": {"reasoning": "r", "security_classification": "c"}}]}'
    )
    # verdict-only result: has 'verdict' but NO 'finding' key
    exp.write_text(
        '{"results": [{"route_key": "f.py:foo", "verification": {"agree": true, "explanation": "e"},'
        ' "verdict": "VULNERABLE", "reasoning": "r1", "confidence": "high"}]}'
    )
    ec.export_csv(str(exp), str(ds), str(out))
    with open(out, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows, "no rows exported"
    assert rows[0]["stage2_verdict"] == "VULNERABLE", f"blank/wrong stage2_verdict: {rows[0]['stage2_verdict']!r}"
    assert rows[0]["stage1_verdict"] == "VULNERABLE", f"blank/wrong stage1_verdict: {rows[0]['stage1_verdict']!r}"
