"""Regression: a verdict-only Stage-1 result must not be downgraded to 'inconclusive'.

Bug (finding_verifier.py :654 and :713): ``result.get("finding", "inconclusive")``
defaulted a findingless verdict-only result (``{"verdict": "vulnerable"}``) to
'inconclusive' instead of reading the raw ``verdict`` -> a real VULNERABLE was
misclassified as inconclusive and dropped from the report.
"""
from __future__ import annotations

from utilities.finding_verifier import _resolve_stage1_finding


def test_verdict_only_vulnerable_reads_raw_verdict():
    # No 'finding' key, only a raw 'verdict' -> must resolve to 'vulnerable'.
    assert _resolve_stage1_finding({"verdict": "vulnerable"}) == "vulnerable"


def test_finding_key_still_wins():
    assert _resolve_stage1_finding({"finding": "safe", "verdict": "vulnerable"}) == "safe"


def test_both_absent_defaults_inconclusive():
    assert _resolve_stage1_finding({}) == "inconclusive"


def test_uppercase_verdict_normalized():
    assert _resolve_stage1_finding({"verdict": "VULNERABLE"}) == "vulnerable"
