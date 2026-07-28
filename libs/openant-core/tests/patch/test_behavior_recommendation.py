"""
Pipeline-level test: ensure Recommendation reason includes behavior mention
when behavior summary exists (mock mode).
"""
from __future__ import annotations

import sys
from pathlib import Path


EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"


def test_recommendation_includes_behavior_phrase():
    from utilities.autopatcher.pipeline import run

    vuln_file = EXAMPLES_DIR / "vulnerability.md"
    report = run(vulnerability_text=vuln_file.read_text(encoding="utf-8"), api_key="")

    assert "## Recommendation" in report
    start = report.find("## Recommendation")
    assert start != -1
    block = report[start:]

    # Should include the word 'affects' from the appended phrase
    assert "affects" in block

    # And include either the function name or file name from behavior
    assert ("authenticate" in block) or ("app/auth.py" in block)
