"""
Test that Validation Actions includes a behavior-derived validation action
when a behavior summary is present (mock LLM mode).

Note: this used to check a separate "Validation Plan" section further down
the report. That section was removed as a terminology/navigation cleanup —
it repeated the same (already capped-at-3) items shown in "Validation
Actions" near the top, with only a "Reason:" line added; "Validation
Actions" now includes Reason too, so nothing unique was lost.
"""
from __future__ import annotations

import sys
from pathlib import Path


EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"


def test_validation_plan_includes_behavior():
    from utilities.autopatcher.pipeline import run

    vuln_file = EXAMPLES_DIR / "vulnerability.md"
    report = run(vulnerability_text=vuln_file.read_text(encoding="utf-8"), api_key="")

    assert "## Validation Actions" in report
    start = report.find("## Validation Actions")
    assert start != -1
    # Patch Hygiene now precedes Validation Actions (promoted next to the
    # diff) — Review Results is the next heading that follows it.
    after = report.find("## Review Results", start)
    block = report[start:after if after != -1 else start + 800]

    # Expect the behavior-driven validation action to be present
    assert "Validate behavior" in block

    # Behavior summary sentence should be present (BehaviorAnalyzer uses
    # "This patch likely affects ...") — now carried via the Reason field.
    assert "This patch likely affects" in block

    # At least one primary behavior item should appear (non-brittle check)
    assert any(x in block for x in ("valid login", "invalid login", "valid input acceptance", "query correctness", "happy-path response"))
