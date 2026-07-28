"""
Integration test: ensure Suggested Tests block contains behavior-derived skeletons
when a behavior summary exists (mock LLM mode).
"""
from __future__ import annotations

import sys
from pathlib import Path


EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"


def test_pipeline_suggested_tests_include_behavior():
    from utilities.autopatcher.pipeline import run

    vuln_file = EXAMPLES_DIR / "vulnerability.md"
    report = run(vulnerability_text=vuln_file.read_text(encoding="utf-8"), api_key="")

    assert "## Suggested Tests" in report
    start = report.find("## Suggested Tests")
    assert start != -1
    after = report.find("## Confidence score", start)
    block = report[start:after if after != -1 else start + 1000]

    # Suggested Tests no longer inlines pytest skeleton code (presentation
    # shortening) — a behavior-derived suggestion is now identified by its
    # test name and reason instead of the removed "# Behavior-focused
    # validation" code-body marker.
    assert "Based on finding:" in block

    # At least one behavior-derived test name present
    assert "test_" in block
