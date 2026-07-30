"""Regression test for finding: report-verdict-count-findingless-vuln-dropped.

A result whose verdict lives only in the raw ``verdict`` field (no normalized
``finding`` key) must still be counted. The canonical verdict-read pattern used
elsewhere in the core (reporter.py, verifier.py, analyzer.py) is
``str(r.get("finding") or r.get("verdict", "")).lower()``. The report paths
previously read only ``result.get("finding", "")``, so a finding-less
vulnerable result was silently dropped from the verdict count -> under-reports.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import report.html_report as generate_report  # noqa: E402


def test_findingless_vulnerable_counted_in_html_report(tmp_path):
    # Result carries only the raw uppercase ``verdict`` field, no ``finding``.
    experiment = {"results": [{"route_key": "app/x.py:foo", "verdict": "VULNERABLE"}]}
    dataset = {"units": []}
    out = tmp_path / "report.html"

    generate_report.generate_html_report(experiment, dataset, "", str(out))
    html_text = out.read_text(encoding="utf-8")

    m = re.search(r'#dc3545">(\d+)</div>\s*<div class="stat-label">Vulnerable', html_text)
    assert m, "Vulnerable stat card not found in rendered report"
    assert m.group(1) == "1", f"expected Vulnerable count 1, got {m.group(1)}"


def test_findingless_vulnerable_counted_in_findings_summary():
    experiment = {"results": [{"route_key": "app/x.py:foo", "verdict": "VULNERABLE"}]}
    dataset = {"units": []}

    findings = generate_report.prepare_findings_summary(experiment, dataset)
    assert findings[0]["verdict"] == "vulnerable", findings[0]["verdict"]
