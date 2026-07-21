"""FAM-ROBUST (fa16 siblings): unguarded iteration over model-supplied `results`.

fa15 guarded `core/reporter.py`, but four sibling emitters iterate the SAME
model-supplied `experiment["results"]` list and call `result.get(...)` on each
element with NO `isinstance(result, dict)` guard. A non-Anthropic model can emit
a bare string / number where a result dict is expected; the first `.get()` then
raises `AttributeError: 'str' object has no attribute 'get'` and aborts the
report / CSV.

Sites:
  * generate_report.prepare_findings_summary  (generate_report.py:150)
  * generate_report.generate_html_report      (generate_report.py:306)
  * export_csv.export_csv                      (export_csv.py:138)
  * openant.cli.cmd_report_data               (cli.py:682) — the LIVE report-data path

The `cmd_report_data` case is driven end-to-end through the real CLI entrypoint
(`cli.cmd_report_data(args)`) reading on-disk results/dataset JSON. The single
real finding is verdict ``safe`` so the post-loop remediation branch is
non-actionable and makes no LLM/network call — the test stays hermetic.
"""

from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

import report.html_report as generate_report
import report.csv_export as export_csv
from openant import cli


# One bare-string element (would crash `.get()`) + one real finding.
# The real finding is ``safe`` so cmd_report_data's remediation stays offline.
DIRTY_RESULTS = {
    "dataset": "fam-robust",
    "code_by_route": {},
    "metrics": {},
    "results": [
        "a bare string a non-Anthropic model emitted",  # non-dict -> would crash result.get()
        {
            "route_key": "app.py:foo",
            "unit_id": "app.py:foo",
            "verdict": "safe",
            "finding": "safe",
            "attack_vector": "",
            "reasoning": "r",
        },
    ],
}
DATASET = {"units": [{"id": "app.py:foo", "code": {"primary_code": "def foo(): pass"}, "llm_context": {}}]}


def test_prepare_findings_summary_skips_non_dict():
    """SITE generate_report.py:150."""
    findings = generate_report.prepare_findings_summary(DIRTY_RESULTS, DATASET)
    assert len(findings) == 1
    assert findings[0]["unit_id"] == "app.py:foo"


def test_generate_html_report_skips_non_dict(tmp_path: Path):
    """SITE generate_report.py:306."""
    out = tmp_path / "report.html"
    generate_report.generate_html_report(
        experiment=DIRTY_RESULTS,
        dataset=DATASET,
        remediation_html="",
        output_path=str(out),
    )
    assert out.exists()


def test_export_csv_skips_non_dict(tmp_path: Path):
    """SITE export_csv.py:138."""
    exp = tmp_path / "results.json"
    ds = tmp_path / "dataset.json"
    out = tmp_path / "out.csv"
    exp.write_text(json.dumps(DIRTY_RESULTS))
    ds.write_text(json.dumps(DATASET))
    export_csv.export_csv(str(exp), str(ds), str(out))
    assert out.exists()
    # header + exactly one data row (bare string skipped)
    lines = [ln for ln in out.read_text().splitlines() if ln.strip()]
    assert len(lines) == 2


def test_cli_report_data_skips_non_dict(tmp_path: Path):
    """SITE cli.py:682 — driven through the real cmd_report_data entrypoint."""
    exp = tmp_path / "results.json"
    ds = tmp_path / "dataset.json"
    exp.write_text(json.dumps(DIRTY_RESULTS))
    ds.write_text(json.dumps(DATASET))
    args = types.SimpleNamespace(results=str(exp), dataset=str(ds))
    rc = cli.cmd_report_data(args)
    # HEAD: the bare string crashes result.get() -> caught -> rc == 2.
    # Fixed: the non-dict is skipped -> the report builds -> rc == 0.
    assert rc == 0
