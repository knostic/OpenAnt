"""#679: the off-enum/error rows are VISIBLE in the report-data output.

Driven end-to-end through the real `cli.cmd_report_data` entrypoint (the
fa16 hermetic convention): a non-actionable verdict set keeps the
remediation offline. Asserts the T1-F1 split — the visible group carries
BOTH the canonical `error` rows and the off-enum spellings, and the honest
remediation names both counts (the false-clean text suppressed).
"""
from __future__ import annotations

import json
import types
from pathlib import Path

from openant import cli


RESULTS = {
    "dataset": "issue-679",
    "code_by_route": {},
    "metrics": {},
    "results": [
        {
            "route_key": "a.py:ok", "unit_id": "a.py:ok",
            "verdict": "safe", "finding": "safe",
            "attack_vector": "", "reasoning": "r",
        },
        {
            "route_key": "b.py:boom", "unit_id": "b.py:boom",
            "verdict": "error", "finding": "error",   # the CANONICAL error (recognized)
            "attack_vector": "", "reasoning": "r",
        },
        {
            "route_key": "c.py:drift", "unit_id": "c.py:drift",
            "verdict": "Probably Fine", "finding": "Probably Fine",  # the OFF-ENUM
            "attack_vector": "", "reasoning": "r",
        },
    ],
}
DATASET = {"units": [
    {"id": u, "code": {"primary_code": "x = 1"}, "llm_context": {}}
    for u in ("a.py:ok", "b.py:boom", "c.py:drift")]}


def test_report_data_shows_error_and_off_enum(tmp_path: Path):
    exp = tmp_path / "results.json"
    ds = tmp_path / "dataset.json"
    exp.write_text(json.dumps(RESULTS))
    ds.write_text(json.dumps(DATASET))
    args = types.SimpleNamespace(results=str(exp), dataset=str(ds))
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.cmd_report_data(args)
    assert rc == 0
    # the payload prints as the success envelope (and lands on disk as
    # report-data.report.json); parse the stdout form
    data = json.loads(buf.getvalue())["data"]
    groups = {g["verdict"]: g for g in data.get("findings_by_verdict", [])}
    assert "error" in groups, "the visible error group must exist"
    files = [f.get("file") for f in groups["error"]["findings"]]
    assert "b.py" in files and "c.py" in files, (
        "BOTH the canonical error row and the off-enum row join the visible "
        "group (the T1 F1 split's call-site half — mutant C)")
    remediation = data.get("remediation_html", "")
    assert "unrecognized verdict" in remediation and "errored" in remediation, (
        "the honest message names both counts")
    assert "No vulnerabilities or security concerns found" not in remediation, (
        "the false-clean text is suppressed")
