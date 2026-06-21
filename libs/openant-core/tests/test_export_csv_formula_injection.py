"""Regression tests for CSV / formula injection in export_csv (CWE-1236).

export_csv() writes the verbatim scanned source (unit_code = primary_code) and LLM text columns into the CSV
with no neutralization. A scanned snippet beginning with =, +, -, @ (or a leading tab / CR) is interpreted as a
formula by Excel / Google Sheets when the analyst opens the file, enabling formula execution / data exfiltration
on the analyst's machine. Fix: prefix any cell whose first character is a formula trigger with a single quote
(the OWASP CSV-Injection defense), applied to every cell.
"""
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

import export_csv as ec  # noqa: E402

PAYLOAD = "=cmd|'/c calc'!A1"


def test__csv_safe_neutralizes_formula_triggers():
    """Unit: cells starting with a formula trigger get a leading quote; safe cells are unchanged."""
    for trigger in ("=", "+", "-", "@", "\t", "\r"):
        assert ec._csv_safe(trigger + "x") == "'" + trigger + "x", f"{trigger!r} not neutralized"
    assert ec._csv_safe("safe value") == "safe value"
    assert ec._csv_safe("") == ""
    assert ec._csv_safe(None) == ""


def test_export_csv_neutralizes_formula_in_unit_code(tmp_path):
    """Integration: a scanned snippet that is a spreadsheet formula is neutralized in the exported CSV."""
    ds = tmp_path / "dataset.json"
    exp = tmp_path / "experiment.json"
    out = tmp_path / "out.csv"
    ds.write_text(
        '{"units": [{"id": "f.py:foo", "code": {"primary_code": "' + PAYLOAD + '"},'
        ' "llm_context": {"reasoning": "r", "security_classification": "c"}}]}'
    )
    exp.write_text(
        '{"results": [{"route_key": "f.py:foo", "verification": {"explanation": "e"},'
        ' "finding": "vulnerable", "reasoning": "r1", "confidence": "high"}]}'
    )
    ec.export_csv(str(exp), str(ds), str(out))
    with open(out, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows, "no rows exported"
    cell = rows[0]["unit_code"]
    assert not cell.startswith(("=", "+", "-", "@")), f"formula cell not neutralized: {cell!r}"
    assert cell == "'" + PAYLOAD, f"expected leading-quote neutralization, got {cell!r}"
