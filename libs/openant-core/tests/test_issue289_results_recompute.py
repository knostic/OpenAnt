"""Regression tests for issue #289 — pipeline_output.json's `results`
block contradicts its own `findings` list.

Two defects:
(1) `results.vulnerable` was computed from `metrics` (the PRE-dedup
count), while `findings` was built from the POST-dedup list — the same
file reported `vulnerable: 183` alongside 175 entries in `findings` and
175 disclosure docs on disk, with no field explaining the difference.
(2) `protected` was folded into `safe` (lossy) even though the summary
template has a row for it.

Contract locked here:
- `results.vulnerable` == `len(findings)` (the deduped list), plus
  `vulnerable_before_dedup` and `deduplicated` counts;
- `protected` is its OWN key in `results`;
- the partition still reconciles to `total` (F13).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.reporter import build_pipeline_output  # noqa: E402
from utilities.file_io import write_json  # noqa: E402

VULN = {"name": "X", "short_name": "x", "description": "d", "impact": "i",
        "suggested_fix": "s", "steps_to_reproduce": "st"}


def _fixture():
    return [
        {"route_key": "a.py:caller", "finding": "vulnerable",
         "verdict": "VULNERABLE", "cwe_id": 79, "attack_vector": "v",
         "reasoning": "r",
         "vulnerability": dict(VULN, name="X"),
         "verification": {"agree": True, "exploit_path": {"entry": "e"}}},
        {"route_key": "a.py:callee", "finding": "vulnerable",
         "verdict": "VULNERABLE", "cwe_id": 79, "attack_vector": "v",
         "reasoning": "r",
         "vulnerability": dict(VULN, name="X"),
         "verification": {"agree": True, "exploit_path": {"entry": "e"}}},
        {"route_key": "b.py:other", "finding": "vulnerable",
         "verdict": "VULNERABLE", "cwe_id": 89, "attack_vector": "w",
         "reasoning": "r",
         "vulnerability": dict(VULN, name="Y"),
         "verification": {"agree": True, "exploit_path": {"entry": "e2"}}},
    ]


def _run(tmp_path: Path, findings=None):
    findings = findings if findings is not None else _fixture()
    results = {
        "dataset": "t",
        "code_by_route": {f["route_key"]: "code" for f in findings},
        "metrics": {"total": 5, "vulnerable": 3, "bypassable": 0,
                    "inconclusive": 0, "protected": 2, "safe": 0,
                    "errors": 0},
        "confirmed_findings": findings,
        "results": findings,
    }
    write_json(tmp_path / "results.json", results)
    # The dedup reads <results_dir>/call_graph.json; a.py:callee has exactly
    # one caller (a.py:caller) with the same CWE 79 → collapsed.
    write_json(tmp_path / "call_graph.json",
               {"reverse_call_graph": {"a.py:callee": ["a.py:caller"]}})
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"),
        output_path=str(out),
        language="python", repo_name="t/r", processing_level="reachable",
    )
    return json.loads(out.read_text())


def test_results_vulnerable_matches_deduped_findings(tmp_path):
    out = _run(tmp_path)
    assert out["results"]["vulnerable"] == len(out["findings"])


def test_dedup_counts_explicit(tmp_path):
    out = _run(tmp_path)
    r = out["results"]
    assert r["vulnerable_before_dedup"] == 3
    assert r["deduplicated"] == 1
    assert r["vulnerable"] == 2


def test_protected_own_key(tmp_path):
    out = _run(tmp_path)
    r = out["results"]
    assert r["protected"] == 2
    assert r["safe"] == 0


def test_partition_reconciles_to_total(tmp_path):
    """F13 (extended): all buckets sum to total — counting the dedup delta
    (a deduped unit was still vulnerable; it is reported once under its
    caller, so `deduplicated` is what keeps the unit-partition closed)."""
    out = _run(tmp_path)
    r = out["results"]
    buckets = ["vulnerable", "deduplicated", "safe", "protected",
               "inconclusive", "errors", "needs_review"]
    assert sum(r[k] for k in buckets) == r["total"]
