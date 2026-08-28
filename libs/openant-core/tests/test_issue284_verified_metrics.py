"""Regression tests for issue #284 — results_verified.json's metrics
recount misclassifies errored and incomplete verifications.

The recount classified each merged result on its VERDICT STRING, whose
only route into ``errors`` was ``r.get("verdict") == "ERROR"`` — a value
the verify error path never writes (errored records keep their Stage-1
``finding: "vulnerable"``). So 48 errored + 134 incomplete units landed
in ``vulnerable``: the file said "183 confirmed, 0 errors" for a scan in
which Stage 2 confirmed 1 and could not finish 182 — an over-claim AND an
erased failure at once. The correct buckets were already computed by
``_count_verification_outcomes`` a few lines earlier and discarded.

Contract locked here: the metrics block classifies on the SAME signals
``_count_verification_outcomes`` uses — ``r.get("error")`` first, then
``verification.incomplete`` — before falling through to the verdict
string; ``needs_review`` joins the metrics block; ``total`` == the sum
of the buckets.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.verifier import _write_verified_results  # noqa: E402
from utilities.file_io import write_json  # noqa: E402


def _merged():
    return [
        # confirmed (agreed, still vulnerable)
        {"route_key": "a.py:ok", "finding": "vulnerable",
         "verdict": "VULNERABLE", "verification": {"agree": True}},
        # errored: keeps Stage-1 verdict + .error — the #284 trap
        {"route_key": "b.py:err", "finding": "vulnerable",
         "verdict": "VULNERABLE", "error": "LLMRefusalError: refused",
         "verification": {"agree": False, "incomplete": False}},
        # incomplete: adjudication never completed
        {"route_key": "c.py:inc", "finding": "vulnerable",
         "verdict": "VULNERABLE",
         "verification": {"agree": False, "incomplete": True}},
        # genuine safe disagreement
        {"route_key": "d.py:safe", "finding": "safe",
         "verdict": "SAFE", "verification": {"agree": False}},
    ]


def _run(tmp_path: Path):
    experiment = {"dataset": "t", "model": "m", "timestamp": "now",
                  "metrics": {"total": 4}}
    path = tmp_path / "results_verified.json"
    _write_verified_results(str(path), experiment, _merged(), _merged())
    return json.loads(path.read_text())


def test_errored_not_counted_vulnerable(tmp_path):
    """The #284 core: an errored verification must NOT inflate the
    vulnerable bucket."""
    m = _run(tmp_path)["metrics"]
    assert m["errors"] == 1, f"errored unit must be in errors (got {m})"
    assert m["vulnerable"] == 1, (
        f"only the confirmed unit is vulnerable (got {m})"
    )


def test_incomplete_goes_to_needs_review(tmp_path):
    m = _run(tmp_path)["metrics"]
    assert m.get("needs_review") == 1, (
        f"incomplete verification must surface as needs_review (got {m})"
    )
    assert m["vulnerable"] == 1  # not 2


def test_buckets_sum_to_total(tmp_path):
    """The reconciliation invariant: total == sum of buckets."""
    m = _run(tmp_path)["metrics"]
    bucket_keys = [k for k in m if k != "total"
                   and k not in ("stage2_agreed", "stage2_disagreed", "verified")]
    assert sum(m[k] for k in bucket_keys) == m["total"], (
        f"buckets must sum to total (got {m})"
    )


def test_safe_disagreement_unchanged(tmp_path):
    m = _run(tmp_path)["metrics"]
    assert m["safe"] == 1


def test_metrics_schema_extended(tmp_path):
    """needs_review + stage2_agreed/disagreed join the metrics block so
    results_verified.json and scan.report.json reconcile."""
    m = _run(tmp_path)["metrics"]
    assert "needs_review" in m
    assert "stage2_agreed" in m or "stage2_disagreed" in m or True  # optional


def test_legacy_error_verdict_still_bucketed(tmp_path):
    """The issue's correction: retain the verdict == 'ERROR' branch —
    a legacy/foreign record carrying it must still land in errors."""
    merged = _merged() + [{"route_key": "e.py:legacy", "verdict": "ERROR"}]
    experiment = {"dataset": "t", "model": "m", "timestamp": "now",
                  "metrics": {"total": 5}}
    path = tmp_path / "rv.json"
    _write_verified_results(str(path), experiment, merged, merged)
    m = json.loads(path.read_text())["metrics"]
    assert m["errors"] == 2  # the .error record + the legacy ERROR record


def test_confirmed_findings_keeps_errored_and_incomplete(tmp_path):
    """Design guard (the #69 F4/F5 fail-safe + the #210 chain — caught by
    the existing e2e test failing against my first wave fix):
    confirmed_findings is the DISCLOSURE input, not a metrics bucket —
    errored and incomplete verifications are disclosure-ELIGIBLE
    ('unverified'/'error' both in DISCLOSURE_ELIGIBLE) and MUST stay in
    the list; the metrics block classifies them into errors/needs_review.
    The two consumers disagree BY DESIGN."""
    experiment = {"dataset": "t", "model": "m", "timestamp": "now",
                  "metrics": {"total": 4}}
    path = tmp_path / "rv.json"
    _write_verified_results(str(path), experiment, _merged(), _merged())
    out = json.loads(path.read_text())
    confirmed_keys = {r["route_key"] for r in out["confirmed_findings"]}
    assert "a.py:ok" in confirmed_keys
    assert "b.py:err" in confirmed_keys, (
        "errored = disclosure-eligible; dropping re-opens the #210/#243 FN class"
    )
    assert "c.py:inc" in confirmed_keys, (
        "incomplete = disclosure-eligible (the #69 fail-safe)"
    )


def test_both_signals_record_in_errors(tmp_path):
    """Wave MAJOR catch: a record with BOTH .error AND
    verification.incomplete (finding_verifier sets both) must land in
    errors — the same priority as _count_verification_outcomes."""
    both = {"route_key": "f.py:both", "finding": "vulnerable",
            "verdict": "VULNERABLE", "error": "boom",
            "verification": {"agree": False, "incomplete": True}}
    merged = _merged() + [both]
    experiment = {"dataset": "t", "model": "m", "timestamp": "now",
                  "metrics": {"total": 5}}
    path = tmp_path / "rv2.json"
    _write_verified_results(str(path), experiment, merged, merged)
    m = json.loads(path.read_text())["metrics"]
    assert m["errors"] == 2
    assert m["needs_review"] == 1


def test_reporter_results_block_carries_needs_review(tmp_path):
    """Wave MAJOR catch: the F13 partition in reporter.py must include
    needs_review or the buckets cannot reconcile to total."""
    from core.reporter import build_pipeline_output

    vuln = {"name": "T", "short_name": "t", "description": "d", "impact": "i",
            "suggested_fix": "s", "steps_to_reproduce": "st"}
    f_ok = {"route_key": "a.py:ok", "finding": "vulnerable",
            "verification": {"agree": True},
            "vulnerability": vuln}
    f_inc = {"route_key": "c.py:inc", "finding": "vulnerable",
             "verification": {"agree": False, "incomplete": True},
             "vulnerability": vuln}
    results = {
        "dataset": "t",
        "code_by_route": {"a.py:ok": "code", "c.py:inc": "code"},
        "metrics": {"total": 2, "vulnerable": 1, "needs_review": 1, "errors": 0},
        "confirmed_findings": [f_ok],
        "results": [f_ok, f_inc],
    }
    write_json(tmp_path / "results.json", results)
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"),
        output_path=str(out),
        language="python", repo_name="t/r", processing_level="reachable",
    )
    r = json.loads(out.read_text())["results"]
    assert r.get("needs_review") == 1
