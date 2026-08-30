"""F13: the pipeline_output `results` block must reconcile to its own `total`.

`total` (== metrics["total"]) counts ALL units including errored ones — proven
in-code by `units_analyzed = total_units - metrics.get("errors", 0)` in
build_pipeline_output. Before the fix the `results` block emitted only
vulnerable/safe/inconclusive/total, so vulnerable+safe+inconclusive == total-errors,
i.e. the buckets silently under-summed `total` by the error count. The fix adds an
`errors` bucket so the partition closes.

#289 UPDATE: `vulnerable` is now re-derived from the DEDUPED findings list
(== len(findings)), NOT from metrics — the same file must never report 183 in
results.vulnerable alongside 175 entries in findings. Two consequences for
this contract:
- the unit-partition closes via the `deduplicated` delta (a deduped unit was
  still vulnerable — it is reported once under its caller), i.e.
  vulnerable + deduplicated + safe + protected + inconclusive + errors
  (+ needs_review) == total;
- `protected` is its OWN key (the lossy safe-fold is gone — the summary
  template has a Protected row and used to print 0 where metrics said 414).

SCOPE (honest): this reconciles the buckets GIVEN a well-formed `metrics` dict. It
does NOT repair an upstream mis-partition: `analyzer._count_verdicts` drops any row
whose verdict is unrecognized (neither a known bucket nor verdict=="ERROR") from
ALL buckets, so metrics built from such rows already have sum(buckets) < total. That
pre-existing gap is documented by `test_count_verdicts_drops_unrecognized_verdict`
below and is explicitly out of F13's scope.

#316/#324 UPDATE: the NEITHER-KEY shape (a result with no `verdict` and no
`finding`) is no longer dropped — `_normalize_result` stamps the one error
shape at the producer, and `_count_verdicts` routes the shape to `errors`
(the legacy singular-"error" default could never match the "errors" key).
Unrecognized VERDICT strings (e.g. "SOMETHING_WEIRD") and the mapped-but-
bucketless `insufficient_context` remain the documented gap above.
"""
import json
import sys
import tempfile
from pathlib import Path

import pytest

CORE = str(Path(__file__).resolve().parents[2])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

from core.reporter import build_pipeline_output  # noqa: E402
from core.analyzer import _count_verdicts  # noqa: E402


def _finding(route: str) -> dict:
    return {"route_key": route, "finding": "vulnerable",
            "verdict": "VULNERABLE", "cwe_id": 79, "attack_vector": "v",
            "reasoning": "r",
            "vulnerability": {"name": "X", "short_name": "x",
                              "description": "d", "impact": "i",
                              "suggested_fix": "s",
                              "steps_to_reproduce": "st"},
            "verification": {"agree": True}}


def _emit(metrics: dict, confirmed=None) -> dict:
    """Run the real builder on a crafted results fixture (no LLM, no scan)."""
    d = Path(tempfile.mkdtemp()).resolve()
    results_path = d / "results_verified.json"
    out_path = d / "pipeline_output.json"
    if confirmed is None:
        # coherent default: one listed finding per vulnerable/bypassable unit
        n = metrics.get("vulnerable", 0) + metrics.get("bypassable", 0)
        confirmed = [_finding(f"u{i}.py:f") for i in range(n)]
    results_path.write_text(json.dumps(
        {"metrics": metrics, "results": [], "confirmed_findings": confirmed}
    ))
    build_pipeline_output(str(results_path), str(out_path))
    return json.loads(out_path.read_text())["results"]


def test_results_block_reconciles_to_total_including_errors():
    # 2 vulnerable + 3 safe + 1 inconclusive + 4 errors == 10 total
    r = _emit({"vulnerable": 2, "safe": 3, "inconclusive": 1,
               "errors": 4, "total": 10})
    assert r["errors"] == 4, "errors bucket must be emitted (RED on pristine base)"
    assert r["vulnerable"] == 2, "2 listed findings → 2 vulnerable (#289)"
    assert (r["vulnerable"] + r["deduplicated"] + r["safe"]
            + r["protected"] + r["inconclusive"] + r["errors"]) == r["total"]


def test_protected_is_own_key_not_folded_into_safe():
    """#289: the lossy fold is gone — protected is emitted as its own key so
    the summary template's Protected row is fillable (it used to print 0
    where the metric blocks said 414/408)."""
    r = _emit({"vulnerable": 1, "bypassable": 1, "safe": 2, "protected": 1,
               "inconclusive": 1, "errors": 2, "total": 8})
    assert r["vulnerable"] == 2 and r["safe"] == 2 and r["protected"] == 1
    assert (r["vulnerable"] + r["deduplicated"] + r["safe"]
            + r["protected"] + r["inconclusive"] + r["errors"]) == r["total"]


@pytest.mark.parametrize("metrics,expected_errors", [
    ({"vulnerable": 2, "safe": 3, "inconclusive": 1, "total": 6}, 0),  # key absent
    ({"vulnerable": 2, "safe": 3, "inconclusive": 1, "errors": 0, "total": 6}, 0),
])
def test_graceful_when_no_errors(metrics, expected_errors):
    r = _emit(metrics)
    assert r["errors"] == expected_errors  # .get default, no crash, no double-count
    assert (r["vulnerable"] + r["deduplicated"] + r["safe"]
            + r["protected"] + r["inconclusive"] + r["errors"]) == r["total"]


def test_count_verdicts_drops_unrecognized_verdict():
    """DOCUMENTS the pre-existing partition gap F13 does NOT close: a row with an
    unrecognized verdict is dropped from every bucket, so the produced metrics
    already under-sum `total`. Kept as a red-flag guard: if a future change makes
    _count_verdicts total-preserving, update F13's scope note.

    #316/#324: the NEITHER-KEY shape is now partitioned into `errors` (see the
    scope note above); the unrecognized-VERDICT drop remains the gap."""
    rows = [
        {"finding": "vulnerable"},
        {"verdict": "ERROR"},
        {"verdict": "SOMETHING_WEIRD"},  # neither a bucket nor "ERROR" -> dropped
        {"reasoning": "no verdict keys"},  # neither-key -> counted as an error (#324)
    ]
    counts = _count_verdicts(rows)
    assert sum(counts.values()) == 3          # 3 of 4 rows partitioned
    assert sum(counts.values()) < len(rows)   # the unrecognized-verdict gap is real
