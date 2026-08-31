"""#423: "deduplicated" is a true dedup delta — never negative.

`vulnerable` is re-derived from the DEDUPED findings list (#289), but
`vulnerable_before_dedup` came from the ANALYZE-stage metrics
(`metrics.vulnerable + metrics.bypassable`) — a DIFFERENT population. When Stage-2
adjudication retains/creates vulnerabilities Stage-1 detection did not flag (the live
run: detect classified 0 vulnerable; verify disagreed on 2 that stayed vulnerable per
the verifier taxonomy), the two populations diverge and the #289/#381 reconciliation
contract (before >= after) breaks — a live run emitted `"deduplicated": -2`, a count
that can never be explained as deduplication.

The fix derives `vulnerable_before_dedup` from the SAME population `vulnerable`
counts — the PRE-dedup confirmed findings list — so the delta is a true dedup delta:
Stage-2 reclassifications no longer produce negative "dedup", and a real caller/callee
collapse still reports the exact number dropped.
"""
import json
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

from core.reporter import build_pipeline_output  # noqa: E402
from utilities.file_io import write_json  # noqa: E402


def _run_build(tmp_path, results, call_graph=None):
    results_path = tmp_path / "results.json"
    write_json(results_path, results)
    if call_graph is not None:
        write_json(tmp_path / "call_graph.json", call_graph)
    out_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(results_path), output_path=str(out_path),
        language="python", repo_name="t/r", processing_level="reachable",
    )
    return json.loads(out_path.read_text())["results"]


def _vuln(route, cwe=79):
    return {"route_key": route, "finding": "vulnerable",
            "verdict": "VULNERABLE", "cwe_id": cwe}


def test_stage2_only_vulns_do_not_negative_dedup(tmp_path):
    """The live-run shape: analyze metrics say 0 vulnerable, Stage 2 retains
    2 — pristine emitted deduplicated=-2 (before < after). The two counters
    must describe ONE population: before=2, after=2, delta=0."""
    res = {
        "dataset": "t",
        "code_by_route": {"a.py:f": "def f(): pass", "a.py:g": "def g(): pass"},
        "metrics": {"total": 25, "errors": 0, "vulnerable": 0, "bypassable": 0,
                    "safe": 23, "protected": 0, "inconclusive": 0},
        "confirmed_findings": [_vuln("a.py:f"), _vuln("a.py:g")],
        "results": [],
    }
    out = _run_build(tmp_path, res)
    assert out["vulnerable"] == 2
    assert out["vulnerable_before_dedup"] == 2, (
        f"before={out['vulnerable_before_dedup']} is the ANALYZE-metrics "
        "population, not the same one `vulnerable` counts — the contract "
        "before >= after broke on the live run"
    )
    assert out["deduplicated"] == 0, (
        f"deduplicated={out['deduplicated']} — a negative dedup count can "
        "never be explained as deduplication"
    )


def test_real_dedup_reports_the_true_delta(tmp_path):
    """A genuine caller/callee collapse (same CWE, callee reachable only via
    the caller): before=2, after=1, deduplicated=1 — from ONE population."""
    caller, callee = _vuln("a.py:run"), _vuln("a.py:query")
    res = {
        "dataset": "t",
        "code_by_route": {"a.py:run": "r", "a.py:query": "q"},
        "metrics": {"total": 10, "errors": 0, "vulnerable": 2, "bypassable": 0,
                    "safe": 8, "protected": 0, "inconclusive": 0},
        "confirmed_findings": [caller, callee],
        "results": [],
    }
    cg = {
        "call_graph": {"a.py:run": ["a.py:query"]},
        "reverse_call_graph": {"a.py:query": ["a.py:run"]},
    }
    out = _run_build(tmp_path, res, cg)
    assert out["vulnerable"] == 1, out
    assert out["vulnerable_before_dedup"] == 2
    assert out["deduplicated"] == 1


def test_manual_filter_path_same_population(tmp_path):
    """No confirmed_findings key: the manual final-verdict filter feeds the
    dedup — the same-population rule must hold on this path too."""
    res = {
        "dataset": "t",
        "code_by_route": {"a.py:f": "r"},
        "metrics": {"total": 3, "errors": 0, "vulnerable": 1, "bypassable": 0,
                    "safe": 2, "protected": 0, "inconclusive": 0},
        "results": [{"route_key": "a.py:f", "finding": "vulnerable",
                     "verdict": "VULNERABLE", "cwe_id": 79},
                    {"route_key": "a.py:s", "finding": "safe",
                     "verdict": "SAFE"}],
    }
    out = _run_build(tmp_path, res)
    assert out["vulnerable"] == 1
    assert out["vulnerable_before_dedup"] == 1
    assert out["deduplicated"] == 0
