"""Regression tests for issue #283 — a Stage-2 disagreement whose corrected
verdict is STILL a real finding is silently dropped from disclosures.

The reducer mapped every completed ``agree=False`` to
``stage2_verdict="rejected"`` (in ``DISCLOSURE_DROPPED``) — so a
``vulnerable → bypassable`` reclassification was counted as a confirmed
vulnerability in the stats AND included in ``confirmed_findings``, yet
produced no ``DISCLOSURE_*.md``: the scan printed "N confirmed
vulnerabilities" while disclosing fewer. The exact "final verdict, not
the agree flag" rule the stats side already uses
(``verifier.py:321``, ``_write_verified_results``) was missing from the
reducer.

Contract locked here: when Stage 2 disagrees but its corrected verdict is
still ``vulnerable``/``bypassable``, the finding's ``stage2_verdict`` IS
the corrected verdict (disclosure-eligible — the honest label for Stage
2's authoritative reclassification). Only a corrected verdict that is
itself disclosure-dropped (safe/protected/inconclusive) maps to
``rejected``. A genuine disagreement to a non-finding is still rejected.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.reporter import build_pipeline_output  # noqa: E402
from core.verdict_taxonomy import (  # noqa: E402
    DISCLOSURE_ELIGIBLE, DISCLOSURE_DROPPED,
)
from utilities.file_io import write_json  # noqa: E402


def _run(tmp_path: Path, finding: dict) -> dict:
    results = {
        "dataset": "t",
        "code_by_route": {"a.py:f": "def f(): ..."},
        "metrics": {"total": 1, "errors": 0},
        "confirmed_findings": [finding],
        "results": [finding],
    }
    write_json(tmp_path / "results.json", results)
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"),
        output_path=str(out),
        language="python", repo_name="t/r", processing_level="reachable",
    )
    return json.loads(out.read_text())


VULN = {"name": "Auth bypass", "short_name": "authbypass",
        "description": "d", "impact": "i", "suggested_fix": "s",
        "steps_to_reproduce": "steps"}


def test_disagree_reclassified_bypassable_is_eligible(tmp_path):
    """The #283 repro: vulnerable → bypassable (agree=False, corrected
    finding still real). The stage2_verdict must be the corrected verdict
    (eligible), NOT 'rejected'."""
    f = {"route_key": "app/auth.py:login", "finding": "bypassable",
         "verdict": "vulnerable",
         "verification": {"agree": False, "incomplete": False},
         "vulnerability": VULN}
    out = _run(tmp_path, f)
    rec = out["findings"][0]
    assert rec["stage2_verdict"] == "bypassable", (
        f"Stage 2's authoritative reclassification must surface as the "
        f"stage2_verdict (got {rec['stage2_verdict']!r})"
    )
    assert rec["stage2_verdict"] in DISCLOSURE_ELIGIBLE
    assert rec["stage2_verdict"] not in DISCLOSURE_DROPPED


def test_disagree_reclassified_vulnerable_is_eligible(tmp_path):
    f = {"route_key": "a.py:g", "finding": "vulnerable",
         "verdict": "bypassable",
         "verification": {"agree": False, "incomplete": False},
         "vulnerability": VULN}
    out = _run(tmp_path, f)
    rec = out["findings"][0]
    assert rec["stage2_verdict"] == "vulnerable"
    assert rec["stage2_verdict"] in DISCLOSURE_ELIGIBLE


def test_disagree_to_safe_is_still_rejected(tmp_path):
    """A genuine disagreement to a non-finding is still rejected — the fix
    must not retain false positives."""
    f = {"route_key": "a.py:h", "finding": "safe",
         "verdict": "vulnerable",
         "verification": {"agree": False, "incomplete": False},
         "vulnerability": VULN}
    out = _run(tmp_path, f)
    rec = out["findings"][0]
    assert rec["stage2_verdict"] == "rejected"
    assert rec["stage2_verdict"] in DISCLOSURE_DROPPED


def test_disagree_to_protected_is_rejected(tmp_path):
    f = {"route_key": "a.py:i", "finding": "protected",
         "verdict": "vulnerable",
         "verification": {"agree": False, "incomplete": False},
         "vulnerability": VULN}
    out = _run(tmp_path, f)
    assert out["findings"][0]["stage2_verdict"] == "rejected"


def test_agree_and_incomplete_paths_unchanged(tmp_path):
    """Guard: the agree=True and incomplete paths must be untouched."""
    agreed = {"route_key": "a.py:j", "finding": "vulnerable",
              "verification": {"agree": True, "incomplete": False},
              "vulnerability": VULN}
    out = _run(tmp_path, agreed)
    # agree=True without exploit_path -> "agreed" (the existing mapping)
    assert out["findings"][0]["stage2_verdict"] == "agreed"

    incomplete = {"route_key": "a.py:k", "finding": "vulnerable",
                  "verification": {"agree": False, "incomplete": True},
                  "vulnerability": VULN}
    xdir = tmp_path / "x"
    xdir.mkdir()
    out2 = _run(xdir, incomplete)
    assert out2["findings"][0]["stage2_verdict"] == "unverified"


def test_disclosure_doc_emitted_and_header_honest(tmp_path, monkeypatch):
    """Wave catch (sonnet-2 MAJOR): prove a disclosure DOC is actually
    emitted for the reclassified finding, and its header says ADJUDICATED
    on the reclassification signal (not the false 'UNVERIFIED — not
    confirmed by Stage-2' the template previously stamped on a finding
    Stage 2 DID adjudicate)."""
    from report import generator as gen
    from utilities.llm.adapter import TextBlock

    f = {"route_key": "app/auth.py:login", "finding": "bypassable",
         "verdict": "vulnerable",
         "verification": {"agree": False, "incomplete": False},
         "vulnerability": dict(VULN, name="Auth bypass")}
    results = {
        "dataset": "t",
        "code_by_route": {"app/auth.py:login": "def login(): ..."},
        "metrics": {"total": 1, "vulnerable": 1, "errors": 0},
        "confirmed_findings": [f],
        "results": [f],
    }
    write_json(tmp_path / "results.json", results)
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"),
        output_path=str(out),
        language="python", repo_name="t/r", processing_level="reachable",
    )
    pipeline = json.loads(out.read_text())
    rec = pipeline["findings"][0]
    assert rec["stage2_verdict"] == "bypassable"

    class _Binding:
        model = "m"
        class adapter:
            name = "fake"
            supports_tools = True
            pricing = {"m": {"input": 1.0, "output": 2.0}}
            @staticmethod
            def complete(**kw):
                from utilities.llm.adapter import CompletionResult
                return CompletionResult(
                    content=(TextBlock("# disclosure body"),),
                    input_tokens=1, output_tokens=1, stop_reason="end_turn")

    text, _usage = gen.generate_disclosure(rec, "prod", _Binding())
    assert "ADJUDICATED by Stage-2" in text, (
        "the disclosure header must say ADJUDICATED for the "
        "vulnerable->bypassable reclassification"
    )


def test_header_branches_unchanged():
    """Guard: confirmed and unverified headers keep their existing wording;
    the ADJUDICATED branch fires ONLY on the reclassification signal
    (stage1 != stage2 both present); same-verdict or absent-stage1 shapes
    stay UNVERIFIED (conservative — they may not have been through
    Stage 2 at all)."""
    from report.generator import _disclosure_verdict_header
    hdr = _disclosure_verdict_header({"stage2_verdict": "unverified"})
    assert "UNVERIFIED" in hdr
    # reclassification signal: stage1 present and differs
    hdr2 = _disclosure_verdict_header(
        {"stage2_verdict": "bypassable", "stage1_verdict": "vulnerable"})
    assert "ADJUDICATED" in hdr2
    # same verdict / absent stage1: conservative UNVERIFIED (existing tests)
    hdr2b = _disclosure_verdict_header({"stage2_verdict": "bypassable"})
    assert "UNVERIFIED" in hdr2b
    hdr3 = _disclosure_verdict_header({"stage2_verdict": "confirmed"})
    assert "CONFIRMED" in hdr3
