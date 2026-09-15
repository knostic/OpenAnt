"""Regression tests for issue #215 (partial repair — dropped-in-transit fields).

#215's headline (76 of 82 findings with ``cwe_id: 0``, no severity field)
needs schema-constrained prompts + a new severity field — deferred on the
issue as beyond a fixes-only campaign. The maintainer comment's
repair-shaped sub-finding is in scope: per-unit fields populated upstream
and surviving into ``results_verified.json`` were DROPPED by
``build_pipeline_output``'s fixed 14-key finding record.

Contract locked here: the finding record carries the two FINDING-SEMANTIC
transit fields — ``confidence`` (triage weight) and ``json_corrected``
(provenance: this finding's JSON was model-repaired). ``elapsed_seconds``
and ``prompt_length`` stay OUT (per-unit step telemetry, not finding
metadata — surface-growth dressed as repair).
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


def _run(tmp_path: Path, finding_extra: dict | None = None) -> dict:
    finding = {
        "finding": "vulnerable",
        "verdict": "vulnerable",
        "confidence": 0.9,
        "json_corrected": True,
        "cwe_id": 79,
        "cwe_name": "XSS",
        "description": "d",
        "reasoning": "r",
        "vulnerabilities": [{"name": "XSS", "short_name": "XSS",
                             "description": "d", "impact": "i",
                             "suggested_fix": "s",
                             "steps_to_reproduce": "steps"}],
    }
    if finding_extra:
        finding.update(finding_extra)
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


def test_finding_record_carries_confidence(tmp_path: Path):
    """confidence is finding-semantic (triage weight) — must survive
    transit with its REAL upstream type (float 0.0-1.0 per the verdict
    schema, json_corrector.py:32 — never a hand-invented string)."""
    out = _run(tmp_path)
    rec = out["findings"][0]
    assert rec.get("confidence") == 0.9, (
        f"confidence populated upstream must reach the finding record "
        f"(got {rec.get('confidence')!r})"
    )
    assert isinstance(rec["confidence"], float)


def test_finding_record_carries_json_corrected(tmp_path: Path):
    """json_corrected is a provenance/trust signal — must survive transit."""
    out = _run(tmp_path)
    rec = out["findings"][0]
    assert rec.get("json_corrected") is True


def test_absent_upstream_stays_absent_not_fabricated(tmp_path: Path):
    """Present-only threading: a unit whose record NEVER CARRIED the keys
    (absent — not None) must not get fabricated values."""
    import json as _json
    _run(tmp_path)  # writes results.json with default fixture
    rp = tmp_path / "results.json"
    data = _json.loads(rp.read_text())
    for f in data["confirmed_findings"]:
        f.pop("confidence", None)
        f.pop("json_corrected", None)
    for f in data.get("results", []):
        f.pop("confidence", None)
        f.pop("json_corrected", None)
    rp.write_text(_json.dumps(data))
    out2_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(rp), output_path=str(out2_path),
        language="python", repo_name="t/r", processing_level="reachable")
    rec = _json.loads(out2_path.read_text())["findings"][0]
    assert "confidence" not in rec, "key-absent upstream must stay key-absent"
    assert "json_corrected" not in rec


def test_falsy_present_values_thread_through(tmp_path: Path):
    """The is-not-None guard's actual purpose: a REAL falsy value (0.0
    confidence, False json_corrected) threads — only absence suppresses."""
    out = _run(tmp_path, finding_extra={"confidence": 0.0, "json_corrected": False})
    rec = out["findings"][0]
    assert rec.get("confidence") == 0.0
    assert rec.get("json_corrected") is False


def test_step_telemetry_stays_out_of_the_finding_record(tmp_path: Path):
    """elapsed_seconds/prompt_length are per-unit STEP telemetry, not
    finding metadata — deliberately NOT threaded (surface-growth)."""
    out = _run(tmp_path, finding_extra={"elapsed_seconds": 1.5, "prompt_length": 100})
    rec = out["findings"][0]
    assert "elapsed_seconds" not in rec
    assert "prompt_length" not in rec


def test_unverified_findings_path_threads_the_fields(tmp_path: Path):
    """The no-Stage-2 path (unverified findings, filtered from results
    rather than confirmed_findings) must thread the fields too."""
    import json as _json
    finding = {
        "route_key": "a.py:f", "finding": "vulnerable", "verdict": "vulnerable",
        "confidence": 0.75, "json_corrected": False, "cwe_id": 79,
        "description": "d", "reasoning": "r",
        "vulnerabilities": [{"name": "X", "short_name": "X", "description": "d",
                             "impact": "i", "suggested_fix": "s",
                             "steps_to_reproduce": "s"}],
    }
    results = {"dataset": "t", "code_by_route": {"a.py:f": "code"},
               "metrics": {"total": 1, "errors": 0},
               "results": [finding]}  # NO confirmed_findings -> filter path
    write_json(tmp_path / "results.json", results)
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(tmp_path / "results.json"), output_path=str(out),
        language="python", repo_name="t/r", processing_level="reachable")
    rec = _json.loads(out.read_text())["findings"][0]
    assert rec.get("confidence") == 0.75
    assert rec.get("json_corrected") is False
