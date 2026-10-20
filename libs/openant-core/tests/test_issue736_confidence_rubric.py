"""#736 — Stage-1 ``confidence`` is a free 0-1 field with no rubric and
no decision consumer, yet it ships to the report record and the CSV as
``stage1_confidence``. Across the campaign's 213 Stage-2-verified
findings it barely separates agreed from refuted (AUC 0.569; agreed mean
0.713 vs refuted 0.686) — the number was presented as triage-meaningful
while measuring as noise.

THE RULING (the issue's shape (a) — the rubric — completed by its
read-side half, the #744 vocabulary-at-the-producer precedent):
  1. the PRODUCER half: the prompt's reply shape defines the number as
     the EVIDENCE-COMPLETENESS rubric — five bands (0.9+ the full chain
     traced in the analyzed code; 0.7-0.89 one named external assumption;
     0.5-0.69 plausible-but-partially-untraced; 0.3-0.49 a named
     suspicion; below 0.3 a guess), ORTHOGONAL to the finding (the
     finding says WHAT was concluded; the confidence says how much of it
     the analyzed code alone supports);
  2. the READ-SIDE half: the single normalization chokepoint every
     verdict dict passes through BOUNDS the field — a numeric value is
     clamped to [0.0, 1.0]; a NON-NUMERIC value (the free-form field's
     "high"/garbage class) reads as NO confidence (None — the reporter's
     present-only gate omits it; an unusable number presented as a triage
     signal is the exact #736 finding), with the raw preserved for manual
     review.

The issue's falsifier — "a rubric or a decision consumer at a future
HEAD, or a labeled corpus on which it discriminates (AUC >= 0.7)" — the
rubric is this PR; the corpus claim stays open (a rubriced field may
earn its consumer only by discriminating on a labeled corpus).

Shapes:
  S1 -- the WITNESS: the REAL rendered prompt carries the five bands +
        the axis name (assertion-red at base: the base prompt's
        confidence line is the bare "0.0-1.0").
  S2 -- the WITNESS: the REAL _normalize_result clamps (1.5 -> 1.0,
        -0.3 -> 0.0), coerces (1 -> 1.0), passes (0.75 unchanged), and
        nulls the non-numeric class ("high" -> None + raw preserved) —
        assertion-red at base (the verbatim flow).
  S3 -- the #215 regression guard: the reporter's record carries the
        clamped float, and a None confidence gains NO key (the
        present-only contract unchanged).
  S4 -- the CSV surface: a clamped value reaches stage1_confidence
        clamped; a None value's cell reads absent/empty (never a raw
        "high").
  S5 -- the parse-ERROR shape's confidence: 0 (the existing default,
        untouched — the error row is not a finding).
  S6 -- the NON-FINITE class: NaN/Infinity/giant-int read as NO
        confidence with the raw preserved and the verdict NEVER lost
        (the T1-r1 NaN-to-1.0 fabrication catch + the T1-r2 F8
        giant-int OverflowError catch; the bool class pinned here too).
  S7 -- the ContextCorrector TWIN mirrors the bound (the
        #316/#324/#427/#215 parity contract; every class incl. the
        giant int).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# S1 — the producer half: the REAL rendered prompt carries the rubric
# ---------------------------------------------------------------------------
def test_the_prompt_defines_the_rubric():
    """The #744 vocabulary-at-the-producer precedent applied to the
    confidence field: the reply shape's confidence line names the axis
    (evidence completeness) and the five bands — the base's bare
    '0.0-1.0' made the number free-form, exactly the #736 mechanism."""
    from prompts.vulnerability_analysis import get_analysis_prompt

    prompt = get_analysis_prompt(code="def f(): pass", language="python",
                                  app_context=None)
    assert "EVIDENCE-COMPLETENESS rubric" in prompt, (
        "the prompt's confidence line does not name the rubric's axis")
    for band in ("0.9-1.0", "0.7-0.89", "0.5-0.69", "0.3-0.49"):
        assert band in prompt, f"the rubric band {band} is missing"
    assert "below 0.3" in prompt
    assert "ORTHOGONAL to the finding" in prompt, (
        "the rubric must name its independence from the finding verdict")
    # the base's bare shape is GONE (the free float replaced by the
    # definition — the line's prefix keeps the range token for the
    # model's format, but never as a bare undefined field)
    assert '"confidence": 0.0-1.0,' not in prompt


# ---------------------------------------------------------------------------
# S2 — the read-side half: the REAL normalization bounds the field
# ---------------------------------------------------------------------------
def _norm(conf):
    """Drive the REAL _normalize_result with a minimal viable verdict."""
    from core.analysis_core import _normalize_result
    row = {"verdict": "VULNERABLE", "reasoning": "r", "confidence": conf}
    return _normalize_result(row)


def test_numeric_confidence_clamps_to_the_range():
    # the prod-hunk symbol: the bound lives in the REAL _normalize_result
    from core.analysis_core import _normalize_result as _real_norm
    out = _real_norm({"verdict": "VULNERABLE", "reasoning": "r",
                      "confidence": 1.5})
    assert out["confidence"] == 1.0, out
    out = _norm(-0.3)
    assert out["confidence"] == 0.0, out
    out = _norm(2)
    assert out["confidence"] == 1.0, out


def test_in_range_confidence_passes_and_int_coerces():
    out = _norm(0.75)
    assert out["confidence"] == 0.75, out
    out = _norm(1)
    assert out["confidence"] == 1.0 and isinstance(out["confidence"], float), out


def test_non_numeric_confidence_reads_as_none_with_raw_preserved():
    # the prod-hunk symbol: the bound lives in the REAL _normalize_result
    from core.analysis_core import _normalize_result as _real_norm
    out = _real_norm({"verdict": "VULNERABLE", "reasoning": "r",
                      "confidence": "high"})
    assert out["confidence"] is None, (
        f"a non-numeric confidence shipped as a triage signal: {out!r}")
    assert out.get("raw_confidence") == "high", (
        f"the raw value must be preserved for manual review: {out!r}")
    out = _norm({"score": 9})
    assert out["confidence"] is None
    assert out.get("raw_confidence") == {"score": 9}
    # absent stays absent (never fabricated)
    from core.analysis_core import _normalize_result
    row = {"verdict": "SAFE", "reasoning": "r"}
    out = _normalize_result(row)
    assert "confidence" not in out, (
        f"an absent confidence was fabricated: {out!r}")


def test_bool_confidence_reads_as_none():
    out = _norm(True)
    assert out["confidence"] is None, (
        f"a bool read as a confidence (True == 1.0's twin): {out!r}")
    assert out.get("raw_confidence") is True
    out = _norm(False)
    assert out["confidence"] is None


# ---------------------------------------------------------------------------
# S3/S4 — the emitted surfaces (the #215 contract)
# ---------------------------------------------------------------------------
def _verified_row(raw_conf, agree=False):
    """A minimal results_verified.json row the reporter/CSV accept — the
    confidence BOUND AT THE NORMALIZATION CHOKEPOINT (the pipeline-real
    shape: the model's raw value flows through the REAL
    _normalize_result, exactly as a live run's does), so the emitted
    surfaces are tested on the value production actually delivers."""
    from core.analysis_core import _normalize_result
    row = _normalize_result({
        "verdict": "VULNERABLE", "reasoning": "r",
        "confidence": raw_conf,
        "severity": "high", "cwe_id": 79, "cwe_name": "XSS",
    })
    row.update({
        "id": "a.go:f", "route_key": "a.go:f", "finding": "vulnerable",
        "verification": {"agree": agree, "explanation": "x",
                         "correct_finding": "safe" if not agree else "vulnerable"},
    })
    return row


def test_reporter_carries_the_clamped_float_present_only():
    from core.reporter import build_pipeline_output
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        results = Path(d) / "results_verified.json"
        results.write_text(json.dumps({
            "dataset": "", "model": "", "timestamp": "",
            "verify": True, "results": [_verified_row(1.5, agree=True)],
            "code_by_route": {},
        }))
        out = Path(d) / "pipeline.json"
        built_path, _n = build_pipeline_output(
            results_path=str(results), output_path=str(out),
            repo_name="r", repo_url="", commit_sha="", language="go",
            application_type="unknown", processing_level="reachable",
            step_reports=[])
        doc = json.loads(Path(built_path).read_text())
        recs = doc.get("findings", [])
        assert recs, f"the reporter emitted no findings records: {doc!r}"
        rec = recs[0]
        assert rec.get("confidence") == 1.0, (
            f"the clamped value did not reach the report record: {rec!r}")
        # the None class gains NO key (the #215 present-only contract)
        results.write_text(json.dumps({
            "dataset": "", "model": "", "timestamp": "",
            "verify": True,
            "results": [_verified_row("high", agree=True)],
            "code_by_route": {},
        }))
        built2_path, _n2 = build_pipeline_output(
            results_path=str(results), output_path=str(out),
            repo_name="r", repo_url="", commit_sha="", language="go",
            application_type="unknown", processing_level="reachable",
            step_reports=[])
        doc2 = json.loads(Path(built2_path).read_text())
        assert doc2.get("findings"), f"the None-class row never reached the findings: {doc2!r}"
        assert "confidence" not in doc2["findings"][0], (
            f"a None confidence gained a key: {doc2['findings'][0]!r}")


def test_csv_cell_reads_clamped_or_absent():
    """The CSV surface: stage1_confidence carries the clamped float; the
    non-numeric class's cell is EMPTY (never a raw 'high' in a CSV cell
    a triage sort might parse)."""
    import csv as _csv
    import tempfile
    from report.csv_export import export_csv
    with tempfile.TemporaryDirectory() as d:
        results = Path(d) / "results_verified.json"
        results.write_text(json.dumps({
            "dataset": "", "model": "", "timestamp": "",
            "verify": True,
            "results": [_verified_row(1.5), _verified_row("high", agree=True)],
            "code_by_route": {},
        }))
        dataset = Path(d) / "dataset.json"
        dataset.write_text(json.dumps({"units": []}))
        out_csv = Path(d) / "out.csv"
        export_csv(str(results), str(dataset), str(out_csv))
        with open(out_csv, newline="") as fh:
            rows = list(_csv.DictReader(fh))
        assert len(rows) == 2, f"the CSV lost rows: {len(rows)}"
        by_conf = {r["stage1_confidence"]: r for r in rows}
        assert "1.0" in by_conf, (
            f"the clamped value did not reach the CSV: {list(by_conf)!r}")
        assert "high" not in by_conf, (
            f"a raw non-numeric value sits in the CSV cell: {list(by_conf)!r}")


# ---------------------------------------------------------------------------
# S5 — the parse-ERROR shape's default (untouched)
# ---------------------------------------------------------------------------
def test_the_parse_error_shape_keeps_its_zero_default():
    from core.analysis_core import _normalize_result
    row = {"verdict": "ERROR", "confidence": 0, "reasoning": "parse failed"}
    out = _normalize_result(row)
    assert out["confidence"] == 0, (
        f"the ERROR shape's zero default changed: {out!r}")


# ---------------------------------------------------------------------------
# S6 — the T1-r1 F1 catch: the NON-FINITE class (NaN/Infinity) is the
# no-confidence branch, never a fabricated 1.0 — Python's comparisons are
# False against NaN, so min(1.0, nan) returns 1.0 and the naive clamp
# would have fabricated the MAXIMUM confidence from json.loads' accepted
# bare-NaN token
# ---------------------------------------------------------------------------
def test_non_finite_confidence_reads_as_none_with_raw_preserved():
    from core.analysis_core import _normalize_result as _real_norm
    import math
    for bad in (float("nan"), float("inf"), float("-inf")):
        out = _real_norm({"verdict": "VULNERABLE", "reasoning": "r",
                          "confidence": bad})
        assert out["confidence"] is None, (
            f"a non-finite confidence shipped as {out['confidence']!r} "
            f"(the fabricated-1.0 class): {out!r}")
        assert out.get("raw_confidence") is bad or (
            isinstance(out.get("raw_confidence"), float)
            and math.isnan(out["raw_confidence"])
            and math.isnan(bad)), (
            f"the raw non-finite value must be preserved: {out!r}")
    # the full parse path (json.loads accepts the bare NaN token)
    from core.analysis_core import parse_response
    out = parse_response(
        '{"finding": "vulnerable", "reasoning": "r", "confidence": NaN}')
    assert out["confidence"] is None, (
        f"the json.loads NaN path shipped {out['confidence']!r}")
    # the T1-r2 F8 falsifier: a >=309-digit bare int (json.loads' int
    # class) overflows the float conversion inside isfinite — the naive
    # guard raised OverflowError, the analyze loop caught it as a
    # NON-RETRYABLE error, and the unit's verdict was LOST
    giant = "9" * 401
    out = parse_response(
        '{"finding": "vulnerable", "reasoning": "r", '
        f'"confidence": {giant}}}')
    assert out["confidence"] is None, (
        f"the giant-int path shipped {out['confidence']!r}")
    assert out.get("raw_confidence") == int(giant), (
        f"the giant raw must be preserved: {out!r}")
    assert out["verdict"] == "VULNERABLE", (
        f"the giant-int path must never lose the verdict: {out!r}")


def test_the_twin_mirrors_the_bound():
    """The ContextCorrector twin's parity contract (#316/#324/#427/#215
    all mirrored): the #736 bound applies there too — an opt-in harness
    path, but its output feeds export_csv's any-JSON reader."""
    from utilities.context_corrector import ContextCorrector
    out = ContextCorrector._normalize_result({
        "verdict": "VULNERABLE", "reasoning": "r", "confidence": "high"})
    assert out["confidence"] is None and out.get("raw_confidence") == "high"
    out = ContextCorrector._normalize_result({
        "verdict": "VULNERABLE", "reasoning": "r", "confidence": 1.5})
    assert out["confidence"] == 1.0
    out = ContextCorrector._normalize_result({
        "verdict": "VULNERABLE", "reasoning": "r",
        "confidence": float("nan")})
    assert out["confidence"] is None
    row = {"verdict": "SAFE", "reasoning": "r"}
    out = ContextCorrector._normalize_result(row)
    assert "confidence" not in out
    # the T1-r3 catch: the twin's F8 mirror unasserted — the giant int
    # must route to no-confidence WITHOUT raising (the pre-remediation
    # twin raised OverflowError on the same input), and the bool class
    out = ContextCorrector._normalize_result({
        "verdict": "VULNERABLE", "reasoning": "r",
        "confidence": int("9" * 401)})
    assert out["confidence"] is None and out["verdict"] == "VULNERABLE", (
        f"the twin's giant-int path lost the verdict or shipped a "
        f"confidence: {out!r}")
    assert out.get("raw_confidence") == int("9" * 401)
    out = ContextCorrector._normalize_result({
        "verdict": "VULNERABLE", "reasoning": "r", "confidence": True})
    assert out["confidence"] is None and out.get("raw_confidence") is True


# ---------------------------------------------------------------------------
# S8 — the csv docstring pin (the scan-floor demand): the emitted surface's
# DOCUMENTATION names the rubric — a prose hunk, but the no-repo floor
# demands its removal be detected
# ---------------------------------------------------------------------------
def test_the_csv_docstring_names_the_rubric():
    """The stage1_confidence column's documentation restates the rubric —
    the consumer reading the CSV column reads the definition (the issue's
    'presented as triage-meaningful' half: the presentation now says
    WHAT the number means)."""
    from report import csv_export
    doc = csv_export.__doc__ or ""
    assert "evidence-completeness rubric" in doc.lower(), (
        "the CSV column's documentation lost the rubric's axis name")
    for band in ("0.9", "0.7-0.89", "0.5-0.69", "0.3-0.49"):
        assert band in doc, f"the band {band} is missing from the docstring"
