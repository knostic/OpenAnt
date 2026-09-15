"""Tests for issue #534 — Stage 2's explanation reaches the disclosure body.

The disclosure record was built from Stage-1 fields only: the one Stage-2 text
hook (``finding.get("verification_explanation")``) reads a key no producer
writes — the verify stage stores its explanation under
``finding["verification"]["explanation"]``. The disclosure model therefore
never saw Stage 2's reasoning, and a disclosure could assert what Stage 2
refuted (receipt: a monitored run's DISCLOSURE_02 asserted the exact entry
path the same run's results_verified.json:152 said was gated).

The fix: (1) the record build reads Stage-2 text from its REAL location
(``verification.explanation`` / ``verification.note``, with the legacy
top-level key as fallback) and emits it as its own record key so the
disclosure prompt's ``{vulnerability_data}`` carries it; (2) the steps-to-
reproduce rebuild path reads the same real location; (3) the deterministic
``_disclosure_verdict_header`` (which the model cannot drop) carries the
Stage-2 qualification line verbatim.
"""
from __future__ import annotations

import json

from core.reporter import build_pipeline_output
from report.generator import _disclosure_verdict_header


def _stage2_row(explanation=None, note=None, legacy=None):
    """A verified row shaped like results_verified.json."""
    row = {
        "finding": "vulnerable",
        "verdict": "vulnerable",
        "file": "app.py",
        "function": "handler",
        "cwe_id": 79,
        "vulnerable_code": "def handler(): pass",
        "description": "XSS in handler",
        "impact": "arbitrary script execution",
        "verification": {
            "agree": True,
            "correct_finding": "vulnerable",
            "explanation": explanation,
            "iterations": 3,
            "total_tokens": 100,
        },
    }
    if note is not None:
        row["verification_note"] = note
    if legacy is not None:
        row["verification_explanation"] = legacy
    return row



def _run_pipeline(rows, tmp_path):
    """Drive the real build_pipeline_output over a results file."""
    results = tmp_path / "results.json"
    results.write_text(json.dumps({
        "dataset": "demo",
        "results": rows,
        "metrics": {"vulnerable": len(rows), "safe": 0, "inconclusive": 0},
    }))
    out = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(results),
        output_path=str(out),
        repo_name="demo",
        language="python",
    )
    return json.loads(out.read_text())["findings"]

class TestRecordCarriesStage2Text:
    def test_explanation_reaches_the_record(self, tmp_path):
        """THE #534 regression: the finding record must carry Stage 2's
        explanation under verification_explanation (the key the steps hook
        and the disclosure prompt read)."""
        row = _stage2_row(
            explanation="Stage 1's cited entry path is gated by the "
                        "autodetect filter; the reachable path requires "
                        "explicit enablement.")
        findings = _run_pipeline([row], tmp_path)
        finding = findings[0]
        assert finding["verification_explanation"] == (
            "Stage 1's cited entry path is gated by the "
            "autodetect filter; the reachable path requires "
            "explicit enablement.")

    def test_fresh_verify_dict_wins_when_both_present(self, tmp_path):
        """One precedence, both sites: the verify dict is the authoritative
        Stage-2 record (the legacy top-level key has no producer)."""
        row = _stage2_row(explanation="new-style", legacy="old-style")
        findings = _run_pipeline([row], tmp_path)
        assert findings[0]["verification_explanation"] == "new-style"

    def test_note_travels_too(self, tmp_path):
        row = _stage2_row(explanation="expl", note="the note")
        findings = _run_pipeline([row], tmp_path)
        assert findings[0]["verification_note"] == "the note"

    def test_absent_stays_absent(self, tmp_path):
        """No verification dict → no fabricated keys (present-only)."""
        row = _stage2_row(explanation="x")
        del row["verification"]
        findings = _run_pipeline([row], tmp_path)
        f = findings[0]
        assert "verification_explanation" not in f
        assert "verification_note" not in f

    def test_steps_rebuild_uses_real_location(self, tmp_path):
        """When steps_to_reproduce is absent, the rebuilt steps must include
        the Verification line sourced from the REAL key."""
        row = _stage2_row(explanation="The gated path requires enablement")
        findings = _run_pipeline([row], tmp_path)
        f = findings[0]
        assert f["steps_to_reproduce"] is not None
        assert "The gated path requires enablement" in f["steps_to_reproduce"]


class TestDeterministicHeader:
    def test_header_carries_the_qualification(self):
        """The deterministic banner (the line the model cannot drop) states
        the Stage-2 qualification verbatim."""
        data = {
            "stage2_verdict": "confirmed",
            "stage1_verdict": "vulnerable",
            "verification_explanation":
                "Weaponization requires chaining a second defect.",
        }
        header = _disclosure_verdict_header(data)
        assert "Weaponization requires chaining a second defect." in header

    def test_header_without_explanation_unchanged(self):
        data = {"stage2_verdict": "confirmed", "stage1_verdict": "vulnerable"}
        base = _disclosure_verdict_header(data)
        assert base
        assert "Stage-2 explanation" not in base

    def test_header_explanation_is_blockquote_safe(self):
        """A multi-paragraph explanation stays inside the banner block —
        every line carries the '> ' prefix (the review's 2c)."""
        data = {
            "stage2_verdict": "confirmed",
            "stage1_verdict": "vulnerable",
            "verification_explanation": "First paragraph.\n\nSecond line of the reasoning.",
        }
        header = _disclosure_verdict_header(data)
        banner_lines = [l for l in header.split("\n") if l.strip()]
        assert all(l.startswith(">") for l in banner_lines), header


# --- the fable+astra gate folds (the consistency provenance + the containment) ----

def _base_vd(explanation="Model analysis of the finding."):
    """The vulnerability_data dict the banner consumes, with a
    verification_explanation present (the #534 shape)."""
    return {
        "status": "confirmed",
        "finding": "vulnerable",
        "verdict": "vulnerable",
        "file": "app.py",
        "function": "handler",
        "cwe_id": 79,
        "verification_explanation": explanation,
    }

def test_fold_consistency_update_carried_and_banner_attributes():
    """The MEDIUM-2 fold: after a consistency pass rewrites the verdict, the
    banner must attribute the pre-update explanation (the explanation argued
    for the ORIGINAL verdict; the status line shows the updated one)."""
    vd = dict(_base_vd(), verification_explanation="The path is gated by the "
              "autodetect filter; exploitation requires the gate to be open.",
              consistency_update={"from": "vulnerable", "to": "bypassable",
                                  "reason": "peer units disagree"})
    header = _disclosure_verdict_header(vd)
    assert "Stage-2 explanation (pre-dating the consistency update" in header, (
        "the banner must attribute the pre-update explanation when an update occurred")
    assert "**Consistency update:** vulnerable → bypassable — peer units disagree" in header


def test_fold_no_update_no_attribution():
    """The negative: without a consistency update, the plain label stays."""
    vd = dict(_base_vd(), verification_explanation="The path is fully reachable.")
    header = _disclosure_verdict_header(vd)
    assert "> **Stage-2 explanation:** " in header
    assert "pre-dating" not in header
    assert "Consistency update:" not in header


def test_fold_crlf_and_cr_stay_inside_the_banner():
    """The LOW-4 fold: \\r\\n and bare \\r are CommonMark line endings — an
    unnormalized \\r would escape the > prefix and dump prose above the H1."""
    vd = dict(_base_vd(), verification_explanation="line one\r\nline two\rline three")
    header = _disclosure_verdict_header(vd)
    assert "line one\n> line two\n> line three" in header, (
        "CRLF and CR must be normalized to \\n and stay inside the blockquote")


def test_fold_gt_leading_line_and_link_contained():
    """The containment probes (fable's ask): a >-leading line nests (cosmetic
    containment); a markdown link renders inside the quote (structural
    containment — the same trust model as every model-text line)."""
    vd = dict(_base_vd(), verification_explanation="> nested quote\n[link](http://x)")
    header = _disclosure_verdict_header(vd)
    assert "> **Stage-2 explanation:** > nested quote" in header
    assert "> [link](http://x)" in header
