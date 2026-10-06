"""Presentation of the Security Patch Report: title branding, the Trust
Signals reading guide (status key + provenance map, rendered below the
table), and the recommendation icon. Rendering only -- no decision logic."""

from __future__ import annotations

from pathlib import Path

import pytest

from utilities.autopatcher import pipeline as pl
from utilities.autopatcher.tools.run_cve_batch import parse_trust_report

_GUIDE = "### How to read the Trust Signals"
_ALL_STATUSES = {
    status for _q, _k, status_map, _t in pl._TRUST_SIGNALS_V2_ROWS for status in status_map.values()
} | {"? Not verified"}  # the renderer's fallback for an unmapped value


def _signals():
    signals = pl._compute_trust_signals(
        [], {"applicable": True, "skipped": False}, pl._classify_challenger({}), "Good", "low",
    )
    signals["source_verification"] = {"value": "Confirmed", "label": "", "notes": ""}
    signals["existing_test_comparison"] = {"value": "PASS", "label": "", "notes": ""}
    return signals


class TestTrustSignalsGuide:
    def test_status_key_lists_exactly_the_statuses_the_table_can_render(self):
        assert {status for status, _meaning in pl._TRUST_SIGNAL_STATUS_KEY} == _ALL_STATUSES

    def test_guide_follows_the_table(self):
        rendered = pl._render_trust_signals_table(_signals())
        assert rendered.index("| Question | Status | Notes |") < rendered.index(_GUIDE)
        assert "How each row is established" not in rendered

    def test_guide_is_a_status_key_and_a_provenance_map(self):
        guide = pl._render_trust_signals_table(_signals()).split(_GUIDE, 1)[1]
        assert "**Status key**" in guide and "| Status | Meaning |" in guide
        assert "**How the signals are established**" in guide
        assert "| Evidence | Questions | What it is — and is not |" in guide
        for status in _ALL_STATUSES:
            assert f"| {status} |" in guide
        for question, _key, _map, _target in pl._TRUST_SIGNALS_V2_ROWS:
            assert question in guide

    def test_every_row_has_exactly_one_provenance_category(self):
        mapped = [key for _e, keys, _c in pl._TRUST_SIGNAL_PROVENANCE for key in keys]
        assert sorted(mapped) == sorted(key for _q, key, _m, _t in pl._TRUST_SIGNALS_V2_ROWS)

    def test_provenance_caveats_are_preserved(self):
        guide = pl._render_trust_signals_table(_signals()).split(_GUIDE, 1)[1]
        assert "not independent verification" in guide
        assert "nothing is executed" in guide
        assert "only when Existing Test Comparison was requested" in guide
        assert "never positive evidence" in guide


class TestRecommendationIcon:
    @pytest.mark.parametrize("decision,icon", sorted(pl._DECISION_CARD_EMOJI.items()))
    def test_recommendation_line_carries_the_decision_card_icon(self, decision, icon):
        block = pl._render_recommendation_block({"decision": decision, "reason": "Because."})
        assert f"{icon} **{decision}**" in block.splitlines()


class TestTitle:
    def test_report_title_has_no_mvp_branding(self, tmp_path):
        report = pl._build_report(pl.PipelineResult(
            vulnerability_text="# V\n\nd.", patch="--- a/m.py\n+++ b/m.py\n@@ -1 +1 @@\n-a\n+b\n",
            review="**Explanation:**\nok\n", score_text="**Confidence score:** 0.8",
            challenger={"verification_status": "VERIFIED_FIXED", "still_vulnerable": False,
                        "edge_cases": [], "potential_issues": [], "summary": ""},
            impact={"impact_level": "low", "changed_files": [], "affected_files": [], "impact_summary": "",
                    "recommendations": [], "usage_matches": []},
            hygiene=[], applicability={"applicable": True, "skipped": False, "skipped_reason": None,
                                       "error": None, "stderr": ""},
            behavior=None, repo_root=tmp_path, detected_language="python",
        ))
        assert report.splitlines()[0] == "# Auto Patcher — Security Patch Report"
        assert "mvp" not in report.lower()


class TestBatchParserAcceptsTheIcon:
    def _report(self, tmp_path: Path, card: str, rec_line: str) -> Path:
        path = tmp_path / "report.md"
        path.write_text(f"# Auto Patcher — Security Patch Report\n\n{card}\n\n## Recommendation\n\n{rec_line}\n",
                        encoding="utf-8")
        return path

    def test_new_format_parses_consistently(self, tmp_path):
        info = parse_trust_report(self._report(tmp_path, "## 🟢 DEPLOY AFTER VALIDATION",
                                               "🟢 **Deploy After Validation**"))
        assert info["recommendation_section_decision"] == "Deploy After Validation"
        assert info["inconsistency"] is None

    def test_old_format_still_parses(self, tmp_path):
        info = parse_trust_report(self._report(tmp_path, "## 🟠 MANUAL REVIEW REQUIRED", "**Manual Review Required**"))
        assert info["recommendation_section_decision"] == "Manual Review Required"
        assert info["inconsistency"] is None

    def test_mismatched_icon_is_flagged(self, tmp_path):
        info = parse_trust_report(self._report(tmp_path, "## 🟠 MANUAL REVIEW REQUIRED", "🟢 **Manual Review Required**"))
        assert "icon" in (info["inconsistency"] or "")
