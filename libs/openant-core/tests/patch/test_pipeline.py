"""
Unit tests for the Auto Patcher MVP.

All tests run in mock mode (no OPENAI_API_KEY required).
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path
from unittest import mock

import pytest


import utilities.autopatcher as _ap_pkg
PROMPTS_DIR = Path(_ap_pkg.__file__).parent / "prompts"
EXAMPLES_DIR = Path(__file__).parent / "fixtures" / "examples"


# ---------------------------------------------------------------------------
# llm_client
# ---------------------------------------------------------------------------

class TestLLMClientMock:
    def test_mock_mode_when_no_key(self):
        from utilities.autopatcher.llm_client import LLMClient
        client = LLMClient(api_key="")
        assert client.is_mock is True

    def test_mock_patch_response(self):
        from utilities.autopatcher.llm_client import LLMClient
        client = LLMClient(api_key="")
        response = client.complete("patch generator system prompt", "fix this")
        assert "diff" in response.lower() or "---" in response or "+++" in response

    def test_mock_review_response(self):
        from utilities.autopatcher.llm_client import LLMClient
        client = LLMClient(api_key="")
        response = client.complete("review and explain impact of patch", "review this")
        # Should contain review-like content
        assert len(response) > 20

    def test_mock_score_response(self):
        from utilities.autopatcher.llm_client import LLMClient
        client = LLMClient(api_key="")
        response = client.complete("confidence score assessment", "score this")
        assert "confidence" in response.lower() or "score" in response.lower()

    def test_live_mode_when_key_provided(self):
        import utilities.autopatcher.llm_client as llm_client
        from utilities.autopatcher.llm_client import LLMClient
        # Clear cached provider and LLM_PROVIDER so is_mock falls back to key check.
        with mock.patch.object(llm_client, "_cached_provider", None), \
             mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LLM_PROVIDER", None)
            client = LLMClient(api_key="sk-fake-key-for-testing")
            assert client.is_mock is False

    def test_env_var_key_used(self):
        import utilities.autopatcher.llm_client as llm_client
        from utilities.autopatcher.llm_client import LLMClient
        with mock.patch.object(llm_client, "_cached_provider", None), \
             mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env-key"}):
            os.environ.pop("LLM_PROVIDER", None)
            client = LLMClient()
            assert client.is_mock is False


# ---------------------------------------------------------------------------
# Pipeline LLM mode log line
# ---------------------------------------------------------------------------

class TestPipelineLLMModeLog:
    """The early [pipeline] LLM mode: ... log must never include a model name
    that hasn't been resolved yet.  MOCK stays MOCK; LIVE carries no model.

    Progress logs go to stderr, not stdout: OpenAnt's Go CLI parses stdout
    as a single final JSON envelope (internal/python.Invoke()), so any
    engine progress print()s ported from the standalone Auto Patcher
    project were redirected to stderr during the merge -- see
    utilities/autopatcher/pipeline.py and llm_client.py."""

    def test_mock_mode_log(self, monkeypatch, capsys):
        import utilities.autopatcher.llm_client as llm_client
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        monkeypatch.setattr(llm_client, "_cached_provider", None)
        from utilities.autopatcher.pipeline import run
        run("XSS in login form")
        captured = capsys.readouterr()
        assert "[pipeline] LLM mode: MOCK" in captured.err

    def test_live_mode_log_has_no_model_name(self, monkeypatch, capsys):
        # With Anthropic configured, the early log should say LIVE with no model.
        import utilities.autopatcher.llm_client as llm_client
        monkeypatch.setenv("LLM_PROVIDER", "anthropic")
        monkeypatch.setattr(llm_client, "_cached_provider", None)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

        # Stub out the actual Anthropic call so the test stays offline.
        import types, sys
        class FakeAnthropic:
            def __init__(self, api_key=None): pass
            class messages:
                @staticmethod
                def create(model, max_tokens, messages):
                    import types
                    msg = types.SimpleNamespace(content=[types.SimpleNamespace(text="```diff\n--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-old\n+new\n```")])
                    return types.SimpleNamespace(content=[msg.content[0]])
        monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=FakeAnthropic))

        from utilities.autopatcher.pipeline import run
        run("path traversal in upload handler")
        captured = capsys.readouterr()
        assert "[pipeline] LLM mode: LIVE" in captured.err
        # Must not include a specific model name in the early log.
        assert "gpt-4o" not in captured.err.split("[pipeline] LLM mode:")[1].split("\n")[0]
        assert "claude" not in captured.err.split("[pipeline] LLM mode:")[1].split("\n")[0].lower()


# ---------------------------------------------------------------------------
# patch_generator
# ---------------------------------------------------------------------------

class TestPatchGenerator:
    def test_returns_string(self):
        from utilities.autopatcher.llm_client import LLMClient
        from utilities.autopatcher.patch_generator import generate_patch
        llm = LLMClient(api_key="")
        result = generate_patch("SQL injection in auth.py", llm)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_patch_contains_diff_markers(self):
        from utilities.autopatcher.llm_client import LLMClient
        from utilities.autopatcher.patch_generator import generate_patch
        llm = LLMClient(api_key="")
        result = generate_patch("SQL injection vulnerability", llm)
        assert "---" in result or "+++" in result or "diff" in result.lower()

    def test_prompt_file_exists(self):
        prompt = PROMPTS_DIR / "patch_generator.md"
        assert prompt.exists(), "prompts/patch_generator.md must exist"
        assert prompt.stat().st_size > 0


# ---------------------------------------------------------------------------
# patch_reviewer
# ---------------------------------------------------------------------------

class TestPatchReviewer:
    def test_returns_string(self):
        from utilities.autopatcher.llm_client import LLMClient
        from utilities.autopatcher.patch_reviewer import review_patch
        llm = LLMClient(api_key="")
        result = review_patch("vuln description", "some patch diff", llm)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_prompt_file_exists(self):
        prompt = PROMPTS_DIR / "patch_reviewer.md"
        assert prompt.exists(), "prompts/patch_reviewer.md must exist"
        assert prompt.stat().st_size > 0


# ---------------------------------------------------------------------------
# confidence_scorer
# ---------------------------------------------------------------------------

class TestConfidenceScorer:
    def test_returns_string(self):
        from utilities.autopatcher.confidence_scorer import score_confidence
        from utilities.autopatcher.llm_client import LLMClient
        llm = LLMClient(api_key="")
        result = score_confidence("vuln", "patch", "review", llm)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_response_mentions_score(self):
        from utilities.autopatcher.confidence_scorer import score_confidence
        from utilities.autopatcher.llm_client import LLMClient
        llm = LLMClient(api_key="")
        result = score_confidence("vuln", "patch", "review", llm)
        assert "score" in result.lower() or "confidence" in result.lower()

    def test_prompt_file_exists(self):
        prompt = PROMPTS_DIR / "confidence_scorer.md"
        assert prompt.exists(), "prompts/confidence_scorer.md must exist"
        assert prompt.stat().st_size > 0


# ---------------------------------------------------------------------------
# pipeline
# ---------------------------------------------------------------------------

class TestPipeline:
    @staticmethod
    def _vuln_text() -> str:
        return (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")

    def test_run_produces_report(self):
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        assert isinstance(report, str)
        assert len(report) > 100

    def test_report_contains_required_sections(self):
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        required = [
            "Vulnerability summary",
            "Vulnerability Sources",  # renamed from "Primary Vulnerability References"; GHSA/CVE/Advisory URL only
            "Proposed patch",
            "Explanation",
            "Affected areas",
            "Reviewer Notes",         # renamed from "Validation notes" (terminology cleanup)
            "Recommendation",
            "Trust Signals",          # new Trust Package section
            "Validation Actions",     # new Trust Package section
            "Review Results",         # renamed from "Known Findings" (reviewer-experience terminology pass)
            "Appendices",             # new: consolidates diagnostics + legacy sections
        ]
        for section in required:
            assert section in report, f"Report is missing section: '{section}'"
        # "Validation Plan" was removed as a duplicate of Validation Actions
        # (same underlying ≤3 items; Validation Actions now includes Reason
        # too, so nothing unique was lost).
        assert "## Validation Plan" not in report
        # Superseded by the epistemic-category Review Results section.
        assert "## Known Limitations" not in report
        assert "## Known Security Gain" not in report
        # Renamed to "Review Results" (reviewer-experience terminology pass).
        assert "## Known Findings" not in report
        # Reviewer-experience redesign: removed entirely as duplicated
        # storytelling (restated Explanation/Known Findings/Reviewer Notes).
        assert "## Patch Impact Summary" not in report
        assert "## Impact Summary" not in report
        assert "## Testing Notes" not in report
        assert "### Testing Notes" not in report
        # Upstream-reference policy: no fix-commit/remediation links in the
        # reviewer report — those belong only in benchmark/evaluation artifacts.
        assert "## Primary Vulnerability References" not in report
        assert "Referenced Upstream Commit" not in report
        # Presentation cleanup: legacy scoring sections, superseded by
        # Trust Signals, are no longer rendered.
        assert "Confidence Score" not in report
        assert "Confidence Reasoning" not in report
        assert "Confidence delta preview" not in report
        # Presentation cleanup: the raw JSON dump duplicating the "Matching
        # tests" list is no longer embedded in the human-facing report.
        assert "```json" not in report

    def test_report_includes_validation_actions_format(self):
        """Validation Actions is now the single, canonical checklist section
        — it must include Reason as well as Next step (previously only the
        now-removed "Validation Plan" section showed Reason)."""
        import re
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        assert "## Validation Actions" in report
        start = report.find("## Validation Actions")
        assert start != -1
        # Patch Hygiene now precedes Validation Actions (promoted next to
        # the diff) — Review Results is the next heading that follows it.
        after = report.find("## Review Results", start)
        block = report[start:after if after != -1 else start + 500]
        assert "Reason:" in block and "Next step:" in block
        actions = [ln for ln in block.splitlines() if re.match(r"^\d+\.\s+\*\*\[", ln.strip())]
        assert len(actions) <= 3

    def test_report_contains_recommendation_format(self):
        """Trust Package V1: Recommendation uses the new decision vocabulary.
        Trust Signals now precedes Recommendation (not after it), so this
        just takes a fixed-width slice following the Recommendation heading."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        assert "## Recommendation" in report
        start = report.find("## Recommendation")
        block = report[start:start + 400]
        # New V1 format: bold decision on its own line, followed by reason text
        bold_lines = [ln for ln in block.splitlines() if ln.strip().startswith("**") and ln.strip().endswith("**")]
        assert bold_lines, "Recommendation must have a bold decision line"
        decision = bold_lines[0].strip().strip("*").strip()
        valid_decisions = (
            "Deploy After Validation", "Deploy With Caution",
            "Manual Review Required", "Do Not Apply",
        )
        assert decision in valid_decisions, f"Unexpected decision value: {decision!r}"
        # Reason text must be a non-empty sentence after the decision line
        non_empty = [ln.strip() for ln in block.splitlines() if ln.strip() and not ln.strip().startswith("#") and not ln.strip().startswith("**")]
        assert non_empty, "Recommendation must contain reason text"
        assert len(non_empty[0]) > 10

    def test_recommendation_ordering(self):
        """Reviewer-experience redesign: a reviewer first wants to know what
        is broken and what patch is proposed — Vulnerability summary,
        Vulnerability Sources, and Proposed patch now precede
        Trust Signals and Recommendation entirely (reversing the previous
        redesign's Trust-Signals-first placement). The legacy Confidence
        Score/Reasoning sections that used to sit at the bottom, inside
        Appendices, have been removed outright (superseded by Trust
        Signals) rather than merely reordered.

        Patch Hygiene and Patch Applicability — the report's only two fully
        deterministic checks — were promoted from Appendices to sit directly
        after Proposed patch, before Trust Signals (a second reviewer-
        experience pass): a reviewer who trusts deterministic evidence over
        LLM narrative should not have to scroll past Explanation/Validation
        Actions/Review Results to reach the actual git-apply result."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        idx_vuln = report.find("## Vulnerability summary")
        idx_refs = report.find("## Vulnerability Sources")
        idx_patch = report.find("## Proposed patch")
        idx_hygiene = report.find("## Patch Hygiene")
        idx_applicability = report.find("## Patch Applicability")
        idx_trust = report.find("## Trust Signals")
        idx_rec = report.find("## Recommendation")
        idx_val_actions = report.find("## Validation Actions")
        idx_review_results = report.find("## Review Results")
        for label, idx in [
            ("Vulnerability summary", idx_vuln), ("Vulnerability Sources", idx_refs),
            ("Proposed patch", idx_patch), ("Patch Hygiene", idx_hygiene),
            ("Patch Applicability", idx_applicability), ("Trust Signals", idx_trust),
            ("Recommendation", idx_rec), ("Validation Actions", idx_val_actions),
            ("Review Results", idx_review_results),
        ]:
            assert idx != -1, f"'{label}' section missing"
        assert (
            idx_vuln < idx_refs < idx_patch < idx_hygiene < idx_applicability
            < idx_trust < idx_rec < idx_val_actions < idx_review_results
        ), (
            "Report order must be: Vulnerability summary, Primary Vulnerability "
            "References, Proposed patch, Patch Hygiene, Patch Applicability, "
            "Trust Signals, Recommendation, Validation Actions, then Review Results"
        )

    def test_report_omits_legacy_numeric_score(self):
        """The legacy 'X / 1.0' confidence score was removed as a
        presentation cleanup — it duplicated/contradicted the qualitative
        Trust Signals verdicts. Trust Signals/Recommendation/decision logic
        are unaffected; only this rendered artifact is gone."""
        import re
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        assert not re.search(r"[0-9]+(?:\.[0-9]+)?\s*/\s*1\.0", report), (
            "Report should no longer contain the legacy numeric confidence score"
        )


# ---------------------------------------------------------------------------
# Report Structure v2, Phase 1 — Decision Card
# ---------------------------------------------------------------------------

class TestDecisionCard:
    """Unit tests for _render_decision_card as a Hero Banner: the decision
    line itself is the heading (first visible line after the title), and
    every field is a direct restatement of an already-computed value —
    never a new derivation, never a separate "confidence" judgment."""

    _EMOJI = {
        "Deploy After Validation": "🟢",
        "Deploy With Caution": "🟡",
        "Manual Review Required": "🟠",
        "Do Not Apply": "🔴",
    }

    def _signals(self, patch_integrity="Clean"):
        return {"patch_integrity": {"value": patch_integrity, "label": patch_integrity, "notes": ""}}

    def test_decision_line_is_first_line_and_uses_existing_emoji_mapping(self):
        from utilities.autopatcher.pipeline import _render_decision_card
        for decision, emoji in self._EMOJI.items():
            rec = {"decision": decision, "reason": "x"}
            card = _render_decision_card(rec, self._signals(), [], [])
            first_line = card.splitlines()[0]
            assert first_line == f"## {emoji} {decision.upper()}"

    def test_patch_line_uses_existing_applicability_label(self):
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Manual Review Required", "reason": "x"}
        card = _render_decision_card(rec, self._signals("Critical Issues"), [], ["a.py"])
        assert "Patch has critical issues." in card

    def test_patch_line_clean(self):
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Deploy After Validation", "reason": "x"}
        card = _render_decision_card(rec, self._signals("Clean"), [], ["a.py"])
        assert "Patch applies cleanly." in card

    def test_no_separate_trust_or_confidence_field(self):
        """Rule: never say 'High confidence' (or any confidence label) as a
        separate Trust field — the banner has no independent confidence line."""
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Deploy After Validation", "reason": "x"}
        card = _render_decision_card(rec, self._signals(), [], [])
        assert "confidence" not in card.lower()
        assert "Trust" not in card

    def test_validation_zero_actions(self):
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Deploy With Caution", "reason": "x"}
        card = _render_decision_card(rec, self._signals(), [], [])
        assert "No additional validation actions identified." in card

    def test_validation_one_action_is_singular(self):
        """Hero wording must not name a section — it must stay valid even if
        section names or positions change (they already have, twice)."""
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Deploy With Caution", "reason": "x"}
        card = _render_decision_card(rec, self._signals(), [{}], [])
        assert "Complete the recommended validation check before deployment." in card
        assert "section" not in card.lower()
        assert "1 checks" not in card

    def test_validation_multiple_actions_is_plural(self):
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Deploy With Caution", "reason": "x"}
        card = _render_decision_card(rec, self._signals(), [{}, {}, {}], [])
        assert "Complete the recommended validation checks before deployment." in card
        assert "section" not in card.lower()

    def test_files_changed_line(self):
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Deploy After Validation", "reason": "x"}
        card = _render_decision_card(rec, self._signals(), [], ["a.py", "b.py", "c.py"])
        assert "Files changed: 3" in card

    def test_do_not_apply_wording_does_not_imply_deployment(self):
        """Reviewer-experience fix: 'before deployment' is contradictory when
        the decision is Do Not Apply — there is no deployment to validate
        toward. The same validation_actions still render; only the sentence
        describing them changes."""
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Do Not Apply", "reason": "x"}
        card = _render_decision_card(rec, self._signals("Critical Issues"), [{}, {}], [])
        assert "should not be deployed" in card
        assert "before deployment" not in card

    def test_do_not_apply_wording_with_zero_actions(self):
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Do Not Apply", "reason": "x"}
        card = _render_decision_card(rec, self._signals("Does Not Apply"), [], [])
        assert "should not be deployed" in card
        assert "before deployment" not in card


class TestValidationActionsDecisionAware:
    """Unit tests for _render_validation_actions_section's decision-aware
    note (reviewer-experience fix): the actions themselves, their order,
    priority, and count are untouched — only a leading note changes."""

    _ACTION = {"priority": "MEDIUM", "title": "x", "reason": "y", "next_step": "z"}

    def test_do_not_apply_adds_note(self):
        from utilities.autopatcher.pipeline import _render_validation_actions_section
        block = _render_validation_actions_section([self._ACTION], "Do Not Apply")
        assert "not recommended for deployment" in block
        assert "1. **[MEDIUM]** x" in block

    def test_other_decisions_add_no_note(self):
        from utilities.autopatcher.pipeline import _render_validation_actions_section
        block = _render_validation_actions_section([self._ACTION], "Deploy After Validation")
        assert "not recommended for deployment" not in block
        assert "1. **[MEDIUM]** x" in block

    def test_default_decision_argument_adds_no_note(self):
        """Backward-compatible default: omitting `decision` entirely must not
        change existing callers' output."""
        from utilities.autopatcher.pipeline import _render_validation_actions_section
        block = _render_validation_actions_section([self._ACTION])
        assert "not recommended for deployment" not in block


class TestDecisionCardInReport:
    """End-to-end wiring: the Hero Banner sits first, Recommendation and
    Trust Signals immediately follow it, and every other section keeps its
    prior relative position."""

    @staticmethod
    def _vuln_text() -> str:
        return (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")

    @staticmethod
    def _find_hero_banner(report: str) -> int:
        """Locate the Hero Banner heading (## <emoji> <DECISION>) — there is
        no longer a literal '## Decision Card' label to search for."""
        import re
        m = re.search(r"^## [🟢🟡🟠🔴] [A-Z ]+$", report, re.MULTILINE)
        return m.start() if m else -1

    def test_decision_card_appears_before_recommendation(self):
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        idx_card = self._find_hero_banner(report)
        idx_rec = report.find("## Recommendation")
        assert idx_card != -1, "Hero Banner heading not found"
        assert idx_rec != -1
        assert idx_card < idx_rec

    def test_decision_card_is_first_section_after_title(self):
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        title_idx = report.find("# Auto Patcher MVP — Security Patch Report")
        first_heading_after_title = report.find("##", title_idx)
        assert first_heading_after_title == self._find_hero_banner(report)

    def test_vulnerability_summary_immediately_follows_hero_banner(self):
        """Reviewer-experience redesign: a reviewer first wants to know what
        is broken — Vulnerability summary now directly follows the Hero
        Banner (reversing the previous redesign, which put Trust Signals
        there instead)."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        idx_card = self._find_hero_banner(report)
        hero_line_end = report.find("\n", idx_card)
        idx_vuln = report.find("## Vulnerability summary")
        between = report[hero_line_end:idx_vuln]
        assert "## " not in between

    def test_trust_signals_follows_proposed_patch(self):
        """Trust Signals only becomes meaningful once a reviewer already
        knows what is broken and what patch is proposed — it now follows
        Vulnerability summary, Vulnerability Sources, and
        Proposed patch, and precedes Recommendation."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        idx_vuln = report.find("## Vulnerability summary")
        idx_patch = report.find("## Proposed patch")
        idx_trust = report.find("## Trust Signals")
        idx_rec = report.find("## Recommendation")
        assert idx_vuln < idx_patch < idx_trust < idx_rec

    def test_security_gain_appears_within_explanation(self):
        """Known Security Gain was merged into Explanation rather than kept
        as its own heading — it was always an extracted sentence from (or,
        on the fallback path, a truncated paragraph of) the same explanation
        text, so it's now a labeled lead-in inside that section instead of a
        separate one repeating the same information. "Impact Summary" no
        longer exists at all (removed as duplicated storytelling)."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        idx_patch = report.find("## Proposed patch")
        idx_rec = report.find("## Recommendation")
        idx_expl = report.find("## Explanation")
        idx_val_actions = report.find("## Validation Actions")
        assert idx_patch < idx_rec < idx_expl < idx_val_actions
        assert "## Impact Summary" not in report
        assert "## Known Security Gain" not in report
        explanation_block = report[idx_expl:idx_val_actions]
        assert "**Security gain:**" in explanation_block


class TestReportTerminologyCleanup:
    """Terminology/navigation cleanup: one name per concept, and every
    forward reference names a real, existing section heading."""

    @staticmethod
    def _vuln_text() -> str:
        return (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")

    def test_validation_plan_removed(self):
        """Validation Plan repeated the same <=3 items already shown, with
        Reason added, in Validation Actions — verified lossless to fold in
        and remove rather than keep as a second name for the same checklist."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        assert "## Validation Plan" not in report
        assert "## Validation Actions" in report

    def test_reviewer_notes_replaces_validation_notes_heading(self):
        """Renamed to stop sharing the word "Validation" with the actions
        checklist, since this section is unrelated LLM reviewer prose, not
        part of that concept."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        assert "## Reviewer Notes" in report
        assert "## Validation notes" not in report

    def test_testing_notes_removed_as_duplicated_storytelling(self):
        """Testing Notes was a third restatement of validation_notes/challenger
        findings, fully duplicating Reviewer Notes and Known Findings —
        removed entirely rather than promoted."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        assert "## Testing Notes" not in report
        assert "### Testing Notes" not in report
        assert "### What should be tested" not in report

    def test_hero_banner_does_not_name_a_section(self):
        """Hero wording must remain valid even if section names or positions
        change elsewhere — it must not reference "Validation Actions" or any
        other section name by name."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        idx = report.find("# Auto Patcher MVP")
        banner = report[idx:report.find("## Vulnerability summary")]
        assert "section" not in banner.lower()
        assert "Complete the recommended validation check" in banner

    def test_no_dangling_see_analysis_below(self):
        """Catches regression of the specific dangling phrase this cleanup
        fixes in Trust Signals. Note: the Recommendation reason string
        "Run the listed validation actions before deployment" (inside
        _build_recommendation_v1, the Deploy After Validation branch) was
        intentionally left untouched pending explicit confirmation that
        editing that function's wording is in scope — not asserted here."""
        import re
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        assert not re.search(r"see analysis below", report, re.IGNORECASE)
# ---------------------------------------------------------------------------
# Explanation rendering fix — dangling list-marker regression
# ---------------------------------------------------------------------------

class TestExplanationDanglingListMarkerFix:
    """Reviewer-experience fix: when the extracted security_gain sentence is
    the entire body of a numbered/bulleted list item in the reviewer LLM's
    explanation text, stripping it used to leave a bare marker behind (e.g.
    a dangling "1." with nothing after it). This only touches how the
    already-generated explanation text is rendered — _extract_security_gain
    and the reviewer LLM's own output are untouched."""

    @staticmethod
    def _build(tmp_path, review):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
                " def foo():\n-    return 1\n+    return 2\n"
            ),
            review=review,
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""},
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""},
            repo_root=tmp_path,
            detected_language="python",
        )
        return _build_report(result)

    def test_no_dangling_list_marker_left_behind(self, tmp_path):
        import re
        review = (
            "**Explanation:**\n"
            "1. This patch does not fix the vulnerability at all.\n\n"
            "The underlying issue remains because the check was never added.\n\n"
            "**Affected areas:**\n"
            "- mod.py\n\n"
            "**Validation notes:**\n"
            "- Test with payload Y.\n"
        )
        report = self._build(tmp_path, review)
        # The extracted sentence still appears once, as the Security gain callout.
        assert "**Security gain:** This patch does not fix the vulnerability at all." in report
        # No line consisting solely of a bare numbered/bulleted marker.
        assert not re.search(r"^[ \t]*(?:\d+\.|[-*])[ \t]*$", report, re.MULTILINE)
        # The rest of the explanation body is preserved.
        assert "The underlying issue remains because the check was never added." in report

    def test_ordinary_explanation_unaffected(self, tmp_path):
        """No list markers involved — behavior is unchanged from before this fix."""
        review = (
            "**Explanation:**\n"
            "This patch fixes the vulnerability by validating input.\n\n"
            "Additional context about the fix follows here.\n\n"
            "**Affected areas:**\n"
            "- mod.py\n\n"
            "**Validation notes:**\n"
            "- Test with payload Y.\n"
        )
        report = self._build(tmp_path, review)
        assert "**Security gain:** This patch fixes the vulnerability by validating input." in report
        assert "Additional context about the fix follows here." in report


# ---------------------------------------------------------------------------
# Slice 1 — Decision Consistency (report-level regression)
# ---------------------------------------------------------------------------

class TestRecommendationConsistencyReport:
    """Report-level regression coverage for Slice 1.

    Builds a PipelineResult directly and calls _build_report() — no LLM
    calls, fully deterministic. Assertions check stable invariants (decision
    label present, caveat text present/absent) rather than full-report
    string equality, since equality would be brittle to unrelated formatting
    and is not needed to prove this slice's behavior.
    """

    def _base_kwargs(self, tmp_path, challenger, applicability=None):
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                "--- a/mod.py\n"
                "+++ b/mod.py\n"
                "@@ -1,3 +1,3 @@\n"
                " def foo():\n"
                "-    return 1\n"
                "+    return 2\n"
            ),
            review=(
                "**Explanation:**\n"
                "The code was vulnerable because of X.\n\n"
                "**Affected areas:**\n"
                "- mod.py\n\n"
                "**Validation notes:**\n"
                "- Test with payload Y.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger=challenger,
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability=applicability or {
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            repo_root=tmp_path,
            detected_language="python",
        )

    def test_no_tests_found_gets_test_caveat_only(self, tmp_path):
        """minimist-representative: no matching tests, no challenger findings.
        Top-tier recommendation is unchanged; the test-coverage caveat is new."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._base_kwargs(tmp_path, challenger))
        report = _build_report(result)

        assert "**Deploy After Validation**" in report
        assert "test coverage" in report
        assert "adversarial coverage" not in report
        # Correction: never say "0 confirmed" / imply the patch is broken.
        assert "0 confirmed" not in report.lower()
        assert "issue(s) flagged" not in report

    def test_low_coverage_confidence_gets_coverage_caveat_only(self, tmp_path):
        """pip-representative: matching tests exist, one unresolved plausible
        finding. Top-tier recommendation is unchanged; the coverage-confidence
        caveat is new."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_foo(): pass\n", encoding="utf-8")
        challenger = {
            "still_vulnerable": False,
            "edge_cases": ["custom configurations may not benefit from this change"],
            "potential_issues": [],
            "summary": "",
        }
        result = PipelineResult(**self._base_kwargs(tmp_path, challenger))
        report = _build_report(result)

        assert "**Deploy After Validation**" in report
        assert "adversarial coverage" in report
        assert "test coverage" not in report
        # Correction: never say "0 confirmed" / imply the patch is broken.
        assert "0 confirmed" not in report.lower()
        assert "issue(s) flagged" not in report

    def test_manual_review_required_gets_no_caveat(self, tmp_path):
        """A non-top-tier decision must not gain caveats even when both
        underlying signals are weak — it already reads as cautious."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": True, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._base_kwargs(tmp_path, challenger))
        report = _build_report(result)

        assert "**Manual Review Required**" in report
        assert "This recommendation currently has no automated test coverage" not in report
        assert "adversarial coverage is heuristic" not in report

    def test_do_not_apply_gets_no_caveat(self, tmp_path):
        """pygeoapi/curl-representative: applicability hard-block. Must remain
        untouched by this slice."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._base_kwargs(
            tmp_path, challenger,
            applicability={
                "applicable": False, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "error: patch does not apply",
            },
        ))
        report = _build_report(result)

        assert "**Do Not Apply**" in report
        assert "This recommendation currently has no automated test coverage" not in report
        assert "adversarial coverage is heuristic" not in report


# ---------------------------------------------------------------------------
# pipeline helpers
# ---------------------------------------------------------------------------

class TestPipelineHelpers:
    def test_extract_score(self):
        from utilities.autopatcher.pipeline import _extract_score
        text = "**Confidence score:** 0.85\n**Reasons:**\n- reason 1"
        assert _extract_score(text) == "0.85"

    def test_extract_score_missing(self):
        from utilities.autopatcher.pipeline import _extract_score
        assert _extract_score("no score here") == "N/A"

    def test_extract_summary(self):
        from utilities.autopatcher.pipeline import _extract_summary
        text = "# SQL Injection\n\nSome details"
        assert _extract_summary(text) == "SQL Injection"

    def test_split_review_sections(self):
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            **Explanation:**
            The code was vulnerable because of X.

            **Affected areas:**
            - app/auth.py

            **Validation notes:**
            - Test with payload Y.
        """)
        sections = _split_review(review)
        assert "vulnerable" in sections["explanation"]
        assert "auth.py" in sections["affected_areas"]
        assert "payload" in sections["validation_notes"]

    def test_build_recommendation_helper(self):
        from utilities.autopatcher.pipeline import build_recommendation
        # still_vulnerable -> Do not deploy yet
        rec = build_recommendation({"still_vulnerable": True}, 0.9, "Good", {"impact_level": "low"})
        assert rec["decision"] == "Do not deploy yet"

        # high impact and no tests -> Do not deploy yet (override)
        rec = build_recommendation({}, 0.95, "None", {"impact_level": "high"})
        assert rec["decision"] == "Do not deploy yet"

        # safe case
        rec = build_recommendation({}, 0.80, "Good", {"impact_level": "low"})
        assert rec["decision"] == "Safe to deploy"

        # reason constraints
        rec = build_recommendation({"edge_cases": ["x"]}, 0.80, "Some", {"impact_level": "medium"})
        reason = rec.get("reason", "")
        assert len(reason) > 0 and len(reason) <= 120
        assert "-" not in reason and "*" not in reason


# ---------------------------------------------------------------------------
# Vulnerability Sources (GHSA/CVE/Advisory URL — no upstream remediation links)
# ---------------------------------------------------------------------------

class TestPrimaryReferences:
    """Direct unit coverage for _extract_primary_references/_render_primary_references
    — previously only exercised indirectly through full report generation."""

    def test_extracts_ghsa_and_cve_from_advisory_line(self):
        from utilities.autopatcher.pipeline import _extract_primary_references
        text = "**Advisory:** GHSA-v845-jxx5-vc9f / CVE-2023-43804\n\nSome description.\n"
        refs = _extract_primary_references(text)
        assert refs["ghsa_id"] == "GHSA-v845-jxx5-vc9f"
        assert refs["cve_id"] == "CVE-2023-43804"
        assert refs["advisory_url"] == "https://github.com/advisories/GHSA-v845-jxx5-vc9f"

    def test_cve_only_advisory_line_uses_nvd_url(self):
        from utilities.autopatcher.pipeline import _extract_primary_references
        text = "**Advisory:** CVE-2022-25883\n\nSome description.\n"
        refs = _extract_primary_references(text)
        assert refs["ghsa_id"] is None
        assert refs["cve_id"] == "CVE-2022-25883"
        assert refs["advisory_url"] == "https://nvd.nist.gov/vuln/detail/CVE-2022-25883"

    def test_file_mode_input_has_no_identifiers(self):
        from utilities.autopatcher.pipeline import _extract_primary_references
        text = "# Some vulnerability\n\nA hand-written description with no advisory line.\n"
        refs = _extract_primary_references(text)
        assert refs["ghsa_id"] is None
        assert refs["cve_id"] is None
        assert refs["advisory_url"] is None

    def test_extraction_never_returns_a_commit_reference(self):
        """The extractor has no notion of an upstream commit at all anymore —
        not computed, not hidden, removed entirely."""
        from utilities.autopatcher.pipeline import _extract_primary_references
        text = (
            "**Advisory:** GHSA-v845-jxx5-vc9f\n\n"
            "## References\n\n- https://github.com/urllib3/urllib3/commit/abc123\n"
        )
        refs = _extract_primary_references(text)
        assert "referenced_commit" not in refs
        assert set(refs.keys()) == {"ghsa_id", "cve_id", "advisory_url"}


class TestRenderPrimaryReferences:
    def test_heading_is_vulnerability_sources(self):
        from utilities.autopatcher.pipeline import _render_primary_references
        block = _render_primary_references({"ghsa_id": "GHSA-xxxx", "cve_id": None, "advisory_url": "https://github.com/advisories/GHSA-xxxx"})
        assert "## Vulnerability Sources" in block
        assert "## Primary Vulnerability References" not in block

    def test_ghsa_and_advisory_url_are_clickable_links(self):
        from utilities.autopatcher.pipeline import _render_primary_references
        block = _render_primary_references({
            "ghsa_id": "GHSA-v845-jxx5-vc9f", "cve_id": "CVE-2023-43804",
            "advisory_url": "https://github.com/advisories/GHSA-v845-jxx5-vc9f",
        })
        assert "[GHSA-v845-jxx5-vc9f](https://github.com/advisories/GHSA-v845-jxx5-vc9f)" in block
        assert "[https://github.com/advisories/GHSA-v845-jxx5-vc9f](https://github.com/advisories/GHSA-v845-jxx5-vc9f)" in block

    def test_cve_only_mode_links_to_nvd(self):
        from utilities.autopatcher.pipeline import _render_primary_references
        block = _render_primary_references({
            "ghsa_id": None, "cve_id": "CVE-2022-25883",
            "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-25883",
        })
        assert "[CVE-2022-25883](https://nvd.nist.gov/vuln/detail/CVE-2022-25883)" in block

    def test_file_mode_degrades_to_single_line(self):
        from utilities.autopatcher.pipeline import _render_primary_references
        block = _render_primary_references({"ghsa_id": None, "cve_id": None, "advisory_url": None})
        assert "## Vulnerability Sources" in block
        assert "User-provided vulnerability description" in block
        assert "|" not in block  # no table at all, not a table of placeholders

    def test_no_upstream_commit_or_remediation_link_ever_rendered(self):
        from utilities.autopatcher.pipeline import _render_primary_references
        block = _render_primary_references({
            "ghsa_id": "GHSA-xxxx", "cve_id": "CVE-2023-1", "advisory_url": "https://github.com/advisories/GHSA-xxxx",
        })
        assert "Referenced Upstream Commit" not in block
        assert "commit" not in block.lower()

    def test_only_three_rows_in_table(self):
        from utilities.autopatcher.pipeline import _render_primary_references
        block = _render_primary_references({
            "ghsa_id": "GHSA-xxxx", "cve_id": "CVE-2023-1", "advisory_url": "https://github.com/advisories/GHSA-xxxx",
        })
        row_lines = [l for l in block.splitlines() if l.startswith("| ") and "---" not in l and "Type" not in l]
        assert len(row_lines) == 3


# ---------------------------------------------------------------------------
# CLI (main.py)
# ---------------------------------------------------------------------------

_FIXTURE_ADVISORY = {
    "ghsa_id": "GHSA-1234-5678-9012",
    "cve_id": "CVE-2021-12345",
    "summary": "SQL injection in example library",
    "description": "A SQL injection vulnerability exists in the authenticate() function.",
    "severity": "critical",
    "cvss": {"score": 9.8},
    "cwes": [{"cwe_id": "CWE-89", "name": "Improper Neutralization"}],
    "vulnerabilities": [
        {
            "package": {"name": "example-lib", "ecosystem": "pip"},
            "vulnerable_version_range": "< 1.2.3",
            "first_patched_version": "1.2.3",
        }
    ],
    "references": [{"url": "https://github.com/example/security/advisories/GHSA-1234"}],
}


# TestCLI (upstream): exercised main.py's argparse CLI, including GHSA mode.
# main.py is not ported -- its role is replaced by core/patch.py + cmd_patch
# in openant/cli.py, which have their own dedicated tests (see
# tests/patch/test_patch_wrapper_contract.py and openant-core's own CLI
# dispatch tests). GHSA mode (advisory_fetcher) is excluded entirely per the
# migration plan -- OpenAnt always supplies a rendered Finding, never a bare
# advisory ID.


# ---------------------------------------------------------------------------
# Pipeline code context integration
# ---------------------------------------------------------------------------

class TestPipelineCodeContext:
    def test_pipeline_passes_nonempty_code_context_when_repo_has_match(self, tmp_path):
        """When repo_root contains a file matching the vulnerability, pipeline
        should pass a non-empty code_context into generate_patch()."""
        from utilities.autopatcher.pipeline import run
        from unittest import mock as _mock
        import utilities.autopatcher.patch_generator as _pg

        # Create a file that the example vulnerability.md references explicitly
        auth_file = tmp_path / "app" / "auth.py"
        auth_file.parent.mkdir(parents=True)
        auth_file.write_text(
            "def authenticate(username, password):\n"
            "    query = f\"SELECT * FROM users WHERE username='{username}'\"\n"
            "    return db.execute(query).fetchone()\n",
            encoding="utf-8",
        )

        vuln_text = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")
        captured: list[str] = []
        _original = _pg.generate_patch

        def _capturing(vtext, llm, code_context=""):
            captured.append(code_context)
            return _original(vtext, llm)  # use real (mock) implementation

        with _mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=_capturing):
            run(vulnerability_text=vuln_text, api_key="", repo_root=str(tmp_path))

        assert captured, "generate_patch was never called"
        assert captured[0] != "", (
            "Expected non-empty code_context when repo contains app/auth.py"
        )

    def test_test_support_uses_target_repo_not_auto_patcher(self, tmp_path):
        """Test Support must scan repo_root, not the Auto-Patcher's own test directory."""
        from utilities.autopatcher.pipeline import run

        # Target repo: a minimal Python project with one test file
        target_test = tmp_path / "tests" / "test_auth.py"
        target_test.parent.mkdir(parents=True)
        target_test.write_text("def test_login(): pass\n", encoding="utf-8")

        vuln_text = (EXAMPLES_DIR / "vulnerability.md").read_text(encoding="utf-8")
        report = run(vulnerability_text=vuln_text, api_key="", repo_root=str(tmp_path))

        # The report must reference the target repo's test, not Auto-Patcher's tests
        assert "test_auth.py" in report, (
            "Test Support should list the target repo's test_auth.py"
        )
        # Auto-Patcher's own tests must not appear
        assert "test_pipeline.py" not in report, (
            "Test Support must not list Auto-Patcher's own test files"
        )
        assert "test_advisory_fetcher.py" not in report, (
            "Test Support must not list Auto-Patcher's own test files"
        )


# ---------------------------------------------------------------------------
# Repository Context section (Repository Grounding surfaced in the report)
# ---------------------------------------------------------------------------

class TestRepositoryContextSection:
    """Coverage for _render_repository_context_section() and its
    _selected_reason_kind() adapter — the report-facing surface of
    Repository Grounding (ground_repository()/RepositoryGroundingResult).

    Builds synthetic RepositoryGroundingResult objects directly rather than
    running a real repo scan — these tests exercise the renderer's mapping
    and presentation rules in isolation from repo_locator's discovery
    algorithm, which is already covered by tests/test_repo_locator.py.
    """

    @staticmethod
    def _evidence(pass_name, tier):
        from utilities.autopatcher.repository_grounding_models import DiscoveryEvidence
        return DiscoveryEvidence(
            pass_name=pass_name, tier=tier, matched_tokens=None,
            total_occurrences=None, hit_line=0, resolution_strategy=None,
        )

    @staticmethod
    def _candidate(path, evidence, best_tier):
        from utilities.autopatcher.repository_grounding_models import RepositoryCandidate
        return RepositoryCandidate(path=path, evidence=evidence, best_tier=best_tier)

    @staticmethod
    def _decision(path, outcome):
        from utilities.autopatcher.repository_grounding_models import GroundingDecision
        return GroundingDecision(
            path=path, outcome=outcome, snippet_ranges=None,
            bytes_contributed=0, truncated=False,
        )

    @staticmethod
    def _grounding(candidates, decisions):
        from utilities.autopatcher.repository_grounding_models import RepositoryGroundingResult
        return RepositoryGroundingResult(
            rendered_context="irrelevant to these tests",
            candidates=candidates, decisions=decisions,
            extraction_signals={}, budget=None,
        )

    # --- renderer behavior ---------------------------------------------------

    def test_renderer_basic_layout(self):
        from utilities.autopatcher.pipeline import _render_repository_context_section
        candidate = self._candidate("retry.py", [self._evidence("explicit_path", tier=3)], best_tier=3)
        decision = self._decision("retry.py", "primary_full_file")
        grounding = self._grounding([candidate], [decision])

        section = _render_repository_context_section(grounding)

        assert section.startswith("---\n\n## Repository Context\n\n")
        assert (
            "The following repository locations were selected to provide "
            "context for patch generation and review." in section
        )
        assert "**`retry.py`**" in section
        assert "Selected because\n- Explicitly referenced in the security advisory" in section
        assert "Used for\n- Primary reference (full file)" in section

    def test_renderer_multi_location_separated_by_rule(self):
        """§4.3 of the approved plan: a horizontal rule separates entries
        when more than one location is selected."""
        from utilities.autopatcher.pipeline import _render_repository_context_section
        cand_a = self._candidate("first.py", [self._evidence("explicit_path", tier=3)], best_tier=3)
        cand_b = self._candidate("second.py", [self._evidence("symbol_search", tier=2)], best_tier=2)
        decisions = [
            self._decision("first.py", "primary_full_file"),
            self._decision("second.py", "secondary_snippet"),
        ]
        grounding = self._grounding([cand_a, cand_b], decisions)

        section = _render_repository_context_section(grounding)

        assert "**`first.py`**" in section
        assert "**`second.py`**" in section
        between = section[section.index("first.py"):section.index("second.py")]
        assert "\n\n---\n\n" in between

    # --- semantic reason mapping ----------------------------------------------

    @pytest.mark.parametrize("pass_name,expected_phrase", [
        ("explicit_path", "Explicitly referenced in the security advisory"),
        ("symbol_search", "References a symbol named in the advisory"),
        ("cwe_keywords", "Contains terminology associated with this vulnerability type"),
        ("class_definition_supplement", "Defines a class named in the advisory"),
    ])
    def test_semantic_reason_mapping(self, pass_name, expected_phrase):
        from utilities.autopatcher.pipeline import _render_repository_context_section
        candidate = self._candidate("a_file.py", [self._evidence(pass_name, tier=1)], best_tier=1)
        decision = self._decision("a_file.py", "primary_full_file")
        grounding = self._grounding([candidate], [decision])

        section = _render_repository_context_section(grounding)

        assert expected_phrase in section

    def test_selected_reason_kind_picks_evidence_matching_best_tier(self):
        """A candidate discovered by more than one pass must report the
        reason for whichever pass produced its best_tier — not just the
        first evidence entry appended. This is the adapter that keeps the
        renderer itself ignorant of DiscoveryEvidence/best_tier/tier
        matching."""
        from utilities.autopatcher.pipeline import _selected_reason_kind
        candidate = self._candidate(
            "a_file.py",
            [self._evidence("cwe_keywords", tier=1), self._evidence("symbol_search", tier=2)],
            best_tier=2,
        )
        assert _selected_reason_kind(candidate) == "symbol_search"

    def test_selected_reason_kind_falls_back_to_first_evidence_when_best_tier_none(self):
        """Class-definition-supplement-only candidates have best_tier=None
        by construction (see repo_locator.py) — must not crash, must use
        the one evidence entry present."""
        from utilities.autopatcher.pipeline import _selected_reason_kind
        candidate = self._candidate(
            "a_file.py", [self._evidence("class_definition_supplement", tier=None)], best_tier=None,
        )
        assert _selected_reason_kind(candidate) == "class_definition_supplement"

    def test_selected_reason_kind_none_for_missing_or_empty_candidate(self):
        from utilities.autopatcher.pipeline import _selected_reason_kind
        assert _selected_reason_kind(None) is None
        assert _selected_reason_kind(self._candidate("a_file.py", [], best_tier=None)) is None

    def test_unknown_reason_kind_falls_back_to_generic_phrase(self):
        """An unrecognized pass_name (a future evidence kind not yet in the
        lookup table) must degrade to a generic sentence, not KeyError."""
        from utilities.autopatcher.pipeline import _render_repository_context_section
        candidate = self._candidate("a_file.py", [self._evidence("some_future_pass", tier=1)], best_tier=1)
        decision = self._decision("a_file.py", "primary_full_file")
        grounding = self._grounding([candidate], [decision])

        section = _render_repository_context_section(grounding)

        assert "Identified during repository grounding" in section

    # --- usage-role mapping -----------------------------------------------

    @pytest.mark.parametrize("outcome,expected_phrase", [
        ("primary_full_file", "Primary reference (full file)"),
        ("primary_snippet", "Primary reference (excerpt)"),
        ("secondary_snippet", "Supporting reference (excerpt)"),
    ])
    def test_usage_role_mapping(self, outcome, expected_phrase):
        from utilities.autopatcher.pipeline import _render_repository_context_section
        candidate = self._candidate("a_file.py", [self._evidence("explicit_path", tier=3)], best_tier=3)
        decision = self._decision("a_file.py", outcome)
        grounding = self._grounding([candidate], [decision])

        section = _render_repository_context_section(grounding)

        assert expected_phrase in section

    # --- rejected locations omitted -----------------------------------------

    def test_rejected_locations_omitted(self):
        from utilities.autopatcher.pipeline import _render_repository_context_section
        kept = self._candidate("kept_file.py", [self._evidence("explicit_path", tier=3)], best_tier=3)
        dropped = self._candidate("dropped_file.py", [self._evidence("cwe_keywords", tier=1)], best_tier=1)
        decisions = [
            self._decision("kept_file.py", "primary_full_file"),
            self._decision("dropped_file.py", "rejected"),
        ]
        grounding = self._grounding([kept, dropped], decisions)

        section = _render_repository_context_section(grounding)

        assert "kept_file.py" in section
        assert "dropped_file.py" not in section

    def test_all_rejected_renders_zero_selection_sentence(self):
        """Every discovered candidate rejected must read the same as no
        candidates at all — not a silently empty location list."""
        from utilities.autopatcher.pipeline import _render_repository_context_section
        candidate = self._candidate("a_file.py", [self._evidence("cwe_keywords", tier=1)], best_tier=1)
        decision = self._decision("a_file.py", "rejected")
        grounding = self._grounding([candidate], [decision])

        section = _render_repository_context_section(grounding)

        assert (
            "No repository locations were identified to provide context "
            "for this vulnerability." in section
        )

    # --- None / empty grounding handling -------------------------------------

    def test_none_grounding_renders_zero_selection_sentence(self):
        from utilities.autopatcher.pipeline import _render_repository_context_section
        section = _render_repository_context_section(None)
        assert "## Repository Context" in section
        assert (
            "No repository locations were identified to provide context "
            "for this vulnerability." in section
        )

    def test_empty_grounding_renders_zero_selection_sentence(self):
        """A grounding result with no candidates/decisions at all (the real
        empty/no-match exit path in ground_repository()) must render the
        same zero-selection sentence as grounding=None."""
        from utilities.autopatcher.pipeline import _render_repository_context_section
        section = _render_repository_context_section(self._grounding([], []))
        assert (
            "No repository locations were identified to provide context "
            "for this vulnerability." in section
        )

    # --- section ordering ----------------------------------------------------

    def test_decision_order_preserved_not_resorted(self):
        """The approved plan does not call for re-ordering by outcome — a
        secondary location that comes before the primary in
        grounding.decisions must still render in that order. No sort is
        applied by the renderer."""
        from utilities.autopatcher.pipeline import _render_repository_context_section
        secondary = self._candidate("secondary_file.py", [self._evidence("cwe_keywords", tier=1)], best_tier=1)
        primary = self._candidate("primary_file.py", [self._evidence("explicit_path", tier=3)], best_tier=3)
        decisions = [
            self._decision("secondary_file.py", "secondary_snippet"),
            self._decision("primary_file.py", "primary_full_file"),
        ]
        grounding = self._grounding([secondary, primary], decisions)

        section = _render_repository_context_section(grounding)

        assert section.index("secondary_file.py") < section.index("primary_file.py")

    def test_repository_context_section_placed_before_impact_surface(self, tmp_path):
        """§4.2 of the approved plan: Repository Context sits immediately
        before Impact Surface, after Review Results — integration-level
        check against a real ground_repository() result via run()."""
        from utilities.autopatcher.pipeline import run
        (tmp_path / "auth.py").write_text(
            "def authenticate(u, p):\n    return db.query(u, p)\n", encoding="utf-8"
        )
        vuln_text = "SQL injection in authenticate() — see auth.py"
        report = run(vulnerability_text=vuln_text, api_key="", repo_root=str(tmp_path))

        idx_review = report.find("## Review Results")
        idx_repo_context = report.find("## Repository Context")
        idx_impact = report.find("## Impact Surface")

        assert idx_review != -1, "Review Results section missing"
        assert idx_repo_context != -1, "Repository Context section missing"
        assert idx_impact != -1, "Impact Surface section missing"
        assert idx_review < idx_repo_context < idx_impact

    # --- path/reason/role pairing -----------------------------------------

    def test_path_reason_role_pairing_not_mixed_up(self):
        """Two locations with different reasons and different roles: each
        path's own reason/role must appear paired with it, not swapped with
        the other location's."""
        from utilities.autopatcher.pipeline import _render_repository_context_section
        cand_a = self._candidate("alpha_file.py", [self._evidence("explicit_path", tier=3)], best_tier=3)
        cand_b = self._candidate("beta_file.py", [self._evidence("symbol_search", tier=2)], best_tier=2)
        decisions = [
            self._decision("alpha_file.py", "primary_full_file"),
            self._decision("beta_file.py", "secondary_snippet"),
        ]
        grounding = self._grounding([cand_a, cand_b], decisions)

        section = _render_repository_context_section(grounding)

        block_a = section[section.index("alpha_file.py"):section.index("beta_file.py")]
        block_b = section[section.index("beta_file.py"):]

        assert "Explicitly referenced in the security advisory" in block_a
        assert "Primary reference (full file)" in block_a
        assert "References a symbol named in the advisory" not in block_a

        assert "References a symbol named in the advisory" in block_b
        assert "Supporting reference (excerpt)" in block_b
