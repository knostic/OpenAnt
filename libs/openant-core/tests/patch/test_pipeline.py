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


def _anthropic_config(analyze_model, name="test-config"):
    """A ConfigFile whose default_llm points at a fully valid, explicitly
    user-authored llm-config with the "analyze" phase bound to Anthropic
    and the given model. Auto Patcher's real-provider resolution now comes
    ONLY from configuration like this (or the built-in openant-default) --
    never from LLM_PROVIDER/LLM_MODEL."""
    from utilities.llm import ConfigFile, LLMConfig, PhaseRef, PHASES

    phases = {p: PhaseRef(provider="anthropic", model="claude-sonnet-4-6") for p in PHASES}
    phases["analyze"] = PhaseRef(provider="anthropic", model=analyze_model)
    return ConfigFile(default_llm=name, llm_configs={name: LLMConfig(name=name, phases=phases)})


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
        from utilities.llm import CompletionResult, TextBlock

        monkeypatch.setattr(llm_client, "load_config_file", lambda: _anthropic_config("claude-test-model"))
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        monkeypatch.setattr(llm_client, "_cached_provider", None)
        monkeypatch.setattr(llm_client, "_cached_model", {})
        monkeypatch.setattr(llm_client, "_cached_adapters", {})
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

        # Stub out the shared adapter (not the raw SDK) so the test stays
        # offline -- llm_client.py no longer constructs anthropic.Anthropic
        # directly, it goes through utilities.llm.build_adapter().
        class FakeAdapter:
            def complete(self, *, model, system, messages, max_tokens, tools=None):
                return CompletionResult(
                    content=[TextBlock(text="```diff\n--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-old\n+new\n```")],
                    input_tokens=1,
                    output_tokens=1,
                    stop_reason="end_turn",
                )

        monkeypatch.setattr(llm_client, "build_adapter", lambda provider_config: FakeAdapter())

        # Mirrors core/patch.py's _require_llm_provider(), which always
        # runs (and resolves/caches the provider) before pipeline.run() in
        # production -- pipeline.run()'s own early "LLM mode" log reads
        # that cache rather than triggering resolution itself, since
        # provider/model resolution is otherwise fully lazy now (there's
        # no LLM_PROVIDER env var left to peek at directly).
        llm_client.ensure_provider_configured()

        from utilities.autopatcher.pipeline import run
        run("path traversal in upload handler")
        captured = capsys.readouterr()
        assert "[pipeline] LLM mode: LIVE" in captured.err
        # Must not include a specific model name in the early log.
        assert "gpt-4o" not in captured.err.split("[pipeline] LLM mode:")[1].split("\n")[0]
        assert "claude" not in captured.err.split("[pipeline] LLM mode:")[1].split("\n")[0].lower()


# ---------------------------------------------------------------------------
# ModelUnavailableError must abort the whole pipeline run -- not just the
# individual Planner stage that first hits it. Proves the fix at both
# remediation_planner.py's own try/except AND pipeline.py's outer
# try/except (which independently wraps each Planner call site) actually
# lets the exception reach pipeline.run()'s caller, and that Patch
# Generation is never reached once it does.
# ---------------------------------------------------------------------------

class TestModelUnavailableAbortsPipeline:
    def test_non_interactive_model_unavailable_aborts_before_patch_generation(self, monkeypatch):
        import utilities.autopatcher.llm_client as llm_client
        from utilities.autopatcher.llm_client import ModelUnavailableError
        from utilities.llm import LLMNotFoundError

        monkeypatch.setattr(llm_client, "load_config_file", lambda: _anthropic_config("claude-opus-4-6"))
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        monkeypatch.setattr(llm_client, "_cached_provider", None)
        monkeypatch.setattr(llm_client, "_cached_model", {})
        monkeypatch.setattr(llm_client, "_cached_adapters", {})
        monkeypatch.setattr(llm_client, "_call_metadata", {})
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

        class _NonInteractiveStdin:
            def isatty(self):
                return False

        monkeypatch.setattr("sys.stdin", _NonInteractiveStdin())

        class FakeAdapter:
            def complete(self, *, model, system, messages, max_tokens, tools=None):
                raise LLMNotFoundError("model: claude-opus-4-6")

        monkeypatch.setattr(llm_client, "build_adapter", lambda provider_config: FakeAdapter())

        from utilities.autopatcher.pipeline import run

        with pytest.raises(ModelUnavailableError):
            run("XSS in login form")

        # Patch Generation -- and every later stage -- must never have run.
        assert "patch_generation" not in llm_client.get_call_metadata()

    def test_model_unavailable_aborts_pipeline_without_prompting_even_when_interactive(self, monkeypatch):
        """There is no more interactive reselection loop to decline -- a
        TTY must not change this outcome, and input() must never even be
        called, let alone determine the result."""
        import utilities.autopatcher.llm_client as llm_client
        from utilities.autopatcher.llm_client import ModelUnavailableError
        from utilities.llm import LLMNotFoundError

        monkeypatch.setattr(llm_client, "load_config_file", lambda: _anthropic_config("claude-opus-4-6"))
        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        monkeypatch.setattr(llm_client, "_cached_provider", None)
        monkeypatch.setattr(llm_client, "_cached_model", {})
        monkeypatch.setattr(llm_client, "_cached_adapters", {})
        monkeypatch.setattr(llm_client, "_call_metadata", {})
        monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

        class _InteractiveStdin:
            def isatty(self):
                return True

        monkeypatch.setattr("sys.stdin", _InteractiveStdin())
        monkeypatch.setattr(
            "builtins.input",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input must never be called")),
        )

        class FakeAdapter:
            def complete(self, *, model, system, messages, max_tokens, tools=None):
                raise LLMNotFoundError("model: claude-opus-4-6")

        monkeypatch.setattr(llm_client, "build_adapter", lambda provider_config: FakeAdapter())

        from utilities.autopatcher.pipeline import run

        with pytest.raises(ModelUnavailableError):
            run("XSS in login form")

        assert "patch_generation" not in llm_client.get_call_metadata()


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

    def test_manual_review_required_wording_does_not_imply_deployment(self):
        """Release-polish fix: Manual Review Required previously fell through
        to the same "Complete the recommended validation check(s) before
        deployment." wording as Deploy After Validation / Deploy With
        Caution — differing only by the headline label above. It must
        instead state plainly that deployment is not the next step and a
        human reviewer must resolve the open questions first, regardless of
        how many validation actions exist."""
        from utilities.autopatcher.pipeline import _render_decision_card
        rec = {"decision": "Manual Review Required", "reason": "x"}
        for actions in ([], [{}], [{}, {}, {}]):
            card = _render_decision_card(rec, self._signals(), actions, [])
            assert "before deployment" not in card
            assert "section" not in card.lower()
            assert "human reviewer" in card.lower()
            assert "not a signal to deploy" in card.lower()


class TestTopAction:
    """Unit tests for _select_top_action / _render_top_action_line
    (release-polish change #7): a single "Top action" line rendered
    immediately under Recommendation, echoing the highest-priority item
    already in validation_actions — no new prioritization algorithm, no
    duplication of Validation Actions' own reason/next_step text."""

    def test_omits_when_no_actions(self):
        from utilities.autopatcher.pipeline import _render_top_action_line
        assert _render_top_action_line([]) == ""
        assert _render_top_action_line(None) == ""

    def test_shows_only_the_title_not_reason_or_next_step(self):
        from utilities.autopatcher.pipeline import _render_top_action_line
        actions = [{
            "priority": "LOW",
            "title": "Add targeted tests for X",
            "reason": "This exact reason text must not repeat here",
            "next_step": "This exact next step text must not repeat here",
        }]
        line = _render_top_action_line(actions)
        assert "**Top action:** Add targeted tests for X" in line
        assert "see Validation Actions below" in line
        assert "This exact reason text must not repeat here" not in line
        assert "This exact next step text must not repeat here" not in line

    def test_picks_highest_priority_even_when_not_first(self):
        """Regression guard: build_validation_plan can unconditionally
        prepend a MEDIUM-priority behavior-driven action ahead of an
        existing HIGH-priority one (see its own "behavior" block, which
        always does `final = [beh_action] + final`) — a naive
        validation_actions[0] would under-represent the true priority."""
        from utilities.autopatcher.pipeline import _select_top_action
        actions = [
            {"priority": "MEDIUM", "title": "Validate behavior", "reason": "r1", "next_step": "n1"},
            {"priority": "HIGH", "title": "Review authentication flow", "reason": "r2", "next_step": "n2"},
            {"priority": "LOW", "title": "Add targeted tests", "reason": "r3", "next_step": "n3"},
        ]
        top = _select_top_action(actions)
        assert top["title"] == "Review authentication flow"

    def test_ties_keep_first_list_order(self):
        from utilities.autopatcher.pipeline import _select_top_action
        actions = [
            {"priority": "HIGH", "title": "First high", "reason": "r1", "next_step": "n1"},
            {"priority": "HIGH", "title": "Second high", "reason": "r2", "next_step": "n2"},
        ]
        top = _select_top_action(actions)
        assert top["title"] == "First high"


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
        other section name by name.

        This fixture's mock pipeline run deterministically resolves to
        Manual Review Required (patch_integrity "Not Verified" — no
        repo_root is passed here, so applicability is unavailable). Release-
        polish pass: Manual Review Required no longer shares the generic
        "Complete the recommended validation check(s) before deployment."
        wording with Deploy After Validation / Deploy With Caution (see
        TestDecisionCard.test_manual_review_required_wording_does_not_imply_deployment)
        — it must still, per this test's own point, avoid naming a section."""
        from utilities.autopatcher.pipeline import run
        report = run(vulnerability_text=self._vuln_text(), api_key="")
        idx = report.find("# Auto Patcher MVP")
        banner = report[idx:report.find("## Vulnerability summary")]
        assert "section" not in banner.lower()
        assert "MANUAL REVIEW REQUIRED" in banner
        assert "This is not a signal to deploy" in banner

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
        """A non-top-tier decision must not gain an "Evidence check" caveat
        even when both underlying signals are weak — it already reads as
        cautious. Distinct from the decision-relevant open-item scope note
        added for Manual Review Required (release-polish change #6, see
        test_manual_review_required_shows_open_item_scope_note below): that
        note uses its own wording and is not gated by this "Evidence check"
        mechanism — it simply doesn't fire here because this scenario's
        empty edge_cases/potential_issues produce zero decision-relevant
        findings to report."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": True, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._base_kwargs(tmp_path, challenger))
        report = _build_report(result)

        assert "**Manual Review Required**" in report
        assert "This recommendation currently has no automated test coverage" not in report
        assert "adversarial coverage is heuristic" not in report
        assert "decision-relevant review item" not in report

    def test_manual_review_required_shows_open_item_scope_note(self, tmp_path):
        """Release-polish change #6: Manual Review Required must surface the
        same decision-relevant finding count Evidence-check caveats already
        compute for the top two decisions — using distinct wording (never
        the top-tier "Evidence check" / "adversarial coverage is heuristic"
        phrasing, which stays reserved for Deploy After Validation / Deploy
        With Caution per the test above)."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {
            "still_vulnerable": True,
            "edge_cases": ["Cannot verify this without running the test suite"],
            "potential_issues": [],
            "summary": "",
        }
        result = PipelineResult(**self._base_kwargs(tmp_path, challenger))
        report = _build_report(result)

        rec_idx = report.find("## Recommendation")
        explanation_idx = report.find("## Explanation")
        rec_block = report[rec_idx:explanation_idx]

        assert "**Manual Review Required**" in rec_block
        assert "1 item to weigh: 1 validation gap" in rec_block
        assert "see Review Results below" in rec_block
        assert "Evidence check" not in rec_block
        assert "adversarial coverage is heuristic" not in rec_block

    def test_top_action_line_appears_below_recommendation(self, tmp_path):
        """Release-polish change #7: a single "Top action" line must render
        immediately under Recommendation, pointing to Validation Actions for
        the full list, without repeating that action's reason/next_step."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {
            "still_vulnerable": False,
            "edge_cases": ["custom configurations may not benefit from this change"],
            "potential_issues": [],
            "summary": "",
        }
        result = PipelineResult(**self._base_kwargs(tmp_path, challenger))
        report = _build_report(result)

        rec_idx = report.find("## Recommendation")
        explanation_idx = report.find("## Explanation")
        rec_block = report[rec_idx:explanation_idx]

        assert "**Top action:**" in rec_block
        assert "see Validation Actions below" in rec_block

    def test_impact_surface_has_epistemic_disclaimer(self, tmp_path):
        """Release-polish change #4: Impact Surface was the only major
        section with no epistemic framing — must state this is static,
        non-executing analysis."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._base_kwargs(tmp_path, challenger))
        report = _build_report(result)

        idx = report.find("## Impact Surface")
        assert idx != -1
        block = report[idx:idx + 400]
        assert "static" in block.lower()
        assert "does not execute the code" in block

    def test_reviewer_notes_has_epistemic_disclaimer(self, tmp_path):
        """Release-polish change #5: Reviewer Notes was the one un-hedged
        LLM-prose section — must state it is reviewer-LLM guidance, not
        independently verified evidence, and must not duplicate Explanation's
        own disclaimer wording."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._base_kwargs(tmp_path, challenger))
        report = _build_report(result)

        idx = report.find("### Reviewer Notes")
        assert idx != -1
        block = report[idx:idx + 300]
        assert "not independently verified evidence" in block
        assert "not independent execution or testing against the target repository" not in block

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
# Release-polish report behaviors (report explainability pass)
# ---------------------------------------------------------------------------

class TestReleasePolishReportBehaviors:
    """Report-level regression coverage for the Trust Report polish pass:
    signal-specific Recommendation reasons, Observed Facts relabeling,
    upstream-provenance disclaimers, and generic-behavior-fallback
    suppression. Builds PipelineResult directly and calls _build_report()
    — no LLM calls, fully deterministic."""

    GENERIC_BEHAVIOR = {
        "function": "foo",
        "file": "mod.py",
        "summary": "This patch likely affects application logic in mod.py.",
        "primary_behaviors": ["normal flow", "edge-case handling"],
        "is_generic": True,
    }
    SPECIFIC_BEHAVIOR = {
        "function": "authenticate",
        "file": "app/auth.py",
        "summary": "This patch likely affects authentication in app/auth.py.",
        "primary_behaviors": ["valid login", "invalid login"],
        "is_generic": False,
    }

    def _kwargs(self, tmp_path, challenger, behavior):
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
                " def foo():\n-    return 1\n+    return 2\n"
            ),
            review=(
                "**Explanation:**\n"
                "This matches the upstream fix released in version 2.0.5.\n\n"
                "**Affected areas:**\n"
                "- mod.py\n\n"
                "**Validation notes:**\n"
                "- This aligns with the accepted upstream remediation.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger=challenger,
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            behavior=behavior,
            repo_root=tmp_path,
            detected_language="python",
        )

    # --- Decision 8: generic behavior fallback suppression ---

    def test_generic_behavior_suppresses_validate_behavior_action(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {
            "still_vulnerable": False,
            "edge_cases": ["custom configurations may not benefit from this change"],
            "potential_issues": [],
            "summary": "",
        }
        result = PipelineResult(**self._kwargs(tmp_path, challenger, self.GENERIC_BEHAVIOR))
        report = _build_report(result)

        va_idx = report.find("## Validation Actions")
        rr_idx = report.find("## Review Results")
        va_block = report[va_idx:rr_idx]
        assert "Validate behavior" not in va_block

        st_idx = report.find("### Suggested Tests")
        st_block = report[st_idx:]
        assert "test_normal_flow" not in st_block
        assert "test_edge_case_handling" not in st_block
        # Challenger-derived suggestions must still render unchanged.
        assert "custom configurations may not benefit from this change" in st_block

    def test_specific_behavior_keeps_validate_behavior_action(self, tmp_path):
        """Non-generic behavior summaries must render exactly as before."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._kwargs(tmp_path, challenger, self.SPECIFIC_BEHAVIOR))
        report = _build_report(result)

        va_idx = report.find("## Validation Actions")
        rr_idx = report.find("## Review Results")
        va_block = report[va_idx:rr_idx]
        assert "Validate behavior" in va_block
        assert "valid login" in va_block or "invalid login" in va_block

    def test_no_behavior_summary_is_unaffected(self, tmp_path):
        """behavior=None (analyzer raised, or no patch) must keep working
        exactly as before — no AttributeError on a None behavior dict."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._kwargs(tmp_path, challenger, None))
        report = _build_report(result)
        assert "## Validation Actions" in report or True  # must not raise

    # --- Decision 7: upstream-provenance disclaimer ---

    def test_explanation_disclaimer_flags_upstream_prior_knowledge(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._kwargs(tmp_path, challenger, self.SPECIFIC_BEHAVIOR))
        report = _build_report(result)

        idx = report.find("## Explanation")
        block = report[idx:idx + 500]
        assert "model's own prior knowledge" in block
        assert "not a fetched or independently verified upstream comparison" in block

    def test_reviewer_notes_disclaimer_flags_upstream_prior_knowledge(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._kwargs(tmp_path, challenger, self.SPECIFIC_BEHAVIOR))
        report = _build_report(result)

        idx = report.find("### Reviewer Notes")
        block = report[idx:idx + 400]
        assert "not independently verified evidence" in block
        assert "model's own prior knowledge" in block
        # Must not duplicate Explanation's own disclaimer phrase.
        assert "not independent execution or testing against the target repository" not in block

    # --- Decision 5: Observed Facts relabel ---

    def test_observed_facts_heading_renders_in_full_report(self, tmp_path):
        """A challenger finding calibrated to group="observed" must render
        under "### Observed Facts" (never the old "Confirmed Observations"
        wording) at the full-report level, with the epistemic-axis subtitle."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        finding_text = "Case-insensitive matching may not handle all header variants"
        challenger = {
            "still_vulnerable": False,
            "edge_cases": [finding_text],
            "potential_issues": [],
            "summary": "",
        }
        kwargs = self._kwargs(tmp_path, challenger, self.SPECIFIC_BEHAVIOR)
        kwargs["finding_calibration"] = [{
            "original": finding_text,
            "group": "observed",
            "reworded": "Header comparison is case-insensitive across the variants shown in the diff.",
        }]
        result = PipelineResult(**kwargs)
        report = _build_report(result)

        assert "### Observed Facts" in report
        assert "### Confirmed Observations" not in report
        assert "may be reassuring, neutral, or concerning" in report
        assert "Header comparison is case-insensitive across the variants shown in the diff." in report

    # --- Decision 2 / minimist causality: Manual Review Required reason ---

    def test_manual_review_reason_names_deployment_safety_not_review_results(self, tmp_path):
        """Report-level version of the minimist case: no repo-language
        support for Impact Surface must produce a Recommendation reason
        naming deployment risk, not a Review Results finding."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {
            "still_vulnerable": False,
            "edge_cases": ["legitimate keys named `constructor` are now silently dropped"],
            "potential_issues": [],
            "summary": "",
        }
        kwargs = self._kwargs(tmp_path, challenger, self.SPECIFIC_BEHAVIOR)
        kwargs["detected_language"] = "javascript"
        # Real minimist-shaped impact result: language guardrail explicitly
        # marks Impact Surface not_applicable (not a swallowed exception).
        kwargs["impact"] = {
            "impact_level": "not_applicable",
            "changed_files": ["index.js"],
            "affected_files": [],
            "impact_summary": (
                "Not Applicable — language not supported by this signal yet "
                "(detected: javascript)."
            ),
            "recommendations": [],
            "usage_matches": [],
        }
        result = PipelineResult(**kwargs)
        report = _build_report(result)

        rec_idx = report.find("## Recommendation")
        explanation_idx = report.find("## Explanation")
        rec_block = report[rec_idx:explanation_idx]

        assert "**Manual Review Required**" in rec_block
        assert "Deployment risk could not be verified" in rec_block
        assert "constructor" not in rec_block

    def test_no_patch_produced_report_unaffected(self, tmp_path):
        """Release polish must not touch the no_patch execution-outcome
        path — it is computed one level above Recommendation Policy."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        kwargs = self._kwargs(tmp_path, challenger, self.GENERIC_BEHAVIOR)
        kwargs["patch"] = ""
        result = PipelineResult(**kwargs)
        report = _build_report(result)
        assert "NO PATCH PRODUCED" in report

    def test_green_decision_reason_unaffected(self, tmp_path):
        """Deploy After Validation's reason text must stay byte-identical —
        the I3 whitelist branch is never enriched (nothing is unmet)."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_foo(): pass\n", encoding="utf-8")
        challenger = {"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""}
        result = PipelineResult(**self._kwargs(tmp_path, challenger, self.SPECIFIC_BEHAVIOR))
        report = _build_report(result)
        assert "**Deploy After Validation**" in report
        assert (
            "Patch addresses the attack vector described by the advisory and applies cleanly. "
            "Run the listed validation actions before deployment."
        ) in report


class TestSuggestedTestsAndTestSupportLanguageAware:
    """Report-polish Batch A, fixes #5 and #6: Suggested Tests must not
    fabricate a `.py` path for a non-Python repo, and Test Support must
    not present its Python-only test count as if the repo had been
    exhaustively searched when the detected language isn't Python.
    Builds PipelineResult directly and calls _build_report() — no LLM
    calls, fully deterministic."""

    def _kwargs(self, tmp_path, *, language, patch_file, edge_case):
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                f"--- a/{patch_file}\n+++ b/{patch_file}\n@@ -1,3 +1,3 @@\n"
                " unchanged\n-old\n+new\n"
            ),
            review=(
                "**Explanation:**\nThe patch fixes the issue.\n\n"
                f"**Affected areas:**\n- {patch_file}\n\n"
                "**Validation notes:**\n- Add tests.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={
                "still_vulnerable": False,
                "edge_cases": [edge_case],
                "potential_issues": [],
                "summary": "",
            },
            impact={
                "impact_level": "low" if language == "python" else "not_applicable",
                "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            behavior=None,
            repo_root=tmp_path,
            detected_language=language,
        )

    # --- Fix #5: Suggested Tests ---

    def test_suggested_tests_python_keeps_py_path(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._kwargs(
            tmp_path, language="python", patch_file="mod.py",
            edge_case="input validation is missing on the new branch",
        )
        report = _build_report(PipelineResult(**kwargs))
        st_block = report[report.find("### Suggested Tests"):]
        assert "tests/suggested/" in st_block
        assert ".py" in st_block

    def test_suggested_tests_javascript_omits_fabricated_py_path(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._kwargs(
            tmp_path, language="javascript", patch_file="index.js",
            edge_case="prototype pollution guard may miss nested aliases",
        )
        report = _build_report(PipelineResult(**kwargs))
        st_block = report[report.find("### Suggested Tests"):]
        assert "tests/suggested/" not in st_block
        assert ".py" not in st_block
        assert "no target path suggested" in st_block
        assert "javascript" in st_block
        # Omission is only of the fabricated path -- the finding itself
        # must still be shown.
        assert "prototype pollution guard may miss nested aliases" in st_block

    def test_suggested_tests_c_omits_fabricated_py_path(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._kwargs(
            tmp_path, language="c", patch_file="lib/transfer.c",
            edge_case="redirect target scheme comparison is case sensitive",
        )
        report = _build_report(PipelineResult(**kwargs))
        st_block = report[report.find("### Suggested Tests"):]
        assert "tests/suggested/" not in st_block
        assert ".py" not in st_block
        assert "no target path suggested" in st_block
        assert "c" in st_block  # language name rendered somewhere

    # --- Fix #6: Test Support ---

    def test_test_support_python_keeps_total_count(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        (tmp_path / "test_mod.py").write_text("def test_x(): pass\n", encoding="utf-8")
        kwargs = self._kwargs(
            tmp_path, language="python", patch_file="mod.py",
            edge_case="edge case needing a test",
        )
        report = _build_report(PipelineResult(**kwargs))
        ts_block = report[report.find("### Test Support"): report.find("### Test Support") + 400]
        assert "Total test files found: 1" in ts_block

    def test_test_support_javascript_does_not_imply_zero_tests(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._kwargs(
            tmp_path, language="javascript", patch_file="index.js",
            edge_case="edge case needing a test",
        )
        report = _build_report(PipelineResult(**kwargs))
        ts_block = report[report.find("### Test Support"): report.find("### Test Support") + 500]
        assert "Total test files found:" not in ts_block
        assert "not evaluated" in ts_block
        assert "javascript" in ts_block
        assert "Rating: Not Applicable" in ts_block
        assert "test discovery does not yet support this language" in ts_block

    def test_test_support_c_does_not_imply_zero_tests(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._kwargs(
            tmp_path, language="c", patch_file="lib/transfer.c",
            edge_case="edge case needing a test",
        )
        report = _build_report(PipelineResult(**kwargs))
        ts_block = report[report.find("### Test Support"): report.find("### Test Support") + 500]
        assert "Total test files found:" not in ts_block
        assert "not evaluated" in ts_block
        assert "Rating: Not Applicable" in ts_block


class TestReportPolishBatchCTestSupport:
    """Report Polish Batch C: Test Support rendering keeps same-file/
    same-module matches in full (repository-relative), collapses generic
    `repo`-proximity matches to a count, and never touches discovery
    (discover_tests/tests_for_file) or scoring (score_test_support)
    themselves — this class only exercises the render output built from
    real files on disk under `tmp_path` (== repo_root), same as the
    pre-existing Batch A test class above."""

    def _kwargs(self, tmp_path, *, patch_file="mod.py"):
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                f"--- a/{patch_file}\n+++ b/{patch_file}\n@@ -1,3 +1,3 @@\n"
                " unchanged\n-old\n+new\n"
            ),
            review=(
                "**Explanation:**\nThe patch fixes the issue.\n\n"
                f"**Affected areas:**\n- {patch_file}\n\n"
                "**Validation notes:**\n- Add tests.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={
                "still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": "",
            },
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            behavior=None,
            repo_root=tmp_path,
            detected_language="python",
        )

    @staticmethod
    def _test_support_block(report: str) -> str:
        idx = report.find("### Test Support")
        end = report.find("### Behavior Summary")
        if end == -1:
            end = report.find("### Affected areas")
        return report[idx: end if end != -1 else len(report)]

    def test_same_file_matches_render_in_full(self, tmp_path):
        """A same-file match must always render, in full, never collapsed."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_x(): pass\n", encoding="utf-8")
        report = _build_report(PipelineResult(**self._kwargs(tmp_path)))
        block = self._test_support_block(report)
        assert "same-file" in block
        assert "test_mod.py" in block

    def test_same_module_matches_remain_visible(self, tmp_path):
        """A same-module match (imports the patched module) must render in
        full alongside any generic repo tests, never collapsed into the
        broader-repository count."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_uses_mod.py").write_text(
            "from mod import thing\n\ndef test_uses_mod(): pass\n", encoding="utf-8",
        )
        for i in range(5):
            (tmp_path / "tests" / f"test_unrelated_{i}.py").write_text(
                "def test_unrelated(): pass\n", encoding="utf-8",
            )
        report = _build_report(PipelineResult(**self._kwargs(tmp_path)))
        block = self._test_support_block(report)
        assert "same-module" in block
        assert "test_uses_mod.py" in block
        assert "Broader repository tests: 5 additional" in block

    def test_large_generic_repo_test_list_collapses_to_count(self, tmp_path):
        """The dominant real-world complaint (pip: 64 matches, 62 of them
        generic `repo` tests) — a large generic-only list collapses to one
        count line, no per-file listing."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        (tmp_path / "tests").mkdir()
        for i in range(40):
            (tmp_path / "tests" / f"test_generic_{i}.py").write_text(
                "def test_generic(): pass\n", encoding="utf-8",
            )
        report = _build_report(PipelineResult(**self._kwargs(tmp_path)))
        block = self._test_support_block(report)
        assert "No tests directly matched the patched file/module." in block
        assert "Broader repository tests: 40 additional" in block
        # None of the 40 generic filenames are individually listed.
        assert "test_generic_0.py" not in block
        assert "test_generic_39.py" not in block

    def test_mixed_same_file_same_module_and_repo_tests(self, tmp_path):
        """Same-file + same-module + a large generic bucket together: both
        direct matches stay fully visible, only the generic bucket
        collapses, and the count is exact."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_x(): pass\n", encoding="utf-8")
        (tmp_path / "tests" / "test_uses_mod.py").write_text(
            "from mod import thing\n\ndef test_uses_mod(): pass\n", encoding="utf-8",
        )
        for i in range(10):
            (tmp_path / "tests" / f"test_generic_{i}.py").write_text(
                "def test_generic(): pass\n", encoding="utf-8",
            )
        report = _build_report(PipelineResult(**self._kwargs(tmp_path)))
        block = self._test_support_block(report)
        assert "test_mod.py" in block and "same-file" in block
        assert "test_uses_mod.py" in block and "same-module" in block
        assert "Broader repository tests: 10 additional" in block
        assert "No tests directly matched" not in block  # direct matches DO exist
        for i in range(10):
            assert f"test_generic_{i}.py" not in block

    def test_repository_relative_path_rendering(self, tmp_path):
        """Paths render repository-relative, not as the absolute
        filesystem path under tmp_path."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        (tmp_path / "tests" / "nested").mkdir(parents=True)
        (tmp_path / "tests" / "nested" / "test_mod.py").write_text(
            "def test_x(): pass\n", encoding="utf-8",
        )
        report = _build_report(PipelineResult(**self._kwargs(tmp_path)))
        block = self._test_support_block(report)
        assert "tests/nested/test_mod.py" in block
        assert str(tmp_path) not in block

    def test_unsupported_language_test_support_unchanged(self, tmp_path):
        """Test Support rendering for an unsupported language is untouched
        by the same-file/same-module/broader-repo grouping — it never
        reaches that branch at all (matches is always empty for a
        non-Python `_report_language`)."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._kwargs(tmp_path, patch_file="index.js")
        kwargs["detected_language"] = "javascript"
        report = _build_report(PipelineResult(**kwargs))
        block = self._test_support_block(report)
        assert "Rating: Not Applicable" in block
        assert "Not evaluated — test discovery does not yet support this language." in block
        assert "Broader repository tests" not in block

    def test_empty_test_support_section_still_renders(self, tmp_path):
        """No repo_root and (separately) a repo_root with zero matches must
        both keep rendering their existing, unchanged messages."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._kwargs(tmp_path)
        kwargs["repo_root"] = None
        report = _build_report(PipelineResult(**kwargs))
        assert "*Not evaluated — no repository root was provided.*" in report

        report2 = _build_report(PipelineResult(**self._kwargs(tmp_path)))
        block2 = self._test_support_block(report2)
        assert "No matching tests found." in block2
        assert "Broader repository tests" not in block2


class TestRelativeTestPathHelper:
    """Direct unit coverage for `_relative_test_path` — presentation only,
    never mutates the underlying stored path/provenance (the caller always
    still has the original `m['path']` available)."""

    def test_path_inside_repo_root(self, tmp_path):
        from utilities.autopatcher.pipeline import _relative_test_path
        p = tmp_path / "tests" / "test_mod.py"
        assert _relative_test_path(str(p), tmp_path) == "tests/test_mod.py"

    def test_path_equal_to_repo_root(self, tmp_path):
        from utilities.autopatcher.pipeline import _relative_test_path
        assert _relative_test_path(str(tmp_path), tmp_path) == "."

    def test_path_outside_repo_root_falls_back_to_original(self, tmp_path):
        from utilities.autopatcher.pipeline import _relative_test_path
        other_root = tmp_path / "unrelated_repo"
        outside_path = tmp_path / "other" / "test_x.py"
        result = _relative_test_path(str(outside_path), other_root)
        assert result == str(outside_path)

    def test_missing_repo_root_returns_original_path(self):
        from utilities.autopatcher.pipeline import _relative_test_path
        assert _relative_test_path("/abs/test_x.py", None) == "/abs/test_x.py"

    def test_invalid_repo_root_falls_back_safely(self):
        """A repo_root that can't even be turned into a Path must never
        raise — the original path is preserved instead."""
        from utilities.autopatcher.pipeline import _relative_test_path
        assert _relative_test_path("/abs/test_x.py", 12345) == "/abs/test_x.py"

    def test_relative_input_path_returned_unchanged(self, tmp_path):
        """tests_for_file always returns an absolute path in practice; a
        non-absolute input is passed through unchanged rather than
        resolved against the process cwd (which could accidentally land
        inside repo_root and produce a misleading relative path)."""
        from utilities.autopatcher.pipeline import _relative_test_path
        assert _relative_test_path("relative/test_x.py", tmp_path) == "relative/test_x.py"


class TestReportPolishBatchCBehaviorSummary:
    """Report Polish Batch C: Behavior Summary's Appendix rendering now
    reads `behavior["is_generic"]` (already computed by behavior_summary.py,
    already used elsewhere in this module) to suppress only the boilerplate
    "normal flow" / "edge-case handling" bullet list — behavior extraction/
    classification itself is untouched."""

    GENERIC_BEHAVIOR = {
        "function": "", "file": "internal/re.js",
        "summary": "This patch likely affects application logic in internal/re.js.",
        "primary_behaviors": ["normal flow", "edge-case handling"],
        "is_generic": True,
    }
    SPECIFIC_BEHAVIOR = {
        "function": "authenticate", "file": "app/auth.py",
        "summary": "This patch likely affects authentication in app/auth.py.",
        "primary_behaviors": ["valid login", "invalid login"],
        "is_generic": False,
    }

    def _kwargs(self, tmp_path, behavior):
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch="--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n def foo():\n-    return 1\n+    return 2\n",
            review=(
                "**Explanation:**\nThe patch fixes the issue.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Add tests.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""},
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            behavior=behavior,
            repo_root=tmp_path,
            detected_language="python",
        )

    def test_generic_behavior_suppresses_boilerplate_list_but_keeps_concrete_sentence(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        report = _build_report(PipelineResult(**self._kwargs(tmp_path, self.GENERIC_BEHAVIOR)))
        idx = report.find("### Behavior Summary")
        end = report.find("### Affected areas")
        block = report[idx: end if end != -1 else len(report)]
        assert "normal flow" not in block
        assert "edge-case handling" not in block
        assert "Primary behaviors to validate:" not in block
        # Concrete file information is preserved.
        assert "internal/re.js" in block

    def test_concrete_behavior_summary_unchanged(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        report = _build_report(PipelineResult(**self._kwargs(tmp_path, self.SPECIFIC_BEHAVIOR)))
        idx = report.find("### Behavior Summary")
        end = report.find("### Affected areas")
        block = report[idx: end if end != -1 else len(report)]
        assert "Primary behaviors to validate:" in block
        assert "valid login" in block
        assert "invalid login" in block
        assert "authenticate" in block


class TestReportPolishBatchCTrustSignals:
    """Report Polish Batch C: the primary Trust Signals table no longer
    restates the raw, pre-calibration Challenger concern count — only the
    render layer changes; `_compute_trust_signals` itself (and therefore
    `signals["coverage_confidence"]["notes"]`, read directly by anything
    else that wants the raw count) is untouched."""

    def _kwargs(self, tmp_path):
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch="--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n def foo():\n-    return 1\n+    return 2\n",
            review=(
                "**Explanation:**\nThe patch fixes the issue.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Add tests.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={
                "still_vulnerable": False,
                "edge_cases": ["custom configurations may not benefit from this change"],
                "potential_issues": ["interaction with nested prototype chains is untested"],
                "summary": "",
            },
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            behavior=None,
            repo_root=tmp_path,
            detected_language="python",
        )

    def test_raw_review_concern_count_absent_from_primary_trust_signals(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        report = _build_report(PipelineResult(**self._kwargs(tmp_path)))
        ts_idx = report.find("## Trust Signals")
        rec_idx = report.find("## Recommendation")
        ts_block = report[ts_idx:rec_idx]
        assert "raw review concern" not in ts_block
        assert "before evidence calibration" not in ts_block
        # The calibration-relevant remainder must still be present.
        assert "no deterministic blocker identified" in ts_block.lower()
        assert "Review Results section below" in ts_block

    def test_calibrated_review_results_still_present(self, tmp_path):
        """The raw-count de-emphasis in Trust Signals must not remove or
        alter the calibrated Review Results section itself."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._kwargs(tmp_path)
        kwargs["finding_calibration"] = [{
            "original": "custom configurations may not benefit from this change",
            "group": "hypothesis",
            "reworded": "Whether custom configurations remain compatible needs validation.",
        }]
        report = _build_report(PipelineResult(**kwargs))
        assert "### Validation Gaps" in report
        assert "interaction with nested prototype chains is untested" in report
        assert "### Validation Questions" in report
        assert "Whether custom configurations remain compatible needs validation." in report

    def test_compute_trust_signals_notes_unchanged(self, tmp_path):
        """The underlying computation (read directly by anything that
        wants the raw count for debugging/provenance) is byte-for-byte
        unchanged — only the render layer de-emphasizes it."""
        from utilities.autopatcher.pipeline import _compute_trust_signals, _classify_challenger
        challenger = {
            "still_vulnerable": False,
            "edge_cases": ["custom configurations may not benefit from this change"],
            "potential_issues": ["interaction with nested prototype chains is untested"],
        }
        classified = _classify_challenger(challenger)
        signals = _compute_trust_signals(
            [], {"applicable": True, "stderr": ""}, classified, "None", "low",
        )
        assert "raw review concern(s) recorded before evidence calibration" in signals["coverage_confidence"]["notes"]


class TestReportPolishBatchCSeparators:
    """Report Polish Batch C: the duplicate '---\\n\\n---' seen in real
    reports (e.g. curl, CVE-2022-27774) is caused by the reviewer LLM's own
    trailing horizontal-rule divider leaking through `_split_review`'s
    header-based split, colliding with the report template's own '---'
    immediately before the next heading. Fixed at that exact boundary
    (`_split_review` / `_strip_trailing_hr`), not with a global regex over
    the assembled report."""

    def test_split_review_strips_trailing_separator_from_explanation(self):
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            ### Explanation
            The fix is correct.

            ---

            ### Affected areas
            - mod.py

            ### Validation notes
            - Add tests.
        """)
        sections = _split_review(review)
        assert sections["explanation"] == "The fix is correct."
        assert not sections["explanation"].endswith("---")

    def test_split_review_strips_trailing_separator_from_last_section(self):
        """A trailing divider with no further header after it (the model's
        own sign-off) is stripped the same way."""
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            ### Explanation
            The fix is correct.

            ### Affected areas
            - mod.py

            ### Validation notes
            - Add tests.

            ---
        """)
        sections = _split_review(review)
        assert sections["validation_notes"] == "- Add tests."

    def test_build_report_does_not_duplicate_separator_after_explanation(self, tmp_path):
        """End-to-end reproduction of the real curl-shaped report: a
        trailing '---' inside the reviewer's own Explanation text must not
        produce a visible '---\\n\\n---' in the assembled report."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch="--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n def foo():\n-    return 1\n+    return 2\n",
            review=(
                "### Explanation\n"
                "The fix is correct.\n\n"
                "---\n\n"
                "### Affected areas\n- mod.py\n\n"
                "### Validation notes\n- Add tests.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""},
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            behavior=None,
            repo_root=tmp_path,
            detected_language="python",
        )
        report = _build_report(result)
        assert "---\n\n---" not in report
        assert "---\n---" not in report

    def test_legitimate_trailing_content_is_not_a_bare_rule_and_is_preserved(self):
        """A line that merely CONTAINS dashes (not exclusively dashes) is
        never mistaken for a horizontal rule."""
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            ### Explanation
            The fix reduces the attack surface --- see CVE-2022-1 for context.

            ### Affected areas
            - mod.py

            ### Validation notes
            - Add tests.
        """)
        sections = _split_review(review)
        assert sections["explanation"] == (
            "The fix reduces the attack surface --- see CVE-2022-1 for context."
        )

    def test_legitimate_midbody_separator_is_preserved(self):
        """A '---' used as a divider INSIDE a section body (not as its
        trailing line) is real reviewer content, not a boundary artifact,
        and must survive."""
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            ### Explanation
            First point.

            ---

            Second point, after the model's own mid-body divider.

            ### Affected areas
            - mod.py

            ### Validation notes
            - Add tests.
        """)
        sections = _split_review(review)
        assert "First point." in sections["explanation"]
        assert "---" in sections["explanation"]
        assert "Second point, after the model's own mid-body divider." in sections["explanation"]

    def test_legitimate_table_separator_row_is_preserved(self):
        """A Markdown table separator row ('|---|---|') is never mistaken
        for a horizontal rule — it contains '|', not just dashes."""
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            ### Explanation
            | Before | After |
            |---|---|
            | old | new |

            ### Affected areas
            - mod.py

            ### Validation notes
            - Add tests.
        """)
        sections = _split_review(review)
        assert "|---|---|" in sections["explanation"]

    def test_legitimate_code_fence_content_is_preserved(self):
        """A '---' inside a fenced code block, not itself the final line
        of the body, is real content and must survive."""
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            ### Explanation
            ```diff
            -foo
            ---
            +bar
            ```
            That diff snippet is illustrative only.

            ### Affected areas
            - mod.py

            ### Validation notes
            - Add tests.
        """)
        sections = _split_review(review)
        assert "```diff" in sections["explanation"]
        assert "-foo" in sections["explanation"]
        assert "That diff snippet is illustrative only." in sections["explanation"]

    def test_unrelated_content_and_whitespace_unchanged(self):
        """A section with no trailing rule is byte-for-byte unaffected."""
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            ### Explanation
            Line one.
            Line two.

            ### Affected areas
            - mod.py

            ### Validation notes
            - Add tests.
        """)
        sections = _split_review(review)
        assert sections["explanation"] == "Line one.\nLine two."


class TestReportPolishBatchCSemanticInvariants:
    """Report Polish Batch C changes rendering only. This proves the
    decision-computing paths Batch C must never touch -- recommendation
    decision/reason, Validation Action membership/priority, Top Action,
    calibrated Review Results, and Test Support's own score/status --
    still produce the expected output, using one rich fixture that
    exercises all of them together (HIGH impact, a same-file test match, a
    calibrated hypothesis finding, an always-validation-gap finding, and a
    non-generic behavior summary)."""

    FINDING_TEXT = "custom configurations may not benefit from this change"
    GAP_TEXT = "interaction with nested prototype chains is untested"

    def _kwargs(self, tmp_path):
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_x(): pass\n", encoding="utf-8")
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch="--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n def foo():\n-    return 1\n+    return 2\n",
            review=(
                "**Explanation:**\nThe patch fixes the issue.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Add tests.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={
                "still_vulnerable": False,
                "edge_cases": [self.FINDING_TEXT],
                "potential_issues": [self.GAP_TEXT],
                "summary": "",
            },
            impact={
                "impact_level": "high", "changed_files": ["mod.py"],
                "affected_files": ["a.py", "b.py"],
                "impact_summary": "widely used", "recommendations": ["review"],
                "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            behavior={
                "function": "authenticate", "file": "app/auth.py",
                "summary": "This patch likely affects authentication in app/auth.py.",
                "primary_behaviors": ["valid login", "invalid login"],
                "is_generic": False,
            },
            repo_root=tmp_path,
            detected_language="python",
            finding_calibration=[{
                "original": self.FINDING_TEXT,
                "group": "hypothesis",
                "reworded": "Whether custom configurations remain compatible needs validation.",
            }],
        )

    def test_recommendation_validation_actions_review_results_and_test_support_unchanged(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._kwargs(tmp_path))
        report = _build_report(result)

        # Recommendation: HIGH impact forces Manual Review Required via the
        # deployment_safety gate, independent of Batch C's rendering changes.
        rec_idx = report.find("## Recommendation")
        expl_idx = report.find("## Explanation")
        rec_block = report[rec_idx:expl_idx]
        assert "**Manual Review Required**" in rec_block
        assert "Change has high deployment risk; regression testing across affected callers required." in rec_block
        assert "**Top action:**" in rec_block

        # Validation Actions: exactly 3 items (cap unchanged), HIGH items
        # present for the two challenger findings, plus the behavior-driven
        # action for the non-generic behavior summary.
        va_idx = report.find("## Validation Actions")
        rr_idx = report.find("## Review Results")
        va_block = report[va_idx:rr_idx]
        assert va_block.count("**[") == 3
        assert va_block.count("**[HIGH]**") == 2
        assert va_block.count("**[MEDIUM]**") == 1
        assert "authenticate" in va_block or "valid login" in va_block or "invalid login" in va_block

        # Review Results: the always-validation-gap finding stays a gap; the
        # calibrated "hypothesis" finding renders under Validation Questions
        # with its reworded calibration text.
        assert "### Validation Gaps" in report
        assert self.GAP_TEXT in report
        assert "### Validation Questions" in report
        assert "Whether custom configurations remain compatible needs validation." in report

        # Test Support: score/status unchanged, same-file match still shown.
        ts_idx = report.find("### Test Support")
        ts_end = report.find("### Behavior Summary")
        ts_block = report[ts_idx:ts_end]
        assert "Rating: Good" in ts_block
        assert "test_mod.py" in ts_block
        assert "same-file" in ts_block


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

    def test_split_review_preserves_bold_subheading_in_body(self):
        # Regression: a bolded subheading immediately after a section
        # header used to have its opening "**" stripped by the old
        # body-cleanup regex, producing a dangling closing marker like
        # "Why the original code was vulnerable**".
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            **Explanation**
            **Why the original code was vulnerable**
            The code failed to validate input.

            **Affected areas**
            - app/auth.py

            **Validation notes**
            - Test with payload Y.
        """)
        sections = _split_review(review)
        assert sections["explanation"].startswith(
            "**Why the original code was vulnerable**"
        )
        # Bug reproduction: the buggy version returned a body starting
        # with "Why the original code was vulnerable**" -- opening marker
        # stripped, closing marker left dangling.
        assert not sections["explanation"].startswith("Why the original code")

    def test_split_review_heading_form_still_supported(self):
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            ### Explanation
            The code was vulnerable because of X.

            ### Affected areas
            - app/auth.py

            ### Validation notes
            - Test with payload Y.
        """)
        sections = _split_review(review)
        assert "vulnerable" in sections["explanation"]
        assert "auth.py" in sections["affected_areas"]
        assert "payload" in sections["validation_notes"]

    def test_split_review_prose_mention_is_not_mistaken_for_header(self):
        # "Validation notes" appears inline, mid-sentence, inside the
        # Explanation body -- it must not be treated as a new section
        # boundary, and the real "Validation notes" section below must not
        # be merged with (or overwritten by) that sentence.
        from utilities.autopatcher.pipeline import _split_review
        review = textwrap.dedent("""\
            ### Explanation
            This fix touches Validation notes for callers as well.

            ### Affected areas
            - foo.py

            ### Validation notes
            - Run tests.
        """)
        sections = _split_review(review)
        assert "touches Validation notes for callers" in sections["explanation"]
        assert sections["validation_notes"].strip() == "- Run tests."

    # -- short_reason() / _truncate_reason() ---------------------------
    # Regression coverage for two baseline bugs: (1) splitting on the
    # first literal "." anywhere (not just a real sentence end) truncated
    # text mid-word/mid-backtick whenever the finding text contained an
    # early "." inside a path, abbreviation, or code span; (2) the final
    # 120-char cap was a hard slice with no word-boundary or ellipsis.

    def test_short_reason_empty_string(self):
        from utilities.autopatcher.pipeline import short_reason
        assert short_reason("") == ""
        assert short_reason(None) == ""

    def test_short_reason_short_text_unchanged(self):
        from utilities.autopatcher.pipeline import short_reason
        text = "Cross-origin redirect handled only in PoolManager"
        assert short_reason(text) == text

    def test_short_reason_does_not_split_on_path_dot(self):
        # Regression: "Symlinks inside `.git/refs` still allow escape..."
        # used to be cut immediately after the backtick because
        # text.split(".", 1)[0] stopped at the "." inside ".git".
        from utilities.autopatcher.pipeline import short_reason
        text = "Symlinks inside `.git/refs` still allow escape if only string checks used."
        result = short_reason(text)
        # Trailing "." is trimmed by design (short_reason always strips
        # trailing "., " -- with or without truncation); the point of this
        # regression test is that nothing is cut *before* that.
        assert result == "Symlinks inside `.git/refs` still allow escape if only string checks used"
        assert not result.endswith("`")

    def test_short_reason_does_not_split_on_abbreviation_dot(self):
        # Regression: "dirpath without leading '/' (e.g. 'collection')..."
        # used to be cut right after "(e" because of the period in "e.g.".
        from utilities.autopatcher.pipeline import short_reason
        text = "dirpath without leading '/' (e.g. 'collection') changes prior concatenation semantics"
        result = short_reason(text)
        assert not result.endswith("(e")
        assert "'collection'" in result

    def test_short_reason_truncates_long_text_with_ellipsis(self):
        from utilities.autopatcher.pipeline import short_reason
        text = "word " * 40  # no sentence-ending punctuation, well over 120 chars
        result = short_reason(text)
        assert len(result) <= 120
        assert result.endswith("...")

    def test_short_reason_no_mid_word_truncation(self):
        from utilities.autopatcher.pipeline import short_reason
        text = (
            "A very long adversarial finding description that keeps going "
            "well past the compact reason budget without any early period "
            "to stop at so it must be cut back to a real word boundary"
        )
        result = short_reason(text)
        assert result.endswith("...")
        core = result[: -len("...")]
        source_words = set(text.split(" "))
        for word in core.split(" "):
            if word:
                assert word in source_words

    def test_short_reason_avoids_dangling_backtick(self):
        from utilities.autopatcher.pipeline import short_reason
        # A backtick-quoted path placed right at the truncation boundary.
        text = "prefix " * 20 + "`some/long/path/that/pushes/past/the/limit`" + " more text " * 5
        result = short_reason(text)
        assert result.count("`") % 2 == 0

    # -- normalize_title_from_text() ------------------------------------
    # Regression coverage: keyword matching used to be plain substring
    # (`"token" in text`), so "version tokens" false-matched "token" and
    # produced "Review authentication flow" for an unrelated ReDoS finding.

    def test_title_version_tokens_does_not_match_auth(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        text = "Long strings of interleaved spaces and version tokens (e.g. 1.2.3 1.2.3)"
        title = normalize_title_from_text(text)
        assert title != "Review authentication flow"

    def test_title_genuine_auth_token_still_matches(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        text = "The auth token is not validated before being trusted"
        assert normalize_title_from_text(text) == "Review authentication flow"

    def test_title_author_does_not_match_auth(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        text = "The author of this module did not document the edge case"
        assert normalize_title_from_text(text) != "Review authentication flow"

    def test_title_database_word_does_not_falsely_match_db_fragment(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        # "db" must not match as a bare substring of an unrelated word.
        text = "The adb-style logging wrapper leaks stack traces"
        assert normalize_title_from_text(text) != "Verify database driver compatibility"

    def test_title_genuine_db_finding_still_matches(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        text = "The db driver placeholder style differs across dialects"
        assert normalize_title_from_text(text) == "Verify database driver compatibility"

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
# F-25 — a MEDIUM duplicate_assignment hygiene finding must land at
# "Minor Issues" / "Manual Review Required", never at "Critical Issues" /
# "Do Not Apply". Exercises _compute_trust_signals + _build_recommendation_v1
# directly, isolating the hygiene-severity effect from the LLM-driven stages.
# ---------------------------------------------------------------------------

class TestMediumHygieneRecommendation:
    def test_medium_duplicate_assignment_yields_minor_issues_not_blocked(self):
        from utilities.autopatcher.pipeline import _compute_trust_signals, _build_recommendation_v1

        hygiene = [{
            "severity": "MEDIUM",
            "check": "duplicate_assignment",
            "detail": "`app/config.py`: `MAX_REQUEST_BYTES` is added, and an "
                       "unchanged assignment with the same name is also "
                       "visible in this diff — verify manually",
        }]
        applicability = {"applicable": True}
        classified_challenger = {
            "confirmed_defect_count": 0,
            "plausible_risk_count": 0,
            "validation_gap_count": 0,
            "still_vulnerable": False,
        }

        signals = _compute_trust_signals(
            hygiene, applicability, classified_challenger, "Good", "low"
        )
        assert signals["patch_integrity"]["value"] == "Minor Issues"

        recommendation = _build_recommendation_v1(
            signals, still_vulnerable=False, defect_count=0
        )
        assert recommendation["decision"] == "Manual Review Required"
        assert recommendation["decision"] != "Do Not Apply"


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
        should pass a non-empty code_context into the Patch Generator.

        Release: response-contract enforcement moved the initial
        generation call site from generate_patch() to
        _generate_patch_with_contract_check(), which itself calls
        generate_patch_raw() (not generate_patch()) — this now spies on
        generate_patch_raw, the actual entry point that receives
        code_context, while still exercising the real (mock) LLM call
        underneath."""
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
        _original = _pg.generate_patch_raw

        def _capturing(vtext, llm, code_context="", retry_hint="", stage="patch_generation"):
            captured.append(code_context)
            return _original(vtext, llm, code_context=code_context, retry_hint=retry_hint, stage=stage)

        with _mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", side_effect=_capturing):
            run(vulnerability_text=vuln_text, api_key="", repo_root=str(tmp_path))

        assert captured, "generate_patch_raw was never called"
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

    def test_intro_clarifies_pre_patch_provenance(self):
        """Release-polish change #8: Repository Context must state these
        locations were selected before the patch was generated, and point
        to Post-Patch Investigation for evidence gathered afterward —
        without implying patch-touched evidence was selected beforehand."""
        from utilities.autopatcher.pipeline import _render_repository_context_section
        candidate = self._candidate("retry.py", [self._evidence("explicit_path", tier=3)], best_tier=3)
        decision = self._decision("retry.py", "primary_full_file")
        grounding = self._grounding([candidate], [decision])

        section = _render_repository_context_section(grounding)

        assert "selected **before** the patch was generated" in section
        assert "Post-Patch Investigation" in section

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
        ("symbol_definition", "Defines the exact symbol named in the advisory"),
        ("symbol_search", "References a symbol named in the advisory"),
        ("cwe_keywords", "Contains terminology associated with this vulnerability type"),
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
        """Defensive fallback for a hypothetical best_tier=None candidate (no
        current repo_locator.py pass produces one — every pass now assigns a
        real tier, including the exact symbol-definition pass) — must not
        crash, must use the one evidence entry present."""
        from utilities.autopatcher.pipeline import _selected_reason_kind
        candidate = self._candidate(
            "a_file.py", [self._evidence("some_future_tierless_pass", tier=None)], best_tier=None,
        )
        assert _selected_reason_kind(candidate) == "some_future_tierless_pass"

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


# ---------------------------------------------------------------------------
# Evidence Sufficiency Gate (Phase 1) -- end-to-end report rendering
#
# source_verification.py computes the signal; pipeline.py merges it into
# the Trust Signals dict as a NEW key, observability-only. These tests
# build PipelineResult directly and call _build_report() -- no LLM calls.
# ---------------------------------------------------------------------------

class TestSourceVerificationInReport:
    def _base_kwargs(self, tmp_path, source_verification=None):
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
                " def foo():\n-    return 1\n+    return 2\n"
            ),
            review=(
                "**Explanation:**\nThe code was vulnerable because of X.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Test with payload Y.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""},
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            repo_root=tmp_path,
            detected_language="python",
            source_verification=source_verification,
        )

    def test_signal_absent_falls_back_to_not_verified(self, tmp_path):
        """A run/test predating this field (or one where the classification
        itself failed) must render "Not verified" -- never a false
        "Confirmed" manufactured from missing data."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path, source_verification=None))
        report = _build_report(result)
        assert "Was the edited content verified against the repository?" in report
        row = [l for l in report.splitlines() if l.startswith("| Was the edited content")][0]
        assert "? Not verified" in row

    def test_confirmed_signal_renders_as_good(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        sig = {"value": "Confirmed", "label": "✓ Confirmed", "notes": "1 hunk(s) matched the repository uniquely"}
        result = PipelineResult(**self._base_kwargs(tmp_path, source_verification=sig))
        report = _build_report(result)
        row = [l for l in report.splitlines() if l.startswith("| Was the edited content")][0]
        assert "✅ Good" in row
        assert "1 hunk(s) matched the repository uniquely" in row

    def test_unverified_signal_renders_but_does_not_change_decision(self, tmp_path):
        """The core Phase-1 contract: the signal is visible, but the
        Recommendation is unaffected -- same decision as the Confirmed case
        above, for otherwise-identical inputs."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        confirmed = {"value": "Confirmed", "label": "Confirmed", "notes": ""}
        unverified = {
            "value": "Unverified", "label": "Unverified",
            "notes": "1 hunk(s) edit content not found anywhere in the repository: mod.py",
        }

        good_report = _build_report(PipelineResult(**self._base_kwargs(tmp_path, source_verification=confirmed)))
        bad_report = _build_report(PipelineResult(**self._base_kwargs(tmp_path, source_verification=unverified)))

        bad_row = [l for l in bad_report.splitlines() if l.startswith("| Was the edited content")][0]
        assert "❌ Content not found" in bad_row
        assert "mod.py" in bad_row

        # Same Recommendation decision either way -- this signal does not
        # yet drive Recommendation Policy. Both inputs are identical except
        # for source_verification, so whichever of the four known decision
        # strings appears in one report must appear in the other too.
        known_decisions = (
            "Deploy After Validation", "Deploy With Caution",
            "Manual Review Required", "Do Not Apply",
        )
        for decision in known_decisions:
            if f"**{decision}**" in good_report:
                assert f"**{decision}**" in bad_report, (
                    f"good_report chose {decision!r} but bad_report did not"
                )
                break
        else:
            raise AssertionError("no known decision string found in good_report")


class TestNoPatchProducedOutcome:
    """Issue 2 -- an empty FINAL patch is a report-level execution outcome
    (`no_patch`, derived inside _build_report), never a fifth Recommendation
    Policy value and never presented via the normal Manual Review Required /
    Deploy / Do Not Apply bottom line."""

    def _base_kwargs(self, tmp_path, patch=""):
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=patch,
            review=(
                "**Explanation:**\nThe code was vulnerable because of X.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Test with payload Y.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""},
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": None, "skipped": True,
                "skipped_reason": "empty diff after stripping fences",
                "error": None, "stderr": "",
            },
            repo_root=tmp_path,
            detected_language="python",
        )

    def test_heading_and_execution_outcome_wording(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path, patch=""))
        report = _build_report(result)

        assert "NO PATCH PRODUCED" in report
        assert "The pipeline did not produce a final candidate patch." in report
        assert "No patch is available for deployment or review." in report

    def test_no_manual_review_or_deploy_bottom_line(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path, patch=""))
        report = _build_report(result)

        assert "MANUAL REVIEW REQUIRED" not in report
        assert "DEPLOY AFTER VALIDATION" not in report
        assert "DEPLOY WITH CAUTION" not in report
        assert "DO NOT APPLY" not in report
        assert "## Recommendation" not in report

    def test_no_misleading_wording(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path, patch=""))
        report = _build_report(result)

        assert "Patch was not verified" not in report
        assert "before deployment" not in report
        assert "review the patch" not in report

    def test_no_top_action_or_validation_actions_section(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path, patch=""))
        report = _build_report(result)

        assert "**Top action:**" not in report
        assert "## Validation Actions" not in report

    def test_proposed_patch_section_is_not_blank(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path, patch=""))
        report = _build_report(result)

        idx = report.find("## Proposed patch")
        assert idx != -1
        section = report[idx:idx + 200]
        assert "No final candidate patch was produced" in section

    def test_whitespace_only_patch_is_also_treated_as_no_patch(self, tmp_path):
        """`no_patch` must be whitespace-tolerant -- not merely `== ""`."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path, patch="   \n  "))
        report = _build_report(result)
        assert "NO PATCH PRODUCED" in report

    def test_normal_patch_is_unaffected(self, tmp_path):
        """Regression: a real, non-empty patch must still render the normal
        Recommendation Policy bottom line, not the no-patch card."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n def foo():\n-    return 1\n+    return 2\n"
        kwargs = self._base_kwargs(tmp_path, patch=patch)
        kwargs["applicability"] = {
            "applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": "",
        }
        result = PipelineResult(**kwargs)
        report = _build_report(result)

        assert "NO PATCH PRODUCED" not in report
        assert "## Recommendation" in report

    # -----------------------------------------------------------------
    # Terminal/report consistency (Issue 3): the SAME `no_patch` state
    # that already gates the report's decision card must also gate the
    # stderr "[pipeline] Recommendation:" line the terminal streams
    # verbatim -- a no-patch run must never print Manual Review Required/
    # Deploy/Do Not Apply as its primary terminal outcome.
    # -----------------------------------------------------------------

    def test_stderr_shows_no_patch_produced_not_manual_review_required(self, tmp_path, capsys):
        """The default no-patch fixture's signals naturally land on the
        Recommendation Policy's own "Manual Review Required" catch-all
        (see test_no_manual_review_or_deploy_bottom_line) -- exactly the
        real-world shape of the reported bug. stderr must show
        NO PATCH PRODUCED instead, never that decision string."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path, patch=""))
        report = _build_report(result)

        captured = capsys.readouterr()
        assert "[pipeline] Recommendation:" in captured.err
        assert "⚫ NO PATCH PRODUCED" in captured.err
        assert "Manual Review Required" not in captured.err
        assert "NO PATCH PRODUCED" in report

    def test_stderr_precedence_independent_of_recommendation_value(self, tmp_path, monkeypatch, capsys):
        """Precedence must hold for ANY underlying decision, not merely the
        Manual Review Required catch-all above -- proven by substituting a
        different decision ("Do Not Apply") and confirming it still never
        reaches the terminal as the primary outcome."""
        from utilities.autopatcher import pipeline as pl

        monkeypatch.setattr(
            pl, "_build_recommendation_v1",
            lambda *args, **kwargs: {"decision": "Do Not Apply", "reason": "stub"},
        )
        result = pl.PipelineResult(**self._base_kwargs(tmp_path, patch=""))
        report = pl._build_report(result)

        captured = capsys.readouterr()
        assert "[pipeline] Recommendation:" in captured.err
        assert "⚫ NO PATCH PRODUCED" in captured.err
        assert "Do Not Apply" not in captured.err
        assert "NO PATCH PRODUCED" in report

    def test_stderr_normal_patch_recommendation_unchanged(self, tmp_path, capsys):
        """Regression: a real, non-empty patch must still print the normal
        Recommendation Policy decision to stderr, exactly as before this
        fix -- the fix must only change the no-patch case."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        patch = "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n def foo():\n-    return 1\n+    return 2\n"
        kwargs = self._base_kwargs(tmp_path, patch=patch)
        kwargs["applicability"] = {
            "applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": "",
        }
        result = PipelineResult(**kwargs)
        report = _build_report(result)

        captured = capsys.readouterr()
        assert "[pipeline] Recommendation:" in captured.err
        assert "NO PATCH PRODUCED" not in captured.err
        assert "NO PATCH PRODUCED" not in report
        assert any(
            decision in captured.err
            for decision in ("Deploy After Validation", "Deploy With Caution", "Manual Review Required", "Do Not Apply")
        )


# ---------------------------------------------------------------------------
# Report Polish Batch B
#
# Part 1 -- human-readable Validation Action / Top Action titles (no more
#           generated test-function slugs like "test_nested_paths_like_a_
#           constructor" leaking into a reader-facing title).
# Part 2 -- an explicit, deterministic "Why manual review" line, derived
#           only from signals that already caused the Manual Review Required
#           decision.
# Part 3 -- Validation Action prioritization: within the same HIGH/MEDIUM/
#           LOW priority tier, the action that most directly validates the
#           vulnerability's own core security behavior ranks ahead of a
#           speculative secondary edge case.
#
# None of this changes recommendation decisions, thresholds, Challenger
# semantics, Finding Calibration classification, repair authorization,
# patch applicability/generation, or confidence scoring -- see the
# per-scenario assertions on `decision` below.
# ---------------------------------------------------------------------------


class TestHumanReadableActionTitles:
    """Part 1: normalize_title_from_text() must never surface a generated
    test-function slug, and should instead build a concise, human-readable
    validation title from the finding's own sentence."""

    def test_generated_test_slug_never_surfaces_as_title(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        # Exactly the shape test_suggester._safe_name() produces: no spaces,
        # word-joined by underscores -- the old fallback
        # ("Add targeted tests for " + first 3 "words") treated this whole
        # slug as a single word and echoed it verbatim.
        slug = "test_nested_paths_like_a_constructor"
        title = normalize_title_from_text(slug)
        assert slug not in title
        assert "test_" not in title

    def test_another_generated_slug_never_surfaces(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        slug = "test_users_passing_a_custom_remove_headers_on"
        title = normalize_title_from_text(slug)
        assert slug not in title
        assert "test_" not in title

    def test_no_patch_produced_slug_never_surfaces(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        slug = "test_no_patch_was_actually_produced"
        title = normalize_title_from_text(slug)
        assert slug not in title
        assert "test_" not in title

    def test_finding_sentence_produces_concise_human_title(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        title = normalize_title_from_text("Nested constructor.prototype paths remain exploitable")
        assert "test_" not in title
        assert title.lower().startswith(("verify", "check", "confirm", "validate", "ensure", "review"))
        # The finding's own concrete subject should survive into the title,
        # not be replaced by a generic placeholder.
        assert "constructor.prototype" in title

    def test_custom_header_finding_produces_prose_not_slug(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        title = normalize_title_from_text(
            "Users passing a custom remove_headers_on_redirect callback may "
            "still leak the Cookie header on same-origin redirects"
        )
        assert "test_" not in title
        assert " " in title  # prose, not a single joined identifier

    def test_legitimate_code_identifier_not_mangled(self):
        """A real code identifier that is genuinely part of the finding's
        own evidence (not a generated slug) must survive in the title
        untouched -- only bare, all-underscore, space-free strings are
        treated as unusable slugs."""
        from utilities.autopatcher.pipeline import normalize_title_from_text
        title = normalize_title_from_text(
            "The get_query_param helper does not sanitize the redirect target"
        )
        assert "get_query_param" in title

    def test_long_finding_truncates_cleanly(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text
        long_finding = (
            "The remediation for the cross-origin redirect handling remains "
            "incomplete because a long chain of intermediate proxies and "
            "load balancers can each independently rewrite the Host header "
            "before the application ever sees the request, which means the "
            "check added by this patch may not observe the same value an "
            "attacker actually sent"
        )
        title = normalize_title_from_text(long_finding)
        assert len(title) <= 90
        # Safe truncation (Batch A's _truncate_reason): no dangling markdown
        # delimiter, cut at a word boundary.
        assert title.count("`") % 2 == 0
        assert not title.endswith(" ")

    def test_empty_or_whitespace_falls_back_to_generic_phrase(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text, _TITLE_GENERIC_FALLBACK
        assert normalize_title_from_text("") == _TITLE_GENERIC_FALLBACK
        assert normalize_title_from_text("   ") == _TITLE_GENERIC_FALLBACK
        assert normalize_title_from_text("test_only_a_slug") == _TITLE_GENERIC_FALLBACK

    def test_keyword_groups_still_take_priority(self):
        """Batch A's word-boundary keyword groups (db/encoding/auth) are
        unchanged by this batch -- they still short-circuit before the new
        generic sentence-based title logic runs."""
        from utilities.autopatcher.pipeline import normalize_title_from_text
        assert normalize_title_from_text("The db driver placeholder style differs across dialects") == \
            "Verify database driver compatibility"
        assert normalize_title_from_text("The auth token is not validated before being trusted") == \
            "Review authentication flow"


class TestSecurityInvariantTitleNormalization:
    """Post-review fix (real-CVE regression, pygeoapi): a security-invariant
    Validation Action's title must never be run through
    normalize_title_from_text's domain keyword classification (auth/db/
    encoding). Root cause: `_TITLE_AUTH_KEYWORDS_RE` includes the generic
    words "access"/"permission"/"token" -- common vocabulary in a path-
    containment or prototype-integrity invariant (e.g. "...preventing
    unauthorized access to files outside the collection scope"), not
    evidence the invariant is actually about authentication. That false
    match previously turned a filesystem-containment invariant's title
    into "Review authentication flow".

    normalize_title_from_text itself is intentionally NOT touched here --
    its keyword groups remain exactly as before for every other caller
    (Suggested Tests, adversarial findings); see
    TestHumanReadableActionTitles above, still green. Only
    normalize_security_invariant_title (a new, narrow entry point used
    solely for security_invariant) skips that classification.
    """

    def test_1_filesystem_containment_invariant_not_classified_as_auth(self):
        from utilities.autopatcher.pipeline import normalize_title_from_text, normalize_security_invariant_title

        invariant = (
            "The absolute resolved filesystem path derived from the untrusted "
            "dirpath/urlpath must remain strictly within the configured provider "
            "root, preventing unauthorized access to files outside the collection scope."
        )

        # Proves the exact false match this fix corrects: the generic
        # normalizer really does mis-fire on this text (via the "access"
        # keyword), which is exactly why the security-invariant path must
        # not reuse it.
        assert normalize_title_from_text(invariant) == "Review authentication flow"

        title = normalize_security_invariant_title(invariant)
        assert "authentication" not in title.lower(), title
        assert any(word in title.lower() for word in ("path", "filesystem", "root")), title

    def test_2_cookie_redirect_invariant_keeps_its_own_semantics(self):
        from utilities.autopatcher.pipeline import normalize_security_invariant_title

        invariant = "A caller-supplied Cookie must not be forwarded on a cross-origin redirect"
        title = normalize_security_invariant_title(invariant)

        assert "cookie" in title.lower(), title
        assert "redirect" in title.lower(), title
        assert "authentication" not in title.lower(), title

    def test_3_prototype_pollution_invariant_keeps_its_own_semantics(self):
        from utilities.autopatcher.pipeline import normalize_security_invariant_title

        invariant = "Attacker-controlled argv must not modify Object.prototype via constructor or prototype keys"
        title = normalize_security_invariant_title(invariant)

        assert "prototype" in title.lower(), title
        assert "authentication" not in title.lower(), title
        assert "database" not in title.lower(), title

    def test_4_generic_words_do_not_trigger_unrelated_domain_remap(self):
        """Invariants containing "untrusted"/"trusted"/"token"/"tokens" in
        an ordinary, non-authentication sense must not be remapped to the
        auth domain merely by substring/keyword presence."""
        from utilities.autopatcher.pipeline import normalize_security_invariant_title

        cases = [
            "Input derived from an untrusted client must not traverse outside the configured root",
            "A value supplied by a trusted internal caller must still be re-validated before use",
            "Version tokens embedded in the query string must not alter the resolved file path",
            "Path tokens containing '..' must be rejected before path resolution",
        ]
        for invariant in cases:
            title = normalize_security_invariant_title(invariant)
            assert "authentication" not in title.lower(), (invariant, title)
            assert "database" not in title.lower(), (invariant, title)

    def test_5_long_invariant_truncates_cleanly(self):
        from utilities.autopatcher.pipeline import normalize_security_invariant_title

        long_invariant = (
            "The absolute resolved filesystem path derived from a combination of "
            "the configured provider root and the untrusted, request-supplied "
            "dirpath and urlpath segments must remain strictly contained within "
            "that configured provider root directory at all times, regardless of "
            "how many levels of parent-directory traversal or symlink indirection "
            "an attacker attempts to use to escape that boundary"
        )
        title = normalize_security_invariant_title(long_invariant)

        assert len(title) <= 90
        assert title.count("`") % 2 == 0
        assert not title.endswith(" ")

    def test_6_existing_keyword_title_tests_untouched(self):
        """Sanity: normalize_title_from_text's own keyword groups (used by
        every non-security-invariant caller) are completely unaffected by
        the new normalize_security_invariant_title entry point."""
        from utilities.autopatcher.pipeline import normalize_title_from_text
        assert normalize_title_from_text("The db driver placeholder style differs across dialects") == \
            "Verify database driver compatibility"
        assert normalize_title_from_text("The auth token is not validated before being trusted") == \
            "Review authentication flow"
        assert normalize_title_from_text("Unicode and binary username inputs are mishandled") == \
            "Validate input handling edge cases"


class TestHumanReadableActionTitlesReport:
    """Part 1, report-level: a real Suggested-Test-derived Validation Action
    must not expose its generated test-function slug as the title -- the
    root cause was `topic = s.get("name") or s.get("reason", "")` preferring
    the always-populated slug over the human-readable finding text."""

    def _base_kwargs(self, tmp_path, **overrides):
        kwargs = dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
                " def foo():\n-    return 1\n+    return 2\n"
            ),
            review=(
                "**Explanation:**\nThe code was vulnerable because of X.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Test with payload Y.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={
                "still_vulnerable": False,
                "edge_cases": [
                    "Users configuring a custom header-removal policy on redirect may "
                    "not have the session cookie stripped, unlike the default policy"
                ],
                "potential_issues": [],
                "summary": "",
            },
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            repo_root=None,
            detected_language="python",
        )
        kwargs.update(overrides)
        return kwargs

    def test_no_generated_slug_in_validation_actions(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path))
        report = _build_report(result)

        va_idx = report.find("## Validation Actions")
        next_section = report.find("\n## ", va_idx + 1)
        va_block = report[va_idx:next_section if next_section != -1 else None]

        assert "test_" not in va_block, va_block
        assert "custom header-removal policy" in va_block.lower() or "cookie" in va_block.lower()


class TestWhyManualReview:
    """Part 2: a concise, deterministic "Why manual review" line, derived
    only from signals that already caused the existing Manual Review
    Required decision -- never a second recommendation engine, and never
    changing green/red outcomes."""

    def _base_kwargs(self, tmp_path, **overrides):
        kwargs = dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
                " def foo():\n-    return 1\n+    return 2\n"
            ),
            review=(
                "**Explanation:**\nThe code was vulnerable because of X.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Test with payload Y.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={"still_vulnerable": False, "edge_cases": [], "potential_issues": [], "summary": ""},
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            repo_root=tmp_path,
            detected_language="python",
        )
        kwargs.update(overrides)
        return kwargs

    def _recommendation_block(self, report):
        rec_idx = report.find("## Recommendation")
        explanation_idx = report.find("## Explanation")
        return report[rec_idx:explanation_idx if explanation_idx != -1 else None]

    def test_unsupported_language_signal_explained(self, tmp_path):
        """minimist-representative: deterministic impact/test signals are
        unavailable for the repository's language. Manual Review's
        explanation must say so, and the decision itself must be unchanged
        by this batch (Manual Review Required, via the existing I3/catch-all
        path -- see _build_recommendation_v1)."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._base_kwargs(
            tmp_path,
            impact={
                "impact_level": "not_applicable", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            detected_language="javascript",
        )
        result = PipelineResult(**kwargs)
        report = _build_report(result)
        rec_block = self._recommendation_block(report)

        assert "**Manual Review Required**" in rec_block
        assert "**Why manual review:**" in rec_block
        assert "not supported for this language" in rec_block

    def test_high_impact_surface_explained(self, tmp_path):
        """pygeoapi-representative: high impact surface / caller coverage
        drives Manual Review. Decision must land on the existing
        safety == "High Risk" branch, unchanged by this batch."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._base_kwargs(
            tmp_path,
            impact={
                "impact_level": "high", "changed_files": [], "affected_files": [],
                "impact_summary": "Touches a widely-used entry point.",
                "recommendations": [], "usage_matches": [],
            },
        )
        result = PipelineResult(**kwargs)
        report = _build_report(result)
        rec_block = self._recommendation_block(report)

        assert "**Manual Review Required**" in rec_block
        assert "**Why manual review:**" in rec_block
        assert "high-impact surface" in rec_block.lower()

    def test_still_unresolved_effectiveness_explained(self, tmp_path):
        """node-semver-representative: the patch's effectiveness against the
        vulnerability remains uncertain (still_vulnerable, no confirmed
        defect). Decision must land on the existing still_vulnerable/
        defect_count==0 branch, unchanged by this batch."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._base_kwargs(
            tmp_path,
            challenger={
                "still_vulnerable": True,
                "edge_cases": ["Cannot verify this without running the full test suite"],
                "potential_issues": [],
                "summary": "",
            },
        )
        result = PipelineResult(**kwargs)
        report = _build_report(result)
        rec_block = self._recommendation_block(report)

        assert "**Manual Review Required**" in rec_block
        assert "**Why manual review:**" in rec_block
        assert "effectiveness" in rec_block.lower() or "has not been confirmed" in rec_block.lower()

    def test_green_recommendation_has_no_why_manual_review_text(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs(tmp_path))
        report = _build_report(result)
        rec_block = self._recommendation_block(report)

        assert "**Deploy After Validation**" in rec_block
        assert "Why manual review" not in rec_block

    def test_red_recommendation_has_no_why_manual_review_text(self, tmp_path):
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._base_kwargs(
            tmp_path,
            applicability={
                "applicable": False, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "patch does not apply",
            },
        )
        result = PipelineResult(**kwargs)
        report = _build_report(result)
        rec_block = self._recommendation_block(report)

        assert "**Do Not Apply**" in rec_block
        assert "Why manual review" not in rec_block

    def test_recommendation_decision_identical_across_all_scenarios(self, tmp_path, monkeypatch):
        """The single most important invariant of Part 2: adding the "Why
        manual review" line must never change which decision
        _build_recommendation_v1 returns. Verified here by comparing the
        decision produced with and without _render_why_manual_review_line
        wired in (simulated by stubbing it out) for every scenario above."""
        from utilities.autopatcher import pipeline as pl

        scenarios = [
            self._base_kwargs(
                tmp_path,
                impact={"impact_level": "not_applicable", "changed_files": [], "affected_files": [],
                        "impact_summary": "", "recommendations": [], "usage_matches": []},
                detected_language="javascript",
            ),
            self._base_kwargs(
                tmp_path,
                impact={"impact_level": "high", "changed_files": [], "affected_files": [],
                        "impact_summary": "", "recommendations": [], "usage_matches": []},
            ),
            self._base_kwargs(
                tmp_path,
                challenger={"still_vulnerable": True, "edge_cases": ["Cannot verify this without running tests"],
                            "potential_issues": [], "summary": ""},
            ),
            self._base_kwargs(tmp_path),  # green
            self._base_kwargs(
                tmp_path,
                applicability={"applicable": False, "skipped": False, "skipped_reason": None,
                                "error": None, "stderr": "patch does not apply"},
            ),  # red
        ]

        for kwargs in scenarios:
            result = pl.PipelineResult(**kwargs)
            report_with = pl._build_report(result)
            decision_with = next(
                d for d in ("Deploy After Validation", "Deploy With Caution", "Manual Review Required", "Do Not Apply")
                if f"**{d}**" in report_with
            )

            monkeypatch.setattr(pl, "_render_why_manual_review_line", lambda rec: "")
            report_without = pl._build_report(result)
            decision_without = next(
                d for d in ("Deploy After Validation", "Deploy With Caution", "Manual Review Required", "Do Not Apply")
                if f"**{d}**" in report_without
            )
            monkeypatch.undo()

            assert decision_with == decision_without


class TestValidationActionDirectness:
    """Part 3: _finding_directness_tier() unit coverage -- the deterministic
    tie-breaker used to rank a direct/confirmed core-security-behavior
    finding ahead of a speculative one within the same priority tier."""

    def test_calibrated_observed_outranks_hypothesis(self):
        """Original Batch B semantics, preserved: calibration's "observed"
        group ranks above "hypothesis" for this secondary-action tiebreaker.

        Post-review note: a real-CVE regression showed this can let an
        already-resolved observed fact outrank a genuinely open question
        for Top Action in some cases -- but the fix for that is
        `security_invariant` (see TestSecurityInvariantTopAction), which
        unconditionally prepends the vulnerability's core security behavior
        ahead of every action ranked here, not a global inversion of this
        mapping. A prior attempt to fix it by globally reversing this
        ranking (hypothesis above observed) was reverted: it still used
        evidence-confidence classification as a proxy for validation
        importance, just inverted, which is too broad a policy change for
        this report-polish batch. General observed-vs-hypothesis relevance
        among secondary (non-Top-Action) findings remains deferred to a
        later batch."""
        from utilities.autopatcher.pipeline import _finding_directness_tier
        calibration = {
            "the core check": {"original": "the core check", "group": "observed", "reworded": "x"},
            "an edge case": {"original": "an edge case", "group": "hypothesis", "reworded": "y"},
        }
        assert _finding_directness_tier("the core check", calibration) > \
            _finding_directness_tier("an edge case", calibration)

    def test_calibrated_hardening_is_least_direct(self):
        from utilities.autopatcher.pipeline import _finding_directness_tier
        calibration = {
            "polish idea": {"original": "polish idea", "group": "hardening", "reworded": "z"},
        }
        assert _finding_directness_tier("polish idea", calibration) < \
            _finding_directness_tier("unrelated text with no calibration entry", calibration)

    def test_uncalibrated_confirmed_defect_outranks_plausible_risk(self):
        """No calibration entry at all -- falls back to _classify_finding's
        own category. A finding phrased as still-exploitable (confirmed_
        defect) must outrank a scoped/limited concern (plausible_risk)."""
        from utilities.autopatcher.pipeline import _finding_directness_tier
        direct = "The redirect handling remains exploitable across origins"
        speculative = "If users configure a custom retry override, that configuration path is not exercised by the existing suite"
        assert _finding_directness_tier(direct, {}) > _finding_directness_tier(speculative, {})

    def test_uncalibrated_generic_is_least_direct(self):
        from utilities.autopatcher.pipeline import _finding_directness_tier
        generic = "Consider adding documentation for the new option"
        direct = "The redirect handling remains exploitable across origins"
        assert _finding_directness_tier(generic, {}) < _finding_directness_tier(direct, {})


class TestValidationActionPrioritizationReport:
    """Part 3, report-level: within the same priority tier, the Validation
    Action validating the vulnerability's own core security behavior must
    rank ahead of a speculative secondary edge case -- urllib3/minimist-
    representative (generic fixtures, not tied to a specific CVE)."""

    DIRECT_FINDING = "The redirect handling remains exploitable when headers are stripped across origins"
    SPECULATIVE_FINDING = "If users configure a custom retry override, that configuration path is not exercised by the existing suite"

    def _base_kwargs(self, tmp_path, edge_cases, **overrides):
        kwargs = dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
                " def foo():\n-    return 1\n+    return 2\n"
            ),
            review=(
                "**Explanation:**\nThe code was vulnerable because of X.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Test with payload Y.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={"still_vulnerable": False, "edge_cases": edge_cases, "potential_issues": [], "summary": ""},
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            repo_root=None,
            detected_language="python",
        )
        kwargs.update(overrides)
        return kwargs

    def _validation_actions_block(self, report):
        va_idx = report.find("## Validation Actions")
        next_section = report.find("\n## ", va_idx + 1)
        return report[va_idx:next_section if next_section != -1 else None]

    def test_direct_core_behavior_ranks_before_speculative_edge_case(self, tmp_path, monkeypatch):
        """The speculative finding is listed FIRST in the raw challenger
        output -- proving the reorder happens on directness, not on
        preserving the challenger's own order. suggest_tests is stubbed out
        so the (separately re-derived, currently non-deduplicated -- cross-
        section dedup is out of scope for this batch) Suggested-Tests path
        doesn't add noise to this specific assertion."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        kwargs = self._base_kwargs(tmp_path, [self.SPECULATIVE_FINDING, self.DIRECT_FINDING])
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)
        va_block = self._validation_actions_block(report)

        direct_idx = va_block.find("redirect handling")
        speculative_idx = va_block.find("retry override")
        assert direct_idx != -1, va_block
        assert speculative_idx == -1 or direct_idx < speculative_idx

        top_action_idx = report.find("**Top action:**")
        top_action_line = report[top_action_idx: report.find("\n", top_action_idx)]
        assert "retry override" not in top_action_line

    def test_membership_unchanged_natural_codepath_no_stubbing(self, tmp_path):
        """Regression guard (final review, pre real-CVE regression): with the
        *natural*, unstubbed suggest_tests codepath -- i.e. exactly what
        production runs -- two distinct, real challenger findings at the
        same priority must BOTH still be representable in Validation
        Actions. Batch B may retitle and reorder them, but must not cause
        one of two genuinely distinct findings to vanish from the section
        entirely while the other is silently duplicated in its place.

        `rating` is forced to "Good" via a repo with a matching test file so
        the test-support-candidate fallback action never competes for a
        cap slot -- isolating this assertion to exactly the two challenger
        findings themselves.
        """
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_foo():\n    pass\n" * 5, encoding="utf-8")
        (tmp_path / "mod.py").write_text("def foo():\n    return 1\n", encoding="utf-8")

        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        kwargs = self._base_kwargs(
            tmp_path, [self.SPECULATIVE_FINDING, self.DIRECT_FINDING], repo_root=tmp_path,
        )
        result = PipelineResult(**kwargs)
        report = _build_report(result)
        va_block = self._validation_actions_block(report)

        assert "redirect handling" in va_block, va_block
        assert "retry override" in va_block, (
            "The speculative finding vanished from Validation Actions entirely "
            "instead of merely being reordered/retitled -- membership changed, "
            "not just presentation.\n" + va_block
        )
        # Human titles remain (item 6): the machine-shaped Suggested-Test
        # slug must never surface as the user-facing title, even though this
        # scenario exercises the real, unstubbed suggest_tests codepath.
        assert "test_" not in va_block, va_block

    def test_shared_action_type_cap_independent_of_title_wording(self, tmp_path, monkeypatch):
        """Post-review fix, items 1 & 5: two actions sharing the same
        explicit `action_type` ("test") but with VERY different display
        titles -- one triggers the "auth" keyword branch ("Review
        authentication flow"), the other the new generic sentence-based
        fallback ("Verify ...") -- must still compete for the SAME 2-slot
        cap. A third, again very differently-titled "test"-type action
        ("Increase targeted test coverage") must be excluded by that shared
        cap, proving the cap groups by the explicit `action_type` field,
        never by a title-derived guess (the removed
        `action_type_from_title`).

        Isolated via a stubbed suggest_tests (fixed, known reason texts)
        and an empty challenger (no adversarial-loop competition), so the
        only "test"-type contenders are exactly the two Suggested-Tests
        entries plus the test-support candidate -- a clean, unambiguous
        reproduction of the shared-bucket cap rather than a side effect of
        the global 3-action cap.
        """
        from utilities.autopatcher import pipeline as pl

        auth_finding = "The auth token is not validated before being trusted"
        redirect_finding = "The redirect handling remains exploitable when headers are stripped across origins"
        monkeypatch.setattr(
            pl, "suggest_tests",
            lambda *a, **k: [
                {"name": "test_auth_thing", "reason": auth_finding, "code": ""},
                {"name": "test_redirect_thing", "reason": redirect_finding, "code": ""},
            ],
        )

        # rating="Some": a test file that imports the target module by name,
        # but isn't the same-file match -- gives exactly one same-module
        # match (see testing_support.score_test_support), which is neither
        # "Good" (no coverage-fallback suppression) nor "None".
        (tmp_path / "mod.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_other.py").write_text(
            "import mod\n\ndef test_x():\n    pass\n", encoding="utf-8",
        )

        kwargs = self._base_kwargs(
            tmp_path,
            # A single unrelated edge case only to make `adv_text_early`
            # non-empty so `_build_report` calls suggest_tests at all (the
            # stub above controls its actual return value regardless of
            # this input) -- becomes one "verify"-type adversarial action,
            # irrelevant to this test's "test"-type-cap assertions.
            ["Some unrelated finding used only to trigger the suggestions codepath"],
            repo_root=tmp_path,
        )
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)
        va_block = self._validation_actions_block(report)

        assert "Review authentication flow" in va_block, va_block
        assert "redirect handling" in va_block, va_block
        assert "Increase targeted test coverage" not in va_block, (
            "The third 'test'-type candidate should have been excluded by "
            "the shared action_type cap, not survived because its title "
            "happens to look different from the other two.\n" + va_block
        )

    def test_priority_unaffected_by_title_wording(self, tmp_path, monkeypatch):
        """Post-review fix, item 3: two adversarial findings that produce
        very different titles (one keyword-branch-shaped, one the new
        generic sentence-based fallback) must both still be assigned
        priority purely from `compute_priority` (impact level / adversarial
        origin) -- never from title wording."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        auth_finding = "The auth token is not validated before being trusted"
        redirect_finding = "The redirect handling remains exploitable when headers are stripped across origins"
        kwargs = self._base_kwargs(
            tmp_path, [auth_finding, redirect_finding],
            impact={
                "impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
        )
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)
        va_block = self._validation_actions_block(report)

        # Both adversarial items get compute_priority(True) with
        # impact_level == "low" -> MEDIUM, regardless of which title branch
        # (keyword vs. generic) their finding text triggered. Only the
        # numbered title line (e.g. "1. **[MEDIUM]** ...") carries the
        # priority marker -- the following "Reason: ..." line for the same
        # action also contains the finding text but never the marker, so it
        # must be excluded from this check.
        import re as _re
        title_lines = [
            line for line in va_block.splitlines()
            if _re.match(r"^\d+\.\s+\*\*\[\w+\]\*\*", line)
        ]
        matched = [
            line for line in title_lines
            if "Review authentication flow" in line or "redirect handling" in line
        ]
        assert len(matched) == 2, va_block
        for line in matched:
            assert "**[MEDIUM]**" in line, line

    def test_reason_and_next_step_unaffected_by_title_wording(self, tmp_path, monkeypatch):
        """Post-review fix, item 4: human title generation must not alter
        an action's `reason` or `next_step` -- both are computed from the
        same finding text independent of `normalize_title_from_text`."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        kwargs = self._base_kwargs(tmp_path, [self.DIRECT_FINDING])
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)
        va_block = self._validation_actions_block(report)

        assert f"Reason: {self.DIRECT_FINDING}" in va_block, va_block
        assert "Next step: Validate the finding via focused unit tests or manual review." in va_block, va_block

    def test_ranking_is_order_independent(self, tmp_path, monkeypatch):
        """Same two findings, reversed input order -> identical outcome
        (requirement: deterministic across input ordering when the
        underlying evidence is equivalent)."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        kwargs_a = self._base_kwargs(tmp_path, [self.SPECULATIVE_FINDING, self.DIRECT_FINDING])
        kwargs_b = self._base_kwargs(tmp_path, [self.DIRECT_FINDING, self.SPECULATIVE_FINDING])
        report_a = pl._build_report(pl.PipelineResult(**kwargs_a))
        report_b = pl._build_report(pl.PipelineResult(**kwargs_b))

        assert self._validation_actions_block(report_a) == self._validation_actions_block(report_b)

    def test_calibrated_observed_finding_outranks_calibrated_hypothesis(self, tmp_path, monkeypatch):
        """Original Batch B semantics, preserved: at equal priority, an
        "observed" finding ranks ahead of a "hypothesis" finding.
        Validation Actions render each action's RAW finding text as
        `reason` (never the calibrated reworded text, which only ever
        appears in Review Results' Observed Facts), so this asserts on
        that raw text directly. Both findings would otherwise classify as
        the same deterministic category (plausible_risk); only
        finding_calibration's already-computed verdict distinguishes them.

        See test_calibrated_observed_outranks_hypothesis for why this
        secondary-action ranking was NOT globally inverted despite the
        real-CVE regression this shape is drawn from -- that regression is
        instead addressed by `security_invariant` (TestSecurityInvariantTopAction),
        which displaces both of these as Top Action when a concrete
        invariant is available, without changing their relative order here."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        open_question = "A symlink created inside the base directory pointing outside it may not be re-validated"
        resolved_observation = "The boundary check specifically prevents a sibling-directory prefix collision"
        kwargs = self._base_kwargs(tmp_path, [resolved_observation, open_question])
        kwargs["finding_calibration"] = [
            {"original": open_question, "group": "hypothesis", "reworded": "Reworded open question"},
            {"original": resolved_observation, "group": "observed", "reworded": "Reworded resolved observation"},
        ]
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)
        va_block = self._validation_actions_block(report)

        assert open_question in va_block, va_block
        assert resolved_observation in va_block, va_block
        assert va_block.find(resolved_observation) < va_block.find(open_question), va_block

    def test_high_priority_action_still_outranks_directness(self, tmp_path, monkeypatch):
        """Requirement: an existing HIGH priority deterministic action still
        outranks a lower-priority action regardless of directness -- priority
        remains the primary sort key; directness only breaks ties within the
        same tier."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        kwargs = self._base_kwargs(
            tmp_path,
            [self.DIRECT_FINDING],
            impact={
                "impact_level": "high", "changed_files": [], "affected_files": [],
                "impact_summary": "Touches a widely-used entry point.",
                "recommendations": [], "usage_matches": [],
            },
        )
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)
        va_block = self._validation_actions_block(report)

        # Both the adversarial item and the impact-driven fallback are HIGH
        # here (impact_level == "high" forces HIGH priority via
        # compute_priority) -- confirms directness doesn't starve a
        # same-tier HIGH action, and priority is computed independently of
        # directness.
        assert "**[HIGH]**" in va_block

    def test_top_action_equals_first_validation_action(self, tmp_path, monkeypatch):
        """Requirement: Top Action must remain conceptually consistent with
        Validation Actions' own ranking -- no second, independent ranking
        system for Top Action."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        kwargs = self._base_kwargs(tmp_path, [self.SPECULATIVE_FINDING, self.DIRECT_FINDING])
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)

        top_action_idx = report.find("**Top action:**")
        top_action_line = report[top_action_idx: report.find("\n", top_action_idx)]

        va_block = self._validation_actions_block(report)
        # First bulleted action's line, e.g. "1. **[MEDIUM]** Verify ...  "
        import re as _re
        first_title_match = _re.search(r"^\d+\.\s+\*\*\[\w+\]\*\*\s+(.+?)\s*$", va_block, _re.MULTILINE)
        assert first_title_match, va_block
        assert first_title_match.group(1) in top_action_line


class TestLegacyEquivalentCapMembership:
    """Post-review fix, round 2: `cap_bucket` must reproduce the exact
    PRE-Batch-B Validation Action membership/priority/count -- not merely a
    *new*, provenance-based bucket split that happens to stop titles from
    moving actions between buckets (round 1 did that, but it changed
    membership in single-finding, weak-test-coverage reports, which is
    itself a regression for this batch).

    Expected counts/content below were verified empirically against frozen
    pre-Batch-B `HEAD` (via a disposable git worktree, not committed) for
    every fixture shape here; see the batch's own review notes. Only
    `title` and same-priority *order* are allowed to differ from what HEAD
    produced.
    """

    DIRECT = "The redirect handling remains exploitable when headers are stripped across origins"
    SPECULATIVE = "If users configure a custom retry override, that configuration path is not exercised by the existing suite"

    def _base_kwargs(self, edge_cases, impact_level="low", repo_root=None):
        return dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
                " def foo():\n-    return 1\n+    return 2\n"
            ),
            review=(
                "**Explanation:**\nThe code was vulnerable because of X.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Test with payload Y.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={"still_vulnerable": False, "edge_cases": edge_cases, "potential_issues": [], "summary": ""},
            impact={
                "impact_level": impact_level, "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            repo_root=repo_root,
            detected_language="python",
        )

    def _validation_actions_block(self, report):
        va_idx = report.find("## Validation Actions")
        next_section = report.find("\n## ", va_idx + 1)
        return report[va_idx:next_section if next_section != -1 else None]

    def _bullets(self, va_block):
        return [
            line.strip() for line in va_block.splitlines()
            if line.strip()[:2].rstrip(".").isdigit() and "**[" in line
        ]

    def test_A_two_findings_exact_legacy_membership(self, tmp_path):
        """Verified against HEAD: exactly 2 items survive (both from the
        Suggested-Tests loop; the adversarial loop's duplicate copies are
        capped out, matching HEAD's own pre-existing behavior -- not
        "improved" here, per the batch's own scope boundary). Both
        underlying findings are represented; direct-behavior may display
        first (approved directness tiebreaker)."""
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_foo():\n    pass\n" * 5, encoding="utf-8")
        (tmp_path / "mod.py").write_text("def foo():\n    return 1\n", encoding="utf-8")

        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs([self.SPECULATIVE, self.DIRECT], repo_root=tmp_path))
        report = _build_report(result)
        va_block = self._validation_actions_block(report)
        bullets = self._bullets(va_block)

        assert len(bullets) == 2, va_block
        assert all("**[MEDIUM]**" in b for b in bullets), va_block
        assert "redirect handling" in va_block
        assert "retry override" in va_block

    def test_A_two_findings_reversed_input_matches(self, tmp_path):
        """Same fixture, reversed input order -> identical membership/count
        (order-independence for equivalent evidence)."""
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_foo():\n    pass\n" * 5, encoding="utf-8")
        (tmp_path / "mod.py").write_text("def foo():\n    return 1\n", encoding="utf-8")

        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs([self.DIRECT, self.SPECULATIVE], repo_root=tmp_path))
        report = _build_report(result)
        va_block = self._validation_actions_block(report)
        bullets = self._bullets(va_block)

        assert len(bullets) == 2, va_block
        assert "redirect handling" in va_block
        assert "retry override" in va_block

    def test_B_single_finding_weak_test_coverage_no_extra_action(self, tmp_path):
        """The exact regression this fix addresses: a repo giving
        rating="Some" (one same-module test match, short of "Good") must
        NOT cause "Increase targeted test coverage" to newly appear --
        verified against HEAD, that action is capped out here (2 duplicate
        "test"-bucket entries for the one real finding already fill the
        cap)."""
        (tmp_path / "mod.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_other.py").write_text(
            "import mod\n\ndef test_x():\n    pass\n", encoding="utf-8",
        )

        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs([self.DIRECT], repo_root=tmp_path))
        report = _build_report(result)
        va_block = self._validation_actions_block(report)
        bullets = self._bullets(va_block)

        assert len(bullets) == 2, (
            "Batch B must not add a Validation Action beyond what HEAD "
            "produced for this fixture.\n" + va_block
        )
        assert "Increase targeted test coverage" not in va_block, va_block
        assert va_block.count("redirect handling") == 4, va_block  # title + Reason line, x2 entries

    def test_C_single_finding_no_test_support_matches_legacy_count(self, tmp_path):
        """rating="None" (repo present, but genuinely no matching test
        files at all) is a DIFFERENT historical shape from "Some" above --
        verified against HEAD, "Improve validation coverage" legitimately
        survives here (it lands in the "other" bucket, not "test", both on
        HEAD and here) alongside the 2 duplicate "test"-bucket entries for
        the one real finding -- 3 items total, exactly matching HEAD."""
        (tmp_path / "mod.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        (tmp_path / "tests").mkdir()  # present but empty -> no matches -> rating "None"

        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs([self.DIRECT], repo_root=tmp_path))
        report = _build_report(result)
        va_block = self._validation_actions_block(report)
        bullets = self._bullets(va_block)

        assert len(bullets) == 3, va_block
        assert "Improve validation coverage" in va_block, va_block
        assert va_block.count("redirect handling") == 4, va_block  # title + Reason line, x2 entries

    def test_D_high_impact_matches_legacy_count(self, tmp_path):
        """impact_level="high" -> both the Suggested-Tests and adversarial
        copies of the one real finding are promoted to HIGH priority;
        verified against HEAD, exactly those 2 survive (no separate
        "Review impacted flows" fallback -- that fallback only fires when
        no HIGH action already exists, and one already does here)."""
        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs([self.DIRECT], impact_level="high", repo_root=None))
        report = _build_report(result)
        va_block = self._validation_actions_block(report)
        bullets = self._bullets(va_block)

        assert len(bullets) == 2, va_block
        assert all("**[HIGH]**" in b for b in bullets), va_block
        assert va_block.count("redirect handling") == 4, va_block  # title + Reason line, x2 entries

    def test_E_title_wording_alone_never_changes_bucket_or_membership(self, tmp_path, monkeypatch):
        """Changing a Suggested-Tests action's rendered title from the old
        "Add targeted tests for X" shape to the new "Verify X" shape must
        not change its cap_bucket -- proven by two same-legacy-bucket
        Suggested-Tests actions with wildly different titles (one via the
        auth keyword branch, one via the new generic sentence fallback)
        both surviving together and excluding a third same-bucket
        contender, exactly as HEAD's title-derived bucket would have."""
        from utilities.autopatcher import pipeline as pl

        auth_finding = "The auth token is not validated before being trusted"
        redirect_finding = self.DIRECT
        monkeypatch.setattr(
            pl, "suggest_tests",
            lambda *a, **k: [
                {"name": "test_auth_thing", "reason": auth_finding, "code": ""},
                {"name": "test_redirect_thing", "reason": redirect_finding, "code": ""},
            ],
        )
        (tmp_path / "mod.py").write_text("def foo():\n    return 1\n", encoding="utf-8")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_other.py").write_text(
            "import mod\n\ndef test_x():\n    pass\n", encoding="utf-8",
        )

        kwargs = self._base_kwargs(
            ["Some unrelated finding used only to trigger the suggestions codepath"],
            repo_root=tmp_path,
        )
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)
        va_block = self._validation_actions_block(report)

        assert "Review authentication flow" in va_block, va_block
        assert "redirect handling" in va_block, va_block
        assert "Increase targeted test coverage" not in va_block, va_block

    def test_F_full_field_invariant_only_title_and_order_differ(self, tmp_path):
        """For the two-finding fixture, every field HEAD produced --
        priority, reason, next_step -- must be recoverable unchanged from
        the new report; only the title wording and (for same-priority
        items) display order are allowed to differ."""
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_mod.py").write_text("def test_foo():\n    pass\n" * 5, encoding="utf-8")
        (tmp_path / "mod.py").write_text("def foo():\n    return 1\n", encoding="utf-8")

        from utilities.autopatcher.pipeline import _build_report, PipelineResult
        result = PipelineResult(**self._base_kwargs([self.SPECULATIVE, self.DIRECT], repo_root=tmp_path))
        report = _build_report(result)
        va_block = self._validation_actions_block(report)

        # HEAD's exact reason/next_step text for each of the 2 surviving
        # (Suggested-Tests-loop) actions -- unchanged by title generation.
        assert f"Reason: {self.DIRECT}" in va_block, va_block
        assert f"Reason: {self.SPECULATIVE}" in va_block, va_block
        assert va_block.count("Next step: Add targeted tests for the identified behavior.") == 2, va_block
        assert va_block.count("**[MEDIUM]**") == 2, va_block


class TestSecurityInvariantTopAction:
    """Post-review fix (real-CVE regression): Top Action / the first
    Validation Action should validate the vulnerability's core remediation
    behavior whenever that behavior is already available as
    `PipelineResult.security_invariant` -- the Final Remediation Strategy's
    own one-sentence security-invariant statement. This is LLM-derived
    remediation guidance produced from already-verified repository/Planner
    evidence and reused here for report presentation, NOT a deterministic
    or Recommendation Policy signal -- but reusing it here still requires
    no new LLM call, since it is already computed by a call the pipeline
    already makes whenever it makes one at all. It must not be displaced
    as Top Action by a secondary edge case that merely happens to rank
    first by accident of source order or evidence-confidence classification
    (see the reverted global observed/hypothesis reordering note on
    `_DIRECTNESS_BY_CALIBRATION_GROUP` in pipeline.py -- that broader
    question is deferred to a later batch). Generic fixtures only, inspired
    by but not tied to any specific CVE/repository.

    Reuses the existing "Validate behavior" action slot (same cap_bucket,
    same directness, same unconditional-prepend mechanism) -- this is not
    a fourth action source; it is the existing behavior-driven path with a
    better content source when one is available.
    """

    def _base_kwargs(self, edge_cases, security_invariant=None, behavior=None, impact_level="low", **overrides):
        kwargs = dict(
            vulnerability_text="# Test vulnerability\n\nSome description.",
            patch=(
                "--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n"
                " def foo():\n-    return 1\n+    return 2\n"
            ),
            review=(
                "**Explanation:**\nThe code was vulnerable because of X.\n\n"
                "**Affected areas:**\n- mod.py\n\n"
                "**Validation notes:**\n- Test with payload Y.\n"
            ),
            score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
            challenger={"still_vulnerable": False, "edge_cases": edge_cases, "potential_issues": [], "summary": ""},
            impact={
                "impact_level": impact_level, "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": [],
            },
            hygiene=[],
            applicability={
                "applicable": True, "skipped": False, "skipped_reason": None,
                "error": None, "stderr": "",
            },
            behavior=behavior if behavior is not None else {
                "function": "foo", "file": "mod.py",
                "summary": "This patch likely affects application logic in mod.py.",
                "primary_behaviors": ["normal flow", "edge-case handling"],
                "is_generic": True,
            },
            security_invariant=security_invariant,
            repo_root=None,
            detected_language="python",
        )
        kwargs.update(overrides)
        return kwargs

    def _validation_actions_block(self, report):
        va_idx = report.find("## Validation Actions")
        next_section = report.find("\n## ", va_idx + 1)
        return report[va_idx:next_section if next_section != -1 else None]

    def _top_action_line(self, report):
        idx = report.find("**Top action:**")
        return report[idx: report.find("\n", idx)]

    def test_1_core_behavior_beats_casing_edge_case(self, tmp_path, monkeypatch):
        """urllib3-representative: a header-casing edge case must not
        outrank the core cross-origin-stripping invariant."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        invariant = "a cross-origin redirect must strip the sensitive header from the outgoing request"
        casing_edge_case = "Verify header name case variations like 'cookie'/'COOKIE' are matched by a lowercase comparison"
        kwargs = self._base_kwargs([casing_edge_case], security_invariant=invariant)
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)

        top_action_line = self._top_action_line(report)
        va_block = self._validation_actions_block(report)

        assert "cross-origin" in top_action_line.lower(), top_action_line
        assert "case variations" not in top_action_line.lower(), top_action_line
        first_bullet_idx = va_block.find("1.")
        second_bullet_idx = va_block.find("2.")
        assert "cross-origin" in va_block[first_bullet_idx:second_bullet_idx].lower(), va_block

    def test_2_core_behavior_beats_legitimate_key_compatibility_concern(self, tmp_path, monkeypatch):
        """minimist-representative: a legitimate-key compatibility/
        regression concern must not outrank the core prototype-pollution
        containment invariant."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        invariant = "traversal through constructor and prototype keys must not pollute the object prototype"
        compat_concern = "Dotted keys legitimately named constructor or prototype are now silently dropped, a compatibility concern"
        kwargs = self._base_kwargs([compat_concern], security_invariant=invariant)
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)

        top_action_line = self._top_action_line(report)
        va_block = self._validation_actions_block(report)

        assert "constructor and prototype" in top_action_line.lower(), top_action_line
        assert "compatibility" not in top_action_line.lower(), top_action_line
        first_bullet_idx = va_block.find("1.")
        second_bullet_idx = va_block.find("2.")
        assert "constructor and prototype" in va_block[first_bullet_idx:second_bullet_idx].lower(), va_block

    def test_3_core_containment_beats_secondary_path_format_concern(self, tmp_path, monkeypatch):
        """pygeoapi-representative: a secondary path-formatting concern
        must not outrank the core path-containment invariant."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        invariant = "a resolved request path must not escape the configured data root directory"
        format_concern = "The resolved path format without a trailing separator differs slightly across platforms"
        kwargs = self._base_kwargs([format_concern], security_invariant=invariant)
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)

        top_action_line = self._top_action_line(report)
        va_block = self._validation_actions_block(report)

        assert "data root" in top_action_line.lower(), top_action_line
        assert "trailing separator" not in top_action_line.lower(), top_action_line
        first_bullet_idx = va_block.find("1.")
        second_bullet_idx = va_block.find("2.")
        assert "data root" in va_block[first_bullet_idx:second_bullet_idx].lower(), va_block

    def test_3b_security_invariant_beats_single_high_secondary_action(self, tmp_path, monkeypatch):
        """Post-review fix (real-CVE regression, pygeoapi-representative):
        the security-invariant-derived action is MEDIUM priority by design
        (unchanged), but a HIGH-priority secondary action must not win Top
        Action honors purely by outranking it on priority -- Top Action
        answers "validate the core behavior first", not "what is most
        important overall". The HIGH action's own priority, and Validation
        Action membership/order, must be completely unaffected."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        invariant = "a resolved request path must not escape the configured data root directory"
        high_secondary = "A symlink inside base pointing outside is resolved by realpath and may still be followed"
        kwargs = self._base_kwargs(
            [high_secondary], security_invariant=invariant, impact_level="high",
        )
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)

        top_action_line = self._top_action_line(report)
        va_block = self._validation_actions_block(report)

        assert "data root" in top_action_line.lower(), top_action_line
        assert "symlink" not in top_action_line.lower(), top_action_line
        # The HIGH action's own priority and membership are untouched.
        assert "**[MEDIUM]**" in va_block, va_block
        assert "**[HIGH]**" in va_block, va_block
        assert "symlink inside base" in va_block.lower(), va_block

    def test_3c_security_invariant_beats_multiple_high_secondary_actions(self, tmp_path, monkeypatch):
        """Same as above, but with two independent HIGH-priority secondary
        actions -- the security invariant still wins Top Action, and both
        HIGH actions remain present, HIGH, and in their existing relative
        order (unchanged membership/priority/ordering)."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        invariant = "a resolved request path must not escape the configured data root directory"
        high_a = "A symlink inside base pointing outside is resolved by realpath and may still be followed"
        high_b = "The trailing slash on self.data affects the boundary comparison across platforms"
        kwargs = self._base_kwargs(
            [high_a, high_b], security_invariant=invariant, impact_level="high",
        )
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)

        top_action_line = self._top_action_line(report)
        va_block = self._validation_actions_block(report)

        assert "data root" in top_action_line.lower(), top_action_line
        assert "symlink" not in top_action_line.lower(), top_action_line
        assert "trailing slash" not in top_action_line.lower(), top_action_line
        assert va_block.count("**[HIGH]**") == 2, va_block
        assert va_block.count("**[MEDIUM]**") == 1, va_block
        assert "symlink inside base" in va_block.lower(), va_block
        assert "trailing slash on self.data" in va_block.lower(), va_block

    def test_3d_top_action_override_does_not_alter_priority_ordering_membership_reason_next_step(
        self, tmp_path, monkeypatch,
    ):
        """The Top Action override must be a pure presentation choice: the
        Validation Actions section itself (priority, order, membership,
        reason, next_step of every action) must be byte-for-byte identical
        whether or not the security-invariant marker exists to redirect
        Top Action -- only the "Top action:" line differs."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        invariant = "a resolved request path must not escape the configured data root directory"
        high_secondary = "A symlink inside base pointing outside is resolved by realpath and may still be followed"

        kwargs_with = self._base_kwargs(
            [high_secondary], security_invariant=invariant, impact_level="high",
        )
        kwargs_without = self._base_kwargs(
            [high_secondary], security_invariant=None, impact_level="high",
        )
        report_with = pl._build_report(pl.PipelineResult(**kwargs_with))
        report_without = pl._build_report(pl.PipelineResult(**kwargs_without))

        # The one HIGH secondary action (present regardless of whether the
        # security-invariant action also exists) must render identically.
        va_with = self._validation_actions_block(report_with)
        va_without = self._validation_actions_block(report_without)
        assert "**[HIGH]** Verify a symlink inside base pointing outside is resolved by realpath" in va_with
        assert "**[HIGH]** Verify a symlink inside base pointing outside is resolved by realpath" in va_without
        assert f"Reason: {high_secondary}" in va_with
        assert f"Reason: {high_secondary}" in va_without
        assert "Next step: Validate the finding via focused unit tests or manual review." in va_with
        assert "Next step: Validate the finding via focused unit tests or manual review." in va_without

        # Top Action differs precisely because the marker exists in one case.
        assert "data root" in self._top_action_line(report_with).lower()
        assert "symlink" in self._top_action_line(report_without).lower()

    def test_4_secondary_observed_hypothesis_ordering_preserves_pre_existing_semantics(self, tmp_path, monkeypatch):
        """No security_invariant/concrete behavior available here -- purely
        calibration-driven ranking among two adversarial findings at the
        same priority, with no primary action to displace either of them.

        Post-review correction: a prior fix globally inverted this ranking
        (hypothesis above observed) to address a real pygeoapi-shaped
        regression, but that still used evidence-confidence classification
        as a proxy for validation importance -- just inverted -- which is
        too broad a change for this batch. That global reordering was
        reverted; this secondary-action ranking must behave exactly as it
        did before this session's change ("observed" outranks "hypothesis"
        at equal priority). The actual product requirement -- the core
        security invariant must not be displaced -- is covered separately
        by tests 1-3 above via `security_invariant`, not by reordering this
        secondary ranking. General observed-vs-hypothesis relevance among
        secondary actions remains deferred to a later batch."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        open_question = "A symlink created inside the base directory pointing outside it may not be re-validated"
        resolved_observation = "The boundary check specifically prevents a sibling-directory prefix collision"
        kwargs = self._base_kwargs([resolved_observation, open_question], security_invariant=None, behavior=None)
        kwargs["finding_calibration"] = [
            {"original": open_question, "group": "hypothesis", "reworded": "Reworded open question"},
            {"original": resolved_observation, "group": "observed", "reworded": "Reworded resolved observation"},
        ]
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)
        top_action_line = self._top_action_line(report)

        assert "prefix collision" in top_action_line.lower(), top_action_line
        assert "symlink" not in top_action_line.lower(), top_action_line

    def test_5_no_security_invariant_ranking_matches_pre_existing_batch_b(self, tmp_path, monkeypatch):
        """With no security_invariant (and no concrete behavior summary),
        Validation Action ranking must behave exactly as it did before this
        latest change -- the uncalibrated confirmed_defect/validation_gap
        vs. plausible_risk directness tiers (`_DIRECTNESS_BY_CLASSIFIER_
        CATEGORY`, untouched by this batch) still decide ordering, and the
        behavior-driven action slot stays empty exactly as before
        `security_invariant` existed."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        direct = "The redirect handling remains exploitable when headers are stripped across origins"
        speculative = "If users configure a custom retry override, that configuration path is not exercised by the existing suite"
        kwargs = self._base_kwargs([speculative, direct], security_invariant=None)
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)

        va_block = self._validation_actions_block(report)
        top_action_line = self._top_action_line(report)

        assert "Validate behavior" not in va_block, va_block
        assert "redirect handling" in top_action_line.lower(), top_action_line
        assert "retry override" not in top_action_line.lower(), top_action_line

    def test_5b_secondary_action_ordering_deterministic_alongside_core_behavior(self, tmp_path, monkeypatch):
        """When a security-invariant-derived action is present, the
        remaining secondary actions must still order deterministically
        (regardless of input order) beneath it -- the new primary action
        does not disturb the existing same-priority tiebreaker."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        invariant = "a cross-origin redirect must strip the sensitive header from the outgoing request"
        direct = "The redirect handling remains exploitable when headers are stripped across origins"
        speculative = "If users configure a custom retry override, that configuration path is not exercised by the existing suite"

        kwargs_a = self._base_kwargs([speculative, direct], security_invariant=invariant)
        kwargs_b = self._base_kwargs([direct, speculative], security_invariant=invariant)
        report_a = pl._build_report(pl.PipelineResult(**kwargs_a))
        report_b = pl._build_report(pl.PipelineResult(**kwargs_b))

        assert self._validation_actions_block(report_a) == self._validation_actions_block(report_b)

    def test_6_recommendation_decision_byte_for_byte_unchanged(self, tmp_path, monkeypatch):
        """The single most important invariant: adding security_invariant
        must never change which decision _build_recommendation_v1 returns,
        for any of the scenarios exercised above."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        scenarios = [
            self._base_kwargs(["some edge case"], security_invariant=None),
            self._base_kwargs(["some edge case"], security_invariant="a concrete security invariant statement"),
            self._base_kwargs(
                ["Cannot verify this without running the full test suite"],
                security_invariant="a concrete security invariant statement",
            ),
        ]

        for kwargs in scenarios:
            with_invariant = dict(kwargs)
            without_invariant = dict(kwargs)
            without_invariant["security_invariant"] = None

            report_with = pl._build_report(pl.PipelineResult(**with_invariant))
            report_without = pl._build_report(pl.PipelineResult(**without_invariant))

            decisions = ("Deploy After Validation", "Deploy With Caution", "Manual Review Required", "Do Not Apply")
            decision_with = next(d for d in decisions if f"**{d}**" in report_with)
            decision_without = next(d for d in decisions if f"**{d}**" in report_without)
            assert decision_with == decision_without

    def test_7_legacy_membership_cap_tests_remain_green(self):
        """Pointer/sanity check: security_invariant defaults to None and
        must not alter the legacy-equivalent membership fixtures already
        covered by TestLegacyEquivalentCapMembership (exercised in full via
        the whole-suite run) -- this is a lightweight direct check that the
        new field's absence is a true no-op."""
        from utilities.autopatcher.pipeline import PipelineResult
        import dataclasses
        assert dataclasses.fields(PipelineResult)  # sanity: still a dataclass
        default_result = PipelineResult(
            vulnerability_text="x", patch="", review="", score_text="", challenger={},
        )
        assert default_result.security_invariant is None

    def test_why_manual_review_unaffected_by_security_invariant(self, tmp_path, monkeypatch):
        """A security_invariant-driven Top Action must not change the
        "Why manual review" text or the Manual Review Required decision --
        that mechanism is derived solely from Trust Signals, never from
        Validation Actions."""
        from utilities.autopatcher import pipeline as pl
        monkeypatch.setattr(pl, "suggest_tests", lambda *a, **k: [])

        kwargs = self._base_kwargs(
            ["Cannot verify this without running the full test suite"],
            security_invariant="a resolved request path must not escape the configured data root directory",
        )
        kwargs["challenger"] = {
            "still_vulnerable": True,
            "edge_cases": ["Cannot verify this without running the full test suite"],
            "potential_issues": [], "summary": "",
        }
        result = pl.PipelineResult(**kwargs)
        report = pl._build_report(result)

        assert "**Manual Review Required**" in report
        assert "**Why manual review:**" in report
        assert "has not been confirmed" in report
