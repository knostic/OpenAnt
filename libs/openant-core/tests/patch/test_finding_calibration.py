"""Unit tests for the finding calibration stage (evidence-quality pass).

Covers the two things that must be robust against imperfect LLM output:
_parse_response's fallback behavior (never drop a finding, never invent an
invalid group), and calibrate_findings's LLM-call contract (empty input never
calls the LLM; mock mode returns something parseable).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest


from utilities.autopatcher.finding_calibration import _parse_response, calibrate_findings


class TestParseResponse:
    def test_well_formed_response_parses_in_order(self):
        resp = (
            "1. Group: Observed\n"
            "   Reworded: The constructor normalizes casing via h.lower().\n\n"
            "2. Group: Hypothesis\n"
            "   Reworded: Same-origin redirects may also strip Cookie if stripping is not scoped.\n"
        )
        findings = ["finding one", "finding two"]
        result = _parse_response(resp, findings)
        assert len(result) == 2
        assert result[0] == {
            "original": "finding one", "group": "observed",
            "reworded": "The constructor normalizes casing via h.lower().",
        }
        assert result[1]["group"] == "hypothesis"

    def test_missing_block_falls_back_to_original_as_hypothesis(self):
        """Fewer blocks than findings must not drop the uncovered finding."""
        resp = "1. Group: Observed\n   Reworded: Reworded first finding.\n"
        findings = ["first finding", "second finding with no block"]
        result = _parse_response(resp, findings)
        assert len(result) == 2
        assert result[1] == {
            "original": "second finding with no block",
            "group": "hypothesis",
            "reworded": "second finding with no block",
        }

    def test_invalid_group_name_falls_back_to_hypothesis(self):
        resp = "1. Group: Definitely\n   Reworded: Some reworded text.\n"
        result = _parse_response(resp, ["original text"])
        assert result[0]["group"] == "hypothesis"
        assert result[0]["reworded"] == "original text"

    def test_empty_reworded_falls_back_to_original(self):
        resp = "1. Group: Observed\n   Reworded: \n"
        result = _parse_response(resp, ["original text"])
        assert result[0]["reworded"] == "original text"
        assert result[0]["group"] == "hypothesis"

    def test_completely_unparseable_response_falls_back_for_every_finding(self):
        result = _parse_response("not a structured response at all", ["a", "b", "c"])
        assert len(result) == 3
        assert all(r["group"] == "hypothesis" for r in result)
        assert [r["reworded"] for r in result] == ["a", "b", "c"]

    def test_empty_findings_list_returns_empty(self):
        assert _parse_response("anything", []) == []

    def test_reworded_text_collapses_internal_whitespace(self):
        resp = "1. Group: Hardening\n   Reworded: Line one\n   continues on line two.\n"
        result = _parse_response(resp, ["x"])
        assert "\n" not in result[0]["reworded"]

    def test_group_name_case_insensitive(self):
        resp = "1. Group: HARDENING\n   Reworded: Some text.\n"
        result = _parse_response(resp, ["x"])
        assert result[0]["group"] == "hardening"


class TestCalibrateFindings:
    def test_empty_findings_returns_empty_without_calling_llm(self):
        llm = mock.MagicMock()
        result = calibrate_findings("vuln text", "patch", [], llm, code_context="ctx")
        assert result == []
        llm.complete.assert_not_called()

    def test_calls_llm_with_stage_label_and_parses_result(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "1. Group: Observed\n   Reworded: Reworded finding.\n"
        result = calibrate_findings("vuln text", "patch", ["a finding"], llm, code_context="ctx")
        _, kwargs = llm.complete.call_args
        assert kwargs.get("stage") == "finding_calibration"
        assert result == [{"original": "a finding", "group": "observed", "reworded": "Reworded finding."}]

    def test_user_message_includes_code_context_and_findings(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "1. Group: Hardening\n   Reworded: x\n"
        calibrate_findings("VULN_MARKER", "PATCH_MARKER", ["FINDING_MARKER"], llm, code_context="CONTEXT_MARKER")
        args, kwargs = llm.complete.call_args
        user_message = args[1] if len(args) > 1 else kwargs.get("user_message")
        assert "VULN_MARKER" in user_message
        assert "PATCH_MARKER" in user_message
        assert "FINDING_MARKER" in user_message
        assert "CONTEXT_MARKER" in user_message


# ---------------------------------------------------------------------------
# Prompt-contract coverage for the "Observed must show the specific claimed
# state/behavior, including any intermediate transformation it depends on"
# tightening.
#
# IMPORTANT SCOPE NOTE: no code change was made to finding_calibration.py's
# classification logic in this pass -- classification remains entirely
# LLM-judgment based on the prompt text. These tests therefore do NOT (and
# cannot) prove an LLM will reason correctly about a missing transformation;
# real reasoning quality can only be validated against a real LLM/real
# trace. What IS deterministically testable and testable here:
#   (a) the prompt file actually contains the tightened distinction (a
#       direct content check on the real prompt file `calibrate_findings`
#       reads, not a mock), and
#   (b) the parsing/plumbing faithfully preserves whatever group an LLM
#       following that contract would return -- i.e. correct classifications
#       are not accidentally altered, dropped, or re-elevated by code
#       downstream of the LLM call.
# ---------------------------------------------------------------------------

class TestPromptContractWording:
    """Wording checks are done against whitespace-collapsed text -- the
    prompt is hand-wrapped Markdown, so a phrase spanning a line break in
    the source file must not produce a false failure here."""

    def test_observed_definition_requires_the_specific_claimed_state(self):
        """Observed must require the SPECIFIC claimed state/behavior to be
        shown -- not merely an adjacent file/function/constant -- and must
        explicitly call out an intermediate transformation/assignment/
        normalization step as part of what has to be visible."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "specific state or behavior" in text
        assert "transformation" in text
        assert "normalization" in text

    def test_hypothesis_definition_covers_an_unseen_reasoning_step(self):
        """Hypothesis must explicitly cover the case where an intermediate
        step in the reasoning chain (not just the whole file/function) is
        unseen -- this is the exact gap a class-attribute-default-only claim
        exploited (evidence showed the producer and the consumer, but not
        the normalization connecting them)."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "reasoning chain" in text
        assert "NOT directly shown" in text

    def test_prompt_contract_does_not_mention_textual_overlap_heuristics(self):
        """Explicit negative check: no textual-overlap/insufficiency-note
        matching heuristic was introduced -- that was deliberately rejected
        as brittle. The tightening is scoped to the Observed/Hypothesis
        definition only."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = _PROMPT_PATH.read_text(encoding="utf-8")
        assert "overlap" not in text.lower()
        assert "insufficien" not in text.lower()


class TestCalibrationPassthroughMatchesPromptContract:
    """Mocked-LLM tests. These simulate an LLM that DOES follow the
    tightened prompt contract and assert calibrate_findings' own plumbing
    (not LLM reasoning) preserves that classification unchanged in both
    directions -- neither silently downgrading a well-supported Observed
    finding nor silently upgrading an under-supported one."""

    def test_missing_transformation_finding_labeled_hypothesis_passes_through_unchanged(self):
        # Producer (class constant) + consumer (membership check) shown;
        # the transformation/normalization step is NOT shown. A
        # contract-following LLM must return Hypothesis for a runtime-
        # consequence claim in this shape -- assert that classification is
        # not altered by parsing.
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Group: Hypothesis\n"
            "   Reworded: If the runtime value is not normalized the same way "
            "it is compared, membership may fail.\n"
        )
        result = calibrate_findings(
            "vuln text", "patch",
            ["Membership check may fail against un-normalized entries."],
            llm, code_context="producer constant + consumer loop shown, no transformation shown",
        )
        assert result[0]["group"] == "hypothesis"

    def test_complete_evidence_finding_labeled_observed_passes_through_unchanged(self):
        # Producer + the transformation/normalization step + consumer are
        # all shown. A contract-following LLM may return Observed here --
        # assert that classification is not downgraded by parsing. This is
        # the "do not over-downgrade" check: no blanket rule was added that
        # forces every finding to Hypothesis regardless of evidence
        # completeness.
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Group: Observed\n"
            "   Reworded: The constructor normalizes values before assignment, "
            "so membership comparison succeeds.\n"
        )
        result = calibrate_findings(
            "vuln text", "patch",
            ["The constructor normalizes the value before storing it."],
            llm, code_context="producer constant + transformation + consumer loop all shown",
        )
        assert result[0]["group"] == "observed"
