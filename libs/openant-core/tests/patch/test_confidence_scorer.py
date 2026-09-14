"""Unit tests for the confidence scorer stage.

Covers score_confidence()'s prompt-assembly contract, and specifically the
optional `finding_calibration` parameter (urllib3-trace cleanup, item 1):
when calibration is provided, the scorer must reason from the pipeline's
own already-calibrated conclusions instead of independently re-deriving
(and potentially contradicting) them; when omitted, the prompt must be
byte-identical to before this parameter existed.
"""

from __future__ import annotations

from unittest import mock

from utilities.autopatcher.confidence_scorer import score_confidence


def _user_message(call_args) -> str:
    args, kwargs = call_args
    return args[1] if len(args) > 1 else kwargs.get("user_message")


class TestScoreConfidenceBackwardCompatibility:
    def test_omitted_calibration_produces_the_exact_prior_prompt(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "Confidence score: 0.9"
        score_confidence("VULN_MARKER", "PATCH_MARKER", "REVIEW_MARKER", llm)

        user_message = _user_message(llm.complete.call_args)
        assert user_message == (
            "## Vulnerability report\n\nVULN_MARKER"
            "\n\n## Proposed patch\n\nPATCH_MARKER"
            "\n\n## Patch review\n\nREVIEW_MARKER"
        )
        assert "Already-calibrated findings" not in user_message

    def test_omitted_calibration_with_code_context_matches_prior_shape(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "Confidence score: 0.9"
        score_confidence("V", "P", "R", llm, code_context="CONTEXT_MARKER")
        user_message = _user_message(llm.complete.call_args)
        assert user_message.startswith("## Repository evidence (selected by static analysis)\n\nCONTEXT_MARKER")
        assert "Already-calibrated findings" not in user_message

    def test_empty_calibration_list_omits_the_section(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "Confidence score: 0.9"
        score_confidence("V", "P", "R", llm, finding_calibration=[])
        user_message = _user_message(llm.complete.call_args)
        assert "Already-calibrated findings" not in user_message

    def test_stage_label_unchanged(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "Confidence score: 0.9"
        score_confidence(
            "V", "P", "R", llm,
            finding_calibration=[{"original": "x", "group": "observed", "reworded": "y"}],
        )
        _, kwargs = llm.complete.call_args
        assert kwargs.get("stage") == "confidence_scorer"


class TestScoreConfidenceWithCalibration:
    def test_calibration_section_is_appended_after_the_review(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "Confidence score: 0.9"
        finding_calibration = [
            {"original": "orig", "group": "observed", "reworded": "CALIBRATION_MARKER"},
        ]
        score_confidence("VULN_MARKER", "PATCH_MARKER", "REVIEW_MARKER", llm, finding_calibration=finding_calibration)

        user_message = _user_message(llm.complete.call_args)
        assert "## Already-calibrated findings" in user_message
        assert "CALIBRATION_MARKER" in user_message
        assert user_message.index("REVIEW_MARKER") < user_message.index("CALIBRATION_MARKER")

    def test_calibration_coexists_with_code_context(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "Confidence score: 0.9"
        finding_calibration = [{"original": "x", "group": "hypothesis", "reworded": "CALIBRATION_MARKER"}]
        score_confidence(
            "V", "P", "R", llm,
            code_context="CONTEXT_MARKER", finding_calibration=finding_calibration,
        )
        user_message = _user_message(llm.complete.call_args)
        assert "CONTEXT_MARKER" in user_message
        assert "CALIBRATION_MARKER" in user_message
        assert user_message.index("CONTEXT_MARKER") < user_message.index("CALIBRATION_MARKER")


# ---------------------------------------------------------------------------
# Evidence-boundary clarification (urllib3-trace cleanup follow-up 3).
#
# Regression shape: the patch review synthesized a new, unsupported factual
# conclusion from an otherwise-valid calibrated finding, and the scorer then
# (a) treated that review-only claim as if it were itself calibrated
# evidence, and (b) used general/prior knowledge about the target software
# to declare the resulting concern resolved -- rather than preserving the
# uncertainty the supplied evidence actually leaves open.
#
# SCOPE NOTE: same limitation as every other prompt-contract test in this
# file -- reasoning quality remains entirely LLM-judgment based on the
# prompt text; this cannot (and does not try to) prove an LLM will reason
# correctly. What IS testable: (a) the prompt contains the new
# clarification, worded generically, (b) it is additive to (not a
# replacement for) the pre-existing instruction, (c) it is domain-neutral,
# and (d) the plumbing preserves whatever a contract-following LLM returns.
# ---------------------------------------------------------------------------

class TestConfidenceScorerEvidenceBoundaryContract:
    def test_patch_review_prose_is_not_calibrated_evidence(self):
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "Patch review prose is analysis, not calibrated evidence" in text
        assert (
            "Do not promote a claim that appears only in the patch review to the "
            "status of an Observed calibrated fact" in text
        )

    def test_must_not_use_prior_knowledge_to_resolve_gap(self):
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "Do not use general, prior, or external knowledge about the target software" in text
        assert "to resolve an uncertainty that remains unresolved in the supplied evidence" in text

    def test_unresolved_evidence_stays_unresolved_for_scoring(self):
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "preserve that uncertainty when assigning confidence" in text
        assert "rather than assuming the gap resolves favorably or unfavorably" in text

    def test_legitimate_supported_reasoning_still_permitted(self):
        """The clarification must not forbid reasoning from real evidence
        -- only from unsupported outside knowledge."""
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "You may still reason from the actual supplied repository evidence, "
            "deterministic results, calibrated findings" in text
        )
        assert "this rule only asks you to preserve evidence boundaries, not to discard supported reasoning" in text

    def test_existing_observed_instruction_still_present_and_additive(self):
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert 'Its "Observed" items are already-established fact' in text
        assert "do not treat an already-Observed item as an open concern when assigning your score" in text

    def test_wording_is_domain_neutral(self):
        """Scoped to the new clarification paragraphs only."""
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("Patch review prose is analysis")
        end = full_text.index("## Output format")
        added_text = full_text[start:end].lower()
        for forbidden in ("urllib3", "cookie", "header", "redirect", "casing", "cve"):
            assert forbidden not in added_text


# ---------------------------------------------------------------------------
# Evidence-boundary clarification follow-up 4 ("known upstream remediation"
# loophole).
#
# Regression shape: a real trace's Confidence response cited the generated
# patch as "exactly matching the known upstream remediation" as a POSITIVE
# scoring reason, even though the supplied vulnerability advisory only
# stated that an external fix exists somewhere -- never what that fix
# contains. The pre-existing rule above ("Do not use general, prior, or
# external knowledge... to resolve an uncertainty that remains unresolved")
# did not clearly cover this: the model was not using prior knowledge to
# resolve an unresolved gap (the diff's own content was already fully
# visible), it was using prior knowledge as unprompted corroboration for a
# score-boosting claim. This follow-up closes that specific scope gap
# without touching the pre-existing rule, the permission to reason from
# real evidence, or score_confidence()'s own plumbing/schema.
#
# SCOPE NOTE: identical limitation to every other prompt-contract test in
# this file and the class above -- reasoning quality remains entirely
# LLM-judgment based on the prompt text. These tests do NOT and cannot
# prove an LLM will actually comply; they are contract-content tests only,
# proving (a) the new prohibition text exists and covers the specific gap
# identified, (b) it is additive to (not a replacement for) the
# pre-existing rule and permission, and (c) it is domain-neutral.
# ---------------------------------------------------------------------------

class TestConfidenceScorerUpstreamKnowledgeLoopholeClosed:
    def test_prohibition_extends_beyond_resolving_an_unresolved_gap(self):
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "This prohibition is not limited to resolving an explicitly unresolved gap" in text
        assert (
            "whether or not that knowledge is being used to resolve an unresolved "
            "uncertainty" in text
        )

    def test_prohibited_knowledge_categories_named(self):
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "known upstream fixes" in text
        assert "historical implementation knowledge" in text
        assert "release-note knowledge" in text
        assert "remembered project behavior" in text
        assert "as a reason for increasing or decreasing confidence" in text

    def test_referenced_external_fix_does_not_imply_generated_patch_matches_it(self):
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "A supplied advisory or reference stating that a fix exists elsewhere "
            "establishes only that fact" in text
        )
        assert (
            "it does not establish that the generated patch matches that unseen "
            "fix, is equivalent to it, is validated by it, or deserves extra "
            "confidence because of it" in text
        )

    def test_advisory_literal_facts_remain_usable_no_overcorrection(self):
        """The new prohibition must not forbid using an advisory for what it
        actually states -- only for importing unseen external fix content."""
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "You may still use an advisory or reference for the facts it "
            "literally states -- the vulnerability description, the affected "
            "behavior, its severity, any explicitly stated version numbers, and "
            "the fact that an external fix exists" in text
        )
        assert (
            "the only prohibited step is importing unseen external fix details "
            "or remembered implementation knowledge and treating them as scoring "
            "evidence" in text
        )

    def test_preexisting_unresolved_gap_rule_still_present_unchanged(self):
        """Additive, not a replacement -- the original rule this follows up
        on must remain present verbatim."""
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "Do not use general, prior, or external knowledge about the target software" in text
        assert "to resolve an uncertainty that remains unresolved in the supplied evidence" in text
        assert "preserve that uncertainty when assigning confidence" in text

    def test_preexisting_permission_to_reason_from_supplied_evidence_still_present(self):
        """Additive, not a replacement -- the existing permission to reason
        from real evidence must remain present and must still read as the
        section's closing statement."""
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "You may still reason from the actual supplied repository evidence, "
            "deterministic results, calibrated findings, and conclusions whose "
            "full evidence chain is present" in text
        )
        assert "this rule only asks you to preserve evidence boundaries, not to discard supported reasoning" in text

    def test_new_clarification_wording_is_domain_neutral(self):
        """Scoped tightly to just the new paragraph added by this follow-up."""
        from utilities.autopatcher.confidence_scorer import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("This prohibition is not limited to resolving")
        end = full_text.index("You may still reason from the actual supplied")
        added_text = full_text[start:end].lower()
        for forbidden in ("urllib3", "cookie", "header", "redirect", "casing", "cve"):
            assert forbidden not in added_text


class TestScoreConfidenceContractFollowingPassthrough:
    """Mocked-LLM test: a response that already follows the new evidence-
    boundary contract (an unresolved dependency correctly left open rather
    than assumed to resolve favorably) passes through score_confidence()'s
    plumbing unchanged."""

    def test_contract_following_response_passes_through_unchanged(self):
        llm = mock.MagicMock()
        response_text = (
            "**Confidence score:** 0.8\n\n"
            "**Reasons:**\n"
            "- The core mechanism is well-established by the supplied evidence.\n"
            "- One additional dependency's exact runtime form is not shown, so it "
            "remains an open point rather than being treated as resolved.\n"
        )
        llm.complete.return_value = response_text
        result = score_confidence(
            "vuln text", "patch text", "review text", llm,
            finding_calibration=[{"original": "x", "group": "observed", "reworded": "y"}],
        )
        assert result == response_text

    def test_response_correctly_declining_to_credit_an_unseen_external_fix_passes_through_unchanged(self):
        """A response that follows the new (follow-up 4) contract -- noting
        that an external fix is referenced without crediting the generated
        patch with matching it -- passes through score_confidence()'s
        plumbing unchanged. Proves plumbing only; does not prove an LLM will
        actually produce this response."""
        llm = mock.MagicMock()
        response_text = (
            "**Confidence score:** 0.75\n\n"
            "**Reasons:**\n"
            "- The supplied evidence directly shows the change and the mechanism "
            "it extends.\n"
            "- The advisory notes that a fix exists elsewhere, but its contents "
            "are not shown here, so no claim is made about whether this patch "
            "matches it.\n"
        )
        llm.complete.return_value = response_text
        result = score_confidence("vuln text", "patch text", "review text", llm)
        assert result == response_text
