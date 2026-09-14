"""Unit tests for the patch reviewer stage.

Covers review_patch()'s prompt-assembly contract, and specifically the
optional `finding_calibration` parameter (urllib3-trace cleanup, item 1):
when calibration is provided, review_patch must not independently
re-derive a concern the pipeline's own finding_calibration stage already
resolved; when omitted, the prompt must be byte-identical to before this
parameter existed.
"""

from __future__ import annotations

from unittest import mock

from utilities.autopatcher.patch_reviewer import review_patch


def _user_message(call_args) -> str:
    args, kwargs = call_args
    return args[1] if len(args) > 1 else kwargs.get("user_message")


class TestReviewPatchBackwardCompatibility:
    def test_omitted_calibration_produces_the_exact_prior_prompt(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "a review"
        review_patch("VULN_MARKER", "PATCH_MARKER", llm)

        user_message = _user_message(llm.complete.call_args)
        assert user_message == (
            "## Vulnerability report\n\nVULN_MARKER\n\n## Proposed patch\n\nPATCH_MARKER"
        )
        assert "Already-calibrated findings" not in user_message

    def test_none_calibration_is_identical_to_omitted(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "a review"
        review_patch("VULN_MARKER", "PATCH_MARKER", llm, finding_calibration=None)
        user_message = _user_message(llm.complete.call_args)
        assert "Already-calibrated findings" not in user_message

    def test_empty_calibration_list_omits_the_section(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "a review"
        review_patch("VULN_MARKER", "PATCH_MARKER", llm, finding_calibration=[])
        user_message = _user_message(llm.complete.call_args)
        assert "Already-calibrated findings" not in user_message

    def test_stage_label_unchanged(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "a review"
        review_patch("v", "p", llm, finding_calibration=[{"original": "x", "group": "observed", "reworded": "y"}])
        _, kwargs = llm.complete.call_args
        assert kwargs.get("stage") == "patch_review"


class TestReviewPatchWithCalibration:
    def test_calibration_section_is_appended_after_the_patch(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "a review"
        finding_calibration = [
            {"original": "orig", "group": "observed", "reworded": "CALIBRATION_MARKER"},
        ]
        review_patch("VULN_MARKER", "PATCH_MARKER", llm, finding_calibration=finding_calibration)

        user_message = _user_message(llm.complete.call_args)
        assert "## Already-calibrated findings" in user_message
        assert "CALIBRATION_MARKER" in user_message
        # The vulnerability report and patch must still come first, unchanged.
        assert user_message.index("VULN_MARKER") < user_message.index("PATCH_MARKER")
        assert user_message.index("PATCH_MARKER") < user_message.index("CALIBRATION_MARKER")

    def test_does_not_duplicate_or_drop_the_underlying_vulnerability_and_patch_text(self):
        llm = mock.MagicMock()
        llm.complete.return_value = "a review"
        finding_calibration = [{"original": "x", "group": "hypothesis", "reworded": "y"}]
        review_patch("VULN_MARKER", "PATCH_MARKER", llm, finding_calibration=finding_calibration)
        user_message = _user_message(llm.complete.call_args)
        assert user_message.count("VULN_MARKER") == 1
        assert user_message.count("PATCH_MARKER") == 1


# ---------------------------------------------------------------------------
# Evidence-boundary clarification (urllib3-trace cleanup follow-up 3).
#
# Regression shape: a calibrated Observed finding correctly stated only a
# narrow, fully-evidenced fact, but the review combined it with its own
# analysis to synthesize a NEW factual conclusion whose missing link (an
# unshown intermediate step) was never itself established -- and then
# described that synthesized conclusion as if it were "established in the
# calibrated findings." The pre-existing "treat Observed as fact"
# instruction constrains what happens TO an existing Observed item, but
# said nothing about what NEW conclusions may be built ON TOP of one.
#
# SCOPE NOTE: same limitation as every other prompt-contract test in this
# file -- reasoning quality remains entirely LLM-judgment based on the
# prompt text; this cannot (and does not try to) prove an LLM will reason
# correctly. What IS testable: (a) the prompt contains the new
# clarification, worded generically, (b) it is additive to (not a
# replacement for) the pre-existing instruction, (c) it is domain-neutral,
# and (d) the plumbing preserves whatever a contract-following LLM returns.
# ---------------------------------------------------------------------------

class TestPatchReviewerEvidenceBoundaryContract:
    def test_new_conclusions_require_every_link_to_be_evidenced(self):
        from utilities.autopatcher.patch_reviewer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "establish only the exact factual claims they state" in text
        assert "every factual link required for that conclusion is itself supported" in text
        assert "intermediate assignment, transformation, normalization, mutation, configuration" in text

    def test_missing_link_must_stay_unresolved_not_an_established_defect(self):
        from utilities.autopatcher.patch_reviewer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "present the resulting conclusion as unresolved or requiring validation" in text
        assert "not as an established defect or established behavior" in text

    def test_legitimate_full_chain_synthesis_still_permitted(self):
        """The clarification must not forbid synthesis outright -- only
        synthesis with an unevidenced missing link."""
        from utilities.autopatcher.patch_reviewer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "does not prevent you from combining evidence when the complete chain actually is shown" in text

    def test_must_not_misattribute_own_conclusion_to_calibrated_findings(self):
        from utilities.autopatcher.patch_reviewer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "Do not describe a newly-derived conclusion as established by calibrated findings" in text
        assert "unless that exact conclusion is itself present in the calibrated findings" in text

    def test_must_not_claim_unresolved_concern_determines_effectiveness(self):
        from utilities.autopatcher.patch_reviewer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "Do not claim that an unresolved derived concern determines" in text
        assert "whether the patch is effective unless the supplied evidence establishes" in text

    def test_existing_observed_instruction_still_present_and_additive(self):
        """The pre-existing "treat Observed as fact" rule must remain
        untouched by this addition."""
        from utilities.autopatcher.patch_reviewer import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert 'Treat its "Observed" items as already-established fact' in text
        assert "do not re-derive or contradict them from general/prior" in text

    def test_wording_is_domain_neutral(self):
        """Scoped to the new clarification paragraphs only -- earlier,
        pre-existing sections of this file are out of scope here."""
        from utilities.autopatcher.patch_reviewer import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("Calibrated findings establish only")
        added_text = full_text[start:].lower()
        for forbidden in ("urllib3", "cookie", "header", "redirect", "casing", "cve"):
            assert forbidden not in added_text


class TestReviewPatchContractFollowingPassthrough:
    """Mocked-LLM test: a response that already follows the new evidence-
    boundary contract (a synthesized conclusion correctly framed as
    unresolved/requiring validation, never as an established defect)
    passes through review_patch()'s plumbing unchanged."""

    def test_contract_following_response_passes_through_unchanged(self):
        llm = mock.MagicMock()
        response_text = (
            "### Explanation\n"
            "The fix reuses an existing mechanism; whether one additional "
            "value reaches its final runtime form the same way is not shown "
            "in the supplied evidence, so that specific behavior remains "
            "unresolved and would benefit from validation rather than being "
            "treated as an established defect.\n"
        )
        llm.complete.return_value = response_text
        result = review_patch(
            "vuln text", "patch text", llm,
            finding_calibration=[{"original": "x", "group": "observed", "reworded": "y"}],
        )
        assert result == response_text
