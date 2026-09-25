"""Unit tests for the finding calibration stage (evidence-quality pass).

Covers the things that must be robust against imperfect LLM output:
_parse_response's fallback behavior (never drop a finding, never invent an
invalid group), the deterministic unresolved-dependency consistency gate
(an `Observed` finding cannot survive if the model's own structured output
declares a required dependency unresolved), and calibrate_findings's LLM-call
contract (empty input never calls the LLM; mock mode returns something
parseable).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest


from utilities.autopatcher.finding_calibration import (
    _parse_response, calibrate_findings, format_calibration_for_prompt,
)


class TestParseResponse:
    def test_well_formed_response_parses_in_order(self):
        resp = (
            "1. Claims:\n"
            "   - The constructor is shown normalizing casing via h.lower().\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: The constructor normalizes casing via h.lower().\n\n"
            "2. Claims:\n"
            "   - Redirect stripping is scoped to cross-origin redirects.\n"
            "   Unresolved: whether stripping is scoped to cross-origin redirects\n"
            "   Group: Hypothesis\n"
            "   Reworded: Same-origin redirects may also strip Cookie if stripping is not scoped.\n"
        )
        findings = ["finding one", "finding two"]
        result = _parse_response(resp, findings)
        assert len(result) == 2
        assert result[0] == {
            "original": "finding one", "group": "observed",
            "reworded": "The constructor normalizes casing via h.lower().",
            "unresolved_dependencies": [],
            "group_before_consistency_check": "observed",
            "remediation_impact": "validation_only",  # normalized: Unresolved parsed to []
        }
        assert result[1]["group"] == "hypothesis"
        assert result[1]["unresolved_dependencies"] == [
            "whether stripping is scoped to cross-origin redirects"
        ]

    def test_missing_block_falls_back_to_original_as_hypothesis(self):
        """Fewer blocks than findings must not drop the uncovered finding."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: Reworded first finding.\n"
        )
        findings = ["first finding", "second finding with no block"]
        result = _parse_response(resp, findings)
        assert len(result) == 2
        assert result[1] == {
            "original": "second finding with no block",
            "group": "hypothesis",
            "reworded": "second finding with no block",
            "unresolved_dependencies": [],
            "group_before_consistency_check": "hypothesis",
            "remediation_impact": "unclear",
        }

    def test_invalid_group_name_falls_back_to_hypothesis(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Group: Definitely\n"
            "   Reworded: Some reworded text.\n"
        )
        result = _parse_response(resp, ["original text"])
        assert result[0]["group"] == "hypothesis"
        assert result[0]["reworded"] == "original text"

    def test_empty_reworded_falls_back_to_original(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: \n"
        )
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
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: Line one\n"
            "   continues on line two.\n"
        )
        result = _parse_response(resp, ["x"])
        assert "\n" not in result[0]["reworded"]

    def test_group_name_case_insensitive(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Group: HARDENING\n"
            "   Reworded: Some text.\n"
        )
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
        llm.complete.return_value = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: Reworded finding.\n"
        )
        result = calibrate_findings("vuln text", "patch", ["a finding"], llm, code_context="ctx")
        _, kwargs = llm.complete.call_args
        assert kwargs.get("stage") == "finding_calibration"
        assert result == [{
            "original": "a finding", "group": "observed", "reworded": "Reworded finding.",
            "unresolved_dependencies": [], "group_before_consistency_check": "observed",
            "remediation_impact": "validation_only",  # normalized: Unresolved parsed to []
        }]

    def test_user_message_includes_code_context_and_findings(self):
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: x\n"
        )
        calibrate_findings("VULN_MARKER", "PATCH_MARKER", ["FINDING_MARKER"], llm, code_context="CONTEXT_MARKER")
        args, kwargs = llm.complete.call_args
        user_message = args[1] if len(args) > 1 else kwargs.get("user_message")
        assert "VULN_MARKER" in user_message
        assert "PATCH_MARKER" in user_message
        assert "FINDING_MARKER" in user_message
        assert "CONTEXT_MARKER" in user_message


# ---------------------------------------------------------------------------
# Structured self-report + deterministic consistency gate (Finding
# Calibration architecture follow-up).
#
# The model must now expose, per finding, the factual dependencies its
# conclusion rests on and explicitly mark any of them "Unresolved" (see
# prompts/finding_calibration.md, step 1). `_parse_response` enforces
# exactly one deterministic invariant on top of that self-report: a finding
# cannot remain "Observed" if the model's OWN structured output declares a
# required dependency unresolved. This is a pure internal-consistency check
# -- it never inspects prose for keywords and never judges whether cited
# evidence actually, semantically proves anything.
# ---------------------------------------------------------------------------

class TestUnresolvedDependencyConsistencyGate:
    def test_observed_with_no_unresolved_dependencies_remains_observed(self):
        resp = (
            "1. Claims:\n"
            "   - The evidence shows the exact behavior claimed.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: The evidence directly shows the claimed behavior.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["group"] == "observed"
        assert result[0]["unresolved_dependencies"] == []
        assert result[0]["group_before_consistency_check"] == "observed"

    def test_observed_with_one_unresolved_dependency_becomes_hypothesis(self):
        resp = (
            "1. Claims:\n"
            "   - A directly-evidenced claim.\n"
            "   - A second claim the conclusion also depends on.\n"
            "   Unresolved: whether the second claim holds\n"
            "   Group: Observed\n"
            "   Reworded: The finding states the outcome directly.\n"
        )
        result = _parse_response(resp, ["finding"])
        # The deterministic gate downgrades the effective group...
        assert result[0]["group"] == "hypothesis"
        # ...while preserving what the model actually wrote, for observability.
        assert result[0]["group_before_consistency_check"] == "observed"
        assert result[0]["unresolved_dependencies"] == ["whether the second claim holds"]
        # The gate corrects the classification, not the prose -- it must not
        # rewrite or judge the reworded text itself.
        assert result[0]["reworded"] == "The finding states the outcome directly."

    def test_observed_with_multiple_unresolved_dependencies_becomes_hypothesis(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   - Another claim.\n"
            "   Unresolved: dependency one; dependency two\n"
            "   Group: Observed\n"
            "   Reworded: The finding states the outcome directly.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["group"] == "hypothesis"
        assert result[0]["group_before_consistency_check"] == "observed"
        assert result[0]["unresolved_dependencies"] == ["dependency one", "dependency two"]

    def test_hypothesis_with_unresolved_dependencies_remains_hypothesis(self):
        """The gate only ever downgrades Observed -- it must not touch an
        already-Hypothesis classification, upgrade it, or otherwise alter it."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: whether the claim holds\n"
            "   Group: Hypothesis\n"
            "   Reworded: The outcome may occur if the claim holds.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["group"] == "hypothesis"
        assert result[0]["group_before_consistency_check"] == "hypothesis"
        assert result[0]["unresolved_dependencies"] == ["whether the claim holds"]

    def test_hardening_behavior_unchanged_regardless_of_unresolved_field(self):
        """Hardening is never subject to the gate (it only fires on
        Observed), whether or not the model also names unresolved items."""
        resp_no_unresolved = (
            "1. Claims:\n"
            "   - A claim unrelated to the advisory.\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: This is an unrelated hardening suggestion.\n"
        )
        result = _parse_response(resp_no_unresolved, ["finding"])
        assert result[0]["group"] == "hardening"
        assert result[0]["group_before_consistency_check"] == "hardening"

        resp_with_unresolved = (
            "1. Claims:\n"
            "   - A claim unrelated to the advisory.\n"
            "   Unresolved: some unrelated dependency\n"
            "   Group: Hardening\n"
            "   Reworded: This is an unrelated hardening suggestion.\n"
        )
        result2 = _parse_response(resp_with_unresolved, ["finding"])
        assert result2[0]["group"] == "hardening"
        assert result2[0]["group_before_consistency_check"] == "hardening"

    def test_missing_unresolved_field_cannot_produce_trusted_observed(self):
        """The whole block fails to match the required format when
        "Unresolved:" is absent entirely -- this finding falls back to the
        existing missing-block fallback (hypothesis, original text), never
        a trusted Observed."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Group: Observed\n"
            "   Reworded: The finding states the outcome directly.\n"
        )
        result = _parse_response(resp, ["original finding text"])
        assert result[0]["group"] == "hypothesis"
        assert result[0]["reworded"] == "original finding text"

    def test_blank_unresolved_value_cannot_produce_trusted_observed(self):
        """"Unresolved:" present but with no confidently-parseable value
        (neither "none" nor a dependency list) must fail closed -- an
        unconfirmed unresolved-status is never treated as "no unresolved
        dependencies", even though the model wrote Group: Observed."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: \n"
            "   Group: Observed\n"
            "   Reworded: The finding states the outcome directly.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["group"] == "hypothesis"
        assert result[0]["unresolved_dependencies"] == []

    def test_legitimate_fully_supported_observed_finding_still_possible(self):
        """The gate must not make Observed unreachable -- a finding whose
        dependencies are all confirmed and explicitly marked "none"
        legitimately remains Observed."""
        resp = (
            "1. Claims:\n"
            "   - The producer, transformation, and consumer are all shown.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: The evidence directly demonstrates the claimed behavior.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["group"] == "observed"
        assert result[0]["group_before_consistency_check"] == "observed"
        assert result[0]["unresolved_dependencies"] == []


class TestBackwardCompatibleFields:
    """The pre-existing `original`/`group`/`reworded` fields and their
    semantics must be preserved exactly -- existing consumers key off these
    three fields only and must not need to change."""

    def test_original_group_reworded_preserved_when_gate_does_not_fire(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: The reworded text.\n"
        )
        result = _parse_response(resp, ["the original finding"])
        assert result[0]["original"] == "the original finding"
        assert result[0]["group"] == "observed"
        assert result[0]["reworded"] == "The reworded text."

    def test_original_preserved_and_group_corrected_when_gate_fires(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: an unresolved dependency\n"
            "   Group: Observed\n"
            "   Reworded: The reworded text.\n"
        )
        result = _parse_response(resp, ["the original finding"])
        assert result[0]["original"] == "the original finding"
        assert result[0]["group"] == "hypothesis"
        assert result[0]["reworded"] == "The reworded text."

    def test_new_fields_are_purely_additive(self):
        """A caller reading only the three pre-existing keys sees exactly
        the same dict shape/values as before this change."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: A hardening suggestion.\n"
        )
        result = _parse_response(resp, ["finding"])
        legacy_view = {k: result[0][k] for k in ("original", "group", "reworded")}
        assert legacy_view == {
            "original": "finding", "group": "hardening", "reworded": "A hardening suggestion.",
        }
        assert "unresolved_dependencies" in result[0]
        assert "group_before_consistency_check" in result[0]


class TestFormatCalibrationForPromptUsesEffectiveGroup:
    def test_gate_corrected_observed_renders_under_hypothesis(self):
        """format_calibration_for_prompt() must key off the corrected,
        post-gate `group` -- since _parse_response already applies the gate
        before returning, this requires no logic change in
        format_calibration_for_prompt() itself, only that it keeps reading
        `entry["group"]` as before."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: an unresolved dependency\n"
            "   Group: Observed\n"
            "   Reworded: DOWNGRADED_TEXT\n"
        )
        finding_calibration = _parse_response(resp, ["finding"])
        rendered = format_calibration_for_prompt(finding_calibration)
        assert "**Hypothesis" in rendered
        assert "DOWNGRADED_TEXT" in rendered
        # Must not appear under the Observed heading.
        observed_idx = rendered.index("**Observed") if "**Observed" in rendered else None
        assert observed_idx is None


class TestRepairGateRespectsConsistencyGate:
    """should_auto_repair() (pipeline.py) keys off `entry.get("group") ==
    "observed"` for repair-eligible findings -- it must therefore naturally
    see the gate-corrected group, with no special-case logic of its own,
    since _parse_response already performs the correction before the entry
    ever reaches pipeline.py."""

    def test_repair_eligible_finding_cannot_authorize_repair_when_gate_fires(self):
        from utilities.autopatcher.pipeline import should_auto_repair

        finding_text = "The patch does not fix the underlying defect."
        resp = (
            "1. Claims:\n"
            "   - A claim the conclusion depends on.\n"
            "   Unresolved: whether the claim holds\n"
            "   Group: Observed\n"
            "   Reworded: The patch does not fix the underlying defect.\n"
        )
        finding_calibration = _parse_response(resp, [finding_text])
        # Sanity: the model itself said Observed; only the gate corrects it.
        assert finding_calibration[0]["group_before_consistency_check"] == "observed"
        assert finding_calibration[0]["group"] == "hypothesis"

        classified_challenger = {
            "classified_edge_cases": [],
            "classified_potential_issues": [
                {"text": finding_text, "category": "confirmed_defect"},
            ],
        }
        assert should_auto_repair(classified_challenger, finding_calibration, applicable=True) is False

    def test_repair_eligible_finding_authorizes_repair_when_genuinely_observed(self):
        from utilities.autopatcher.pipeline import should_auto_repair

        finding_text = "The patch does not fix the underlying defect."
        resp = (
            "1. Claims:\n"
            "   - A claim the conclusion depends on, fully confirmed by the evidence.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: The patch does not fix the underlying defect.\n"
        )
        finding_calibration = _parse_response(resp, [finding_text])
        assert finding_calibration[0]["group"] == "observed"

        classified_challenger = {
            "classified_edge_cases": [],
            "classified_potential_issues": [
                {"text": finding_text, "category": "confirmed_defect"},
            ],
        }
        assert should_auto_repair(classified_challenger, finding_calibration, applicable=True) is True


class TestGenericFailureShapeMockedCalibration:
    """Mocked calibration response reproducing the generic shape of the
    motivating failure: some component facts are supported by evidence, but
    one load-bearing dependency the final conclusion needs is explicitly
    unresolved -- and the model nevertheless writes `Group: Observed`. The
    parser/gate must correct this to `Hypothesis` without any keyword or
    semantic inspection of the prose itself."""

    def test_generic_load_bearing_unresolved_dependency_corrects_observed_to_hypothesis(self):
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Claims:\n"
            "   - The producing component's default value is shown.\n"
            "   - The consuming component's comparison logic is shown.\n"
            "   - The value is transformed the same way on both sides before comparison.\n"
            "   Unresolved: whether the value is transformed the same way on both sides before comparison\n"
            "   Group: Observed\n"
            "   Reworded: The comparison succeeds because both sides use the same value.\n"
        )
        result = calibrate_findings(
            "vuln text", "patch",
            ["The comparison succeeds because both sides use the same value."],
            llm, code_context="producer default and consumer comparison shown; "
                               "the transformation connecting them is not shown",
        )
        assert result[0]["group"] == "hypothesis"
        assert result[0]["group_before_consistency_check"] == "observed"
        assert result[0]["unresolved_dependencies"] == [
            "whether the value is transformed the same way on both sides before comparison"
        ]
        # The gate corrects classification only -- reworded text is untouched.
        assert result[0]["reworded"] == "The comparison succeeds because both sides use the same value."


# ---------------------------------------------------------------------------
# Block-local parsing (Finding Calibration structured-output follow-up).
#
# Regression shape: the original _BLOCK_RE skipped from "N. Claims:" forward
# to the next literal "Unresolved:"/"Group:"/"Reworded:" trio with an
# unbounded `.*?`, without ever checking whether it crossed into the NEXT
# numbered block's own text along the way. When an intermediate block was
# malformed (e.g. missing "Unresolved:"), the regex would keep scanning
# straight through that block's remaining lines and the next block's
# "N+1. Claims:" header, ultimately capturing the *next* block's own
# Unresolved/Group/Reworded fields -- silently merging two findings' data
# into one match and shifting every subsequent finding's positional
# mapping by one. This is the exact failure the fix targets: parsing must
# be strictly block-local (a block's fields are looked for only within
# that block's own isolated text span) and finding-to-block mapping must
# use the block's own printed number, never positional list order.
# ---------------------------------------------------------------------------

class TestBlockLocalParsing:
    def test_malformed_middle_block_falls_back_independently(self):
        """Block 2 is missing "Unresolved:" entirely. It must fall back to
        Hypothesis/original text on its own -- not merge with block 3."""
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   Group: Hypothesis\n"
            "   Reworded: finding two reworded.\n\n"
            "3. Claims:\n"
            "   - claim c\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding three reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        assert result[1]["group"] == "hypothesis"
        assert result[1]["reworded"] == "finding two"  # falls back to its OWN original text

    def test_following_valid_block_remains_attached_to_correct_finding(self):
        """Same malformed-middle-block response as above: finding three
        must still get its own correct Observed classification and its
        own reworded text, not be dropped or relabeled."""
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   Group: Hypothesis\n"
            "   Reworded: finding two reworded.\n\n"
            "3. Claims:\n"
            "   - claim c\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding three reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        assert result[0]["group"] == "observed"
        assert result[0]["reworded"] == "finding one reworded."
        assert result[2]["original"] == "finding three"
        assert result[2]["group"] == "observed"
        assert result[2]["reworded"] == "finding three reworded."

    def test_malformed_first_block_does_not_shift_second(self):
        """Block 1 is missing "Unresolved:". Block 2 must still map to the
        SECOND input finding with its own correct data, not be pulled up
        into slot one."""
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Group: Hypothesis\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding two reworded.\n"
        )
        findings = ["finding one", "finding two"]
        result = _parse_response(resp, findings)
        assert result[0]["original"] == "finding one"
        assert result[0]["group"] == "hypothesis"
        assert result[0]["reworded"] == "finding one"
        assert result[1]["original"] == "finding two"
        assert result[1]["group"] == "observed"
        assert result[1]["reworded"] == "finding two reworded."

    def test_blank_unresolved_cannot_borrow_fields_from_next_block(self):
        """Block 2 has a blank "Unresolved:" value. Before the fix, the
        unbounded skip would swallow block 2's own Group/Reworded AND part
        of block 3's text into one merged, mislabeled match. After the
        fix, block 2 must fail closed using only its OWN text, and block 3
        must independently parse correctly."""
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   Unresolved: \n"
            "   Group: Observed\n"
            "   Reworded: finding two reworded.\n\n"
            "3. Claims:\n"
            "   - claim c\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding three reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        # Block 2's own Group/Reworded ARE present and well-formed -- only
        # its Unresolved value is unconfirmed -- so it fails closed to
        # Hypothesis using its OWN reworded text, never block 3's.
        assert result[1]["group"] == "hypothesis"
        assert result[1]["reworded"] == "finding two reworded."
        assert result[1]["unresolved_dependencies"] == []
        # Block 3 is untouched and independently correct.
        assert result[2]["original"] == "finding three"
        assert result[2]["group"] == "observed"
        assert result[2]["reworded"] == "finding three reworded."

    def test_missing_group_cannot_borrow_fields_from_next_block(self):
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   Unresolved: none\n"
            "   Reworded: finding two reworded.\n\n"
            "3. Claims:\n"
            "   - claim c\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding three reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        assert result[1]["group"] == "hypothesis"
        assert result[1]["reworded"] == "finding two"
        assert result[2]["group"] == "observed"
        assert result[2]["reworded"] == "finding three reworded."

    def test_missing_reworded_cannot_borrow_fields_from_next_block(self):
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   Unresolved: none\n"
            "   Group: Hypothesis\n\n"
            "3. Claims:\n"
            "   - claim c\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding three reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        assert result[1]["group"] == "hypothesis"
        assert result[1]["reworded"] == "finding two"
        assert result[2]["group"] == "observed"
        assert result[2]["reworded"] == "finding three reworded."

    def test_all_valid_multi_block_response_still_parses_correctly(self):
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   Unresolved: an unresolved dependency\n"
            "   Group: Hypothesis\n"
            "   Reworded: finding two reworded.\n\n"
            "3. Claims:\n"
            "   - claim c\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: finding three reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        assert [r["group"] for r in result] == ["observed", "hypothesis", "hardening"]
        assert [r["reworded"] for r in result] == [
            "finding one reworded.", "finding two reworded.", "finding three reworded.",
        ]
        assert result[1]["unresolved_dependencies"] == ["an unresolved dependency"]

    def test_missing_block_number_fails_closed_without_shifting(self):
        """Only blocks 1 and 2 are present in the response (block 3 is
        entirely absent -- e.g. the model truncated its output). Finding
        three must fall back on its own; it must NOT silently disappear or
        cause findings one/two to shift."""
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding two reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        assert len(result) == 3
        assert result[0]["group"] == "observed" and result[0]["reworded"] == "finding one reworded."
        assert result[1]["group"] == "observed" and result[1]["reworded"] == "finding two reworded."
        assert result[2] == {
            "original": "finding three",
            "group": "hypothesis",
            "reworded": "finding three",
            "unresolved_dependencies": [],
            "group_before_consistency_check": "hypothesis",
            "remediation_impact": "unclear",
        }

    def test_duplicate_block_numbers_do_not_corrupt_other_findings(self):
        """A duplicated block number must not disturb parsing of the
        distinctly-numbered blocks around it -- the duplicate itself fails
        closed (see TestDuplicateBlockNumberFailsClosed below), and other
        findings are entirely unaffected."""
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "1. Claims:\n"
            "   - claim dup\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: duplicate one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding two reworded.\n"
        )
        findings = ["finding one", "finding two"]
        result = _parse_response(resp, findings)
        assert result[1]["original"] == "finding two"
        assert result[1]["group"] == "observed"
        assert result[1]["reworded"] == "finding two reworded."

    def test_deterministic_consistency_gate_still_fires_after_block_local_fix(self):
        """Block 2 is a well-formed Observed block that itself names an
        unresolved dependency, sitting between two other valid blocks. The
        gate must still downgrade it to Hypothesis using only its own
        text, and must not affect blocks 1 or 3."""
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b\n"
            "   - claim c\n"
            "   Unresolved: whether claim c holds\n"
            "   Group: Observed\n"
            "   Reworded: finding two reworded.\n\n"
            "3. Claims:\n"
            "   - claim d\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: finding three reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        assert result[0]["group"] == "observed"
        assert result[1]["group"] == "hypothesis"
        assert result[1]["group_before_consistency_check"] == "observed"
        assert result[1]["unresolved_dependencies"] == ["whether claim c holds"]
        assert result[1]["reworded"] == "finding two reworded."
        assert result[2]["group"] == "hardening"


# ---------------------------------------------------------------------------
# Duplicate block-number handling (Finding Calibration structured-output
# follow-up 2).
#
# A repeated numbered block (e.g. two separate "2. Claims:" blocks in one
# response) is structurally ambiguous -- there is no safe basis for
# choosing which duplicate speaks for that finding. The prior
# last-write-wins tie-break silently picked one anyway. Per the
# calibration parser's fail-closed philosophy, a duplicate number must
# instead fall back to Hypothesis/original text, exactly like a missing
# block -- never pick either duplicate as authoritative.
# ---------------------------------------------------------------------------

class TestDuplicateBlockNumberFailsClosed:
    def test_duplicate_number_falls_back_to_hypothesis_and_original_text(self):
        resp = (
            "1. Claims:\n"
            "   - claim a1\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: dup A reworded.\n\n"
            "1. Claims:\n"
            "   - claim a2\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: dup B reworded.\n"
        )
        findings = ["the original finding text"]
        result = _parse_response(resp, findings)
        assert result[0] == {
            "original": "the original finding text",
            "group": "hypothesis",
            "reworded": "the original finding text",
            "unresolved_dependencies": [],
            "group_before_consistency_check": "hypothesis",
            "remediation_impact": "unclear",
        }

    def test_duplicate_number_observed_vs_hypothesis_still_fails_closed(self):
        """Even when one duplicate says Observed and the other says
        Hypothesis, neither is trusted -- the ambiguity itself, not the
        content of either duplicate, is what triggers the fallback."""
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b1\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: dup observed reworded.\n\n"
            "2. Claims:\n"
            "   - claim b2\n"
            "   Unresolved: none\n"
            "   Group: Hypothesis\n"
            "   Reworded: dup hypothesis reworded.\n\n"
            "3. Claims:\n"
            "   - claim c\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: finding three reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        assert result[1]["group"] == "hypothesis"
        assert result[1]["reworded"] == "finding two"
        assert result[1]["reworded"] not in ("dup observed reworded.", "dup hypothesis reworded.")

    def test_duplicate_number_does_not_affect_neighboring_unique_findings(self):
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n\n"
            "2. Claims:\n"
            "   - claim b1\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: dup one.\n\n"
            "2. Claims:\n"
            "   - claim b2\n"
            "   Unresolved: none\n"
            "   Group: Hypothesis\n"
            "   Reworded: dup two.\n\n"
            "3. Claims:\n"
            "   - claim c\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: finding three reworded.\n"
        )
        findings = ["finding one", "finding two", "finding three"]
        result = _parse_response(resp, findings)
        assert result[0]["group"] == "observed"
        assert result[0]["reworded"] == "finding one reworded."
        assert result[2]["group"] == "hardening"
        assert result[2]["reworded"] == "finding three reworded."

    def test_out_of_order_unique_numbers_still_parse_correctly(self):
        """Out-of-order but UNIQUE numbering must keep working -- only
        actual duplication triggers the fail-closed path."""
        resp = (
            "2. Claims:\n"
            "   - claim b\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding two reworded.\n\n"
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Hardening\n"
            "   Reworded: finding one reworded.\n"
        )
        findings = ["finding one", "finding two"]
        result = _parse_response(resp, findings)
        assert result[0]["original"] == "finding one"
        assert result[0]["group"] == "hardening"
        assert result[0]["reworded"] == "finding one reworded."
        assert result[1]["original"] == "finding two"
        assert result[1]["group"] == "observed"
        assert result[1]["reworded"] == "finding two reworded."

    def test_missing_block_number_unaffected_by_duplicate_handling(self):
        """A block that is simply ABSENT (not duplicated) must continue to
        fail closed exactly as before -- duplicate-detection must not
        change plain-missing-block behavior."""
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: finding one reworded.\n"
        )
        findings = ["finding one", "finding two"]
        result = _parse_response(resp, findings)
        assert result[1] == {
            "original": "finding two",
            "group": "hypothesis",
            "reworded": "finding two",
            "unresolved_dependencies": [],
            "group_before_consistency_check": "hypothesis",
            "remediation_impact": "unclear",
        }


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

    def test_dependency_exposure_step_present(self):
        """The new step 1 (expose factual dependencies / mark unresolved
        ones) must precede classification and require the group to follow
        from the dependency list."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "Expose the finding's factual dependencies" in text
        assert "mark any of them the supplied evidence above does not independently establish as unresolved" in text
        assert "the group must follow from this list, not the other way around" in text

    def test_observed_requires_no_unresolved_item_in_dependency_list(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "A finding may be classified `Observed` only if the dependency list above contains no unresolved item" in text

    def test_output_format_requires_claims_and_unresolved_fields(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = _PROMPT_PATH.read_text(encoding="utf-8")
        assert "Claims:" in text
        assert "Unresolved: none" in text
        assert "Group: <Observed|Hypothesis|Hardening>" in text
        assert "Reworded: <the reworded finding, one paragraph, no line breaks>" in text


# ---------------------------------------------------------------------------
# Cross-finding contradiction check (urllib3-trace cleanup follow-up).
#
# Regression shape: two challenger findings drew mutually incompatible
# runtime conclusions from the same, only-partially-shown mechanism, and
# calibration classified BOTH as `Observed` because classification was
# applied to each finding in isolation, with nothing checking the batch's
# own internal consistency. The prompt now requires the model to check for
# exactly this shape before finalizing any `Observed` classification.
#
# SCOPE NOTE: no change was made to calibrate_findings()/_parse_response()'s
# classification logic -- classification remains entirely LLM-judgment
# based on the prompt text (same limitation TestPromptContractWording above
# already documents). What IS deterministically testable here: (a) the
# prompt contains the new contract, worded generically, and (b) the
# existing parsing/plumbing preserves whatever a contract-following LLM
# returns for a contradictory pair, unchanged.
# ---------------------------------------------------------------------------

class TestCrossFindingContradictionContract:
    def test_prompt_requires_checking_the_batch_for_contradictions(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "mutually incompatible conclusions" in text
        assert "same underlying mechanism, value, transformation, or comparison" in text
        assert "neither one may be classified `Observed`" in text
        assert "reclassify both as `Hypothesis`" in text

    def test_prompt_still_requires_the_original_observed_bar_on_its_own(self):
        """The contradiction check must be additive, not a replacement for
        the pre-existing single-finding Observed requirement."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "specific state or behavior" in text
        assert "transformation" in text
        assert "normalization" in text
        assert "in addition to, not instead of, the `Observed` requirement above" in text

    def test_reworded_contract_requires_naming_the_unresolved_tension(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "a related finding reaches the opposite conclusion" in text
        assert "the available evidence does not establish which one is correct" in text

    def test_contract_wording_is_domain_neutral(self):
        """Must not mention urllib3, Cookie, headers, casing, or any
        CVE-specific vocabulary -- the added instruction must generalize to
        any pair of contradictory findings, not just this trace's shape.

        Scoped to the NEW contradiction-check step (item 4) and its Reword
        clause (item 5's added sentence) only -- the file's pre-existing
        "Example input findings"/"Example output" section already uses
        Cookie/header as an illustration unrelated to this change and is
        out of scope here. (Item numbers shifted from 3/4 to 4/5 when the
        Remediation impact axis was inserted as item 2.)"""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("4. **Check the full batch for contradictions**")
        end = full_text.index("Do not invent new findings.")
        added_text = full_text[start:end].lower()
        for forbidden in ("urllib3", "cookie", "header", "casing", "cve"):
            assert forbidden not in added_text


class TestContradictoryFindingsPassthrough:
    """Mocked-LLM tests: simulate an LLM that DOES follow the new
    contradiction-check contract and assert calibrate_findings' own
    plumbing preserves that outcome unchanged -- proving the mechanical
    pipeline doesn't itself re-elevate, drop, or otherwise corrupt a
    contradiction-driven reclassification."""

    def test_unresolved_contradictory_pair_both_pass_through_as_hypothesis(self):
        # Two findings about the same generic mechanism, reaching opposite
        # conclusions, with a mocked response that already applied the new
        # contract (both reclassified Hypothesis, each noting the other's
        # opposite conclusion). Deliberately domain-neutral wording.
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Claims:\n"
            "   - The transformation normalizes the value before comparison.\n"
            "   Unresolved: whether the transformation normalizes the value before comparison\n"
            "   Group: Hypothesis\n"
            "   Reworded: The transformation may normalize the value before comparison, "
            "in which case the comparison would succeed; a related finding reaches the "
            "opposite conclusion and the available evidence does not establish which one "
            "is correct.\n\n"
            "2. Claims:\n"
            "   - The transformation normalizes the value before comparison.\n"
            "   Unresolved: whether the transformation normalizes the value before comparison\n"
            "   Group: Hypothesis\n"
            "   Reworded: The transformation may not normalize the value before comparison, "
            "in which case the comparison would fail; a related finding reaches the "
            "opposite conclusion and the available evidence does not establish which one "
            "is correct.\n"
        )
        findings = [
            "The value is normalized before comparison, so the comparison succeeds.",
            "The value is not normalized before comparison, so the comparison fails.",
        ]
        result = calibrate_findings(
            "vuln text", "patch", findings, llm,
            code_context="only the comparison site is shown, not the value's construction",
        )
        assert len(result) == 2
        assert result[0]["group"] == "hypothesis"
        assert result[1]["group"] == "hypothesis"
        assert "opposite conclusion" in result[0]["reworded"]
        assert "opposite conclusion" in result[1]["reworded"]

    def test_uncontested_fully_evidenced_observed_finding_still_passes_through(self):
        """The new contract must not cause a well-evidenced, uncontested
        finding to be downgraded by the plumbing -- classification is
        entirely the model's call; parsing must preserve Observed here
        exactly as before this change (same case already covered by
        TestCalibrationPassthroughMatchesPromptContract, repeated here to
        prove the new contract addition didn't alter this path)."""
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Claims:\n"
            "   - The constructor normalizes values before assignment.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: The constructor normalizes values before assignment, "
            "so membership comparison succeeds.\n"
        )
        result = calibrate_findings(
            "vuln text", "patch",
            ["The constructor normalizes the value before storing it."],
            llm, code_context="producer constant + transformation + consumer loop all shown",
        )
        assert result[0]["group"] == "observed"
        assert result[0]["reworded"] == (
            "The constructor normalizes values before assignment, so membership comparison succeeds."
        )


# ---------------------------------------------------------------------------
# Use-site vs. runtime-value distinction (urllib3-trace cleanup follow-up 2).
#
# Regression shape: two challenger findings independently reached the same
# transformation-dependent conclusion (they AGREE, they don't contradict
# each other), and calibration classified BOTH as Observed because the
# comparison/use site itself was visible in the evidence -- even though the
# value flowing into that comparison only reaches its final runtime form
# through an unseen transformation. The pre-existing cross-finding
# contradiction check (above) does not fire here by design (nothing
# contradicts), so the Observed bar itself needed to explicitly rule out
# "the use site is visible" as sufficient grounds on its own.
#
# SCOPE NOTE: same limitation as every other prompt-contract test in this
# file -- classification remains entirely LLM-judgment based on the prompt
# text; this cannot (and does not try to) prove an LLM will reason
# correctly. What IS testable: (a) the prompt contains the new distinction,
# worded generically, (b) it does not replace either pre-existing rule, and
# (c) the plumbing preserves whatever a contract-following LLM returns.
# ---------------------------------------------------------------------------

class TestUseSiteVersusRuntimeValueContract:
    def test_prompt_distinguishes_use_site_visibility_from_runtime_value(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "is not sufficient on its own" in text
        assert "must independently be visible in the supplied evidence" in text
        assert "must not be classified as `Observed`" in text

    def test_holds_even_when_conclusion_agreed_or_uncontradicted(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "the conclusion appears likely" in text
        assert "multiple findings agree with it" in text
        assert "no finding contradicts it" in text
        assert "the comparison/use site itself is directly shown" in text

    def test_existing_transformation_visibility_requirement_still_present(self):
        """Additive, not a replacement: the original Observed bar (specific
        state/behavior, transformation/normalization step) must remain."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "specific state or behavior" in text
        assert "transformation" in text
        assert "normalization" in text
        assert "that step itself must be" in text
        assert "visible in the evidence above" in text

    def test_cross_finding_contradiction_rule_still_present_and_additive(self):
        """The earlier contradiction check (a separate fix) must remain
        untouched by this addition."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "mutually incompatible conclusions" in text
        assert "reclassify both as `Hypothesis`" in text
        assert "in addition to, not instead of, the `Observed` requirement above" in text

    def test_contract_wording_is_domain_neutral(self):
        """Scoped to the new clarification paragraph only -- the file's
        pre-existing "Example input findings"/"Example output" section
        already uses Cookie/header/redirect as an illustration unrelated
        to this change and is out of scope here."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("Seeing the comparison, membership check")
        end = full_text.index("- `Hypothesis`")
        added_text = full_text[start:end].lower()
        for forbidden in ("urllib3", "cookie", "header", "redirect", "casing", "cve"):
            assert forbidden not in added_text

    def test_output_format_instructions_unchanged(self):
        """The Group/Reworded numbered-list contract must be untouched by
        this addition."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = _PROMPT_PATH.read_text(encoding="utf-8")
        assert "Group: <Observed|Hypothesis|Hardening>" in text
        assert "Reworded: <the reworded finding, one paragraph, no line breaks>" in text


class TestTransformationDependentHedgedFindingPassthrough:
    """Mocked-LLM tests: simulate an LLM that DOES follow the new use-site/
    runtime-value distinction and assert calibrate_findings' own plumbing
    preserves that outcome unchanged -- proving the mechanical pipeline
    doesn't itself re-elevate a hedged, transformation-dependent finding."""

    def test_hedged_transformation_dependent_finding_returned_hypothesis_passes_through(self):
        # The finding's own wording hedges ("would need confirmation") about
        # a value that only reaches its runtime form through an unseen
        # step; the comparison/use site itself IS shown. A contract-
        # following LLM returns Hypothesis regardless -- the plumbing must
        # not re-elevate it to Observed.
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Claims:\n"
            "   - The comparison uses the value's runtime form after an unseen transformation.\n"
            "   Unresolved: whether the value's runtime form reflects the required transformation\n"
            "   Group: Hypothesis\n"
            "   Reworded: The use site compares against the value directly, but "
            "whether that value reflects the required transformation is not shown, "
            "so this would need confirmation before treating the comparison's "
            "outcome as established.\n"
        )
        result = calibrate_findings(
            "vuln text", "patch",
            ["The comparison site is shown, but the transformation feeding its "
             "operand is not, so the match outcome would need confirmation."],
            llm, code_context="only the comparison/use site is shown, not the producing transformation",
        )
        assert result[0]["group"] == "hypothesis"
        assert "would need confirmation" in result[0]["reworded"]

    def test_uncontested_fully_evidenced_observed_finding_unchanged(self):
        """Existing uncontested Observed passthrough behavior is unaffected
        by this addition -- same scenario/assertions as the pre-existing
        coverage elsewhere in this file, repeated here for direct
        traceability to this specific prompt change."""
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Claims:\n"
            "   - The constructor normalizes values before assignment.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: The constructor normalizes values before assignment, "
            "so membership comparison succeeds.\n"
        )
        result = calibrate_findings(
            "vuln text", "patch",
            ["The constructor normalizes the value before storing it."],
            llm, code_context="producer constant + transformation + consumer loop all shown",
        )
        assert result[0]["group"] == "observed"
        assert result[0]["reworded"] == (
            "The constructor normalizes values before assignment, so membership comparison succeeds."
        )


# ---------------------------------------------------------------------------
# Entire-final-conclusion standard (urllib3-trace cleanup follow-up 4).
#
# Regression shape: a finding cited a directly-observed comparison mechanism
# (one operand's own transformation shown) and a directly-observed
# constant/default, then drew a composed conclusion (a match/coverage
# outcome) that ALSO depended on a different, unshown operand's own
# construction -- and was classified Observed anyway. The prior use-site/
# runtime-value clarification is phrased around a single value's own
# transformation; it doesn't explicitly say that a comparison/composed
# outcome needs EVERY operand's derivation shown, or that partial,
# component-level evidence never suffices for the finding's overall claim.
#
# SCOPE NOTE: same limitation as every other prompt-contract test in this
# file -- reasoning quality remains entirely LLM-judgment based on the
# prompt text; this cannot (and does not try to) prove an LLM will reason
# correctly. What IS testable: (a) the prompt contains the new
# clarification, worded generically, (b) it is additive to (not a
# replacement for) both pre-existing Observed-related rules, (c) it is
# domain-neutral, and (d) the plumbing preserves whatever a contract-
# following LLM returns.
# ---------------------------------------------------------------------------

class TestEntireFinalConclusionContract:
    def test_standard_applies_to_entire_final_conclusion_not_component_facts(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "applies to the finding's entire final conclusion, not" in text
        assert "merely to individual supporting facts" in text

    def test_component_level_evidence_alone_is_insufficient(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "may contain several directly observed component facts and still fail to qualify as `Observed`" in text

    def test_every_operand_or_link_must_independently_be_evidenced(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "Every factual dependency required for the final conclusion must independently satisfy" in text
        assert "the same `Observed` standard" in text

    def test_one_side_of_a_comparison_does_not_establish_the_other(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "For comparisons or composed outcomes, evidence for one side or one "
            "contributing transformation does not establish the other side" in text
        )

    def test_unsupported_final_outcome_must_remain_hypothesis(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "otherwise the finding must remain `Hypothesis`" in text

    def test_reworded_text_must_not_overstate_the_supported_classification(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "its reworded text must not state a stronger factual conclusion than the evidence supports" in text

    def test_existing_use_site_transformation_clarification_still_present(self):
        """Additive, not a replacement: the prior single-value use-site/
        runtime-value clarification must remain untouched."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "is not sufficient on its own" in text
        assert "must independently be visible in the supplied evidence" in text
        assert "must not be classified as `Observed`" in text

    def test_existing_cross_finding_contradiction_rule_still_present(self):
        """Additive, not a replacement: the earlier contradiction check
        must remain untouched by this addition."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "mutually incompatible conclusions" in text
        assert "reclassify both as `Hypothesis`" in text
        assert "in addition to, not instead of, the `Observed` requirement above" in text

    def test_wording_is_domain_neutral(self):
        """Scoped to the new clarification paragraph only."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("This standard applies to the finding's entire final conclusion")
        end = full_text.index("- `Hypothesis`")
        added_text = full_text[start:end].lower()
        for forbidden in ("urllib3", "cookie", "header", "redirect", "casing", "cve"):
            assert forbidden not in added_text


class TestComposedConclusionPassthrough:
    """Mocked-LLM tests: simulate an LLM that DOES follow the new
    entire-final-conclusion standard and assert calibrate_findings' own
    plumbing preserves that outcome unchanged."""

    def test_two_operand_finding_with_one_missing_derivation_stays_hypothesis(self):
        # One operand's own transformation is shown (e.g. an incoming value
        # is normalized before use); the OTHER operand's own construction
        # is not shown. A contract-following LLM must return Hypothesis for
        # the composed match/coverage outcome -- the plumbing must not
        # re-elevate it.
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Claims:\n"
            "   - The incoming value is normalized before comparison.\n"
            "   - The stored collection's entries went through the same normalization.\n"
            "   Unresolved: whether the stored collection's entries went through the same normalization\n"
            "   Group: Hypothesis\n"
            "   Reworded: The incoming value is normalized before the comparison, but "
            "whether the stored collection's own entries went through the same "
            "normalization is not shown, so the comparison outcome is not established "
            "by the supplied evidence.\n"
        )
        result = calibrate_findings(
            "vuln text", "patch",
            ["A differently-formed input value is covered because the comparison "
             "normalizes the incoming value before checking it against the "
             "collection."],
            llm, code_context="only the incoming-value normalization and the comparison site are shown; "
                               "the collection's own construction is not shown",
        )
        assert result[0]["group"] == "hypothesis"
        assert "not established by the supplied evidence" in result[0]["reworded"]

    def test_fully_evidenced_composed_comparison_stays_observed(self):
        """The new standard must not cause a genuinely fully-evidenced
        composed conclusion (every operand's derivation shown) to be
        downgraded by the plumbing -- classification remains the model's
        call; parsing must preserve Observed here."""
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "1. Claims:\n"
            "   - The incoming value's normalization is shown.\n"
            "   - The stored collection's own construction and normalization are shown.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: Both the incoming value's normalization and the stored "
            "collection's own construction are shown, and both apply the same "
            "normalization, so the comparison succeeds as claimed.\n"
        )
        result = calibrate_findings(
            "vuln text", "patch",
            ["A differently-formed input value is covered because both sides of "
             "the comparison are normalized the same way."],
            llm, code_context="both the incoming-value normalization and the collection's own "
                               "construction/normalization are shown",
        )
        assert result[0]["group"] == "observed"
        assert result[0]["reworded"] == (
            "Both the incoming value's normalization and the stored collection's own "
            "construction are shown, and both apply the same normalization, so the "
            "comparison succeeds as claimed."
        )


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
            "1. Claims:\n"
            "   - The runtime value is normalized the same way it is compared.\n"
            "   Unresolved: whether the runtime value is normalized the same way it is compared\n"
            "   Group: Hypothesis\n"
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
            "1. Claims:\n"
            "   - The constructor normalizes values before assignment.\n"
            "   Unresolved: none\n"
            "   Group: Observed\n"
            "   Reworded: The constructor normalizes values before assignment, "
            "so membership comparison succeeds.\n"
        )
        result = calibrate_findings(
            "vuln text", "patch",
            ["The constructor normalizes the value before storing it."],
            llm, code_context="producer constant + transformation + consumer loop all shown",
        )
        assert result[0]["group"] == "observed"


# ---------------------------------------------------------------------------
# format_calibration_for_prompt -- the later-stage (Patch Review, Confidence
# Scoring) prompt section built from already-computed calibrate_findings()
# output (urllib3-trace cleanup, item 1). Pure formatting: no LLM call, no
# re-classification.
# ---------------------------------------------------------------------------

class TestFormatCalibrationForPrompt:
    def test_none_returns_empty_string(self):
        assert format_calibration_for_prompt(None) == ""

    def test_empty_list_returns_empty_string(self):
        assert format_calibration_for_prompt([]) == ""

    def test_groups_by_epistemic_group_with_labels(self):
        finding_calibration = [
            {"original": "o1", "group": "observed", "reworded": "OBSERVED_TEXT"},
            {"original": "o2", "group": "hypothesis", "reworded": "HYPOTHESIS_TEXT"},
            {"original": "o3", "group": "hardening", "reworded": "HARDENING_TEXT"},
        ]
        rendered = format_calibration_for_prompt(finding_calibration)
        assert "## Already-calibrated findings" in rendered
        assert "OBSERVED_TEXT" in rendered
        assert "HYPOTHESIS_TEXT" in rendered
        assert "HARDENING_TEXT" in rendered
        # Observed must precede Hypothesis must precede Hardening, regardless
        # of input order -- a stable, predictable reading order for the
        # later-stage prompt.
        assert rendered.index("OBSERVED_TEXT") < rendered.index("HYPOTHESIS_TEXT")
        assert rendered.index("HYPOTHESIS_TEXT") < rendered.index("HARDENING_TEXT")

    def test_falls_back_to_original_when_reworded_missing(self):
        finding_calibration = [{"original": "ORIGINAL_TEXT", "group": "observed", "reworded": ""}]
        rendered = format_calibration_for_prompt(finding_calibration)
        assert "ORIGINAL_TEXT" in rendered

    def test_unknown_group_falls_back_to_hypothesis_bucket(self):
        finding_calibration = [{"original": "x", "group": "something_else", "reworded": "TEXT"}]
        rendered = format_calibration_for_prompt(finding_calibration)
        assert "TEXT" in rendered
        assert "Hypothesis" in rendered

    def test_entry_with_no_text_at_all_is_skipped_not_rendered_blank(self):
        finding_calibration = [
            {"original": "", "group": "observed", "reworded": ""},
            {"original": "o2", "group": "observed", "reworded": "KEPT_TEXT"},
        ]
        rendered = format_calibration_for_prompt(finding_calibration)
        # Bullet lines only -- "\n- " (never the prose disclaimer's own
        # "-- build on them" em-dash-like punctuation).
        assert rendered.count("\n- ") == 1
        assert "KEPT_TEXT" in rendered

    def test_all_entries_empty_returns_empty_string(self):
        finding_calibration = [{"original": "", "group": "observed", "reworded": ""}]
        assert format_calibration_for_prompt(finding_calibration) == ""

    def test_result_ends_with_single_trailing_newline(self):
        finding_calibration = [{"original": "o", "group": "observed", "reworded": "x"}]
        rendered = format_calibration_for_prompt(finding_calibration)
        assert rendered.endswith("\n") and not rendered.endswith("\n\n")


# ---------------------------------------------------------------------------
# Remediation impact -- second, independent structured axis (additive to
# Observed/Hypothesis/Hardening). See finding_calibration.py's own module
# docstring and pipeline._reconcile_verification_status_with_calibration,
# the sole consumer authorized to turn this into blocking authority.
# ---------------------------------------------------------------------------

class TestRemediationImpactField:
    def test_proof_required_parses(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: whether X holds\n"
            "   Remediation impact: proof_required\n"
            "   Group: Hypothesis\n"
            "   Reworded: Some reworded text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["remediation_impact"] == "proof_required"
        # Independent of the existing axis -- group is untouched by this field.
        assert result[0]["group"] == "hypothesis"

    def test_validation_only_parses(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: whether X holds\n"
            "   Remediation impact: validation_only\n"
            "   Group: Hypothesis\n"
            "   Reworded: Some reworded text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["remediation_impact"] == "validation_only"

    def test_unclear_parses(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: whether X holds\n"
            "   Remediation impact: unclear\n"
            "   Group: Hypothesis\n"
            "   Reworded: Some reworded text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["remediation_impact"] == "unclear"

    def test_missing_field_fails_closed_to_unclear(self):
        """Old-format block (no Remediation impact line at all) must still
        parse Group/Reworded/Unresolved exactly as before -- only this new
        field degrades, to "unclear", never silently to "validation_only".

        Uses a non-empty Unresolved value deliberately: an empty
        ("none") Unresolved list is deterministically normalized to
        "validation_only" regardless of the (missing) field -- see
        TestRemediationImpactEmptyUnresolvedNormalization -- so this test
        keeps a genuinely unresolved dependency to isolate the
        missing-field fail-closed behavior on its own."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: whether the consuming code normalizes this value\n"
            "   Group: Observed\n"
            "   Reworded: Some reworded text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["remediation_impact"] == "unclear"
        assert result[0]["group"] == "hypothesis"  # Observed downgraded: Unresolved names a dependency
        assert result[0]["reworded"] == "Some reworded text."

    def test_malformed_value_fails_closed_to_unclear(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: whether X holds\n"
            "   Remediation impact: sort_of_maybe\n"
            "   Group: Hypothesis\n"
            "   Reworded: Some reworded text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["remediation_impact"] == "unclear"

    def test_empty_value_fails_closed_to_unclear(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: whether X holds\n"
            "   Remediation impact: \n"
            "   Group: Hypothesis\n"
            "   Reworded: Some reworded text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["remediation_impact"] == "unclear"

    def test_case_insensitive(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: whether X holds\n"
            "   Remediation impact: PROOF_REQUIRED\n"
            "   Group: Hypothesis\n"
            "   Reworded: Some reworded text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["remediation_impact"] == "proof_required"

    def test_missing_block_fails_closed_to_unclear_for_that_finding_only(self):
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Remediation impact: validation_only\n"
            "   Group: Observed\n"
            "   Reworded: Reworded first finding.\n"
        )
        result = _parse_response(resp, ["first finding", "second finding with no block"])
        assert result[0]["remediation_impact"] == "validation_only"
        assert result[1]["remediation_impact"] == "unclear"

    def test_duplicate_block_number_fails_closed_to_unclear(self):
        resp = (
            "1. Claims:\n"
            "   - claim a\n"
            "   Unresolved: none\n"
            "   Remediation impact: validation_only\n"
            "   Group: Observed\n"
            "   Reworded: dup A reworded.\n\n"
            "1. Claims:\n"
            "   - claim a2\n"
            "   Unresolved: none\n"
            "   Remediation impact: validation_only\n"
            "   Group: Observed\n"
            "   Reworded: dup B reworded.\n"
        )
        result = _parse_response(resp, ["the original finding text"])
        assert result[0]["remediation_impact"] == "unclear"

    def test_completely_unparseable_response_fails_closed_to_unclear_for_every_finding(self):
        result = _parse_response("not a structured response at all", ["a", "b", "c"])
        assert all(r["remediation_impact"] == "unclear" for r in result)

    def test_never_borrows_another_findings_value(self):
        """Block 1 has proof_required, block 2 has validation_only -- each
        finding's own value must never leak onto its neighbor."""
        resp = (
            "1. Claims:\n"
            "   - claim one\n"
            "   Unresolved: whether X holds\n"
            "   Remediation impact: proof_required\n"
            "   Group: Hypothesis\n"
            "   Reworded: one reworded.\n\n"
            "2. Claims:\n"
            "   - claim two\n"
            "   Unresolved: whether Y holds\n"
            "   Remediation impact: validation_only\n"
            "   Group: Hypothesis\n"
            "   Reworded: two reworded.\n"
        )
        result = _parse_response(resp, ["finding one", "finding two"])
        assert result[0]["remediation_impact"] == "proof_required"
        assert result[1]["remediation_impact"] == "validation_only"

    def test_unresolved_status_unconfirmed_fails_closed_to_unclear(self):
        """When the sibling "Unresolved:" field itself is unparseable (the
        existing gate that already falls the finding back to "hypothesis"),
        remediation_impact must fail closed alongside it, never keep
        whatever value happened to follow."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: \n"
            "   Remediation impact: proof_required\n"
            "   Group: Observed\n"
            "   Reworded: Some reworded text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["group"] == "hypothesis"
        assert result[0]["remediation_impact"] == "unclear"

    def test_does_not_replace_observed_hypothesis_hardening_axis(self):
        """Independent second axis -- group classification is computed
        exactly as before, regardless of the new field's value.

        Uses a non-empty Unresolved value deliberately, so this test's own
        `remediation_impact` value survives unnormalized and actually
        exercises independence from `group` -- see
        TestRemediationImpactEmptyUnresolvedNormalization for the
        `Unresolved: none` + non-"validation_only" case, which is
        deterministically normalized regardless of `group`."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: whether the consuming code normalizes this value\n"
            "   Remediation impact: proof_required\n"
            "   Group: Hardening\n"
            "   Reworded: A hardening suggestion.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["group"] == "hardening"
        assert result[0]["remediation_impact"] == "proof_required"


# ---------------------------------------------------------------------------
# Deterministic empty-unresolved consistency normalization: Unresolved
# successfully parsed to an empty list ("none") forces remediation_impact to
# "validation_only", regardless of what the model wrote for that field --
# see prompts/finding_calibration.md's own contract ("Whenever Unresolved:
# none applies, Remediation impact: must be validation_only") and
# pipeline._finding_blocks_remediation_proof, which already treats an empty
# unresolved_dependencies list as non-blocking before ever consulting
# remediation_impact -- this normalization makes the STORED record
# internally consistent with that pre-existing decision; it never changes
# decision behavior on its own.
# ---------------------------------------------------------------------------

class TestRemediationImpactEmptyUnresolvedNormalization:
    def test_none_plus_proof_required_normalizes_to_validation_only(self):
        resp = (
            "1. Claims:\n"
            "   - The evidence directly establishes the claim.\n"
            "   Unresolved: none\n"
            "   Remediation impact: proof_required\n"
            "   Group: Observed\n"
            "   Reworded: text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["unresolved_dependencies"] == []
        assert result[0]["remediation_impact"] == "validation_only"

    def test_none_plus_unclear_normalizes_to_validation_only(self):
        resp = (
            "1. Claims:\n"
            "   - The evidence directly establishes the claim.\n"
            "   Unresolved: none\n"
            "   Remediation impact: unclear\n"
            "   Group: Observed\n"
            "   Reworded: text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["unresolved_dependencies"] == []
        assert result[0]["remediation_impact"] == "validation_only"

    def test_none_plus_validation_only_is_unchanged(self):
        resp = (
            "1. Claims:\n"
            "   - The evidence directly establishes the claim.\n"
            "   Unresolved: none\n"
            "   Remediation impact: validation_only\n"
            "   Group: Observed\n"
            "   Reworded: text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["unresolved_dependencies"] == []
        assert result[0]["remediation_impact"] == "validation_only"

    def test_non_empty_unresolved_is_never_normalized(self):
        """Genuine unresolved proof requirement: normalization must not
        touch a finding whose Unresolved list is actually non-empty."""
        resp = (
            "1. Claims:\n"
            "   - Partial evidence only.\n"
            "   Unresolved: whether X holds\n"
            "   Remediation impact: proof_required\n"
            "   Group: Hypothesis\n"
            "   Reworded: text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["unresolved_dependencies"] == ["whether X holds"]
        assert result[0]["remediation_impact"] == "proof_required"

    def test_related_but_insufficient_evidence_stays_proof_required(self):
        """Related evidence existing nearby must not, by itself, empty out
        Unresolved -- only a model-authored empty Unresolved normalizes."""
        resp = (
            "1. Claims:\n"
            "   - Related evidence was shown but does not establish the\n"
            "     specific dependency.\n"
            "   Unresolved: whether the specific dependency holds\n"
            "   Remediation impact: proof_required\n"
            "   Group: Hypothesis\n"
            "   Reworded: text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["unresolved_dependencies"] == ["whether the specific dependency holds"]
        assert result[0]["remediation_impact"] == "proof_required"

    def test_unparseable_unresolved_field_is_not_normalized_to_validation_only(self):
        """The normalization must never fire on the FAIL-CLOSED path -- an
        Unresolved field that could not itself be confidently parsed stays
        "unclear", never "validation_only", even though the fail-closed
        default also sets unresolved_dependencies to []."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: \n"
            "   Remediation impact: proof_required\n"
            "   Group: Observed\n"
            "   Reworded: text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["remediation_impact"] == "unclear"

    def test_missing_block_is_not_normalized_to_validation_only(self):
        result = _parse_response("not a structured response at all", ["a"])
        assert result[0]["unresolved_dependencies"] == []
        assert result[0]["remediation_impact"] == "unclear"

    def test_group_classification_unaffected_by_normalization(self):
        """The normalization only ever touches remediation_impact, never
        group -- Hardening + Unresolved:none + proof_required keeps
        Hardening (unaffected) while remediation_impact still normalizes."""
        resp = (
            "1. Claims:\n"
            "   - A claim.\n"
            "   Unresolved: none\n"
            "   Remediation impact: proof_required\n"
            "   Group: Hardening\n"
            "   Reworded: text.\n"
        )
        result = _parse_response(resp, ["finding"])
        assert result[0]["group"] == "hardening"
        assert result[0]["remediation_impact"] == "validation_only"


# ---------------------------------------------------------------------------
# Remediation-scope boundary (release-convergence follow-up): proof_required
# vs. validation_only must be bounded by what the supplied Security
# Invariant / vulnerability evidence establishes as in scope, not by a bare
# "is this necessary for the mechanism" question with no scope anchor at
# all. Regression shape: a technically real, unresolved dependency about a
# scenario the supplied evidence never described as part of the required
# remediation behavior was rated proof_required anyway, because the prior
# prompt wording never told the model to bound "sufficient" by scope.
#
# SCOPE NOTE: same limitation as every other prompt-contract test in this
# file -- the scope judgment itself remains entirely LLM-judgment based on
# the prompt text; this cannot (and does not try to) prove an LLM will
# reason correctly about any specific advisory. What IS testable: (a) the
# prompt states the scope-bounded definition and the fail-closed-on-
# ambiguity rule, worded generically, (b) it explicitly forbids deciding
# scope from a keyword or from upstream's own choices, (c) it does not
# touch Group's independence from this axis, and (d) the new contrastive
# example is domain-neutral.
# ---------------------------------------------------------------------------

class TestRemediationScopeContract:
    def test_proof_required_and_validation_only_are_bounded_by_security_invariant(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "supplied Security Invariant" in text
        assert "the scenario the evidence establishes as in scope" in text
        assert (
            "the dependency instead concerns a scenario that the supplied evidence does "
            "not establish as part of the required remediation behavior"
        ) in text

    def test_validation_only_does_not_mean_safe_false_resolved_or_unimportant(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "`validation_only` never means the concern is false, that the underlying "
            "behavior is safe, that the dependency is resolved, or that the concern "
            "is unimportant"
        ) in text

    def test_scope_ambiguity_fails_closed_to_proof_required(self):
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "If that evidence does not clearly establish whether the dependency's "
            "scenario is part of the required remediation behavior, answer "
            "`proof_required`, not `validation_only`"
        ) in text
        assert "scope ambiguity is never resolved by downgrading to" in text.lower()

    def test_scope_decision_forbids_keyword_and_upstream_shortcuts(self):
        """The scope judgment must come from the supplied evidence, never
        from a bare keyword in the finding's own wording, and never from
        whether upstream did or did not address the scenario."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "never from a keyword in the finding's" in text
        assert '"override", "non-default", "explicit", or "advanced"' in text
        assert "upstream's own choices are not evidence of what this advisory's" in text

    def test_remediation_impact_axis_remains_independent_of_group(self):
        """Group is never coupled to remediation_impact in either
        direction: Hardening must not be documented as automatically
        non-blocking, and Hypothesis must not be documented as
        automatically blocking."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "This axis never determines Group, and Group never determines this axis" in text
        assert "`Hardening` is not automatically non-blocking, and `Hypothesis` is not" in text
        assert "automatically blocking" in text

    def test_empty_unresolved_still_normalizes_to_validation_only(self):
        """The previously-approved deterministic-normalization contract
        sentence must survive this change unchanged."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "Whenever `Unresolved: none` applies, `Remediation impact:` must be "
            "`validation_only`"
        ) in text

    def test_is_valid_contrastive_example_still_present_and_unchanged(self):
        """The previously-approved evidence-sufficiency example (and its
        Group-held-constant lesson) must not be regressed by this change."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert "is_valid" in text
        assert "`Group` is deliberately" in text
        assert "Hypothesis` in both findings above: resolving this one dependency changes" in text

    def test_new_contrastive_example_is_domain_neutral(self):
        """Must not mention urllib3, Cookie, Retry, HTTPConnectionPool,
        redirects, or assert_same_host -- scoped to the new "remediation
        scope" contrastive example section only; the file's pre-existing
        Cookie/redirect example sets are out of scope here."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("Contrastive example — remediation scope")
        added_text = full_text[start:].lower()
        for forbidden in (
            "urllib3", "cookie", "retry", "httpconnectionpool", "redirect", "assert_same_host",
        ):
            assert forbidden not in added_text

    def test_new_contrastive_example_holds_group_constant(self):
        """Isolates the remediation-scope lesson to Unresolved/remediation_
        impact only, mirroring the same design already used for the
        is_valid evidence-sufficiency example. Scoped to this example's own
        span (up to the NEXT contrastive example, the invariant-deferred-
        predicate one added later) so later additions to the prompt file
        can't silently inflate this count."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("Contrastive example — remediation scope")
        end = full_text.index("Contrastive example — existing predicate the patch does not modify")
        added_text = full_text[start:end]
        assert added_text.count("Group: Hypothesis") == 2
        assert "Group: Observed" not in added_text
        assert "Group: Hardening" not in added_text


# ---------------------------------------------------------------------------
# Invariant-deferred-predicate / non-default-override scope rules (forensic
# urllib3 green->orange regression fix). Behavior-level proof that these
# rules actually change downstream authority lives in test_pipeline.py's
# TestInvariantDeferredPredicateAndNonDefaultOverrideScope (calibrate_
# findings -> _parse_response -> _reconcile_verification_status_with_
# calibration, exercised end to end). These are supplementary prompt-
# contract checks only, matching TestRemediationScopeContract's own
# established pattern for this file -- not a substitute for the behavior
# tests above.
# ---------------------------------------------------------------------------

class TestInvariantDeferredPredicateAndOverrideScopeRules:
    def test_rule_a_predicate_deference_is_asymmetric(self):
        """Rule A must both (a) instruct against recursively reopening an
        unmodified predicate/helper's own broader semantics, and (b)
        preserve the exception for a concrete, evidence-backed
        contradiction or an invariant that explicitly makes the predicate's
        own property part of the remediation -- an asymmetric rule, not a
        blanket exemption for existing code."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "existing predicate, helper, policy, contract, or abstraction — and the patch "
            "does not modify that predicate/helper/policy"
        ) in text
        assert "Do not recursively expand the proof obligation" in text
        assert (
            "a concrete, evidence-backed contradiction always overrides this rule" in text
        )
        assert (
            "never from a general assumption that unmodified code is automatically "
            "correct" in text
        )

    def test_rule_b_non_default_override_is_asymmetric(self):
        """Rule B must both (a) instruct against automatically treating an
        explicit non-default caller configuration as proof the default
        remediation is incomplete, and (b) preserve the exception for an
        invariant that explicitly extends the remediation to that
        configuration -- never a blanket "custom configuration never
        matters" exemption."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "does not, by itself, make the default remediation incomplete" in text
        )
        assert (
            "Security Invariant, or verified evidence itself extends the required "
            "remediation to that alternate configuration, override, or entry point" in text
        )
        assert (
            "never a blanket rule that a custom configuration or non-default path can "
            "never matter" in text
        )

    def test_new_scope_rules_forbid_keyword_heuristics(self):
        """Both rules must explicitly disclaim keyword-based shortcuts --
        the scope decision must come from the supplied evidence/invariant,
        never from a word in the finding's own text."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())
        assert (
            "never merely because the predicate/helper/policy exists unexamined in the "
            "codebase" in text
        )
        assert (
            'it is never decided from a keyword describing the configuration (such as '
            '"override", "custom", "explicit", "disabled", or "non-default") in the '
            "finding's own wording" in text
        )

    def test_new_scope_rules_and_examples_are_domain_neutral(self):
        """Neither the two new rule paragraphs nor their two new
        contrastive examples may mention urllib3, Cookie, Retry,
        PoolManager, HTTPConnectionPool, or is_same_host -- these are
        general scope rules, not a urllib3-specific fix. The file's
        pre-existing Cookie/redirect example sets (added by earlier work)
        are deliberately out of scope for this check."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        rule_start = full_text.index(
            "Two specific scope patterns recur often enough to name explicitly"
        )
        rule_end = full_text.index(
            "This axis never determines Group, and Group never determines this axis:"
        )
        example_start = full_text.index(
            "Contrastive example — existing predicate the patch does not modify"
        )
        forbidden = (
            "urllib3", "cookie", "retry", "poolmanager", "httpconnectionpool", "is_same_host",
        )
        for name, segment in (
            ("rules", full_text[rule_start:rule_end].lower()),
            ("examples", full_text[example_start:].lower()),
        ):
            for term in forbidden:
                assert term not in segment, f"found forbidden term {term!r} in new {name}"

    def test_new_rules_placed_within_remediation_impact_step_before_group_axis_note(self):
        """The two new rules are sub-cases of the SAME remediation-impact
        judgment (step 2), not a new numbered step -- they must sit before
        the pre-existing Group-independence reminder, never after it or in
        a separate step."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        text = _PROMPT_PATH.read_text(encoding="utf-8")
        rule_pos = text.index("Two specific scope patterns recur often enough to name explicitly")
        group_axis_pos = text.index(
            "This axis never determines Group, and Group never determines this axis:"
        )
        step_3_pos = text.index("3. **Classify** it into exactly one of three groups:")
        assert rule_pos < group_axis_pos < step_3_pos

    def test_case_a_and_case_b_hold_evidence_state_constant(self):
        """Regression guard for the corrected contrastive example: Case A
        and Case B must describe IDENTICAL evidence availability for
        `is_allowed_destination` (its own implementation not shown in
        either case) -- only the supplied Security Invariant differs. Case
        B must never claim the implementation/source was additionally
        supplied while its own output simultaneously treats it as
        unresolved -- the exact contradiction this correction fixes."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("Contrastive example — existing predicate the patch does not modify")
        end = full_text.index("Contrastive example — explicit non-default caller configuration")
        segment = full_text[start:end]
        # The exact evidence-availability statement must appear identically
        # in both Case A's and Case B's input finding -- evidence is held
        # constant, never varied alongside the invariant.
        finding_text = (
            "`is_allowed_destination`'s own comparison logic (exact match vs.\n"
            "   suffix match) is not shown in the supplied evidence."
        )
        assert segment.count(finding_text) == 2
        # The specific contradiction this correction removes: Case B must
        # never claim the evidence "additionally includes" the predicate's
        # own source/implementation while its own output still treats that
        # implementation as unshown/unresolved.
        assert "evidence additionally includes" not in segment
        assert "was not part of the evidence originally supplied" not in segment

    def test_rule_a_example_ambiguity_stays_proof_required(self):
        """Rule A's own contrastive example must explicitly restate the
        fail-closed ambiguity rule (mirroring Rule B's own reminder) --
        Rule A is the pattern most directly implicated in the forensic
        regression, so its example must not rely solely on the general,
        earlier ambiguity sentence in step 2's own intro paragraph."""
        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("Contrastive example — existing predicate the patch does not modify")
        end = full_text.index("Contrastive example — explicit non-default caller configuration")
        segment = " ".join(full_text[start:end].split())
        assert (
            "does not clearly establish whether `is_allowed_destination`'s own "
            "broader comparison semantics are outside the required remediation, "
            "the uncertainty remains `proof_required`"
        ) in segment
        assert (
            "never `validation_only` merely because the predicate already existed, "
            "because the patch does not modify it, or because the invariant merely "
            "mentions it by name"
        ) in segment
        assert (
            "genuine scope ambiguity is never resolved by downgrading to `validation_only`"
        ) in segment

    def test_rule_a_example_case_a_validation_only_case_b_proof_required(self):
        """Structural check on the corrected example's own output lines --
        Case A (invariant defines the boundary by reference to the
        predicate) still resolves `validation_only`; Case B (invariant
        explicitly requires the predicate's own property) still resolves
        `proof_required`, in that order."""
        import re

        from utilities.autopatcher.finding_calibration import _PROMPT_PATH
        full_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = full_text.index("Contrastive example — existing predicate the patch does not modify")
        end = full_text.index("Contrastive example — explicit non-default caller configuration")
        segment = full_text[start:end]
        impacts = re.findall(r"Remediation impact: (\w+)", segment)
        assert impacts == ["validation_only", "proof_required"]
