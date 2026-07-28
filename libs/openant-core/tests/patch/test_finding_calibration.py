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
