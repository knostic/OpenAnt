"""Unit tests for patch_challenger.challenge_patch, focused on the
code_context parameter (mirrors generate_patch/score_confidence grounding)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock


_CHALLENGER_RESPONSE = """\
Still vulnerable: No

Edge cases:
- Some edge case

Potential issues:
- Some potential issue

Summary:
- A concise paragraph summarising the adversarial findings.
"""


class TestCodeContextParameter:
    """code_context is optional and, when provided, must reach the LLM call
    the same way generate_patch/score_confidence already do."""

    def test_default_omits_repository_evidence_section(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE

        challenge_patch("some vuln", "some diff", llm)

        _system, user_message = llm.complete.call_args[0]
        assert "## Repository evidence" not in user_message

    def test_code_context_included_when_provided(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE

        challenge_patch("some vuln", "some diff", llm, code_context="def foo(): pass")

        _system, user_message = llm.complete.call_args[0]
        assert "## Repository evidence" in user_message
        assert "def foo(): pass" in user_message

    def test_empty_code_context_omits_section(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE

        challenge_patch("some vuln", "some diff", llm, code_context="")

        _system, user_message = llm.complete.call_args[0]
        assert "## Repository evidence" not in user_message

    def test_code_context_precedes_vulnerability_report(self):
        """Same ordering as score_confidence: repository evidence first, so
        the model reads the real code before the advisory framing."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE

        challenge_patch("some vuln", "some diff", llm, code_context="def foo(): pass")

        _system, user_message = llm.complete.call_args[0]
        assert user_message.index("## Repository evidence") < user_message.index("## Vulnerability report")

    def test_backward_compatible_without_code_context_kwarg(self):
        """Existing positional-only call sites must keep working unchanged."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["still_vulnerable"] is False
        assert result["edge_cases"] == ["Some edge case"]
        assert result["potential_issues"] == ["Some potential issue"]


class TestChallengePatchBasicBehavior:
    """Baseline behavior, unrelated to code_context, that the new parameter
    must not disturb."""

    def test_returns_expected_keys(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE

        result = challenge_patch("some vuln", "some diff", llm, code_context="ctx")

        assert set(result.keys()) == {"still_vulnerable", "edge_cases", "potential_issues", "summary"}

    def test_still_vulnerable_yes_parsed_true(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE.replace(
            "Still vulnerable: No", "Still vulnerable: Yes"
        )

        result = challenge_patch("some vuln", "some diff", llm, code_context="ctx")

        assert result["still_vulnerable"] is True

    def test_stage_argument_is_challenger(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE

        challenge_patch("some vuln", "some diff", llm, code_context="ctx")

        assert llm.complete.call_args.kwargs.get("stage") == "challenger"
