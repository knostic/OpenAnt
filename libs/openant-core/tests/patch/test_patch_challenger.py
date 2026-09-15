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

_NEW_FORMAT_RESPONSE = """\
Verification status: {status}

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

        assert set(result.keys()) == {
            "verification_status", "still_vulnerable", "edge_cases", "potential_issues", "summary",
        }

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


class TestVerificationStatus:
    """The authoritative tri-state signal and its backward-compatible
    `still_vulnerable` projection -- see patch_challenger._parse_verification."""

    def test_verified_fixed_new_format(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _NEW_FORMAT_RESPONSE.format(status="VERIFIED_FIXED")

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] == "VERIFIED_FIXED"
        assert result["still_vulnerable"] is False

    def test_residual_vulnerability_new_format(self):
        """Affirmative demonstrated bypass -> RESIDUAL_VULNERABILITY."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _NEW_FORMAT_RESPONSE.format(status="RESIDUAL_VULNERABILITY")

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] == "RESIDUAL_VULNERABILITY"
        assert result["still_vulnerable"] is True

    def test_insufficient_evidence_new_format(self):
        """Missing verification evidence -> INSUFFICIENT_EVIDENCE, not a
        demonstrated bypass, but still projects still_vulnerable=True."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _NEW_FORMAT_RESPONSE.format(status="INSUFFICIENT_EVIDENCE")

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert result["still_vulnerable"] is True

    def test_new_format_unrecognized_token_fails_closed(self):
        """A hallucinated/garbage value under the new header must never be
        read as VERIFIED_FIXED -- it fails closed exactly like a missing
        classification."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _NEW_FORMAT_RESPONSE.format(status="MAYBE_FIXED_IDK")

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] is None
        assert result["still_vulnerable"] is True

    def test_no_status_header_at_all_fails_closed(self):
        """Neither the new nor the legacy header is present at all
        (fully malformed response) -- fails closed, never VERIFIED_FIXED."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = (
            "Edge cases:\n- Some edge case\n\n"
            "Potential issues:\n- Some potential issue\n\n"
            "Summary:\n- A concise paragraph.\n"
        )

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] is None
        assert result["still_vulnerable"] is True

    def test_legacy_still_vulnerable_no_preserved_exactly(self):
        """LEGACY-format-only response: `Still vulnerable: No` must remain
        False, NOT be derived via `verification_status != VERIFIED_FIXED`
        (which would incorrectly flip it to True since verification_status
        is None for a legacy-only response)."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE  # "Still vulnerable: No"

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] is None
        assert result["still_vulnerable"] is False

    def test_legacy_still_vulnerable_yes_preserved_exactly(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE.replace(
            "Still vulnerable: No", "Still vulnerable: Yes"
        )

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] is None
        assert result["still_vulnerable"] is True

    def test_new_format_takes_priority_over_legacy_header_if_both_present(self):
        """If a response somehow contains both headers, the new,
        authoritative one wins -- never silently overridden by a
        coincidentally-present legacy header."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = (
            "Verification status: VERIFIED_FIXED\n\n"
            "Still vulnerable: Yes\n\n"
            "Edge cases:\n- Some edge case\n\n"
            "Potential issues:\n- Some potential issue\n\n"
            "Summary:\n- A concise paragraph.\n"
        )

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] == "VERIFIED_FIXED"
        assert result["still_vulnerable"] is False

    def test_no_urllib3_cookie_cve_strings_in_production_files(self):
        """Genericity guard: the Challenger prompt/parser must never carry
        repository- or CVE-specific production logic."""
        import utilities.autopatcher.patch_challenger as challenger_mod

        prompt_text = (Path(challenger_mod.__file__).parent / "prompts" / "patch_challenger.md").read_text(
            encoding="utf-8"
        )
        source_text = Path(challenger_mod.__file__).read_text(encoding="utf-8")
        for blob in (prompt_text, source_text):
            for needle in ("urllib3", "Cookie", "GHSA", "CVE-"):
                assert needle not in blob
