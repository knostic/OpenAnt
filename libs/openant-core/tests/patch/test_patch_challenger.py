"""Unit tests for patch_challenger.challenge_patch, focused on the
code_context parameter (mirrors generate_patch/score_confidence grounding)."""

from __future__ import annotations

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

def _stated_verdict(llm):
    """The model's own stated verdict, as the diagnostic `_parse_verification`
    reads it from the mocked response. Never decision-relevant (RB-1)."""
    from utilities.autopatcher.patch_challenger import _parse_verification, _split_sections
    return _parse_verification(_split_sections(llm.complete.return_value))


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

        assert result["still_vulnerable"] is True  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
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
    """The tri-state signal and its backward-compatible `still_vulnerable`
    projection. Without a `Concerns:` section, `challenge_patch` fails
    closed whatever is stated (RB-1); `_stated_verdict` checks that the
    diagnostic `_parse_verification` still reads the stated value."""

    def test_verified_fixed_new_format(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _NEW_FORMAT_RESPONSE.format(status="VERIFIED_FIXED")

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] is None  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["still_vulnerable"] is True
        assert _stated_verdict(llm) == ("VERIFIED_FIXED", False)

    def test_residual_vulnerability_new_format(self):
        """Affirmative demonstrated bypass -> RESIDUAL_VULNERABILITY."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _NEW_FORMAT_RESPONSE.format(status="RESIDUAL_VULNERABILITY")

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] is None  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["still_vulnerable"] is True
        assert _stated_verdict(llm) == ("RESIDUAL_VULNERABILITY", True)

    def test_insufficient_evidence_new_format(self):
        """Missing verification evidence -> INSUFFICIENT_EVIDENCE, not a
        demonstrated bypass, but still projects still_vulnerable=True."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _NEW_FORMAT_RESPONSE.format(status="INSUFFICIENT_EVIDENCE")

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] is None  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["still_vulnerable"] is True
        assert _stated_verdict(llm) == ("INSUFFICIENT_EVIDENCE", True)

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

    def test_legacy_still_vulnerable_no_fails_closed(self):
        """LEGACY-format-only response: `Still vulnerable: No` is read by
        the diagnostic `_parse_verification` as before, but no longer
        decides anything -- `challenge_patch` fails closed (RB-1)."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE  # "Still vulnerable: No"

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] is None
        assert result["still_vulnerable"] is True  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert _stated_verdict(llm) == (None, False)

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

        assert result["verification_status"] is None  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["still_vulnerable"] is True
        assert _stated_verdict(llm) == ("VERIFIED_FIXED", False)

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


class TestCompletePathReachabilityContract:
    """V8 fix: RESIDUAL_VULNERABILITY previously required only a bypass
    'using ONLY the supplied evidence' -- a bar a model can clear by citing
    a later operation while never checking it against an equally-supplied
    PRECEDING guard. This class protects the prompt-level correction: a
    complete-path reachability trace is now a prerequisite for selecting
    RESIDUAL_VULNERABILITY at all.

    These are structural/prompt-content tests only -- they prove the rule's
    text landed, is generic, and sits in the right place. They cannot prove
    an LLM will actually perform the trace; only a real regression can."""

    def _full_text(self):
        from utilities.autopatcher.patch_challenger import _PROMPT_PATH
        return _PROMPT_PATH.read_text(encoding="utf-8")

    def _joined(self):
        return " ".join(self._full_text().split())

    def test_rule_requires_complete_path_trace_before_residual_vulnerability(self):
        joined = self._joined()
        assert "Before selecting RESIDUAL_VULNERABILITY for an additional execution path" in joined
        assert "trace the complete supplied control flow from entry to the alleged unsafe" in joined
        assert "any preceding guard, any verified default argument or" in joined
        assert "the order those steps actually execute in" in joined
        assert "any early return, raised error, or other control-flow stop" in joined

    def test_existence_of_operation_is_not_itself_evidence_of_reachability(self):
        joined = self._joined()
        assert (
            "The existence of a later operation in supplied source is not "
            "by itself evidence that execution can reach that operation "
            "under the relevant conditions"
        ) in joined

    def test_default_blocked_override_path_is_not_automatic_residual_vulnerability(self):
        joined = self._joined()
        assert (
            "this does not by itself establish RESIDUAL_VULNERABILITY — "
            "record it instead as a non-blocking edge case or potential issue"
        ) in joined
        assert (
            "unless the supplied Security Invariant, vulnerability "
            "description, or verified evidence itself establishes that "
            "this explicit override is within the required remediation "
            "scope, in which case RESIDUAL_VULNERABILITY may still apply"
        ) in joined

    def test_rule_does_not_introduce_general_non_default_irrelevance_rule(self):
        joined = self._joined()
        assert (
            "This is not a rule that a non-default configuration is "
            "automatically irrelevant"
        ) in joined

    def test_missing_guard_evidence_fails_closed_to_insufficient_evidence(self):
        joined = self._joined()
        assert (
            "If the existence of a relevant guard, its default value, its "
            "position relative to the alleged operation, or its effect "
            "cannot be established from the supplied evidence, do not "
            "assume either answer — that is INSUFFICIENT_EVIDENCE, not "
            "RESIDUAL_VULNERABILITY and not VERIFIED_FIXED"
        ) in joined

    def test_example_present_and_domain_neutral(self):
        text = self._full_text()
        assert "process(item, allow_external=False)" in text
        assert "if external(item) and not allow_external:" in text
        assert "perform_sensitive_operation(item)" in text
        joined = self._joined()
        start = joined.index("Before selecting RESIDUAL_VULNERABILITY for an additional execution path")
        end = joined.index("- INSUFFICIENT_EVIDENCE:")
        segment = joined[start:end].lower()
        for forbidden in (
            "urllib3", "httpconnectionpool", "redirect", "cookie", "hosts",
            "assert_same_host", "retry", "poolmanager", "cve-", "cve ",
        ):
            assert forbidden not in segment, f"found forbidden term {forbidden!r}"

    def test_rule_placed_inside_residual_vulnerability_definition_before_insufficient_evidence(self):
        text = self._full_text()
        residual_pos = text.index("- RESIDUAL_VULNERABILITY:")
        rule_pos = text.index("Before selecting RESIDUAL_VULNERABILITY for an additional execution path")
        insufficient_pos = text.index("- INSUFFICIENT_EVIDENCE:")
        assert residual_pos < rule_pos < insufficient_pos

    def test_existing_status_definitions_and_example_output_unchanged(self):
        """Purely additive: VERIFIED_FIXED/INSUFFICIENT_EVIDENCE definitions,
        the dedup instruction, and the worked example output must remain
        byte-for-byte present."""
        text = self._full_text()
        assert (
            "VERIFIED_FIXED: the supplied evidence (repository context + patch) affirmatively\n"
            "  supports that the mechanism works"
        ) in text
        assert (
            "Do not restate the same underlying concern in both \"Edge cases\" and\n"
            "\"Potential issues\""
        ) in text
        assert "Database drivers that use `%s` placeholders (driver mismatch)" in text


class TestReachabilityOutcomesPassthrough:
    """Mocked-LLM tests: simulate a Challenger response that DOES follow the
    new complete-path reachability rule, for each of the outcomes the rule
    can produce, and assert the diagnostic free-text parser (never LLM
    reasoning) reads that outcome unchanged -- while `challenge_patch`
    itself fails closed for these unstructured responses (RB-1). These prove the
    mechanical parser does not fight, reinterpret, or require any
    special-casing for a contract-following response -- they cannot and do
    not prove an LLM will actually perform the trace; only a real
    regression can."""

    def _response(self, status, edge_cases, potential_issues):
        edge_text = "\n".join(f"- {e}" for e in edge_cases) or "- none"
        issue_text = "\n".join(f"- {p}" for p in potential_issues) or "- none"
        return (
            f"Verification status: {status}\n\n"
            f"Edge cases:\n{edge_text}\n\n"
            f"Potential issues:\n{issue_text}\n\n"
            "Summary:\n- A concise paragraph summarising the adversarial findings.\n"
        )

    def test_b_default_reachable_path_may_establish_residual_vulnerability(self):
        """Outcome B: the trace itself shows the operation IS reachable
        under default execution -- RESIDUAL_VULNERABILITY is supported."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = self._response(
            "RESIDUAL_VULNERABILITY",
            edge_cases=[],
            potential_issues=[
                "No preceding guard gates the operation under default "
                "arguments; the traced control flow reaches it directly.",
            ],
        )
        result = challenge_patch("some vuln", "some diff", llm, code_context="ctx")
        assert result["verification_status"] is None  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["still_vulnerable"] is True
        assert _stated_verdict(llm) == ("RESIDUAL_VULNERABILITY", True)

    def test_c_explicit_override_in_scope_may_establish_residual_vulnerability(self):
        """Outcome C: the operation is only reachable via an explicit
        non-default override, but the supplied invariant extends the
        required remediation to that override -- still RESIDUAL_VULNERABILITY."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = self._response(
            "RESIDUAL_VULNERABILITY",
            edge_cases=[],
            potential_issues=[
                "Reaching the operation requires an explicit non-default "
                "override, and the supplied Security Invariant explicitly "
                "extends the required remediation to that override path.",
            ],
        )
        result = challenge_patch("some vuln", "some diff", llm, code_context="ctx")
        assert result["verification_status"] is None  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["still_vulnerable"] is True
        assert _stated_verdict(llm) == ("RESIDUAL_VULNERABILITY", True)

    def test_d_guard_default_or_order_unestablished_is_insufficient_evidence(self):
        """Outcome D: the guard/default/order cannot be established from
        supplied evidence -- must fail closed to INSUFFICIENT_EVIDENCE,
        never assumed reachable (RESIDUAL_VULNERABILITY) or blocked
        (VERIFIED_FIXED)."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = self._response(
            "INSUFFICIENT_EVIDENCE",
            edge_cases=[],
            potential_issues=[
                "Whether a preceding guard gates this operation, and its "
                "default value, is not established by the supplied evidence.",
            ],
        )
        result = challenge_patch("some vuln", "some diff", llm, code_context="ctx")
        assert result["verification_status"] is None  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["still_vulnerable"] is True
        assert _stated_verdict(llm) == ("INSUFFICIENT_EVIDENCE", True)

    def test_default_blocked_path_recorded_as_non_blocking_edge_case_not_residual(self):
        """Outcome A/E combined: a complete trace shows the operation is
        blocked under defaults and reachable only via an explicit
        non-default override not established as in scope -- the contract
        says record this as a non-blocking edge case, so the overall
        verdict may remain VERIFIED_FIXED."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = self._response(
            "VERIFIED_FIXED",
            edge_cases=[
                "A preceding guard, enabled by default, stops execution "
                "before this operation; reaching it requires an explicit "
                "non-default override not established as in scope by the "
                "supplied invariant.",
            ],
            potential_issues=[],
        )
        result = challenge_patch("some vuln", "some diff", llm, code_context="ctx")
        assert result["verification_status"] is None  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["still_vulnerable"] is True
        assert _stated_verdict(llm) == ("VERIFIED_FIXED", False)
        assert len(result["edge_cases"]) == 1


# ---------------------------------------------------------------------------
# Structured `Concerns:` schema -- deterministic atomic-fact derivation.
#
# Covers, in order: block-local parsing safety, per-concern deterministic
# policy, multi-concern aggregation, legacy-response/valid-new-schema/
# malformed-new-schema-attempt compatibility, and open-ended prose vs.
# structured concern correspondence.
# ---------------------------------------------------------------------------

def _concern_block(
    num=1, role="primary", description="a concern", reachability="blocked",
    reach_prov="none", override="false", override_prov="none",
    scope="not_applicable", scope_prov="none",
):
    return (
        f"{num}. Role: {role}\n"
        f"   Description: {description}\n"
        f"   Default execution reachability: {reachability}\n"
        f"   Reachability provenance: {reach_prov}\n"
        f"   Requires explicit non-default action: {override}\n"
        f"   Override provenance: {override_prov}\n"
        f"   Contract addresses override: {scope}\n"
        f"   Scope provenance: {scope_prov}\n"
    )


def _response_with_concerns(concerns_text, status="VERIFIED_FIXED", edge_cases=(), potential_issues=(), summary="none"):
    edge_text = "\n".join(f"- {e}" for e in edge_cases) or "- none"
    issue_text = "\n".join(f"- {p}" for p in potential_issues) or "- none"
    return (
        f"Verification status: {status}\n\n"
        f"Concerns:\n\n{concerns_text}\n"
        f"Edge cases:\n{edge_text}\n\n"
        f"Potential issues:\n{issue_text}\n\n"
        f"Summary:\n{summary}\n"
    )


class TestConcernBlockParsingSafety:
    """Deterministic parser/validation safety net for the `Concerns:`
    schema -- every failure mode fails closed to `consequence:
    "UNRESOLVED"`; nothing is silently dropped, corrected, or promoted."""

    def _parse_one(self, **kwargs):
        from utilities.autopatcher.patch_challenger import _parse_concern_block
        block = _concern_block(**kwargs)
        return _parse_concern_block(block, code_context="ctx", patch="diff", vulnerability_text="vuln text")

    def test_missing_required_field_fails_closed(self):
        """Case 1: `Default execution reachability:` line entirely absent."""
        from utilities.autopatcher.patch_challenger import _parse_concern_block
        block = "1. Role: primary\n   Description: d\n"
        result = _parse_concern_block(block, code_context="", patch="", vulnerability_text="")
        assert result["malformed"] is True
        assert result["consequence"] == "UNRESOLVED"

    def test_malformed_enum_fails_closed(self):
        """Case 2: an unrecognized reachability token."""
        result = self._parse_one(reachability="probably_fine")
        assert result["malformed"] is True
        assert result["consequence"] == "UNRESOLVED"

    def test_duplicate_concern_number_fails_closed_as_one_malformed_concern(self):
        """Case 3: two blocks both numbered "1" -- ambiguous, no safe basis
        to pick either; collapses to exactly one malformed concern for
        that number, never two, never a silently-chosen winner."""
        from utilities.autopatcher.patch_challenger import _parse_concerns
        text = (
            _concern_block(num=1, role="primary", reachability="blocked", override="false")
            + _concern_block(num=1, role="primary", reachability="reachable", override="not_applicable")
        )
        concerns = _parse_concerns(text, code_context="", patch="", vulnerability_text="")
        assert len(concerns) == 1
        assert concerns[0]["malformed"] is True
        assert concerns[0]["malformed_reason"] == "duplicate_concern_number"

    def test_numbering_gap_does_not_cause_misattribution(self):
        """Case 4: block numbers 1 and 5 (a gap) must not corrupt or shift
        either block's own fields -- numbering gaps are not themselves an
        error."""
        from utilities.autopatcher.patch_challenger import _parse_concerns
        text = (
            _concern_block(num=1, role="primary", description="first", reachability="blocked", override="false")
            + _concern_block(num=5, role="additional", description="second", reachability="reachable", override="not_applicable")
        )
        concerns = _parse_concerns(text, code_context="", patch="", vulnerability_text="")
        assert len(concerns) == 2
        assert concerns[0]["description"] == "first"
        assert concerns[0]["concern_role"] == "primary"
        assert concerns[1]["description"] == "second"
        assert concerns[1]["concern_role"] == "additional"

    def test_malformed_middle_concern_does_not_corrupt_neighbors(self):
        """Case 7: a garbled block 2 sitting between two well-formed blocks
        must not shift or corrupt block 1's or block 3's own fields --
        each block's span is independently bounded."""
        from utilities.autopatcher.patch_challenger import _parse_concerns
        text = (
            _concern_block(num=1, role="primary", description="first", reachability="blocked", override="false")
            + "2. Role: not_a_real_role\n   Description: garbled\n"
            + _concern_block(num=3, role="additional", description="third", reachability="reachable", override="not_applicable")
        )
        concerns = _parse_concerns(text, code_context="", patch="", vulnerability_text="")
        assert len(concerns) == 3
        assert concerns[0]["description"] == "first"
        assert concerns[0]["malformed"] is False
        assert concerns[1]["malformed"] is True
        assert concerns[2]["description"] == "third"
        assert concerns[2]["malformed"] is False

    def test_resolved_reachability_without_provenance_fails_closed_to_unresolved(self):
        """Case 8: `blocked` with no citation (or a citation not actually
        present in the evidence Challenger received) is never trusted --
        demoted to `unresolved`, never left as a silently-accepted
        `blocked`."""
        result = self._parse_one(reachability="blocked", reach_prov="none", override="false")
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"
        assert result["consequence"] == "UNRESOLVED"

    def test_scope_citation_from_repository_evidence_fails_closed(self):
        """Case 9: a `Scope provenance:` quote that is only present in
        `code_context`/the diff, never in `vulnerability_text`, must not
        validate `explicitly_included` -- the only authoritative source is
        the complete vulnerability text."""
        from utilities.autopatcher.patch_challenger import _parse_concern_block
        block = _concern_block(
            reachability="blocked", reach_prov="the guard line", override="true",
            override_prov="the override line", scope="explicitly_included",
            scope_prov="this text only lives in repo evidence",
        )
        result = _parse_concern_block(
            block,
            code_context="the guard line\nthis text only lives in repo evidence",
            patch="the override line",
            vulnerability_text="a vulnerability report that never quotes that repo text",
        )
        assert result["contract_addresses_override"] == "unresolved"
        assert result["consequence"] == "UNRESOLVED"

    def test_silent_with_point_citation_instead_of_whole_document_marker_fails_closed(self):
        """Case 10: `silent` requires the exact whole-document marker, not
        a quoted span -- a point citation offered here does not satisfy
        it, since silence is an absence claim no local quote can prove."""
        result = self._parse_one(
            reachability="blocked", reach_prov="guard", override="true",
            override_prov="override site", scope="silent",
            scope_prov="the report never discusses this",
        )
        assert result["contract_addresses_override"] == "unresolved"
        assert result["consequence"] == "UNRESOLVED"

    def test_explicitly_included_without_provenance_fails_closed(self):
        """Case 11."""
        result = self._parse_one(
            reachability="blocked", reach_prov="guard", override="true",
            override_prov="override site", scope="explicitly_included", scope_prov="none",
        )
        assert result["contract_addresses_override"] == "unresolved"
        assert result["consequence"] == "UNRESOLVED"

    def test_explicitly_excluded_without_provenance_fails_closed(self):
        """Case 12."""
        result = self._parse_one(
            reachability="blocked", reach_prov="guard", override="true",
            override_prov="override site", scope="explicitly_excluded", scope_prov="none",
        )
        assert result["contract_addresses_override"] == "unresolved"
        assert result["consequence"] == "UNRESOLVED"

    def test_reachable_with_populated_override_field_is_malformed(self):
        """Case 13: `reachable` structurally forecloses the override/scope
        question (it is not "applicable"); a response that nonetheless
        populates `Requires explicit non-default action` with anything
        other than `not_applicable` is self-contradictory and must not be
        silently ignored -- the whole concern is malformed."""
        result = self._parse_one(reachability="reachable", override="true", override_prov="x", scope="not_applicable")
        assert result["malformed"] is True
        assert result["consequence"] == "UNRESOLVED"

    def test_blocked_override_not_applicable_is_malformed(self):
        """Symmetric case: `blocked` requires override to be one of
        true/false/unresolved -- `not_applicable` here is itself a schema
        violation, not a permissive default."""
        result = self._parse_one(reachability="blocked", override="not_applicable", scope="not_applicable")
        assert result["malformed"] is True

    def test_override_true_with_scope_not_applicable_is_malformed(self):
        """Symmetric applicability gate on the scope field: `true` requires
        a real scope value, never `not_applicable`."""
        result = self._parse_one(
            reachability="blocked", reach_prov="guard", override="true",
            override_prov="override site", scope="not_applicable",
        )
        assert result["malformed"] is True

    def test_override_false_with_populated_scope_is_malformed(self):
        """Symmetric case: `false`/`unresolved` override requires scope to
        be exactly `not_applicable`."""
        result = self._parse_one(reachability="blocked", override="false", scope="silent", scope_prov="whole document")
        assert result["malformed"] is True

    def test_citation_not_present_in_shown_evidence_fails_closed(self):
        """Case 16 (technical-capacity omission proxy): a citation that is
        not, verbatim, present in the `code_context`/diff strings this run
        actually received fails closed -- exactly the same mechanical
        check that also protects against citing content silently omitted
        upstream for technical capacity, since omitted content is never
        concatenated into these strings in the first place."""
        result = self._parse_one(
            reachability="blocked",
            reach_prov="a guard line that was never actually shown to this run",
            override="false",
        )
        assert result["default_execution_reachability"] == "unresolved"
        assert result["consequence"] == "UNRESOLVED"

    def test_valid_provenance_present_in_diff_is_accepted(self):
        """The provenance check accepts either the repository-evidence
        string or the diff -- a guard visible only in the patch itself is
        still eligible provenance for reachability/override facts."""
        from utilities.autopatcher.patch_challenger import _parse_concern_block
        block = _concern_block(reachability="blocked", reach_prov="+    raise AccessError()", override="false")
        result = _parse_concern_block(
            block, code_context="", patch="+    raise AccessError()", vulnerability_text="",
        )
        assert result["default_execution_reachability"] == "blocked"

    def test_quote_wrapping_is_stripped_before_containment_check(self):
        """A citation wrapped in quote/backtick marks still validates
        against the same underlying text."""
        from utilities.autopatcher.patch_challenger import _parse_concern_block
        block = _concern_block(reachability="blocked", reach_prov="`raise AccessError()`", override="false")
        result = _parse_concern_block(
            block, code_context="raise AccessError()", patch="", vulnerability_text="",
        )
        assert result["default_execution_reachability"] == "blocked"


class TestPerConcernDeterministicPolicy:
    """Exhaustive table for `_concern_consequence` -- the frozen per-concern
    policy, in isolation from parsing."""

    def test_reachable_is_blocking(self):
        from utilities.autopatcher.patch_challenger import _concern_consequence
        assert _concern_consequence("reachable", "not_applicable", "not_applicable") == "BLOCKING"

    def test_reachability_unresolved_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _concern_consequence
        assert _concern_consequence("unresolved", "not_applicable", "not_applicable") == "UNRESOLVED"

    def test_blocked_false_is_non_blocking(self):
        from utilities.autopatcher.patch_challenger import _concern_consequence
        assert _concern_consequence("blocked", "false", "not_applicable") == "NON_BLOCKING"

    def test_blocked_override_unresolved_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _concern_consequence
        assert _concern_consequence("blocked", "unresolved", "not_applicable") == "UNRESOLVED"

    def test_blocked_true_explicitly_included_is_blocking(self):
        from utilities.autopatcher.patch_challenger import _concern_consequence
        assert _concern_consequence("blocked", "true", "explicitly_included") == "BLOCKING"

    def test_blocked_true_explicitly_excluded_is_non_blocking(self):
        from utilities.autopatcher.patch_challenger import _concern_consequence
        assert _concern_consequence("blocked", "true", "explicitly_excluded") == "NON_BLOCKING"

    def test_blocked_true_silent_is_non_blocking(self):
        from utilities.autopatcher.patch_challenger import _concern_consequence
        assert _concern_consequence("blocked", "true", "silent") == "NON_BLOCKING"

    def test_blocked_true_scope_unresolved_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _concern_consequence
        assert _concern_consequence("blocked", "true", "unresolved") == "UNRESOLVED"


class TestMultiConcernAggregation:
    """Exhaustive table for `_derive_status_from_concerns` -- the frozen
    precedence BLOCKING > UNRESOLVED > NON_BLOCKING, plus the mandatory-
    primary and legacy-prose gates."""

    def _c(self, role, consequence):
        return {"concern_role": role, "consequence": consequence}

    def test_all_non_blocking_is_verified_fixed(self):
        from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
        concerns = [self._c("primary", "NON_BLOCKING"), self._c("additional", "NON_BLOCKING")]
        assert _derive_status_from_concerns(concerns, False) == ("VERIFIED_FIXED", False)

    def test_blocking_plus_non_blocking_is_residual_vulnerability(self):
        from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
        concerns = [self._c("primary", "NON_BLOCKING"), self._c("additional", "BLOCKING")]
        assert _derive_status_from_concerns(concerns, False) == ("RESIDUAL_VULNERABILITY", True)

    def test_unresolved_plus_non_blocking_is_insufficient_evidence(self):
        from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
        concerns = [self._c("primary", "NON_BLOCKING"), self._c("additional", "UNRESOLVED")]
        assert _derive_status_from_concerns(concerns, False) == ("INSUFFICIENT_EVIDENCE", True)

    def test_blocking_plus_unresolved_is_residual_vulnerability(self):
        """BLOCKING dominates UNRESOLVED -- a clean concern (or an
        unresolved one) never cancels a confirmed blocking concern."""
        from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
        concerns = [self._c("primary", "BLOCKING"), self._c("additional", "UNRESOLVED")]
        assert _derive_status_from_concerns(concerns, False) == ("RESIDUAL_VULNERABILITY", True)

    def test_zero_concerns_is_insufficient_evidence(self):
        """Case 5 (zero primary via zero concerns entirely)."""
        from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
        assert _derive_status_from_concerns([], False) == ("INSUFFICIENT_EVIDENCE", True)

    def test_zero_primary_among_additional_concerns_is_insufficient_evidence(self):
        """Case 5."""
        from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
        concerns = [self._c("additional", "NON_BLOCKING")]
        assert _derive_status_from_concerns(concerns, False) == ("INSUFFICIENT_EVIDENCE", True)

    def test_multiple_primary_concerns_is_insufficient_evidence(self):
        """Case 6."""
        from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
        concerns = [self._c("primary", "NON_BLOCKING"), self._c("primary", "NON_BLOCKING")]
        assert _derive_status_from_concerns(concerns, False) == ("INSUFFICIENT_EVIDENCE", True)

    def test_legacy_prose_present_forces_insufficient_evidence_regardless_of_concerns(self):
        """Case 17 at the aggregation level: legacy prose alongside the new
        schema forces closed even when every concern would otherwise be
        clean."""
        from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
        concerns = [self._c("primary", "NON_BLOCKING")]
        assert _derive_status_from_concerns(concerns, True) == ("INSUFFICIENT_EVIDENCE", True)


class TestNewSchemaEndToEnd:
    """`challenge_patch` end to end for a genuinely valid structured
    response -- proves the additive `concerns`/`schema_version` keys and
    the derived status/still_vulnerable, all the way through the public
    entry point, not just the internal helpers."""

    def test_valid_new_schema_response_derives_verified_fixed(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(
            num=1, role="primary", reachability="blocked", reach_prov="guard line", override="false",
        )
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(concerns_text, status="VERIFIED_FIXED")

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard line")

        # The structured facts (blocked, no override) govern the derived,
        # authoritative outcome (see the RESIDUAL_VULNERABILITY test below
        # for the header never raising it).
        assert result["verification_status"] == "VERIFIED_FIXED"
        assert result["still_vulnerable"] is False
        assert result["schema_version"] == "concerns_v1"
        assert len(result["concerns"]) == 1
        assert result["concerns"][0]["consequence"] == "NON_BLOCKING"
        assert "verdict_conflict" not in result

    def test_negative_legacy_header_fails_a_verified_derivation_closed(self):
        """PR #763 review: the header never raises the derived outcome, but a
        negative header contradicting VERIFIED_FIXED facts fails the run closed
        instead of being silently overridden."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(
            num=1, role="primary", reachability="blocked", reach_prov="guard line", override="false",
        )
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(concerns_text, status="RESIDUAL_VULNERABILITY")

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard line")

        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert result["still_vulnerable"] is True
        assert result["concerns"][0]["consequence"] == "NON_BLOCKING"
        assert "RESIDUAL_VULNERABILITY" in result["verdict_conflict"]

    def test_valid_new_schema_response_derives_residual_vulnerability(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(
            num=1, role="primary", reachability="reachable", reach_prov="some diff", override="not_applicable",
        )
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(concerns_text, status="VERIFIED_FIXED")

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] == "RESIDUAL_VULNERABILITY"
        assert result["still_vulnerable"] is True

    def test_scope_facts_cite_the_actual_vulnerability_text_supplied(self):
        """End-to-end proof that `contract_addresses_override` validates
        against the REAL `vulnerability_text` argument, not a fixed
        string."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = (
            _concern_block(num=1, role="primary", reachability="blocked", reach_prov="guard", override="false")
            + _concern_block(
                num=2, role="additional", reachability="blocked", reach_prov="guard",
                override="true", override_prov="override site",
                scope="explicitly_included", scope_prov="must hold even for the override path",
            )
        )
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(concerns_text)

        result = challenge_patch(
            "The fix must hold even for the override path.", "override site", llm, code_context="guard",
        )

        assert result["concerns"][1]["contract_addresses_override"] == "explicitly_included"
        assert result["concerns"][1]["consequence"] == "BLOCKING"
        assert result["verification_status"] == "RESIDUAL_VULNERABILITY"


class TestLegacyCompatibility:
    """The three-way distinction the migration must preserve: an old
    response with no new schema; a genuinely valid new response; and a
    new-schema ATTEMPT that is malformed -- these must NOT be treated the
    same way."""

    def test_true_legacy_response_has_no_concerns_key_and_is_unaffected(self):
        """A response with no `Concerns:` header at all keeps the legacy
        5-key shape (no `concerns`/`schema_version` keys), and fails closed
        rather than taking its stated verdict (RB-1)."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _NEW_FORMAT_RESPONSE.format(status="VERIFIED_FIXED")

        result = challenge_patch("some vuln", "some diff", llm)

        assert "concerns" not in result
        assert "schema_version" not in result
        assert result["verification_status"] is None  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["still_vulnerable"] is True
        assert set(result.keys()) == {
            "verification_status", "still_vulnerable", "edge_cases", "potential_issues", "summary",
        }

    def test_malformed_new_schema_attempt_does_not_fall_back_to_legacy(self):
        """Case 18: a response that DOES contain a `Concerns:` header, but
        whose body is entirely unparseable (zero valid concerns), must
        fail closed under the NEW schema's own rules (zero primary ->
        INSUFFICIENT_EVIDENCE) -- never silently re-routed through
        `_parse_verification`, even though the legacy header here claims
        VERIFIED_FIXED."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = (
            "Verification status: VERIFIED_FIXED\n\n"
            "Concerns:\n\nthis is not a valid numbered block at all\n\n"
            "Edge cases:\n- none\n\nPotential issues:\n- none\n\n"
            "Summary:\n- A concise paragraph.\n"
        )

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert result["still_vulnerable"] is True
        assert result["concerns"] == []

    def test_empty_concerns_header_does_not_fall_back_to_legacy(self):
        """A `Concerns:` header with a body of nothing at all (e.g. the
        model immediately continues to the next section) is still a new-
        schema attempt, not a legacy response -- zero concerns fails
        closed exactly like a malformed attempt, never falls back."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = (
            "Verification status: VERIFIED_FIXED\n\n"
            "Concerns:\n\n"
            "Edge cases:\n- none\n\nPotential issues:\n- none\n\n"
            "Summary:\n- A concise paragraph.\n"
        )

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert "concerns" in result  # new-schema mode WAS engaged, unlike true legacy


class TestOpenEndedProseCorrespondence:
    """Case 17: every verdict-relevant concern discussed in prose must
    have a corresponding structured block once the new schema is used --
    mechanically enforced by requiring the legacy prose sections be empty,
    never by guessing whether a bullet's wording matches a structured
    concern's description."""

    def test_new_schema_response_with_edge_case_bullet_fails_closed(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(num=1, role="primary", reachability="blocked", reach_prov="guard", override="false")
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(
            concerns_text, edge_cases=["A concern only ever mentioned here, never structured"],
        )

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard")

        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert result["still_vulnerable"] is True

    def test_new_schema_response_with_potential_issue_bullet_fails_closed(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(num=1, role="primary", reachability="blocked", reach_prov="guard", override="false")
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(
            concerns_text, potential_issues=["Also only mentioned here"],
        )

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard")

        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"

    def test_new_schema_response_with_empty_legacy_sections_is_unaffected(self):
        """The correspondence gate itself must not misfire on a genuinely
        empty legacy section -- only a NON-empty one is a violation."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(num=1, role="primary", reachability="blocked", reach_prov="guard", override="false")
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(concerns_text)

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard")

        assert result["verification_status"] == "VERIFIED_FIXED"

    def test_no_urllib3_cookie_cve_strings_in_new_schema_additions(self):
        """Same genericity guard as the legacy prompt content, re-applied
        to the newly-added Concerns: prompt section and parser code."""
        import utilities.autopatcher.patch_challenger as challenger_mod

        prompt_text = (Path(challenger_mod.__file__).parent / "prompts" / "patch_challenger.md").read_text(
            encoding="utf-8"
        )
        source_text = Path(challenger_mod.__file__).read_text(encoding="utf-8")
        for blob in (prompt_text, source_text):
            for needle in ("urllib3", "Cookie", "GHSA", "CVE-"):
                assert needle not in blob


class TestSummaryCannotHideAConcern:
    """Closes the fail-closed gap the correspondence gate previously left
    open: `Edge cases:`/`Potential issues:` were checked for substantive
    content, but `Summary:` was not -- a verdict-relevant concern
    described only in free-form prose there, with no corresponding
    structured `Concerns:` block, would previously vanish from
    adjudication entirely while every structured concern computed clean.

    `Summary:` is now checked on exactly the same footing, using the same
    non-semantic presence/placeholder check (never a reading of what the
    prose says) -- and the report-facing `summary` returned for a
    new-schema response is always deterministically synthesized from
    `concerns` alone, never the model's own free-form text."""

    def test_a_summary_only_concern_cannot_pass_green(self):
        """A. A valid, NON_BLOCKING structured primary concern, empty Edge
        cases/Potential issues, but a substantive free-form Summary
        describing an additional residual-path concern that was never
        given its own structured block -- must NOT be VERIFIED_FIXED."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(
            num=1, role="primary", reachability="blocked", reach_prov="guard", override="false",
        )
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(
            concerns_text,
            summary=(
                "- However, a caller can also reach the same sensitive operation through "
                "an undocumented alternate entry point that bypasses this guard entirely."
            ),
        )

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard")

        assert result["verification_status"] != "VERIFIED_FIXED"
        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert result["still_vulnerable"] is True

    def test_b_clean_new_schema_output_still_derives_verified_fixed(self):
        """B. A correctly formatted response -- every concern represented
        structurally, Summary left as the documented placeholder -- must
        still derive VERIFIED_FIXED when every concern is NON_BLOCKING."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = (
            _concern_block(num=1, role="primary", reachability="blocked", reach_prov="guard", override="false")
            + _concern_block(
                num=2, role="additional", reachability="blocked", reach_prov="guard",
                override="true", override_prov="override site", scope="silent", scope_prov="whole document",
            )
        )
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(concerns_text, summary="none")

        result = challenge_patch("some vuln", "override site", llm, code_context="guard")

        assert result["verification_status"] == "VERIFIED_FIXED"
        assert result["still_vulnerable"] is False
        assert "Primary concern" in result["summary"]
        assert "Additional concern" in result["summary"]

    def test_c_blocking_structured_concern_still_wins(self):
        """C. A structured BLOCKING concern still produces
        RESIDUAL_VULNERABILITY, unaffected by the Summary check (Summary
        correctly left as the placeholder here)."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(num=1, role="primary", reachability="reachable", reach_prov="guard", override="not_applicable")
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(concerns_text, summary="none")

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard")

        assert result["verification_status"] == "RESIDUAL_VULNERABILITY"
        assert result["still_vulnerable"] is True

    def test_d_true_legacy_response_summary_behavior_unchanged(self):
        """D. A true legacy response (no `Concerns:` header) keeps its
        existing Summary behavior exactly -- the model's own raw text,
        never synthesized, never gated -- while its verdict fails closed
        (RB-1)."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        llm = mock.MagicMock()
        llm.complete.return_value = _CHALLENGER_RESPONSE  # legacy "Still vulnerable: No" + real Summary prose

        result = challenge_patch("some vuln", "some diff", llm)

        assert result["verification_status"] is None
        assert result["still_vulnerable"] is True  # RB-1: no `Concerns:` section -> fails closed; the stated verdict is never trusted
        assert result["summary"] == "- A concise paragraph summarising the adversarial findings."
        assert "concerns" not in result

    def test_e_no_semantic_matching_bland_summary_also_fails_closed(self):
        """E. The check is purely presence/placeholder-based, never a
        reading of what the prose says -- even an utterly bland,
        non-conflicting, seemingly redundant Summary sentence (one that
        does NOT describe any new concern at all) still fails closed,
        proving no attempt is made to judge whether the wording is
        "equivalent enough" to already-structured content."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(num=1, role="primary", reachability="blocked", reach_prov="guard", override="false")
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(
            concerns_text, summary="- The patch looks fine.",
        )

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard")

        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"

    def test_placeholder_variants_do_not_trigger_the_gate(self):
        """`none`/`n/a`, case-insensitively, are the documented placeholder
        vocabulary -- neither should be misread as substantive content."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(num=1, role="primary", reachability="blocked", reach_prov="guard", override="false")
        for placeholder in ("none", "None", "N/A", "n/a"):
            llm = mock.MagicMock()
            llm.complete.return_value = _response_with_concerns(concerns_text, summary=placeholder)
            result = challenge_patch("some vuln", "some diff", llm, code_context="guard")
            assert result["verification_status"] == "VERIFIED_FIXED", placeholder

    def test_synthesized_summary_never_echoes_raw_model_text(self):
        """The returned `summary` for a new-schema response is always
        code-generated from `concerns` -- the model's own free-form
        Summary sentence (even a compliant, gate-passing empty one is
        irrelevant here) never appears verbatim in the returned value."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(
            num=1, role="primary", description="the originally-described path",
            reachability="blocked", reach_prov="guard", override="false",
        )
        llm = mock.MagicMock()
        llm.complete.return_value = _response_with_concerns(concerns_text, summary="none")

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard")

        assert "the originally-described path" in result["summary"]
        assert result["summary"] != "none"


# ---------------------------------------------------------------------------
# N=5 real-regression masking-bug fixes (CVE-2023-43804 forensic). Three
# confirmed implementation defects, none of them atomic-schema/policy
# questions:
#
# 1. The Summary placeholder check compared raw section text against bare
#    "none"/"n/a", but Summary (unlike Edge cases/Potential issues) is never
#    passed through `_lines_from_bullets` -- so the prompt's own documented
#    "- none" bullet-formatted placeholder failed the check on every single
#    real run, forcing INSUFFICIENT_EVIDENCE unconditionally regardless of
#    concern content.
# 2. The prompt's own worked example wrote `Default execution reachability:
#    blocked` paired with `Requires explicit non-default action:
#    not_applicable` -- a combination the parser's own applicability gate
#    (correctly) rejects as malformed, since not_applicable is reserved for
#    reachability != blocked. Models faithfully reproduced this exact,
#    self-contradictory pattern, corrupting the primary concern in 3 of 4
#    real runs.
# 3. Provenance containment required an exact byte-for-byte substring
#    match, so a citation of genuinely multi-line code -- written out with
#    literal backslash-n escapes, or collapsed onto one line with extra
#    spaces -- failed to validate against the real (actually multi-line)
#    evidence text, spuriously demoting well-grounded facts to unresolved.
# ---------------------------------------------------------------------------

class TestPlaceholderNormalization:
    """Fix 1. `_is_placeholder` must recognize the prompt's own documented
    bullet-formatted placeholder for ALL three legacy sections, while still
    treating any real content -- even content that merely starts with a
    placeholder word -- as substantive."""

    def test_bare_none_is_placeholder(self):
        from utilities.autopatcher.patch_challenger import _is_placeholder
        assert _is_placeholder("none") is True

    def test_dash_none_is_placeholder(self):
        from utilities.autopatcher.patch_challenger import _is_placeholder
        assert _is_placeholder("- none") is True

    def test_star_none_is_placeholder(self):
        from utilities.autopatcher.patch_challenger import _is_placeholder
        assert _is_placeholder("* none") is True

    def test_bare_n_a_is_placeholder(self):
        from utilities.autopatcher.patch_challenger import _is_placeholder
        assert _is_placeholder("N/A") is True

    def test_dash_n_a_is_placeholder(self):
        from utilities.autopatcher.patch_challenger import _is_placeholder
        assert _is_placeholder("- N/A") is True

    def test_star_n_a_is_placeholder(self):
        from utilities.autopatcher.patch_challenger import _is_placeholder
        assert _is_placeholder("* N/A") is True

    def test_empty_string_is_placeholder(self):
        from utilities.autopatcher.patch_challenger import _is_placeholder
        assert _is_placeholder("") is True
        assert _is_placeholder(None) is True

    def test_real_content_after_placeholder_word_is_not_a_placeholder(self):
        """The bullet strip must not launder substantive content that
        merely happens to start with a placeholder word."""
        from utilities.autopatcher.patch_challenger import _is_placeholder
        assert _is_placeholder("- none, but also a residual concern") is False

    def test_exact_n5_observed_summary_shape_passes_end_to_end(self):
        """The exact real-regression shape: every one of the four real
        Challenger runs wrote precisely this, and all four incorrectly
        failed closed before this fix."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(num=1, role="primary", reachability="blocked", reach_prov="guard", override="false")
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "Verification status: VERIFIED_FIXED\n\n"
            f"Concerns:\n\n{concerns_text}\n"
            "Edge cases:\n- none\n\n"
            "Potential issues:\n- none\n\n"
            "Summary:\n- none\n"
        )

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard")

        assert result["verification_status"] == "VERIFIED_FIXED"
        assert result["still_vulnerable"] is False

    def test_substantive_summary_still_fails_closed_after_fix(self):
        """The fix must recognize the documented placeholder without
        becoming permissive about genuine content -- a real residual-path
        claim in Summary must still force the run closed."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        concerns_text = _concern_block(num=1, role="primary", reachability="blocked", reach_prov="guard", override="false")
        llm = mock.MagicMock()
        llm.complete.return_value = (
            "Verification status: VERIFIED_FIXED\n\n"
            f"Concerns:\n\n{concerns_text}\n"
            "Edge cases:\n- none\n\n"
            "Potential issues:\n- none\n\n"
            "Summary:\n- However, a caller can also reach the same operation through an undocumented path.\n"
        )

        result = challenge_patch("some vuln", "some diff", llm, code_context="guard")

        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert result["still_vulnerable"] is True


class TestApplicabilityCanonicalSemantics:
    """Fix 2. `requires_explicit_non_default_action` has ONE unambiguous
    valid representation for a blocked-with-no-override concern: `false`
    -- never `not_applicable`, which is reserved exclusively for
    reachability != "blocked". This is the representation consistent with
    the frozen `_concern_consequence` policy, which explicitly branches on
    `override == "false"` (never on `not_applicable`) inside its
    `reachability == "blocked"` arm."""

    def _parse_one(self, **kwargs):
        from utilities.autopatcher.patch_challenger import _parse_concern_block
        block = _concern_block(**kwargs)
        return _parse_concern_block(block, code_context="ctx", patch="diff", vulnerability_text="vuln text")

    def test_canonical_blocked_default_concern_parses_and_is_non_blocking(self):
        """The ONE valid representation of "blocked, no override at all"."""
        result = self._parse_one(reachability="blocked", reach_prov="ctx", override="false")
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "blocked"
        assert result["requires_explicit_non_default_action"] == "false"
        assert result["consequence"] == "NON_BLOCKING"

    def test_canonical_reachable_concern_parses_and_is_blocking(self):
        result = self._parse_one(reachability="reachable", reach_prov="ctx", override="not_applicable")
        assert result["malformed"] is False
        assert result["consequence"] == "BLOCKING"

    def test_canonical_explicit_non_default_concern_parses(self):
        result = self._parse_one(
            reachability="blocked", reach_prov="ctx", override="true", override_prov="diff",
            scope="silent", scope_prov="whole document",
        )
        assert result["malformed"] is False
        assert result["requires_explicit_non_default_action"] == "true"
        assert result["consequence"] == "NON_BLOCKING"

    def test_blocked_with_not_applicable_override_still_fails_closed(self):
        """The exact real-regression pattern (the prompt's OWN prior
        worked example, before this fix) must remain rejected -- the fix
        must not have weakened validation to accommodate it."""
        result = self._parse_one(reachability="blocked", override="not_applicable")
        assert result["malformed"] is True
        assert result["malformed_reason"] == "override_applicability_violated"
        assert result["consequence"] == "UNRESOLVED"

    def test_reachable_with_populated_override_still_fails_closed(self):
        """Symmetric contradictory combination, also still rejected."""
        result = self._parse_one(reachability="reachable", override="true", override_prov="x", scope="not_applicable")
        assert result["malformed"] is True

    def test_exactly_one_primary_invariant_still_enforced(self):
        from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
        zero_primary = [{"concern_role": "additional", "consequence": "NON_BLOCKING"}]
        two_primary = [
            {"concern_role": "primary", "consequence": "NON_BLOCKING"},
            {"concern_role": "primary", "consequence": "NON_BLOCKING"},
        ]
        assert _derive_status_from_concerns(zero_primary, False) == ("INSUFFICIENT_EVIDENCE", True)
        assert _derive_status_from_concerns(two_primary, False) == ("INSUFFICIENT_EVIDENCE", True)

    def test_prompt_worked_example_itself_conforms_to_the_parser_contract(self):
        """Regression guard tying the prompt directly to the parser: the
        shipped worked `Concerns:` example must itself parse with zero
        malformed concerns -- this is exactly the real-world failure mode
        (a model faithfully reproducing the example) that caused 3 of 4
        real runs to corrupt their primary concern."""
        from utilities.autopatcher.patch_challenger import challenge_patch, _PROMPT_PATH

        prompt_text = _PROMPT_PATH.read_text(encoding="utf-8")
        start = prompt_text.index("Example output using the `Concerns:` schema")
        example = prompt_text[start:]

        llm = mock.MagicMock()
        llm.complete.return_value = example

        result = challenge_patch("some vuln", "some diff", llm, code_context=example)

        assert result["concerns"], "worked example must parse at least one concern"
        for concern in result["concerns"]:
            assert concern["malformed"] is False, concern.get("malformed_reason")
        assert any(c["concern_role"] == "primary" for c in result["concerns"])


class TestProvenanceNormalization:
    """Fix 3. Whitespace-only differences between a quoted citation and
    the real evidence text (real multi-line layout, a literal
    backslash-n-collapsed quote, or a whitespace-collapsed quote) must
    validate identically -- but every non-whitespace token and its order
    must still match exactly; no semantic or fuzzy matching."""

    MULTILINE_SOURCE = (
        "        remove_headers_on_redirect: typing.Collection[\n"
        "            str\n"
        "        ] = DEFAULT_REMOVE_HEADERS_ON_REDIRECT,\n"
    )

    def _parse_one(self, code_context="", patch="", vulnerability_text="", **kwargs):
        from utilities.autopatcher.patch_challenger import _parse_concern_block
        block = _concern_block(**kwargs)
        return _parse_concern_block(block, code_context=code_context, patch=patch, vulnerability_text=vulnerability_text)

    def test_exact_single_line_quote_validates(self):
        result = self._parse_one(
            code_context="if retries.remove_headers_on_redirect and not conn.is_same_host(x):",
            reachability="blocked", reach_prov="if retries.remove_headers_on_redirect and not conn.is_same_host(x):",
            override="false",
        )
        assert result["default_execution_reachability"] == "blocked"

    def test_actual_multiline_quote_validates(self):
        """The citation itself spans real newlines, matching a real
        multi-line evidence block exactly."""
        quote = (
            "remove_headers_on_redirect: typing.Collection[\n"
            "            str\n"
            "        ] = DEFAULT_REMOVE_HEADERS_ON_REDIRECT,"
        )
        result = self._parse_one(
            code_context=self.MULTILINE_SOURCE, reachability="blocked", reach_prov=quote, override="false",
        )
        assert result["default_execution_reachability"] == "blocked"

    def test_literal_escaped_newline_equivalent_validates(self):
        """The EXACT shape observed in the real N=5 regression: the model
        wrote out a literal two-character backslash-n instead of an
        actual newline, collapsing a multi-line quote onto one physical
        line."""
        quote = (
            "remove_headers_on_redirect: typing.Collection[\\n"
            "        str\\n"
            "    ] = DEFAULT_REMOVE_HEADERS_ON_REDIRECT,"
        )
        result = self._parse_one(
            code_context=self.MULTILINE_SOURCE, reachability="blocked", reach_prov=quote, override="false",
        )
        assert result["default_execution_reachability"] == "blocked"

    def test_whitespace_collapsed_equivalent_validates(self):
        """The second real-regression shape: the model collapsed the
        multi-line quote onto one line using plain spaces instead of
        newlines or escapes."""
        quote = "remove_headers_on_redirect: typing.Collection[ str ] = DEFAULT_REMOVE_HEADERS_ON_REDIRECT,"
        result = self._parse_one(
            code_context=self.MULTILINE_SOURCE, reachability="blocked", reach_prov=quote, override="false",
        )
        assert result["default_execution_reachability"] == "blocked"

    def test_materially_different_quote_still_rejected(self):
        """A quote that differs in actual token content (a different
        constant name) must NOT validate merely because its whitespace
        shape is plausible -- proves the normalization is formatting-only,
        never semantic/fuzzy."""
        quote = "remove_headers_on_redirect: typing.Collection[ str ] = SOME_OTHER_CONSTANT,"
        result = self._parse_one(
            code_context=self.MULTILINE_SOURCE, reachability="blocked", reach_prov=quote, override="false",
        )
        assert result["default_execution_reachability"] == "unresolved"

    def test_quote_from_unauthorized_source_still_rejected(self):
        """A scope citation present only in repository evidence, never in
        `vulnerability_text`, must not validate `explicitly_included` --
        the normalization applies equally to both sources, so this is not
        a side effect of the whitespace change."""
        result = self._parse_one(
            code_context="the phrase lives only here", patch="",
            vulnerability_text="an unrelated advisory that never quotes that phrase",
            reachability="blocked", reach_prov="guard", override="true", override_prov="override site",
            scope="explicitly_included", scope_prov="the phrase lives only here",
        )
        assert result["contract_addresses_override"] == "unresolved"

    def test_technical_capacity_omitted_evidence_still_cannot_ground_a_fact(self):
        """A citation naming content that was never concatenated into
        `code_context`/`patch` (exactly what happens when it is omitted
        upstream for technical capacity) still fails to validate, even
        after whitespace normalization -- normalization never invents
        missing content."""
        result = self._parse_one(
            code_context="only this much evidence was included after the capacity cutoff",
            reachability="blocked",
            reach_prov="a guard that existed in the omitted, unincluded portion of the evidence",
            override="false",
        )
        assert result["default_execution_reachability"] == "unresolved"


# ---------------------------------------------------------------------------
# concerns_v2 -- atomic default-execution-reachability decomposition.
#
# Covers, in order: pure deterministic derivation (all 11 rules + catch-all),
# per-field applicability gates, the structural absence of an illegitimate
# `operation_present_in_evidence` value, the deterministic guard/operation
# ordering check, the bounded (function-scoped) absence provenance rule,
# named mechanism-diversity fixtures, the urllib3 Run 1 evidence-shape
# regression fixtures, and schema-version routing/backward compatibility.
# ---------------------------------------------------------------------------

def _concern_block_v2(
    num=1, role="primary", description="a concern",
    op_present="present", op_prov="none",
    guard="present", guard_prov="none", function_prov="none",
    default_state="condition_true_under_default", default_state_prov="none",
    effect="prevents_operation", effect_prov="none",
    reentry="not_applicable", reentry_prov="none",
    override="not_applicable", override_prov="none",
    scope="not_applicable", scope_prov="none",
    hypothesized_outcome=None,
):
    # `override`'s applicability gate depends on the DERIVED reachability
    # (blocked -> true/false/unresolved; anything else -> not_applicable),
    # so `not_applicable` -- valid for every non-"blocked" outcome, the
    # common case across these fixtures -- is the safe default; a caller
    # asserting a `blocked` outcome must pass an explicit override value.
    # `hypothesized_outcome` defaults to `None`, which OMITS the line
    # entirely (not merely writes `none`) -- every existing fixture/test
    # calling this helper keeps producing a byte-identical block unless it
    # opts in.
    hypothesized_outcome_line = (
        f"   Hypothesized outcome: {hypothesized_outcome}\n" if hypothesized_outcome is not None else ""
    )
    return (
        f"{num}. Role: {role}\n"
        f"   Description: {description}\n"
        f"   Operation present in evidence: {op_present}\n"
        f"   Preceding guard: {guard}\n"
        f"   Guard provenance: {guard_prov}\n"
        f"   Function provenance: {function_prov}\n"
        f"   Operation provenance: {op_prov}\n"
        f"   Guard default state: {default_state}\n"
        f"   Guard default state provenance: {default_state_prov}\n"
        f"   Guard effect: {effect}\n"
        f"   Guard effect provenance: {effect_prov}\n"
        f"   Reentry state propagation: {reentry}\n"
        f"   Reentry provenance: {reentry_prov}\n"
        f"   Requires explicit non-default action: {override}\n"
        f"   Override provenance: {override_prov}\n"
        f"   Contract addresses override: {scope}\n"
        f"   Scope provenance: {scope_prov}\n"
        f"{hypothesized_outcome_line}"
    )


class TestDeriveDefaultExecutionReachability:
    """Exhaustive table for `_derive_default_execution_reachability` --
    the frozen 11-rule v2 derivation, in isolation from parsing/provenance."""

    def _facts(self, **overrides):
        base = {
            "operation_present_in_evidence": "present",
            "preceding_guard": "present",
            "guard_default_state": "condition_true_under_default",
            "guard_effect": "prevents_operation",
            "reentry_state_propagation": "not_applicable",
        }
        base.update(overrides)
        return base

    def test_rule1_operation_unresolved_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(operation_present_in_evidence="unresolved")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_rule2_guard_unresolved_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(preceding_guard="unresolved")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_rule3_guard_absent_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(preceding_guard="absent")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_rule4_default_state_unresolved_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(guard_default_state="unresolved")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_rule5_default_state_false_is_reachable(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(guard_default_state="condition_false_under_default")
        assert _derive_default_execution_reachability(facts) == "reachable"

    def test_rule6_effect_unresolved_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(guard_effect="unresolved")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_rule7_effect_no_effect_is_reachable(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(guard_effect="no_effect")
        assert _derive_default_execution_reachability(facts) == "reachable"

    def test_rule8_prevents_operation_not_applicable_reentry_is_blocked(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(guard_effect="prevents_operation", reentry_state_propagation="not_applicable")
        assert _derive_default_execution_reachability(facts) == "blocked"

    def test_rule8_neutralizes_operation_not_applicable_reentry_is_blocked(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(guard_effect="neutralizes_operation", reentry_state_propagation="not_applicable")
        assert _derive_default_execution_reachability(facts) == "blocked"

    def test_rule9_reentry_unresolved_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(reentry_state_propagation="unresolved")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_rule10_reentry_reset_or_bypassed_is_reachable(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(reentry_state_propagation="reset_or_bypassed")
        assert _derive_default_execution_reachability(facts) == "reachable"

    def test_rule11_reentry_preserved_is_blocked(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(reentry_state_propagation="preserved")
        assert _derive_default_execution_reachability(facts) == "blocked"

    def test_catchall_malformed_operation_value_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(operation_present_in_evidence="garbage")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_catchall_malformed_guard_value_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(preceding_guard="garbage")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_catchall_malformed_default_state_value_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(guard_default_state="garbage")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_catchall_malformed_effect_value_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(guard_effect="garbage")
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_catchall_malformed_reentry_value_is_unresolved(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = self._facts(reentry_state_propagation="garbage")
        assert _derive_default_execution_reachability(facts) == "unresolved"


class TestV2ApplicabilityGates:
    """Every v2 field's applicability gate -- a value/`not_applicable`
    mismatch fails the WHOLE concern closed to malformed, never silently
    corrected, mirroring OVERRIDE_VALUES/SCOPE_VALUES's own discipline."""

    def _parse_one(self, code_context="", patch="", vulnerability_text="", **kwargs):
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2
        block = _concern_block_v2(**kwargs)
        return _parse_concern_block_v2(block, code_context=code_context, patch=patch, vulnerability_text=vulnerability_text)

    def test_fully_valid_shape_is_not_malformed(self):
        result = self._parse_one(
            code_context="flag: bool = True\nif flag: raise Err()\nop()",
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="prevents_operation", effect_prov="raise Err()",
            reentry="not_applicable", override="false",
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "blocked"

    def test_guard_value_while_operation_unresolved_is_malformed(self):
        result = self._parse_one(op_present="unresolved", guard="present")
        assert result["malformed"] is True
        assert result["malformed_reason"] == "preceding_guard_applicability_violated"

    def test_operation_unresolved_with_guard_not_applicable_is_valid_shape(self):
        result = self._parse_one(
            op_present="unresolved", guard="not_applicable",
            default_state="not_applicable", effect="not_applicable", reentry="not_applicable",
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"

    def test_guard_absent_with_default_state_value_is_malformed(self):
        result = self._parse_one(
            code_context="def f():\n    op()",
            op_present="present", op_prov="op()",
            guard="absent", guard_prov="whole function", function_prov="def f():",
            default_state="condition_true_under_default",  # must be not_applicable when guard != present
        )
        assert result["malformed"] is True
        assert result["malformed_reason"] == "guard_default_state_applicability_violated"

    def test_default_state_false_with_effect_value_is_malformed(self):
        result = self._parse_one(
            code_context="if flag: pass\nop()",
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: pass",
            default_state="condition_false_under_default", default_state_prov="flag = False",
            effect="prevents_operation",  # must be not_applicable when default_state != condition_true
        )
        assert result["malformed"] is True
        assert result["malformed_reason"] == "guard_effect_applicability_violated"

    def test_effect_no_effect_with_reentry_value_is_malformed(self):
        result = self._parse_one(
            code_context="if flag: log()\nop()",
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: log()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="no_effect", effect_prov="log()",
            reentry="preserved",  # must be not_applicable when effect is not prevents/neutralizes
        )
        assert result["malformed"] is True
        assert result["malformed_reason"] == "reentry_propagation_applicability_violated"

    def test_reentry_not_applicable_is_legitimate_even_when_effect_qualifies(self):
        """Unlike every other v2 gate, `not_applicable` remains a REAL
        answer for reentry even when `guard_effect` qualifies -- the
        common, non-recursive case (rule 8)."""
        result = self._parse_one(
            code_context="flag: bool = True\nif flag: raise Err()\nop()",
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="prevents_operation", effect_prov="raise Err()",
            reentry="not_applicable", override="false",
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "blocked"

    def test_invalid_role_is_malformed(self):
        result = self._parse_one(role="bogus")
        assert result["malformed"] is True
        assert result["malformed_reason"] == "invalid_or_missing_role"

    def test_invalid_operation_present_value_is_malformed(self):
        result = self._parse_one(op_present="bogus")
        assert result["malformed"] is True
        assert result["malformed_reason"] == "invalid_or_missing_operation_present"


class TestOperationPresenceHasNoAbsenceValue:
    """Structural lock: `operation_present_in_evidence` must never be able
    to express `false`/`absent` -- Challenger receives a selected slice of
    the repository, never a complete one, so "not found" can never
    legitimately become "does not exist" (see OPERATION_PRESENCE_VALUES)."""

    def test_value_set_is_exactly_present_and_unresolved(self):
        from utilities.autopatcher.patch_challenger import OPERATION_PRESENCE_VALUES
        assert OPERATION_PRESENCE_VALUES == ("present", "unresolved")
        assert "false" not in OPERATION_PRESENCE_VALUES
        assert "absent" not in OPERATION_PRESENCE_VALUES

    def test_a_false_value_in_the_response_is_malformed_not_an_absence_claim(self):
        """A model that writes `false` anyway (deviating from the
        contract) must fail closed as malformed -- never silently
        accepted as a resolved absence claim."""
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2
        block = _concern_block_v2(op_present="false")
        result = _parse_concern_block_v2(block, code_context="", patch="", vulnerability_text="")
        assert result["malformed"] is True
        assert result["malformed_reason"] == "invalid_or_missing_operation_present"


class TestGuardOperationOrdering:
    """Deterministic (non-LLM) check: a guard citation must be textually
    before the operation citation within a SHARED evidence source --
    necessary, never sufficient, for a preceding guard (see
    `_citation_precedes`). Textual order alone never proves true CFG
    dominance; it only catches a citation that is backwards."""

    def _parse_one(self, code_context, patch="", **kwargs):
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2
        block = _concern_block_v2(**kwargs)
        return _parse_concern_block_v2(block, code_context=code_context, patch=patch, vulnerability_text="")

    def _facts_kwargs(self):
        return dict(
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="prevents_operation", effect_prov="raise Err()",
        )

    def test_guard_before_operation_establishes_preceding_guard(self):
        result = self._parse_one(
            "flag: bool = True\nif flag: raise Err()\nop()", override="false", **self._facts_kwargs()
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "blocked"

    def test_guard_after_operation_cannot_establish_preceding_guard(self):
        """The SAME two citations, reversed order in the source, must
        demote to unresolved -- never assumed present just because both
        citations individually validate somewhere in the evidence."""
        result = self._parse_one("op()\nflag: bool = True\nif flag: raise Err()", **self._facts_kwargs())
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"

    def test_guard_and_operation_in_different_sources_cannot_establish_order(self):
        """Individually valid citations against DIFFERENT sources (one
        found only in `code_context`, the other only in `patch`) share no
        common coordinate space -- ordering can never be established."""
        result = self._parse_one(
            "flag: bool = True\nif flag: raise Err()", patch="op()", **self._facts_kwargs()
        )
        assert result["default_execution_reachability"] == "unresolved"


class TestBoundedAbsenceProvenance:
    """`preceding_guard == absent` is the ONLY new bounded absence claim.
    The `whole function` marker plus a grounded `Function provenance:`
    citation are NECESSARY but never SUFFICIENT by themselves: `absent`
    is only mechanically accepted when BOTH the function and operation
    citations are found within the SAME block an existing, unmodified
    repository-evidence renderer (remediation_planner.py's
    `_render_full_file_block`/`_render_definition_block`) already marks,
    deterministically, as complete -- never merely because the model
    asserts it reviewed the whole function, and never invented here."""

    _TRUSTED_FULL_FILE = (
        "#### Full file (last resort): `pkg/mod.py` (2 lines)\n\n"
        "```python\n"
        "def f():\n"
        "    op()\n"
        "```\n"
    )

    _TRUSTED_TARGET_DEFINITION = (
        "#### Target definition: `pkg/mod.py:f` (lines 1–2)\n\n"
        "```python\n"
        "def f():\n"
        "    op()\n"
        "```\n"
    )

    _TRUSTED_RELATED_DEFINITION = (
        "#### Related definition (context only, not an approved edit target): `pkg/mod.py:f` (lines 1–2)\n\n"
        "```python\n"
        "def f():\n"
        "    op()\n"
        "```\n"
    )

    _TRUSTED_HEADING_BUT_TRUNCATED_BEFORE_OPERATION = (
        # A REAL trusted heading -- but the fenced content itself was cut
        # before ever reaching the operation. The heading alone must
        # never substitute for the citation actually being findable
        # inside that same block's own source.
        "#### Target definition: `pkg/mod.py:f` (lines 1–1)\n\n"
        "```python\n"
        "def f():\n"
        "```\n"
    )

    _UNTRUSTED_USAGE_WINDOW_HEADING = (
        # A REAL renderer heading (a usage window around a call site) --
        # deliberately excluded from the trusted set: a window is not a
        # definition and is not presumed complete.
        "#### Discovered consumer: `pkg/mod.py:f` (lines 1–2, deterministic discovered usage)\n\n"
        "```python\n"
        "def f():\n"
        "    op()\n"
        "```\n"
    )

    _NAKED_SNIPPET = "def f():\n    op()"

    def _parse_one(self, code_context, **kwargs):
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2
        defaults = dict(
            op_present="present", op_prov="op()",
            guard="absent", guard_prov="whole function", function_prov="def f():",
            default_state="not_applicable", effect="not_applicable", reentry="not_applicable",
        )
        defaults.update(kwargs)
        block = _concern_block_v2(**defaults)
        return _parse_concern_block_v2(block, code_context=code_context, patch="", vulnerability_text="")

    # --- 1. marker + citation, but no deterministic completeness proof ---

    def test_marker_and_citation_with_no_completeness_heading_is_unresolved(self):
        result = self._parse_one(self._NAKED_SNIPPET)
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"

    def test_untrusted_usage_window_heading_is_unresolved(self):
        """A REAL renderer heading, but one this module deliberately does
        not trust -- must never be confused with a completeness proof."""
        result = self._parse_one(self._UNTRUSTED_USAGE_WINDOW_HEADING)
        assert result["default_execution_reachability"] == "unresolved"

    # --- 2. truncated function evidence ---

    def test_truncated_evidence_under_a_trusted_heading_is_unresolved(self):
        """The trusted heading alone is never sufficient either -- the
        operation citation must actually be findable inside that SAME
        trusted block's own fenced content, not merely somewhere else in
        `code_context`."""
        result = self._parse_one(self._TRUSTED_HEADING_BUT_TRUNCATED_BEFORE_OPERATION)
        assert result["default_execution_reachability"] == "unresolved"

    # --- 3. a genuinely complete block establishes the bounded absence
    # claim mechanically (span-completeness), but that completeness proof
    # is never itself a semantic-correctness proof -- so even a fully
    # mechanically-verified absence still de-escalates to `unresolved`
    # (rule 3), never `reachable`. ---

    def test_full_file_heading_establishes_mechanically_verified_absence(self):
        result = self._parse_one(self._TRUSTED_FULL_FILE)
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"

    def test_target_definition_heading_establishes_mechanically_verified_absence(self):
        result = self._parse_one(self._TRUSTED_TARGET_DEFINITION)
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"

    def test_related_definition_heading_establishes_mechanically_verified_absence(self):
        result = self._parse_one(self._TRUSTED_RELATED_DEFINITION)
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"

    # --- remaining fail-closed cases, now against a trusted block ---

    def test_marker_alone_without_function_citation_still_fails_closed(self):
        """The marker by itself is never sufficient -- a real `Function
        provenance:` citation is also required, even under a trusted
        heading."""
        result = self._parse_one(self._TRUSTED_FULL_FILE, function_prov="none")
        assert result["default_execution_reachability"] == "unresolved"

    def test_wrong_marker_text_still_fails_closed(self):
        result = self._parse_one(self._TRUSTED_FULL_FILE, guard_prov="I checked the whole function")
        assert result["default_execution_reachability"] == "unresolved"

    def test_function_citation_not_actually_present_fails_closed(self):
        result = self._parse_one(self._TRUSTED_FULL_FILE, function_prov="def some_other_function():")
        assert result["default_execution_reachability"] == "unresolved"

    def test_function_citation_after_operation_within_trusted_block_fails_closed(self):
        """The containing function's own citation must textually precede
        the operation it supposedly contains WITHIN the trusted block --
        a backwards citation cannot establish that even under a trusted
        heading."""
        reversed_block = (
            "#### Full file (last resort): `pkg/mod.py` (2 lines)\n\n"
            "```python\n"
            "op()\n"
            "def f():\n"
            "```\n"
        )
        result = self._parse_one(reversed_block, function_prov="def f():")
        assert result["default_execution_reachability"] == "unresolved"

    def test_citations_split_across_two_different_trusted_blocks_fails_closed(self):
        """Each citation individually validating against SOME trusted
        block is not enough -- both must be found in the SAME one, or a
        function citation from an unrelated file's trusted block could
        "borrow" completeness for an operation found somewhere else
        entirely."""
        two_blocks = (
            "#### Full file (last resort): `pkg/other.py` (2 lines)\n\n"
            "```python\n"
            "def f():\n"
            "    pass\n"
            "```\n\n"
            "#### Full file (last resort): `pkg/mod.py` (1 lines)\n\n"
            "```python\n"
            "op()\n"
            "```\n"
        )
        result = self._parse_one(two_blocks, function_prov="def f():", op_prov="op()")
        assert result["default_execution_reachability"] == "unresolved"


class TestMechanismDiversityFixtures:
    """One deterministic fixture per mechanism shape the v2 schema must
    represent without contortion -- not only the control-flow-blocking
    shape a single `reachable|blocked|unresolved` field biased toward."""

    def _derive(self, **overrides):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability
        facts = {
            "operation_present_in_evidence": "present",
            "preceding_guard": "present",
            "guard_default_state": "condition_true_under_default",
            "guard_effect": "prevents_operation",
            "reentry_state_propagation": "not_applicable",
        }
        facts.update(overrides)
        return _derive_default_execution_reachability(facts)

    def test_1_hard_control_flow_prevention_is_blocked(self):
        assert self._derive(guard_effect="prevents_operation", reentry_state_propagation="not_applicable") == "blocked"

    def test_2_state_input_neutralization_is_blocked(self):
        assert self._derive(guard_effect="neutralizes_operation", reentry_state_propagation="not_applicable") == "blocked"

    def test_3_no_relevant_guard_is_unresolved(self):
        assert self._derive(preceding_guard="absent") == "unresolved"

    def test_4_default_condition_false_is_reachable(self):
        assert self._derive(guard_default_state="condition_false_under_default") == "reachable"

    def test_5_reentry_preserved_is_blocked(self):
        assert self._derive(reentry_state_propagation="preserved") == "blocked"

    def test_6_reentry_reset_or_bypassed_is_reachable(self):
        assert self._derive(reentry_state_propagation="reset_or_bypassed") == "reachable"


class TestUrllib3Run1ReachabilityRegressionFixtures:
    """Bounded, hand-authored fixtures representing the ACTUAL evidence
    shape (the `assert_same_host` recursive-redirect guard, and the
    `remove_headers_on_redirect` stripping guard) that produced a real
    `unresolved` composition failure under the v1 schema -- see the
    Challenger reachability design investigation this schema implements.
    NOT a real CVE regression: these are literal, self-contained,
    hand-written source-text fixtures, never fetched, cloned, applied, or
    executed."""

    _ASSERT_SAME_HOST_SOURCE = (
        "class HTTPConnectionPool(ConnectionPool, RequestMethods):\n"
        "    def urlopen(\n"
        "        self,\n"
        "        method,\n"
        "        url,\n"
        "        redirect=True,\n"
        "        assert_same_host: bool = True,\n"
        "    ):\n"
        "        # Check host\n"
        "        if assert_same_host and not self.is_same_host(url):\n"
        "            raise HostChangedError(self, url, retries)\n"
        "        redirect_location = redirect and response.get_redirect_location()\n"
        "        if redirect_location:\n"
        "            return self.urlopen(\n"
        "                method,\n"
        "                redirect_location,\n"
        "                redirect=redirect,\n"
        "                assert_same_host=assert_same_host,\n"
        "            )\n"
    )

    _HEADER_STRIP_SOURCE = (
        "class PoolManager(RequestMethods):\n"
        "    def urlopen(\n"
        "        self,\n"
        "        method,\n"
        "        url,\n"
        "        redirect=True,\n"
        "        remove_headers_on_redirect=DEFAULT_REMOVE_HEADERS_ON_REDIRECT,\n"
        "        **kw,\n"
        "    ):\n"
        "        if retries.remove_headers_on_redirect and not conn.is_same_host(redirect_location):\n"
        "            for header in list(kw['headers']):\n"
        "                if header.lower() in retries.remove_headers_on_redirect:\n"
        "                    del kw['headers'][header]\n"
        "        return self.urlopen(method, redirect_location, **kw)\n"
    )

    def test_assert_same_host_preserved_across_redirect_recursion_derives_blocked(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        block = _concern_block_v2(
            role="primary",
            description=(
                "Whether a cross-origin redirect is still reachable via "
                "recursive urlopen under default execution."
            ),
            op_present="present", op_prov="return self.urlopen(",
            guard="present", guard_prov="if assert_same_host and not self.is_same_host(url):",
            default_state="condition_true_under_default", default_state_prov="assert_same_host: bool = True,",
            effect="prevents_operation", effect_prov="raise HostChangedError(self, url, retries)",
            reentry="preserved", reentry_prov="assert_same_host=assert_same_host,",
            override="false",
        )
        response = _response_with_concerns(block)
        llm = mock.MagicMock()
        llm.complete.return_value = response

        result = challenge_patch("some vuln", "some diff", llm, code_context=self._ASSERT_SAME_HOST_SOURCE)

        assert result["schema_version"] == "concerns_v2"
        concern = result["concerns"][0]
        assert concern["malformed"] is False, concern.get("malformed_reason")
        assert concern["default_execution_reachability"] == "blocked"
        assert concern["reachability_facts"]["preceding_guard"] == "present"
        assert concern["reachability_facts"]["guard_default_state"] == "condition_true_under_default"
        assert concern["reachability_facts"]["guard_effect"] == "prevents_operation"
        assert concern["reachability_facts"]["reentry_state_propagation"] == "preserved"

    def test_header_stripping_neutralization_derives_blocked(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        block = _concern_block_v2(
            role="primary",
            description=(
                "Whether a cookie-bearing header still reaches a "
                "cross-origin redirect target under default execution."
            ),
            op_present="present", op_prov="return self.urlopen(method, redirect_location, **kw)",
            guard="present",
            guard_prov="if retries.remove_headers_on_redirect and not conn.is_same_host(redirect_location):",
            default_state="condition_true_under_default",
            default_state_prov="remove_headers_on_redirect=DEFAULT_REMOVE_HEADERS_ON_REDIRECT,",
            effect="neutralizes_operation", effect_prov="del kw['headers'][header]",
            reentry="not_applicable",
            override="false",
        )
        response = _response_with_concerns(block)
        llm = mock.MagicMock()
        llm.complete.return_value = response

        result = challenge_patch("some vuln", "some diff", llm, code_context=self._HEADER_STRIP_SOURCE)

        assert result["schema_version"] == "concerns_v2"
        concern = result["concerns"][0]
        assert concern["malformed"] is False, concern.get("malformed_reason")
        assert concern["default_execution_reachability"] == "blocked"
        assert concern["reachability_facts"]["guard_effect"] == "neutralizes_operation"


class TestV2SchemaVersionRoutingAndBackwardCompatibility:
    """A response is routed to v2 ONLY when its `Concerns:` body literally
    carries the `Preceding guard:` field label -- a label absent from
    every `concerns_v1` response, archived or new (see
    `_response_uses_v2_schema`). Existing v1/legacy parsing/output stays
    byte-identical; this is purely additive routing."""

    def test_v1_response_is_schema_v1_unchanged(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        block = _concern_block(reachability="blocked", reach_prov="the guard", override="false")
        response = _response_with_concerns(block)
        llm = mock.MagicMock()
        llm.complete.return_value = response

        result = challenge_patch("v", "p", llm, code_context="the guard")
        assert result["schema_version"] == "concerns_v1"
        assert "reachability_facts" not in result["concerns"][0]

    def test_v2_response_is_schema_v2(self):
        from utilities.autopatcher.patch_challenger import challenge_patch

        block = _concern_block_v2()
        response = _response_with_concerns(block)
        llm = mock.MagicMock()
        llm.complete.return_value = response

        result = challenge_patch("v", "p", llm, code_context="ctx")
        assert result["schema_version"] == "concerns_v2"

    def test_response_with_v2_marker_never_falls_back_to_v1_parsing_for_a_v1_shaped_block(self):
        """A response containing `Preceding guard:` ANYWHERE routes EVERY
        block in it through the v2 parser -- a second, v1-shaped block
        (using `Default execution reachability:` instead) in the SAME
        response fails closed on its own missing v2 fields, never
        silently reinterpreted as legacy v1."""
        from utilities.autopatcher.patch_challenger import challenge_patch

        v2_block = _concern_block_v2(num=1, role="primary")
        v1_shaped_block = _concern_block(num=2, role="additional", reachability="blocked", override="false")
        response = _response_with_concerns(v2_block + "\n" + v1_shaped_block)
        llm = mock.MagicMock()
        llm.complete.return_value = response

        result = challenge_patch("v", "p", llm, code_context="if flag: raise Err()\nop()")

        assert result["schema_version"] == "concerns_v2"
        concerns = result["concerns"]
        assert concerns[0]["concern_role"] == "primary"
        assert concerns[1]["malformed"] is True
        assert concerns[1]["malformed_reason"] == "invalid_or_missing_operation_present"

    def test_response_uses_v2_schema_pure_function(self):
        from utilities.autopatcher.patch_challenger import _response_uses_v2_schema

        assert _response_uses_v2_schema("1. Role: primary\n   Preceding guard: present\n") is True
        assert _response_uses_v2_schema("1. Role: primary\n   Default execution reachability: blocked\n") is False
        assert _response_uses_v2_schema(None) is False
        assert _response_uses_v2_schema("") is False


class TestAbsenceDeescalationRegression:
    """`preceding_guard == absent` must fail closed to `unresolved`, never
    `reachable` -- the bounded-absence span-completeness check
    (`_absence_mechanically_verified_complete`) proves only that the cited
    span IS the complete function, never that "no guard" is semantically
    true of its content. This is the entire behavioral fix in this
    module: a bounded absence claim is a categorically weaker,
    unverified LLM semantic assertion, so it must not, by itself, license
    the same conclusion a positively-cited fact can."""

    def test_absence_derivation_rule_is_unresolved_in_isolation(self):
        from utilities.autopatcher.patch_challenger import _derive_default_execution_reachability

        facts = {
            "operation_present_in_evidence": "present",
            "preceding_guard": "absent",
            "guard_default_state": "not_applicable",
            "guard_effect": "not_applicable",
            "reentry_state_propagation": "not_applicable",
        }
        assert _derive_default_execution_reachability(facts) == "unresolved"

    def test_mechanically_complete_absence_end_to_end_is_unresolved_not_blocking(self):
        """Full parse, including a genuinely trusted/complete evidence
        block (so the span-completeness check itself PASSES) -- the
        de-escalation still applies, and `consequence` reflects it as
        UNRESOLVED, never BLOCKING or NON_BLOCKING."""
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2

        code_context = (
            "#### Full file (last resort): `pkg/mod.py` (2 lines)\n\n"
            "```python\n"
            "def f():\n"
            "    op()\n"
            "```\n"
        )
        block = _concern_block_v2(
            op_present="present", op_prov="op()",
            guard="absent", guard_prov="whole function", function_prov="def f():",
            default_state="not_applicable", effect="not_applicable", reentry="not_applicable",
        )
        result = _parse_concern_block_v2(block, code_context=code_context, patch="", vulnerability_text="")

        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"
        assert result["consequence"] == "UNRESOLVED"


class TestPositiveChainNonRegression:
    """The de-escalation touches ONLY the `absent` rule -- every
    positively-resolved atomic chain (`preceding_guard=present`,
    `guard_default_state`, `guard_effect`, `reentry_state_propagation`)
    must retain identical `reachable`/`blocked` behavior. Not a rewrite of
    the full rule table (already covered by `TestDeriveDefaultExecutionReachability`
    and `TestMechanismDiversityFixtures`) -- just a direct confirmation
    that guard-present chains still resolve to `reachable`/`blocked`."""

    def test_present_guard_condition_false_under_default_is_still_reachable(self):
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2

        block = _concern_block_v2(
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_false_under_default", default_state_prov="flag = False",
            effect="not_applicable", reentry="not_applicable",
        )
        result = _parse_concern_block_v2(
            block, code_context="flag = False\nif flag: raise Err()\nop()", patch="", vulnerability_text="",
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "reachable"
        assert result["consequence"] == "BLOCKING"

    def test_present_guard_prevents_operation_is_still_blocked(self):
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2

        block = _concern_block_v2(
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="prevents_operation", effect_prov="raise Err()",
            reentry="not_applicable", override="false",
        )
        result = _parse_concern_block_v2(
            block, code_context="flag: bool = True\nif flag: raise Err()\nop()", patch="", vulnerability_text="",
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "blocked"
        assert result["consequence"] == "NON_BLOCKING"


class TestHypothesizedOutcomeHasNoPolicyAuthority:
    """The most important regression test for the new field: three
    otherwise-identical concerns, differing ONLY in `Hypothesized
    outcome`, must produce IDENTICAL `default_execution_reachability`
    and `consequence`. The field is informational-only text, extracted
    independently of and never passed into
    `_derive_default_execution_reachability` or `_concern_consequence` --
    its presence must never force a weaker/stronger result, and its
    absence must never enable one either. In particular, this locks out
    the previously-considered (and explicitly rejected) design of forcing
    `consequence = UNRESOLVED` whenever the field is present."""

    def _block(self, hypothesized_outcome):
        return _concern_block_v2(
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="prevents_operation", effect_prov="raise Err()",
            reentry="not_applicable", override="false",
            hypothesized_outcome=hypothesized_outcome,
        )

    def _parse(self, hypothesized_outcome):
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2

        block = self._block(hypothesized_outcome)
        return _parse_concern_block_v2(
            block, code_context="flag: bool = True\nif flag: raise Err()\nop()", patch="", vulnerability_text="",
        )

    def test_none_text_and_absent_all_produce_identical_reachability_and_consequence(self):
        result_none = self._parse("none")
        result_text = self._parse(
            "This guard might not cover every call path, so the operation could still execute."
        )
        result_absent = self._parse(None)  # field omitted from the block entirely

        for result in (result_none, result_text, result_absent):
            assert result["malformed"] is False

        assert result_none["default_execution_reachability"] == result_text["default_execution_reachability"]
        assert result_text["default_execution_reachability"] == result_absent["default_execution_reachability"]
        assert result_none["default_execution_reachability"] == "blocked"

        assert result_none["consequence"] == result_text["consequence"]
        assert result_text["consequence"] == result_absent["consequence"]
        assert result_none["consequence"] == "NON_BLOCKING"

    def test_plausible_hypothesis_text_does_not_force_unresolved(self):
        """Direct lock against the rejected design: a present, plausible-
        sounding hypothesis text must NOT, by itself, force `consequence`
        to UNRESOLVED."""
        result = self._parse("This might still be exploitable through an untested code path.")
        assert result["default_execution_reachability"] == "blocked"
        assert result["consequence"] == "NON_BLOCKING"


class TestDescriptionHasNoPolicyAuthority:
    """`description` is free text, already never read by the derivation
    functions -- confirmed behaviorally here (not via source
    introspection): two otherwise-identical concerns differing only in
    `description` must produce identical `default_execution_reachability`
    and `consequence`."""

    def test_different_descriptions_produce_identical_reachability_and_consequence(self):
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2

        def parse_with_description(description):
            block = _concern_block_v2(
                description=description,
                op_present="present", op_prov="op()",
                guard="absent", guard_prov="whole function", function_prov="def f():",
                default_state="not_applicable", effect="not_applicable", reentry="not_applicable",
            )
            return _parse_concern_block_v2(block, code_context="def f():\n    op()", patch="", vulnerability_text="")

        result_a = parse_with_description("A totally unremarkable concern.")
        result_b = parse_with_description(
            "This is almost certainly exploitable and extremely dangerous."
        )

        assert result_a["default_execution_reachability"] == result_b["default_execution_reachability"]
        assert result_a["consequence"] == result_b["consequence"]


class TestHypothesizedOutcomeParsing:
    """Backward-compatible parsing/normalization for the new optional
    `Hypothesized outcome:` field: free text, the literal `none`, and the
    field being entirely absent from the block must all be handled
    without becoming a malformed-concern condition."""

    def _parse(self, hypothesized_outcome):
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2

        block = _concern_block_v2(
            op_present="present", op_prov="op()",
            guard="absent", guard_prov="whole function", function_prov="def f():",
            default_state="not_applicable", effect="not_applicable", reentry="not_applicable",
            hypothesized_outcome=hypothesized_outcome,
        )
        return _parse_concern_block_v2(block, code_context="def f():\n    op()", patch="", vulnerability_text="")

    def test_field_absent_from_block_normalizes_to_none(self):
        result = self._parse(None)
        assert result["malformed"] is False
        assert result["hypothesized_outcome"] is None

    def test_literal_none_value_normalizes_to_none(self):
        result = self._parse("none")
        assert result["malformed"] is False
        assert result["hypothesized_outcome"] is None

    def test_literal_none_is_case_insensitive(self):
        result = self._parse("None")
        assert result["hypothesized_outcome"] is None

    def test_free_text_is_preserved_verbatim_after_stripping(self):
        result = self._parse("The operation could still be reachable via an unverified path.")
        assert result["malformed"] is False
        assert result["hypothesized_outcome"] == "The operation could still be reachable via an unverified path."

    def test_malformed_concern_does_not_carry_hypothesized_outcome(self):
        """`_malformed_concern`'s shared shape already discards
        `description` too -- consistent, not a gap: this key simply does
        not exist on the malformed-concern shape at all."""
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2

        block = _concern_block_v2(role="bogus", hypothesized_outcome="some text")
        result = _parse_concern_block_v2(block, code_context="", patch="", vulnerability_text="")

        assert result["malformed"] is True
        assert "hypothesized_outcome" not in result


class TestV2OverrideScopeNormalization:
    """`_normalize_v2_override_scope` -- the v2-only authority-boundary
    correction: `Requires explicit non-default action`/`Contract
    addresses override` applicability is NORMALIZED against the already-
    DERIVED `default_execution_reachability`, never used to reject the
    whole concern the way v1's `_validate_and_resolve_override_scope`
    still does (see TestApplicabilityCanonicalSemantics, untouched,
    below -- v1's model directly asserts reachability itself, so a
    mismatch there remains genuine self-contradiction and stays
    rejected). v2's `reachability` is derived from five separate atomic
    facts the model never combines itself, so a mismatch here is only
    ever a wrong guess about an undisclosed formula -- normalized, not
    punished."""

    _BLOCKED_PREVENTS_CTX = "flag: bool = True\nif flag: raise Err()\nop()"
    _BLOCKED_NEUTRALIZES_PRESERVED_CTX = (
        "flag: bool = True\nif flag: sanitize()\nrecurse(flag)\nop()"
    )
    _ABSENT_CTX = "def f():\n    op()"

    def _parse(self, code_context, patch="", vulnerability_text="", **kwargs):
        from utilities.autopatcher.patch_challenger import _parse_concern_block_v2
        block = _concern_block_v2(**kwargs)
        return _parse_concern_block_v2(block, code_context=code_context, patch=patch, vulnerability_text=vulnerability_text)

    # --- 1. reachability != blocked + raw override populated ---

    def test_non_blocked_with_populated_override_normalizes_to_not_applicable(self):
        result = self._parse(
            self._ABSENT_CTX,
            op_present="present", op_prov="op()",
            guard="absent", guard_prov="whole function", function_prov="def f():",
            default_state="not_applicable", effect="not_applicable", reentry="not_applicable",
            override="true", override_prov="op()", scope="silent", scope_prov="whole document",
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"
        assert result["requires_explicit_non_default_action"] == "not_applicable"
        assert result["contract_addresses_override"] == "not_applicable"

    # --- 2. reachability == blocked + raw override = not_applicable ---

    def test_blocked_with_not_applicable_override_demotes_to_unresolved_not_malformed(self):
        result = self._parse(
            self._BLOCKED_PREVENTS_CTX,
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="prevents_operation", effect_prov="raise Err()",
            reentry="not_applicable", override="not_applicable",
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "blocked"
        assert result["requires_explicit_non_default_action"] == "unresolved"
        assert result["contract_addresses_override"] == "not_applicable"
        assert result["consequence"] == "UNRESOLVED"

    # --- 3. reachability == blocked + valid override=true: existing
    # scope-domain/provenance behavior preserved (still strict) ---

    def test_blocked_with_valid_override_true_preserves_scope_validation(self):
        result = self._parse(
            self._BLOCKED_PREVENTS_CTX,
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="prevents_operation", effect_prov="raise Err()",
            reentry="not_applicable",
            override="true", override_prov="op()", scope="silent", scope_prov="whole document",
        )
        assert result["malformed"] is False
        assert result["requires_explicit_non_default_action"] == "true"
        assert result["contract_addresses_override"] == "silent"
        assert result["consequence"] == "NON_BLOCKING"

    def test_blocked_with_genuinely_applicable_invalid_scope_still_fails_closed(self):
        """Once override is EFFECTIVELY true, scope's own domain check
        must remain exactly as strict as before -- this is a self-
        consistent gate (scope depends only on a value the model itself
        asserted, now confirmed true), not the derived-value mismatch
        this fix targets, so it is NOT weakened."""
        result = self._parse(
            self._BLOCKED_PREVENTS_CTX,
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="prevents_operation", effect_prov="raise Err()",
            reentry="not_applicable",
            override="true", override_prov="op()", scope="bogus",
        )
        assert result["malformed"] is True
        assert result["malformed_reason"] == "scope_applicability_violated"

    # --- 4. scope applicability keyed on EFFECTIVE override, not raw ---

    def test_scope_applicability_uses_effective_not_raw_override(self):
        """Raw override is `not_applicable` (demoted to `unresolved`,
        never `true`) -- scope must normalize to `not_applicable` too,
        and must NOT be validated against `explicitly_included`'s own
        provenance requirement (which the model never even attempted to
        satisfy here)."""
        result = self._parse(
            self._BLOCKED_PREVENTS_CTX,
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: raise Err()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="prevents_operation", effect_prov="raise Err()",
            reentry="not_applicable",
            override="not_applicable", scope="explicitly_included", scope_prov="none",
        )
        assert result["malformed"] is False
        assert result["requires_explicit_non_default_action"] == "unresolved"
        assert result["contract_addresses_override"] == "not_applicable"

    # --- 5. the exact real-world release regression ---

    def test_exact_release_regression_absent_guard_concern(self):
        result = self._parse(
            self._ABSENT_CTX,
            op_present="present", op_prov="op()",
            guard="absent", guard_prov="whole function", function_prov="def f():",
            default_state="not_applicable", effect="not_applicable", reentry="not_applicable",
            override="unresolved",
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "unresolved"
        assert result["requires_explicit_non_default_action"] == "not_applicable"
        assert result["contract_addresses_override"] == "not_applicable"
        assert result["consequence"] == "UNRESOLVED"

    # --- 6. the exact real-world positive-chain concern (neutralizes +
    # reentry preserved -> blocked), with a wrong override guess ---

    def test_exact_release_regression_neutralizes_preserved_concern(self):
        result = self._parse(
            self._BLOCKED_NEUTRALIZES_PRESERVED_CTX,
            op_present="present", op_prov="op()",
            guard="present", guard_prov="if flag: sanitize()",
            default_state="condition_true_under_default", default_state_prov="flag: bool = True",
            effect="neutralizes_operation", effect_prov="sanitize()",
            reentry="preserved", reentry_prov="recurse(flag)",
            override="not_applicable",
        )
        assert result["malformed"] is False
        assert result["default_execution_reachability"] == "blocked"
        assert result["requires_explicit_non_default_action"] == "unresolved"
        assert result["contract_addresses_override"] == "not_applicable"
        assert result["consequence"] == "UNRESOLVED"

    # --- 8/9. hypothesized_outcome / description remain non-authoritative
    # through this specific normalization path too ---

    def test_hypothesized_outcome_does_not_change_normalization_outcome(self):
        results = [
            self._parse(
                self._BLOCKED_NEUTRALIZES_PRESERVED_CTX,
                op_present="present", op_prov="op()",
                guard="present", guard_prov="if flag: sanitize()",
                default_state="condition_true_under_default", default_state_prov="flag: bool = True",
                effect="neutralizes_operation", effect_prov="sanitize()",
                reentry="preserved", reentry_prov="recurse(flag)",
                override="not_applicable", hypothesized_outcome=ho,
            )
            for ho in ("none", "This might still be exploitable somehow.", None)
        ]
        shapes = {(r["default_execution_reachability"], r["requires_explicit_non_default_action"], r["consequence"]) for r in results}
        assert len(shapes) == 1
        assert all(r["malformed"] is False for r in results)

    def test_description_does_not_change_normalization_outcome(self):
        results = [
            self._parse(
                self._BLOCKED_NEUTRALIZES_PRESERVED_CTX,
                op_present="present", op_prov="op()",
                guard="present", guard_prov="if flag: sanitize()",
                default_state="condition_true_under_default", default_state_prov="flag: bool = True",
                effect="neutralizes_operation", effect_prov="sanitize()",
                reentry="preserved", reentry_prov="recurse(flag)",
                override="not_applicable", description=desc,
            )
            for desc in ("a bland concern", "this is extremely dangerous and certainly exploitable")
        ]
        shapes = {(r["default_execution_reachability"], r["requires_explicit_non_default_action"], r["consequence"]) for r in results}
        assert len(shapes) == 1
        assert all(r["malformed"] is False for r in results)
