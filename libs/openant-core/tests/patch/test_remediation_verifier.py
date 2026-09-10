"""Tests for the Planner Claim Verifier (remediation_verifier.py)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from utilities.autopatcher.remediation_verifier import VerifierResult, verify_planner_claim
from utilities.autopatcher.llm_client import ModelUnavailableError


def _llm(response):
    m = mock.MagicMock()
    m.complete.return_value = response
    return m


def _call(llm, mode="REJECTED"):
    """Default mode is "REJECTED" (Mode A) -- every pre-existing test in
    this file is shaped around the counterexample-validity question this
    module started with, so defaulting here keeps every one of them
    unchanged in intent (see TestModeBAcceptanceMatrix/
    TestCrossModeFieldMalformation below for the mode="SELECTED" (Mode B)
    equivalents)."""
    return verify_planner_claim(
        "some vuln", "some invariant", "the broad mechanism",
        "the narrower mechanism, rejected because X",
        ["edit one"], "some verified evidence", llm, mode=mode,
    )


def _call_selected(llm):
    """Mode B ("SELECTED") equivalent of `_call` -- same marker shape, but
    framed as a claimed selection rather than a claimed rejection, matching
    what a real Mode B call is actually given."""
    return verify_planner_claim(
        "some vuln", "some invariant", "the authoritative mechanism",
        "the narrower mechanism, selected as the final mechanism",
        ["edit one"], "some verified evidence", llm, mode="SELECTED",
    )


# ---------------------------------------------------------------------------
# Well-formed responses
# ---------------------------------------------------------------------------

class TestWellFormedResponses:
    def test_supported(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "the claim holds up", "contradiction": None,
            "counterexample_reaches_unsafe_state": True,
        }))
        result = _call(llm)
        assert result == VerifierResult(
            status="SUPPORTED", reason="the claim holds up", contradiction=None,
            failure_kind=None, evaluated=True, counterexample_reaches_unsafe_state=True,
        )

    def test_contradicted_requires_and_carries_contradiction(self):
        llm = _llm(json.dumps({
            "status": "CONTRADICTED", "reason": "the trace ignores the guard",
            "contradiction": "the guard at step 2 would have prevented the traversal claimed in step 3",
        }))
        result = _call(llm)
        assert result.status == "CONTRADICTED"
        assert result.contradiction == "the guard at step 2 would have prevented the traversal claimed in step 3"
        assert result.failure_kind is None
        assert result.evaluated is True

    def test_unresolved(self):
        llm = _llm(json.dumps({
            "status": "UNRESOLVED", "reason": "the evidence does not cover this transition", "contradiction": None,
        }))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind is None
        assert result.evaluated is True

    def test_parses_fenced_json(self):
        llm = _llm("```json\n" + json.dumps({
            "status": "supported", "reason": "ok", "contradiction": None,
            "counterexample_reaches_unsafe_state": True,
        }) + "\n```")
        result = _call(llm)
        assert result.status == "SUPPORTED"  # status is uppercased

    def test_contradiction_ignored_for_non_contradicted_status(self):
        # A stray non-null contradiction on a SUPPORTED/UNRESOLVED response
        # is not something to trust or surface -- only CONTRADICTED carries one.
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "ok", "contradiction": "stray text",
            "counterexample_reaches_unsafe_state": True,
        }))
        result = _call(llm)
        assert result.status == "SUPPORTED"  # confirms this is a genuinely-accepted SUPPORTED, not a rejection
        assert result.contradiction is None


# ---------------------------------------------------------------------------
# Malformed / invalid responses -- all degrade to UNRESOLVED/infrastructure
# ---------------------------------------------------------------------------

class TestMalformedResponses:
    def test_not_json_at_all(self):
        llm = _llm("not json, just prose")
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_json_but_not_an_object(self):
        llm = _llm(json.dumps(["a", "list"]))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_missing_status(self):
        llm = _llm(json.dumps({"reason": "ok", "contradiction": None}))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_invalid_status_value(self):
        llm = _llm(json.dumps({"status": "MAYBE", "reason": "ok", "contradiction": None}))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_missing_reason(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "contradiction": None}))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_empty_reason(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "   ", "contradiction": None}))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_contradicted_with_no_contradiction_is_rejected(self):
        # This is the critical fail-closed case: CONTRADICTED without a
        # checkable contradiction is exactly the "unsupported assertion"
        # this mechanism exists to reject -- it must never be accepted as
        # a real CONTRADICTED result.
        llm = _llm(json.dumps({"status": "CONTRADICTED", "reason": "it's wrong", "contradiction": None}))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_contradicted_with_empty_string_contradiction_is_rejected(self):
        llm = _llm(json.dumps({"status": "CONTRADICTED", "reason": "it's wrong", "contradiction": "   "}))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_empty_response(self):
        llm = _llm("")
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_non_string_response(self):
        llm = _llm(mock.MagicMock())
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"


# ---------------------------------------------------------------------------
# Infrastructure failures -- ordinary exceptions and ModelUnavailableError
# ---------------------------------------------------------------------------

class TestInfrastructureFailures:
    def test_ordinary_exception_degrades_to_unresolved_infrastructure(self):
        llm = mock.MagicMock()
        llm.complete.side_effect = RuntimeError("boom")
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False
        assert "boom" in result.reason or "RuntimeError" in result.reason

    def test_never_fabricates_supported(self):
        llm = mock.MagicMock()
        llm.complete.side_effect = TimeoutError("timed out")
        result = _call(llm)
        assert result.status != "SUPPORTED"

    def test_never_fabricates_contradicted(self):
        llm = mock.MagicMock()
        llm.complete.side_effect = ConnectionError("network down")
        result = _call(llm)
        assert result.status != "CONTRADICTED"

    def test_model_unavailable_error_propagates(self):
        llm = mock.MagicMock()
        llm.complete.side_effect = ModelUnavailableError("model rejected")
        with pytest.raises(ModelUnavailableError):
            _call(llm)


# ---------------------------------------------------------------------------
# Prose-before-JSON extraction (real minimist regression)
#
# A real targeted minimist CVE-2021-44906 trace produced a semantically
# correct CONTRADICTED verdict, prefaced with several paragraphs of
# explanatory reasoning the prompt explicitly says not to include. Strict
# whole-response json.loads() rejected the entire response, discarding a
# genuine finding -- see remediation_verifier.py's _find_balanced_json_
# objects/_has_verifier_shape docstrings for the full incident writeup.
# ---------------------------------------------------------------------------

_MINIMIST_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "minimist-cve-2021-44906-verifier-response.txt"


class TestRealMinimistResponseFixture:
    """The exact captured response, byte-for-byte -- this test exists
    specifically because the real transcript exposed the bug; a synthetic
    approximation would not have caught it (the real prose's own bare `{}`
    snippets are what defeated a naive balanced-object scan)."""

    def test_real_response_recovers_the_genuine_contradicted_verdict(self):
        raw = _MINIMIST_FIXTURE_PATH.read_text(encoding="utf-8")
        llm = _llm(raw)
        result = _call(llm)

        assert result.status == "CONTRADICTED"
        assert result.failure_kind is None
        assert result.evaluated is True
        assert result.contradiction
        # The specific source-grounded point: traversal is redirected into
        # a fresh object before the terminal write -- not a generic
        # "something is wrong" contradiction.
        assert "fresh" in result.contradiction
        assert "Object.prototype" in result.contradiction
        assert "o[key] = {}" in result.contradiction or "reassigning o to a fresh" in result.contradiction


class TestGenericProseWithBraceNoise:
    """Repository-agnostic version of the same failure shape: explanatory
    prose containing several literal `{}` snippets (as inline code
    notation), followed by exactly one real verifier JSON object."""

    def test_recovers_the_one_real_candidate_among_brace_noise(self):
        raw = (
            "Let me walk through this claim step by step.\n\n"
            "At the first step, the code does `state = {}` to create a fresh object.\n"
            "At the second step, another branch also does `target[key] = {}` before continuing.\n"
            "A third, unrelated example elsewhere in the codebase uses `{}` as a default argument.\n\n"
            "Given all of that, here is my conclusion:\n\n"
            '{\n'
            '  "status": "CONTRADICTED",\n'
            '  "reason": "the claim ignores the reset at the second step",\n'
            '  "contradiction": "the second step resets the target to a fresh object before the write"\n'
            '}\n'
        )
        llm = _llm(raw)
        result = _call(llm)

        assert result.status == "CONTRADICTED"
        assert result.failure_kind is None
        assert result.evaluated is True
        assert result.contradiction == "the second step resets the target to a fresh object before the write"


class TestTrueAmbiguityStillFailsClosed:
    """Two separate, independently-valid verifier-shaped JSON objects --
    genuine ambiguity, not brace noise. No arbitrary selection: this must
    still resolve to UNRESOLVED/infrastructure, exactly like an unparseable
    response, never pick the first/last/any one of them."""

    def test_two_verifier_shaped_objects_reject_without_selecting_either(self):
        raw = (
            "Here is one analysis:\n"
            '{"status": "SUPPORTED", "reason": "looks fine", "contradiction": null}\n\n'
            "Actually, let me reconsider and give a second analysis instead:\n"
            '{"status": "CONTRADICTED", "reason": "actually wrong", "contradiction": "the guard fires here"}\n'
        )
        llm = _llm(raw)
        result = _call(llm)

        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False


class TestNoVerifierShapedCandidate:
    """Plain prose / brace noise only, with no object that even looks like
    a verifier response (no `status` key anywhere) -- must degrade exactly
    like today's existing malformed-response behavior, not attempt to
    invent a candidate from unrelated JSON-ish content."""

    def test_prose_with_only_unrelated_braces_still_rejects(self):
        raw = (
            "I looked at the code and here is a snippet: `config = {}`.\n"
            "Another example: `options = {\"debug\": true}` shows the pattern.\n"
            "No conclusion reached.\n"
        )
        llm = _llm(raw)
        result = _call(llm)

        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_plain_prose_with_no_json_at_all_still_rejects(self):
        raw = "I could not determine an answer here, no JSON follows."
        llm = _llm(raw)
        result = _call(llm)

        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False


class TestExtractedCandidateStillEnforcesStrictSchema:
    """Extraction only recovers a CANDIDATE dict -- it must never bypass
    _parse_response's own strict semantic checks. A CONTRADICTED claim
    recovered via extraction, but missing a concrete contradiction, must
    still fail exactly like a directly-parsed one would."""

    def test_recovered_contradicted_without_contradiction_still_fails(self):
        raw = (
            "Some reasoning here with a snippet like `x = {}` in it.\n\n"
            '{"status": "CONTRADICTED", "reason": "it is wrong"}\n'
        )
        llm = _llm(raw)
        result = _call(llm)

        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_recovered_object_with_invalid_status_still_fails(self):
        raw = (
            "Some reasoning here with a snippet like `x = {}` in it.\n\n"
            '{"status": "MAYBE", "reason": "unclear", "contradiction": null}\n'
        )
        llm = _llm(raw)
        result = _call(llm)

        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False


class TestExistingRawAndFencedBehaviorUnchanged:
    """The two fast paths this fix must leave byte-for-byte unchanged."""

    def test_raw_json_still_parses_directly(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "ok", "contradiction": None,
            "counterexample_reaches_unsafe_state": True,
        }))
        result = _call(llm)
        assert result.status == "SUPPORTED"
        assert result.evaluated is True

    def test_fenced_json_still_parses_directly(self):
        raw = "```json\n" + json.dumps({
            "status": "CONTRADICTED", "reason": "r", "contradiction": "c",
        }) + "\n```"
        llm = _llm(raw)
        result = _call(llm)
        assert result.status == "CONTRADICTED"
        assert result.contradiction == "c"
        assert result.evaluated is True


# ---------------------------------------------------------------------------
# Call shape
# ---------------------------------------------------------------------------

class TestCallShape:
    def test_stage_label_default(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "ok", "contradiction": None}))
        _call(llm)
        _args, kwargs = llm.complete.call_args
        assert kwargs.get("stage") == "remediation_plan_verification"

    def test_custom_stage_label(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "ok", "contradiction": None}))
        verify_planner_claim(
            "vuln", None, None, "narrower", [], "", llm, mode="REJECTED",
            stage="remediation_plan_reverification",
        )
        _args, kwargs = llm.complete.call_args
        assert kwargs.get("stage") == "remediation_plan_reverification"

    def test_user_message_contains_narrower_alternative(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "ok", "contradiction": None}))
        verify_planner_claim(
            "VULN_MARKER", "INVARIANT_MARKER", "MECHANISM_MARKER",
            "NARROWER_MARKER", ["EDIT_MARKER"], "EVIDENCE_MARKER", llm, mode="REJECTED",
        )
        _system, user_message = llm.complete.call_args[0]
        for marker in ("VULN_MARKER", "INVARIANT_MARKER", "MECHANISM_MARKER",
                       "NARROWER_MARKER", "EDIT_MARKER", "EVIDENCE_MARKER"):
            assert marker in user_message

    def test_optional_sections_omitted_when_absent(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "ok", "contradiction": None}))
        verify_planner_claim("vuln", None, None, "narrower", [], "", llm, mode="REJECTED")
        _system, user_message = llm.complete.call_args[0]
        assert "## Security invariant" not in user_message
        assert "## Authoritative remediation mechanism" not in user_message
        assert "## Required edits" not in user_message
        assert "## Verified Planner evidence" not in user_message

    def test_mode_is_a_required_argument(self):
        # No default -- a caller must always explicitly pick a mode; there
        # is no mode-blind fallback that could silently ask the wrong
        # question.
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "ok", "contradiction": None}))
        with pytest.raises(TypeError):
            verify_planner_claim("vuln", None, None, "narrower", [], "", llm)

    def test_user_message_states_rejected_mode_explicitly(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "ok", "contradiction": None}))
        _call(llm, mode="REJECTED")
        _system, user_message = llm.complete.call_args[0]
        assert "## Mode" in user_message
        assert "REJECTED" in user_message

    def test_user_message_states_selected_mode_explicitly(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "ok", "contradiction": None,
            "authoritative_remediation_matches_selected_alternative": True,
        }))
        _call_selected(llm)
        _system, user_message = llm.complete.call_args[0]
        assert "## Mode" in user_message
        assert "SELECTED" in user_message


def _PROMPT_TEXT() -> str:
    from utilities.autopatcher.remediation_verifier import _PROMPT_PATH
    return _PROMPT_PATH.read_text(encoding="utf-8")


def _PROMPT_TEXT_NORMALIZED() -> str:
    """Whitespace-collapsed, lowercased prompt text -- so a multi-word
    phrase check survives the source .md file's own line wrapping AND its
    markdown blockquote ("> ") prefixes (stripped per line before
    collapsing, so a phrase spanning a blockquote line break doesn't get a
    stray literal ">" token spliced into the middle of it)."""
    lines = (line.lstrip().removeprefix(">").lstrip() for line in _PROMPT_TEXT().lower().splitlines())
    return " ".join(" ".join(lines).split())


class TestVerifierPromptNarrowContract:
    def test_reserves_contradicted_for_checkable_contradiction(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "must never mean" in text
        assert "preference" in text
        assert "design disagreement" in text

    def test_requires_contradiction_field_when_contradicted(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "contradiction` is required" in text

    def test_disclaims_generic_challenger_and_patch_generation_responsibilities(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "do not propose, generate, or describe a patch" in text
        assert "do not design a new remediation mechanism" in text
        assert "do not evaluate code style, tests, or confidence" in text

    def test_schema_has_no_diff_or_code_field(self):
        text = _PROMPT_TEXT()
        schema_start = text.index("## Output schema")
        schema_block = text[schema_start:].lower()
        assert '"diff"' not in schema_block
        assert '"code"' not in schema_block
        assert '"patch"' not in schema_block


class TestVerifierPromptRepositoryAgnostic:
    def test_no_hardcoded_domain_terms(self):
        text = _PROMPT_TEXT().lower()
        for term in (
            "minimist", "cve-2021-44906", "constructor", "prototype", "__proto__",
            "javascript", "urllib3", "cookie", "header", "redirect", "python",
        ):
            assert term not in text, f"prompt hardcodes domain-specific term: {term!r}"


class TestVerifierPromptModeDispatch:
    """Decision-aware verification: the prompt now names two explicit,
    mutually-exclusive modes, dispatched by the orchestration (never
    inferred by the verifier from the Planner's own prose) -- see
    pipeline.py's `_dispatch_narrower_mode`."""

    def test_mode_a_no_longer_treats_selected_as_nothing_to_contradict(self):
        # The exact defect this change targets: under the OLD prompt,
        # "the narrower mechanism was selected" and "no rejection claim is
        # present" were both folded into the SAME "answer SUPPORTED"
        # branch inside what is now Mode A -- meaning a genuine SELECTED
        # claim could reach the counterexample-validity gate and get a
        # coincidental, not-actually-diagnostic pass/fail. Mode A's own
        # text must no longer mention "selected" as a reason to answer
        # SUPPORTED at all.
        text = _PROMPT_TEXT()
        mode_a_start = text.index("## Mode A")
        mode_b_start = text.index("## Mode B")
        mode_a_block = text[mode_a_start:mode_b_start].lower()
        assert "selected" not in mode_a_block

    def test_mode_b_asks_only_decision_coherence(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "do the authoritative remediation mechanism and required edits describe" in text
        assert "the same remediation that the narrower alternative claim says the" in text
        assert "planner selected" in text

    def test_mode_b_explicitly_disclaims_global_correctness_and_optimality(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "whether the remediation is globally correct" in text
        assert "whether it is the best or most complete possible mechanism" in text
        assert "whether some other, different mechanism would be preferable" in text
        assert "you to redesign, extend, or propose a different mechanism" in text
        assert "perform the later evidence-backed strategy step's job" in text

    def test_schema_declares_both_mode_specific_fields(self):
        text = _PROMPT_TEXT()
        schema_start = text.index("## Output schema")
        next_heading = text.index("\n## ", schema_start + 1)
        schema_block = text[schema_start:next_heading]
        assert "counterexample_reaches_unsafe_state" in schema_block
        assert "authoritative_remediation_matches_selected_alternative" in schema_block

    def test_schema_requires_populating_only_the_assigned_modes_field(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "populate only the one structured field that belongs to your assigned mode" in text
        assert "populating the wrong mode's field, or both, is treated as an invalid response" in text

    def test_mode_b_contradicted_requires_explicit_mismatch_commitment(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "you must also set" in text
        assert "authoritative_remediation_matches_selected_alternative` to `false`" in text

    def test_mode_b_contradicted_never_means_stylistic_wording_difference(self):
        # The exact structural-comparison trap this design must avoid --
        # the verifier itself, not deterministic code, is the one making
        # this judgment, and it is explicitly told wording differences
        # alone are not a contradiction.
        text = _PROMPT_TEXT_NORMALIZED()
        assert "two differently-worded descriptions of the same scope are" in text
        assert "not a contradiction" in text


class TestModeAPromptNoLongerAllowsSupportedNull:
    """Cleanup: Mode A is now ONLY ever invoked when the Planner's decision
    is REJECTED (see pipeline.py's `_dispatch_narrower_mode`), so the
    pre-mode-dispatch "no rejection claim -> SUPPORTED, nothing to
    contradict" language is stale -- it describes a case that can no longer
    legitimately occur, and it contradicted the already-validated parser
    gate, which has always required `counterexample_reaches_unsafe_state is
    True` for SUPPORTED (never accepting `null`). This aligns the prompt's
    stated contract with that gate; the gate itself is unchanged."""

    def _mode_a_block(self):
        text = _PROMPT_TEXT()
        mode_a_start = text.index("## Mode A")
        mode_b_start = text.index("## Mode B")
        return text[mode_a_start:mode_b_start]

    def test_no_rejection_claim_supported_branch_is_removed(self):
        # "nothing to contradict" now appears only inside the NEGATION
        # ("never answer SUPPORTED merely because there is nothing to
        # contradict") -- the old AFFIRMATIVE instruction to answer
        # SUPPORTED in that case must be gone.
        block = self._mode_a_block().lower()
        assert "check at all, answer supported" not in block
        assert "never answer supported merely because" in block

    def test_supported_requires_a_concrete_counterexample_reaching_unsafe_state(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "supported` has exactly one valid meaning" in text
        assert "you walked at least one concrete claimed counterexample through the narrower remediation and it actually reaches the stated unsafe state" in text

    def test_supported_always_requires_true_never_null(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "this is the only value that ever accompanies a genuine supported in this mode" in text
        assert "there is no valid supported with this field `null`" in text

    def test_no_prompt_text_claims_supported_null_is_valid_in_mode_a(self):
        block = self._mode_a_block().lower()
        # The old phrasing that explicitly permitted SUPPORTED with a null
        # commitment must be entirely gone from Mode A's own block.
        assert "either there is no rejection claim to check" not in block
        assert "to `true` only in this second case" not in block

    def test_unresolved_covers_missing_concrete_counterexample_without_manufacturing_support(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "no concrete claimed counterexample was actually" in text
        assert "never guessing supported merely because the rejection was never substantiated" in text

    def test_mode_a_states_it_is_only_invoked_after_an_explicit_rejection(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "you are only invoked in this mode when the planner has stated it rejected" in text


class TestModeBPromptUnchangedAfterModeACleanup:
    """Mode B's own contract must be byte-for-byte unaffected by the Mode A
    cleanup -- these mirror TestVerifierPromptModeDispatch's Mode B
    assertions as an explicit regression guard for this specific change."""

    def test_mode_b_still_asks_only_decision_coherence(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "do the authoritative remediation mechanism and required edits describe" in text
        assert "planner selected" in text

    def test_mode_b_still_requires_explicit_true_and_false_commitments(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "set `authoritative_remediation_matches_selected_alternative` to `true` only" in text
        assert "you must also set" in text
        assert "authoritative_remediation_matches_selected_alternative` to `false`" in text


# ---------------------------------------------------------------------------
# Verdict-integrity fix: counterexample_reaches_unsafe_state
#
# A second real minimist CVE-2021-44906 trace showed verifier v2 walk EVERY
# concrete Planner-claimed counterexample to an explicit "neutralized"
# conclusion in its own prose, then still emit status="SUPPORTED" by
# appealing to unproven "general reasoning" about some other, unspecified
# path. SUPPORTED must now be structurally backed by an explicit True
# commitment in counterexample_reaches_unsafe_state -- missing, null,
# false, and wrong-type all fail identically, and are NEVER reinterpreted
# as CONTRADICTED (that would fabricate a verdict the response never
# actually supplied).
# ---------------------------------------------------------------------------

_MINIMIST_V2_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "minimist-cve-2021-44906-verifier-v2-response.txt"


class TestRealMinimistV2FalseSupportedRegression:
    """The exact captured v2 transcript: ends with status="SUPPORTED" after
    explicitly walking every concrete counterexample to a "neutralized"
    conclusion. This exact response must never be accepted as SUPPORTED."""

    def test_real_v2_response_no_longer_accepted_as_supported(self):
        raw = _MINIMIST_V2_FIXTURE_PATH.read_text(encoding="utf-8")
        llm = _llm(raw)
        result = _call(llm)

        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False
        assert result.status != "SUPPORTED"
        assert result.status != "CONTRADICTED"  # never fabricate a different verdict either


class TestSupportedRequiresExplicitUnsafeStateCommitment:
    def test_well_formed_supported_with_true_is_accepted(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "the concrete path reaches the unsafe state",
            "contradiction": None, "counterexample_reaches_unsafe_state": True,
        }))
        result = _call(llm)
        assert result.status == "SUPPORTED"
        assert result.evaluated is True
        assert result.failure_kind is None
        assert result.counterexample_reaches_unsafe_state is True

    def test_supported_with_false_fails_closed(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "looked fine generally",
            "contradiction": None, "counterexample_reaches_unsafe_state": False,
        }))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_supported_with_null_fails_closed(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "looked fine generally",
            "contradiction": None, "counterexample_reaches_unsafe_state": None,
        }))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_supported_with_missing_field_fails_closed(self):
        # No counterexample_reaches_unsafe_state key at all -- the exact
        # shape a pre-fix (or otherwise non-compliant) response takes.
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "looked fine generally", "contradiction": None,
        }))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_supported_with_string_true_fails_closed(self):
        # Python bool is a subclass of int, and JSON has no separate
        # "stringly-typed boolean" -- this must still be rejected: only
        # the literal JSON `true` (-> Python `True`) counts.
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "looked fine generally",
            "contradiction": None, "counterexample_reaches_unsafe_state": "true",
        }))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_supported_with_integer_one_fails_closed(self):
        # The critical bool-vs-int case: json.loads maps JSON `1` to a
        # plain Python `int`, never a `bool`, so `isinstance(1, bool)` is
        # already False -- confirms the implementation does not accept a
        # truthy-but-wrong-type value.
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "looked fine generally",
            "contradiction": None, "counterexample_reaches_unsafe_state": 1,
        }))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_never_fabricates_contradicted_from_a_failed_supported_gate(self):
        # A rejected SUPPORTED must become UNRESOLVED, never CONTRADICTED --
        # CONTRADICTED asserts a specific, checkable finding the response
        # never actually supplied.
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "looked fine generally", "contradiction": None,
        }))
        result = _call(llm)
        assert result.status != "CONTRADICTED"
        assert result.status == "UNRESOLVED"


class TestContradictedFieldFlexibility:
    """CONTRADICTED's existing contract (non-empty `contradiction`) is
    unchanged -- it may carry `counterexample_reaches_unsafe_state` as
    either `False` (a concrete path was walked and neutralized) or `None`
    (rejection was invalid for some other reason, e.g. no genuine
    alternative existed to walk at all -- the future no-genuine-alternative
    path this field must not block)."""

    def test_contradicted_with_false_remains_valid(self):
        llm = _llm(json.dumps({
            "status": "CONTRADICTED", "reason": "the path is neutralized",
            "contradiction": "the guard fires and redirects before the write",
            "counterexample_reaches_unsafe_state": False,
        }))
        result = _call(llm)
        assert result.status == "CONTRADICTED"
        assert result.evaluated is True
        assert result.failure_kind is None
        assert result.contradiction == "the guard fires and redirects before the write"

    def test_contradicted_with_null_remains_valid(self):
        llm = _llm(json.dumps({
            "status": "CONTRADICTED", "reason": "no genuine alternative was ever proposed",
            "contradiction": "the alternative merely restates the vulnerable baseline",
            "counterexample_reaches_unsafe_state": None,
        }))
        result = _call(llm)
        assert result.status == "CONTRADICTED"
        assert result.evaluated is True
        assert result.failure_kind is None
        assert result.contradiction == "the alternative merely restates the vulnerable baseline"

    def test_contradicted_without_contradiction_still_fails_as_before(self):
        llm = _llm(json.dumps({
            "status": "CONTRADICTED", "reason": "it's wrong", "contradiction": None,
            "counterexample_reaches_unsafe_state": False,
        }))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False


class TestUnresolvedFieldUnaffected:
    def test_unresolved_with_null_field_unchanged(self):
        llm = _llm(json.dumps({
            "status": "UNRESOLVED", "reason": "cannot determine the path",
            "contradiction": None, "counterexample_reaches_unsafe_state": None,
        }))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.evaluated is True
        assert result.failure_kind is None

    def test_unresolved_with_missing_field_unchanged(self):
        llm = _llm(json.dumps({
            "status": "UNRESOLVED", "reason": "cannot determine the path", "contradiction": None,
        }))
        result = _call(llm)
        assert result.status == "UNRESOLVED"
        assert result.evaluated is True
        assert result.failure_kind is None


# ---------------------------------------------------------------------------
# Decision-aware verification: Mode B (SELECTED -- decision coherence)
#
# A real minimist Planner response explicitly said it selected a narrower,
# constructor-only guard in narrower_alternative_considered, while
# remediation_mechanism/required_edits still described a broader mechanism
# left over from before that decision. Deterministic free-text comparison
# of two independently-phrased descriptions is not a safe way to detect
# this (semantically identical phrasing can differ; differently-worded
# text is not proof of a mismatch either) -- so this exact question is
# delegated to the SAME bounded verifier call, in a second explicit mode,
# rather than compared by deterministic code.
# ---------------------------------------------------------------------------

class TestModeBAcceptanceMatrix:
    def test_supported_with_true_is_accepted(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "same scope, same points of action",
            "contradiction": None, "authoritative_remediation_matches_selected_alternative": True,
        }))
        result = _call_selected(llm)
        assert result.status == "SUPPORTED"
        assert result.evaluated is True
        assert result.failure_kind is None
        assert result.authoritative_remediation_matches_selected_alternative is True
        assert result.counterexample_reaches_unsafe_state is None

    def test_supported_with_false_fails_closed(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "looked fine generally",
            "contradiction": None, "authoritative_remediation_matches_selected_alternative": False,
        }))
        result = _call_selected(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_supported_with_null_fails_closed(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "looked fine generally",
            "contradiction": None, "authoritative_remediation_matches_selected_alternative": None,
        }))
        result = _call_selected(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_supported_with_missing_field_fails_closed(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "looked fine generally", "contradiction": None}))
        result = _call_selected(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_supported_with_wrong_type_fails_closed(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "looked fine generally", "contradiction": None,
            "authoritative_remediation_matches_selected_alternative": 1,
        }))
        result = _call_selected(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_contradicted_with_false_and_contradiction_is_accepted(self):
        llm = _llm(json.dumps({
            "status": "CONTRADICTED",
            "reason": "the authoritative fields cover more than the selected alternative",
            "contradiction": "selected alternative covers only key X; authoritative fields also block key Y",
            "authoritative_remediation_matches_selected_alternative": False,
        }))
        result = _call_selected(llm)
        assert result.status == "CONTRADICTED"
        assert result.evaluated is True
        assert result.failure_kind is None
        assert result.authoritative_remediation_matches_selected_alternative is False
        assert result.contradiction == "selected alternative covers only key X; authoritative fields also block key Y"

    def test_contradicted_with_true_is_malformed(self):
        # A CONTRADICTED verdict that does not also commit `false` has not
        # actually supplied the one concrete finding Mode B exists to
        # check for -- never accepted, never reinterpreted as SUPPORTED.
        llm = _llm(json.dumps({
            "status": "CONTRADICTED", "reason": "some mismatch",
            "contradiction": "some mismatch", "authoritative_remediation_matches_selected_alternative": True,
        }))
        result = _call_selected(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_contradicted_with_null_is_malformed(self):
        llm = _llm(json.dumps({
            "status": "CONTRADICTED", "reason": "some mismatch",
            "contradiction": "some mismatch", "authoritative_remediation_matches_selected_alternative": None,
        }))
        result = _call_selected(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_contradicted_without_contradiction_still_fails(self):
        llm = _llm(json.dumps({
            "status": "CONTRADICTED", "reason": "some mismatch", "contradiction": None,
            "authoritative_remediation_matches_selected_alternative": False,
        }))
        result = _call_selected(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"

    def test_unresolved_with_null_field_is_valid(self):
        llm = _llm(json.dumps({
            "status": "UNRESOLVED", "reason": "cannot tell if the scopes match",
            "contradiction": None, "authoritative_remediation_matches_selected_alternative": None,
        }))
        result = _call_selected(llm)
        assert result.status == "UNRESOLVED"
        assert result.evaluated is True
        assert result.failure_kind is None

    def test_never_fabricates_contradicted_from_a_failed_supported_gate(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "looked fine generally", "contradiction": None}))
        result = _call_selected(llm)
        assert result.status != "CONTRADICTED"
        assert result.status == "UNRESOLVED"


class TestCrossModeFieldMalformation:
    """A response that populates the OTHER mode's field answered the wrong
    question -- never silently accepted, never silently ignored."""

    def test_mode_a_response_populating_mode_b_field_is_malformed(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "ok", "contradiction": None,
            "counterexample_reaches_unsafe_state": True,
            "authoritative_remediation_matches_selected_alternative": True,
        }))
        result = _call(llm, mode="REJECTED")
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_mode_b_response_populating_mode_a_field_is_malformed(self):
        llm = _llm(json.dumps({
            "status": "SUPPORTED", "reason": "ok", "contradiction": None,
            "authoritative_remediation_matches_selected_alternative": True,
            "counterexample_reaches_unsafe_state": True,
        }))
        result = _call_selected(llm)
        assert result.status == "UNRESOLVED"
        assert result.failure_kind == "infrastructure"
        assert result.evaluated is False

    def test_invalid_mode_raises(self):
        llm = _llm(json.dumps({"status": "SUPPORTED", "reason": "ok", "contradiction": None}))
        with pytest.raises(ValueError):
            _call(llm, mode="NONE_IDENTIFIED")


class TestExactRunThreeEquivalentModeB:
    """The concrete design test the schema change was built for: the exact
    third-run pattern (Planner selects a narrower, constructor-only guard
    in `narrower_alternative_considered`, but `remediation_mechanism`/
    `required_edits` still describe a broader constructor-and-prototype
    mechanism) must be catchable -- WITHOUT any regex or text search over
    the Planner's own prose. This mocks the verifier's OWN structured
    judgment of that exact mismatch, per the task's explicit instruction
    not to rely on deterministic string comparison."""

    def test_the_exact_third_run_pattern_is_rejected_via_mode_b(self):
        llm = _llm(json.dumps({
            "status": "CONTRADICTED",
            "reason": (
                "the selected alternative covers only the constructor key; the "
                "authoritative fields also block the prototype key at both steps"
            ),
            "contradiction": (
                "narrower_alternative_considered selects a constructor-only guard; "
                "remediation_mechanism/required_edits block both constructor and "
                "prototype -- broader than what was selected"
            ),
            "authoritative_remediation_matches_selected_alternative": False,
        }))
        result = verify_planner_claim(
            "some vuln", "some invariant",
            "block constructor and prototype at both intermediate and final steps",
            "I select the narrow constructor-only guard as the mechanism",
            ["extend the constructor guard", "extend the prototype guard"],
            "some verified evidence", llm, mode="SELECTED",
        )
        assert result.status == "CONTRADICTED"
        assert result.evaluated is True
        assert result.authoritative_remediation_matches_selected_alternative is False
        assert result.contradiction


class TestVerdictIntegrityPromptWording:
    def test_forbids_general_reasoning_escape_hatch(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "never conclude" in text
        assert "still seems plausible" in text
        assert "is not evidence" in text

    def test_requires_walking_planners_own_concrete_counterexamples(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "planner's actual claimed concrete counterexample" in text
        assert "apply the proposed narrower remediation first" in text

    def test_does_not_require_proving_no_bypass_exists(self):
        text = _PROMPT_TEXT_NORMALIZED()
        assert "never asked to prove that no possible bypass exists" in text

    def test_schema_mentions_new_field(self):
        text = _PROMPT_TEXT()
        schema_start = text.index("## Output schema")
        schema_block = text[schema_start:]
        assert "counterexample_reaches_unsafe_state" in schema_block
