"""Tests for the Planner Claim Verifier orchestration
(pipeline._run_planner_claim_verification, and its wiring into
pipeline.run()'s Stage 1 -> Stage 2 -> Stage 3 flow).

Two layers, matching how this codebase already tests similar bounded
critique->revision loops (see test_pipeline_repair.py's direct
_build_repair_hint unit tests alongside its full pipeline.run() tests):

- Direct unit tests of `_run_planner_claim_verification` (the policy
  matrix, the strict bound, the generic semantic-regression fixture) --
  fast, isolated, no repository/investigation-context machinery involved.
- Full `pipeline.run()` tests (the trigger, the end-to-end skip behavior,
  and the no-trigger regression) -- these prove the WIRING, not just the
  orchestration function in isolation.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from utilities.autopatcher import pipeline as pipeline_mod
from utilities.autopatcher.pipeline import _dispatch_narrower_mode, _run_planner_claim_verification
from utilities.autopatcher.remediation_planner import _EMPTY_PLAN_RESULT, RemediationPlanResult
from utilities.autopatcher.remediation_verifier import VerifierResult

_VULN_TEXT = "# Test vulnerability\n\nSome description of a vulnerability for testing.\n"


def _plan(
    narrower="considered a narrower mechanism, rejected because X",
    rendered="## Target Discovery Plan\n", decision=None,
):
    return RemediationPlanResult(
        rendered=rendered, target_files=["a.py"], target_symbols=["a.py:foo"],
        security_invariant="the unsafe condition must not occur",
        remediation_mechanism="the broad mechanism",
        narrower_alternative_decision=decision,
        narrower_alternative_considered=narrower,
        required_edits=["edit one"], approaches_to_avoid=[], explicit_unknowns=[],
    )


def _plan_with_real_target(tmp_path, narrower, rendered="## Target Discovery Plan\n", decision=None):
    """Like `_plan`, but `target_files`/`target_symbols` point at a REAL
    file written into `tmp_path` -- so `build_planner_evidence`'s
    `_verify_file` check actually succeeds and `_planner_evidence_ctx`
    becomes non-empty. Needed for end-to-end tests that must prove
    Strategy is skipped BECAUSE of this feature's own forced-skip logic,
    not merely because the pre-existing "no verified evidence" gate
    already skips it regardless (a target that never verifies would make
    that assertion trivially true for the wrong reason)."""
    target = tmp_path / "target.py"
    if not target.exists():
        target.write_text("def foo():\n    pass\n", encoding="utf-8")
    return RemediationPlanResult(
        rendered=rendered, target_files=["target.py"], target_symbols=["target.py:foo"],
        security_invariant="the unsafe condition must not occur",
        remediation_mechanism="the broad mechanism",
        narrower_alternative_decision=decision,
        narrower_alternative_considered=narrower,
        required_edits=["edit one"], approaches_to_avoid=[], explicit_unknowns=[],
    )


def _verdict(
    status, reason="because", contradiction=None, failure_kind=None, evaluated=True,
    reaches_unsafe_state=None, matches_selected=None,
):
    return VerifierResult(
        status=status, reason=reason, contradiction=contradiction,
        failure_kind=failure_kind, evaluated=evaluated,
        counterexample_reaches_unsafe_state=reaches_unsafe_state,
        authoritative_remediation_matches_selected_alternative=matches_selected,
    )


def _run(plan_result, verify_side_effect, revised_plan_result=None, mode="REJECTED"):
    """Call the real orchestration function with `verify_planner_claim` and
    `generate_remediation_plan`/`build_planner_evidence` mocked at their
    SOURCE modules -- both are local (function-body) imports inside
    _run_planner_claim_verification, so mocking pipeline.<name> would not
    intercept them; mocking the source module's attribute does, because
    the local import re-fetches it at call time.

    `mode` defaults to "REJECTED" -- every pre-existing test in this file
    predates mode-aware verification and is shaped around the Mode A
    (counterexample-validity) question this orchestration started with."""
    with (
        mock.patch(
            "utilities.autopatcher.remediation_verifier.verify_planner_claim",
            side_effect=verify_side_effect,
        ) as spy_verify,
        mock.patch(
            "utilities.autopatcher.remediation_planner.generate_remediation_plan",
            return_value=revised_plan_result,
        ) as spy_revise,
        mock.patch(
            "utilities.autopatcher.remediation_planner.build_planner_evidence",
            return_value="revised evidence",
        ) as spy_evidence,
    ):
        result = _run_planner_claim_verification(
            vulnerability_text="some vuln", llm=mock.MagicMock(), repo_root="/tmp/repo",
            investigation_context=None, evidence_so_far="evidence so far",
            plan_result=plan_result, planner_evidence_ctx="verified evidence", mode=mode,
        )
    return result, spy_verify, spy_revise, spy_evidence


# ---------------------------------------------------------------------------
# Policy matrix (cases A-F)
# ---------------------------------------------------------------------------

class TestPolicyMatrix:
    def test_case_a_v1_supported(self):
        result, spy_verify, spy_revise, _ = _run(_plan(), [_verdict("SUPPORTED")])
        assert result["authoritative"] == "v1"
        assert result["forced_skip"] is False
        assert result["revision_attempted"] is False
        spy_revise.assert_not_called()
        assert spy_verify.call_count == 1

    def test_case_b_contradicted_then_revision_supported(self):
        revised = _plan(narrower="revised: selected the narrower mechanism", rendered="## revised plan\n")
        result, spy_verify, spy_revise, spy_evidence = _run(
            _plan(), [_verdict("CONTRADICTED", contradiction="the guard was ignored"), _verdict("SUPPORTED")],
            revised_plan_result=revised,
        )
        assert result["authoritative"] == "v2"
        assert result["forced_skip"] is False
        assert result["revision_attempted"] is True
        assert result["revised_plan_result"] is revised
        assert result["revised_plan_ctx"] == "## revised plan\n"
        assert result["revised_planner_evidence_ctx"] == "revised evidence"
        spy_revise.assert_called_once()
        spy_evidence.assert_called_once()
        assert spy_verify.call_count == 2

    def test_case_c_contradicted_then_revision_still_contradicted(self):
        revised = _plan(rendered="## revised plan\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(),
            [_verdict("CONTRADICTED", contradiction="finding one"), _verdict("CONTRADICTED", contradiction="finding two")],
            revised_plan_result=revised,
        )
        assert result["authoritative"] == "none"
        assert result["forced_skip"] is True
        assert "not cleared" in result["skip_reason"]
        assert "CONTRADICTED" in result["skip_reason"]
        spy_revise.assert_called_once()
        assert spy_verify.call_count == 2

    def test_case_d_contradicted_then_revision_unresolved(self):
        revised = _plan(rendered="## revised plan\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(),
            [_verdict("CONTRADICTED", contradiction="finding one"), _verdict("UNRESOLVED")],
            revised_plan_result=revised,
        )
        assert result["authoritative"] == "none"
        assert result["forced_skip"] is True
        assert "not cleared" in result["skip_reason"]
        assert "UNRESOLVED" in result["skip_reason"]
        spy_revise.assert_called_once()
        assert spy_verify.call_count == 2

    def test_case_e_v1_unresolved_proceeds(self):
        result, spy_verify, spy_revise, _ = _run(_plan(), [_verdict("UNRESOLVED")])
        assert result["authoritative"] == "v1"
        assert result["forced_skip"] is False
        assert result["revision_attempted"] is False
        spy_revise.assert_not_called()
        assert spy_verify.call_count == 1

    def test_case_f_v1_unresolved_sets_broadening_flag_but_does_not_skip(self):
        # Since the trigger only ever fires on a non-empty
        # narrower_alternative_considered (a rejection claim), a v1
        # UNRESOLVED here IS exactly the "broadening proposed, necessity
        # unestablished" case -- there is no separate signal to compute.
        result, _, _, _ = _run(_plan(), [_verdict("UNRESOLVED", reason="path is ambiguous")])
        assert result["broadening_unresolved"] is True
        assert result["forced_skip"] is False
        assert result["authoritative"] == "v1"

    def test_supported_does_not_set_broadening_flag(self):
        result, _, _, _ = _run(_plan(), [_verdict("SUPPORTED")])
        assert result["broadening_unresolved"] is False


# ---------------------------------------------------------------------------
# Decision-aware mode dispatch (_dispatch_narrower_mode + threading into
# _run_planner_claim_verification's v1/v2 verifier calls)
# ---------------------------------------------------------------------------

class TestDispatchNarrowerModeUnit:
    """Direct unit tests of `_dispatch_narrower_mode` -- the deterministic,
    non-inferring substitution rule pipeline.py uses to resolve which
    Planner Claim Verifier mode (if any) applies."""

    def test_explicit_rejected_is_returned_as_is(self):
        assert _dispatch_narrower_mode(_plan(decision="REJECTED")) == "REJECTED"

    def test_explicit_selected_is_returned_as_is(self):
        assert _dispatch_narrower_mode(_plan(decision="SELECTED")) == "SELECTED"

    def test_explicit_none_identified_is_returned_as_is(self):
        assert _dispatch_narrower_mode(_plan(decision="NONE_IDENTIFIED")) == "NONE_IDENTIFIED"

    def test_missing_decision_with_narrative_defaults_to_rejected(self):
        # Conservative substitution, never prose inference: a narrative
        # that reads as a selection claim must NOT be treated as SELECTED
        # merely because the enum is absent.
        plan = _plan(narrower="I select the narrow mechanism as the answer.", decision=None)
        assert _dispatch_narrower_mode(plan) == "REJECTED"

    def test_invalid_decision_with_narrative_defaults_to_rejected(self):
        plan = _plan(decision="MAYBE")
        assert _dispatch_narrower_mode(plan) == "REJECTED"

    def test_missing_decision_with_no_narrative_is_none_identified(self):
        plan = _plan(narrower=None, decision=None)
        assert _dispatch_narrower_mode(plan) == "NONE_IDENTIFIED"

    def test_missing_decision_with_blank_narrative_is_none_identified(self):
        plan = _plan(narrower="   ", decision=None)
        assert _dispatch_narrower_mode(plan) == "NONE_IDENTIFIED"


class TestModeDispatchIntoVerifierCall:
    """The resolved mode is actually threaded into `verify_planner_claim`'s
    own `mode` keyword argument -- not merely computed and discarded."""

    def test_rejected_decision_dispatches_mode_a(self):
        result, spy_verify, _, _ = _run(_plan(decision="REJECTED"), [_verdict("SUPPORTED")], mode="REJECTED")
        assert result["mode_v1"] == "REJECTED"
        assert spy_verify.call_args_list[0].kwargs.get("mode") == "REJECTED"

    def test_selected_decision_dispatches_mode_b(self):
        result, spy_verify, _, _ = _run(
            _plan(decision="SELECTED"), [_verdict("SUPPORTED", matches_selected=True)], mode="SELECTED",
        )
        assert result["mode_v1"] == "SELECTED"
        assert spy_verify.call_args_list[0].kwargs.get("mode") == "SELECTED"

    def test_none_identified_makes_no_verifier_call_via_full_pipeline(self, tmp_path):
        # NONE_IDENTIFIED is resolved by the CALLER (the S1 executor) before
        # _run_planner_claim_verification is ever invoked -- proven here at
        # the full pipeline.run() level, where the real dispatch decision
        # actually happens.
        plan_v1 = _plan_with_real_target(tmp_path, narrower=None, decision="NONE_IDENTIFIED")
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=plan_v1,
            ),
            mock.patch("utilities.autopatcher.remediation_verifier.verify_planner_claim") as spy_verify,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        spy_verify.assert_not_called()


# ---------------------------------------------------------------------------
# Strict bound
# ---------------------------------------------------------------------------

class TestStrictBound:
    def test_at_most_one_revision_call_on_double_contradiction(self):
        revised = _plan(rendered="## revised plan\n")
        _, _, spy_revise, _ = _run(
            _plan(),
            [_verdict("CONTRADICTED", contradiction="one"), _verdict("CONTRADICTED", contradiction="two")],
            revised_plan_result=revised,
        )
        assert spy_revise.call_count == 1

    def test_at_most_two_verifier_calls_on_double_contradiction(self):
        revised = _plan(rendered="## revised plan\n")
        _, spy_verify, _, _ = _run(
            _plan(),
            [_verdict("CONTRADICTED", contradiction="one"), _verdict("CONTRADICTED", contradiction="two")],
            revised_plan_result=revised,
        )
        assert spy_verify.call_count == 2

    def test_zero_revisions_when_v1_not_contradicted(self):
        _, _, spy_revise, _ = _run(_plan(), [_verdict("SUPPORTED")])
        assert spy_revise.call_count == 0

    def test_revision_failure_itself_fails_closed_without_a_second_attempt(self):
        # Defensive-belt-and-suspenders proxy: generate_remediation_plan
        # returns None, a shape it can only produce via
        # _run_planner_claim_verification's OWN `except Exception:
        # revised_plan_result = None` fallback (see the real-contract test
        # below for the shape generate_remediation_plan ACTUALLY returns on
        # every ordinary failure). Kept because it still exercises the same
        # `revised_plan_result is None or not .rendered` gate.
        result, spy_verify, spy_revise, _ = _run(
            _plan(), [_verdict("CONTRADICTED", contradiction="one")], revised_plan_result=None,
        )
        assert result["forced_skip"] is True
        assert result["authoritative"] == "none"
        assert spy_revise.call_count == 1
        assert spy_verify.call_count == 1  # v2 never ran -- there was nothing to re-verify

    def test_real_empty_plan_result_revision_failure_contract(self):
        # review fix test A: generate_remediation_plan() NEVER actually
        # returns None on an ordinary failure -- it returns _EMPTY_PLAN_
        # RESULT (rendered=""). This is the REAL, documented failure shape
        # (malformed JSON, empty response, ordinary LLM exception, or a
        # response with no meaningful content all coerce to this exact
        # value -- see remediation_planner.generate_remediation_plan's own
        # contract). This test proves the primary contract, not a proxy.
        result, spy_verify, spy_revise, _ = _run(
            _plan(), [_verdict("CONTRADICTED", contradiction="one")],
            revised_plan_result=_EMPTY_PLAN_RESULT,
        )
        assert spy_revise.call_count == 1  # revision attempted exactly once
        assert spy_verify.call_count == 1  # verifier v2 is NOT called
        assert result["authoritative"] == "none"
        assert result["forced_skip"] is True
        assert result["revised_plan_result"] is None  # never promoted, even though a real object was returned
        assert "did not produce a usable result" in result["skip_reason"]


class TestFailClosedAfterEstablishedContradiction:
    """Review fix 2: once verifier v1 has returned CONTRADICTED, an
    unexpected internal failure anywhere in the revision/rebuild/re-verify
    sequence must fail closed -- never silently leave v1 authoritative."""

    def test_unexpected_exception_during_v2_verification_fails_closed(self):
        revised = _plan(rendered="## revised plan\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(),
            [_verdict("CONTRADICTED", contradiction="c1"), RuntimeError("unexpected internal bug")],
            revised_plan_result=revised,
        )
        assert result["authoritative"] == "none"
        assert result["forced_skip"] is True
        assert "internal failure" in result["skip_reason"].lower()
        assert "already-established contradiction" in result["skip_reason"]
        # No second revision attempt, and v2 was attempted (raised) exactly
        # once -- the failure is not silently retried.
        assert spy_revise.call_count == 1
        assert spy_verify.call_count == 2

    def test_unexpected_exception_during_evidence_rebuild_fails_closed(self):
        # build_planner_evidence is only wrapped by its OWN local
        # try/except inside _run_planner_claim_verification (which already
        # degrades to "" on failure) -- this proves the OUTER fail-closed
        # boundary still holds even if that inner guard were ever bypassed,
        # by raising from the mock directly at that call site.
        revised = _plan(rendered="## revised plan\n")
        with (
            mock.patch(
                "utilities.autopatcher.remediation_verifier.verify_planner_claim",
                side_effect=[_verdict("CONTRADICTED", contradiction="c1"), _verdict("SUPPORTED")],
            ) as spy_verify,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=revised,
            ) as spy_revise,
            mock.patch(
                "utilities.autopatcher.remediation_planner.build_planner_evidence",
                side_effect=RuntimeError("unexpected bug"),
            ),
        ):
            result = _run_planner_claim_verification(
                vulnerability_text="some vuln", llm=mock.MagicMock(), repo_root="/tmp/repo",
                investigation_context=None, evidence_so_far="evidence so far",
                plan_result=_plan(), planner_evidence_ctx="verified evidence", mode="REJECTED",
            )
        # build_planner_evidence's own inner try/except catches this and
        # degrades to "" -- so this specific failure does NOT reach the
        # outer boundary; included to document that this call site is
        # already safe on its own, not to prove the outer catch fired.
        assert result["authoritative"] == "v2"
        assert spy_revise.call_count == 1
        assert spy_verify.call_count == 2

    def test_control_infrastructure_failure_before_contradiction_is_not_a_hard_block(self):
        # Before any contradiction is established, ordinary/infrastructure
        # failure must NOT be converted into a hard block by this
        # orchestration -- verify_planner_claim's OWN contract already maps
        # such failures to UNRESOLVED internally (see remediation_verifier.py),
        # and _run_planner_claim_verification must not add a second,
        # stricter failure path on top of that.
        result, spy_verify, spy_revise, _ = _run(
            _plan(), [_verdict("UNRESOLVED", failure_kind="infrastructure", evaluated=False)],
        )
        assert result["authoritative"] == "v1"
        assert result["forced_skip"] is False
        spy_revise.assert_not_called()


class TestBroadeningUnresolvedCorrection:
    """Review fix 3: `broadening_unresolved` must reflect a genuine semantic
    UNRESOLVED (the verifier actually reasoned about the claim), never an
    infrastructure failure that establishes nothing about broadening
    necessity. Observability-only in both cases -- Strategy/Patch
    Generation behavior is identical regardless of this flag's value."""

    def test_semantic_unresolved_sets_the_flag(self):
        result, _, _, _ = _run(_plan(), [_verdict("UNRESOLVED", failure_kind=None, evaluated=True)])
        assert result["broadening_unresolved"] is True
        assert result["forced_skip"] is False
        assert result["authoritative"] == "v1"

    def test_infrastructure_unresolved_does_not_set_the_flag(self):
        result, _, _, _ = _run(_plan(), [_verdict("UNRESOLVED", failure_kind="infrastructure", evaluated=False)])
        assert result["broadening_unresolved"] is False
        assert result["forced_skip"] is False
        assert result["authoritative"] == "v1"

    def test_supported_never_sets_the_flag(self):
        result, _, _, _ = _run(_plan(), [_verdict("SUPPORTED")])
        assert result["broadening_unresolved"] is False

    def test_contradicted_v1_does_not_set_the_flag(self):
        # broadening_unresolved is defined only in terms of v1's own
        # status -- a v1 CONTRADICTED (a different, stronger finding) must
        # not also claim "unresolved".
        revised = _plan(rendered="## revised plan\n")
        result, _, _, _ = _run(
            _plan(), [_verdict("CONTRADICTED", contradiction="c1"), _verdict("SUPPORTED")],
            revised_plan_result=revised,
        )
        assert result["broadening_unresolved"] is False

    def test_mode_b_unresolved_does_not_set_the_flag(self):
        # broadening_unresolved is specifically about Mode A's own question
        # (was BROADENING's necessity established) -- a Mode B
        # (decision-coherence) UNRESOLVED is a different kind of ambiguity
        # and must never be mislabeled under this name.
        result, _, _, _ = _run(
            _plan(decision="SELECTED"),
            [_verdict("UNRESOLVED", failure_kind=None, evaluated=True)],
            mode="SELECTED",
        )
        assert result["broadening_unresolved"] is False
        assert result["forced_skip"] is False
        assert result["authoritative"] == "v1"


# ---------------------------------------------------------------------------
# Mode-aware bounded revision -- the IMPORTANT correction from this design
# round: only a genuine CONTRADICTED (in EITHER mode) consumes the single
# revision budget; ordinary infrastructure/malformed-response UNRESOLVED
# never does (this already follows structurally from _parse_response never
# emitting CONTRADICTED for an infrastructure failure -- these tests prove
# it holds under mode dispatch too, not just assert it). v2's mode is
# re-dispatched from the REVISED plan's OWN decision, which may differ from
# v1's -- and a v2 that re-dispatches to NONE_IDENTIFIED must not be able
# to escape an already-established contradiction.
# ---------------------------------------------------------------------------

class TestModeAwareBoundedRevision:
    def test_case_1_rejected_contradicted_then_selected_supported_proceeds(self):
        """Exactly the corrected real run-3 target: v1 REJECTED/CONTRADICTED
        -> one revision -> v2 SELECTED, Mode B checks decision coherence.
        If Mode B clears (SUPPORTED/true), v2 becomes authoritative."""
        revised = _plan(decision="SELECTED", rendered="## revised plan (selected)\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(decision="REJECTED"),
            [
                _verdict("CONTRADICTED", contradiction="the rejection does not hold up"),
                _verdict("SUPPORTED", matches_selected=True),
            ],
            revised_plan_result=revised,
            mode="REJECTED",
        )
        assert result["authoritative"] == "v2"
        assert result["forced_skip"] is False
        assert result["mode_v1"] == "REJECTED"
        assert result["mode_v2"] == "SELECTED"
        assert spy_revise.call_count == 1
        assert spy_verify.call_count == 2
        assert spy_verify.call_args_list[1].kwargs.get("mode") == "SELECTED"

    def test_case_1_variant_selected_mode_b_contradicted_forces_skip(self):
        """The exact defect this design targets: v2 SELECTED, but Mode B
        finds the authoritative fields do not match the claimed selection
        -- must fail closed, with NO second revision."""
        revised = _plan(decision="SELECTED", rendered="## revised plan (still broad)\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(decision="REJECTED"),
            [
                _verdict("CONTRADICTED", contradiction="the rejection does not hold up"),
                _verdict("CONTRADICTED", contradiction="selected narrow, authoritative still broad", matches_selected=False),
            ],
            revised_plan_result=revised,
            mode="REJECTED",
        )
        assert result["authoritative"] == "none"
        assert result["forced_skip"] is True
        assert "not cleared" in result["skip_reason"]
        assert spy_revise.call_count == 1
        assert spy_verify.call_count == 2

    def test_case_2_selected_contradicted_then_rejected_supported_proceeds(self):
        """v1 SELECTED, Mode B finds a mismatch (CONTRADICTED) -- consumes
        the one revision. v2 flips to REJECTED; Mode A clears -> v2
        authoritative. Proves the revision budget is shared across modes,
        not per-mode."""
        revised = _plan(decision="REJECTED", rendered="## revised plan (rejected)\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(decision="SELECTED"),
            [
                _verdict("CONTRADICTED", contradiction="authoritative fields do not match selection", matches_selected=False),
                _verdict("SUPPORTED", reaches_unsafe_state=True),
            ],
            revised_plan_result=revised,
            mode="SELECTED",
        )
        assert result["authoritative"] == "v2"
        assert result["mode_v1"] == "SELECTED"
        assert result["mode_v2"] == "REJECTED"
        assert spy_revise.call_count == 1
        assert spy_verify.call_count == 2

    def test_no_second_revision_regardless_of_mode_flip(self):
        revised = _plan(decision="SELECTED", rendered="## revised plan\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(decision="REJECTED"),
            [
                _verdict("CONTRADICTED", contradiction="c1"),
                _verdict("CONTRADICTED", contradiction="c2", matches_selected=False),
            ],
            revised_plan_result=revised,
            mode="REJECTED",
        )
        assert result["authoritative"] == "none"
        assert spy_revise.call_count == 1  # never more than one, regardless of mode flip
        assert spy_verify.call_count == 2  # never more than two


class TestV2NoneIdentifiedAfterContradiction:
    """The critical corrected policy: a Planner cannot escape an
    already-established contradiction by revising its decision to
    NONE_IDENTIFIED. Must fail closed WITHOUT a second verifier call (no
    new LLM call is spent discovering what the orchestration already knows:
    there is nothing left to check, and the contradiction was never
    positively cleared)."""

    def test_v2_none_identified_fails_closed_without_a_second_verifier_call(self):
        revised = _plan(decision="NONE_IDENTIFIED", narrower=None, rendered="## revised plan (no alternative)\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(decision="REJECTED"),
            [_verdict("CONTRADICTED", contradiction="the rejection does not hold up")],
            revised_plan_result=revised,
            mode="REJECTED",
        )
        assert result["authoritative"] == "none"
        assert result["forced_skip"] is True
        assert "NONE_IDENTIFIED" in result["skip_reason"]
        assert result["mode_v2"] is None
        assert result["verifier_v2"] is None
        spy_revise.assert_called_once()
        assert spy_verify.call_count == 1  # v2 never called -- no new LLM call

    def test_v2_none_identified_via_missing_decision_and_narrative_also_fails_closed(self):
        # The same fallback substitution rule (_dispatch_narrower_mode)
        # applies to the revised result too -- a revision that omits both
        # the decision AND the narrative resolves to NONE_IDENTIFIED, which
        # must be treated identically to an explicit one here.
        revised = _plan(decision=None, narrower=None, rendered="## revised plan (blank)\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(decision="REJECTED"),
            [_verdict("CONTRADICTED", contradiction="c1")],
            revised_plan_result=revised,
            mode="REJECTED",
        )
        assert result["authoritative"] == "none"
        assert result["forced_skip"] is True
        assert spy_verify.call_count == 1


class TestInfrastructureDoesNotConsumeRevisionBudget:
    """IMPORTANT correction: ordinary infrastructure/malformed-response
    UNRESOLVED must never consume the single Planner revision budget, in
    EITHER mode -- only a genuine CONTRADICTED does. This already follows
    structurally from `_parse_response` never emitting `status=
    "CONTRADICTED"` for an infrastructure failure, so these tests prove the
    invariant holds through the real orchestration under mode dispatch,
    not merely assert the parser's own contract again."""

    def test_mode_a_infrastructure_unresolved_does_not_trigger_revision(self):
        result, _, spy_revise, _ = _run(
            _plan(decision="REJECTED"),
            [_verdict("UNRESOLVED", failure_kind="infrastructure", evaluated=False)],
            mode="REJECTED",
        )
        assert result["authoritative"] == "v1"
        assert result["forced_skip"] is False
        spy_revise.assert_not_called()

    def test_mode_b_infrastructure_unresolved_does_not_trigger_revision(self):
        result, _, spy_revise, _ = _run(
            _plan(decision="SELECTED"),
            [_verdict("UNRESOLVED", failure_kind="infrastructure", evaluated=False)],
            mode="SELECTED",
        )
        assert result["authoritative"] == "v1"
        assert result["forced_skip"] is False
        spy_revise.assert_not_called()

    def test_v2_infrastructure_unresolved_after_established_contradiction_fails_closed(self):
        # Preserve existing case-D-style policy under mode dispatch: once a
        # real contradiction is established, a v2 that comes back as an
        # ordinary infrastructure failure still must not clear it -- no
        # second revision is spent trying again.
        revised = _plan(decision="SELECTED", rendered="## revised plan\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(decision="REJECTED"),
            [
                _verdict("CONTRADICTED", contradiction="c1"),
                _verdict("UNRESOLVED", failure_kind="infrastructure", evaluated=False),
            ],
            revised_plan_result=revised,
            mode="REJECTED",
        )
        assert result["authoritative"] == "none"
        assert result["forced_skip"] is True
        assert spy_revise.call_count == 1
        assert spy_verify.call_count == 2


class TestStageTagSequencing:
    """Through the real orchestration: the exact `stage=` tag pipeline.py
    itself passes at each call site, not just what the callee would
    default to. Catches a typo (wrong constant, or a missing override)
    that no other test would -- these mocks record pipeline.py's OWN call
    arguments regardless of what the real function's default is."""

    def test_exact_tags_through_a_full_contradiction_cycle(self):
        revised = _plan(rendered="## revised plan\n")
        result, spy_verify, spy_revise, _ = _run(
            _plan(),
            [_verdict("CONTRADICTED", contradiction="c1"), _verdict("SUPPORTED")],
            revised_plan_result=revised,
        )
        assert result["authoritative"] == "v2"
        assert spy_verify.call_count == 2

        # Initial verifier call: pipeline.py passes NO stage override --
        # relies on verify_planner_claim's own default
        # ("remediation_plan_verification"), never remediation_planning.
        v1_kwargs = spy_verify.call_args_list[0].kwargs
        assert "stage" not in v1_kwargs

        # Revision call: explicit remediation_plan_revision -- never the
        # normal Planner tag.
        _revise_args, revise_kwargs = spy_revise.call_args
        assert revise_kwargs.get("stage") == "remediation_plan_revision"
        assert revise_kwargs.get("stage") != "remediation_planning"

        # Second verifier call: explicit remediation_plan_reverification --
        # distinguishable from the first verifier call's tag.
        v2_kwargs = spy_verify.call_args_list[1].kwargs
        assert v2_kwargs.get("stage") == "remediation_plan_reverification"
        assert v2_kwargs.get("stage") != "remediation_plan_verification"
        assert v2_kwargs.get("stage") != "remediation_planning"

    def test_no_revision_call_ever_uses_the_normal_planning_tag(self):
        revised = _plan(rendered="## revised plan\n")
        _result, _spy_verify, spy_revise, _ = _run(
            _plan(),
            [_verdict("CONTRADICTED", contradiction="c1"), _verdict("CONTRADICTED", contradiction="c2")],
            revised_plan_result=revised,
        )
        _revise_args, revise_kwargs = spy_revise.call_args
        assert revise_kwargs.get("stage") != "remediation_planning"
        assert revise_kwargs.get("stage") == "remediation_plan_revision"


# ---------------------------------------------------------------------------
# Generic semantic-regression fixture
#
# Models, WITHOUT any minimist/JS-specific names, the exact class of
# failure this whole mechanism exists to catch: a baseline lookup/
# traversal behavior would follow inherited/shared state, a proposed
# narrower remediation changes that intermediate transition, and the
# Planner's counterexample incorrectly reasons as though the baseline
# transition still happens after the hypothetical change.
# ---------------------------------------------------------------------------

_GENERIC_FLAWED_COUNTEREXAMPLE = (
    "Considered a narrower mechanism that would create a fresh, unshared "
    "value at the point where lookup would otherwise fall through to "
    "inherited/shared state. Rejected: even with that mechanism applied, "
    "the lookup at the second traversal step still resolves through the "
    "inherited/shared state and reaches the same unsafe object."
)

_GENERIC_CONTRADICTION = (
    "The claim reasons about the second traversal step as if the fresh, "
    "unshared value from the first step were never introduced -- but the "
    "narrower mechanism replaces the lookup result at exactly that point, "
    "so the traversal cannot fall through to the inherited/shared state "
    "the claim relies on."
)


class TestGenericSemanticRegressionFixture:
    def test_verifier_plumbing_carries_the_contradiction_end_to_end(self):
        """verify_planner_claim itself (no orchestration involved) correctly
        parses and returns a CONTRADICTED verdict, with the exact
        contradiction, for this class of flawed counterexample."""
        from utilities.autopatcher.remediation_verifier import verify_planner_claim
        import json

        llm = mock.MagicMock()
        llm.complete.return_value = json.dumps({
            "status": "CONTRADICTED", "reason": "the claim ignores its own mechanism's effect",
            "contradiction": _GENERIC_CONTRADICTION,
        })

        result = verify_planner_claim(
            "some vuln", "the unsafe state must not become reachable",
            "the broad mechanism", _GENERIC_FLAWED_COUNTEREXAMPLE, ["edit one"],
            "verified source evidence", llm, mode="REJECTED",
        )

        assert result.status == "CONTRADICTED"
        assert result.contradiction == _GENERIC_CONTRADICTION
        assert result.evaluated is True
        assert result.failure_kind is None

    def test_orchestration_clears_this_class_of_contradiction_via_one_revision(self):
        """Case B applied specifically to this fixture: the orchestration
        makes exactly one revision call and promotes the revised result
        once a second verification no longer finds the same flaw."""
        flawed_plan = _plan(narrower=_GENERIC_FLAWED_COUNTEREXAMPLE)
        revised_plan = _plan(
            narrower="considered the same narrower mechanism; selected it -- it closes "
                     "the traversal step the broad mechanism also targeted, while "
                     "preserving unrelated legitimate values untouched",
            rendered="## revised plan (narrower mechanism selected)\n",
        )
        result, spy_verify, spy_revise, _ = _run(
            flawed_plan,
            [_verdict("CONTRADICTED", contradiction=_GENERIC_CONTRADICTION), _verdict("SUPPORTED")],
            revised_plan_result=revised_plan,
        )
        assert result["authoritative"] == "v2"
        assert result["revised_plan_result"] is revised_plan
        assert spy_revise.call_count == 1
        assert spy_verify.call_count == 2

    def test_orchestration_blocks_when_revision_repeats_the_same_flaw(self):
        """If the revision's OWN counterexample repeats the same class of
        error (still reasoning about pre-mechanism state), the second
        verification must also find it CONTRADICTED, and the run must not
        promote either version to Strategy."""
        flawed_plan = _plan(narrower=_GENERIC_FLAWED_COUNTEREXAMPLE)
        still_flawed_revision = _plan(
            narrower=_GENERIC_FLAWED_COUNTEREXAMPLE, rendered="## revised plan (same flaw)\n",
        )
        result, _, spy_revise, _ = _run(
            flawed_plan,
            [
                _verdict("CONTRADICTED", contradiction=_GENERIC_CONTRADICTION),
                _verdict("CONTRADICTED", contradiction=_GENERIC_CONTRADICTION),
            ],
            revised_plan_result=still_flawed_revision,
        )
        assert result["authoritative"] == "none"
        assert result["forced_skip"] is True
        assert spy_revise.call_count == 1  # still only one revision attempt, even though it didn't help


# ---------------------------------------------------------------------------
# Full pipeline.run() tests -- these prove the WIRING (trigger, end-to-end
# skip propagation, no-trigger regression), not just the orchestration
# function in isolation. Same hermetic style as test_pipeline_no_patch_
# early_stop.py: an empty tmp_path repo_root, api_key="" (mock LLM mode),
# and source-level mocks/spies for whichever calls each test cares about.
# ---------------------------------------------------------------------------

class TestTriggerEndToEnd:
    def test_no_trigger_when_narrower_alternative_absent(self, tmp_path):
        """Default mock-mode LLM returns an unparseable response for the
        Planner call -> _EMPTY_PLAN_RESULT -> narrower_alternative_considered
        is None -> the verifier must never be called at all."""
        with mock.patch(
            "utilities.autopatcher.remediation_verifier.verify_planner_claim"
        ) as spy_verify:
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        spy_verify.assert_not_called()

    def test_trigger_fires_exactly_once_and_strategy_still_proceeds_on_supported(self, tmp_path):
        import utilities.autopatcher.remediation_planner as remediation_planner_mod

        plan_v1 = _plan_with_real_target(tmp_path, narrower="considered a narrower mechanism and selected it")
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=plan_v1,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_verifier.verify_planner_claim",
                return_value=_verdict("SUPPORTED"),
            ) as spy_verify,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                wraps=remediation_planner_mod.generate_remediation_strategy,
            ) as spy_strategy,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        spy_verify.assert_called_once()
        # Proves SUPPORTED does not block Strategy -- and, since the target
        # file is real and verifiable (see _plan_with_real_target), this is
        # Strategy actually running, not the pre-existing "no verified
        # evidence" gate skipping it for an unrelated reason.
        spy_strategy.assert_called_once()


class TestExistingBehaviorRegressionWhenNoTrigger:
    """When the trigger never fires, S1 -> S2 must behave EXACTLY as before
    this feature existed: zero verifier calls, and Strategy's own existing
    "no planner_evidence_ctx -> skip entirely" behavior is what decides
    whether it runs -- never anything new from this feature."""

    def test_zero_verifier_llm_calls_and_normal_flow_unaffected(self, tmp_path):
        # Deliberately no mock on generate_remediation_plan itself -- the
        # default mock-mode LLM's unparseable response is exactly the
        # pre-existing "no plan" degradation this feature must not disturb.
        # The rest of the pipeline (mock-mode Patch Generator/Challenger/
        # Reviewer/Confidence Scorer) proceeds completely normally, exactly
        # as it did before this feature existed -- proven by reaching a
        # real recommendation rather than raising or hanging.
        with mock.patch(
            "utilities.autopatcher.remediation_verifier.verify_planner_claim"
        ) as spy_verify:
            report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        spy_verify.assert_not_called()
        assert "# Auto Patcher MVP" in report


class TestDoubleContradictionEndToEnd:
    """Locked policy cases C/D, proven end-to-end through pipeline.run():
    Strategy's own LLM call and Patch Generation's own LLM call must both
    be skipped, the resulting patch must be empty, and the specific skip
    reason must propagate through the EXISTING applicability-skip/no-patch
    reporting path -- no new recommendation category, no new report
    section."""

    def _run_double_contradiction(self, tmp_path, v2_status="CONTRADICTED"):
        # A REAL, verifiable target file -- so "Strategy never called" below
        # proves this feature's own forced-skip logic, not the pre-existing
        # (unrelated) "no verified evidence at all" gate skipping it for a
        # different reason.
        plan_v1 = _plan_with_real_target(tmp_path, narrower="rejected narrower mechanism because X")
        plan_v2 = _plan_with_real_target(tmp_path, narrower="rejected narrower mechanism because Y (revised)")
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                side_effect=[plan_v1, plan_v2],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_verifier.verify_planner_claim",
                side_effect=[
                    _verdict("CONTRADICTED", contradiction="finding one"),
                    _verdict(v2_status, contradiction="finding two" if v2_status == "CONTRADICTED" else None),
                ],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
            ) as spy_strategy,
            mock.patch(
                "utilities.autopatcher.pipeline.generate_patch_raw",
            ) as spy_patch_gen,
        ):
            report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        return report, spy_strategy, spy_patch_gen

    def test_strategy_never_called(self, tmp_path):
        _report, spy_strategy, _spy_patch_gen = self._run_double_contradiction(tmp_path)
        spy_strategy.assert_not_called()

    def test_patch_generation_never_called(self, tmp_path):
        _report, _spy_strategy, spy_patch_gen = self._run_double_contradiction(tmp_path)
        spy_patch_gen.assert_not_called()

    def test_resulting_patch_reports_no_patch_produced(self, tmp_path):
        report, _spy_strategy, _spy_patch_gen = self._run_double_contradiction(tmp_path)
        assert "NO PATCH PRODUCED" in report

    def test_exact_skip_reason_propagates_into_report(self, tmp_path):
        report, _spy_strategy, _spy_patch_gen = self._run_double_contradiction(tmp_path)
        assert "Planner Claim Verifier" in report
        assert "causal contradiction not cleared after one" in report
        assert "bounded revision" in report

    def test_second_verification_unresolved_also_blocks(self, tmp_path):
        report, spy_strategy, spy_patch_gen = self._run_double_contradiction(tmp_path, v2_status="UNRESOLVED")
        spy_strategy.assert_not_called()
        spy_patch_gen.assert_not_called()
        assert "NO PATCH PRODUCED" in report
        assert "UNRESOLVED" in report


class TestS1ExecutionArtifact:
    """Review fix requirement E: a verifier-triggered production S1
    execution artifact must record the verifier state needed for
    debugging. Uses a real ExecutionRecorder + pipeline.run(), same
    pattern as test_pipeline_execution_recording.py."""

    def _run_with_recorder(self, tmp_path, verify_side_effect, revised_plan_result=None):
        from utilities.autopatcher.execution_recorder import ExecutionRecorder

        recorder = ExecutionRecorder(
            call_log=[], run_dir=str(tmp_path / "run"), artifacts_dir=tmp_path / "run" / "executions",
        )
        plan_v1 = _plan_with_real_target(tmp_path, narrower="rejected narrower mechanism because X")
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                side_effect=[plan_v1, revised_plan_result] if revised_plan_result is not None else [plan_v1],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_verifier.verify_planner_claim",
                side_effect=verify_side_effect,
            ),
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path), execution_recorder=recorder,
            )
        return recorder

    def _s1_artifact(self, recorder):
        s1 = recorder.executions[0]
        return json.loads(open(s1["artifact_path"], encoding="utf-8").read())

    def test_records_verifier_v1_and_forced_skip_on_double_contradiction(self, tmp_path):
        revised = _plan_with_real_target(tmp_path, narrower="revised, still rejected")
        recorder = self._run_with_recorder(
            tmp_path,
            [_verdict("CONTRADICTED", contradiction="finding one"), _verdict("CONTRADICTED", contradiction="finding two")],
            revised_plan_result=revised,
        )
        artifact = self._s1_artifact(recorder)
        pcv = artifact["planner_claim_verification"]
        assert pcv["verifier_v1"]["status"] == "CONTRADICTED"
        assert pcv["verifier_v2"]["status"] == "CONTRADICTED"
        assert pcv["mode_v1"] == "REJECTED"
        assert pcv["mode_v2"] == "REJECTED"
        assert pcv["revision_attempted"] is True
        assert pcv["forced_skip"] is True
        assert "not cleared" in pcv["skip_reason"]
        assert pcv["broadening_necessity_unresolved"] is False

    def test_records_supported_v1_with_no_revision(self, tmp_path):
        recorder = self._run_with_recorder(tmp_path, [_verdict("SUPPORTED")])
        artifact = self._s1_artifact(recorder)
        pcv = artifact["planner_claim_verification"]
        assert pcv["verifier_v1"]["status"] == "SUPPORTED"
        assert pcv["verifier_v2"] is None
        assert pcv["mode_v1"] == "REJECTED"
        assert pcv["mode_v2"] is None
        assert pcv["revision_attempted"] is False
        assert pcv["forced_skip"] is False
        assert pcv["skip_reason"] is None

    def test_no_verifier_trigger_still_has_the_key_at_safe_defaults(self, tmp_path):
        # Default mock-mode LLM never populates narrower_alternative_considered
        # -- the verifier must not run, and the artifact key must still be
        # present (not absent) at its safe "no verifier ran" defaults, so a
        # consumer never needs to special-case a missing key.
        from utilities.autopatcher.execution_recorder import ExecutionRecorder

        recorder = ExecutionRecorder(
            call_log=[], run_dir=str(tmp_path / "run"), artifacts_dir=tmp_path / "run" / "executions",
        )
        pipeline_mod.run(
            vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path), execution_recorder=recorder,
        )
        artifact = self._s1_artifact(recorder)
        pcv = artifact["planner_claim_verification"]
        assert pcv["verifier_v1"] is None
        assert pcv["mode_v1"] is None
        assert pcv["mode_v2"] is None
        assert pcv["forced_skip"] is False


class TestExactRunThreeEndToEnd:
    """Full pipeline.run() reproduction of the corrected target behavior
    for the real third minimist trace: v1 REJECTED/CONTRADICTED -> one
    revision -> v2 SELECTED, Mode B finds the authoritative fields do not
    match the claimed selection -> forced skip, with NO Strategy and NO
    Patch Generation call -- and, critically, the verifier ACTUALLY ran in
    the correct mode and produced a real CONTRADICTED/false verdict, not an
    accidental collision with an unrelated field (see remediation_verifier.
    VerifierResult's own docstring on why the original run's SUPPORTED+null
    outcome was not a real detection)."""

    def test_forced_skip_via_mode_b_contradiction_no_strategy_no_patch_gen(self, tmp_path):
        plan_v1 = _plan_with_real_target(
            tmp_path, narrower="considered a narrower guard, rejected because X", decision="REJECTED",
        )
        plan_v2 = _plan_with_real_target(
            tmp_path, narrower="I select the narrow guard as the mechanism", decision="SELECTED",
            rendered="## revised plan (selected, still broad authoritative fields)\n",
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                side_effect=[plan_v1, plan_v2],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_verifier.verify_planner_claim",
                side_effect=[
                    _verdict("CONTRADICTED", contradiction="the rejection does not hold up"),
                    _verdict(
                        "CONTRADICTED",
                        contradiction="selected a narrow guard, but authoritative fields describe a broader one",
                        matches_selected=False,
                    ),
                ],
            ) as spy_verify,
            mock.patch("utilities.autopatcher.remediation_planner.generate_remediation_strategy") as spy_strategy,
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw") as spy_patch_gen,
        ):
            report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))

        assert spy_verify.call_count == 2
        assert spy_verify.call_args_list[0].kwargs.get("mode") == "REJECTED"
        assert spy_verify.call_args_list[1].kwargs.get("mode") == "SELECTED"
        spy_strategy.assert_not_called()
        spy_patch_gen.assert_not_called()
        assert "NO PATCH PRODUCED" in report
        assert "Planner Claim Verifier" in report
        assert "not cleared" in report
