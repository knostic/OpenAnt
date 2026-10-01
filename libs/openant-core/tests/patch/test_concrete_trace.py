"""Tests for the EXPERIMENTAL, zero-policy-authority Concrete Trace
mechanism (utilities/autopatcher/concrete_trace.py) and its standalone
harness (utilities/autopatcher/tools/concrete_trace_harness.py).

Hermetic: no real LLM call anywhere in this file (every `llm.complete` is
mocked), no real repo, no Docker, no network. This file does not duplicate
patch_challenger.py's own test suite -- it tests ONLY this new,
independent module's parsing/validation/isolation/call-budget behavior."""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest
from unittest import mock

from utilities.autopatcher.concrete_trace import (
    OUTCOME_VALUES,
    _ISOLATION_BOUNDARY_FIELDS,
    _parse_concrete_trace_response,
    resolve_concrete_trace,
)
from utilities.autopatcher.lineage import (
    INVOCATION_KIND_INITIAL,
    make_execution_id,
    new_execution_record,
    new_full_run_manifest,
)
from utilities.autopatcher.tools.concrete_trace_harness import (
    ConcreteTraceHarnessError,
    _isolate_concern_input,
    run_concrete_trace_harness,
)

_CODE_CONTEXT = (
    "def urlopen(self, url, assert_same_host=True):\n"
    "    if assert_same_host and not self.is_same_host(url):\n"
    "        raise HostChangedError(self, url)\n"
    "    return self.urlopen(url, assert_same_host=assert_same_host)\n"
)
_PATCH = "some diff"


def _mock_llm(response_text):
    llm = mock.MagicMock()
    llm.complete.return_value = response_text
    return llm


def _reached_response():
    return (
        "Example scenario: Calling urlopen directly on a same-origin URL with default arguments.\n\n"
        "Trace:\n"
        "1. Citation: if assert_same_host and not self.is_same_host(url):\n"
        "   Note: Guard is false for a same-origin URL, so execution continues past it.\n"
        "2. Citation: return self.urlopen(url, assert_same_host=assert_same_host)\n"
        "   Note: The operation this concern describes executes for this scenario.\n\n"
        "Outcome: REACHED\n"
        "Blocking step: none\n"
    )


def _blocked_response():
    return (
        "Example scenario: Calling urlopen directly with default arguments and a cross-origin redirect target.\n\n"
        "Trace:\n"
        "1. Citation: if assert_same_host and not self.is_same_host(url):\n"
        "   Note: Guard evaluates true by default for a cross-origin target.\n"
        "2. Citation: raise HostChangedError(self, url)\n"
        "   Note: Execution stops here for this scenario.\n\n"
        "Outcome: BLOCKED\n"
        "Blocking step: 2\n"
    )


def _unresolved_response():
    return (
        "Example scenario: none\n\n"
        "Outcome: UNRESOLVED\n"
        "Blocking step: none\n"
    )


class TestValidOutcomes:
    """1-3: a well-formed response for each of the three outcomes."""

    def test_valid_reached(self):
        llm = _mock_llm(_reached_response())
        result = resolve_concrete_trace(
            concern_role="primary", description="d", code_context=_CODE_CONTEXT, patch=_PATCH, llm=llm,
        )
        assert result["outcome"] == "REACHED"
        assert result["blocking_step_index"] is None
        assert result["invalid_reason"] is None
        assert len(result["trace_steps"]) == 2

    def test_valid_blocked(self):
        llm = _mock_llm(_blocked_response())
        result = resolve_concrete_trace(
            concern_role="additional", description="d", code_context=_CODE_CONTEXT, patch=_PATCH, llm=llm,
        )
        assert result["outcome"] == "BLOCKED"
        assert result["blocking_step_index"] == 1
        assert result["invalid_reason"] is None
        assert result["trace_steps"][1]["citation"] == "raise HostChangedError(self, url)"

    def test_valid_unresolved(self):
        llm = _mock_llm(_unresolved_response())
        result = resolve_concrete_trace(
            concern_role="primary", description="d", code_context=_CODE_CONTEXT, patch=_PATCH, llm=llm,
        )
        assert result["outcome"] == "UNRESOLVED"
        assert result["blocking_step_index"] is None
        # `Example scenario: none` is checked before the model's own
        # UNRESOLVED -- see `test_model_reported_unresolved` for that path.
        assert result["invalid_reason"] == "example_scenario_blank_or_missing"

    def test_model_reported_unresolved(self):
        response = (
            "Example scenario: A call whose next transition the evidence does not show.\n\n"
            "Trace:\n"
            "1. Citation: if assert_same_host and not self.is_same_host(url):\n"
            "   Note: The evidence does not establish is_same_host's result.\n\n"
            "Outcome: UNRESOLVED\n"
            "Blocking step: none\n"
        )
        result = resolve_concrete_trace(
            concern_role="primary", description="d", code_context=_CODE_CONTEXT, patch=_PATCH,
            llm=_mock_llm(response),
        )
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "model_reported_unresolved"


class TestFailClosedValidation:
    """4-10: every listed fail-closed rule collapses to UNRESOLVED, never
    a raised exception and never a trusted REACHED/BLOCKED."""

    def _resolve(self, response_text):
        llm = _mock_llm(response_text)
        return resolve_concrete_trace(
            concern_role="primary", description="d", code_context=_CODE_CONTEXT, patch=_PATCH, llm=llm,
        )

    def test_malformed_response_is_unresolved(self):
        result = self._resolve("this is not shaped like the response format at all")
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "example_scenario_blank_or_missing"

    def test_invalid_citation_is_unresolved(self):
        response = (
            "Example scenario: A scenario.\n\n"
            "Trace:\n"
            "1. Citation: this text does not appear anywhere in the evidence or patch\n"
            "   Note: fabricated.\n\n"
            "Outcome: REACHED\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "invalid_trace_citation"

    def test_blocked_missing_blocking_step_is_unresolved(self):
        response = (
            "Example scenario: A scenario.\n\n"
            "Trace:\n"
            "1. Citation: raise HostChangedError(self, url)\n"
            "   Note: stop.\n\n"
            "Outcome: BLOCKED\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "blocked_without_blocking_index"

    def test_out_of_range_blocking_step_is_unresolved(self):
        response = (
            "Example scenario: A scenario.\n\n"
            "Trace:\n"
            "1. Citation: raise HostChangedError(self, url)\n"
            "   Note: stop.\n\n"
            "Outcome: BLOCKED\n"
            "Blocking step: 7\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "blocking_index_out_of_range"

    def test_reached_with_blocking_index_is_unresolved(self):
        response = (
            "Example scenario: A scenario.\n\n"
            "Trace:\n"
            "1. Citation: return self.urlopen(url, assert_same_host=assert_same_host)\n"
            "   Note: reached.\n\n"
            "Outcome: REACHED\n"
            "Blocking step: 1\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "reached_with_blocking_index"

    def test_blank_scenario_is_unresolved(self):
        response = (
            "Example scenario: none\n\n"
            "Trace:\n"
            "1. Citation: raise HostChangedError(self, url)\n"
            "   Note: stop.\n\n"
            "Outcome: BLOCKED\n"
            "Blocking step: 1\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "example_scenario_blank_or_missing"

    def test_wrong_field_types_is_unresolved(self):
        from utilities.autopatcher.concrete_trace import _validate_concrete_trace

        parsed = {
            "example_scenario": "A scenario.",
            "trace_steps": "not-a-list",
            "outcome_raw": "REACHED",
            "blocking_step_raw": None,
        }
        result = _validate_concrete_trace(parsed, _CODE_CONTEXT, _PATCH)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "trace_steps_wrong_type"

    def test_outcome_outside_enum_is_unresolved(self):
        response = (
            "Example scenario: A scenario.\n\n"
            "Trace:\n"
            "1. Citation: raise HostChangedError(self, url)\n"
            "   Note: stop.\n\n"
            "Outcome: MAYBE\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "outcome_outside_enum"

    def test_no_trace_steps_is_unresolved(self):
        response = "Example scenario: A scenario.\n\nOutcome: REACHED\nBlocking step: none\n"
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "no_trace_steps"


class TestExactlyOneLlmCall:
    """12/13: the call budget is fixed at exactly 1, regardless of what
    the (single) response says -- there is no code path in this module
    that can call `llm.complete` a second time, so a response that reads
    like a request for more evidence cannot trigger one either (there is
    no evidence-acquisition mechanism to trigger)."""

    def test_exactly_one_call_for_a_normal_response(self):
        llm = _mock_llm(_blocked_response())
        resolve_concrete_trace(concern_role="primary", description="d", code_context=_CODE_CONTEXT, patch=_PATCH, llm=llm)
        assert llm.complete.call_count == 1

    def test_exactly_one_call_even_when_response_resembles_an_evidence_request(self):
        llm = _mock_llm("Example scenario: none\n\nOutcome: UNRESOLVED\nBlocking step: none\n"
                        "I would need to REQUEST_EVIDENCE about the following file to continue.\n")
        result = resolve_concrete_trace(concern_role="primary", description="d", code_context=_CODE_CONTEXT, patch=_PATCH, llm=llm)
        assert llm.complete.call_count == 1
        assert result["outcome"] == "UNRESOLVED"

    def test_llm_calls_made_field_is_always_one(self):
        for response in (_reached_response(), _blocked_response(), _unresolved_response(), "garbage"):
            llm = _mock_llm(response)
            result = resolve_concrete_trace(concern_role="primary", description="d", code_context=_CODE_CONTEXT, patch=_PATCH, llm=llm)
            assert result["llm_calls_made"] == 1


class TestInputIsolation:
    """11: forbidden Challenger fields never reach the prompt/call."""

    def test_resolve_concrete_trace_signature_has_no_forbidden_parameters(self):
        params = set(inspect.signature(resolve_concrete_trace).parameters.keys())
        assert params == {"concern_role", "description", "code_context", "patch", "llm"}
        assert not (params & _ISOLATION_BOUNDARY_FIELDS)

    def test_isolate_concern_input_drops_every_forbidden_field(self):
        concern = {
            "concern_role": "primary",
            "description": "a concern",
            "vulnerability_text": "SECRET VULN TEXT",
            "preceding_guard": "absent",
            "guard_default_state": "condition_true_under_default",
            "guard_effect": "prevents_operation",
            "reentry_state_propagation": "preserved",
            "default_execution_reachability": "blocked",
            "requires_explicit_non_default_action": "false",
            "contract_addresses_override": "not_applicable",
            "consequence": "NON_BLOCKING",
            "reachability_facts": {"preceding_guard": "absent"},
            "hypothesized_outcome": "a sneaky hypothesis",
            "verification_status": "RESIDUAL_VULNERABILITY",
        }
        isolated = _isolate_concern_input(concern)
        assert isolated == {"concern_role": "primary", "description": "a concern"}
        assert not (_ISOLATION_BOUNDARY_FIELDS & set(isolated.keys()))

    def test_forbidden_field_values_never_appear_in_the_prompt_sent_to_the_model(self):
        llm = _mock_llm(_blocked_response())
        secret_hypothesis = "ZZZ_SECRET_HYPOTHESIZED_OUTCOME_ZZZ"
        secret_vuln_text = "ZZZ_SECRET_VULNERABILITY_TEXT_ZZZ"
        # `resolve_concrete_trace` has no parameter for either secret --
        # this call cannot forward them even if it wanted to.
        resolve_concrete_trace(concern_role="primary", description="an ordinary description", code_context=_CODE_CONTEXT, patch=_PATCH, llm=llm)
        system_prompt, user_message = llm.complete.call_args[0][:2]
        assert secret_hypothesis not in system_prompt + user_message
        assert secret_vuln_text not in system_prompt + user_message


def _write_manifest(manifest_dir: Path, executions: list) -> Path:
    manifest = new_full_run_manifest(
        target_repository={"repo_root": "/repo", "repo_commit": "aaa"},
        openant={"patcher_commit": "bbb"},
        llm={"provider": "mock", "model": "mock"},
        executions=executions,
    )
    manifest_dir.mkdir(parents=True, exist_ok=True)
    (manifest_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_dir


def _build_archived_run(tmp_path: Path, response_text: str, vulnerability_text: str = "SECRET_VULN_TEXT") -> Path:
    """A minimal, hand-built archived full-run directory: one
    patch_generation_and_post_patch_investigation execution (S4) whose
    artifact carries vulnerability_text/patch/challenger_context, and
    one challenger execution whose own llm_calls entry points at a raw
    response file -- same shape used by test_replay_challenger_reparse.py."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)

    s4_id = make_execution_id(1, "patch_generation_and_post_patch_investigation")
    s4_artifact_path = run_dir / "004_patch_generation_and_post_patch_investigation.json"
    s4_artifact_path.write_text(json.dumps({
        "vulnerability_text": vulnerability_text,
        "patch": _PATCH,
        "challenger_context": _CODE_CONTEXT,
        "code_context": _CODE_CONTEXT,
    }), encoding="utf-8")

    response_path = run_dir / "002_challenger.response.txt"
    response_path.write_text(response_text, encoding="utf-8")
    (run_dir / "002_challenger.prompt.txt").write_text("irrelevant", encoding="utf-8")
    challenger_artifact_path = run_dir / "005_challenger.json"
    challenger_artifact_path.write_text(json.dumps({"challenger": {}}), encoding="utf-8")

    executions = [
        new_execution_record(
            execution_id=s4_id,
            canonical_stage="patch_generation_and_post_patch_investigation",
            sequence=1,
            invocation_kind=INVOCATION_KIND_INITIAL,
            outcome="settled",
            artifact_path=str(s4_artifact_path),
        ),
        new_execution_record(
            execution_id=make_execution_id(2, "challenger"),
            canonical_stage="challenger",
            sequence=2,
            invocation_kind=INVOCATION_KIND_INITIAL,
            outcome="settled",
            consumed={"patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": s4_id}},
            artifact_path=str(challenger_artifact_path),
            llm_calls=[{
                "seq": 2, "stage": "challenger",
                "prompt_file": "002_challenger.prompt.txt", "response_file": "002_challenger.response.txt",
            }],
        ),
    ]
    _write_manifest(run_dir, executions)
    return run_dir


_ARCHIVED_RESPONSE = (
    "Verification status: VERIFIED_FIXED\n\n"
    "Concerns:\n\n"
    "1. Role: primary\n"
    "   Description: whether the operation is still reached under default execution\n"
    "   Operation present in evidence: present\n"
    "   Preceding guard: present\n"
    "   Guard provenance: if assert_same_host and not self.is_same_host(url):\n"
    "   Operation provenance: return self.urlopen(url, assert_same_host=assert_same_host)\n"
    "   Guard default state: condition_true_under_default\n"
    "   Guard default state provenance: assert_same_host=True\n"
    "   Guard effect: prevents_operation\n"
    "   Guard effect provenance: raise HostChangedError(self, url)\n"
    "   Reentry state propagation: preserved\n"
    "   Requires explicit non-default action: not_applicable\n\n"
    "2. Role: additional\n"
    "   Description: whether a direct caller still leaks the header cross-origin\n"
    "   Operation present in evidence: present\n"
    "   Preceding guard: absent\n"
    "   Guard provenance: whole function\n"
    "   Function provenance: def urlopen(self, url, assert_same_host=True):\n"
    "   Operation provenance: return self.urlopen(url, assert_same_host=assert_same_host)\n"
    "   Guard default state: not_applicable\n"
    "   Guard effect: not_applicable\n"
    "   Reentry state propagation: not_applicable\n"
    "   Requires explicit non-default action: unresolved\n\n"
    "Edge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- none\n"
)


class TestHarness:
    def test_harness_does_not_invoke_production_challenge_patch(self, tmp_path):
        """14: patch challenge_patch itself to explode if called, then
        run the full harness against an archived run -- it must still
        succeed cleanly, proving it never goes anywhere near that
        production entry point."""
        run_dir = _build_archived_run(tmp_path, _ARCHIVED_RESPONSE)
        llm = _mock_llm(_blocked_response())
        with mock.patch(
            "utilities.autopatcher.patch_challenger.challenge_patch",
            side_effect=AssertionError("challenge_patch must not be invoked by the Concrete Trace harness"),
        ):
            artifact = run_concrete_trace_harness(run_dir, tmp_path / "out", llm)

        assert len(artifact["concerns"]) == 2
        assert artifact["llm_calls_made"] == 2

    def test_harness_makes_exactly_one_call_per_concern(self, tmp_path):
        run_dir = _build_archived_run(tmp_path, _ARCHIVED_RESPONSE)
        llm = _mock_llm(_reached_response())
        artifact = run_concrete_trace_harness(run_dir, tmp_path / "out", llm)
        assert llm.complete.call_count == 2
        assert artifact["llm_calls_made"] == 2

    def test_harness_can_restrict_to_one_concern_number(self, tmp_path):
        run_dir = _build_archived_run(tmp_path, _ARCHIVED_RESPONSE)
        llm = _mock_llm(_blocked_response())
        artifact = run_concrete_trace_harness(run_dir, tmp_path / "out", llm, concern_number=2)
        assert len(artifact["concerns"]) == 1
        assert artifact["concerns"][0]["concern_number"] == 2
        assert llm.complete.call_count == 1

    def test_harness_artifact_written_matches_returned_artifact(self, tmp_path):
        run_dir = _build_archived_run(tmp_path, _ARCHIVED_RESPONSE)
        output_dir = tmp_path / "out"
        llm = _mock_llm(_reached_response())
        artifact = run_concrete_trace_harness(run_dir, output_dir, llm)
        on_disk = json.loads((output_dir / "concrete_trace.json").read_text())
        assert on_disk == artifact

    def test_harness_forbidden_fields_do_not_reach_the_model_prompt(self, tmp_path):
        secret_vuln_text = "ZZZ_SECRET_VULNERABILITY_TEXT_ZZZ"
        run_dir = _build_archived_run(tmp_path, _ARCHIVED_RESPONSE, vulnerability_text=secret_vuln_text)
        llm = _mock_llm(_reached_response())
        run_concrete_trace_harness(run_dir, tmp_path / "out", llm)
        for call in llm.complete.call_args_list:
            system_prompt, user_message = call[0][:2]
            assert secret_vuln_text not in system_prompt + user_message

    def test_harness_reports_zero_policy_authority(self, tmp_path):
        run_dir = _build_archived_run(tmp_path, _ARCHIVED_RESPONSE)
        llm = _mock_llm(_reached_response())
        artifact = run_concrete_trace_harness(run_dir, tmp_path / "out", llm)
        assert artifact["policy_authority"] is False

    def test_malformed_source_run_raises_clearly(self, tmp_path):
        from utilities.autopatcher.lineage import LineageError
        empty_dir = tmp_path / "not-a-run"
        empty_dir.mkdir()
        llm = _mock_llm(_reached_response())
        with pytest.raises(LineageError):
            run_concrete_trace_harness(empty_dir, tmp_path / "out", llm)

    def test_unknown_concern_number_raises_clearly(self, tmp_path):
        run_dir = _build_archived_run(tmp_path, _ARCHIVED_RESPONSE)
        llm = _mock_llm(_reached_response())
        with pytest.raises(ConcreteTraceHarnessError):
            run_concrete_trace_harness(run_dir, tmp_path / "out", llm, concern_number=99)


class TestSyntheticAssertSameHostShapedExample:
    """15: a small synthetic (not the real archived urllib3 file)
    assert-same-host-shaped example demonstrating a citation-backed
    BLOCKED result surviving deterministic validation end-to-end."""

    def test_synthetic_blocked_example_survives_validation(self):
        code_context = (
            "class HTTPConnectionPool:\n"
            "    def urlopen(self, method, url, redirect=True, assert_same_host: bool = True):\n"
            "        if assert_same_host and not self.is_same_host(url):\n"
            "            raise HostChangedError(self, url, retries)\n"
            "        redirect_location = redirect and response.get_redirect_location()\n"
            "        if redirect_location:\n"
            "            return self.urlopen(method, redirect_location, redirect=redirect, assert_same_host=assert_same_host)\n"
        )
        response = (
            "Example scenario: A direct HTTPConnectionPool.urlopen() call with default arguments "
            "and a Cookie header, where the server responds with a redirect to a different host.\n\n"
            "Trace:\n"
            "1. Citation: if assert_same_host and not self.is_same_host(url):\n"
            "   Note: assert_same_host defaults to True and the redirect target is a different host, so this condition is true for this scenario.\n"
            "2. Citation: raise HostChangedError(self, url, retries)\n"
            "   Note: This raises before the recursive redirect call is ever reached for this scenario.\n\n"
            "Outcome: BLOCKED\n"
            "Blocking step: 2\n"
        )
        llm = _mock_llm(response)
        result = resolve_concrete_trace(
            concern_role="additional",
            description="whether a direct pool caller still forwards a cookie header cross-origin on redirect",
            code_context=code_context, patch="", llm=llm,
        )
        assert result["outcome"] == "BLOCKED"
        assert result["blocking_step_index"] == 1
        assert result["invalid_reason"] is None
        assert "HostChangedError" in result["trace_steps"][1]["citation"]


# ---------------------------------------------------------------------------
# Trace-termination semantics: "the concern's own named mechanism was
# exercised" is NOT the same claim as "the final problematic outcome
# occurred." This is a generic, mechanism-agnostic fixture (an early guard,
# a named "mechanism" call, a later guard, and a final-outcome call) --
# deliberately NOT HTTP/redirect/assert_same_host-shaped, to keep this
# class about the termination semantics themselves, not about any one
# concrete example.
# ---------------------------------------------------------------------------

_TERMINATION_CODE_CONTEXT = (
    "def entry(flag_a, flag_b):\n"
    "    if flag_a:\n"
    "        raise EarlyBlock()\n"
    "    mechanism_call()\n"
    "    if flag_b:\n"
    "        raise LateBlock()\n"
    "    final_outcome_call()\n"
)


class TestTraceTerminationSemantics:
    """1-6: reaching the concern's own named mechanism is an intermediate
    trace event, never sufficient by itself for REACHED -- the schema
    (example_scenario/trace_steps/outcome/blocking_step_index) is
    unchanged and already sufficient to represent all of these; only the
    PROMPT's task instructions (prompts/concrete_trace.md) establish this
    distinction -- see concrete_trace.py's own "KNOWN LIMITATION"
    docstring for exactly what deterministic validation can and cannot
    enforce here."""

    def _resolve(self, response_text):
        llm = _mock_llm(response_text)
        return resolve_concrete_trace(
            concern_role="additional", description="whether the mechanism this concern names ultimately produces the outcome",
            code_context=_TERMINATION_CODE_CONTEXT, patch="", llm=llm,
        )

    def test_1_mechanism_reached_then_final_outcome_reached_is_reached(self):
        response = (
            "Example scenario: A call with flag_a=False and flag_b=False.\n\n"
            "Trace:\n"
            "1. Citation: mechanism_call()\n"
            "   Note: The concern's own named mechanism executes for this scenario.\n"
            "2. Citation: final_outcome_call()\n"
            "   Note: Execution continues past the mechanism and reaches the final outcome for this scenario.\n\n"
            "Outcome: REACHED\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "REACHED"
        assert result["invalid_reason"] is None
        assert len(result["trace_steps"]) == 2

    def test_2_mechanism_reached_then_later_condition_blocks_final_outcome(self):
        response = (
            "Example scenario: A call with flag_a=False and flag_b=True.\n\n"
            "Trace:\n"
            "1. Citation: mechanism_call()\n"
            "   Note: The concern's own named mechanism executes for this scenario.\n"
            "2. Citation: raise LateBlock()\n"
            "   Note: This later condition, evaluated after the mechanism, prevents the final outcome from ever executing for this scenario.\n\n"
            "Outcome: BLOCKED\n"
            "Blocking step: 2\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "BLOCKED"
        assert result["blocking_step_index"] == 1
        assert result["invalid_reason"] is None

    def test_3_mechanism_reached_then_evidence_ends_is_unresolved(self):
        response = (
            "Example scenario: A call with flag_a=False.\n\n"
            "Trace:\n"
            "1. Citation: mechanism_call()\n"
            "   Note: The concern's own named mechanism executes for this scenario.\n\n"
            "Outcome: UNRESOLVED\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"

    def test_4_blocking_condition_before_mechanism_can_execute_is_blocked(self):
        response = (
            "Example scenario: A call with flag_a=True.\n\n"
            "Trace:\n"
            "1. Citation: raise EarlyBlock()\n"
            "   Note: This condition fires before the mechanism the concern names is ever reached for this scenario.\n\n"
            "Outcome: BLOCKED\n"
            "Blocking step: 1\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "BLOCKED"
        assert result["blocking_step_index"] == 0
        assert result["invalid_reason"] is None

    def test_5_mechanism_never_exercised_because_execution_is_blocked_first(self):
        """Same shape as test 4, from the angle the task calls out
        separately: the concern's own named mechanism is never exercised
        at all for this scenario, because an earlier condition already
        blocks it -- still BLOCKED, never UNRESOLVED-for-lack-of-a-
        mechanism-citation and never a false REACHED."""
        response = (
            "Example scenario: A call with flag_a=True and flag_b=False.\n\n"
            "Trace:\n"
            "1. Citation: if flag_a:\n"
            "   Note: True for this scenario.\n"
            "2. Citation: raise EarlyBlock()\n"
            "   Note: Execution stops here; mechanism_call() is never reached for this scenario.\n\n"
            "Outcome: BLOCKED\n"
            "Blocking step: 2\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "BLOCKED"
        assert result["blocking_step_index"] == 1
        assert result["invalid_reason"] is None

    def test_6_mechanism_only_trace_claiming_reached_is_a_known_uncaught_limitation(self):
        """This is deliberately NOT a "the validator rejects this" test --
        it documents the opposite, on purpose. A trace that cites ONLY
        the concern's own named mechanism and then claims `REACHED` is
        shape-valid, citation-valid, and internally consistent (no
        blocking_step_index contradiction) -- `_validate_concrete_trace`
        has no semantic basis to tell "this citation is the mechanism"
        apart from "this citation is the final outcome," so it CANNOT
        catch this by design (see concrete_trace.py's own "KNOWN
        LIMITATION" docstring). Preventing this exact failure mode is
        entirely prompts/concrete_trace.md's job, verified only by the
        real replay, never by this deterministic layer. This test exists
        so a future reader does not mistake the validator's silence here
        for a guarantee."""
        response = (
            "Example scenario: A call with flag_a=False and flag_b=False.\n\n"
            "Trace:\n"
            "1. Citation: mechanism_call()\n"
            "   Note: The concern's own named mechanism executes for this scenario.\n\n"
            "Outcome: REACHED\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "REACHED"
        assert result["invalid_reason"] is None


# ---------------------------------------------------------------------------
# Next-execution trace contract: the prompt now asks for "the next executed
# statement or control-flow decision," not "steps that matter." These tests
# lock the SCHEMA/VALIDATOR's sufficiency for that discipline -- they are
# generic, mechanism-agnostic fixtures, never urllib3-shaped. Per the
# approved design, "C. BLOCKING CONDITION" and "F. CONCERN MECHANISM IS
# INTERMEDIATE" are already adequately covered by
# TestTraceTerminationSemantics above (tests 1/2 for F's shape, tests 4/5
# for C's shape) and are deliberately NOT duplicated here.
# ---------------------------------------------------------------------------

_BRANCH_CODE_CONTEXT = (
    "def entry(x):\n"
    "    if x:\n"
    "        foo()\n"
    "    bar()\n"
    "    final_outcome_call()\n"
)

_RECURSIVE_CODE_CONTEXT = (
    "def process(depth):\n"
    "    if depth >= 1:\n"
    "        finish()\n"
    "        return\n"
    "    return process(depth + 1)\n"
)


class TestNextExecutionContract:
    """Schema/validator sufficiency for the next-execution discipline --
    the prompt change is the actual experiment; these tests only confirm
    the EXISTING schema (example_scenario/trace_steps/outcome/
    blocking_step_index) and the EXISTING validator can represent and
    accept every shape that discipline requires, with zero code change."""

    def _resolve(self, response_text, code_context=_BRANCH_CODE_CONTEXT):
        llm = _mock_llm(response_text)
        return resolve_concrete_trace(
            concern_role="additional", description="whether a concrete scenario's execution reaches the outcome this concern describes",
            code_context=code_context, patch="", llm=llm,
        )

    def test_a_condition_true_branch_entered_later_outcome_reached(self):
        response = (
            "Example scenario: A call with x=True.\n\n"
            "Trace:\n"
            "1. Citation: if x:\n"
            "   Note: True for this scenario, so the branch below is entered.\n"
            "2. Citation: foo()\n"
            "   Note: This executes for this scenario because the decision above was true.\n"
            "3. Citation: final_outcome_call()\n"
            "   Note: Execution continues past the branch and reaches the final outcome for this scenario.\n\n"
            "Outcome: REACHED\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "REACHED"
        assert result["invalid_reason"] is None
        assert len(result["trace_steps"]) == 3

    def test_b_condition_false_branch_skipped_execution_continues(self):
        response = (
            "Example scenario: A call with x=False.\n\n"
            "Trace:\n"
            "1. Citation: if x:\n"
            "   Note: False for this scenario, so the branch below is not entered.\n"
            "2. Citation: bar()\n"
            "   Note: Execution continues directly here after the skipped branch, for this scenario.\n"
            "3. Citation: final_outcome_call()\n"
            "   Note: The final outcome is reached for this scenario.\n\n"
            "Outcome: REACHED\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "REACHED"
        assert result["invalid_reason"] is None
        # The untaken branch's own body (`foo()`) is correctly never cited.
        citations = [s["citation"] for s in result["trace_steps"]]
        assert "foo()" not in citations

    def test_d_recursive_call_with_repeated_and_backward_offset_citation_is_accepted(self):
        """The SAME source line (`if depth >= 1:`) is cited twice, once
        per pass through the recursive call -- the second occurrence's
        raw text offset is EARLIER than the recursive call site cited
        just before it. The validator must accept this: source order is
        not execution order, and a citation may legitimately repeat or
        "move backward" through source text on a recursive re-entry."""
        response = (
            "Example scenario: A call with depth=0.\n\n"
            "Trace:\n"
            "1. Citation: if depth >= 1:\n"
            "   Note: False at depth=0 for this scenario, so the branch below is not entered.\n"
            "2. Citation: return process(depth + 1)\n"
            "   Note: This scenario recurses with depth=1.\n"
            "3. Citation: if depth >= 1:\n"
            "   Note: True at depth=1 for this scenario, re-entering the same decision.\n"
            "4. Citation: finish()\n"
            "   Note: This executes on the recursive pass for this scenario.\n\n"
            "Outcome: REACHED\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response, code_context=_RECURSIVE_CODE_CONTEXT)
        assert result["outcome"] == "REACHED"
        assert result["invalid_reason"] is None
        assert result["trace_steps"][0]["citation"] == result["trace_steps"][2]["citation"]

    def test_e_insufficient_evidence_for_next_transition_is_unresolved(self):
        """The model reaches a control-flow decision but the evidence
        does not let it establish which way it resolves for this
        scenario -- it must not guess or advance past it."""
        response = (
            "Example scenario: A call with x set by a caller-controlled value not shown in this evidence.\n\n"
            "Trace:\n"
            "1. Citation: if x:\n"
            "   Note: The evidence shown does not establish x's value for this scenario, so what executes next cannot be determined.\n\n"
            "Outcome: UNRESOLVED\n"
            "Blocking step: none\n"
        )
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"


# ---------------------------------------------------------------------------
# Multi-line `Citation:` extraction. Regression for the archived N=5 urllib3
# experiment (runs 1, 3, 5): the model wrote each citation as a multi-line
# code span wrapped in ONE matching pair of backticks. The parser kept only
# the first physical line, which dropped the closing backtick, so the
# shared `_strip_quote_wrapping` no longer saw a matching wrapper and every
# step failed `_point_citation_valid` -- turning a correct BLOCKED into
# UNRESOLVED. The same truncation meant later lines of an UNWRAPPED
# multi-line citation (runs 2, 4) were never validated at all. The fixture
# lines below are verbatim from that run's real evidence.
# ---------------------------------------------------------------------------

_MULTILINE_CODE_CONTEXT = (
    "    def urlopen(self, method, url, body=None, headers=None, retries=None,\n"
    "                redirect=True, assert_same_host=True, **response_kw):\n"
    "        parsed_url = parse_url(url)\n"
    "        destination_scheme = parsed_url.scheme\n"
    "\n"
    "        if headers is None:\n"
    "            headers = self.headers\n"
    "\n"
    "        # Check host\n"
    "        if assert_same_host and not self.is_same_host(url):\n"
    "            raise HostChangedError(self, url, retries)\n"
)


def _two_step_blocked_response(citation_1: str, citation_2: str) -> str:
    return (
        "Example scenario: A direct pool.urlopen() call whose redirect targets a different host.\n\n"
        "Trace:\n"
        f"1. Citation: {citation_1}\n"
        "   Note: headers is the caller-supplied dict, so it is not replaced.\n\n"
        f"2. Citation: {citation_2}\n"
        "   Note: url is not the same host, so this raises.\n\n"
        "Outcome: BLOCKED\n"
        "Blocking step: 2\n"
    )


# Exactly the Run 1 shape: an opening backtick on the first line, the
# closing backtick at the end of the last line, original indentation kept.
_RUN1_CITATION_1 = (
    "`        parsed_url = parse_url(url)\n"
    "        destination_scheme = parsed_url.scheme\n"
    "\n"
    "        if headers is None:\n"
    "            headers = self.headers`"
)
_RUN1_CITATION_2 = (
    "`        if assert_same_host and not self.is_same_host(url):\n"
    "            raise HostChangedError(self, url, retries)`"
)


class TestMultiLineCitationExtraction:

    def _resolve(self, response_text):
        return resolve_concrete_trace(
            concern_role="additional", description="d",
            code_context=_MULTILINE_CODE_CONTEXT, patch="", llm=_mock_llm(response_text),
        )

    def test_run1_backtick_wrapped_multiline_citation_blocked_survives_validation(self):
        result = self._resolve(_two_step_blocked_response(_RUN1_CITATION_1, _RUN1_CITATION_2))
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"
        assert result["blocking_step_index"] == 1
        assert [s["citation"] for s in result["trace_steps"]] == [_RUN1_CITATION_1, _RUN1_CITATION_2]

    def test_unwrapped_multiline_citation_keeps_second_line_and_validates(self):
        """The Run 4 shape: no wrapper, continuation lines indented."""
        citation = (
            "if assert_same_host and not self.is_same_host(url):\n"
            "            raise HostChangedError(self, url, retries)"
        )
        result = self._resolve(_two_step_blocked_response("if headers is None:", citation))
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"
        assert result["trace_steps"][1]["citation"] == citation

    def test_single_line_matching_backticks_still_validates(self):
        """The Run 5 step 1 shape -- unchanged behavior."""
        result = self._resolve(_two_step_blocked_response(
            "`        parsed_url = parse_url(url)`",
            "`raise HostChangedError(self, url, retries)`",
        ))
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"

    def test_note_is_not_part_of_citation(self):
        parsed = _parse_concrete_trace_response(_two_step_blocked_response(_RUN1_CITATION_1, _RUN1_CITATION_2))
        steps = parsed["trace_steps"]
        assert len(steps) == 2
        assert steps[0]["citation"] == _RUN1_CITATION_1
        assert steps[1]["citation"] == _RUN1_CITATION_2
        assert all("Note:" not in s["citation"] for s in steps)
        assert steps[0]["note"] == "headers is the caller-supplied dict, so it is not replaced."
        assert steps[1]["note"] == "url is not the same host, so this raises."
        assert parsed["outcome_raw"] == "BLOCKED"
        assert parsed["blocking_step_raw"] == "2"

    @pytest.mark.parametrize("wrapper", ["`", ""], ids=["backtick_wrapped", "unwrapped"])
    def test_genuine_first_line_with_altered_continuation_is_rejected(self, wrapper):
        """Line 1 is verbatim evidence; line 2 is invented. Before the fix
        only line 1 was ever validated, so the unwrapped form was
        accepted -- the whole citation must now be grounded."""
        altered = (
            f"{wrapper}        if assert_same_host and not self.is_same_host(url):\n"
            f"            raise SomeOtherError(self, url, retries){wrapper}"
        )
        result = self._resolve(_two_step_blocked_response("if headers is None:", altered))
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "invalid_trace_citation"

    def test_single_line_wrapped_citation_with_altered_content_is_rejected(self):
        result = self._resolve(_two_step_blocked_response(
            "if headers is None:", "`raise HostChangedError(self, url, redirects)`",
        ))
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "invalid_trace_citation"

    def test_unmatched_opening_backtick_is_not_stripped(self):
        """No one-sided wrapper stripping: an opening backtick that is never
        closed stays part of the citation and fails containment."""
        unmatched = (
            "`        if assert_same_host and not self.is_same_host(url):\n"
            "            raise HostChangedError(self, url, retries)"
        )
        result = self._resolve(_two_step_blocked_response("if headers is None:", unmatched))
        assert result["trace_steps"][1]["citation"] == unmatched
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "invalid_trace_citation"


# ---------------------------------------------------------------------------
# Structural response contract. Response structure (step headers, Notes,
# `Example scenario`/`Outcome`/`Blocking step`) is read only from the text
# OUTSIDE citation contents, and any ambiguity fails closed. The fixture
# below deliberately contains repository text that superficially resembles
# that structure -- a numbered docstring list, `Note:`/`Outcome:`/`Example
# scenario:` docstring lines, a `# Citation:` comment, a `note:` annotation,
# and YAML `outcome:`/`blocking step:` keys -- so every positive control
# proves such text, when cited verbatim, is validated as a citation and
# never mistaken for response structure.
# ---------------------------------------------------------------------------

_COLLISION_CODE_CONTEXT = (
    "    def resolve(self, request):\n"
    '        """Resolve a request.\n'
    "\n"
    "        Steps:\n"
    "            1. Validate the request.\n"
    "            2. Retry the request.\n"
    "\n"
    "        Example scenario: a retried request.\n"
    "        Outcome: the resolved value.\n"
    "        Note: retries are bounded.\n"
    '        """\n'
    "        # Citation: RFC 9110 section 15.4\n"
    "        note: str = request.note\n"
    "        if request.retries > self.max_retries:\n"
    "            raise RetryError(request)\n"
    "        return self.send(request)\n"
    "\n"
    "config.yaml:\n"
    "outcome: REACHED\n"
    "blocking step: 1\n"
)
_IF = "if request.retries > self.max_retries:"
_RAISE = "raise RetryError(request)"
_RETURN = "return self.send(request)"
_FABRICATED = "totally_fabricated_call(request)"
_DOCSTRING_CITATION = (
    '"""Resolve a request.\n'
    "\n"
    "        Steps:\n"
    "            1. Validate the request.\n"
    "            2. Retry the request.\n"
    "\n"
    "        Example scenario: a retried request.\n"
    "        Outcome: the resolved value.\n"
    "        Note: retries are bounded.\n"
    '        """\n'
    "        # Citation: RFC 9110 section 15.4\n"
    "        note: str = request.note\n"
    "        if request.retries > self.max_retries:"
)
_YAML_CITATION = "config.yaml:\noutcome: REACHED\nblocking step: 1"
_STRUCTURAL_NOTE = "retries exceed the limit for this scenario."


def _step(number, citation, note=_STRUCTURAL_NOTE):
    text = f"{number}. Citation: {citation}\n"
    if note is not None:
        text += f"   Note: {note}\n"
    return text


def _trace(*steps, outcome="BLOCKED", blocking="2", scenario="A request retried past its limit.",
           before="", after=""):
    return (
        f"Example scenario: {scenario}\n\n{before}Trace:\n" + "".join(steps) + "\n"
        + (f"Outcome: {outcome}\n" if outcome is not None else "")
        + (f"Blocking step: {blocking}\n" if blocking is not None else "")
        + after
    )


_MALFORMED_STEP_PREFIXES = ["2) Citation:", "2. citation:", "- 2. Citation:", "**2.** Citation:", "Citation:"]


class TestStructuralResponseContract:

    def _resolve(self, response_text):
        return resolve_concrete_trace(
            concern_role="additional", description="d",
            code_context=_COLLISION_CODE_CONTEXT, patch="", llm=_mock_llm(response_text),
        )

    # --- F1: an attempted step the header pattern misses is never dropped --

    @pytest.mark.parametrize("prefix", _MALFORMED_STEP_PREFIXES)
    def test_malformed_step_with_note_is_validated_not_dropped(self, prefix):
        """Its Note becomes the step's last Note, so the malformed step lands
        inside the previous step's citation -- which must then validate."""
        response = _trace(_step(1, _IF), f"{prefix} {_FABRICATED}\n   Note: n.\n",
                          outcome="REACHED", blocking="none")
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "invalid_trace_citation"

    @pytest.mark.parametrize("prefix", _MALFORMED_STEP_PREFIXES)
    def test_malformed_step_without_note_is_unrecognized(self, prefix):
        response = _trace(_step(1, _IF), f"{prefix} {_FABRICATED}\n", outcome="REACHED", blocking="none")
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "unrecognized_trace_step"

    def test_unnumbered_step_before_first_step_is_unrecognized(self):
        response = _trace(_step(1, _IF), before=f"- Citation: {_FABRICATED}\n   Note: n.\n",
                          outcome="REACHED", blocking="none")
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "unrecognized_trace_step"

    def test_citation_label_after_terminal_fields_is_unrecognized(self):
        response = _trace(_step(1, _IF), _step(2, _RAISE), after=f"Citation: {_FABRICATED}\n")
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "unrecognized_trace_step"

    def test_cited_numbered_list_and_citation_comment_are_not_trace_structure(self):
        """Positive control: `1. ...`/`2. ...` docstring lines and a
        `# Citation:` comment inside a valid citation are citation content."""
        citation = (
            "1. Validate the request.\n"
            "            2. Retry the request.\n"
            "\n"
            "        Example scenario: a retried request.\n"
            "        Outcome: the resolved value.\n"
            "        Note: retries are bounded.\n"
            '        """\n'
            "        # Citation: RFC 9110 section 15.4"
        )
        result = self._resolve(_trace(_step(1, citation), _step(2, _RAISE)))
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"
        assert result["trace_steps"][0]["citation"] == citation

    def test_note_mentioning_citation_without_label_is_accepted(self):
        result = self._resolve(_trace(_step(1, _IF, note="this citation shows the guard."), _step(2, _RAISE)))
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"

    @pytest.mark.parametrize("line", [
        f"2. `{_FABRICATED}`",
        f"2. Citaton: {_FABRICATED}",
        f"2. Сitation: {_FABRICATED}",  # Cyrillic capital Es, not Latin C
        f"- 2. {_FABRICATED}",
        f"2) {_FABRICATED}",
    ], ids=["unlabelled", "misspelled_label", "homoglyph_label", "bulleted", "paren"])
    def test_numbered_step_without_recognizable_label_is_unrecognized(self, line):
        """An attempted step with no recognizable `Citation:` label and no
        Note of its own must not be dropped while REACHED stands."""
        response = _trace(_step(1, _IF), f"{line}\n", outcome="REACHED", blocking="none")
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "unrecognized_trace_step"

    def test_numbers_within_note_and_scenario_lines_are_accepted(self):
        response = _trace(_step(1, _IF, note="2. retries remain, so the guard is false."), _step(2, _RAISE),
                          scenario="A request on its 3. attempt.")
        result = self._resolve(response)
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"

    # --- F2: printed step numbers must be exactly 1..N ---------------------

    @pytest.mark.parametrize("numbers", [(1, 3, 4), (0, 1, 2), (2, 3), (2, 1), (1, 2, 2, 3)])
    def test_step_numbering_other_than_one_to_n_fails_closed(self, numbers):
        citations = [_IF, _RAISE, _RETURN, _IF]
        steps = [_step(n, citations[i]) for i, n in enumerate(numbers)]
        result = self._resolve(_trace(*steps, blocking="2"))
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "trace_step_numbering_invalid"

    def test_step_numbering_one_to_n_is_accepted(self):
        result = self._resolve(_trace(_step(1, _IF), _step(2, _RAISE), _step(3, _RETURN), blocking="2"))
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"
        assert result["blocking_step_index"] == 1

    # --- F3: the citation ends at the step's LAST Note line -----------------

    def test_repository_note_line_inside_citation_is_preserved_in_full(self):
        result = self._resolve(_trace(_step(1, _DOCSTRING_CITATION), _step(2, _RAISE)))
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"
        assert result["trace_steps"][0]["citation"] == _DOCSTRING_CITATION
        assert result["trace_steps"][0]["note"] == _STRUCTURAL_NOTE

    def test_invented_text_after_repository_note_line_is_rejected(self):
        citation = (
            "Note: retries are bounded.\n"
            "        retries = 0  # invented, not in the evidence"
        )
        result = self._resolve(_trace(_step(1, citation), _step(2, _RAISE)))
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "invalid_trace_citation"

    def test_structural_note_is_not_absorbed_into_citation(self):
        parsed = _parse_concrete_trace_response(_trace(_step(1, _DOCSTRING_CITATION), _step(2, _RAISE)))
        assert parsed["structural_error"] is None
        for step in parsed["trace_steps"]:
            assert _STRUCTURAL_NOTE not in step["citation"]
            assert step["note"] == _STRUCTURAL_NOTE

    def test_duplicate_structural_note_fails_closed(self):
        """Neither Note is silently selected: the earlier one becomes part of
        the citation, which then fails provenance."""
        result = self._resolve(_trace(_step(1, _IF, note="first.\n   Note: second."), _step(2, _RAISE)))
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "invalid_trace_citation"

    # --- F4: terminal fields come only from structural text -----------------

    def test_terminal_field_lines_inside_citation_are_ignored(self):
        result = self._resolve(_trace(_step(1, _DOCSTRING_CITATION), _step(2, _RAISE)))
        assert result["outcome"] == "BLOCKED"
        assert result["example_scenario"] == "A request retried past its limit."

    def test_cited_outcome_line_cannot_override_model_unresolved(self):
        result = self._resolve(_trace(_step(1, _YAML_CITATION), outcome="UNRESOLVED", blocking="none"))
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "model_reported_unresolved"

    def test_cited_outcome_line_with_model_blocked_is_accepted(self):
        result = self._resolve(_trace(_step(1, _YAML_CITATION), outcome="BLOCKED", blocking="1"))
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"
        assert result["blocking_step_index"] == 0

    @pytest.mark.parametrize("kwargs", [
        {"after": "Outcome: UNRESOLVED\n"},
        {"outcome": "REACHED", "blocking": "none", "after": "Outcome: BLOCKED\nBlocking step: 2\n"},
        {"after": "Blocking step: 1\n"},
        {"before": "Example scenario: A different scenario.\n"},
    ], ids=["outcome_blocked_then_unresolved", "outcome_reached_then_blocked", "blocking_step", "scenario"])
    def test_duplicate_terminal_field_fails_closed(self, kwargs):
        result = self._resolve(_trace(_step(1, _IF), _step(2, _RAISE), **kwargs))
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "duplicate_terminal_field"

    def test_outcome_line_after_a_note_cannot_create_a_verdict(self):
        """The model's real Outcome is UNRESOLVED; an `Outcome:` line after a
        Note must not win."""
        response = _trace(_step(1, _IF, note="n.\n   Outcome: BLOCKED"), _step(2, _RAISE),
                          outcome="UNRESOLVED", blocking="2")
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "duplicate_terminal_field"

    def test_terminal_field_text_within_a_note_line_is_inert(self):
        response = _trace(_step(1, _IF, note="the guard fires, so Outcome: REACHED is impossible."),
                          _step(2, _RAISE))
        result = self._resolve(response)
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"

    # --- F5: every step has exactly one usable Note --------------------------

    @pytest.mark.parametrize("steps", [
        (_step(1, _IF, note=None), _step(2, _RAISE)),
        (_step(1, _IF, note=""), _step(2, _RAISE)),
        (_step(1, _IF, note="none"), _step(2, _RAISE)),
        (_step(1, _IF), _step(2, _RAISE, note=None)),
    ], ids=["missing_middle", "empty_middle", "placeholder_middle", "missing_last"])
    def test_step_without_usable_note_fails_closed(self, steps):
        result = self._resolve(_trace(*steps))
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "trace_step_note_missing"

    # --- F6: scalar fields are read from their own line only ----------------

    def test_blank_example_scenario_does_not_consume_next_line(self):
        response = "Example scenario:\nTrace:\n" + _step(1, _IF) + _step(2, _RAISE) + "\nOutcome: BLOCKED\nBlocking step: 2\n"
        assert _parse_concrete_trace_response(response)["example_scenario"] == ""
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "example_scenario_blank_or_missing"

    def test_blank_outcome_does_not_consume_next_line(self):
        response = _trace(_step(1, _IF), _step(2, _RAISE), outcome=None, blocking=None,
                          after="Outcome:\nBLOCKED\nBlocking step: 2\n")
        result = self._resolve(response)
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == "outcome_outside_enum"

    def test_crlf_line_endings_are_accepted(self):
        response = _trace(_step(1, _DOCSTRING_CITATION), _step(2, _RAISE)).replace("\n", "\r\n")
        result = self._resolve(response)
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"
        assert result["blocking_step_index"] == 1

    # --- Blocking-step values and pinned tolerances --------------------------

    @pytest.mark.parametrize("blocking, reason", [
        ("0", "blocking_index_out_of_range"),
        ("-1", "blocking_index_out_of_range"),
        ("step 2", "blocking_index_not_integer"),
        ("`2`", "blocking_index_not_integer"),
    ])
    def test_invalid_blocking_step_values_fail_closed(self, blocking, reason):
        result = self._resolve(_trace(_step(1, _IF), _step(2, _RAISE), blocking=blocking))
        assert result["outcome"] == "UNRESOLVED"
        assert result["invalid_reason"] == reason

    def test_lowercase_outcome_is_an_accepted_tolerance(self):
        result = self._resolve(_trace(_step(1, _IF), _step(2, _RAISE), outcome="blocked"))
        assert result["invalid_reason"] is None
        assert result["outcome"] == "BLOCKED"


# ---------------------------------------------------------------------------
# Reachability-challenge prompt contract. Pins ONLY the wording of
# prompts/concrete_trace.md's task instructions -- no model behavior is
# tested, and nothing here is enforced by the parser/validator. The
# contract: before claiming a later consequential operation is reached,
# account for decisions on the concrete route that could prevent it --
# NOT enumerate every executed statement or syntactic decision.
# ---------------------------------------------------------------------------

def _normalized_prompt() -> str:
    from utilities.autopatcher.concrete_trace import _PROMPT_PATH
    return " ".join(_PROMPT_PATH.read_text(encoding="utf-8").split())


class TestReachabilityChallengePromptContract:

    def test_1_requires_reachability_challenge_before_advancing(self):
        prompt = _normalized_prompt()
        assert (
            "Before advancing from your current established point to a proposed "
            "later consequential operation, challenge that transition"
        ) in prompt
        assert "what, if anything, could prevent that operation from being reached?" in prompt

    def test_2_requires_accounting_for_intervening_preventing_decision(self):
        prompt = _normalized_prompt()
        assert (
            "Account for each such decision as its own step, before the operation "
            "it could prevent, evaluated with THIS scenario's own concrete values"
        ) in prompt

    def test_3_preventing_decision_is_blocked(self):
        assert "if it prevents the operation, stop there with `BLOCKED`" in _normalized_prompt()

    def test_4_undeterminable_decision_is_unresolved(self):
        assert (
            "if the evidence cannot establish whether execution gets past it, "
            "stop there with `UNRESOLVED`"
        ) in _normalized_prompt()

    def test_5_challenge_applies_within_each_call_or_recursive_invocation(self):
        prompt = _normalized_prompt()
        assert "A call or recursive call starts a new invocation with its own route." in prompt
        assert "apply the same challenge from that invocation's own entry" in prompt
        assert "a decision you evaluated in an earlier invocation does not carry over" in prompt
        assert "because a caller invokes the function containing it" in prompt

    def test_6_does_not_require_enumerating_every_statement_or_decision(self):
        prompt = _normalized_prompt()
        assert (
            "You do not need to cite every statement, call, assignment, or branch "
            "that executes in between."
        ) in prompt
        assert (
            "A decision that cannot prevent that particular operation from being "
            "reached on this route needs no step"
        ) in prompt
        # Supporting statements are an allowance, never a requirement.
        assert (
            "You may cite a supporting statement when its value is needed to evaluate "
            "whether a later decision permits the proposed operation to be reached."
        ) in prompt
        # The superseded next-execution discipline is gone.
        assert "very next statement" not in prompt
        assert "one actual execution step at a time" not in prompt

    def test_prompt_contract_is_generic(self):
        prompt = _normalized_prompt().lower()
        for specific in ("urllib3", "urlopen", "assert_same_host", "is_same_host",
                         "hostchangederror", "_make_request", "cookie"):
            assert specific not in prompt
