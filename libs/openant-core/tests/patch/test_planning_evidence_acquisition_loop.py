"""Tests for bounded iterative Planning evidence acquisition ("Fix A") --
the structured `additional_evidence_required`/`evidence_requests` contract
on `RemediationPlanResult`, deterministic request resolution, the bounded
acquisition loop (`remediation_planner.run_planning_evidence_acquisition`),
and its pipeline.py wiring (`_planning_forced_skip`/`_planning_skip_reason`
propagation, S1/S2/S3 outcome provenance, Plan-Verification-only-after-
grounded-Planning ordering).

Layered like this codebase's other bounded-loop test suites (see
test_evidence_gap_strategy_fallback.py, test_planner_claim_verifier_
orchestration.py):

- Pure unit tests of the parsing/gate/resolution primitives -- fast,
  isolated, no LLM, no repository machinery.
- Direct tests of `run_planning_evidence_acquisition` itself, with a
  mocked `llm` and a real on-disk `tmp_path` repo (so file/symbol
  resolution exercises real code, not a stand-in).
- Full `pipeline.run()` / `_run_repository_analysis_and_remediation_
  planning` wiring tests, mocking `remediation_planner.<name>` at SOURCE
  (never `pipeline.<name>` -- these are local, function-body imports
  inside pipeline.py, so only a source-module patch is actually seen).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from utilities.autopatcher import pipeline as pipeline_mod
from utilities.autopatcher.remediation_planner import (
    MAX_EVIDENCE_REQUESTS_PER_ROUND,
    MAX_PLANNING_ATTEMPTS,
    PlanningEvidenceRequest,
    RemediationPlanResult,
    _parse_additional_evidence_required,
    _planning_gate_outcome,
    _planning_request_key,
    _resolve_planning_evidence_request,
    _validate_planning_request_schema,
    run_planning_evidence_acquisition,
)

_VULN_TEXT = "# Test vulnerability\n\nSome description of a vulnerability for testing.\n"

_WELL_FORMED_BASE = {
    "remediation_mechanism": "Strip the sensitive header before the unsafe transition.",
    "target_files": [],
    "target_symbols": [],
    "security_invariant": "The sensitive header must not cross the unsafe boundary.",
    "narrower_alternative_decision": "NONE_IDENTIFIED",
    "narrower_alternative_considered": None,
    "required_edits": ["add the guard"],
    "approaches_to_avoid": [],
    "explicit_unknowns": [],
}


def _make_context(functions=None, constants=None, repo_path=None):
    """A real (not mocked) InvestigationContext -- see test_remediation_
    planner.py's own identical helper; duplicated here (rather than
    imported) since these are independent, self-contained test modules
    following this codebase's own "each test file owns its local
    builders" convention."""
    from utilities.agentic_enhancer.reachability_analyzer import ReachabilityAnalyzer
    from utilities.agentic_enhancer.repository_index import RepositoryIndex
    from utilities.autopatcher.candidate_enrichment import InvestigationContext

    functions = functions or {}
    index = RepositoryIndex({"functions": functions}, repo_path=str(repo_path) if repo_path else None)
    reachability = ReachabilityAnalyzer(functions, {}, set())
    return InvestigationContext(
        index=index, call_graph={}, reverse_call_graph={},
        reachability=reachability, constants=constants or {},
    )


def _plan(gate="missing", requests=(), **overrides):
    defaults = dict(rendered="", target_files=[], target_symbols=[])
    defaults.update(overrides)
    return RemediationPlanResult(
        additional_evidence_required=gate, evidence_requests=list(requests), **defaults,
    )


def _req(request_type="file_source", file_hint=None, symbol=None, reason="need it"):
    return PlanningEvidenceRequest(request_type=request_type, file_hint=file_hint, symbol=symbol, reason=reason)


def _response(gate, requests=()):
    """A well-formed Planner JSON response string with the given gate
    value/evidence_requests -- `gate` is a real JSON bool/None, matching
    what the model actually emits (never the parsed "explicit_false"-style
    string)."""
    body = dict(_WELL_FORMED_BASE)
    body["additional_evidence_required"] = gate
    body["evidence_requests"] = list(requests)
    return json.dumps(body)


# ---------------------------------------------------------------------------
# _parse_additional_evidence_required -- the four gate states
# ---------------------------------------------------------------------------

class TestParseAdditionalEvidenceRequired:
    def test_missing_key(self):
        assert _parse_additional_evidence_required({}) == "missing"

    def test_explicit_false(self):
        assert _parse_additional_evidence_required({"additional_evidence_required": False}) == "explicit_false"

    def test_explicit_true(self):
        assert _parse_additional_evidence_required({"additional_evidence_required": True}) == "explicit_true"

    def test_explicit_null_is_malformed(self):
        assert _parse_additional_evidence_required({"additional_evidence_required": None}) == "malformed"

    def test_wrong_type_string_is_malformed(self):
        assert _parse_additional_evidence_required({"additional_evidence_required": "false"}) == "malformed"

    def test_wrong_type_number_is_malformed(self):
        assert _parse_additional_evidence_required({"additional_evidence_required": 0}) == "malformed"


# ---------------------------------------------------------------------------
# _validate_planning_request_schema -- shape only, never repository state
# ---------------------------------------------------------------------------

class TestValidatePlanningRequestSchema:
    def test_valid_file_source(self):
        assert _validate_planning_request_schema(_req("file_source", file_hint="a.py")) is None

    def test_file_source_missing_file_hint(self):
        assert _validate_planning_request_schema(_req("file_source")) == "missing_required_field"

    def test_valid_symbol_definition(self):
        assert _validate_planning_request_schema(_req("symbol_definition", symbol="foo")) is None

    def test_symbol_definition_missing_symbol(self):
        assert _validate_planning_request_schema(_req("symbol_definition")) == "missing_required_field"

    def test_unsupported_request_type(self):
        assert _validate_planning_request_schema(_req("enclosing_symbol", symbol="foo")) == "unsupported_request_type"

    def test_none_request_type(self):
        assert _validate_planning_request_schema(_req(None)) == "unsupported_request_type"


# ---------------------------------------------------------------------------
# _planning_gate_outcome -- the full authority truth table, per the
# approved final correction: only explicit_false+[] certifies grounded;
# only explicit_true+[>=1 valid] continues; EVERY other combination fails
# closed with its own distinct, machine-readable reason -- never
# reinterpreted by giving one field precedence over the other.
# ---------------------------------------------------------------------------

class TestPlanningGateOutcomeTruthTable:
    def test_explicit_false_empty_requests_is_grounded(self):
        assert _planning_gate_outcome(_plan("explicit_false", [])) == (True, [], "grounded")

    def test_explicit_true_with_valid_request_continues(self):
        req = _req("file_source", file_hint="a.py")
        grounded, actionable, reason = _planning_gate_outcome(_plan("explicit_true", [req]))
        assert grounded is False
        assert actionable == [req]
        assert reason == "continue"

    def test_explicit_false_with_requests_never_reinterpreted_as_continue(self):
        req = _req("file_source", file_hint="a.py")
        result = _planning_gate_outcome(_plan("explicit_false", [req]))
        assert result == (False, [], "contradictory_false_with_requests")

    def test_explicit_true_with_zero_requests_fails_closed(self):
        result = _planning_gate_outcome(_plan("explicit_true", []))
        assert result == (False, [], "no_actionable_requests_declared_insufficient")

    def test_explicit_true_with_only_invalid_requests_fails_closed(self):
        bad = _req("file_source")  # missing file_hint -> schema-invalid
        result = _planning_gate_outcome(_plan("explicit_true", [bad]))
        assert result == (False, [], "no_actionable_requests_declared_insufficient")

    def test_missing_gate_empty_requests_fails_closed(self):
        assert _planning_gate_outcome(_plan("missing", [])) == (False, [], "missing_gate")

    def test_missing_gate_with_valid_requests_still_fails_closed(self):
        # The critical final-correction case: a request list never
        # "rescues" a missing gate into "continue" -- only an EXPLICIT
        # true may authorize acquisition.
        req = _req("file_source", file_hint="a.py")
        result = _planning_gate_outcome(_plan("missing", [req]))
        assert result == (False, [], "missing_gate")

    def test_malformed_gate_empty_requests_fails_closed(self):
        assert _planning_gate_outcome(_plan("malformed", [])) == (False, [], "malformed_gate")

    def test_malformed_gate_with_valid_requests_still_fails_closed(self):
        req = _req("file_source", file_hint="a.py")
        result = _planning_gate_outcome(_plan("malformed", [req]))
        assert result == (False, [], "malformed_gate")

    def test_mixed_valid_and_invalid_requests_uses_only_valid_subset(self):
        good = _req("file_source", file_hint="a.py")
        bad = _req("symbol_definition")  # missing symbol
        grounded, actionable, reason = _planning_gate_outcome(_plan("explicit_true", [good, bad]))
        assert grounded is False
        assert actionable == [good]
        assert reason == "continue"


# ---------------------------------------------------------------------------
# _planning_request_key -- cross-round duplicate-detection identity
# ---------------------------------------------------------------------------

class TestPlanningRequestKey:
    def test_file_source_key_normalizes_case_and_whitespace(self):
        a = _req("file_source", file_hint=" A.PY ")
        b = _req("file_source", file_hint="a.py")
        assert _planning_request_key(a) == _planning_request_key(b)

    def test_symbol_definition_key_distinguishes_by_file_hint(self):
        a = _req("symbol_definition", symbol="Foo", file_hint="a.py")
        b = _req("symbol_definition", symbol="Foo", file_hint="b.py")
        assert _planning_request_key(a) != _planning_request_key(b)

    def test_file_source_and_symbol_definition_never_collide(self):
        a = _req("file_source", file_hint="foo")
        b = _req("symbol_definition", symbol="foo")
        assert _planning_request_key(a) != _planning_request_key(b)


# ---------------------------------------------------------------------------
# _resolve_planning_evidence_request -- deterministic resolution, no LLM,
# entirely independent of any character budget
# ---------------------------------------------------------------------------

class TestResolvePlanningEvidenceRequest:
    def test_file_source_resolves_existing_file(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        rf, rs, reason = _resolve_planning_evidence_request(
            _req("file_source", file_hint="a.py"), tmp_path, None,
        )
        assert (rf, rs, reason) == ("a.py", None, None)

    def test_file_source_unresolved_for_missing_file(self, tmp_path):
        rf, rs, reason = _resolve_planning_evidence_request(
            _req("file_source", file_hint="does_not_exist.py"), tmp_path, None,
        )
        assert rf is None and reason == "unresolved_file"

    def test_file_source_unresolved_for_unsafe_path(self, tmp_path):
        rf, rs, reason = _resolve_planning_evidence_request(
            _req("file_source", file_hint="../outside.py"), tmp_path, None,
        )
        assert rf is None and reason == "unresolved_file"

    def test_symbol_definition_resolves_unique_symbol(self, tmp_path):
        (tmp_path / "a.py").write_text("def foo():\n    pass\n", encoding="utf-8")
        context = _make_context(
            functions={"a.py:foo": {"name": "foo", "startLine": 1, "endLine": 2}}, repo_path=tmp_path,
        )
        rf, rs, reason = _resolve_planning_evidence_request(
            _req("symbol_definition", symbol="foo"), tmp_path, context,
        )
        assert rf == "a.py" and rs == "foo" and reason is None

    def test_symbol_definition_ambiguous_across_files_fails_closed(self, tmp_path):
        (tmp_path / "a.py").write_text("def foo():\n    pass\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("def foo():\n    pass\n", encoding="utf-8")
        context = _make_context(functions={
            "a.py:foo": {"name": "foo", "startLine": 1, "endLine": 2},
            "b.py:foo": {"name": "foo", "startLine": 1, "endLine": 2},
        }, repo_path=tmp_path)
        rf, rs, reason = _resolve_planning_evidence_request(
            _req("symbol_definition", symbol="foo"), tmp_path, context,
        )
        assert rf is None and reason == "ambiguous_symbol"

    def test_symbol_definition_unresolved_when_absent(self, tmp_path):
        context = _make_context(functions={}, repo_path=tmp_path)
        rf, rs, reason = _resolve_planning_evidence_request(
            _req("symbol_definition", symbol="nonexistent"), tmp_path, context,
        )
        assert rf is None and reason == "unresolved_symbol"

    def test_symbol_definition_cross_file_mismatch(self, tmp_path):
        # cross_file_mismatch fires specifically when the symbol STRING
        # itself carries an embedded file component that CONTRADICTS a
        # separately-given file_hint -- not merely "not found in that
        # file" (that's unresolved_symbol; see _resolve_guided_symbol's
        # own docstring).
        (tmp_path / "a.py").write_text("def foo():\n    pass\n", encoding="utf-8")
        context = _make_context(
            functions={"a.py:foo": {"name": "foo", "startLine": 1, "endLine": 2}}, repo_path=tmp_path,
        )
        rf, rs, reason = _resolve_planning_evidence_request(
            _req("symbol_definition", symbol="a.py:foo", file_hint="b.py"), tmp_path, context,
        )
        assert rf is None and reason == "cross_file_mismatch"

    def test_symbol_definition_not_found_in_hinted_file_is_unresolved(self, tmp_path):
        (tmp_path / "a.py").write_text("def foo():\n    pass\n", encoding="utf-8")
        context = _make_context(
            functions={"a.py:foo": {"name": "foo", "startLine": 1, "endLine": 2}}, repo_path=tmp_path,
        )
        rf, rs, reason = _resolve_planning_evidence_request(
            _req("symbol_definition", symbol="foo", file_hint="b.py"), tmp_path, context,
        )
        assert rf is None and reason == "unresolved_symbol"


# ---------------------------------------------------------------------------
# run_planning_evidence_acquisition -- the bounded state machine
# ---------------------------------------------------------------------------

class TestRunPlanningEvidenceAcquisition:
    def test_grounded_on_first_attempt_single_llm_call(self, tmp_path):
        llm = mock.MagicMock()
        llm.complete.return_value = _response(False, [])
        result = run_planning_evidence_acquisition(
            "vuln", llm, str(tmp_path), None, base_evidence="baseline context",
        )
        assert result.grounded is True
        assert result.terminal_state == "grounded"
        assert llm.complete.call_count == 1
        assert len(result.attempts) == 1
        assert result.attempts[0].llm_tag == "remediation_planning"
        assert result.attempts[0].gate_state == "explicit_false"
        # Attempt 1's code_context must be base_evidence UNCHANGED -- see
        # _render_planning_acquisition_context's own docstring on why the
        # common "grounded immediately" case must be byte-identical to
        # pre-Fix-A behavior.
        _, kwargs = llm.complete.call_args
        assert "baseline context" in llm.complete.call_args[0][1]

    def test_finalize_also_verifies_final_plans_own_target_files(self, tmp_path):
        # A plan that finalizes WITHOUT ever using evidence_requests (the
        # common, everyday case) must still verify its own target_files --
        # exactly what pre-Fix-A Planning always did.
        (tmp_path / "own_target.py").write_text("x = 1\n", encoding="utf-8")
        llm = mock.MagicMock()
        body = dict(_WELL_FORMED_BASE)
        body["additional_evidence_required"] = False
        body["evidence_requests"] = []
        body["target_files"] = ["own_target.py"]
        llm.complete.return_value = json.dumps(body)
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="")
        assert result.grounded is True
        assert "own_target.py" in result.planner_evidence_result.rendered

    def test_one_successful_evidence_acquisition_round_then_grounded(self, tmp_path):
        (tmp_path / "needed.py").write_text("x = 1\n", encoding="utf-8")
        llm = mock.MagicMock()
        llm.complete.side_effect = [
            _response(True, [{"request_type": "file_source", "file_hint": "needed.py", "reason": "need it"}]),
            _response(False, []),
        ]
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="ctx")
        assert result.grounded is True
        assert llm.complete.call_count == 2
        assert result.attempts[0].outcome == "continue"
        assert result.attempts[1].llm_tag == "remediation_planning_reattempt"
        assert result.attempts[1].outcome == "grounded"
        assert "needed.py" in result.planner_evidence_result.rendered
        # The successful resolution is recorded on attempt 1.
        assert len(result.attempts[0].resolutions) == 1
        assert result.attempts[0].resolutions[0].resolved is True
        assert result.attempts[0].resolutions[0].resolved_file == "needed.py"

    def test_multiple_bounded_rounds_preserve_evidence_monotonically(self, tmp_path):
        (tmp_path / "a.py").write_text("alpha = 1\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("beta = 1\n", encoding="utf-8")
        llm = mock.MagicMock()
        llm.complete.side_effect = [
            _response(True, [{"request_type": "file_source", "file_hint": "a.py", "reason": "r1"}]),
            _response(True, [{"request_type": "file_source", "file_hint": "b.py", "reason": "r2"}]),
            _response(False, []),
        ]
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="")
        assert result.grounded is True
        assert llm.complete.call_count == 3
        # Evidence preservation: round 2's evidence must not have dropped
        # round 1's already-acquired evidence.
        assert "a.py" in result.planner_evidence_result.rendered
        assert "b.py" in result.planner_evidence_result.rendered
        assert "alpha" in result.planner_evidence_result.rendered
        assert "beta" in result.planner_evidence_result.rendered
        # Round 2's own prompt must show round 1's evidence was already
        # supplied (monotonic carry-forward into code_context).
        round_2_user_message = llm.complete.call_args_list[1][0][1]
        assert "a.py" in round_2_user_message

    def test_round_limit_reached_fails_closed_never_exceeds_max_attempts(self, tmp_path):
        for name in ("a.py", "b.py", "c.py"):
            (tmp_path / name).write_text("x = 1\n", encoding="utf-8")
        llm = mock.MagicMock()
        llm.complete.side_effect = [
            _response(True, [{"request_type": "file_source", "file_hint": "a.py", "reason": "r1"}]),
            _response(True, [{"request_type": "file_source", "file_hint": "b.py", "reason": "r2"}]),
            _response(True, [{"request_type": "file_source", "file_hint": "c.py", "reason": "r3"}]),
        ]
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="")
        assert result.grounded is False
        assert result.terminal_state == "ungrounded_max_attempts"
        assert llm.complete.call_count == MAX_PLANNING_ATTEMPTS
        assert len(result.attempts) == MAX_PLANNING_ATTEMPTS
        # Reaching the round limit must NOT silently promote the
        # hypothesis: the un-grounded final plan is still returned for
        # observability, but `grounded` stays False.
        assert result.plan_result.additional_evidence_required == "explicit_true"

    def test_unresolved_request_fails_closed_without_spending_extra_round(self, tmp_path):
        llm = mock.MagicMock()
        llm.complete.return_value = _response(
            True, [{"request_type": "file_source", "file_hint": "does_not_exist.py", "reason": "need it"}],
        )
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="")
        assert result.grounded is False
        assert result.terminal_state == "ungrounded_unresolvable"
        assert llm.complete.call_count == 1
        assert result.attempts[0].resolutions[0].failure_reason == "unresolved_file"

    def test_ambiguous_request_fails_closed(self, tmp_path):
        (tmp_path / "a.py").write_text("def foo():\n    pass\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("def foo():\n    pass\n", encoding="utf-8")
        context = _make_context(functions={
            "a.py:foo": {"name": "foo", "startLine": 1, "endLine": 2},
            "b.py:foo": {"name": "foo", "startLine": 1, "endLine": 2},
        }, repo_path=tmp_path)
        llm = mock.MagicMock()
        llm.complete.return_value = _response(
            True, [{"request_type": "symbol_definition", "symbol": "foo", "reason": "need it"}],
        )
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), context, base_evidence="")
        assert result.grounded is False
        assert result.terminal_state == "ungrounded_unresolvable"
        assert result.attempts[0].resolutions[0].failure_reason == "ambiguous_symbol"

    def test_duplicate_request_in_later_round_not_re_resolved(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        llm = mock.MagicMock()
        llm.complete.side_effect = [
            _response(True, [{"request_type": "file_source", "file_hint": "a.py", "reason": "r1"}]),
            # Round 2 repeats the SAME already-resolved request -- must be
            # recognized as a duplicate and never re-resolved; since it is
            # the ONLY request this round, no new evidence is gained and
            # acquisition must fail closed rather than loop again.
            _response(True, [{"request_type": "file_source", "file_hint": "a.py", "reason": "still need it"}]),
        ]
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="")
        assert result.grounded is False
        assert result.terminal_state == "ungrounded_unresolvable"
        assert llm.complete.call_count == 2
        round_2_resolution = result.attempts[1].resolutions[0]
        assert round_2_resolution.resolved is False
        assert round_2_resolution.failure_reason == "duplicate_request"

    def test_declares_insufficient_with_no_requests_fails_closed_immediately(self, tmp_path):
        # additional_evidence_required=true with an EMPTY evidence_requests
        # list -- nothing actionable was even named. Must fail closed on
        # attempt 1 without ever attempting resolution.
        llm = mock.MagicMock()
        llm.complete.return_value = _response(True, [])
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="")
        assert result.grounded is False
        assert result.terminal_state == "ungrounded_no_actionable_requests_declared_insufficient"
        assert llm.complete.call_count == 1
        assert result.attempts[0].resolutions == []

    def test_missing_gate_fails_closed_immediately(self, tmp_path):
        # A response that omits additional_evidence_required entirely
        # (old-format / non-compliant model output) -- must never be
        # silently treated as grounded.
        llm = mock.MagicMock()
        body = dict(_WELL_FORMED_BASE)
        llm.complete.return_value = json.dumps(body)  # no additional_evidence_required key at all
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="")
        assert result.grounded is False
        assert result.terminal_state == "ungrounded_missing_gate"

    def test_unparseable_response_fails_closed(self, tmp_path):
        llm = mock.MagicMock()
        llm.complete.return_value = "not json at all"
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="")
        assert result.grounded is False
        assert result.terminal_state == "ungrounded_missing_gate"
        assert llm.complete.call_count == 1

    def test_requests_beyond_per_round_cap_are_ignored_this_round(self, tmp_path):
        for i in range(MAX_EVIDENCE_REQUESTS_PER_ROUND + 2):
            (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")
        requests = [
            {"request_type": "file_source", "file_hint": f"f{i}.py", "reason": "r"}
            for i in range(MAX_EVIDENCE_REQUESTS_PER_ROUND + 2)
        ]
        llm = mock.MagicMock()
        llm.complete.side_effect = [_response(True, requests), _response(False, [])]
        result = run_planning_evidence_acquisition("vuln", llm, str(tmp_path), None, base_evidence="")
        assert len(result.attempts[0].resolutions) == MAX_EVIDENCE_REQUESTS_PER_ROUND


# ---------------------------------------------------------------------------
# Upstream-knowledge isolation -- minimal prompt hardening (Section 8 of
# the approved design). Simple content assertions: this test suite cannot
# exercise a real model's compliance, only that the prohibition text
# actually exists in the shipped prompt.
# ---------------------------------------------------------------------------

class TestUpstreamKnowledgeIsolationPromptHardening:
    def _read(self, name):
        from pathlib import Path
        return (Path(__file__).parent.parent.parent / "utilities" / "autopatcher" / "prompts" / name).read_text(
            encoding="utf-8"
        )

    def test_remediation_planner_prompt_prohibits_remembered_upstream_fix(self):
        text = self._read("remediation_planner.md")
        assert "remembered" in text.lower()
        assert "upstream patch" in text.lower()
        assert "additional_evidence_required" in text
        assert "evidence_requests" in text

    def test_remediation_strategy_prompt_prohibits_remembered_upstream_fix(self):
        text = self._read("remediation_strategy.md")
        assert "remembered" in text.lower()

    def test_remediation_verifier_prompt_prohibits_remembered_upstream_fix(self):
        text = self._read("remediation_verifier.md")
        assert "remembered" in text.lower()


# ---------------------------------------------------------------------------
# pipeline.py wiring: _planning_forced_skip/_planning_skip_reason
# propagation into S1/S2/S3 outcome provenance, and the authority boundary
# (Strategy/Patch Generation never run when Planning is ungrounded).
#
# `generate_remediation_plan`/`verify_planner_claim`/`generate_remediation_
# strategy` are mocked at their SOURCE modules -- all three are local
# (function-body) imports inside pipeline.py, so mocking `pipeline.<name>`
# would not intercept them (same discipline as every other full-pipeline
# test file in this suite).
# ---------------------------------------------------------------------------

def _strategy_result(**overrides):
    from utilities.autopatcher.remediation_planner import RemediationStrategyResult

    defaults = dict(
        rendered="## Final Strategy\n", target_files=[], target_symbols=[], warnings=[],
        extended_mechanism="the mechanism", required_edits=["edit"], evaluated=True,
    )
    defaults.update(overrides)
    return RemediationStrategyResult(**defaults)


class TestPipelineProvenanceWhenPlanningUngrounded:
    def _run_with_recorder(self, tmp_path, plan_return_value):
        from utilities.autopatcher.execution_recorder import ExecutionRecorder

        recorder = ExecutionRecorder(
            call_log=[], run_dir=str(tmp_path / "run"), artifacts_dir=tmp_path / "run" / "executions",
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                return_value=plan_return_value,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
            ) as spy_strategy,
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path), execution_recorder=recorder,
            )
        outcomes = {e["canonical_stage"]: e["outcome"] for e in recorder.executions}
        return outcomes, spy_strategy

    def test_declared_insufficient_no_requests_produces_planning_ungrounded_provenance(self, tmp_path):
        plan = _plan(gate="explicit_true", requests=[], target_files=[], target_symbols=[])
        outcomes, spy_strategy = self._run_with_recorder(tmp_path, plan)
        assert outcomes["repository_analysis_and_remediation_planning"] == "planning_ungrounded"
        assert outcomes["remediation_strategy"] == "skipped_planning_ungrounded"
        assert outcomes["guided_context_acquisition"] == "skipped_planning_ungrounded"
        spy_strategy.assert_not_called()

    def test_missing_gate_produces_planning_ungrounded_provenance(self, tmp_path):
        # additional_evidence_required entirely absent (old-format /
        # non-compliant model output) must fail closed the same way --
        # never silently promoted to "generated" just because a
        # RemediationPlanResult object exists.
        plan = RemediationPlanResult(rendered="some plan text", target_files=[], target_symbols=[])
        outcomes, spy_strategy = self._run_with_recorder(tmp_path, plan)
        assert outcomes["repository_analysis_and_remediation_planning"] == "planning_ungrounded"
        assert outcomes["remediation_strategy"] == "skipped_planning_ungrounded"
        spy_strategy.assert_not_called()

    def test_skip_reason_reaches_patch_generation_skip(self, tmp_path):
        from utilities.autopatcher.execution_recorder import ExecutionRecorder
        import json as _json

        plan = _plan(gate="explicit_true", requests=[])
        recorder = ExecutionRecorder(
            call_log=[], run_dir=str(tmp_path / "run"), artifacts_dir=tmp_path / "run" / "executions",
        )
        with mock.patch(
            "utilities.autopatcher.remediation_planner.generate_remediation_plan", return_value=plan,
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path), execution_recorder=recorder,
            )
        s4 = next(e for e in recorder.executions if e["canonical_stage"] == "patch_generation_and_post_patch_investigation")
        assert s4["outcome"] == "no_candidate_patch"


class TestPipelineExistingBehaviorRegressionWhenGrounded:
    """A plan that certifies grounded on attempt 1 (the common, everyday
    case -- explicit `false` + empty evidence_requests) must proceed to
    Strategy exactly as pre-Fix-A Planning always did."""

    def test_grounded_plan_reaches_strategy(self, tmp_path):
        from utilities.autopatcher.execution_recorder import ExecutionRecorder

        target = tmp_path / "target.py"
        target.write_text("def foo():\n    pass\n", encoding="utf-8")
        plan = _plan(gate="explicit_false", requests=[], target_files=["target.py"], target_symbols=[])
        recorder = ExecutionRecorder(
            call_log=[], run_dir=str(tmp_path / "run"), artifacts_dir=tmp_path / "run" / "executions",
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan", return_value=plan,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=_strategy_result(target_files=["target.py"]),
            ) as spy_strategy,
        ):
            pipeline_mod.run(
                vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path), execution_recorder=recorder,
            )
        outcomes = {e["canonical_stage"]: e["outcome"] for e in recorder.executions}
        assert outcomes["repository_analysis_and_remediation_planning"] == "generated"
        assert outcomes["remediation_strategy"] == "generated"
        spy_strategy.assert_called_once()


class TestVerificationOnlyAfterGroundedPlanning:
    """Plan Verification must never run at all when Planning's own
    acquisition loop never reached a grounded terminal state -- see
    run_planning_evidence_acquisition's own docstring and the approved
    design's Section 7 (Plan Verification interaction)."""

    def test_verify_planner_claim_never_called_when_ungrounded(self, tmp_path):
        # A narrower_alternative_decision of "REJECTED" with non-empty
        # narrative WOULD normally trigger verification dispatch -- this
        # proves the ungrounded check happens strictly BEFORE that
        # dispatch, not merely that verification happens to not trigger.
        plan = _plan(
            gate="explicit_true", requests=[], target_files=[], target_symbols=[],
            narrower_alternative_decision="REJECTED",
            narrower_alternative_considered="considered a narrower mechanism, rejected because X",
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan", return_value=plan,
            ),
            mock.patch(
                "utilities.autopatcher.remediation_verifier.verify_planner_claim",
            ) as spy_verify,
        ):
            result = pipeline_mod._run_repository_analysis_and_remediation_planning(
                vulnerability_text=_VULN_TEXT, repo_root=str(tmp_path),
                investigation_output_dir=None, llm=mock.MagicMock(),
            )
        spy_verify.assert_not_called()
        assert result["_planning_forced_skip"] is True
        assert result["_active_verifier_result"] is None


class TestPostRevisionGroundingGate:
    """The SAME evidence-sufficiency gate that gates v1 before Verification
    ever runs must ALSO gate a post-revision (v2) plan -- see the approved
    design's Section 7: 'apply the same gate uniformly to whichever plan
    ends up authoritative, v1 or v2'."""

    def test_ungrounded_v2_after_contradicted_revision_fails_closed(self, tmp_path):
        from utilities.autopatcher.remediation_verifier import VerifierResult

        def _verdict(status, **kw):
            defaults = dict(
                reason="because", contradiction=None, failure_kind=None, evaluated=True,
                counterexample_reaches_unsafe_state=None,
                authoritative_remediation_matches_selected_alternative=None,
            )
            defaults.update(kw)
            return VerifierResult(status=status, **defaults)

        target = tmp_path / "target.py"
        target.write_text("def foo():\n    pass\n", encoding="utf-8")
        v1 = _plan(
            gate="explicit_false", requests=[], target_files=["target.py"], target_symbols=[],
            narrower_alternative_decision="REJECTED",
            narrower_alternative_considered="considered a narrower mechanism, rejected because X",
        )
        # v2 (the revision's own response) explicitly declares evidence
        # insufficient with nothing actionable named -- must fail closed
        # even though it successfully resolved v1's CONTRADICTED coherence
        # issue.
        v2 = _plan(
            gate="explicit_true", requests=[], target_files=["target.py"], target_symbols=[],
            narrower_alternative_decision="REJECTED",
            narrower_alternative_considered="revised narrower-alternative reasoning",
            rendered="## revised plan\n",
        )
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                side_effect=[v1, v2],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_verifier.verify_planner_claim",
                side_effect=[
                    _verdict("CONTRADICTED", contradiction="the guard was ignored"),
                    _verdict("SUPPORTED", authoritative_remediation_matches_selected_alternative=None),
                ],
            ),
        ):
            result = pipeline_mod._run_repository_analysis_and_remediation_planning(
                vulnerability_text=_VULN_TEXT, repo_root=str(tmp_path),
                investigation_output_dir=None, llm=mock.MagicMock(),
            )
        assert result["_plan_authority_version"] == "v2"
        assert result["_planning_forced_skip"] is True
        assert result["_planner_evidence_ctx"] == ""
        assert result["_planner_evidence_result"] is None
        assert "ungrounded_post_revision" in result["_planning_terminal_state"]


# ---------------------------------------------------------------------------
# Replay behavior: production and replay must share the exact same
# executor function objects (Planning's new loop lives inside the SAME
# shared executor, so replay gets it "for free" -- no new replay-only
# code path was introduced).
# ---------------------------------------------------------------------------

class TestProductionAndReplayShareTheSamePlanningExecutor:
    def test_s1_executor_identity(self):
        from utilities.autopatcher import replay_engine as replay_engine_mod

        assert (
            replay_engine_mod._run_repository_analysis_and_remediation_planning
            is pipeline_mod._run_repository_analysis_and_remediation_planning
        )

    def test_s3_executor_identity_still_unchanged(self):
        # Not touched by this change -- regression guard that Fix A's S3
        # wiring (new kwargs with defaults) didn't accidentally break the
        # existing production/replay identity.
        from utilities.autopatcher import replay_engine as replay_engine_mod

        assert (
            replay_engine_mod._run_guided_context_acquisition
            is pipeline_mod._run_guided_context_acquisition
        )

    def test_replay_s1_outcome_matches_production_vocabulary(self, tmp_path):
        from utilities.autopatcher import replay_engine as replay_engine_mod

        plan = _plan(gate="explicit_true", requests=[], target_files=[], target_symbols=[])
        with mock.patch(
            "utilities.autopatcher.remediation_planner.generate_remediation_plan", return_value=plan,
        ):
            s1_locals = pipeline_mod._run_repository_analysis_and_remediation_planning(
                vulnerability_text=_VULN_TEXT, repo_root=str(tmp_path),
                investigation_output_dir=None, llm=mock.MagicMock(),
            )
        assert s1_locals["_planning_forced_skip"] is True
        # replay_engine's own S1 run_fn computes `outcome` from the exact
        # same locals dict shape (see _run_replay_repository_analysis_and_
        # remediation_planning) -- verified here structurally rather than
        # invoking the full replay machinery (which needs a real lineage
        # chain/prior execution on disk).
        assert "_planning_forced_skip" in s1_locals
        assert "_planning_skip_reason" in s1_locals
        assert "_planning_terminal_state" in s1_locals
        assert "_planning_attempts" in s1_locals


# ---------------------------------------------------------------------------
# Pre-Fix-A artifact replay compatibility: an isolated downstream replay
# (S2/S3) consuming a PERSISTED S1 artifact that predates the Planning
# evidence-sufficiency contract must refuse to reinterpret it under the new
# contract -- neither "grounded" nor "planning_ungrounded" is a truthful
# description of a run made under a contract that didn't exist yet.
# ---------------------------------------------------------------------------

class TestPreFixAArtifactReplayCompatibility:
    def _resolution(self, path):
        from utilities.autopatcher.lineage import RESOLVED, Resolution
        return Resolution(state=RESOLVED, artifact_path=str(path))

    def _write_pre_fix_a_s1_artifact(self, output_dir):
        """An S1 artifact shaped EXACTLY like production wrote before Fix A
        existed -- no `planning_forced_skip`/`planning_skip_reason` key,
        and `plan_result` itself lacks `additional_evidence_required`/
        `evidence_requests`. This is the literal historical shape (see the
        real urllib3 forensic run's own 001_repository_analysis_and_
        remediation_planning.json), not a synthetic approximation."""
        artifact = {
            "plan_result": {
                "rendered": "## Target Discovery Plan\n",
                "target_files": ["retry.py"], "target_symbols": [],
                "security_invariant": "the unsafe condition",
                "remediation_mechanism": "the mechanism",
                "narrower_alternative_decision": None, "narrower_alternative_considered": None,
                "required_edits": [], "approaches_to_avoid": [], "explicit_unknowns": [],
            },
            "repository_understanding": None,
            "pre_patch_anchors": None,
            "vulnerability_text": _VULN_TEXT,
            "repository_understanding_ctx": "",
            "planner_evidence_ctx": "## Planner-Proposed Candidate Evidence\n\nsome evidence\n",
            "plan_ctx": "## Target Discovery Plan\n",
            "repo_code": "",
            "grounding": None,
            # No "planning_forced_skip" / "planning_skip_reason" key at
            # all -- the defining characteristic of a pre-Fix-A artifact.
        }
        path = output_dir / "repository_analysis_and_remediation_planning.json"
        path.write_text(json.dumps(artifact), encoding="utf-8")
        return path

    def _write_current_contract_s1_artifact(self, output_dir):
        """The current-contract shape -- `planning_forced_skip` present
        (grounded run, so False) -- everything an isolated S2/S3 replay
        needs to proceed normally."""
        artifact = {
            "plan_result": {
                "rendered": "## Target Discovery Plan\n",
                "target_files": ["retry.py"], "target_symbols": [],
                "security_invariant": "the unsafe condition",
                "remediation_mechanism": "the mechanism",
                "narrower_alternative_decision": None, "narrower_alternative_considered": None,
                "required_edits": [], "approaches_to_avoid": [], "explicit_unknowns": [],
                "additional_evidence_required": "explicit_false", "evidence_requests": [],
            },
            "repository_understanding": None,
            "pre_patch_anchors": None,
            "vulnerability_text": _VULN_TEXT,
            "repository_understanding_ctx": "",
            "planner_evidence_ctx": "## Planner-Proposed Candidate Evidence\n\nsome evidence\n",
            "plan_ctx": "## Target Discovery Plan\n",
            "repo_code": "",
            "grounding": None,
            "planning_forced_skip": False,
            "planning_skip_reason": None,
        }
        path = output_dir / "repository_analysis_and_remediation_planning.json"
        path.write_text(json.dumps(artifact), encoding="utf-8")
        return path

    def test_old_s1_artifact_s2_replay_raises_explicit_incompatibility(self, tmp_path):
        from utilities.autopatcher import replay_engine
        from utilities.autopatcher.replay_engine import ReplayEngineError
        from utilities.autopatcher.stage_registry import REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING

        output_dir = tmp_path / "out"
        output_dir.mkdir()
        s1_path = self._write_pre_fix_a_s1_artifact(output_dir)

        with pytest.raises(ReplayEngineError, match="predates the Planning evidence-sufficiency contract"):
            replay_engine._run_replay_remediation_strategy(
                repo_root=str(tmp_path), llm=mock.MagicMock(), output_dir=output_dir,
                resolved_dependencies={REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: self._resolution(s1_path)},
            )

    def test_old_s1_artifact_s3_replay_also_raises(self, tmp_path):
        from utilities.autopatcher import replay_engine
        from utilities.autopatcher.replay_engine import ReplayEngineError
        from utilities.autopatcher.stage_registry import (
            REMEDIATION_STRATEGY,
            REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
        )

        output_dir = tmp_path / "out"
        output_dir.mkdir()
        s1_path = self._write_pre_fix_a_s1_artifact(output_dir)
        # A hypothetical S2 artifact is irrelevant -- S3 must reject on S1's
        # own incompatibility before ever looking at S2.
        s2_path = output_dir / "remediation_strategy.json"
        s2_path.write_text(json.dumps({"strategy_result": None}), encoding="utf-8")

        with pytest.raises(ReplayEngineError, match="predates the Planning evidence-sufficiency contract"):
            replay_engine._run_replay_guided_context_acquisition(
                repo_root=str(tmp_path), llm=mock.MagicMock(), output_dir=output_dir,
                resolved_dependencies={
                    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: self._resolution(s1_path),
                    REMEDIATION_STRATEGY: self._resolution(s2_path),
                },
            )

    def test_old_artifact_rejection_produces_no_artifact_file_at_all(self, tmp_path):
        # Neither "planning_ungrounded" NOR "grounded": the rejection must
        # happen BEFORE any S2 artifact is ever written, so there is no
        # artifact anywhere claiming either epistemic outcome for this run.
        from utilities.autopatcher import replay_engine
        from utilities.autopatcher.replay_engine import ReplayEngineError
        from utilities.autopatcher.stage_registry import REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING

        output_dir = tmp_path / "out"
        output_dir.mkdir()
        s1_path = self._write_pre_fix_a_s1_artifact(output_dir)

        with pytest.raises(ReplayEngineError):
            replay_engine._run_replay_remediation_strategy(
                repo_root=str(tmp_path), llm=mock.MagicMock(), output_dir=output_dir,
                resolved_dependencies={REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: self._resolution(s1_path)},
            )
        assert not (output_dir / "remediation_strategy.json").exists()

    def test_replaying_s1_itself_remains_supported_and_uses_current_contract(self, tmp_path):
        # Replaying S1 itself is never blocked by the old-artifact guard --
        # it always re-runs the CURRENT executor for real, producing a
        # fresh, current-contract artifact regardless of what existed
        # before (see _run_replay_repository_analysis_and_remediation_
        # planning, which never reads Planning-specific fields from its own
        # prior artifact -- only `vulnerability_text`, the run-level input).
        from utilities.autopatcher import replay_engine
        from utilities.autopatcher.lineage import RESOLVED, build_chain

        output_dir = tmp_path / "out"
        output_dir.mkdir()
        prior_dir = tmp_path / "prior"
        prior_dir.mkdir()
        self._write_pre_fix_a_s1_artifact(prior_dir)

        plan = _plan(gate="explicit_false", requests=[])
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan", return_value=plan,
            ),
            mock.patch("utilities.autopatcher.replay_engine.lineage.resolve_effective") as mock_resolve,
        ):
            from utilities.autopatcher.lineage import Resolution
            mock_resolve.return_value = Resolution(
                state=RESOLVED, artifact_path=str(prior_dir / "repository_analysis_and_remediation_planning.json"),
            )
            result = replay_engine._run_replay_repository_analysis_and_remediation_planning(
                repo_root=str(tmp_path), llm=mock.MagicMock(), output_dir=output_dir,
                resolved_dependencies={}, chain=object(),
            )
        new_artifact = json.loads(Path(result.artifact_path).read_text(encoding="utf-8"))
        assert "planning_forced_skip" in new_artifact
        assert result.outcome == "generated"

    def test_current_contract_s1_artifact_supports_normal_s2_replay(self, tmp_path):
        from utilities.autopatcher import replay_engine
        from utilities.autopatcher.stage_registry import REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING

        output_dir = tmp_path / "out"
        output_dir.mkdir()
        s1_path = self._write_current_contract_s1_artifact(output_dir)

        with mock.patch(
            "utilities.autopatcher.replay_engine.generate_remediation_strategy",
            return_value=_strategy_result(target_files=["retry.py"], evaluated=True),
        ) as spy:
            result = replay_engine._run_replay_remediation_strategy(
                repo_root=str(tmp_path), llm=mock.MagicMock(), output_dir=output_dir,
                resolved_dependencies={REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: self._resolution(s1_path)},
            )
        spy.assert_called_once()
        assert result.outcome == "generated"
