"""Tests for the deterministic verified-narrower authority split: when an
INDEPENDENTLY VERIFIED Planner narrower-alternative decision (Planner
`narrower_alternative_decision == "SELECTED"`, the active Planner Claim
Verifier result `status == "SUPPORTED"`, and
`authoritative_remediation_matches_selected_alternative is True`) becomes
semantic authority for Patch Generation in place of Strategy's own
mechanism-bearing prose (`extended_mechanism`/`security_invariant`/
`required_edits`). Strategy's independently re-verified `target_files`/
`target_symbols`/`rejected_targets` remain fully authoritative for WHERE
the patch applies -- only semantic (mechanism) authority moves.

Enforced purely by WHICH rendered text occupies pipeline.py's flat
`code_context` string (see `_verified_narrower_authoritative` in
pipeline.py and `_render_verified_authoritative_semantics`/
`_render_strategy_target_block` in remediation_planner.py) -- never by
comparing Planner's and Strategy's prose against each other. Every test
below either exercises the real `pipeline.run()` context-assembly branch
(mocking only the LLM-backed Planner/Verifier/Strategy calls, exactly like
test_planner_claim_verifier_orchestration.py and
test_evidence_gap_strategy_fallback.py already do) or unit-tests the
deterministic renderers/activation flag directly. Domain-neutral
throughout -- no repo/CVE-specific wording.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from utilities.autopatcher import pipeline as pipeline_mod
from utilities.autopatcher.remediation_planner import (
    RemediationPlanResult,
    RemediationStrategyResult,
    _render_strategy_target_block,
    _render_verified_authoritative_semantics,
)
from utilities.autopatcher.remediation_verifier import VerifierResult

_VULN_TEXT = "# Test vulnerability\n\nSome description of a vulnerability for testing.\n"

_NARROW_MECHANISM = "apply the narrow, state-sensitive guard at the single unsafe call site"
_NARROW_INVARIANT = "the narrow invariant: the unsafe state must never be reachable from that call site"
_NARROW_REQUIRED_EDIT = "add the narrow state-sensitive guard immediately before the unsafe call"
_NARROW_APPROACH_TO_AVOID = "do not rewrite the surrounding control flow"

_BROAD_MECHANISM = "rewrite the entire subsystem to remove the unsafe pattern everywhere"
_BROAD_REQUIRED_EDIT = "rewrite every call site across the subsystem"
_BROAD_INVARIANT = "an altered, broader invariant covering the whole subsystem"

_CLEAN_DIFF = """\
```diff
--- a/target.py
+++ b/target.py
@@ -1,2 +1,3 @@
 def foo():
+    pass
     pass
```"""


def _plan(
    tmp_path,
    decision="SELECTED",
    mechanism=_NARROW_MECHANISM,
    invariant=_NARROW_INVARIANT,
    required_edits=(_NARROW_REQUIRED_EDIT,),
    approaches_to_avoid=(_NARROW_APPROACH_TO_AVOID,),
    narrower="the narrower alternative that was selected",
    target_files=("target.py",),
    target_symbols=("target.py:foo",),
):
    """A Planner result pointing at a REAL file written into tmp_path, so
    the deterministic evidence bridge (`build_planner_evidence`) and
    Final-Target Slice machinery actually succeed -- same pattern as
    test_planner_claim_verifier_orchestration.py's `_plan_with_real_target`."""
    target = tmp_path / "target.py"
    if not target.exists():
        target.write_text("def foo():\n    pass\n", encoding="utf-8")
    return RemediationPlanResult(
        rendered="## Target Discovery Plan\n",
        target_files=list(target_files),
        target_symbols=list(target_symbols),
        security_invariant=invariant,
        remediation_mechanism=mechanism,
        narrower_alternative_decision=decision,
        narrower_alternative_considered=narrower,
        required_edits=list(required_edits),
        approaches_to_avoid=list(approaches_to_avoid),
        explicit_unknowns=[],
    )


def _verdict(status="SUPPORTED", matches_selected=True, reason="because", contradiction=None, failure_kind=None):
    return VerifierResult(
        status=status, reason=reason, contradiction=contradiction, failure_kind=failure_kind, evaluated=True,
        counterexample_reaches_unsafe_state=None,
        authoritative_remediation_matches_selected_alternative=matches_selected,
    )


def _strategy(
    target_files=("target.py",),
    target_symbols=("target.py:foo",),
    extended_mechanism=_BROAD_MECHANISM,
    required_edits=(_BROAD_REQUIRED_EDIT,),
    security_invariant=_BROAD_INVARIANT,
    rejected_targets=(),
    insufficient_evidence=(),
    warnings=(),
    evaluated=True,
):
    """A Strategy result deliberately carrying BROADER mechanism-bearing
    prose than the Planner's narrow decision -- exactly the shape Section
    10.A of the authority-split task requires: real, valid targets, but a
    broader extended_mechanism/required_edits/altered security_invariant
    that must never reach Patch Generation once verified authority is
    active."""
    body = []
    if extended_mechanism:
        body.append(f"\n**Extended mechanism:** {extended_mechanism}")
    if required_edits:
        body.append("\n**Required edits:**")
        body.extend(f"- {e}" for e in required_edits)
    if security_invariant:
        body.append(f"\n**Security invariant:** {security_invariant}")
    rendered = "\n".join(
        ["## Final Evidence-Backed Remediation Strategy", ""] + body
    ) + "\n" if body else ""
    return RemediationStrategyResult(
        rendered=rendered,
        target_files=list(target_files),
        target_symbols=list(target_symbols),
        warnings=list(warnings),
        extended_mechanism=extended_mechanism,
        required_edits=list(required_edits),
        security_invariant=security_invariant,
        insufficient_evidence=list(insufficient_evidence),
        evaluated=evaluated,
        rejected_targets=list(rejected_targets),
    )


def _run_pipeline(tmp_path, *, plan_result, verify_side_effect, strategy_result, execution_recorder=None):
    """Run the real pipeline.run(), mocking only the LLM-backed Planner/
    Verifier/Strategy calls at their SOURCE modules (local, function-body
    imports -- mocking pipeline.<name> would not intercept them) and
    generate_patch_raw (to capture the exact code_context Patch Generation
    receives without needing a real LLM call). Everything else --
    `_verified_narrower_authoritative`, the renderer functions, the
    `_ctx_parts` assembly, Strategy's own target verification, Final-Target
    Slice, Edit Readiness -- runs for REAL."""
    with (
        mock.patch(
            "utilities.autopatcher.remediation_planner.generate_remediation_plan",
            return_value=plan_result,
        ),
        mock.patch(
            "utilities.autopatcher.remediation_verifier.verify_planner_claim",
            side_effect=verify_side_effect,
        ) as spy_verify,
        mock.patch(
            "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
            return_value=strategy_result,
        ) as spy_strategy,
        mock.patch(
            "utilities.autopatcher.pipeline.generate_patch_raw",
            return_value=_CLEAN_DIFF,
        ) as mock_gen,
    ):
        report = pipeline_mod.run(
            vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path),
            execution_recorder=execution_recorder,
        )
    return report, spy_verify, spy_strategy, mock_gen


# ---------------------------------------------------------------------------
# A. Core orchestration regression
# ---------------------------------------------------------------------------

class TestCoreOrchestrationRegression:
    def test_verified_planner_semantics_reach_context_strategy_broadening_excluded(self, tmp_path):
        plan_result = _plan(tmp_path)
        strategy_result = _strategy()
        _report, spy_verify, spy_strategy, mock_gen = _run_pipeline(
            tmp_path, plan_result=plan_result, verify_side_effect=[_verdict("SUPPORTED", matches_selected=True)],
            strategy_result=strategy_result,
        )
        spy_verify.assert_called_once()
        spy_strategy.assert_called_once()
        mock_gen.assert_called_once()
        code_context = mock_gen.call_args.kwargs["code_context"]

        # Planner's verified semantics ARE present.
        assert _NARROW_MECHANISM in code_context
        assert _NARROW_INVARIANT in code_context
        assert _NARROW_REQUIRED_EDIT in code_context
        assert _NARROW_APPROACH_TO_AVOID in code_context

        # Strategy's broader mechanism-bearing prose is NOT present.
        assert _BROAD_MECHANISM not in code_context
        assert _BROAD_REQUIRED_EDIT not in code_context
        assert _BROAD_INVARIANT not in code_context

        # Strategy's own verified targets ARE still present (target
        # authority never moves).
        assert "target.py" in code_context


# ---------------------------------------------------------------------------
# B/C. Target behavior under verified authority
# ---------------------------------------------------------------------------

class TestTargetBehaviorUnchanged:
    def test_valid_strategy_targets_still_used_for_slice(self, tmp_path):
        plan_result = _plan(tmp_path)
        strategy_result = _strategy()
        with mock.patch(
            "utilities.autopatcher.remediation_planner.build_final_target_slice",
        ) as mock_slice:
            mock_slice.return_value = None
            _run_pipeline(
                tmp_path, plan_result=plan_result,
                verify_side_effect=[_verdict("SUPPORTED", matches_selected=True)],
                strategy_result=strategy_result,
            )
        mock_slice.assert_called_once()
        called_strategy = mock_slice.call_args[0][0]
        assert called_strategy.target_files == ["target.py"]
        assert called_strategy.target_symbols == ["target.py:foo"]

    def test_rejected_targets_survive_into_context(self, tmp_path):
        plan_result = _plan(tmp_path)
        strategy_result = _strategy(rejected_targets=["some/other/candidate.py"])
        _report, _spy_verify, _spy_strategy, mock_gen = _run_pipeline(
            tmp_path, plan_result=plan_result,
            verify_side_effect=[_verdict("SUPPORTED", matches_selected=True)],
            strategy_result=strategy_result,
        )
        code_context = mock_gen.call_args.kwargs["code_context"]
        assert "some/other/candidate.py" in code_context
        assert _BROAD_MECHANISM not in code_context


# ---------------------------------------------------------------------------
# D. Implementation evidence gap under verified authority
# ---------------------------------------------------------------------------

class TestImplementationEvidenceGap:
    def test_gap_recorded_without_restoring_strategy_semantic_authority(self, tmp_path):
        from utilities.autopatcher.execution_recorder import ExecutionRecorder

        recorder = ExecutionRecorder(
            call_log=[], run_dir=str(tmp_path / "run"), artifacts_dir=tmp_path / "run" / "executions",
        )
        plan_result = _plan(tmp_path)
        strategy_result = _strategy(insufficient_evidence=["some evidence gap note"])
        _report, _spy_verify, _spy_strategy, mock_gen = _run_pipeline(
            tmp_path, plan_result=plan_result,
            verify_side_effect=[_verdict("SUPPORTED", matches_selected=True)],
            strategy_result=strategy_result, execution_recorder=recorder,
        )
        code_context = mock_gen.call_args.kwargs["code_context"]
        assert _BROAD_MECHANISM not in code_context
        assert _NARROW_MECHANISM in code_context

        s2 = next(e for e in recorder.executions if e["canonical_stage"] == "remediation_strategy")
        artifact = json.loads(open(s2["artifact_path"], encoding="utf-8").read())
        assert artifact["verified_authority"]["strategy_reported_implementation_gap"] is True
        assert artifact["verified_authority"]["semantic_authority_source"] == "planner"


# ---------------------------------------------------------------------------
# E. v2 authoritative Planner
# ---------------------------------------------------------------------------

class TestV2AuthoritativePlanner:
    def test_v2_semantics_used_not_v1(self, tmp_path):
        """v1 is contradicted; the bounded one-shot revision produces v2;
        verifier_v2 SUPPORTS v2 with match=True. Semantic authority MUST
        come from v2's fields, never v1's."""
        v1_mechanism = "v1's own narrow mechanism, later contradicted"
        v2_mechanism = "v2's own, revised narrow mechanism"
        plan_v1 = _plan(tmp_path, mechanism=v1_mechanism, narrower="v1 narrower alternative")
        plan_v2 = _plan(tmp_path, mechanism=v2_mechanism, narrower="v2 narrower alternative (revised)")
        strategy_result = _strategy()
        with (
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_plan",
                side_effect=[plan_v1, plan_v2],
            ),
            mock.patch(
                "utilities.autopatcher.remediation_verifier.verify_planner_claim",
                side_effect=[_verdict("CONTRADICTED", contradiction="v1 was wrong"), _verdict("SUPPORTED", matches_selected=True)],
            ) as spy_verify,
            mock.patch(
                "utilities.autopatcher.remediation_planner.generate_remediation_strategy",
                return_value=strategy_result,
            ),
            mock.patch(
                "utilities.autopatcher.pipeline.generate_patch_raw",
                return_value=_CLEAN_DIFF,
            ) as mock_gen,
        ):
            pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert spy_verify.call_count == 2
        mock_gen.assert_called_once()
        code_context = mock_gen.call_args.kwargs["code_context"]
        assert v2_mechanism in code_context
        assert v1_mechanism not in code_context


# ---------------------------------------------------------------------------
# F. Negative compatibility cases -- Strategy remains fully authoritative
# ---------------------------------------------------------------------------

class TestNegativeCompatibility:
    def _assert_strategy_authoritative(self, tmp_path, plan_result, verify_side_effect):
        strategy_result = _strategy()
        _report, _spy_verify, _spy_strategy, mock_gen = _run_pipeline(
            tmp_path, plan_result=plan_result, verify_side_effect=verify_side_effect,
            strategy_result=strategy_result,
        )
        mock_gen.assert_called_once()
        code_context = mock_gen.call_args.kwargs["code_context"]
        assert _BROAD_MECHANISM in code_context
        assert _BROAD_REQUIRED_EDIT in code_context
        assert _BROAD_INVARIANT in code_context

    def test_selected_but_verifier_not_supported(self, tmp_path):
        plan_result = _plan(tmp_path)
        self._assert_strategy_authoritative(tmp_path, plan_result, [_verdict("UNRESOLVED", matches_selected=None)])

    def test_selected_but_match_false(self, tmp_path):
        plan_result = _plan(tmp_path)
        self._assert_strategy_authoritative(
            tmp_path, plan_result, [_verdict("SUPPORTED", matches_selected=False)],
        )

    def test_selected_but_match_none(self, tmp_path):
        plan_result = _plan(tmp_path)
        self._assert_strategy_authoritative(
            tmp_path, plan_result, [_verdict("SUPPORTED", matches_selected=None)],
        )

    def test_none_identified_never_calls_verifier(self, tmp_path):
        plan_result = _plan(tmp_path, decision="NONE_IDENTIFIED")
        strategy_result = _strategy()
        with mock.patch(
            "utilities.autopatcher.remediation_verifier.verify_planner_claim"
        ) as spy_verify:
            _run_pipeline(
                tmp_path, plan_result=plan_result, verify_side_effect=None,
                strategy_result=strategy_result,
            )
        spy_verify.assert_not_called()

    def test_no_verifier_result_hand_authored_plan_path(self, tmp_path):
        """No verifier ever runs (Planner never even calls the model) --
        `_active_verifier_result` stays at its default None, so the split
        can never activate."""
        report = pipeline_mod.run(vulnerability_text=_VULN_TEXT, api_key="", repo_root=str(tmp_path))
        assert "# Auto Patcher MVP" in report


# ---------------------------------------------------------------------------
# G. Observability
# ---------------------------------------------------------------------------

class TestObservability:
    def _artifacts(self, tmp_path, plan_result, verify_side_effect, strategy_result):
        from utilities.autopatcher.execution_recorder import ExecutionRecorder

        recorder = ExecutionRecorder(
            call_log=[], run_dir=str(tmp_path / "run"), artifacts_dir=tmp_path / "run" / "executions",
        )
        _run_pipeline(
            tmp_path, plan_result=plan_result, verify_side_effect=verify_side_effect,
            strategy_result=strategy_result, execution_recorder=recorder,
        )
        s1 = next(e for e in recorder.executions if e["canonical_stage"] == "repository_analysis_and_remediation_planning")
        s2 = next(e for e in recorder.executions if e["canonical_stage"] == "remediation_strategy")
        s1_artifact = json.loads(open(s1["artifact_path"], encoding="utf-8").read())
        s2_artifact = json.loads(open(s2["artifact_path"], encoding="utf-8").read())
        return s1_artifact, s2_artifact

    def test_verified_path_metadata(self, tmp_path):
        plan_result = _plan(tmp_path)
        strategy_result = _strategy()
        s1_artifact, s2_artifact = self._artifacts(
            tmp_path, plan_result, [_verdict("SUPPORTED", matches_selected=True)], strategy_result,
        )
        assert s1_artifact["planner_claim_verification"]["verified_narrower_authoritative"] is True
        assert s1_artifact["planner_claim_verification"]["semantic_authority_plan_version"] == "v1"
        assert s2_artifact["verified_authority"]["verified_narrower_authoritative"] is True
        assert s2_artifact["verified_authority"]["semantic_authority_source"] == "planner"
        assert s2_artifact["verified_authority"]["target_authority_source"] == "strategy"
        assert s2_artifact["verified_authority"]["strategy_reported_implementation_gap"] is False

    def test_non_verified_path_metadata(self, tmp_path):
        plan_result = _plan(tmp_path)
        strategy_result = _strategy()
        s1_artifact, s2_artifact = self._artifacts(
            tmp_path, plan_result, [_verdict("SUPPORTED", matches_selected=False)], strategy_result,
        )
        assert s1_artifact["planner_claim_verification"]["verified_narrower_authoritative"] is False
        assert s1_artifact["planner_claim_verification"]["semantic_authority_plan_version"] is None
        assert s2_artifact["verified_authority"]["semantic_authority_source"] == "strategy"
        assert s2_artifact["verified_authority"]["target_authority_source"] == "strategy"


# ---------------------------------------------------------------------------
# Renderer unit tests
# ---------------------------------------------------------------------------

class TestRenderVerifiedAuthoritativeSemantics:
    def test_renders_only_the_five_fields(self, tmp_path):
        plan_result = _plan(tmp_path)
        rendered = _render_verified_authoritative_semantics(plan_result)
        assert "Verified Authoritative Remediation Semantics" in rendered
        assert _NARROW_MECHANISM in rendered
        assert _NARROW_INVARIANT in rendered
        assert _NARROW_REQUIRED_EDIT in rendered
        assert _NARROW_APPROACH_TO_AVOID in rendered
        assert "exploratory -- not authoritative" not in rendered

    def test_empty_when_all_five_fields_empty(self):
        empty_plan = RemediationPlanResult(rendered="", target_files=[], target_symbols=[])
        assert _render_verified_authoritative_semantics(empty_plan) == ""


class TestRenderStrategyTargetBlock:
    def test_excludes_mechanism_bearing_fields_by_construction(self):
        strategy_result = _strategy()
        rendered = _render_strategy_target_block(strategy_result)
        assert "target.py" in rendered
        assert _BROAD_MECHANISM not in rendered
        assert _BROAD_REQUIRED_EDIT not in rendered
        assert _BROAD_INVARIANT not in rendered

    def test_includes_rejected_targets_and_evidence_gap(self):
        strategy_result = _strategy(
            rejected_targets=["rejected/candidate.py"], insufficient_evidence=["gap note"],
        )
        rendered = _render_strategy_target_block(strategy_result)
        assert "rejected/candidate.py" in rendered
        assert "gap note" in rendered

    def test_empty_when_nothing_to_render(self):
        empty_strategy = RemediationStrategyResult(
            rendered="", target_files=[], target_symbols=[], warnings=[],
            extended_mechanism=None, required_edits=[], security_invariant=None,
            insufficient_evidence=[], evaluated=False, rejected_targets=[],
        )
        assert _render_strategy_target_block(empty_strategy) == ""
