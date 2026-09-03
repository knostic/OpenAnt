"""Tests for the Final Remediation Strategy -> Patch Generation safety gate
(pipeline._run_guided_context_acquisition, Stage 3 -- guided_context_
acquisition): a real urllib3 full-run finding that Patch Generation ran even
though Final Strategy had already, explicitly, found no evidence-backed
target.

The three structural states this gate distinguishes (see
RemediationStrategyResult's own docstring):

  A. No authoritative Final Strategy decision exists
     (`_strategy_result is None`, or `_strategy_result.evaluated is False`
     -- e.g. `_EMPTY_STRATEGY_RESULT`, covering "no planner_evidence_ctx",
     an LLM-call failure, or a response that failed to parse).
  B. Final Strategy ran (`evaluated=True`) and named >=1 verified target.
  C. Final Strategy ran (`evaluated=True`) and named ZERO verified targets
     -- regardless of whether `insufficient_evidence` happens to be
     populated (see the "subtle case" test below).

Only state C must set `_skip_patch_generation = True`. States A and B must
leave existing behavior completely unchanged -- this gate must never
suppress Patch Generation merely because no Final Strategy decision exists.
"""

from __future__ import annotations

from unittest import mock

import pytest

from utilities.autopatcher.pipeline import (
    _run_guided_context_acquisition,
    _run_patch_generation_and_investigation,
)
from utilities.autopatcher.remediation_planner import (
    _EMPTY_STRATEGY_RESULT,
    RemediationStrategyResult,
)


def _strategy(
    *, evaluated: bool, target_files=(), target_symbols=(), insufficient_evidence=(),
) -> RemediationStrategyResult:
    return RemediationStrategyResult(
        rendered="", target_files=list(target_files), target_symbols=list(target_symbols),
        warnings=[], extended_mechanism=None, required_edits=[], security_invariant=None,
        insufficient_evidence=list(insufficient_evidence), evaluated=evaluated,
    )


def _run_gate(**overrides):
    kwargs = dict(
        vulnerability_text="v", llm=None, repo_root=None, budget_controller=None,
        _strategy_result=None, _plan_result=None, _investigation_context=None,
    )
    kwargs.update(overrides)
    return _run_guided_context_acquisition(**kwargs)


class TestFinalStrategyNotRun:
    """State A -- absence of a Final Strategy decision must preserve
    existing behavior and must never automatically suppress Patch
    Generation."""

    def test_strategy_result_none_leaves_patch_generation_unaffected(self):
        result = _run_gate(_strategy_result=None)
        assert result["_skip_patch_generation"] is False

    def test_empty_strategy_sentinel_leaves_patch_generation_unaffected(self):
        """_EMPTY_STRATEGY_RESULT (evaluated=False) -- the common case
        where Final Strategy was never meaningfully invoked at all (e.g.
        no planner_evidence_ctx) -- must be treated identically to
        `_strategy_result is None`, never as a declined decision."""
        result = _run_gate(_strategy_result=_EMPTY_STRATEGY_RESULT)
        assert result["_skip_patch_generation"] is False


class TestFinalStrategyRanWithTargets:
    """State B -- existing guided-context/Edit-Readiness path must remain
    completely unchanged when Final Strategy names a verified target."""

    def test_has_targets_enters_existing_slice_path_not_the_new_gate(self):
        strategy = _strategy(evaluated=True, target_files=["src/util.py"])
        with mock.patch(
            "utilities.autopatcher.remediation_planner.build_final_target_slice",
            side_effect=RuntimeError("unrelated internal failure -- proves this branch was reached"),
        ) as mock_build:
            result = _run_gate(_strategy_result=strategy)
        mock_build.assert_called_once()
        # The pre-existing exception handler for THIS branch (not the new
        # gate) catches the failure and never touches _skip_patch_generation.
        assert result["_skip_patch_generation"] is False


class TestFinalStrategyRanWithZeroTargets:
    """State C -- the real urllib3 finding: Final Strategy ran and
    explicitly selected no evidence-backed target. Patch Generation must
    be skipped, and this must never depend on `rendered`."""

    def test_zero_targets_with_insufficient_evidence_skips_patch_generation(self):
        strategy = _strategy(
            evaluated=True, target_files=[], target_symbols=[],
            insufficient_evidence=[
                "missing verified PoolManager.urlopen source",
                "no verified existing sensitive-header mechanism",
            ],
        )
        with mock.patch("utilities.autopatcher.remediation_planner.build_final_target_slice") as mock_build:
            result = _run_gate(_strategy_result=strategy)
        mock_build.assert_not_called()
        assert result["_skip_patch_generation"] is True

    def test_zero_targets_with_no_insufficient_evidence_also_skips_patch_generation(self):
        """The 'subtle case': a real (evaluated=True), successfully-parsed
        Final Strategy response that names zero targets AND leaves
        insufficient_evidence empty. Per prompts/remediation_strategy.md's
        own ground rule ("if the verified evidence is insufficient... say
        so in insufficient_evidence"), a well-formed response should
        always explain itself here -- but this response did not, and nothing
        in the current contract requires it to. This module never silently
        classifies that gap using `rendered`; it makes the fail-closed
        choice explicit: no verified target, evaluated=True -> unsafe to
        generate from, regardless of the explanation's presence."""
        strategy = _strategy(evaluated=True, target_files=[], target_symbols=[], insufficient_evidence=[])
        with mock.patch("utilities.autopatcher.remediation_planner.build_final_target_slice") as mock_build:
            result = _run_gate(_strategy_result=strategy)
        mock_build.assert_not_called()
        assert result["_skip_patch_generation"] is True

    def test_gate_does_not_read_rendered(self):
        """Explicit non-regression guard: a non-empty `rendered` string
        must never, by itself, change the gate's decision -- it is
        presentation output, not a control-flow signal."""
        strategy_rendered_empty = _strategy(evaluated=True, target_files=[], target_symbols=[])
        strategy_rendered_nonempty = strategy_rendered_empty._replace(rendered="## Some Markdown\n")
        with mock.patch("utilities.autopatcher.remediation_planner.build_final_target_slice"):
            r1 = _run_gate(_strategy_result=strategy_rendered_empty)
            r2 = _run_gate(_strategy_result=strategy_rendered_nonempty)
        assert r1["_skip_patch_generation"] is True
        assert r2["_skip_patch_generation"] is True


class TestSkipPatchGenerationReachesNoPatchProducedPathUnchanged:
    """Requirement 6: NO PATCH PRODUCED continues through the EXISTING
    empty-patch reporting path -- this fix creates no parallel terminal
    state. Proven by calling Stage 4's own executor
    (_run_patch_generation_and_investigation) directly with
    _skip_patch_generation=True (exactly what the new gate above produces)
    and confirming generate_patch/generate_patch_raw are never invoked and
    `patch` settles to "" -- the same, single mechanism
    test_pipeline_no_patch_early_stop.py already exhaustively proves feeds
    the existing "NO PATCH PRODUCED" report path, regardless of WHICH
    upstream condition set the flag."""

    def test_generate_patch_never_called_when_skip_flag_is_set(self):
        with (
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw") as mock_raw,
            mock.patch("utilities.autopatcher.pipeline.generate_patch") as mock_gen,
        ):
            result = _run_patch_generation_and_investigation(
                vulnerability_text="v", llm=None, repo_root=None, code_context="",
                budget_controller=None, _skip_patch_generation=True,
                _edit_readiness=None, _slice_result=None, _investigation_context=None,
                _pre_patch_anchors=None, _plan_result=None, _strategy_result=None,
            )
        mock_raw.assert_not_called()
        mock_gen.assert_not_called()
        assert result["patch"] == ""
        assert result["_patch_validation_skip_reason"] == "no verified final-target source"


class TestProductionAndReplayShareTheSameGate:
    """Production (pipeline.run()) and replay (replay_engine.py) must
    exhibit identical behavior -- verified structurally: both call the
    exact same function object, not two independently-maintained copies."""

    def test_replay_engine_imports_the_same_function_object(self):
        import utilities.autopatcher.pipeline as pipeline_mod
        import utilities.autopatcher.replay_engine as replay_engine_mod

        assert replay_engine_mod._run_guided_context_acquisition is pipeline_mod._run_guided_context_acquisition
