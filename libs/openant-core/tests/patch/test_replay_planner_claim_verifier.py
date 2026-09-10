"""Replay regression tests for the Planner Claim Verifier's forced-skip
decision (review fix 1).

Before this fix: `replay_engine.py`'s S1 replay artifact never persisted
`_verifier_forced_skip`/`_verifier_skip_reason`, and its S3 replay handler
never passed them into `_run_guided_context_acquisition` -- so replaying a
captured run that was deliberately blocked by the Planner Claim Verifier
could silently produce `skip_patch_generation=False` in S3's replay
artifact, and a subsequent S4 replay off that artifact would actually
invoke the real Patch Generator LLM.

Style: rather than the full `tools/run_traced.py` + real git repo + full
pipeline harness (see test_replay_engine_s1_s3_s9_s11_s12.py) -- which
cannot even reach a verifier-forced-skip state through the canned mock LLM
responses -- these tests hand-construct exactly ONE synthetic input (an S1
artifact representing "production already ran the Planner Claim Verifier
and decided forced_skip"), then chain through the REAL, unmodified S2/S3/S4
replay handler functions, letting each one produce its own real artifact
from the one before it -- directly proving the propagation this fix adds,
without re-deriving anything by hand downstream of S1.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from utilities.autopatcher import replay_engine
from utilities.autopatcher.lineage import RESOLVED, Resolution
from utilities.autopatcher.stage_registry import (
    GUIDED_CONTEXT_ACQUISITION,
    REMEDIATION_STRATEGY,
    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
)

_VULN_TEXT = "some vuln"


def _resolution(path) -> Resolution:
    return Resolution(state=RESOLVED, artifact_path=str(path))


def _write_s1_artifact(
    output_dir, *, forced_skip: bool, skip_reason, planner_evidence_ctx: str = "",
    include_planner_claim_verification: bool = True, include_mode_fields: bool = True,
):
    """A hand-built S1 artifact -- exactly the shape
    _run_replay_repository_analysis_and_remediation_planning now writes
    (see replay_engine.py), representing a production run whose Planner
    Claim Verifier already reached a final decision. `planner_evidence_ctx`
    empty mirrors the real forced-skip case (S1 clears it so Strategy
    self-gates); non-empty models a run where Strategy still had something
    to reason over despite the verifier state given.
    """
    artifact = {
        "plan_result": {
            "rendered": "## Target Discovery Plan\n", "target_files": [], "target_symbols": [],
            "security_invariant": "the unsafe condition", "remediation_mechanism": "the broad mechanism",
            "narrower_alternative_considered": "considered a narrower mechanism",
            "required_edits": [], "approaches_to_avoid": [], "explicit_unknowns": [],
        },
        "repository_understanding": None,
        "pre_patch_anchors": None,
        "vulnerability_text": _VULN_TEXT,
        "repository_understanding_ctx": "",
        "planner_evidence_ctx": planner_evidence_ctx,
        "plan_ctx": "## Target Discovery Plan\n",
        "repo_code": "",
        "grounding": None,
    }
    if include_planner_claim_verification:
        artifact["planner_claim_verification"] = {
            "verifier_v1": {
                "status": "CONTRADICTED", "reason": "the trace ignores the guard",
                "contradiction": "the guard would have prevented this", "failure_kind": None, "evaluated": True,
            },
            "verifier_v2": {
                "status": "CONTRADICTED", "reason": "still ignores the guard",
                "contradiction": "same issue in the revision", "failure_kind": None, "evaluated": True,
            },
            "revision_attempted": True,
            "forced_skip": forced_skip,
            "skip_reason": skip_reason,
            "broadening_necessity_unresolved": False,
        }
        if include_mode_fields:
            # The NEW (decision-aware) artifact shape -- present on every
            # artifact written by the current production/replay code.
            # `mode_v1`/`mode_v2` are read by nothing in S2/S3/S4 replay
            # (they only ever read `forced_skip`/`skip_reason`) -- included
            # here to prove their presence is harmless, not required.
            artifact["planner_claim_verification"]["mode_v1"] = "REJECTED"
            artifact["planner_claim_verification"]["mode_v2"] = "REJECTED"
    path = output_dir / "repository_analysis_and_remediation_planning.json"
    path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    return path


_SKIP_REASON = (
    "Planner Claim Verifier: causal contradiction not cleared after one bounded "
    "revision (second verification: CONTRADICTED)"
)


class TestForcedSkipReplayChain:
    """The mandatory regression: must fail against the pre-fix implementation
    and pass after it."""

    def _replay_chain(self, tmp_path):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        s1_path = _write_s1_artifact(
            output_dir, forced_skip=True, skip_reason=_SKIP_REASON, planner_evidence_ctx="",
        )
        llm = mock.MagicMock()

        # S2's replay handler calls generate_remediation_strategy()
        # unconditionally (it relies on that function's OWN internal
        # "empty planner_evidence_ctx -> no LLM call" gate, exactly as
        # production does -- see remediation_strategy.py's docstring) --
        # so the real assertion here is "no underlying LLM call happened",
        # not "the function was never invoked". `wraps=` runs the REAL
        # function (producing a real, valid _EMPTY_STRATEGY_RESULT for
        # downstream to_jsonable/from_jsonable) while still letting us spy.
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy as _real_strategy_fn
        with mock.patch(
            "utilities.autopatcher.replay_engine.generate_remediation_strategy",
            wraps=_real_strategy_fn,
        ) as spy_strategy:
            s2_result = replay_engine._run_replay_remediation_strategy(
                repo_root=str(tmp_path), llm=llm, output_dir=output_dir,
                resolved_dependencies={REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: _resolution(s1_path)},
            )

        s3_result = replay_engine._run_replay_guided_context_acquisition(
            repo_root=str(tmp_path), llm=llm, output_dir=output_dir,
            resolved_dependencies={
                REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: _resolution(s1_path),
                REMEDIATION_STRATEGY: _resolution(s2_result.artifact_path),
            },
        )

        with mock.patch("utilities.autopatcher.pipeline.generate_patch_raw") as spy_patch_gen:
            s4_result = replay_engine._run_replay_patch_generation_and_investigation(
                repo_root=str(tmp_path), llm=llm, output_dir=output_dir,
                resolved_dependencies={
                    REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: _resolution(s1_path),
                    REMEDIATION_STRATEGY: _resolution(s2_result.artifact_path),
                    GUIDED_CONTEXT_ACQUISITION: _resolution(s3_result.artifact_path),
                },
            )

        return s1_path, spy_strategy, s2_result, s3_result, spy_patch_gen, s4_result

    def test_s1_artifact_carries_forced_skip_and_reason(self, tmp_path):
        s1_path, *_ = self._replay_chain(tmp_path)
        s1_data = json.loads(s1_path.read_text())
        assert s1_data["planner_claim_verification"]["forced_skip"] is True
        assert s1_data["planner_claim_verification"]["skip_reason"] == _SKIP_REASON

    def test_s2_replay_makes_zero_strategy_llm_calls(self, tmp_path):
        # generate_remediation_strategy() itself IS invoked (S2's replay
        # handler always calls it) -- the property that matters is that it
        # never reaches the LLM, exactly like production's own
        # `if _planner_evidence_ctx:` gate prevents in the first place.
        _s1, spy_strategy, s2_result, *_ = self._replay_chain(tmp_path)
        spy_strategy.assert_called_once()
        llm_used = spy_strategy.call_args[0][1]
        llm_used.complete.assert_not_called()
        s2_data = json.loads(s2_result.artifact_path.read_text())
        assert s2_data["strategy_result"]["evaluated"] is False

    def test_s3_replay_produces_skip_patch_generation_true(self, tmp_path):
        *_, s3_result, _spy_patch_gen, _s4 = self._replay_chain(tmp_path)
        s3_data = json.loads(s3_result.artifact_path.read_text())
        assert s3_data["skip_patch_generation"] is True

    def test_s3_replay_preserves_exact_verifier_reason(self, tmp_path):
        *_, s3_result, _spy_patch_gen, _s4 = self._replay_chain(tmp_path)
        s3_data = json.loads(s3_result.artifact_path.read_text())
        assert s3_data["skip_patch_generation_reason"] == _SKIP_REASON

    def test_s4_replay_never_calls_the_patch_generator(self, tmp_path):
        *_, spy_patch_gen, _s4 = self._replay_chain(tmp_path)
        spy_patch_gen.assert_not_called()

    def test_s4_replay_patch_remains_empty(self, tmp_path):
        *_, s4_result = self._replay_chain(tmp_path)
        s4_data = json.loads(s4_result.artifact_path.read_text())
        assert s4_data["patch"] == ""

    def test_s4_replay_outcome_is_no_candidate_patch(self, tmp_path):
        *_, s4_result = self._replay_chain(tmp_path)
        assert s4_result.outcome == "no_candidate_patch"

    def test_s4_replay_skip_reason_matches_s3(self, tmp_path):
        *_, s4_result = self._replay_chain(tmp_path)
        s4_data = json.loads(s4_result.artifact_path.read_text())
        assert s4_data["applicability_result"]["skipped_reason"] == _SKIP_REASON

    def test_old_artifact_shape_without_mode_fields_still_forces_skip_correctly(self, tmp_path):
        # An S1 artifact from BEFORE this decision-aware change existed
        # (forced_skip=True/skip_reason set, but no mode_v1/mode_v2 keys at
        # all) must replay to the identical S3/S4 outcome -- S2/S3/S4
        # replay never reads mode at all, only the already-resolved
        # forced_skip/skip_reason.
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        s1_path = _write_s1_artifact(
            output_dir, forced_skip=True, skip_reason=_SKIP_REASON,
            planner_evidence_ctx="", include_mode_fields=False,
        )
        llm = mock.MagicMock()
        from utilities.autopatcher.remediation_planner import generate_remediation_strategy as _real_strategy_fn
        with mock.patch(
            "utilities.autopatcher.replay_engine.generate_remediation_strategy", wraps=_real_strategy_fn,
        ):
            s2_result = replay_engine._run_replay_remediation_strategy(
                repo_root=str(tmp_path), llm=llm, output_dir=output_dir,
                resolved_dependencies={REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: _resolution(s1_path)},
            )
        s3_result = replay_engine._run_replay_guided_context_acquisition(
            repo_root=str(tmp_path), llm=llm, output_dir=output_dir,
            resolved_dependencies={
                REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: _resolution(s1_path),
                REMEDIATION_STRATEGY: _resolution(s2_result.artifact_path),
            },
        )
        s3_data = json.loads(s3_result.artifact_path.read_text())
        assert s3_data["skip_patch_generation"] is True
        assert s3_data["skip_patch_generation_reason"] == _SKIP_REASON


class TestNonForcedReplayControl:
    """Existing replay behavior must remain unchanged when the verifier
    never forced a skip -- both for an S1 artifact that predates this
    feature (no `planner_claim_verification` key at all) and for one where
    the verifier ran but never blocked anything."""

    def test_missing_planner_claim_verification_key_is_backward_compatible(self, tmp_path):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        s1_path = _write_s1_artifact(
            output_dir, forced_skip=False, skip_reason=None,
            planner_evidence_ctx="", include_planner_claim_verification=False,
        )
        llm = mock.MagicMock()

        s2_result = replay_engine._run_replay_remediation_strategy(
            repo_root=str(tmp_path), llm=llm, output_dir=output_dir,
            resolved_dependencies={REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: _resolution(s1_path)},
        )
        s3_result = replay_engine._run_replay_guided_context_acquisition(
            repo_root=str(tmp_path), llm=llm, output_dir=output_dir,
            resolved_dependencies={
                REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: _resolution(s1_path),
                REMEDIATION_STRATEGY: _resolution(s2_result.artifact_path),
            },
        )
        s3_data = json.loads(s3_result.artifact_path.read_text())
        # No verifier data at all -- must not crash, must not spuriously
        # force a skip; whatever value skip_patch_generation takes here is
        # driven entirely by the pre-existing Edit-Readiness/Strategy gates,
        # exactly as before this feature existed.
        assert s3_data["skip_patch_generation_reason"] is None

    def test_present_but_not_forced_skip_is_not_propagated(self, tmp_path):
        output_dir = tmp_path / "out"
        output_dir.mkdir()
        s1_path = _write_s1_artifact(
            output_dir, forced_skip=False, skip_reason=None, planner_evidence_ctx="",
        )
        llm = mock.MagicMock()

        s2_result = replay_engine._run_replay_remediation_strategy(
            repo_root=str(tmp_path), llm=llm, output_dir=output_dir,
            resolved_dependencies={REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: _resolution(s1_path)},
        )
        s3_result = replay_engine._run_replay_guided_context_acquisition(
            repo_root=str(tmp_path), llm=llm, output_dir=output_dir,
            resolved_dependencies={
                REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: _resolution(s1_path),
                REMEDIATION_STRATEGY: _resolution(s2_result.artifact_path),
            },
        )
        s3_data = json.loads(s3_result.artifact_path.read_text())
        assert s3_data["skip_patch_generation_reason"] is None
