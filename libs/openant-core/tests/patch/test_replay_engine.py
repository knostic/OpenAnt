"""Tests for the generic Auto Patcher replay engine
(utilities/autopatcher/replay_engine.py) -- Foundation Batch A.

Covers: unknown/not-yet-replayable stage failures, the transitional
test_analysis_and_plan replay (LLM-call guarantee, provenance, immutability),
capability-aware preflight, LLM-ownership enforcement, and dependency
resolution/staleness failures exercised THROUGH the engine end-to-end
(using synthetic stub stages registered temporarily on top of the real
registry, since Batch A ships only one real replayable stage -- see
TestSyntheticChaining).

Hermetic throughout: LLM_PROVIDER=mock (tests/patch/conftest.py's autouse
fixture), no network, no real LLM provider credential, no Docker.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from utilities.autopatcher import lineage, stage_registry
from utilities.autopatcher import replay_engine as replay_engine_module
from utilities.autopatcher.replay_engine import (
    REPLAY_HANDLERS,
    ReplayEngineError,
    ReplayHandler,
    RunFnResult,
    _assert_llm_ownership,
    _docker_preflight,
    _llm_provider_preflight,
    _repo_preflight,
    replay_stage,
)
from utilities.autopatcher.stage_registry import STAGE_SPECS, StageSpec


# ---------------------------------------------------------------------------
# Fixtures / helpers (mirrors test_stage_replay.py's, kept local/hermetic)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_replay_handlers():
    """REPLAY_HANDLERS (replay_engine.py) is a plain module-level dict --
    unlike Batch A's earlier register_run_fn(), it is never mutated by
    production code, but TestSyntheticChaining below deliberately mutates
    it to exercise the engine generically with stub stages; restore it
    after every test so that leaks into other tests. Note this fixture
    restores REPLAY_HANDLERS, never stage_registry.STAGE_SPECS -- that
    registry is immutable (MappingProxyType) and is never touched by any
    test in this file."""
    snapshot = dict(REPLAY_HANDLERS)
    yield
    REPLAY_HANDLERS.clear()
    REPLAY_HANDLERS.update(snapshot)


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)


def _make_target_repo(tmp_path: Path, name: str = "target-repo", *, with_evidence: bool = True) -> Path:
    repo = tmp_path / name
    repo.mkdir()
    if with_evidence:
        (repo / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    else:
        (repo / ".gitkeep").write_text("", encoding="utf-8")
    _git("init", cwd=repo)
    _git("config", "user.email", "t@t.com", cwd=repo)
    _git("config", "user.name", "T", cwd=repo)
    _git("add", "-A", cwd=repo)
    _git("commit", "-m", "init", cwd=repo)
    return repo


def _head_sha(repo: Path) -> str:
    result = subprocess.run(
        ["git", "log", "-1", "--format=%H"], cwd=repo, capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def _write_full_run_trace(
    trace_dir: Path,
    *,
    repo_root: Path,
    llm_provider: str = "anthropic",
    llm_model: str = "claude-source-x",
    executions: "list | None" = None,
) -> Path:
    """A v3 full-run manifest -- honestly empty `executions` by default
    (production pipeline.run() is not instrumented yet in Batch B1; see
    lineage.py's module docstring), never synthesized placeholder rows."""
    trace_dir.mkdir(parents=True, exist_ok=True)
    manifest = lineage.new_full_run_manifest(
        target_repository={"repo_root": str(repo_root), "repo_commit": _head_sha(repo_root)},
        openant={"patcher_commit": "1234567890abcdef1234567890abcdef12345678"},
        llm={"provider": llm_provider, "model": llm_model},
        executions=executions or [],
    )
    (trace_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return trace_dir


def _execution_for(manifest: dict, canonical_stage: str) -> dict:
    matching = [e for e in manifest["executions"] if e["canonical_stage"] == canonical_stage]
    assert len(matching) == 1, f"expected exactly one execution for {canonical_stage!r}, found {len(matching)}"
    return matching[0]


def _accepted_response_json(evidence=("pyproject.toml",)) -> str:
    return json.dumps({
        "setup_commands": [["python", "-m", "pip", "install", "-e", "."]],
        "test_command": ["python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"],
        "result_strategy": "junit",
        "result_output_path": "/tmp/openant-result.xml",
        "runtime_family": "python",
        "runtime_version_hint": "3.11",
        "evidence": list(evidence),
        "reasoning_summary": "pyproject.toml declares pytest.",
        "confidence": "high",
    })


def _install_fake_call_llm(monkeypatch, response):
    import utilities.autopatcher.llm_client as llm_client_module

    calls = []

    def fake(prompt, model=None, stage="unknown"):
        calls.append({"prompt": prompt, "model": model, "stage": stage})
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(llm_client_module, "call_llm", fake)
    return calls


# ---------------------------------------------------------------------------
# Unknown / not-yet-replayable stage
# ---------------------------------------------------------------------------


class TestStageDispatch:
    def test_unknown_stage_fails_before_any_io(self, tmp_path):
        with pytest.raises(ReplayEngineError, match="Unknown stage"):
            replay_stage(
                source_run=tmp_path / "does-not-exist",
                stage_name="not_a_real_stage",
                output_dir=tmp_path / "out",
            )
        assert not (tmp_path / "out").exists()

    def test_registered_but_not_replayable_fails_before_any_io(self, tmp_path):
        with pytest.raises(ReplayEngineError, match="not replayable yet"):
            replay_stage(
                source_run=tmp_path / "does-not-exist",
                stage_name="trust_signals_and_recommendation",
                output_dir=tmp_path / "out",
            )
        assert not (tmp_path / "out").exists()

    def test_exactly_the_batch_b7_stages_have_a_replay_handler_today(self):
        assert set(REPLAY_HANDLERS.keys()) == {
            "test_analysis_and_plan",
            "repository_analysis_and_remediation_planning",
            "remediation_strategy",
            "guided_context_acquisition",
            "patch_generation_and_post_patch_investigation",
            "challenger",
            "patch_repair_and_calibration",
            "patch_review",
            "confidence_scoring",
            "impact_and_behavior_analysis",
            "existing_test_comparison",
            "report_generation",
        }

    def test_registered_but_no_handler_stage_fails_cleanly_and_lists_what_is_replayable(self, tmp_path, capsys):
        for stage_name in stage_registry.CANONICAL_STAGE_ORDER:
            if stage_name in REPLAY_HANDLERS:
                continue
            with pytest.raises(ReplayEngineError, match="not replayable yet"):
                replay_stage(source_run=tmp_path / "nowhere", stage_name=stage_name, output_dir=tmp_path / "out")

    def test_persisted_and_replayable_are_demonstrably_separate_concepts(self, tmp_path):
        """Every canonical stage except test_analysis_and_plan is
        "produced-but-not-replayable"-capable: it can appear as
        status="produced" in a manifest (see
        test_lineage.py::test_produced_artifact_resolves_even_when_stage_has_no_replay_handler)
        while having zero entry in REPLAY_HANDLERS. This test proves the
        REPLAY_HANDLERS side of that separation directly: attempting to
        replay any such stage fails with "not replayable yet", never with
        some other error implying its artifact doesn't/can't exist."""
        produced_but_not_replayable = [
            n for n in stage_registry.CANONICAL_STAGE_ORDER if n not in REPLAY_HANDLERS
        ]
        assert produced_but_not_replayable  # 12 of the 13 stages today
        assert "test_analysis_and_plan" not in produced_but_not_replayable

        with pytest.raises(ReplayEngineError, match="not replayable yet"):
            replay_stage(
                source_run=tmp_path / "nowhere",
                stage_name=produced_but_not_replayable[0],
                output_dir=tmp_path / "out",
            )


# ---------------------------------------------------------------------------
# test_analysis_and_plan -- the one real replayable stage in Batch A
# ---------------------------------------------------------------------------


class TestTestAnalysisAndPlanReplay:
    def test_accepted_plan_via_engine(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        calls = _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=output_dir)

        assert result.outcome == "accepted"
        assert result.execution_id == "001_test_analysis_and_plan"
        assert len(calls) == 1
        assert calls[0]["stage"] == "test_plan_discovery"  # the only tag this stage owns
        manifest = json.loads((output_dir / "run_manifest.json").read_text())
        assert manifest["kind"] == "replay"
        assert "replaces_stage" not in manifest
        assert "stages" not in manifest
        assert len(manifest["executions"]) == 1
        execution = _execution_for(manifest, "test_analysis_and_plan")
        assert execution["execution_id"] == "001_test_analysis_and_plan"
        assert execution["invocation_kind"] == "replay"
        assert execution["transitional"] is True
        assert execution["sub_artifacts_produced"] == ["test_execution_plan"]
        assert "test_support" in execution["sub_artifacts_not_yet_produced"]
        assert execution["llm_calls"] and execution["llm_calls"][0]["stage"] == "test_plan_discovery"
        assert (output_dir / "test_execution_plan.json").is_file()

    def test_rejected_plan_via_engine(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, "not json at all")
        output_dir = tmp_path / "replay-out"

        result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=output_dir)

        assert result.outcome == "rejected"
        assert (output_dir / "rejection_reason.json").is_file()

    def test_transitional_stage_has_zero_declared_dependencies_to_check(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=output_dir)

        execution = _execution_for(result.manifest, "test_analysis_and_plan")
        assert execution["consumed"] == {}

    def test_invocation_kind_is_replay(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())

        result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=tmp_path / "out")

        execution = _execution_for(result.manifest, "test_analysis_and_plan")
        assert execution["invocation_kind"] == "replay"

    def test_replay_of_is_null_when_source_has_no_prior_execution(self, tmp_path, monkeypatch):
        """The source full run predates real StageExecution persistence
        (Batch B1 scope) -- replay_of must be honestly null, never
        fabricated."""
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())

        result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=tmp_path / "out")

        execution = _execution_for(result.manifest, "test_analysis_and_plan")
        assert execution["replay_of"] is None

    def test_replay_of_references_the_prior_execution_when_chaining(self, tmp_path, monkeypatch):
        """Replaying the SAME canonical stage a second time, from a
        lineage that already contains a real execution of it, must set
        replay_of honestly -- this is genuinely knowable here."""
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        first = tmp_path / "replay-1"
        first_result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=first)

        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        second_result = replay_stage(source_run=first, stage_name="test_analysis_and_plan", output_dir=tmp_path / "replay-2")

        execution = _execution_for(second_result.manifest, "test_analysis_and_plan")
        assert execution["replay_of"] == {"run": str(first), "execution_id": first_result.execution_id}

    def test_replay_produces_exactly_one_new_execution_record(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())

        result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=tmp_path / "out")

        assert len(result.manifest["executions"]) == 1

    def test_replay_produces_same_test_execution_plan_content_as_before(self, tmp_path, monkeypatch):
        """Migrating to v3 must not change WHAT gets discovered -- only
        how it's persisted."""
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "out"

        replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=output_dir)

        parsed = json.loads((output_dir / "test_execution_plan.json").read_text())
        assert parsed["test_command"] == ["python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"]
        assert parsed["result_strategy"] == "junit"
        assert parsed["confidence"] == "high"
        assert parsed["evidence"] == ["pyproject.toml"]


class TestRepoIdentitySafety:
    def test_wrong_sha_fails_before_llm(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        calls = _install_fake_call_llm(monkeypatch, _accepted_response_json())
        (repo / "new_file.txt").write_text("x\n", encoding="utf-8")
        _git("add", "-A", cwd=repo)
        _git("commit", "-m", "second", cwd=repo)

        with pytest.raises(Exception, match="HEAD does not match"):
            replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=tmp_path / "out")
        assert len(calls) == 0

    def test_dirty_repo_fails_before_llm(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        calls = _install_fake_call_llm(monkeypatch, _accepted_response_json())
        (repo / "untracked.txt").write_text("x\n", encoding="utf-8")

        with pytest.raises(Exception, match="uncommitted changes"):
            replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=tmp_path / "out")
        assert len(calls) == 0

    def test_dirty_openant_checkout_does_not_block_replay(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        import utilities.autopatcher.replay_engine as replay_engine_module

        monkeypatch.setattr(replay_engine_module, "is_worktree_clean", lambda path: Path(path) == repo)
        output_dir = tmp_path / "replay-out"

        result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=output_dir)

        assert result.outcome == "accepted"
        assert result.manifest["openant"]["replay_openant_dirty"] is True


class TestProvenanceRecorded:
    def test_source_and_replay_llm_provenance_recorded(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo, llm_provider="anthropic", llm_model="claude-source-x")
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=output_dir)

        llm_prov = result.manifest["llm"]
        assert llm_prov["source_provider"] == "anthropic"
        assert llm_prov["source_model"] == "claude-source-x"
        assert llm_prov["replay_provider"] == "mock"

    def test_source_and_replay_openant_provenance_recorded(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        output_dir = tmp_path / "replay-out"

        result = replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=output_dir)

        openant = result.manifest["openant"]
        assert openant["source_patcher_commit"] == "1234567890abcdef1234567890abcdef12345678"
        assert "replay_patcher_commit" in openant


class TestImmutability:
    def test_source_run_byte_for_byte_unchanged_after_replay(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        before = (source / "run_manifest.json").read_bytes()
        _install_fake_call_llm(monkeypatch, _accepted_response_json())

        replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=tmp_path / "out")

        assert (source / "run_manifest.json").read_bytes() == before

    def test_prior_replay_unchanged_after_a_second_independent_replay(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        _install_fake_call_llm(monkeypatch, _accepted_response_json())
        first_output = tmp_path / "replay-1"
        replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=first_output)
        before = (first_output / "run_manifest.json").read_bytes()

        _install_fake_call_llm(monkeypatch, "not json at all")
        replay_stage(source_run=source, stage_name="test_analysis_and_plan", output_dir=tmp_path / "replay-2")

        assert (first_output / "run_manifest.json").read_bytes() == before


# ---------------------------------------------------------------------------
# LLM ownership enforcement
# ---------------------------------------------------------------------------


class TestLLMOwnershipEnforcement:
    def test_owned_tag_passes(self):
        _assert_llm_ownership([{"stage": "test_plan_discovery"}], "test_analysis_and_plan")  # no raise

    def test_foreign_tag_raises(self):
        with pytest.raises(ReplayEngineError, match="LLM ownership violation"):
            _assert_llm_ownership([{"stage": "patch_generation"}], "test_analysis_and_plan")

    def test_no_calls_at_all_passes(self):
        _assert_llm_ownership([], "test_analysis_and_plan")  # no raise


class TestReplayHandlerValidation:
    """_validate_replay_handlers() runs once at import time -- these tests
    call it directly against deliberately-broken REPLAY_HANDLERS content
    to prove it actually catches misconfiguration, without needing a
    second real broken import to happen."""

    def test_unknown_stage_in_handlers_raises(self, monkeypatch):
        monkeypatch.setitem(REPLAY_HANDLERS, "not_a_real_stage", ReplayHandler(run_fn=lambda **kw: None, dependencies=()))
        with pytest.raises(ValueError, match="unknown canonical stage"):
            replay_engine_module._validate_replay_handlers()

    def test_handler_dependencies_wider_than_approved_raises(self, monkeypatch):
        monkeypatch.setitem(
            REPLAY_HANDLERS, "challenger",
            ReplayHandler(run_fn=lambda **kw: None, dependencies=("not_an_approved_dependency",)),
        )
        with pytest.raises(ValueError, match="not a subset"):
            replay_engine_module._validate_replay_handlers()

    def test_current_replay_handlers_pass_validation(self):
        replay_engine_module._validate_replay_handlers()  # no raise


# ---------------------------------------------------------------------------
# Capability-aware preflight -- unit-level, using the real registry's
# capability flags on stages that legitimately differ (Batch A has only
# ONE replayable stage, but the preflight helpers themselves are pure
# functions of a StageSpec's flags and are directly testable against
# every capability combination the registry declares).
# ---------------------------------------------------------------------------


class TestCapabilityAwarePreflight:
    def test_docker_preflight_skipped_for_stage_that_does_not_require_it(self):
        spec = STAGE_SPECS["report_generation"]
        assert spec.requires_docker is False
        _docker_preflight(spec)  # must not raise / must not even try to import docker helpers

    def test_docker_preflight_invoked_for_stage_that_requires_it(self, monkeypatch):
        spec = STAGE_SPECS["existing_test_comparison"]
        assert spec.requires_docker is True
        called = []
        import utilities.autopatcher.existing_test_regression as etr

        monkeypatch.setattr(etr, "preflight_test_comparison_environment", lambda: called.append(True))
        _docker_preflight(spec)
        assert called == [True]

    def test_repo_preflight_skipped_for_stage_that_does_not_require_repo_access(self):
        spec = STAGE_SPECS["confidence_scoring"]
        assert spec.requires_repo_access is False
        from utilities.autopatcher.stage_replay import SourceProvenance

        provenance = SourceProvenance(
            repo_root="/nonexistent", repo_commit="deadbeef", repo_commit_is_short=False,
            patcher_commit=None, llm_provider=None, llm_model=None, input_type=None, input_id=None,
            source="structured_manifest",
        )
        # Must NOT raise even though /nonexistent doesn't exist -- the SHA/
        # clean-worktree gate is never invoked for a stage that doesn't
        # require repo access.
        result = _repo_preflight(spec, None, provenance)
        assert result is None

    def test_repo_preflight_enforced_for_stage_that_requires_repo_access(self, tmp_path):
        spec = STAGE_SPECS["test_analysis_and_plan"]
        assert spec.requires_repo_access is True
        from utilities.autopatcher.stage_replay import SourceProvenance, StageReplayError

        provenance = SourceProvenance(
            repo_root=str(tmp_path / "nonexistent"), repo_commit="deadbeef", repo_commit_is_short=False,
            patcher_commit=None, llm_provider=None, llm_model=None, input_type=None, input_id=None,
            source="structured_manifest",
        )
        with pytest.raises(StageReplayError, match="does not exist"):
            _repo_preflight(spec, None, provenance)

    def test_llm_provider_preflight_skipped_for_deterministic_stage(self, monkeypatch):
        spec = STAGE_SPECS["impact_and_behavior_analysis"]
        assert spec.requires_llm_provider is False
        called = []
        import utilities.autopatcher.replay_engine as replay_engine_module

        monkeypatch.setattr(replay_engine_module, "ensure_provider_configured", lambda: called.append(True))
        _llm_provider_preflight(spec)
        assert called == []

    def test_llm_provider_preflight_invoked_for_llm_owning_stage(self, monkeypatch):
        spec = STAGE_SPECS["test_analysis_and_plan"]
        assert spec.requires_llm_provider is True
        called = []
        import utilities.autopatcher.replay_engine as replay_engine_module

        monkeypatch.setattr(replay_engine_module, "ensure_provider_configured", lambda: called.append(True))
        _llm_provider_preflight(spec)
        assert called == [True]


# ---------------------------------------------------------------------------
# Dependency resolution / staleness THROUGH the engine, end to end, using
# synthetic stub stages (Batch A has no second real replayable stage yet
# -- these tests wire up trivial run_fns on top of TWO real canonical
# stage names with a real dependency edge between them, restored after
# each test by the autouse _restore_stage_registry fixture above).
# ---------------------------------------------------------------------------


class TestSyntheticChaining:
    """repository_analysis_and_remediation_planning (no deps) ->
    remediation_strategy (depends on it) is a REAL edge in
    stage_registry.STAGE_DEPENDENCIES. Stubbing trivial run_fns onto both
    lets these tests prove the engine's dependency resolution, staleness
    detection, chaining, and missing-dependency-fails-first guarantees
    end-to-end, without touching any real production stage code."""

    UPSTREAM = "repository_analysis_and_remediation_planning"
    DOWNSTREAM = "remediation_strategy"

    def _stub_run_fn(self, tag):
        def _run_fn(*, repo_root, llm, output_dir, resolved_dependencies, chain=None):
            artifact_path = output_dir / "artifact.json"
            artifact_path.write_text(json.dumps({"tag": tag}), encoding="utf-8")
            return RunFnResult(outcome="ok", artifact_path=artifact_path, extra_stage_fields={})
        return _run_fn

    def _register_both_stubs(self, monkeypatch, upstream_tag="u0", downstream_deps=None):
        # Batch B8: both UPSTREAM and DOWNSTREAM now also have REAL
        # replay handlers (S1/S2) -- monkeypatch.setitem auto-reverts this
        # temporary stub swap at test teardown, so these synthetic-engine
        # tests never leak stub handlers into any other test in the suite.
        monkeypatch.setitem(REPLAY_HANDLERS, self.UPSTREAM, ReplayHandler(
            run_fn=self._stub_run_fn(upstream_tag),
            dependencies=(),
        ))
        monkeypatch.setitem(REPLAY_HANDLERS, self.DOWNSTREAM, ReplayHandler(
            run_fn=self._stub_run_fn("d0"),
            dependencies=(self.UPSTREAM,) if downstream_deps is None else downstream_deps,
        ))

    def test_downstream_fails_before_run_fn_when_dependency_missing(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)  # upstream stage never produced

        sentinel_called = []
        monkeypatch.setitem(REPLAY_HANDLERS, self.DOWNSTREAM, ReplayHandler(
            run_fn=lambda **kw: sentinel_called.append(True) or RunFnResult(outcome="ok", artifact_path=None, extra_stage_fields={}),
            dependencies=(self.UPSTREAM,),
        ))

        with pytest.raises(ReplayEngineError, match="UNRESOLVED|dependency"):
            replay_stage(source_run=source, stage_name=self.DOWNSTREAM, output_dir=tmp_path / "out")
        assert sentinel_called == []  # run_fn never invoked
        assert not (tmp_path / "out").exists()

    def test_chained_replay_consumes_the_new_upstream_artifact(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        self._register_both_stubs(monkeypatch)

        replay_upstream = tmp_path / "replay-upstream"
        replay_stage(source_run=source, stage_name=self.UPSTREAM, output_dir=replay_upstream)

        replay_downstream = tmp_path / "replay-downstream"
        result = replay_stage(source_run=replay_upstream, stage_name=self.DOWNSTREAM, output_dir=replay_downstream)

        consumed = _execution_for(result.manifest, self.DOWNSTREAM)["consumed"][self.UPSTREAM]
        assert consumed["run"] == str(replay_upstream)

    def test_downstream_replay_from_original_is_stale_after_upstream_replayed_elsewhere(self, tmp_path, monkeypatch):
        """Full run has UPSTREAM_0 -> DOWNSTREAM_0. Replay UPSTREAM alone.
        Replaying DOWNSTREAM again directly from the ORIGINAL full run
        (not the new upstream replay) must still work (dependencies are
        resolved fresh from whatever --source-run is given), but
        replaying it from a lineage where upstream was superseded and
        downstream was NOT re-run must show downstream is stale when
        queried."""
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        self._register_both_stubs(monkeypatch)

        replay_upstream = tmp_path / "replay-upstream"
        replay_stage(source_run=source, stage_name=self.UPSTREAM, output_dir=replay_upstream)

        # DOWNSTREAM was never produced anywhere in replay_upstream's
        # lineage -- resolving it must be UNRESOLVED, not silently valid.
        chain = lineage.build_chain(replay_upstream)
        resolution = lineage.resolve_effective(chain, self.DOWNSTREAM, {})
        assert resolution.state == lineage.UNRESOLVED

    def test_branch_replays_of_upstream_do_not_interfere(self, tmp_path, monkeypatch):
        repo = _make_target_repo(tmp_path)
        source = _write_full_run_trace(tmp_path / "run", repo_root=repo)
        self._register_both_stubs(monkeypatch)

        branch_a = tmp_path / "branch-a"
        branch_b = tmp_path / "branch-b"
        replay_stage(source_run=source, stage_name=self.UPSTREAM, output_dir=branch_a)
        replay_stage(source_run=source, stage_name=self.UPSTREAM, output_dir=branch_b)

        a_bytes = (branch_a / "run_manifest.json").read_bytes()
        b_bytes = (branch_b / "run_manifest.json").read_bytes()
        assert a_bytes != b_bytes or branch_a != branch_b  # distinct, independent directories

        # Downstream chained from branch_a must resolve upstream from
        # branch_a, never branch_b.
        downstream_from_a = tmp_path / "downstream-from-a"
        result = replay_stage(source_run=branch_a, stage_name=self.DOWNSTREAM, output_dir=downstream_from_a)
        consumed = _execution_for(result.manifest, self.DOWNSTREAM)["consumed"][self.UPSTREAM]
        assert consumed["run"] == str(branch_a)
