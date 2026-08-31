"""Tests for the unified full-run/replay manifest model + dependency-aware
lineage resolution (utilities/autopatcher/lineage.py) -- Batch B1
(execution-based v3 schema).

Hermetic: hand-built manifest fixtures on tmp_path, no LLM, no real repo,
no Docker. This file tests the RESOLVER in isolation, independent of the
replay engine (see test_replay_engine.py for engine-level behavior).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from utilities.autopatcher import lineage
from utilities.autopatcher.lineage import (
    INVOCATION_KIND_INITIAL,
    INVOCATION_KIND_REPLAY,
    INVOCATION_KIND_RETRY,
    RESOLVED,
    STALE,
    UNRESOLVED,
    ArtifactIdentity,
    LineageError,
    Resolution,
    build_chain,
    find_latest_execution_identity,
    latest_execution_in_manifest,
    load_manifest,
    make_execution_id,
    new_execution_record,
    new_full_run_manifest,
    new_replay_manifest,
    resolve_effective,
)


def _write(run_dir: Path, manifest: dict) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return run_dir


def _full_run(run_dir: Path, executions: list) -> Path:
    manifest = new_full_run_manifest(
        target_repository={"repo_root": "/repo", "repo_commit": "aaa"},
        openant={"patcher_commit": "bbb"},
        llm={"provider": "mock", "model": "mock"},
        executions=executions,
    )
    return _write(run_dir, manifest)


def _replay(run_dir: Path, *, parent: Path, executions: list) -> Path:
    manifest = new_replay_manifest(
        parent=parent,
        target_repository={"repo_root": "/repo", "repo_commit": "aaa"},
        openant={"patcher_commit": "bbb", "replay_patcher_commit": "ccc"},
        llm={"provider": "mock", "model": "mock"},
        executions=executions,
    )
    return _write(run_dir, manifest)


def _execution(canonical_stage, sequence, *, consumed=None, artifact_path="x.json", invocation_kind=INVOCATION_KIND_INITIAL, replay_of=None, invoked_by=None, run_dir=None, outcome=None, extra=None):
    """Convenience wrapper: new_execution_record with a matching execution_id."""
    return new_execution_record(
        execution_id=make_execution_id(sequence, canonical_stage),
        canonical_stage=canonical_stage,
        sequence=sequence,
        invocation_kind=invocation_kind,
        consumed=consumed,
        artifact_path=artifact_path,
        replay_of=replay_of,
        invoked_by=invoked_by,
        outcome=outcome,
        extra=extra,
    )


# ---------------------------------------------------------------------------
# Manifest shape / schema versioning
# ---------------------------------------------------------------------------


class TestSchemaVersioning:
    def test_new_full_run_manifest_uses_schema_v3(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[])
        assert load_manifest(run)["schema_version"] == 3

    def test_new_replay_manifest_uses_schema_v3(self, tmp_path):
        source = _full_run(tmp_path / "run", executions=[])
        replay = _replay(tmp_path / "replay", parent=source, executions=[])
        assert load_manifest(replay)["schema_version"] == 3

    def test_schema_version_constant_is_3(self):
        assert lineage.SCHEMA_VERSION == 3

    def test_run_traced_schema_version_matches_lineage_schema_version(self):
        """Two independent constants (run_traced.py's own
        _REPLAY_SCHEMA_VERSION and lineage.SCHEMA_VERSION) must never
        drift apart -- both describe the version written into the SAME
        top-level "schema_version" field of the SAME manifest."""
        import importlib.util
        from pathlib import Path as _Path

        tools_dir = _Path(__file__).resolve().parent.parent.parent / "utilities" / "autopatcher" / "tools"
        spec = importlib.util.spec_from_file_location("run_traced_schema_check", tools_dir / "run_traced.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module._REPLAY_SCHEMA_VERSION == lineage.SCHEMA_VERSION

    def test_v1_missing_schema_version_uses_bounded_legacy_compatibility(self, tmp_path):
        run_dir = tmp_path / "v1-run"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({"status": "success"}), encoding="utf-8")
        manifest = load_manifest(run_dir)
        assert manifest["kind"] == "full_run"
        assert manifest["parent"] is None
        # Honest -- no synthetic per-stage executions (Batch B1 removed
        # the Batch-A placeholder-row synthesis entirely).
        assert manifest["executions"] == []

    def test_v1_with_explicit_schema_version_also_bounded_legacy(self, tmp_path):
        run_dir = tmp_path / "v1-explicit"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({
            "schema_version": 1,
            "target_repository": {"repo_root": "/repo", "repo_commit": "aaa"},
            "openant": {}, "llm": {},
        }), encoding="utf-8")
        manifest = load_manifest(run_dir)
        assert manifest["kind"] == "full_run"
        assert manifest["executions"] == []

    def test_v2_uses_bounded_compatibility(self, tmp_path):
        run_dir = tmp_path / "v2-run"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({
            "schema_version": 2,
            "kind": "full_run",
            "parent": None,
            "target_repository": {"repo_root": "/repo", "repo_commit": "aaa"},
            "openant": {}, "llm": {},
            "stages": {
                "test_analysis_and_plan": {
                    "status": "produced",
                    "artifact_path": "plan.json",
                    "dependencies_checked": [],
                    "consumed_dependencies": {},
                    "llm_calls": [{"seq": 1, "stage": "test_plan_discovery"}],
                    "outcome": "accepted",
                    "timing": None,
                },
                "patch_repair_and_calibration": {"status": "not_persisted"},
                "challenger": {"status": "legacy"},
            },
        }), encoding="utf-8")
        manifest = load_manifest(run_dir)
        assert manifest["schema_version"] == 2
        assert len(manifest["executions"]) == 1
        execution = manifest["executions"][0]
        assert execution["canonical_stage"] == "test_analysis_and_plan"
        assert execution["invocation_kind"] == INVOCATION_KIND_INITIAL
        assert execution["outcome"] == "accepted"
        assert execution["llm_calls"] == [{"seq": 1, "stage": "test_plan_discovery"}]

    def test_v2_compat_never_fabricates_from_not_persisted_or_legacy(self, tmp_path):
        """Only status=="produced" v2 entries become executions -- never
        "not_persisted"/"legacy", which have no artifact to adapt."""
        run_dir = tmp_path / "v2-honest"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({
            "schema_version": 2,
            "target_repository": {}, "openant": {}, "llm": {},
            "stages": {
                "test_analysis_and_plan": {"status": "not_persisted"},
                "challenger": {"status": "legacy"},
            },
        }), encoding="utf-8")
        manifest = load_manifest(run_dir)
        assert manifest["executions"] == []

    def test_v2_compat_never_synthesizes_more_than_one_execution_per_stage(self, tmp_path):
        """v2 never recorded retries/multiple attempts -- compat must not
        invent them."""
        run_dir = tmp_path / "v2-single"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({
            "schema_version": 2,
            "target_repository": {}, "openant": {}, "llm": {},
            "stages": {"test_analysis_and_plan": {"status": "produced", "artifact_path": "x.json"}},
        }), encoding="utf-8")
        manifest = load_manifest(run_dir)
        matching = [e for e in manifest["executions"] if e["canonical_stage"] == "test_analysis_and_plan"]
        assert len(matching) == 1

    def test_unsupported_future_schema_fails_before_execution(self, tmp_path):
        run_dir = tmp_path / "future"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({"schema_version": 999}), encoding="utf-8")
        with pytest.raises(LineageError, match="schema_version=999"):
            load_manifest(run_dir)

    def test_v3_executions_trusted_as_written_not_synthesized(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("test_analysis_and_plan", 1)])
        manifest = load_manifest(run)
        assert len(manifest["executions"]) == 1
        assert manifest["executions"][0]["canonical_stage"] == "test_analysis_and_plan"


# ---------------------------------------------------------------------------
# v3 manifest shape: executions, not stages; no replaces_stage
# ---------------------------------------------------------------------------


class TestV3ManifestShape:
    def test_v3_uses_executions_not_stages(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[])
        manifest = load_manifest(run)
        assert "executions" in manifest
        assert "stages" not in manifest

    def test_v3_has_no_replaces_stage(self, tmp_path):
        source = _full_run(tmp_path / "run", executions=[])
        replay = _replay(tmp_path / "replay", parent=source, executions=[_execution("challenger", 1)])
        manifest = load_manifest(replay)
        assert "replaces_stage" not in manifest

    def test_replay_records_parent(self, tmp_path):
        source = _full_run(tmp_path / "run", executions=[])
        replay = _replay(tmp_path / "replay", parent=source, executions=[])
        assert load_manifest(replay)["parent"] == str(source)

    def test_duplicate_execution_id_within_a_manifest_is_rejected(self, tmp_path):
        dup = [_execution("challenger", 1), _execution("challenger", 1)]  # same sequence -> same id
        with pytest.raises(LineageError, match="Duplicate execution_id"):
            new_full_run_manifest(target_repository={}, openant={}, llm={}, executions=dup)

    def test_duplicate_execution_id_rejected_on_load_too(self, tmp_path):
        run_dir = tmp_path / "dup"
        run_dir.mkdir()
        raw = {
            "schema_version": 3, "kind": "full_run", "parent": None,
            "target_repository": {}, "openant": {}, "llm": {},
            "executions": [
                {"execution_id": "001_challenger", "canonical_stage": "challenger", "sequence": 1, "invocation_kind": "initial", "consumed": {}},
                {"execution_id": "001_challenger", "canonical_stage": "challenger", "sequence": 2, "invocation_kind": "initial", "consumed": {}},
            ],
        }
        (run_dir / "run_manifest.json").write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(LineageError, match="Duplicate execution_id"):
            load_manifest(run_dir)

    def test_invalid_invocation_kind_rejected(self):
        with pytest.raises(LineageError, match="invocation_kind"):
            new_execution_record(
                execution_id="001_challenger", canonical_stage="challenger", sequence=1,
                invocation_kind="not_a_real_kind",
            )

    def test_stage_local_attempt_is_not_a_persisted_field(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("challenger", 1)])
        execution = load_manifest(run)["executions"][0]
        assert "stage_local_attempt" not in execution

    def test_execution_level_trigger_is_not_a_persisted_field(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("challenger", 1)])
        execution = load_manifest(run)["executions"][0]
        assert "trigger" not in execution


# ---------------------------------------------------------------------------
# Chain building (unchanged from Batch A -- directory-level, untouched by
# the executions-list shape change)
# ---------------------------------------------------------------------------


class TestChainBuilding:
    def test_single_full_run_chain_has_one_element(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[])
        chain = build_chain(run)
        assert [str(p) for p in chain] == [str(run)]

    def test_chain_walks_parent_pointers_tip_first(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[])
        replay1 = _replay(tmp_path / "replay1", parent=run, executions=[])
        replay2 = _replay(tmp_path / "replay2", parent=replay1, executions=[])
        chain = build_chain(replay2)
        assert [str(p) for p in chain] == [str(replay2), str(replay1), str(run)]

    def test_cycle_raises_lineage_error(self, tmp_path):
        a_dir = tmp_path / "a"
        b_dir = tmp_path / "b"
        _write(a_dir, new_replay_manifest(parent=b_dir, target_repository={}, openant={}, llm={}, executions=[]))
        _write(b_dir, new_replay_manifest(parent=a_dir, target_repository={}, openant={}, llm={}, executions=[]))
        with pytest.raises(LineageError, match="Cycle detected"):
            build_chain(a_dir)

    def test_parent_directories_remain_immutable_after_child_created(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("challenger", 1)])
        before = (run / "run_manifest.json").read_bytes()
        _replay(tmp_path / "replay", parent=run, executions=[_execution("patch_review", 1)])
        assert (run / "run_manifest.json").read_bytes() == before


# ---------------------------------------------------------------------------
# latest_execution_in_manifest / find_latest_execution_identity
# ---------------------------------------------------------------------------


class TestLatestExecutionLookup:
    def test_multiple_executions_of_same_stage_are_representable(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[
            _execution("patch_generation_and_post_patch_investigation", 1, artifact_path="a.json"),
            _execution("patch_generation_and_post_patch_investigation", 2, artifact_path="b.json"),
        ])
        manifest = load_manifest(run)
        matching = [e for e in manifest["executions"] if e["canonical_stage"] == "patch_generation_and_post_patch_investigation"]
        assert len(matching) == 2

    def test_multiple_executions_of_same_stage_do_not_overwrite_each_other(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[
            _execution("challenger", 1, artifact_path="first.json"),
            _execution("challenger", 2, artifact_path="second.json"),
        ])
        manifest = load_manifest(run)
        by_id = {e["execution_id"]: e for e in manifest["executions"]}
        assert by_id["001_challenger"]["artifact_path"] == "first.json"
        assert by_id["002_challenger"]["artifact_path"] == "second.json"

    def test_latest_execution_in_manifest_picks_max_sequence(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[
            _execution("challenger", 1, artifact_path="first.json"),
            _execution("challenger", 2, artifact_path="second.json"),
        ])
        manifest = load_manifest(run)
        latest = latest_execution_in_manifest(manifest, "challenger")
        assert latest["execution_id"] == "002_challenger"

    def test_sequence_is_local_to_one_directory(self, tmp_path):
        """Two independent directories may both use sequence=1 -- no
        cross-directory coordination exists or is needed."""
        run_a = _full_run(tmp_path / "a", executions=[_execution("challenger", 1)])
        run_b = _full_run(tmp_path / "b", executions=[_execution("challenger", 1)])
        assert load_manifest(run_a)["executions"][0]["sequence"] == 1
        assert load_manifest(run_b)["executions"][0]["sequence"] == 1


class TestFindLatestExecutionIdentity:
    def test_returns_none_when_never_produced(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[])
        assert find_latest_execution_identity(build_chain(run), "challenger") is None

    def test_returns_identity_when_found(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("challenger", 1)])
        identity = find_latest_execution_identity(build_chain(run), "challenger")
        assert identity == {"run": str(run), "execution_id": "001_challenger"}

    def test_no_staleness_check_applied(self, tmp_path):
        """find_latest_execution_identity is a provenance lookup, not a
        data-dependency resolution -- it must find an execution even if
        that execution's OWN consumed identities would resolve STALE."""
        run = _full_run(tmp_path / "run", executions=[
            _execution("patch_generation_and_post_patch_investigation", 1),
        ])
        replay = _replay(tmp_path / "replay", parent=run, executions=[
            _execution("patch_generation_and_post_patch_investigation", 1),  # supersedes run's
        ])
        stale_downstream = _replay(tmp_path / "stale-downstream", parent=run, executions=[
            _execution("challenger", 1, consumed={
                "patch_generation_and_post_patch_investigation": {"run": str(run), "execution_id": "001_patch_generation_and_post_patch_investigation"},
            }),
        ])
        # From `replay`'s own lineage, "challenger" was never produced,
        # but find_latest_execution_identity should still just report
        # None honestly (nothing to find), not attempt staleness logic.
        identity = find_latest_execution_identity(build_chain(replay), "challenger")
        assert identity is None


# ---------------------------------------------------------------------------
# Resolution: RESOLVED / STALE / UNRESOLVED, now execution-identity based
# ---------------------------------------------------------------------------


class TestResolveEffective:
    def test_missing_dependency_is_unresolved(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[])
        result = resolve_effective(build_chain(run), "never_produced", {})
        assert result.state == UNRESOLVED

    def test_closest_valid_ancestor_resolves(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("challenger", 1, artifact_path="a.json")])
        result = resolve_effective(build_chain(run), "challenger", {})
        assert result.state == RESOLVED
        assert result.identity == ArtifactIdentity(run_dir=str(run), execution_id="001_challenger")
        assert result.artifact_path == "a.json"

    def test_artifact_identity_is_run_plus_execution_id(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("challenger", 1)])
        result = resolve_effective(build_chain(run), "challenger", {})
        assert result.as_identity_dict() == {"run": str(run), "execution_id": "001_challenger"}

    def test_resolve_picks_max_sequence_execution_in_a_directory(self, tmp_path):
        """When a directory holds two executions of the same canonical
        stage (a future multi-execution production scenario), resolution
        must pick the latest (highest sequence), not the first."""
        run = _full_run(tmp_path / "run", executions=[
            _execution("challenger", 1, artifact_path="first.json"),
            _execution("challenger", 2, artifact_path="second.json"),
        ])
        result = resolve_effective(build_chain(run), "challenger", {})
        assert result.identity.execution_id == "002_challenger"
        assert result.artifact_path == "second.json"

    def test_replay_artifact_supersedes_original(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("test_analysis_and_plan", 1, artifact_path="a0.json")])
        replay = _replay(tmp_path / "replay", parent=run, executions=[_execution("test_analysis_and_plan", 1, artifact_path="a1.json")])
        result = resolve_effective(build_chain(replay), "test_analysis_and_plan", {})
        assert result.state == RESOLVED
        assert result.run_dir == str(replay)
        assert result.artifact_path == "a1.json"

    def test_execution_with_no_declared_consumed_is_always_valid_where_found(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("repository_analysis_and_remediation_planning", 1, consumed={})])
        result = resolve_effective(build_chain(run), "repository_analysis_and_remediation_planning", {})
        assert result.state == RESOLVED

    def test_downstream_execution_is_stale_when_consumed_identity_changed(self, tmp_path):
        """THE central scenario: full run has S10_0 -> S11_0 (S11_0
        recorded consuming S10_0's exact execution identity). Replay S10
        alone -> S10_1. Resolving S11 in that lineage must be STALE, NOT
        silently fall back to the original S11_0."""
        run_dir = tmp_path / "run"
        run = _full_run(run_dir, executions=[
            _execution("test_analysis_and_plan", 1, artifact_path="s10_0.json"),
            _execution("existing_test_comparison", 1, artifact_path="s11_0.json", consumed={
                "test_analysis_and_plan": {"run": str(run_dir), "execution_id": "001_test_analysis_and_plan"},
            }),
        ])
        replay = _replay(tmp_path / "replay-s10", parent=run, executions=[
            _execution("test_analysis_and_plan", 1, artifact_path="s10_1.json"),
        ])
        result = resolve_effective(build_chain(replay), "existing_test_comparison", {})
        assert result.state == STALE
        assert "test_analysis_and_plan" in result.reason

    def test_stale_never_wins_over_original_output(self, tmp_path):
        run_dir = tmp_path / "run"
        run = _full_run(run_dir, executions=[
            _execution("test_analysis_and_plan", 1, artifact_path="s10_0.json"),
            _execution("existing_test_comparison", 1, artifact_path="s11_0.json", consumed={
                "test_analysis_and_plan": {"run": str(run_dir), "execution_id": "001_test_analysis_and_plan"},
            }),
        ])
        replay = _replay(tmp_path / "replay-s10", parent=run, executions=[
            _execution("test_analysis_and_plan", 1, artifact_path="s10_1.json"),
        ])
        result = resolve_effective(build_chain(replay), "existing_test_comparison", {})
        assert result.state != RESOLVED

    def test_stale_is_branch_incompatible_not_invalid(self, tmp_path):
        """STALE describes a historical execution that remains valid
        history but is incompatible with the CURRENT branch resolution --
        it must still be independently addressable/inspectable by its own
        execution_id, never deleted or overwritten."""
        run_dir = tmp_path / "run"
        run = _full_run(run_dir, executions=[
            _execution("test_analysis_and_plan", 1, artifact_path="s10_0.json"),
            _execution("existing_test_comparison", 1, artifact_path="s11_0.json", consumed={
                "test_analysis_and_plan": {"run": str(run_dir), "execution_id": "001_test_analysis_and_plan"},
            }),
        ])
        replay = _replay(tmp_path / "replay-s10", parent=run, executions=[
            _execution("test_analysis_and_plan", 1, artifact_path="s10_1.json"),
        ])
        # STALE from the replay's branch...
        assert resolve_effective(build_chain(replay), "existing_test_comparison", {}).state == STALE
        # ...but the original s11_0 execution is untouched and still
        # findable directly in `run`'s own manifest.
        original_manifest = load_manifest(run)
        assert latest_execution_in_manifest(original_manifest, "existing_test_comparison")["artifact_path"] == "s11_0.json"

    def test_staleness_propagates_transitively(self, tmp_path):
        run_dir = tmp_path / "run"
        run = _full_run(run_dir, executions=[
            _execution("test_analysis_and_plan", 1, artifact_path="s10_0.json"),
            _execution("existing_test_comparison", 1, artifact_path="s11_0.json", consumed={
                "test_analysis_and_plan": {"run": str(run_dir), "execution_id": "001_test_analysis_and_plan"},
            }),
            _execution("trust_signals_and_recommendation", 1, artifact_path="s12_0.json", consumed={
                "existing_test_comparison": {"run": str(run_dir), "execution_id": "001_existing_test_comparison"},
            }),
        ])
        replay = _replay(tmp_path / "replay-s10", parent=run, executions=[
            _execution("test_analysis_and_plan", 1, artifact_path="s10_1.json"),
        ])
        cache: dict = {}
        chain = build_chain(replay)
        result_s11 = resolve_effective(chain, "existing_test_comparison", cache)
        result_s12 = resolve_effective(chain, "trust_signals_and_recommendation", cache)
        assert result_s11.state == STALE
        assert result_s12.state == STALE

    def test_independent_execution_remains_valid_when_unrelated_stage_replayed(self, tmp_path):
        run_dir = tmp_path / "run"
        run = _full_run(run_dir, executions=[
            _execution("patch_repair_and_calibration", 1, artifact_path="s6_0.json"),
            _execution("impact_and_behavior_analysis", 1, artifact_path="s9_0.json", consumed={
                "patch_repair_and_calibration": {"run": str(run_dir), "execution_id": "001_patch_repair_and_calibration"},
            }),
            _execution("existing_test_comparison", 1, artifact_path="s11_0.json", consumed={
                "patch_repair_and_calibration": {"run": str(run_dir), "execution_id": "001_patch_repair_and_calibration"},
            }),
        ])
        replay = _replay(tmp_path / "replay-s9", parent=run, executions=[
            _execution("impact_and_behavior_analysis", 1, artifact_path="s9_1.json", consumed={
                "patch_repair_and_calibration": {"run": str(run_dir), "execution_id": "001_patch_repair_and_calibration"},
            }),
        ])
        result_s11 = resolve_effective(build_chain(replay), "existing_test_comparison", {})
        assert result_s11.state == RESOLVED
        assert result_s11.run_dir == str(run_dir)  # still the ORIGINAL, untouched

    def test_sibling_branches_remain_independent(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("test_analysis_and_plan", 1, artifact_path="s10_0.json")])
        branch_a = _replay(tmp_path / "branch-a", parent=run, executions=[_execution("test_analysis_and_plan", 1, artifact_path="a.json")])
        branch_b = _replay(tmp_path / "branch-b", parent=run, executions=[_execution("test_analysis_and_plan", 1, artifact_path="b.json")])
        result_a = resolve_effective(build_chain(branch_a), "test_analysis_and_plan", {})
        result_b = resolve_effective(build_chain(branch_b), "test_analysis_and_plan", {})
        assert result_a.artifact_path == "a.json"
        assert result_b.artifact_path == "b.json"
        assert result_a.run_dir != result_b.run_dir

    def test_downstream_replay_from_one_branch_does_not_see_the_other(self, tmp_path):
        run = _full_run(tmp_path / "run", executions=[_execution("test_analysis_and_plan", 1, artifact_path="s10_0.json")])
        branch_a = _replay(tmp_path / "branch-a", parent=run, executions=[_execution("test_analysis_and_plan", 1, artifact_path="a.json")])
        _replay(tmp_path / "branch-b", parent=run, executions=[_execution("test_analysis_and_plan", 1, artifact_path="b.json")])
        downstream_from_a = _replay(tmp_path / "downstream-a", parent=branch_a, executions=[
            _execution("existing_test_comparison", 1, artifact_path="s11-from-a.json", consumed={
                "test_analysis_and_plan": {"run": str(branch_a), "execution_id": "001_test_analysis_and_plan"},
            }),
        ])
        result = resolve_effective(build_chain(downstream_from_a), "test_analysis_and_plan", {})
        assert result.artifact_path == "a.json"  # never b.json


class TestWorkflowInternalMultiExecution:
    """Proves the corrected "consumed vs. invoked_by" model documented in
    lineage.py's module docstring, using the future Stage-6 repair-loop
    scenario as the concrete worked case (NOT implemented in production
    yet -- these are hand-built fixtures proving the DATA MODEL/resolver
    can represent it correctly once it is).

    Worked topology (all in ONE directory -- a single production run,
    never a replay); Required Cases A/B from the Batch B1 correctness
    correction:

        001 patch_generation_and_post_patch_investigation (S4#1)
        001 challenger                                    (S5#1, consumes S4#1)
        001 patch_repair_and_calibration                  (S6#1, decides RETRY_PATCH)
        002 patch_generation_and_post_patch_investigation (S4#2, repair regen; invoked_by=S6#1)
        002 challenger                                    (S5#2, consumes S4#2)
        002 patch_repair_and_calibration                  (S6#2, evaluates S4#2/S5#2)

    S6#2's own `consumed` is ALWAYS exactly {S4#2, S5#2} -- the executions
    it actually evaluated -- regardless of whether it accepts or rejects
    the repair. `consumed` is strict DATA provenance and must never be
    repointed at "whatever became authoritative." The accept/reject
    DECISION, and (on reject) which candidate is selected for
    continuation, are STAGE-SPECIFIC bookkeeping recorded via `outcome`/
    `extra` -- never via `consumed`. S4#2 exists BECAUSE S6#1 decided
    RETRY_PATCH -- that CAUSAL relationship is recorded via the separate
    `invoked_by` field, which resolve_effective() never reads, so it
    cannot create a Stage6->Stage4->Stage6 cycle.
    """

    def _s4_s5_s6_repair_topology(self, run_dir: Path, *, accept: bool) -> list:
        s4_1 = _execution("patch_generation_and_post_patch_investigation", 1, artifact_path="s4_1.json")
        s5_1 = _execution("challenger", 1, artifact_path="s5_1.json", consumed={
            "patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": "001_patch_generation_and_post_patch_investigation"},
        })
        s6_1 = _execution("patch_repair_and_calibration", 1, artifact_path="s6_1.json", consumed={
            "patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": "001_patch_generation_and_post_patch_investigation"},
            "challenger": {"run": str(run_dir), "execution_id": "001_challenger"},
        }, outcome="RETRY_PATCH", extra={"decision": "RETRY_PATCH"})

        # S4#2 exists BECAUSE S6#1 decided RETRY_PATCH -- CAUSAL/CONTROL
        # provenance, recorded via `invoked_by`, deliberately NOT via
        # `consumed` (patch_generation_and_post_patch_investigation is
        # not, and never becomes, a canonical dependent of
        # patch_repair_and_calibration -- the canonical dependency runs
        # the other way). Modeling the trigger as a `consumed` edge was
        # tried first (Batch B1's initial correctness pass) and produces a
        # genuine cyclic-resolution hazard: resolving
        # patch_repair_and_calibration (S6#2) needs the CURRENT
        # patch_generation_and_post_patch_investigation, which (being S4#2,
        # the chronologically latest) would need to resolve
        # patch_repair_and_calibration again to validate ITS OWN consumed
        # edge -- re-entering the very resolution already in progress on
        # the same memoization cache key. Reproduced directly:
        # resolve_effective raised "cycle detected". Keeping the causal
        # edge in `invoked_by` (never traversed by the resolver) avoids
        # this entirely -- see test_invoked_by_does_not_create_a_cycle.
        s4_2 = _execution(
            "patch_generation_and_post_patch_investigation", 2, artifact_path="s4_2.json",
            invocation_kind=INVOCATION_KIND_RETRY,
            invoked_by={"run": str(run_dir), "execution_id": "001_patch_repair_and_calibration"},
        )
        s5_2 = _execution("challenger", 2, artifact_path="s5_2.json", consumed={
            "patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": "002_patch_generation_and_post_patch_investigation"},
        })

        # THE crux, corrected: `consumed` is ALWAYS the exact evaluated
        # inputs (S4#2/S5#2) -- accept vs. reject is recorded via
        # outcome/extra, never by repointing `consumed` at a different
        # candidate.
        s6_2_consumed = {
            "patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": "002_patch_generation_and_post_patch_investigation"},
            "challenger": {"run": str(run_dir), "execution_id": "002_challenger"},
        }
        if accept:
            outcome = "repair_accepted"
            selected_candidate = {
                "patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": "002_patch_generation_and_post_patch_investigation"},
                "challenger": {"run": str(run_dir), "execution_id": "002_challenger"},
            }
        else:
            outcome = "repair_rejected"
            selected_candidate = {
                "patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": "001_patch_generation_and_post_patch_investigation"},
                "challenger": {"run": str(run_dir), "execution_id": "001_challenger"},
            }
        s6_2 = new_execution_record(
            execution_id="002_patch_repair_and_calibration",
            canonical_stage="patch_repair_and_calibration",
            sequence=2,
            invocation_kind=INVOCATION_KIND_INITIAL,
            consumed=s6_2_consumed,
            outcome=outcome,
            artifact_path="s6_2.json",
            # Stage-specific bookkeeping -- NOT part of `consumed` -- is
            # where "what becomes authoritative for continuation" lives.
            # A future real patch_repair_and_calibration run_fn would read
            # THIS to know which patch text to carry forward; the generic
            # resolver never needs to know it to correctly resolve "the
            # latest patch_repair_and_calibration execution."
            extra={"decision": "CONTINUE", "repair_outcome": "accepted" if accept else "rejected", "selected_candidate": selected_candidate},
        )
        return [s4_1, s5_1, s6_1, s4_2, s5_2, s6_2]

    def test_consumed_always_reflects_exact_evaluated_input_regardless_of_decision(self, tmp_path):
        """Required proof (1): `consumed` always references the exact
        evaluated input execution -- identical for accept and reject."""
        run_dir = tmp_path / "run"
        expected_consumed = {
            "patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": "002_patch_generation_and_post_patch_investigation"},
            "challenger": {"run": str(run_dir), "execution_id": "002_challenger"},
        }
        for accept in (True, False):
            executions = self._s4_s5_s6_repair_topology(run_dir, accept=accept)
            s6_2 = next(e for e in executions if e["execution_id"] == "002_patch_repair_and_calibration")
            assert s6_2["consumed"] == expected_consumed

    def test_invoked_by_does_not_create_a_cycle(self, tmp_path):
        """Required proof (3): the workflow causal edge (`invoked_by`)
        does not participate in canonical dependency recursion, and
        therefore does not create a Stage6->Stage4->Stage6 cycle, despite
        S4#2.invoked_by pointing at S6#1 and S6#2.consumed pointing at
        S4#2."""
        run_dir = tmp_path / "run"
        run = _full_run(run_dir, executions=self._s4_s5_s6_repair_topology(run_dir, accept=False))
        chain = build_chain(run)

        s6_result = resolve_effective(chain, "patch_repair_and_calibration", {})
        assert s6_result.state == RESOLVED
        assert s6_result.identity.execution_id == "002_patch_repair_and_calibration"

        s4_result = resolve_effective(chain, "patch_generation_and_post_patch_investigation", {})
        assert s4_result.state == RESOLVED
        assert s4_result.identity.execution_id == "002_patch_generation_and_post_patch_investigation"

        manifest = load_manifest(run)
        s4_2 = next(e for e in manifest["executions"] if e["execution_id"] == "002_patch_generation_and_post_patch_investigation")
        assert s4_2["invoked_by"] == {"run": str(run_dir), "execution_id": "001_patch_repair_and_calibration"}

    def test_rejected_repair_preserves_complete_provenance_of_rejected_candidate(self, tmp_path):
        """Required proof (4): rejected repair preserves complete
        provenance of the rejected candidate -- S4#2/S5#2 remain fully
        present and inspectable, the evaluation is never erased."""
        run_dir = tmp_path / "run"
        executions = self._s4_s5_s6_repair_topology(run_dir, accept=False)
        run = _full_run(run_dir, executions=executions)

        manifest = load_manifest(run)
        by_id = {e["execution_id"]: e for e in manifest["executions"]}
        assert by_id["002_patch_generation_and_post_patch_investigation"]["artifact_path"] == "s4_2.json"
        assert by_id["002_challenger"]["artifact_path"] == "s5_2.json"
        rejected_s6 = by_id["002_patch_repair_and_calibration"]
        assert rejected_s6["outcome"] == "repair_rejected"
        assert rejected_s6["consumed"]["patch_generation_and_post_patch_investigation"]["execution_id"] == "002_patch_generation_and_post_patch_investigation"

    def test_rejected_repair_selects_previous_candidate_via_stage_specific_extra(self, tmp_path):
        """Required proof (5): rejected repair can still select the
        previous candidate for continuation, via the stage-specific
        `extra` mechanism -- never via `consumed`."""
        run_dir = tmp_path / "run"
        executions = self._s4_s5_s6_repair_topology(run_dir, accept=False)
        s6_2 = next(e for e in executions if e["execution_id"] == "002_patch_repair_and_calibration")
        assert s6_2["repair_outcome"] == "rejected"
        assert s6_2["selected_candidate"]["patch_generation_and_post_patch_investigation"]["execution_id"] == "001_patch_generation_and_post_patch_investigation"
        assert s6_2["selected_candidate"]["challenger"]["execution_id"] == "001_challenger"
        # And NOT via consumed, which stays pointed at what was evaluated.
        assert s6_2["consumed"]["patch_generation_and_post_patch_investigation"]["execution_id"] == "002_patch_generation_and_post_patch_investigation"

    def test_accepted_repair_selects_new_candidate_via_stage_specific_extra(self, tmp_path):
        """Required proof (6): accepted repair selects the repaired
        candidate, via the same stage-specific `extra` mechanism."""
        run_dir = tmp_path / "run"
        executions = self._s4_s5_s6_repair_topology(run_dir, accept=True)
        s6_2 = next(e for e in executions if e["execution_id"] == "002_patch_repair_and_calibration")
        assert s6_2["repair_outcome"] == "accepted"
        assert s6_2["selected_candidate"]["patch_generation_and_post_patch_investigation"]["execution_id"] == "002_patch_generation_and_post_patch_investigation"
        assert s6_2["selected_candidate"]["challenger"]["execution_id"] == "002_challenger"

    def test_s7_consumes_latest_stage6_decision_in_both_accept_and_reject_cases(self, tmp_path):
        """Required proof (7): a downstream Stage-7 execution can consume
        the latest patch_repair_and_calibration execution (S6#2) cleanly,
        whether S6#2 accepted or rejected the repair."""
        for accept in (True, False):
            run_dir = tmp_path / f"run-{'accept' if accept else 'reject'}"
            executions = self._s4_s5_s6_repair_topology(run_dir, accept=accept)
            s7_1 = _execution("patch_review", 1, artifact_path="s7_1.json", consumed={
                "patch_repair_and_calibration": {"run": str(run_dir), "execution_id": "002_patch_repair_and_calibration"},
            })
            run = _full_run(run_dir, executions=executions + [s7_1])

            result = resolve_effective(build_chain(run), "patch_review", {})
            assert result.state == RESOLVED
            assert result.identity.execution_id == "001_patch_review"

    def test_cross_directory_replay_of_s4_still_correctly_supersedes(self, tmp_path):
        """Required proof (8): cross-directory replay staleness still
        works, unaffected by this correction -- an explicit replay of
        patch_generation_and_post_patch_investigation into a NEW,
        different directory still correctly makes the repair loop's own
        S6#2 stale, since S6#2's `consumed` no longer matches the current
        resolution of that dependency."""
        run_dir = tmp_path / "run"
        executions = self._s4_s5_s6_repair_topology(run_dir, accept=False)
        run = _full_run(run_dir, executions=executions)

        replay = _replay(tmp_path / "replay-s4", parent=run, executions=[
            _execution("patch_generation_and_post_patch_investigation", 1, artifact_path="s4_replayed.json"),
        ])

        result = resolve_effective(build_chain(replay), "patch_repair_and_calibration", {})
        assert result.state == STALE

    def test_historical_executions_remain_immutable(self, tmp_path):
        run_dir = tmp_path / "run"
        executions = self._s4_s5_s6_repair_topology(run_dir, accept=False)
        run = _full_run(run_dir, executions=executions)
        before = (run / "run_manifest.json").read_bytes()

        resolve_effective(build_chain(run), "patch_repair_and_calibration", {})
        resolve_effective(build_chain(run), "patch_generation_and_post_patch_investigation", {})

        assert (run / "run_manifest.json").read_bytes() == before

    def test_sibling_branches_remain_independent(self, tmp_path):
        """Required proof (9): sibling branches remain independent, even
        when each replays a stage that itself has multi-execution history
        in the shared parent directory."""
        run_dir = tmp_path / "run"
        executions = self._s4_s5_s6_repair_topology(run_dir, accept=False)
        run = _full_run(run_dir, executions=executions)

        branch_a = _replay(tmp_path / "branch-a", parent=run, executions=[
            _execution("patch_repair_and_calibration", 1, artifact_path="a.json", consumed={
                "patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": "002_patch_generation_and_post_patch_investigation"},
                "challenger": {"run": str(run_dir), "execution_id": "002_challenger"},
            }),
        ])
        branch_b = _replay(tmp_path / "branch-b", parent=run, executions=[
            _execution("patch_repair_and_calibration", 1, artifact_path="b.json", consumed={
                "patch_generation_and_post_patch_investigation": {"run": str(run_dir), "execution_id": "002_patch_generation_and_post_patch_investigation"},
                "challenger": {"run": str(run_dir), "execution_id": "002_challenger"},
            }),
        ])

        result_a = resolve_effective(build_chain(branch_a), "patch_repair_and_calibration", {})
        result_b = resolve_effective(build_chain(branch_b), "patch_repair_and_calibration", {})
        assert result_a.artifact_path == "a.json"
        assert result_b.artifact_path == "b.json"


class TestSameDirectorySupersession:
    """Required Case C: two executions of the SAME canonical stage within
    ONE directory are NOT automatically compatible with each other's
    dependents merely by sharing a directory. This is the entire reason
    artifact identity is (run_dir, execution_id) rather than merely
    run_dir -- dependency compatibility must stay execution-specific."""

    def test_second_same_stage_execution_makes_earlier_dependent_stale(self, tmp_path):
        """Required proof (2): exact execution-id mismatch can make a
        dependent output incompatible even WITHIN one directory, once the
        branch's current resolution for the upstream stage moves to a
        later execution."""
        run_dir = tmp_path / "run"
        s10_1 = _execution("test_analysis_and_plan", 1, artifact_path="s10_1.json")
        s11_1 = _execution("existing_test_comparison", 1, artifact_path="s11_1.json", consumed={
            "test_analysis_and_plan": {"run": str(run_dir), "execution_id": "001_test_analysis_and_plan"},
        })
        # A second execution of test_analysis_and_plan in the SAME
        # directory (e.g. a workflow-internal retry) becomes the current
        # branch's resolution for that canonical stage.
        s10_2 = _execution("test_analysis_and_plan", 2, artifact_path="s10_2.json")
        run = _full_run(run_dir, executions=[s10_1, s11_1, s10_2])
        chain = build_chain(run)

        s10_result = resolve_effective(chain, "test_analysis_and_plan", {})
        assert s10_result.state == RESOLVED
        assert s10_result.identity.execution_id == "002_test_analysis_and_plan"

        # S11#1 recorded consuming S10#1 specifically -- it must NOT be
        # treated as compatible with the branch's current S10#2 merely
        # because S10#1/S10#2 share a directory.
        s11_result = resolve_effective(chain, "existing_test_comparison", {})
        assert s11_result.state == STALE
        assert "test_analysis_and_plan" in s11_result.reason

    def test_earlier_dependent_remains_inspectable_as_history(self, tmp_path):
        """STALE describes incompatibility with the current branch, not
        deletion -- S11#1 must remain directly addressable in the
        manifest even after a same-directory S10#2 supersedes it."""
        run_dir = tmp_path / "run"
        s10_1 = _execution("test_analysis_and_plan", 1, artifact_path="s10_1.json")
        s11_1 = _execution("existing_test_comparison", 1, artifact_path="s11_1.json", consumed={
            "test_analysis_and_plan": {"run": str(run_dir), "execution_id": "001_test_analysis_and_plan"},
        })
        s10_2 = _execution("test_analysis_and_plan", 2, artifact_path="s10_2.json")
        run = _full_run(run_dir, executions=[s10_1, s11_1, s10_2])

        manifest = load_manifest(run)
        by_id = {e["execution_id"]: e for e in manifest["executions"]}
        assert by_id["001_existing_test_comparison"]["artifact_path"] == "s11_1.json"


class TestPersistedWithoutReplayHandler:
    def test_produced_artifact_resolves_even_when_stage_has_no_replay_handler(self, tmp_path):
        """Architectural requirement: a stage may have a real execution
        record -- a persisted structured artifact -- while having NO
        entry in replay_engine.REPLAY_HANDLERS at all. "persisted" and
        "replayable" are independent concepts; the resolver only cares
        about the former."""
        from utilities.autopatcher import replay_engine

        target_stage = "trust_signals_and_recommendation"
        assert target_stage not in replay_engine.REPLAY_HANDLERS  # sanity: genuinely not replayable today

        run = _full_run(tmp_path / "run", executions=[_execution(target_stage, 1, artifact_path="stage6.json")])
        result = resolve_effective(build_chain(run), target_stage, {})
        assert result.state == RESOLVED
        assert result.artifact_path == "stage6.json"


class TestResolutionAsIdentityDict:
    def test_as_identity_dict_raises_for_non_resolved(self):
        result = Resolution(state=STALE, reason="x")
        with pytest.raises(LineageError):
            result.as_identity_dict()
