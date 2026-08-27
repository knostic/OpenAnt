"""Tests for the unified full-run/replay manifest model + dependency-aware
lineage resolution (utilities/autopatcher/lineage.py) -- Foundation Batch A.

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
    RESOLVED,
    STALE,
    UNRESOLVED,
    ArtifactIdentity,
    LineageError,
    Resolution,
    build_chain,
    load_manifest,
    new_full_run_manifest,
    new_replay_manifest,
    produced_stage_entry,
    resolve_effective,
)


def _write(run_dir: Path, manifest: dict) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return run_dir


def _full_run(run_dir: Path, stages: dict) -> Path:
    manifest = new_full_run_manifest(
        target_repository={"repo_root": "/repo", "repo_commit": "aaa"},
        openant={"patcher_commit": "bbb"},
        llm={"provider": "mock", "model": "mock"},
        stages=stages,
    )
    return _write(run_dir, manifest)


def _replay(run_dir: Path, *, parent: Path, replaces_stage: str, stages: dict) -> Path:
    manifest = new_replay_manifest(
        parent=parent,
        replaces_stage=replaces_stage,
        target_repository={"repo_root": "/repo", "repo_commit": "aaa"},
        openant={"patcher_commit": "bbb", "replay_patcher_commit": "ccc"},
        llm={"provider": "mock", "model": "mock"},
        stages=stages,
    )
    return _write(run_dir, manifest)


# ---------------------------------------------------------------------------
# Manifest shape / validation
# ---------------------------------------------------------------------------


class TestManifestShape:
    def test_full_run_manifest_validates(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={"a": produced_stage_entry(artifact_path="a.json")})
        manifest = load_manifest(run)
        assert manifest["kind"] == "full_run"
        assert manifest["parent"] is None
        assert manifest["replaces_stage"] is None
        assert manifest["schema_version"] == lineage.SCHEMA_VERSION

    def test_replay_manifest_validates(self, tmp_path):
        source = _full_run(tmp_path / "run", stages={})
        replay = _replay(tmp_path / "replay", parent=source, replaces_stage="a", stages={
            "a": produced_stage_entry(artifact_path="a.json"),
        })
        manifest = load_manifest(replay)
        assert manifest["kind"] == "replay"
        assert manifest["parent"] == str(source)
        assert manifest["replaces_stage"] == "a"

    def test_replay_records_parent(self, tmp_path):
        source = _full_run(tmp_path / "run", stages={})
        replay = _replay(tmp_path / "replay", parent=source, replaces_stage="a", stages={})
        assert load_manifest(replay)["parent"] == str(source)

    def test_replay_records_replaces_stage(self, tmp_path):
        source = _full_run(tmp_path / "run", stages={})
        replay = _replay(tmp_path / "replay", parent=source, replaces_stage="test_analysis_and_plan", stages={})
        assert load_manifest(replay)["replaces_stage"] == "test_analysis_and_plan"

    def test_manifest_missing_kind_and_parent_defaults_to_legacy_full_run(self, tmp_path):
        """A trace written before this schema existed (no schema_version/
        kind/parent/stages keys at all) must still load, defaulting to a
        root full run with every canonical stage synthesized as
        status="legacy" -- bounded legacy compatibility."""
        run_dir = tmp_path / "legacy"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({"status": "success"}), encoding="utf-8")
        manifest = load_manifest(run_dir)
        assert manifest["kind"] == "full_run"
        assert manifest["parent"] is None
        assert manifest["stages"]
        assert all(entry["status"] == "legacy" for entry in manifest["stages"].values())

    def test_missing_manifest_raises_lineage_error(self, tmp_path):
        with pytest.raises(LineageError, match="No run_manifest.json"):
            load_manifest(tmp_path / "nowhere")

    def test_resolves_trace_subdirectory_shape(self, tmp_path):
        """A full run's manifest lives under <root>/trace/ -- must resolve
        from the root path directly, matching run_traced.py's layout."""
        run_dir = tmp_path / "run"
        (run_dir / "trace").mkdir(parents=True)
        (run_dir / "trace" / "run_manifest.json").write_text(
            json.dumps(new_full_run_manifest(target_repository={}, openant={}, llm={}, stages={})),
            encoding="utf-8",
        )
        manifest = load_manifest(run_dir)
        assert manifest["kind"] == "full_run"


# ---------------------------------------------------------------------------
# Schema versioning -- cleanup batch: bumped 1 -> 2 for the unified
# manifest; v1 (and no schema_version at all) get bounded legacy
# compatibility; anything else fails closed before execution.
# ---------------------------------------------------------------------------


class TestSchemaVersioning:
    def test_new_full_run_manifest_uses_schema_v2(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={})
        assert load_manifest(run)["schema_version"] == 2

    def test_new_replay_manifest_uses_schema_v2(self, tmp_path):
        source = _full_run(tmp_path / "run", stages={})
        replay = _replay(tmp_path / "replay", parent=source, replaces_stage="a", stages={})
        assert load_manifest(replay)["schema_version"] == 2

    def test_schema_version_constant_is_2(self):
        assert lineage.SCHEMA_VERSION == 2

    def test_run_traced_schema_version_matches_lineage_schema_version(self):
        """The two independent constants (run_traced.py's own
        _REPLAY_SCHEMA_VERSION and lineage.SCHEMA_VERSION) must never
        drift apart -- both describe the version written into the SAME
        top-level "schema_version" field of the SAME manifest."""
        import importlib.util
        import sys
        from pathlib import Path as _Path

        tools_dir = _Path(__file__).resolve().parent.parent.parent / "utilities" / "autopatcher" / "tools"
        spec = importlib.util.spec_from_file_location("run_traced_schema_check", tools_dir / "run_traced.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module._REPLAY_SCHEMA_VERSION == lineage.SCHEMA_VERSION

    def test_schema_v1_uses_bounded_legacy_compatibility(self, tmp_path):
        run_dir = tmp_path / "v1-run"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({
            "schema_version": 1,
            "target_repository": {"repo_root": "/repo", "repo_commit": "aaa"},
            "openant": {}, "llm": {},
        }), encoding="utf-8")
        manifest = load_manifest(run_dir)
        assert manifest["kind"] == "full_run"
        assert manifest["parent"] is None
        assert manifest["stages"]
        assert all(entry["status"] == "legacy" for entry in manifest["stages"].values())

    def test_missing_schema_version_also_uses_bounded_legacy_path(self, tmp_path):
        run_dir = tmp_path / "no-version"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({"status": "success"}), encoding="utf-8")
        manifest = load_manifest(run_dir)
        assert manifest["kind"] == "full_run"
        assert all(e["status"] == "legacy" for e in manifest["stages"].values())

    def test_unsupported_future_schema_fails_before_execution(self, tmp_path):
        run_dir = tmp_path / "future"
        run_dir.mkdir()
        (run_dir / "run_manifest.json").write_text(json.dumps({"schema_version": 999}), encoding="utf-8")
        with pytest.raises(LineageError, match="schema_version=999"):
            load_manifest(run_dir)

    def test_v2_manifest_stages_are_trusted_as_written_not_synthesized(self, tmp_path):
        """A v2 manifest's own "stages" content must be used verbatim --
        never overridden with legacy/not_persisted synthesis."""
        run = _full_run(tmp_path / "run", stages={
            "test_analysis_and_plan": produced_stage_entry(artifact_path="real.json"),
        })
        manifest = load_manifest(run)
        assert manifest["stages"]["test_analysis_and_plan"]["status"] == "produced"
        assert manifest["stages"]["test_analysis_and_plan"]["artifact_path"] == "real.json"


# ---------------------------------------------------------------------------
# Status semantics -- "legacy" (old v1-or-older manifest) vs.
# "not_persisted" (new v2 full run, honest "not migrated yet") vs.
# "produced" (a real artifact exists). Never interchangeable.
# ---------------------------------------------------------------------------


class TestStatusSemantics:
    def test_new_v2_full_run_uses_not_persisted_not_legacy(self, tmp_path):
        from utilities.autopatcher.lineage import not_persisted_stage_entries

        run = _full_run(tmp_path / "run", stages=not_persisted_stage_entries(("a", "b")))
        manifest = load_manifest(run)
        assert manifest["stages"]["a"]["status"] == "not_persisted"
        assert manifest["stages"]["b"]["status"] == "not_persisted"

    def test_legacy_status_reserved_for_old_format_manifests_only(self, tmp_path):
        """A v2 writer must never emit status="legacy" -- only
        load_manifest()'s bounded legacy-compatibility path (for v1-or-
        older manifests) ever produces it."""
        from utilities.autopatcher.lineage import not_persisted_stage_entries

        run = _full_run(tmp_path / "run", stages=not_persisted_stage_entries(("a",)))
        manifest = load_manifest(run)
        assert manifest["stages"]["a"]["status"] != "legacy"

        legacy_run_dir = tmp_path / "old"
        legacy_run_dir.mkdir()
        (legacy_run_dir / "run_manifest.json").write_text(json.dumps({"status": "success"}), encoding="utf-8")
        legacy_manifest = load_manifest(legacy_run_dir)
        assert all(e["status"] == "legacy" for e in legacy_manifest["stages"].values())

    def test_not_persisted_status_never_resolves_as_an_artifact(self, tmp_path):
        """"not_persisted" behaves identically to "never produced" for
        resolution purposes -- it must not accidentally count as
        RESOLVED just because the stage's key is present."""
        from utilities.autopatcher.lineage import not_persisted_stage_entries

        run = _full_run(tmp_path / "run", stages=not_persisted_stage_entries(("a",)))
        result = resolve_effective(build_chain(run), "a", {})
        assert result.state == UNRESOLVED

    def test_produced_artifact_resolves_even_when_stage_has_no_replay_handler(self, tmp_path):
        """Architectural requirement for Batch B (item 4 of the cleanup
        instructions): a stage may have status="produced" -- a real,
        persisted structured artifact -- while having NO entry in
        replay_engine.REPLAY_HANDLERS at all. "persisted" and
        "replayable" are independent concepts; the resolver only cares
        about the former."""
        from utilities.autopatcher import replay_engine

        target_stage = "patch_repair_and_calibration"
        assert target_stage not in replay_engine.REPLAY_HANDLERS  # sanity: genuinely not replayable today

        run = _full_run(tmp_path / "run", stages={
            target_stage: produced_stage_entry(artifact_path="stage6.json"),
        })
        result = resolve_effective(build_chain(run), target_stage, {})
        assert result.state == RESOLVED
        assert result.artifact_path == "stage6.json"


# ---------------------------------------------------------------------------
# Chain building
# ---------------------------------------------------------------------------


class TestChainBuilding:
    def test_single_full_run_chain_has_one_element(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={})
        chain = build_chain(run)
        assert [str(p) for p in chain] == [str(run)]

    def test_chain_walks_parent_pointers_tip_first(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={})
        replay1 = _replay(tmp_path / "replay1", parent=run, replaces_stage="a", stages={})
        replay2 = _replay(tmp_path / "replay2", parent=replay1, replaces_stage="b", stages={})
        chain = build_chain(replay2)
        assert [str(p) for p in chain] == [str(replay2), str(replay1), str(run)]

    def test_cycle_raises_lineage_error(self, tmp_path):
        a_dir = tmp_path / "a"
        b_dir = tmp_path / "b"
        # a's parent is b, b's parent is a -- a genuine cycle.
        _write(a_dir, new_replay_manifest(parent=b_dir, replaces_stage="x", target_repository={}, openant={}, llm={}, stages={}))
        _write(b_dir, new_replay_manifest(parent=a_dir, replaces_stage="y", target_repository={}, openant={}, llm={}, stages={}))
        with pytest.raises(LineageError, match="Cycle detected"):
            build_chain(a_dir)


# ---------------------------------------------------------------------------
# Resolution: RESOLVED / STALE / UNRESOLVED
# ---------------------------------------------------------------------------


class TestResolveEffective:
    def test_missing_dependency_is_unresolved(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={})
        chain = build_chain(run)
        result = resolve_effective(chain, "never_produced", {})
        assert result.state == UNRESOLVED

    def test_closest_valid_ancestor_resolves(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={
            "a": produced_stage_entry(artifact_path="a0.json"),
        })
        result = resolve_effective(build_chain(run), "a", {})
        assert result.state == RESOLVED
        assert result.identity == ArtifactIdentity(run_dir=str(run), stage="a")
        assert result.artifact_path == "a0.json"

    def test_replay_artifact_supersedes_original(self, tmp_path):
        """Given full: S10=A0 -> S11=B0 (B0 declares a dependency on A0).
        Replay S10 -> A1. Resolving S10 in the replay lineage must return
        A1, not A0 (closest-ancestor-wins)."""
        run = _full_run(tmp_path / "run", stages={
            "s10": produced_stage_entry(artifact_path="a0.json"),
        })
        replay = _replay(tmp_path / "replay", parent=run, replaces_stage="s10", stages={
            "s10": produced_stage_entry(artifact_path="a1.json"),
        })
        result = resolve_effective(build_chain(replay), "s10", {})
        assert result.state == RESOLVED
        assert result.run_dir == str(replay)
        assert result.artifact_path == "a1.json"

    def test_dependency_with_no_declared_deps_is_always_valid_where_found(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={
            "root": produced_stage_entry(artifact_path="root.json", dependencies_checked=()),
        })
        result = resolve_effective(build_chain(run), "root", {})
        assert result.state == RESOLVED

    def test_downstream_artifact_is_stale_when_its_recorded_dependency_identity_changed(self, tmp_path):
        """THE central scenario from the architecture report: full run has
        S10_0 -> S11_0 (S11_0 recorded consuming S10_0). Replay S10 alone
        -> S10_1. Resolving S11 in that lineage must be STALE, NOT
        silently fall back to the original S11_0."""
        run = _full_run(tmp_path / "run", stages={
            "s10": produced_stage_entry(artifact_path="s10_0.json"),
            "s11": produced_stage_entry(
                artifact_path="s11_0.json",
                dependencies_checked=("s10",),
                consumed_dependencies={"s10": {"run": str(tmp_path / "run"), "stage": "s10"}},
            ),
        })
        replay = _replay(tmp_path / "replay-s10", parent=run, replaces_stage="s10", stages={
            "s10": produced_stage_entry(artifact_path="s10_1.json"),
        })
        result = resolve_effective(build_chain(replay), "s11", {})
        assert result.state == STALE
        assert "s10" in result.reason

    def test_stale_never_wins_over_original_output(self, tmp_path):
        """A stale artifact must never be reported as RESOLVED merely
        because it exists on disk."""
        run = _full_run(tmp_path / "run", stages={
            "s10": produced_stage_entry(artifact_path="s10_0.json"),
            "s11": produced_stage_entry(
                artifact_path="s11_0.json",
                dependencies_checked=("s10",),
                consumed_dependencies={"s10": {"run": str(tmp_path / "run"), "stage": "s10"}},
            ),
        })
        replay = _replay(tmp_path / "replay-s10", parent=run, replaces_stage="s10", stages={
            "s10": produced_stage_entry(artifact_path="s10_1.json"),
        })
        result = resolve_effective(build_chain(replay), "s11", {})
        assert result.state != RESOLVED

    def test_staleness_propagates_transitively(self, tmp_path):
        """S10_0 -> S11_0 -> S12_0 (S12_0 depends on S11). Replay S10 only.
        Resolving S12 must ALSO be STALE, even though S12's own recorded
        dependency (S11) identity pointer hasn't itself been replayed --
        it's S11 that becomes invalid, and that must propagate."""
        run_dir = tmp_path / "run"
        run = _full_run(run_dir, stages={
            "s10": produced_stage_entry(artifact_path="s10_0.json"),
            "s11": produced_stage_entry(
                artifact_path="s11_0.json",
                dependencies_checked=("s10",),
                consumed_dependencies={"s10": {"run": str(run_dir), "stage": "s10"}},
            ),
            "s12": produced_stage_entry(
                artifact_path="s12_0.json",
                dependencies_checked=("s11",),
                consumed_dependencies={"s11": {"run": str(run_dir), "stage": "s11"}},
            ),
        })
        replay = _replay(tmp_path / "replay-s10", parent=run, replaces_stage="s10", stages={
            "s10": produced_stage_entry(artifact_path="s10_1.json"),
        })
        cache: dict = {}
        chain = build_chain(replay)
        result_s11 = resolve_effective(chain, "s11", cache)
        result_s12 = resolve_effective(chain, "s12", cache)
        assert result_s11.state == STALE
        assert result_s12.state == STALE

    def test_independent_artifact_remains_valid_when_unrelated_stage_replayed(self, tmp_path):
        """S9 and S11 both exist in the full run; S11 does NOT depend on
        S9. Replaying S9 must NOT invalidate S11 -- dependency graph, not
        numeric stage order, governs staleness."""
        run_dir = tmp_path / "run"
        run = _full_run(run_dir, stages={
            "s6": produced_stage_entry(artifact_path="s6_0.json"),
            "s9": produced_stage_entry(
                artifact_path="s9_0.json",
                dependencies_checked=("s6",),
                consumed_dependencies={"s6": {"run": str(run_dir), "stage": "s6"}},
            ),
            "s11": produced_stage_entry(
                artifact_path="s11_0.json",
                dependencies_checked=("s6",),  # NOT dependent on s9
                consumed_dependencies={"s6": {"run": str(run_dir), "stage": "s6"}},
            ),
        })
        replay = _replay(tmp_path / "replay-s9", parent=run, replaces_stage="s9", stages={
            "s9": produced_stage_entry(
                artifact_path="s9_1.json",
                dependencies_checked=("s6",),
                consumed_dependencies={"s6": {"run": str(run_dir), "stage": "s6"}},
            ),
        })
        result_s11 = resolve_effective(build_chain(replay), "s11", {})
        assert result_s11.state == RESOLVED
        assert result_s11.run_dir == str(run_dir)  # still the ORIGINAL s11, untouched

    def test_branch_replays_from_same_parent_do_not_interfere(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={
            "s10": produced_stage_entry(artifact_path="s10_0.json"),
        })
        branch_a = _replay(tmp_path / "branch-a", parent=run, replaces_stage="s10", stages={
            "s10": produced_stage_entry(artifact_path="a.json"),
        })
        branch_b = _replay(tmp_path / "branch-b", parent=run, replaces_stage="s10", stages={
            "s10": produced_stage_entry(artifact_path="b.json"),
        })
        result_a = resolve_effective(build_chain(branch_a), "s10", {})
        result_b = resolve_effective(build_chain(branch_b), "s10", {})
        assert result_a.artifact_path == "a.json"
        assert result_b.artifact_path == "b.json"
        assert result_a.run_dir != result_b.run_dir

    def test_downstream_replay_from_one_branch_does_not_see_the_other(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={"s10": produced_stage_entry(artifact_path="s10_0.json")})
        branch_a = _replay(tmp_path / "branch-a", parent=run, replaces_stage="s10", stages={
            "s10": produced_stage_entry(artifact_path="a.json"),
        })
        branch_b = _replay(tmp_path / "branch-b", parent=run, replaces_stage="s10", stages={
            "s10": produced_stage_entry(artifact_path="b.json"),
        })
        downstream_from_a = _replay(tmp_path / "downstream-a", parent=branch_a, replaces_stage="s11", stages={
            "s11": produced_stage_entry(
                artifact_path="s11-from-a.json",
                dependencies_checked=("s10",),
                consumed_dependencies={"s10": {"run": str(branch_a), "stage": "s10"}},
            ),
        })
        result = resolve_effective(build_chain(downstream_from_a), "s10", {})
        assert result.artifact_path == "a.json"  # never b.json


class TestArtifactIdentity:
    def test_identity_is_run_dir_plus_stage_name(self, tmp_path):
        run = _full_run(tmp_path / "run", stages={"a": produced_stage_entry(artifact_path="a.json")})
        result = resolve_effective(build_chain(run), "a", {})
        assert result.as_identity_dict() == {"run": str(run), "stage": "a"}

    def test_as_identity_dict_raises_for_non_resolved(self):
        result = Resolution(state=STALE, reason="x")
        with pytest.raises(LineageError):
            result.as_identity_dict()
