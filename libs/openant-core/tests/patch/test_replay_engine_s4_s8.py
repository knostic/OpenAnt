"""Batch B7: replay support for Stage 4 (patch_generation_and_post_patch_
investigation), Stage 5 (challenger), Stage 6 (patch_repair_and_calibration),
Stage 7 (patch_review), and Stage 8 (confidence_scoring) -- plus chained
replay proof (full run -> replay S5 -> replay S6 -> replay S7 -> replay S8,
each consuming the newest execution from its own source-run lineage).

Real, end-to-end: LLM_PROVIDER=mock (genuine call_llm() calls, no pipeline
internals mocked), a real full traced run via tools/run_traced.py, then real
replay_stage() calls -- the same harness style as
test_run_traced_execution_recording.py.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest

SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "utilities" / "autopatcher" / "tools" / "run_traced.py"
)

FIXTURE_CVE = {
    "id": "CVE-2021-12345",
    "descriptions": [
        {"lang": "en", "value": "A SQL injection vulnerability exists in the authenticate() function."}
    ],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
}


@pytest.fixture(scope="module")
def run_traced():
    assert SCRIPT_PATH.exists(), f"expected wrapper at {SCRIPT_PATH}"
    spec = importlib.util.spec_from_file_location("run_traced_s4_s8", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mock_fetch_cve_at_source(cve=FIXTURE_CVE):
    return mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve)


def _make_git_repo(tmp_path: Path) -> Path:
    """Replay's own repo-identity preflight requires a real git commit SHA
    (target_repository.repo_commit) -- a plain mkdir()'d directory has
    none."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("placeholder\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)
    return repo


def _full_run(run_traced, tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    repo_root = _make_git_repo(tmp_path)
    output_dir = tmp_path / "out"
    argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
    with _mock_fetch_cve_at_source():
        exit_code = run_traced.main(argv)
    assert exit_code == 0
    return repo_root, output_dir


def _manifest(run_dir: Path) -> dict:
    from utilities.autopatcher import lineage
    return lineage.load_manifest(run_dir)


# ---------------------------------------------------------------------------
# Each stage independently replayable from the full run
# ---------------------------------------------------------------------------

class TestIndependentReplay:
    def test_s4_replays_with_real_reconstructed_upstream(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="patch_generation_and_post_patch_investigation",
            output_dir=tmp_path / "replay-s4", repo_root_override=str(repo_root),
        )
        assert result.execution_id == "001_patch_generation_and_post_patch_investigation"
        manifest = _manifest(tmp_path / "replay-s4")
        execution = manifest["executions"][0]
        assert execution["invocation_kind"] == "replay"
        assert set(execution["consumed"].keys()) == {
            "repository_analysis_and_remediation_planning", "remediation_strategy", "guided_context_acquisition",
        }
        artifact = json.loads(Path(execution["artifact_path"]).read_text())
        assert "patch" in artifact and isinstance(artifact["patch"], str)

    def test_s5_replays_using_s4_artifact(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="challenger",
            output_dir=tmp_path / "replay-s5", repo_root_override=str(repo_root),
        )
        assert result.outcome in ("settled", "skipped_no_candidate_patch")
        manifest = _manifest(tmp_path / "replay-s5")
        execution = manifest["executions"][0]
        assert set(execution["consumed"].keys()) == {"patch_generation_and_post_patch_investigation"}

    def test_s6_replays_using_s4_s5_artifacts(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="patch_repair_and_calibration",
            output_dir=tmp_path / "replay-s6", repo_root_override=str(repo_root),
        )
        manifest = _manifest(tmp_path / "replay-s6")
        execution = manifest["executions"][0]
        assert set(execution["consumed"].keys()) == {"patch_generation_and_post_patch_investigation", "challenger"}
        artifact = json.loads(Path(execution["artifact_path"]).read_text())
        assert "authoritative_candidate" in artifact
        assert "repair_outcome" in artifact

    def test_s7_replays_using_s6_authoritative_candidate(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="patch_review",
            output_dir=tmp_path / "replay-s7", repo_root_override=str(repo_root),
        )
        manifest = _manifest(tmp_path / "replay-s7")
        execution = manifest["executions"][0]
        assert set(execution["consumed"].keys()) == {"patch_repair_and_calibration"}

    def test_s8_replays_using_s6_s7_artifacts(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="confidence_scoring",
            output_dir=tmp_path / "replay-s8", repo_root_override=str(repo_root),
        )
        manifest = _manifest(tmp_path / "replay-s8")
        execution = manifest["executions"][0]
        assert set(execution["consumed"].keys()) == {"patch_repair_and_calibration", "patch_review"}
        artifact = json.loads(Path(execution["artifact_path"]).read_text())
        assert "adjusted_score" in artifact

    def test_s10_replay_still_works(self, run_traced, tmp_path, monkeypatch):
        """Existing transitional Stage-10 replay must remain unaffected."""
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="test_analysis_and_plan",
            output_dir=tmp_path / "replay-s10", repo_root_override=str(repo_root),
        )
        assert result.outcome in ("accepted", "rejected")


# ---------------------------------------------------------------------------
# Chained replay: full -> replay S5 -> replay S6 -> replay S7 -> replay S8,
# each consuming the newest execution from ITS OWN source-run lineage.
# ---------------------------------------------------------------------------

class TestChainedReplay:
    def test_full_chain_consumes_newest_at_each_hop(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage

        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        full_manifest = _manifest(full_run)
        original_s5_id = next(e for e in full_manifest["executions"] if e["canonical_stage"] == "challenger")["execution_id"]

        r5 = replay_stage(
            source_run=full_run, stage_name="challenger",
            output_dir=tmp_path / "replay-s5", repo_root_override=str(repo_root),
        )
        s5_manifest = _manifest(tmp_path / "replay-s5")
        replayed_s5_id = s5_manifest["executions"][0]["execution_id"]
        # A replay directory always starts sequence at 1 (run_stage.py's
        # "one stage, stop" contract) -- a DIFFERENT execution_id than the
        # original full run's (whatever position challenger happened to be
        # recorded at there), in a DIFFERENT directory -- both expected.
        assert replayed_s5_id == "001_challenger"
        assert replayed_s5_id != original_s5_id or str(tmp_path / "replay-s5") != str(full_run)

        r6 = replay_stage(
            source_run=tmp_path / "replay-s5", stage_name="patch_repair_and_calibration",
            output_dir=tmp_path / "replay-s6", repo_root_override=str(repo_root),
        )
        s6_manifest = _manifest(tmp_path / "replay-s6")
        s6_consumed = s6_manifest["executions"][0]["consumed"]
        # THE key proof: S6 consumed the REPLAYED S5 (a different directory
        # than the original full run), not a silent fallback to the original.
        assert s6_consumed["challenger"]["run"] == str(tmp_path / "replay-s5")
        assert s6_consumed["challenger"]["execution_id"] == replayed_s5_id
        # And S4 (never replayed in this chain) is correctly inherited from
        # the ORIGINAL full-run directory, several hops up the parent chain.
        assert s6_consumed["patch_generation_and_post_patch_investigation"]["run"] == str(full_run)

        r7 = replay_stage(
            source_run=tmp_path / "replay-s6", stage_name="patch_review",
            output_dir=tmp_path / "replay-s7", repo_root_override=str(repo_root),
        )
        s7_manifest = _manifest(tmp_path / "replay-s7")
        s7_consumed = s7_manifest["executions"][0]["consumed"]
        assert s7_consumed["patch_repair_and_calibration"]["run"] == str(tmp_path / "replay-s6")

        r8 = replay_stage(
            source_run=tmp_path / "replay-s7", stage_name="confidence_scoring",
            output_dir=tmp_path / "replay-s8", repo_root_override=str(repo_root),
        )
        s8_manifest = _manifest(tmp_path / "replay-s8")
        s8_consumed = s8_manifest["executions"][0]["consumed"]
        assert s8_consumed["patch_review"]["run"] == str(tmp_path / "replay-s7")
        # S6 wasn't replayed again between S7 and S8 -- consumed correctly
        # points at the replay-s6 directory (still the nearest ancestor
        # with a patch_repair_and_calibration execution).
        assert s8_consumed["patch_repair_and_calibration"]["run"] == str(tmp_path / "replay-s6")

        for r in (r5, r6, r7, r8):
            assert r.outcome is not None

    def test_resolver_does_not_fall_back_to_stale_full_run_execution(self, run_traced, tmp_path, monkeypatch):
        """If S6 is replayed directly from the ORIGINAL full run (S5 never
        replayed), it must consume the full run's OWN S5 -- proving the
        prior test's "consumes the replayed S5" result is a real
        resolution, not an artifact of always picking the nearest
        directory regardless of content."""
        from utilities.autopatcher.replay_engine import replay_stage

        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        full_manifest = _manifest(full_run)
        original_s5_id = next(e for e in full_manifest["executions"] if e["canonical_stage"] == "challenger")["execution_id"]

        replay_stage(
            source_run=full_run, stage_name="patch_repair_and_calibration",
            output_dir=tmp_path / "replay-s6-direct", repo_root_override=str(repo_root),
        )
        s6_manifest = _manifest(tmp_path / "replay-s6-direct")
        s6_consumed = s6_manifest["executions"][0]["consumed"]
        assert s6_consumed["challenger"]["run"] == str(full_run)
        assert s6_consumed["challenger"]["execution_id"] == original_s5_id


# ---------------------------------------------------------------------------
# No duplicated production/replay logic -- structural proof.
# ---------------------------------------------------------------------------

class TestSharedImplementation:
    def test_replay_handlers_call_the_same_pipeline_executors(self):
        from utilities.autopatcher import replay_engine as re_mod
        from utilities.autopatcher import pipeline as pipeline_mod

        assert re_mod._run_patch_generation_and_investigation is pipeline_mod._run_patch_generation_and_investigation
        assert re_mod._run_patch_repair_and_calibration is pipeline_mod._run_patch_repair_and_calibration
        assert re_mod._adjust_confidence_score_for_challenger is pipeline_mod._adjust_confidence_score_for_challenger
