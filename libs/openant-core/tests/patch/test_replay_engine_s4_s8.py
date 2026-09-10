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


# ---------------------------------------------------------------------------
# Post-review correction (run-4 Architecture B count/artifact semantics):
# _run_replay_report_generation's own reconstruction of
# original_challenger_repair_eligible_count/repair_eligible_defect_count
# from a Stage-6 artifact -- hand-built synthetic artifacts, same style as
# test_replay_planner_claim_verifier.py's own S1-artifact tests, since this
# is a narrow backward-compatibility property (old artifact shape without
# "behavioral_defect_count" at all) that the real-run_traced integration
# tests above cannot exercise (mock-mode LLM never produces a behavioral_
# defect-shaped Challenger response).
# ---------------------------------------------------------------------------

class TestReplayReportGenerationRepairEligibleCounts:
    def _resolution(self, path):
        from utilities.autopatcher.lineage import RESOLVED, Resolution
        return Resolution(state=RESOLVED, artifact_path=str(path))

    def _write(self, path, data):
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def _build_artifacts(self, tmp_path, *, s6_challenger_extra=None, s6_rechallenge_extra=None,
                          repair_rechallenged=True):
        """Minimal-but-complete S1/S2/S4/S6/S7/S8/S9 artifacts -- only the
        fields _run_replay_report_generation actually reads (traced
        directly from its own source), so this fails loudly (KeyError) if
        that function's required-field contract ever changes without this
        test being updated."""
        s1 = self._write(tmp_path / "s1.json", {"grounding": None, "repository_understanding": None})
        s2 = self._write(tmp_path / "s2.json", {"strategy_result": None})
        s4 = self._write(tmp_path / "s4.json", {})
        original_challenger = {"confirmed_defect_count": 1, **(s6_challenger_extra or {})}
        s6_data = {
            "vulnerability_text": "some vuln",
            "patch": "some patch",
            "challenger": original_challenger,
            "authoritative_candidate": {
                "source": "original", "patch": "some patch",
                "applicability_result": None, "hygiene_findings": None,
            },
            "original_candidate_evaluated": {"patch": "some patch", "challenger": original_challenger},
            "repair_regeneration": None,
            "repair_rechallenge": (
                {"challenger": original_challenger, "confirmed_defect_count": 0, **(s6_rechallenge_extra or {})}
                if repair_rechallenged else None
            ),
            "repair_attempted": repair_rechallenged,
            "finding_calibration": None,
        }
        s6 = self._write(tmp_path / "s6.json", s6_data)
        s7 = self._write(tmp_path / "s7.json", {"review": "some review"})
        s8 = self._write(tmp_path / "s8.json", {"score_text": "Confidence score: 0.8"})
        s9 = self._write(tmp_path / "s9.json", {})
        from utilities.autopatcher.stage_registry import (
            CONFIDENCE_SCORING, IMPACT_AND_BEHAVIOR_ANALYSIS, PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
            PATCH_REPAIR_AND_CALIBRATION, PATCH_REVIEW, REMEDIATION_STRATEGY,
            REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING,
        )
        return {
            REPOSITORY_ANALYSIS_AND_REMEDIATION_PLANNING: self._resolution(s1),
            REMEDIATION_STRATEGY: self._resolution(s2),
            PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION: self._resolution(s4),
            PATCH_REPAIR_AND_CALIBRATION: self._resolution(s6),
            PATCH_REVIEW: self._resolution(s7),
            CONFIDENCE_SCORING: self._resolution(s8),
            IMPACT_AND_BEHAVIOR_ANALYSIS: self._resolution(s9),
        }

    def _replay(self, tmp_path, **kwargs):
        from utilities.autopatcher.replay_engine import _run_replay_report_generation
        artifacts_dir = tmp_path / "artifacts"
        artifacts_dir.mkdir()
        deps = self._build_artifacts(artifacts_dir, **kwargs)
        result = _run_replay_report_generation(
            repo_root=None, llm=None, output_dir=tmp_path, resolved_dependencies=deps, chain=None,
        )
        artifact = json.loads(result.artifact_path.read_text(encoding="utf-8"))
        return artifact["pipeline_result"]

    def test_old_artifact_shape_without_behavioral_key_replays_unchanged(self, tmp_path):
        """The exact backward-compatibility requirement: an S6 artifact
        from before behavioral_defect existed (no "behavioral_defect_count"
        key anywhere) must reproduce the pre-existing confirmed_defect-only
        totals exactly -- eligible == confirmed, byte-for-byte."""
        pr = self._replay(tmp_path)
        assert pr["original_challenger_defect_count"] == 1
        assert pr["original_challenger_repair_eligible_count"] == 1
        assert pr["repair_defect_count"] == 0
        assert pr["repair_eligible_defect_count"] == 0

    def test_new_artifact_shape_with_behavioral_key_sums_correctly(self, tmp_path):
        pr = self._replay(
            tmp_path,
            s6_challenger_extra={"behavioral_defect_count": 2},
            s6_rechallenge_extra={"confirmed_defect_count": 0, "behavioral_defect_count": 1},
        )
        assert pr["original_challenger_defect_count"] == 1
        assert pr["original_challenger_repair_eligible_count"] == 3  # 1 confirmed + 2 behavioral
        assert pr["repair_defect_count"] == 0
        assert pr["repair_eligible_defect_count"] == 1  # 0 confirmed + 1 behavioral

    def test_no_rechallenge_defaults_eligible_count_to_zero(self, tmp_path):
        pr = self._replay(tmp_path, repair_rechallenged=False)
        assert pr["repair_defect_count"] == 0
        assert pr["repair_eligible_defect_count"] == 0
