"""Batch B8: replay support for the remaining canonical stages -- Stage 1
(repository_analysis_and_remediation_planning), Stage 2 (remediation_strategy),
Stage 3 (guided_context_acquisition), Stage 9 (impact_and_behavior_analysis),
Stage 11 (existing_test_comparison), and the combined terminal replay unit
(registered under report_generation) for the fused trust_signals_and_
recommendation + report_generation tail. Completes pipeline-wide replay
coverage (S1-S11 + the combined terminal unit) started in Batch B7.

Real, end-to-end: LLM_PROVIDER=mock (genuine call_llm() calls, no pipeline
internals mocked), a real full traced run via tools/run_traced.py, then real
replay_stage() calls -- same harness style as test_replay_engine_s4_s8.py.
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
    spec = importlib.util.spec_from_file_location("run_traced_s1_s12", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mock_fetch_cve_at_source(cve=FIXTURE_CVE):
    return mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve)


def _make_git_repo(tmp_path: Path, *, applicable_target: bool = False) -> Path:
    """Replay's own repo-identity preflight requires a real git commit SHA
    (target_repository.repo_commit) -- a plain mkdir()'d directory has none.

    `applicable_target=True` additionally seeds app/auth.py with the EXACT
    pre-image llm_client._MOCK_PATCH's fixed diff expects (lines 1-41 filler
    + the authenticate() function at line 42), so the mock LLM's canned
    patch actually applies -- needed for any test that must reach the
    Existing Test Comparison block (gated on applicability_result.get(
    "applicable") is True in pipeline.run()).
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("placeholder\n", encoding="utf-8")
    if applicable_target:
        app_dir = repo / "app"
        app_dir.mkdir()
        filler = "\n".join(f"# line {i}" for i in range(1, 42))
        auth_py = (
            filler + "\n"
            "def authenticate(username: str, password: str) -> bool:\n"
            "    query = f\"SELECT * FROM users WHERE username='{username}' AND password='{password}'\"\n"
            "    cursor = db.execute(query)\n"
            "    return cursor.fetchone() is not None\n"
        )
        (app_dir / "auth.py").write_text(auth_py, encoding="utf-8")
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, capture_output=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, capture_output=True, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, capture_output=True, check=True)
    return repo


def _full_run(run_traced, tmp_path, monkeypatch, *, compare_existing_tests=False, name="run"):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    repo_root = _make_git_repo(tmp_path, applicable_target=compare_existing_tests)
    output_dir = tmp_path / name
    argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
    if compare_existing_tests:
        argv.append("--compare-existing-tests")
    with _mock_fetch_cve_at_source():
        exit_code = run_traced.main(argv)
    assert exit_code == 0
    return repo_root, output_dir


def _manifest(run_dir: Path) -> dict:
    from utilities.autopatcher import lineage
    return lineage.load_manifest(run_dir)


# ---------------------------------------------------------------------------
# Independent replay -- S1, S2, S3, S9, S11, report_generation (combined)
# ---------------------------------------------------------------------------

class TestIndependentReplay:
    def test_s1_replays_using_its_own_prior_execution(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="repository_analysis_and_remediation_planning",
            output_dir=tmp_path / "replay-s1", repo_root_override=str(repo_root),
        )
        assert result.execution_id == "001_repository_analysis_and_remediation_planning"
        manifest = _manifest(tmp_path / "replay-s1")
        execution = manifest["executions"][0]
        assert execution["invocation_kind"] == "replay"
        # S1 is genesis -- no declared dependency, so `consumed` is empty;
        # its own-history resolution happens via `chain`, not `consumed`.
        assert execution["consumed"] == {}
        artifact = json.loads(Path(execution["artifact_path"]).read_text())
        assert "vulnerability_text" in artifact

    def test_s2_replays_using_s1_artifact(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="remediation_strategy",
            output_dir=tmp_path / "replay-s2", repo_root_override=str(repo_root),
        )
        manifest = _manifest(tmp_path / "replay-s2")
        execution = manifest["executions"][0]
        assert set(execution["consumed"].keys()) == {"repository_analysis_and_remediation_planning"}
        assert result.outcome in ("generated", "skipped_no_planner_evidence", "unavailable")

    def test_s3_replays_using_s1_s2_artifacts(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="guided_context_acquisition",
            output_dir=tmp_path / "replay-s3", repo_root_override=str(repo_root),
        )
        manifest = _manifest(tmp_path / "replay-s3")
        execution = manifest["executions"][0]
        assert set(execution["consumed"].keys()) == {
            "repository_analysis_and_remediation_planning", "remediation_strategy",
        }
        artifact = json.loads(Path(execution["artifact_path"]).read_text())
        assert "skip_patch_generation" in artifact

    def test_s9_replays_using_s6_artifact(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="impact_and_behavior_analysis",
            output_dir=tmp_path / "replay-s9", repo_root_override=str(repo_root),
        )
        assert result.outcome == "settled"
        manifest = _manifest(tmp_path / "replay-s9")
        execution = manifest["executions"][0]
        assert set(execution["consumed"].keys()) == {"patch_repair_and_calibration"}
        artifact = json.loads(Path(execution["artifact_path"]).read_text())
        assert "detected_language" in artifact

    def test_s11_replays_using_s6_s10_artifacts(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch, compare_existing_tests=True)
        result = replay_stage(
            source_run=full_run, stage_name="existing_test_comparison",
            output_dir=tmp_path / "replay-s11", repo_root_override=str(repo_root),
        )
        manifest = _manifest(tmp_path / "replay-s11")
        execution = manifest["executions"][0]
        # remediation_strategy added for the Existing Test Amendment
        # feature -- see stage_registry.STAGE_DEPENDENCIES[
        # EXISTING_TEST_COMPARISON]'s own comment.
        assert set(execution["consumed"].keys()) == {
            "patch_repair_and_calibration", "test_analysis_and_plan", "remediation_strategy",
        }
        artifact = json.loads(Path(execution["artifact_path"]).read_text())
        assert "status" in artifact

    def test_report_generation_replays_and_produces_a_report(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        result = replay_stage(
            source_run=full_run, stage_name="report_generation",
            output_dir=tmp_path / "replay-s12", repo_root_override=str(repo_root),
        )
        assert result.outcome == "settled"
        manifest = _manifest(tmp_path / "replay-s12")
        execution = manifest["executions"][0]
        assert execution["invocation_kind"] == "replay"
        artifact = json.loads(Path(execution["artifact_path"]).read_text())
        report = artifact["report_markdown"]
        assert isinstance(report, str) and len(report) > 0
        assert "Trust Report" in report or "#" in report  # a real Markdown report was rendered
        assert (tmp_path / "replay-s12" / "report.md").exists()

    def test_report_generation_missing_dependency_fails_cleanly(self, run_traced, tmp_path, monkeypatch):
        """report_generation depends on patch_review (among others) -- if a
        source lineage never produced one, resolution must fail BEFORE any
        report is rendered, not silently degrade."""
        from utilities.autopatcher.replay_engine import ReplayEngineError, replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)
        # Truncate the manifest to remove patch_review so resolution fails.
        from utilities.autopatcher import lineage
        manifest = lineage.load_manifest(full_run)
        manifest["executions"] = [
            e for e in manifest["executions"] if e["canonical_stage"] != "patch_review"
        ]
        lineage.resolve_manifest_path(full_run).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        out = tmp_path / "replay-s12-missing"
        with pytest.raises(ReplayEngineError, match="UNRESOLVED|dependency"):
            replay_stage(
                source_run=full_run, stage_name="report_generation",
                output_dir=out, repo_root_override=str(repo_root),
            )
        assert not out.exists()


# ---------------------------------------------------------------------------
# Chained replay -- full -> replay S1 -> replay S2
# ---------------------------------------------------------------------------

class TestS1S2Chain:
    def test_full_chain_s1_then_s2_consumes_the_replayed_s1(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)

        r1 = replay_stage(
            source_run=full_run, stage_name="repository_analysis_and_remediation_planning",
            output_dir=tmp_path / "replay-s1", repo_root_override=str(repo_root),
        )
        assert r1.outcome is not None

        r2 = replay_stage(
            source_run=tmp_path / "replay-s1", stage_name="remediation_strategy",
            output_dir=tmp_path / "replay-s2", repo_root_override=str(repo_root),
        )
        s2_manifest = _manifest(tmp_path / "replay-s2")
        s2_consumed = s2_manifest["executions"][0]["consumed"]
        # THE key proof: S2 consumed the REPLAYED S1, not the original full run.
        assert s2_consumed["repository_analysis_and_remediation_planning"]["run"] == str(tmp_path / "replay-s1")
        assert r2.outcome is not None


# ---------------------------------------------------------------------------
# Chained replay -- full -> replay S5 -> S6 -> S7 -> S8 -> S9 (one more hop
# beyond Batch B7's own S5-S8 chain, proving S9 also consumes newest S6).
# ---------------------------------------------------------------------------

class TestChainThroughS9:
    def test_chain_ending_in_s9_consumes_the_replayed_s6(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)

        replay_stage(
            source_run=full_run, stage_name="challenger",
            output_dir=tmp_path / "replay-s5", repo_root_override=str(repo_root),
        )
        replay_stage(
            source_run=tmp_path / "replay-s5", stage_name="patch_repair_and_calibration",
            output_dir=tmp_path / "replay-s6", repo_root_override=str(repo_root),
        )
        replay_stage(
            source_run=tmp_path / "replay-s6", stage_name="patch_review",
            output_dir=tmp_path / "replay-s7", repo_root_override=str(repo_root),
        )
        replay_stage(
            source_run=tmp_path / "replay-s7", stage_name="confidence_scoring",
            output_dir=tmp_path / "replay-s8", repo_root_override=str(repo_root),
        )
        r9 = replay_stage(
            source_run=tmp_path / "replay-s8", stage_name="impact_and_behavior_analysis",
            output_dir=tmp_path / "replay-s9", repo_root_override=str(repo_root),
        )
        s9_manifest = _manifest(tmp_path / "replay-s9")
        s9_consumed = s9_manifest["executions"][0]["consumed"]
        # S9 depends ONLY on patch_repair_and_calibration -- must resolve the
        # REPLAYED S6 (nearest ancestor), not the original full run's S6.
        assert s9_consumed["patch_repair_and_calibration"]["run"] == str(tmp_path / "replay-s6")
        assert r9.outcome == "settled"


# ---------------------------------------------------------------------------
# Chained replay -- full (compare_existing_tests=True) -> replay S10 ->
# replay S11, proving S11 consumes the REPLAYED S10, never rediscovering it.
# ---------------------------------------------------------------------------

class TestS10S11Chain:
    def test_full_chain_s10_then_s11_consumes_the_replayed_s10(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch, compare_existing_tests=True)

        r10 = replay_stage(
            source_run=full_run, stage_name="test_analysis_and_plan",
            output_dir=tmp_path / "replay-s10", repo_root_override=str(repo_root),
        )
        assert r10.outcome in ("accepted", "rejected")

        r11 = replay_stage(
            source_run=tmp_path / "replay-s10", stage_name="existing_test_comparison",
            output_dir=tmp_path / "replay-s11", repo_root_override=str(repo_root),
        )
        s11_manifest = _manifest(tmp_path / "replay-s11")
        s11_consumed = s11_manifest["executions"][0]["consumed"]
        # THE key proof: S11 consumed the REPLAYED S10, not the original.
        assert s11_consumed["test_analysis_and_plan"]["run"] == str(tmp_path / "replay-s10")
        # And S6 (never replayed here) is inherited from the original full run.
        assert s11_consumed["patch_repair_and_calibration"]["run"] == str(full_run)
        assert r11.outcome is not None

    def test_s11_never_calls_discover_test_plan(self):
        """Structural proof S11's replay handler cannot rediscover a plan --
        it has no import of discover_test_plan/discover_test_plan_for_comparison
        at all, only the COMPARISON half."""
        from utilities.autopatcher import replay_engine as re_mod
        import inspect
        src = inspect.getsource(re_mod._run_replay_existing_test_comparison)
        assert "discover_test_plan" not in src


# ---------------------------------------------------------------------------
# Terminal case: upstream replay chain -> combined report_generation replay
# -> final report generated successfully.
# ---------------------------------------------------------------------------

class TestTerminalReplay:
    def test_upstream_replay_then_combined_terminal_replay_produces_report(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.replay_engine import replay_stage
        repo_root, full_run = _full_run(run_traced, tmp_path, monkeypatch)

        # Replay the FULL downstream chain after S6 (S7/S8/S9 too) --
        # report_generation depends on all of them, and the resolver
        # correctly refuses a STALE patch_review still bound to the
        # pre-replay S6 (proven separately in TestChainThroughS9 above) --
        # so reaching report_generation from a partially-replayed lineage
        # requires catching every dependent stage up, exactly like a real
        # debugging session would.
        replay_stage(
            source_run=full_run, stage_name="challenger",
            output_dir=tmp_path / "replay-s5", repo_root_override=str(repo_root),
        )
        r6 = replay_stage(
            source_run=tmp_path / "replay-s5", stage_name="patch_repair_and_calibration",
            output_dir=tmp_path / "replay-s6", repo_root_override=str(repo_root),
        )
        assert r6.outcome is not None
        replay_stage(
            source_run=tmp_path / "replay-s6", stage_name="patch_review",
            output_dir=tmp_path / "replay-s7", repo_root_override=str(repo_root),
        )
        replay_stage(
            source_run=tmp_path / "replay-s7", stage_name="confidence_scoring",
            output_dir=tmp_path / "replay-s8", repo_root_override=str(repo_root),
        )
        replay_stage(
            source_run=tmp_path / "replay-s8", stage_name="impact_and_behavior_analysis",
            output_dir=tmp_path / "replay-s9", repo_root_override=str(repo_root),
        )

        r12 = replay_stage(
            source_run=tmp_path / "replay-s9", stage_name="report_generation",
            output_dir=tmp_path / "replay-s12", repo_root_override=str(repo_root),
        )
        assert r12.outcome == "settled"
        s12_manifest = _manifest(tmp_path / "replay-s12")
        s12_consumed = s12_manifest["executions"][0]["consumed"]
        # newest-upstream-wins across the WHOLE chain, for every dependency.
        assert s12_consumed["patch_repair_and_calibration"]["run"] == str(tmp_path / "replay-s6")
        assert s12_consumed["patch_review"]["run"] == str(tmp_path / "replay-s7")
        assert s12_consumed["confidence_scoring"]["run"] == str(tmp_path / "replay-s8")
        assert s12_consumed["impact_and_behavior_analysis"]["run"] == str(tmp_path / "replay-s9")
        # S1/S2/S4 were never replayed -- correctly inherited from the
        # original full run, several hops up the parent chain.
        assert s12_consumed["repository_analysis_and_remediation_planning"]["run"] == str(full_run)
        artifact = json.loads(Path(s12_manifest["executions"][0]["artifact_path"]).read_text())
        assert len(artifact["report_markdown"]) > 0


# ---------------------------------------------------------------------------
# No duplicated production/replay logic -- structural proof.
# ---------------------------------------------------------------------------

class TestSharedImplementation:
    def test_replay_handlers_call_the_same_pipeline_executors(self):
        from utilities.autopatcher import replay_engine as re_mod
        from utilities.autopatcher import pipeline as pipeline_mod

        assert re_mod._run_repository_analysis_and_remediation_planning is pipeline_mod._run_repository_analysis_and_remediation_planning
        assert re_mod._run_guided_context_acquisition is pipeline_mod._run_guided_context_acquisition
        assert re_mod._run_impact_and_behavior_analysis is pipeline_mod._run_impact_and_behavior_analysis
        assert re_mod._build_report is pipeline_mod._build_report
