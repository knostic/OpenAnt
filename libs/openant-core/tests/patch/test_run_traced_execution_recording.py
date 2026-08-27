"""End-to-end proof of Batch B2's StageExecution recording through the real
tools/run_traced.py wrapper -- a REAL mock-mode LLMClient (LLM_PROVIDER=mock,
genuine utilities.autopatcher.llm_client.call_llm() calls, no mocking of
pipeline internals), so the manifest this produces is exactly what a real
`--trace-dir` run would write.

Same harness/fixtures as test_run_traced_wrapper.py (loads run_traced.py by
file path, fetch_cve mocked at its source module, a real empty git repo).
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
    spec = importlib.util.spec_from_file_location("run_traced_exec_rec", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mock_fetch_cve_at_source(cve=FIXTURE_CVE):
    return mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve)


def _run_traced(run_traced, tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    output_dir = tmp_path / "out"
    argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
    with _mock_fetch_cve_at_source():
        exit_code = run_traced.main(argv)
    assert exit_code == 0
    manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
    return output_dir, manifest


class TestRealTracedRunRecordsExecutions:
    def test_manifest_is_v3_with_real_executions(self, run_traced, tmp_path, monkeypatch):
        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        assert manifest["schema_version"] == 3
        assert manifest["kind"] == "full_run"
        assert manifest["parent"] is None
        assert "executions" in manifest
        assert len(manifest["executions"]) == 6

    def test_exact_canonical_stage_order(self, run_traced, tmp_path, monkeypatch):
        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        assert [e["canonical_stage"] for e in manifest["executions"]] == [
            "repository_analysis_and_remediation_planning",
            "remediation_strategy",
            "guided_context_acquisition",
            "patch_generation_and_post_patch_investigation",
            "challenger",
            "patch_repair_and_calibration",
        ]

    def test_exact_execution_ids(self, run_traced, tmp_path, monkeypatch):
        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        assert [e["execution_id"] for e in manifest["executions"]] == [
            "001_repository_analysis_and_remediation_planning",
            "002_remediation_strategy",
            "003_guided_context_acquisition",
            "004_patch_generation_and_post_patch_investigation",
            "005_challenger",
            "006_patch_repair_and_calibration",
        ]

    def test_consumed_edges_reference_the_output_dir_as_run(self, run_traced, tmp_path, monkeypatch):
        output_dir, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        s4 = manifest["executions"][3]
        assert s4["consumed"]["guided_context_acquisition"]["run"] == str(output_dir)
        assert s4["consumed"]["guided_context_acquisition"]["execution_id"] == "003_guided_context_acquisition"

    def test_no_repeated_canonical_stage_executions(self, run_traced, tmp_path, monkeypatch):
        """Batch B3: S6 (patch_repair_and_calibration) IS now expected --
        but no canonical stage should ever appear twice (no fabricated
        S4#2/S5#2/S6#2)."""
        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        stages = [e["canonical_stage"] for e in manifest["executions"]]
        assert "patch_repair_and_calibration" in stages
        assert len(stages) == len(set(stages))  # no canonical stage repeated

    def test_every_execution_has_an_artifact_file(self, run_traced, tmp_path, monkeypatch):
        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        for execution in manifest["executions"]:
            assert execution["artifact_path"], execution["execution_id"]
            assert Path(execution["artifact_path"]).is_file()
            json.loads(Path(execution["artifact_path"]).read_text())  # valid JSON

    def test_llm_call_attribution_matches_real_checkpoints(self, run_traced, tmp_path, monkeypatch):
        """The REAL, end-to-end proof: every genuine mock-mode LLM call
        this run made (per checkpoints.jsonl, the ground truth) is
        attributed to AT MOST one execution's llm_calls, and every call
        attributed to an execution is a real call that actually happened.
        """
        output_dir, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        checkpoints = [
            json.loads(line)
            for line in (output_dir / "trace" / "checkpoints.jsonl").read_text().splitlines()
        ]
        real_seqs = {c["seq"] for c in checkpoints}

        attributed_seqs = []
        for execution in manifest["executions"]:
            for call in execution["llm_calls"]:
                attributed_seqs.append(call["seq"])
                # Full prompt/response text must not be duplicated inline.
                assert "prompt" not in call
                assert "response" not in call
                assert "prompt_file" in call

        # No call attributed to more than one execution.
        assert len(attributed_seqs) == len(set(attributed_seqs))
        # Every attributed call really happened.
        assert set(attributed_seqs) <= real_seqs
        # Attribution windows are non-overlapping and in order: S4's own
        # patch-generation call is attributed to S4 specifically.
        s4_seqs = {c["seq"] for c in manifest["executions"][3]["llm_calls"]}
        s5_seqs = {c["seq"] for c in manifest["executions"][4]["llm_calls"]}
        assert s4_seqs.isdisjoint(s5_seqs)

    def test_s1_artifact_has_real_structured_plan_result(self, run_traced, tmp_path, monkeypatch):
        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        s1 = manifest["executions"][0]
        artifact = json.loads(Path(s1["artifact_path"]).read_text())
        assert "plan_result" in artifact
        assert isinstance(artifact["plan_result"], dict)

    def test_call_llm_is_restored_after_run_with_recording(self, run_traced, tmp_path, monkeypatch):
        """Recording must not leave the LLM client monkeypatched -- proves
        no nested capture leaked past the run (Final Correction 2)."""
        import utilities.autopatcher.llm_client as llm_client_module
        original = llm_client_module.call_llm
        _run_traced(run_traced, tmp_path, monkeypatch)
        assert llm_client_module.call_llm is original

    def test_failure_manifest_still_includes_partial_executions(self, run_traced, tmp_path, monkeypatch):
        """A run that fails mid-way must still write whatever executions
        DID finish before the failure -- not silently drop them, and not
        fabricate the rest."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"
        argv = ["--cve", "CVE-2021-12345", "--repo-root", str(repo_root), "--output", str(output_dir)]
        with _mock_fetch_cve_at_source(), mock.patch(
            "utilities.autopatcher.pipeline.challenge_patch", side_effect=RuntimeError("boom")
        ):
            with pytest.raises(RuntimeError):
                run_traced.main(argv)
        manifest = json.loads((output_dir / "trace" / "run_manifest.json").read_text())
        assert manifest["status"] == "failed"
        # S1-S4 (everything before the injected failure) must still be present.
        stages = [e["canonical_stage"] for e in manifest["executions"]]
        assert "patch_generation_and_post_patch_investigation" in stages
        assert "challenger" not in stages  # S5 never finished -- honestly absent


class TestStage6CalibrationFallback:
    """Case D: the real mock-mode challenger response
    (llm_client._MOCK_CHALLENGE) has no confirmed_defect finding, so Stage
    6's late-calibration fallback genuinely fires with a real LLM call --
    this is the exact dataflow that previously blocked Stage-6 persistence
    (the fallback settling `finding_calibration` after Existing Test
    Comparison/Stage 7 would have started). Proves, end-to-end, that it now
    settles INSIDE S6, before S6 finishes, with no Stage-7 leakage."""

    def test_fallback_llm_call_is_captured_inside_s6(self, run_traced, tmp_path, monkeypatch):
        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        s6 = manifest["executions"][5]
        assert s6["canonical_stage"] == "patch_repair_and_calibration"
        tags = [c["stage"] for c in s6["llm_calls"]]
        assert "finding_calibration" in tags

    def test_s6_llm_calls_all_within_registry_owned_tags(self, run_traced, tmp_path, monkeypatch):
        from utilities.autopatcher.stage_registry import PATCH_REPAIR_AND_CALIBRATION, STAGE_OWNED_LLM_TAGS

        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        s6 = manifest["executions"][5]
        owned = STAGE_OWNED_LLM_TAGS[PATCH_REPAIR_AND_CALIBRATION]
        for call in s6["llm_calls"]:
            assert call["stage"] in owned

    def test_no_stage7_call_leaks_into_s6(self, run_traced, tmp_path, monkeypatch):
        """patch_review/confidence_scorer (Stage 7/Confidence Scoring's own
        owned tags) must never appear inside S6's llm_calls."""
        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        s6 = manifest["executions"][5]
        tags = {c["stage"] for c in s6["llm_calls"]}
        assert "patch_review" not in tags
        assert "confidence_scorer" not in tags

    def test_final_calibration_artifact_matches_what_downstream_report_used(self, run_traced, tmp_path, monkeypatch):
        """The S6 artifact's `finding_calibration` must be the SAME final
        value that fed the report -- proven by checking it's non-empty,
        sourced from the fallback, and its reworded text appears in the
        trust report the run actually wrote."""
        output_dir, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        s6 = manifest["executions"][5]
        artifact = json.loads(Path(s6["artifact_path"]).read_text())
        assert artifact["finding_calibration_source"] == "fallback"
        assert artifact["finding_calibration"]
        trust_report = (output_dir / "patch" / "CVE-2021-12345-trust-report.md").read_text()
        first_reworded = artifact["finding_calibration"][0]["reworded"]
        assert first_reworded in trust_report

    def test_repair_not_triggered_honestly_recorded(self, run_traced, tmp_path, monkeypatch):
        _, manifest = _run_traced(run_traced, tmp_path, monkeypatch)
        s6 = manifest["executions"][5]
        artifact = json.loads(Path(s6["artifact_path"]).read_text())
        assert artifact["repair_attempted"] is False
        assert artifact["repair_outcome"] == "not_triggered_no_defects"
        assert artifact["authoritative_candidate"]["source"] == "original"
