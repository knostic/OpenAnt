"""Integration tests for run_patch_cve: CVE id -> fetch -> InvestigationCase ->
ContextProjection -> the existing (unmodified) Auto Patcher pipeline ->
artifacts on disk.

Hermetic: LLM_PROVIDER=mock, no network (fetch_cve is mocked at the
utilities.autopatcher.cve_fetcher module boundary), no real repo beyond a
tmp_path directory, no Docker. Mirrors test_patch_wrapper_contract.py's style
for the equivalent run_patch() (Finding-mode) tests.
"""

from __future__ import annotations

import os
from unittest import mock

import pytest

from core.patch import PatchStepResult, run_patch_cve
from utilities.autopatcher.cve_fetcher import CVEFetchError, CVENotFoundError

FIXTURE_CVE = {
    "id": "CVE-2021-12345",
    "descriptions": [
        {"lang": "en", "value": "A SQL injection vulnerability exists in the authenticate() function."}
    ],
    "metrics": {
        "cvssMetricV31": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
        ]
    },
    "weaknesses": [
        {"description": [{"lang": "en", "value": "CWE-89"}]}
    ],
}


# core.patch imports fetch_cve locally inside run_patch_cve's body (from
# utilities.autopatcher.cve_fetcher import fetch_cve), so the patch target
# must be the function's home module, not core.patch's namespace.
def _mock_fetch_cve_at_source(cve=FIXTURE_CVE, side_effect=None):
    if side_effect is not None:
        return mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", side_effect=side_effect)
    return mock.patch("utilities.autopatcher.cve_fetcher.fetch_cve", return_value=cve)


class TestRunPatchCveHappyPath:
    def test_writes_artifacts_named_after_cve_id(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source():
            result = run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path))

        assert isinstance(result, PatchStepResult)
        assert result.finding_id == "CVE-2021-12345"
        assert result.input_type == "cve"
        assert result.input_id == "CVE-2021-12345"
        assert result.vulnerability_path == str(tmp_path / "patch" / "CVE-2021-12345-vulnerability.md")
        assert result.trust_report_path == str(tmp_path / "patch" / "CVE-2021-12345-trust-report.md")
        assert os.path.exists(result.vulnerability_path)
        assert os.path.exists(result.trust_report_path)

    def test_trust_report_discloses_cve_input_source(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source():
            result = run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path))

        report_text = open(result.trust_report_path, encoding="utf-8").read()
        assert "Input Source: CVE (CVE-2021-12345)" in report_text
        assert "not been verified against this repository" in report_text
        assert "| Input type | CVE (CVE-2021-12345, NVD) |" in report_text

    def test_vulnerability_artifact_matches_cve_to_vuln_text(self, tmp_path, monkeypatch):
        from utilities.autopatcher.cve_converter import cve_to_vuln_text

        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source():
            result = run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path))

        vuln_text = open(result.vulnerability_path, encoding="utf-8").read()
        assert vuln_text == cve_to_vuln_text(FIXTURE_CVE)

    def test_trust_report_mock_mode_is_self_disclosing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source():
            result = run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path))

        report_text = open(result.trust_report_path, encoding="utf-8").read()
        assert "MOCK MODE" in report_text
        assert "LLM mode | MOCK" in report_text

    def test_never_leaves_stale_trust_report_after_failed_rerun(self, tmp_path, monkeypatch):
        """F-39 guarantee, ported to the CVE entry point."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source():
            first = run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path))
        assert os.path.exists(first.trust_report_path)

        import utilities.autopatcher.pipeline as _pipeline_module

        def _boom(**kwargs):
            raise RuntimeError("simulated pipeline failure")

        monkeypatch.setattr(_pipeline_module, "run", _boom)

        with _mock_fetch_cve_at_source():
            with pytest.raises(RuntimeError, match="simulated pipeline failure"):
                run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path))

        assert not os.path.exists(first.trust_report_path)
        assert os.path.exists(first.vulnerability_path)


class TestRunPatchCveRepoRootValidation:
    def test_missing_repo_root_raises_before_any_fetch(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        nonexistent = str(tmp_path / "does-not-exist")

        with _mock_fetch_cve_at_source() as mocked_fetch:
            with pytest.raises(ValueError, match="does-not-exist"):
                run_patch_cve("CVE-2021-12345", nonexistent, str(tmp_path))
        mocked_fetch.assert_not_called()

    def test_empty_repo_root_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        with pytest.raises(ValueError):
            run_patch_cve("CVE-2021-12345", "", str(tmp_path))

    def test_repo_root_pointing_at_a_file_not_a_directory_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        a_file = tmp_path / "not-a-dir"
        a_file.write_text("x")
        with pytest.raises(ValueError):
            run_patch_cve("CVE-2021-12345", str(a_file), str(tmp_path))


class TestRunPatchCveFetchFailures:
    def test_cve_not_found_propagates(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source(side_effect=CVENotFoundError("no such CVE")):
            with pytest.raises(CVENotFoundError):
                run_patch_cve("CVE-9999-99999", str(repo_root), str(tmp_path))

    def test_network_failure_propagates(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source(side_effect=CVEFetchError("network error")):
            with pytest.raises(CVEFetchError):
                run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path))

    def test_no_artifacts_written_when_fetch_fails(self, tmp_path, monkeypatch):
        """Fetch failures happen before any artifact is written -- mirrors
        run_patch()'s existing behavior for an unknown/ineligible finding."""
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source(side_effect=CVENotFoundError("no such CVE")):
            with pytest.raises(CVENotFoundError):
                run_patch_cve("CVE-9999-99999", str(repo_root), str(tmp_path))

        assert not os.path.exists(tmp_path / "patch")


class TestRunPatchCveRequiresLlmProvider:
    def test_requires_resolvable_credential(self, tmp_path, monkeypatch):
        """No credential anywhere for the canonically-resolved provider --
        must fail clearly, before pipeline work (repo_root check + fetch
        already happened). Uses OpenAI: canonical resolve_provider() has
        no anthropic-style construction-time leniency for it, so this
        failure is guaranteed to surface at the eager
        _require_llm_provider() preflight rather than only deep inside the
        pipeline's first real call_llm()."""
        import utilities.autopatcher.llm_client as llm_client
        from utilities.llm import PHASES, ConfigFile, LLMConfig, PhaseRef

        phases = {p: PhaseRef(provider="openai", model="gpt-test-model") for p in PHASES}
        cf = ConfigFile(default_llm="test-config", llm_configs={"test-config": LLMConfig(name="test-config", phases=phases)})

        monkeypatch.delenv("LLM_PROVIDER", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
        repo_root = tmp_path / "repo"
        repo_root.mkdir()

        with _mock_fetch_cve_at_source() as mocked_fetch:
            with pytest.raises(RuntimeError, match="No usable credential for provider 'openai'"):
                run_patch_cve("CVE-2021-12345", str(repo_root), str(tmp_path))
        # repo_root check and fetch both happen before the credential
        # check inside the shared helper -- fetch_cve is still called here,
        # unlike the repo_root-invalid case above.
        mocked_fetch.assert_called_once()


class TestRunPatchCveRepoRootNormalization:
    """Repository Understanding integration: repo_root must be normalized
    (resolved) once, at this entry point, before InvestigationCase /
    ground_repository / parsing ever see it -- an unresolved path (e.g. a
    macOS /var/... symlink to /private/var/...) can otherwise degrade
    repository-grounding candidate paths to bare filenames."""

    def test_repo_root_is_resolved_before_reaching_pipeline_run(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        real_repo = tmp_path / "real_repo"
        real_repo.mkdir()
        link_repo = tmp_path / "link_repo"
        link_repo.symlink_to(real_repo)

        import utilities.autopatcher.pipeline as _pipeline_module

        captured = {}
        original_run = _pipeline_module.run

        def _capturing_run(*, vulnerability_text, api_key, repo_root=None, investigation_output_dir=None,
                            budget_controller=None, compare_existing_tests=False):
            captured["repo_root"] = repo_root
            return original_run(
                vulnerability_text=vulnerability_text, api_key=api_key,
                repo_root=repo_root, investigation_output_dir=investigation_output_dir,
                budget_controller=budget_controller, compare_existing_tests=compare_existing_tests,
            )

        with _mock_fetch_cve_at_source(), mock.patch.object(_pipeline_module, "run", side_effect=_capturing_run):
            run_patch_cve("CVE-2021-12345", str(link_repo), str(tmp_path))

        assert captured["repo_root"] == str(real_repo.resolve())
        assert captured["repo_root"] != str(link_repo)


class TestRunPatchCveInvestigationDirectory:
    """Run-scoped Repository Understanding parser-artifact directory."""

    def test_created_outside_repo_and_under_output_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("LLM_PROVIDER", "mock")
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        output_dir = tmp_path / "out"

        with _mock_fetch_cve_at_source():
            run_patch_cve("CVE-2021-12345", str(repo_root), str(output_dir))

        expected = output_dir / "patch" / "CVE-2021-12345-investigation"
        assert expected.is_dir()
        assert not str(expected).startswith(str(repo_root))
