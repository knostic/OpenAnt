import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


from utilities.autopatcher.run_metadata import RunMetadata, auto_output_path, collect_git_info, render_metadata_section

_TS = datetime(2026, 6, 16, 18, 35, 42, tzinfo=timezone.utc)


def _meta(**overrides) -> RunMetadata:
    defaults = dict(
        timestamp="2026-06-16 18:35:42 UTC",
        input_source="GHSA-v845-jxx5-vc9f",
        repo_root="/tmp/urllib3-eval",
        repo_commit="d9f85a74",
        llm_provider="anthropic",
        llm_model="claude-sonnet-4-6",
        llm_mode="LIVE",
        output_path="reports/20260616-183542-urllib3-eval-ghsa-v845-jxx5-vc9f.md",
        patcher_commit="e0f8737",
    )
    defaults.update(overrides)
    return RunMetadata(**defaults)


# ---------------------------------------------------------------------------
# auto_output_path
# ---------------------------------------------------------------------------

class TestAutoOutputPath:
    def test_ghsa_mode_full_format(self):
        path = auto_output_path(_TS, "GHSA-v845-jxx5-vc9f", None, "/tmp/urllib3-eval")
        assert path == "reports/20260616-183542-urllib3-eval-ghsa-v845-jxx5-vc9f.md"

    def test_file_mode_no_repo(self):
        path = auto_output_path(_TS, None, "examples/vulnerability.md", None)
        assert path == "reports/20260616-183542-vulnerability.md"

    def test_file_mode_with_repo(self):
        path = auto_output_path(_TS, None, "examples/vulnerability.md", "/tmp/myrepo")
        assert path == "reports/20260616-183542-myrepo-vulnerability.md"

    def test_output_always_under_reports_dir(self):
        path = auto_output_path(_TS, "GHSA-x-y-z", None, "/tmp/proj")
        assert path.startswith("reports/")
        assert path.endswith(".md")

    def test_ghsa_id_is_lowercased(self):
        path = auto_output_path(_TS, "GHSA-V845-JXX5-VC9F", None, "/tmp/urllib3-eval")
        assert "ghsa-v845-jxx5-vc9f" in path
        assert "GHSA" not in path

    def test_repo_slug_is_lowercased(self):
        path = auto_output_path(_TS, "GHSA-x-y-z", None, "/tmp/MyProject")
        assert "myproject" in path
        assert "MyProject" not in path

    def test_seconds_included_in_timestamp(self):
        ts = datetime(2026, 6, 16, 9, 5, 3, tzinfo=timezone.utc)
        path = auto_output_path(ts, "GHSA-a-b-c", None, "/tmp/repo")
        assert "20260616-090503" in path

    def test_no_ghsa_no_file_fallback(self):
        path = auto_output_path(_TS, None, None, None)
        assert path == "reports/20260616-183542-report.md"


# ---------------------------------------------------------------------------
# collect_git_info
# ---------------------------------------------------------------------------

class TestCollectGitInfo:
    def test_non_repo_returns_unknown(self, tmp_path):
        result = collect_git_info(tmp_path)
        assert result == "unknown"

    def test_nonexistent_path_returns_unknown(self):
        result = collect_git_info(Path("/nonexistent/path/xyz"))
        assert result == "unknown"

    def test_never_raises(self, tmp_path):
        result = collect_git_info(tmp_path / "does_not_exist")
        assert isinstance(result, str)

    def test_real_repo_returns_short_sha(self):
        project_root = Path(__file__).parent.parent
        result = collect_git_info(project_root)
        assert result != "unknown"
        assert len(result) >= 7
        assert all(c in "0123456789abcdef" for c in result), f"Not a hex SHA: {result!r}"

    def test_real_repo_sha_matches_git_log(self):
        project_root = Path(__file__).parent.parent
        expected = subprocess.run(
            ["git", "log", "-1", "--format=%h"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert collect_git_info(project_root) == expected


# ---------------------------------------------------------------------------
# render_metadata_section
# ---------------------------------------------------------------------------

class TestRenderMetadataSection:
    def test_all_required_fields_present(self):
        md = render_metadata_section(_meta())
        for field in [
            "Generated",
            "Input",
            "Repository",
            "Repo commit",
            "LLM provider",
            "LLM model",
            "LLM mode",
            "Output",
            "Auto-patcher",
        ]:
            assert field in md, f"Required field missing from metadata: {field!r}"

    def test_values_rendered_in_table(self):
        md = render_metadata_section(_meta())
        assert "GHSA-v845-jxx5-vc9f" in md
        assert "d9f85a74" in md
        assert "anthropic" in md
        assert "claude-sonnet-4-6" in md
        assert "LIVE" in md
        assert "e0f8737" in md

    def test_mock_warning_present_in_mock_mode(self):
        md = render_metadata_section(_meta(llm_mode="MOCK"))
        assert "MOCK MODE" in md
        assert "must not be used as benchmark evidence" in md

    def test_mock_warning_absent_in_live_mode(self):
        md = render_metadata_section(_meta(llm_mode="LIVE"))
        assert "MOCK MODE" not in md

    def test_empty_repo_root_renders_dash(self):
        md = render_metadata_section(_meta(repo_root=""))
        assert "| Repository | — |" in md

    def test_output_path_in_table(self):
        md = render_metadata_section(_meta(
            output_path="reports/20260616-183542-urllib3-eval-ghsa-v845-jxx5-vc9f.md"
        ))
        assert "reports/20260616-183542-urllib3-eval-ghsa-v845-jxx5-vc9f.md" in md


# ---------------------------------------------------------------------------
# render_metadata_section — max_tokens_configured / stage_stop_reasons
# ---------------------------------------------------------------------------

class TestTokenBudgetAndStopReasons:
    def test_max_tokens_row_rendered_when_present(self):
        md = render_metadata_section(_meta(max_tokens_configured=4096))
        assert "| Max output tokens | 4096 |" in md

    def test_max_tokens_row_renders_dash_when_absent(self):
        md = render_metadata_section(_meta())
        assert "| Max output tokens | — |" in md

    def test_stage_stop_reason_table_rendered_when_present(self):
        md = render_metadata_section(_meta(stage_stop_reasons={
            "patch_generation": "end_turn",
            "patch_review": "end_turn",
            "challenger": "end_turn",
            "confidence_scorer": "end_turn",
        }))
        assert "### Stage Stop Reasons" in md
        assert "| Patch generation | end_turn |" in md
        assert "| Patch review | end_turn |" in md
        assert "| Challenger | end_turn |" in md
        assert "| Confidence scorer | end_turn |" in md

    def test_stage_stop_reason_table_absent_when_no_stages_recorded(self):
        md = render_metadata_section(_meta())
        assert "Stage Stop Reasons" not in md

    def test_truncated_stage_gets_warning_icon_in_table(self):
        md = render_metadata_section(_meta(stage_stop_reasons={
            "patch_generation": "max_tokens",
            "patch_review": "end_turn",
        }))
        assert "| Patch generation | ⚠️ max_tokens |" in md
        assert "| Patch review | end_turn |" in md

    def test_openai_length_stop_reason_also_flagged(self):
        md = render_metadata_section(_meta(stage_stop_reasons={
            "patch_generation": "length",
        }))
        assert "| Patch generation | ⚠️ length |" in md

    def test_truncation_banner_present_when_any_stage_truncated(self):
        md = render_metadata_section(_meta(stage_stop_reasons={
            "patch_generation": "max_tokens",
            "patch_review": "end_turn",
        }))
        assert "TRUNCATED OUTPUT DETECTED" in md

    def test_truncation_banner_absent_when_no_stage_truncated(self):
        md = render_metadata_section(_meta(stage_stop_reasons={
            "patch_generation": "end_turn",
            "patch_review": "stop",
        }))
        assert "TRUNCATED OUTPUT DETECTED" not in md

    def test_truncation_banner_absent_when_no_stages_recorded(self):
        md = render_metadata_section(_meta())
        assert "TRUNCATED OUTPUT DETECTED" not in md

    def test_truncation_banner_coexists_with_mock_warning(self):
        md = render_metadata_section(_meta(
            llm_mode="MOCK",
            stage_stop_reasons={"patch_generation": "max_tokens"},
        ))
        assert "MOCK MODE" in md
        assert "TRUNCATED OUTPUT DETECTED" in md


# ---------------------------------------------------------------------------
# render_metadata_section — CVE input-source disclosure (additive; must not
# change output for the default "finding" input_type)
# ---------------------------------------------------------------------------

class TestCveInputSourceDisclosure:
    def test_default_input_type_renders_no_disclosure_or_row(self):
        md = render_metadata_section(_meta())
        assert "Input Source: CVE" not in md
        assert "Input type" not in md

    def test_finding_input_type_renders_no_disclosure_or_row(self):
        md = render_metadata_section(_meta(input_type="finding"))
        assert "Input Source: CVE" not in md
        assert "Input type" not in md

    def test_cve_input_type_renders_disclosure(self):
        md = render_metadata_section(_meta(
            input_type="cve", advisory_id="CVE-2022-25883", advisory_source="NVD",
        ))
        assert "Input Source: CVE (CVE-2022-25883)" in md
        assert "NVD" in md

    def test_cve_disclosure_states_not_repository_verified(self):
        md = render_metadata_section(_meta(
            input_type="cve", advisory_id="CVE-2022-25883", advisory_source="NVD",
        ))
        assert "not been verified against this repository" in md

    def test_cve_disclosure_states_recommendation_based_on_collected_evidence(self):
        md = render_metadata_section(_meta(
            input_type="cve", advisory_id="CVE-2022-25883", advisory_source="NVD",
        ))
        assert "based only on the evidence this pipeline run actually collected" in md

    def test_cve_input_type_renders_table_row(self):
        md = render_metadata_section(_meta(
            input_type="cve", advisory_id="CVE-2022-25883", advisory_source="NVD",
        ))
        assert "| Input type | CVE (CVE-2022-25883, NVD) |" in md

    def test_cve_disclosure_handles_missing_advisory_fields_without_crash(self):
        md = render_metadata_section(_meta(input_type="cve"))
        assert "Input Source: CVE (unknown)" in md

    def test_cve_disclosure_coexists_with_mock_warning(self):
        md = render_metadata_section(_meta(
            input_type="cve", advisory_id="CVE-2022-25883", advisory_source="NVD",
            llm_mode="MOCK",
        ))
        assert "MOCK MODE" in md
        assert "Input Source: CVE" in md

    def test_rest_of_table_unaffected_by_cve_disclosure(self):
        md = render_metadata_section(_meta(
            input_type="cve", advisory_id="CVE-2022-25883", advisory_source="NVD",
        ))
        for field in ["Generated", "Repository", "Repo commit", "LLM provider", "Output", "Auto-patcher"]:
            assert field in md
