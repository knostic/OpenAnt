"""Tests for the Phase C challenger-driven repair loop in pipeline.py."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

_CLEAN_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -1,2 +1,3 @@
 def retry():
+    pass
     pass
```"""

_REPAIR_DIFF = """\
```diff
--- a/src/urllib3/util/retry.py
+++ b/src/urllib3/util/retry.py
@@ -1,2 +1,3 @@
 def retry():
+    # repaired
     pass
```"""

# A challenger result that contains a confirmed defect (bypasses _EXPLICIT_DEFECT_RE)
_CHALLENGER_WITH_DEFECT = {
    "still_vulnerable": False,
    "edge_cases": ["An attacker can bypass this check via path traversal"],
    "potential_issues": [],
    "summary": "The patch has a confirmed bypass.",
}

# A challenger result with BOTH a confirmed defect and a plausible-risk finding
_CHALLENGER_MIXED = {
    "still_vulnerable": False,
    "edge_cases": ["An attacker can bypass this check via crafted input"],
    "potential_issues": ["Performance may be impacted under high load"],
    "summary": "Mixed findings.",
}

# A clean challenger result (no defects)
_CHALLENGER_CLEAN = {
    "still_vulnerable": False,
    "edge_cases": [],
    "potential_issues": [],
    "summary": "No issues found.",
}

# A challenger result whose finding is a plausible_risk only
_CHALLENGER_RISK_ONLY = {
    "still_vulnerable": False,
    "edge_cases": ["This might behave unexpectedly under concurrent access"],
    "potential_issues": [],
    "summary": "Unverified risk only.",
}

_APPLICABILITY_CLEAN = {
    "applicable": True, "skipped": False, "stderr": "",
    "exit_code": 0, "skipped_reason": None, "error": None,
}
_APPLICABILITY_FAIL = {
    "applicable": False, "skipped": False, "stderr": "error: patch failed",
    "exit_code": 1, "skipped_reason": None, "error": None,
}
_APPLICABILITY_SKIPPED = {
    "applicable": None, "skipped": True, "stderr": "",
    "exit_code": None, "skipped_reason": "no repo_root", "error": None,
}


def _capture_result(tmp_path, *, patches_gen, patches_app, patches_chall, repo_root=None):
    """Run pipeline.run() with controlled mocks and capture the PipelineResult."""
    captured = {}
    import utilities.autopatcher.pipeline as _pipeline_mod
    orig_build = _pipeline_mod._build_report

    def _capture(r):
        captured["result"] = r
        return orig_build(r)

    with (
        mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
        mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen) as _mock_gen,
        mock.patch("utilities.autopatcher.patch_applicability.check_applicability", side_effect=patches_app),
        mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
        mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=patches_chall) as _mock_chall,
        mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
        mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
        mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        mock.patch("utilities.autopatcher.pipeline._build_report", side_effect=_capture),
    ):
        mock_llm_cls.return_value = mock.MagicMock()
        from utilities.autopatcher.pipeline import run
        run("test vuln", api_key="", repo_root=repo_root or str(tmp_path))

    return captured["result"], _mock_gen, _mock_chall


# ---------------------------------------------------------------------------
# _build_repair_hint
# ---------------------------------------------------------------------------

class TestBuildRepairHint:
    def test_contains_defect_text(self):
        from utilities.autopatcher.pipeline import _build_repair_hint
        hint = _build_repair_hint(["attacker can bypass the check via path traversal"])
        assert "bypass" in hint

    def test_operation_level_instruction_present(self):
        from utilities.autopatcher.pipeline import _build_repair_hint
        hint = _build_repair_hint(["some defect"])
        assert "dangerous operation" in hint.lower() or "perimeter" in hint.lower()

    def test_multiple_defects_produce_multiple_bullets(self):
        from utilities.autopatcher.pipeline import _build_repair_hint
        hint = _build_repair_hint(["defect one", "defect two"])
        assert "defect one" in hint
        assert "defect two" in hint
        assert hint.count("- defect") == 2

    def test_helper_wiring_instruction_present(self):
        from utilities.autopatcher.pipeline import _build_repair_hint
        hint = _build_repair_hint(["helper not called"])
        assert "helper" in hint.lower() and "every" in hint.lower()

    def test_empty_list_returns_string(self):
        from utilities.autopatcher.pipeline import _build_repair_hint
        hint = _build_repair_hint([])
        assert isinstance(hint, str)
        assert len(hint) > 0


# ---------------------------------------------------------------------------
# _render_repair_notice
# ---------------------------------------------------------------------------

class TestRenderRepairNotice:
    def _make_result(self, **kwargs):
        from utilities.autopatcher.pipeline import PipelineResult
        defaults = dict(
            vulnerability_text="v", patch="p", review="r",
            score_text="Confidence score: 0.8", challenger={},
        )
        defaults.update(kwargs)
        return PipelineResult(**defaults)

    def test_no_notice_when_not_attempted(self):
        from utilities.autopatcher.pipeline import _render_repair_notice
        r = self._make_result(repair_attempted=False)
        assert _render_repair_notice(r) == ""

    def test_success_notice_contains_auto_repaired(self):
        from utilities.autopatcher.pipeline import _render_repair_notice
        r = self._make_result(
            repair_attempted=True, repair_succeeded=True,
            original_challenger_defect_count=2,
        )
        notice = _render_repair_notice(r)
        assert "auto-repaired" in notice.lower()
        assert "2" in notice

    def test_failure_notice_contains_repair_attempted(self):
        from utilities.autopatcher.pipeline import _render_repair_notice
        r = self._make_result(
            repair_attempted=True, repair_succeeded=False, repair_rechallenged=True,
            original_challenger_defect_count=1, repair_defect_count=1,
        )
        notice = _render_repair_notice(r)
        assert "repair attempted" in notice.lower()
        assert "1" in notice

    def test_failure_notice_states_original_recommendation_stands(self):
        from utilities.autopatcher.pipeline import _render_repair_notice
        r = self._make_result(
            repair_attempted=True, repair_succeeded=False, repair_rechallenged=True,
            original_challenger_defect_count=2, repair_defect_count=1,
        )
        notice = _render_repair_notice(r)
        assert "original recommendation stands" in notice.lower()

    def test_never_rechallenged_notice_does_not_claim_a_defect_count(self):
        """When the repair patch never reached re-challenge (applicability
        failure or an internal error), the notice must say so explicitly and
        must not present the untouched repair_defect_count default as if it
        were an observed finding."""
        from utilities.autopatcher.pipeline import _render_repair_notice
        r = self._make_result(
            repair_attempted=True, repair_succeeded=False, repair_rechallenged=False,
            original_challenger_defect_count=2, repair_defect_count=0,
        )
        notice = _render_repair_notice(r)
        assert "repair attempted" in notice.lower()
        assert "did not reach re-challenge" in notice.lower()
        assert "no repair defect count is available" in notice.lower()
        assert "original recommendation stands" in notice.lower()
        # Must not claim the repair patch "had 0 confirmed defect(s)" — that
        # number was never observed.
        assert "repair patch still had" not in notice.lower()
        assert "0 confirmed defect(s)" not in notice.lower()

    def test_never_rechallenged_notice_still_reports_original_count(self):
        """The original (pre-repair) defect count IS a real, observed value
        and should still be reported."""
        from utilities.autopatcher.pipeline import _render_repair_notice
        r = self._make_result(
            repair_attempted=True, repair_succeeded=False, repair_rechallenged=False,
            original_challenger_defect_count=3, repair_defect_count=0,
        )
        notice = _render_repair_notice(r)
        assert "3" in notice


# ---------------------------------------------------------------------------
# Repair NOT triggered
# ---------------------------------------------------------------------------

class TestRepairNotTriggered:
    """Repair must NOT fire when there are no confirmed defects or patch does not apply."""

    def test_no_repair_when_no_confirmed_defects(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert result.repair_attempted is False
        assert mock_gen.call_count == 1
        assert mock_chall.call_count == 1

    def test_no_repair_when_plausible_risk_only(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_RISK_ONLY],
        )
        assert result.repair_attempted is False
        assert mock_gen.call_count == 1

    def test_no_repair_when_applicable_false(self, tmp_path):
        # Patch doesn't apply — repair must not fire (applicability retry handles this)
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_FAIL],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_attempted is False
        assert mock_gen.call_count == 1

    def test_no_repair_when_applicable_none(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_SKIPPED],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_attempted is False
        assert mock_gen.call_count == 1

    def test_urllib3_analog_passes_through_unchanged(self, tmp_path):
        # urllib3 pattern: applicable, no confirmed defects → single generate, single challenge
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert result.repair_attempted is False
        assert result.repair_succeeded is False
        assert result.repair_patch is None
        assert mock_gen.call_count == 1
        assert mock_chall.call_count == 1


# ---------------------------------------------------------------------------
# Repair triggered
# ---------------------------------------------------------------------------

class TestRepairTriggered:
    """Repair fires when applicable=True and confirmed_defect_count > 0."""

    def test_repair_calls_generate_patch_twice(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert result.repair_attempted is True
        assert mock_gen.call_count == 2

    def test_repair_calls_challenge_patch_twice(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert mock_chall.call_count == 2

    def test_repair_hint_passed_to_second_generate_call(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        _args, kwargs = mock_gen.call_args_list[1]
        hint = kwargs.get("retry_hint") or (len(_args) > 3 and _args[3]) or ""
        assert "bypass" in hint.lower()

    def test_repair_hint_contains_confirmed_defect_not_plausible_risk(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_MIXED, _CHALLENGER_CLEAN],
        )
        _args, kwargs = mock_gen.call_args_list[1]
        hint = kwargs.get("retry_hint") or (len(_args) > 3 and _args[3]) or ""
        # confirmed defect text is in the hint
        assert "bypass" in hint.lower()
        # plausible risk (performance) is NOT in the repair hint
        assert "Performance" not in hint

    def test_repair_attempted_flag_set(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert result.repair_attempted is True


# ---------------------------------------------------------------------------
# Repair outcomes
# ---------------------------------------------------------------------------

class TestRepairOutcomes:
    def test_repair_accepted_when_no_defects_remain(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert result.repair_succeeded is True
        # Final patch must be the repair diff content
        assert "repaired" in result.patch

    def test_repair_rejected_when_defects_remain_after_repair(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            # repair challenger still has a confirmed defect
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_succeeded is False
        # patch must be the original, not the repair
        assert "repaired" not in result.patch

    def test_repair_rejected_when_repair_patch_does_not_apply(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            # repair patch does not apply
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_FAIL],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_succeeded is False
        assert result.repair_attempted is True
        # Repair patch never reached re-challenge (applicability failed first),
        # so repair_defect_count must not be presented as an observed value.
        assert result.repair_rechallenged is False

    def test_review_runs_on_accepted_repair_patch(self, tmp_path):
        """When repair is accepted, review_patch must be called with the repair diff."""
        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
            mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=[_CLEAN_DIFF, _REPAIR_DIFF]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       side_effect=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN]),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok") as mock_review,
            mock.patch("utilities.autopatcher.pipeline.challenge_patch",
                       side_effect=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN]),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        ):
            mock_llm_cls.return_value = mock.MagicMock()
            from utilities.autopatcher.pipeline import run
            run("test vuln", api_key="", repo_root=str(tmp_path))
            # review_patch first arg is vuln text, second is the patch
            _args, _ = mock_review.call_args
            reviewed_patch = _args[1]
            assert "repaired" in reviewed_patch

    def test_original_patch_kept_on_rejection(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_FAIL],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_succeeded is False
        assert "repaired" not in result.patch


# ---------------------------------------------------------------------------
# Repair metadata
# ---------------------------------------------------------------------------

class TestRepairMetadata:
    def test_repair_patch_stored_even_when_not_applicable(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_FAIL],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_patch is not None
        assert "repaired" in result.repair_patch

    def test_repair_patch_stored_even_when_rejected_on_defects(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_patch is not None

    def test_original_challenger_defect_count_stored(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert result.original_challenger_defect_count == 1

    def test_repair_challenger_stored_when_repair_applicable(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert result.repair_challenger is not None

    def test_repair_challenger_none_when_repair_not_applicable(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_FAIL],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_challenger is None

    def test_repair_defect_count_zero_on_success(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert result.repair_defect_count == 0

    def test_repair_defect_count_nonzero_on_rejection(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_defect_count > 0

    def test_repair_rechallenged_true_when_repair_patch_applies(self, tmp_path):
        """repair_defect_count is a real, observed value here — repair_rechallenged
        must be True whether the re-challenge finds 0 or nonzero defects."""
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_rechallenged is True

    def test_repair_rechallenged_false_when_repair_patch_does_not_apply(self, tmp_path):
        """repair_defect_count stays at its untouched default (0) here — this
        must be distinguishable from an actual re-challenge finding 0 defects."""
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_FAIL],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_defect_count == 0
        assert result.repair_rechallenged is False

    def test_defaults_when_repair_not_triggered(self, tmp_path):
        result, _, _ = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert result.repair_attempted is False
        assert result.repair_succeeded is False
        assert result.repair_patch is None
        assert result.repair_challenger is None
        assert result.repair_defect_count == 0
        assert result.repair_rechallenged is False
        assert result.original_challenger_defect_count == 0


# ---------------------------------------------------------------------------
# Report content
# ---------------------------------------------------------------------------

class TestRepairReport:
    def _run_and_get_report(self, tmp_path, patches_gen, patches_app, patches_chall):
        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
            mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability", side_effect=patches_app),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="**Explanation**\nok\n"
                       "**Affected areas**\nok\n**Validation notes**\nok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=patches_chall),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        ):
            mock_llm_cls.return_value = mock.MagicMock()
            from utilities.autopatcher.pipeline import run
            return run("test vuln", api_key="", repo_root=str(tmp_path))

    def test_report_contains_auto_repaired_on_success(self, tmp_path):
        report = self._run_and_get_report(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert "auto-repaired" in report.lower()

    def test_report_contains_repair_attempted_on_rejection(self, tmp_path):
        report = self._run_and_get_report(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
        )
        assert "repair attempted" in report.lower()

    def test_report_no_repair_notice_when_not_triggered(self, tmp_path):
        report = self._run_and_get_report(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_CLEAN],
        )
        assert "auto-repaired" not in report.lower()
        assert "repair attempted" not in report.lower()

    def test_report_states_no_rechallenge_when_repair_patch_does_not_apply(self, tmp_path):
        """End-to-end: when the repair patch fails applicability, the rendered
        report must not claim a repair defect count that was never observed."""
        report = self._run_and_get_report(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_FAIL],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert "repair attempted" in report.lower()
        assert "did not reach re-challenge" in report.lower()
        assert "no repair defect count is available" in report.lower()
        assert "repair patch still had" not in report.lower()
        assert "0 confirmed defect(s)" not in report.lower()

    def test_report_states_defect_count_before_repair(self, tmp_path):
        # original had 1 confirmed defect; notice should say 1
        report = self._run_and_get_report(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert "1 confirmed defect" in report
