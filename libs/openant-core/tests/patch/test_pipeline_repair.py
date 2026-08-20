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


def _calibrate_all_observed(vulnerability_text, patch, findings, llm, code_context=""):
    """Default Finding Calibration mock for this module: labels every
    finding it's given "Observed". Since should_auto_repair/accept_repair
    now require an EXPLICIT "observed" calibration entry before a raw
    confirmed_defect finding can authorize or accept a mutation (see
    pipeline.py), this reproduces -- for every test in this module that is
    not specifically exercising the calibration gate itself -- the same
    repair-triggering behavior this module tested before that gate
    existed: repair fires whenever a raw confirmed_defect finding is
    present and the patch applies. Tests that DO exercise the gate itself
    (TestDeterministicRepairGate below) pass their own
    calibration_side_effect explicitly instead of relying on this default.
    """
    return [{"original": f, "group": "observed", "reworded": f} for f in findings]


def _capture_result(tmp_path, *, patches_gen, patches_app, patches_chall, repo_root=None,
                     calibration_side_effect=None):
    """Run pipeline.run() with controlled mocks and capture the PipelineResult."""
    captured = {}
    import utilities.autopatcher.pipeline as _pipeline_mod
    orig_build = _pipeline_mod._build_report

    def _capture(r):
        captured["result"] = r
        return orig_build(r)

    # Release: response-contract enforcement moved the initial generation
    # call site (Site 1) from generate_patch() to
    # _generate_patch_with_contract_check() -> generate_patch_raw() (both
    # defined in pipeline.py); the Challenger-repair loop (Site 4, what
    # this test module exercises) still calls generate_patch() directly
    # (patch_generator.py), unchanged. patches_gen[0] is always the Site 1
    # response (every caller of this helper passes it first) -- mocking
    # generate_patch_raw with it, and generate_patch with the REMAINING
    # items, preserves every existing call's exact meaning: Site 1 always
    # sees patches_gen[0], and Site 4's repair call sees patches_gen[1:] in
    # the same order as before.
    with (
        mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
        mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=patches_gen[0]),
        mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen[1:]) as _mock_gen,
        mock.patch("utilities.autopatcher.patch_applicability.check_applicability", side_effect=patches_app),
        mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok review"),
        mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=patches_chall) as _mock_chall,
        mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
        mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
        mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        mock.patch("utilities.autopatcher.pipeline._build_report", side_effect=_capture),
        mock.patch("utilities.autopatcher.pipeline.calibrate_findings",
                   side_effect=calibration_side_effect or _calibrate_all_observed) as _mock_calibrate,
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
        assert mock_gen.call_count == 0  # Site 4 (repair) never fires; Site 1 is now generate_patch_raw
        assert mock_chall.call_count == 1

    def test_no_repair_when_plausible_risk_only(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_RISK_ONLY],
        )
        assert result.repair_attempted is False
        assert mock_gen.call_count == 0  # Site 4 (repair) never fires; Site 1 is now generate_patch_raw

    def test_no_repair_when_applicable_false(self, tmp_path):
        # Patch doesn't apply — repair must not fire (applicability retry handles this)
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_FAIL],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_attempted is False
        assert mock_gen.call_count == 0  # Site 4 (repair) never fires; Site 1 is now generate_patch_raw

    def test_no_repair_when_applicable_none(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_SKIPPED],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
        )
        assert result.repair_attempted is False
        assert mock_gen.call_count == 0  # Site 4 (repair) never fires; Site 1 is now generate_patch_raw

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
        assert mock_gen.call_count == 0  # Site 4 (repair) never fires; Site 1 is now generate_patch_raw
        assert mock_chall.call_count == 1


# ---------------------------------------------------------------------------
# Repair triggered
# ---------------------------------------------------------------------------

class TestRepairTriggered:
    """Repair fires when applicable=True and confirmed_defect_count > 0."""

    def test_repair_calls_generate_patch_twice(self, tmp_path):
        """Release: response-contract enforcement moved the initial
        generation call site (Site 1) to generate_patch_raw() (mocked via
        patches_gen[0], see _capture_result) -- `mock_gen` here now
        reflects only the repair loop's own generate_patch() call (Site 4),
        so "twice" is: once for Site 1 (implicit, via patches_gen[0]) and
        once here for the repair call."""
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert result.repair_attempted is True
        assert mock_gen.call_count == 1

    def test_repair_calls_challenge_patch_twice(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        assert mock_chall.call_count == 2

    def test_repair_hint_passed_to_second_generate_call(self, tmp_path):
        """`mock_gen` now reflects only the repair loop's own call (Site 4)
        -- see test_repair_calls_generate_patch_twice -- so it is the FIRST
        (and only) recorded call here, not the second."""
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
        )
        _args, kwargs = mock_gen.call_args_list[0]
        hint = kwargs.get("retry_hint") or (len(_args) > 3 and _args[3]) or ""
        assert "bypass" in hint.lower()

    def test_repair_hint_contains_confirmed_defect_not_plausible_risk(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_MIXED, _CHALLENGER_CLEAN],
        )
        _args, kwargs = mock_gen.call_args_list[0]
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
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=_CLEAN_DIFF),
            mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=[_REPAIR_DIFF]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       side_effect=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN]),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok") as mock_review,
            mock.patch("utilities.autopatcher.pipeline.challenge_patch",
                       side_effect=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN]),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.pipeline.calibrate_findings", side_effect=_calibrate_all_observed),
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
    def _run_and_get_report(self, tmp_path, patches_gen, patches_app, patches_chall,
                             calibration_side_effect=None):
        # patches_gen[0] is always the Site 1 response (see _capture_result's
        # comment above) -- mocked via generate_patch_raw; generate_patch
        # itself now only serves the Site 4 repair call, if any.
        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=patches_gen[0]),
            mock.patch("utilities.autopatcher.pipeline.generate_patch", side_effect=patches_gen[1:]),
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability", side_effect=patches_app),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="**Explanation**\nok\n"
                       "**Affected areas**\nok\n**Validation notes**\nok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", side_effect=patches_chall),
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
            mock.patch("utilities.autopatcher.pipeline.calibrate_findings",
                       side_effect=calibration_side_effect or _calibrate_all_observed),
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


# ---------------------------------------------------------------------------
# Deterministic repair gate -- should_auto_repair / accept_repair
#
# Flow: Patch v1 -> Challenger v1 -> raw classification -> Finding
# Calibration v1 -> should_auto_repair -> optional Repair v2 -> deterministic
# applicability/hygiene -> Challenger v2 -> Finding Calibration v2 ->
# accept_repair -> continue. Both gate functions are pure: no LLM calls, no
# prose inspection, structured input only.
# ---------------------------------------------------------------------------

_BYPASS_TEXT = "An attacker can bypass this check via path traversal"
_BYPASS_CHALLENGER = {
    "still_vulnerable": False,
    "edge_cases": [_BYPASS_TEXT],
    "potential_issues": [],
    "summary": "one confirmed defect",
}


def _observed(text: str) -> dict:
    return {"original": text, "group": "observed", "reworded": text}


def _hypothesis(text: str) -> dict:
    return {"original": text, "group": "hypothesis", "reworded": text}


def _hardening(text: str) -> dict:
    return {"original": text, "group": "hardening", "reworded": text}


class TestShouldAutoRepair:
    """Unit tests for should_auto_repair — condition 1 (applicable) AND
    condition 2 (raw confirmed_defect) AND condition 3 (that SAME finding
    explicitly calibrated "observed") must ALL hold; anything else denies."""

    def _classified(self, challenger=None):
        from utilities.autopatcher.pipeline import _classify_challenger
        return _classify_challenger(challenger or _BYPASS_CHALLENGER)

    def test_no_repair_when_calibrated_hypothesis(self):
        from utilities.autopatcher.pipeline import should_auto_repair
        classified = self._classified()
        assert should_auto_repair(classified, [_hypothesis(_BYPASS_TEXT)], True) is False

    def test_no_repair_when_calibrated_hardening(self):
        from utilities.autopatcher.pipeline import should_auto_repair
        classified = self._classified()
        assert should_auto_repair(classified, [_hardening(_BYPASS_TEXT)], True) is False

    def test_no_repair_when_calibration_is_none(self):
        """Calibration did not run or failed outright -- must not fall back
        to authorizing repair on the raw regex classification alone."""
        from utilities.autopatcher.pipeline import should_auto_repair
        classified = self._classified()
        assert should_auto_repair(classified, None, True) is False

    def test_no_repair_when_calibration_is_empty_list(self):
        from utilities.autopatcher.pipeline import should_auto_repair
        classified = self._classified()
        assert should_auto_repair(classified, [], True) is False

    def test_no_repair_when_calibration_omits_this_specific_finding(self):
        """Calibration ran (non-empty) but has no entry for THIS
        confirmed_defect finding -- missing must not be treated as cleared."""
        from utilities.autopatcher.pipeline import should_auto_repair
        classified = self._classified()
        other = _observed("a completely unrelated finding")
        assert should_auto_repair(classified, [other], True) is False

    def test_repair_authorized_when_observed_and_applicable(self):
        """Genuine repair authorization: all three conditions hold."""
        from utilities.autopatcher.pipeline import should_auto_repair
        classified = self._classified()
        assert should_auto_repair(classified, [_observed(_BYPASS_TEXT)], True) is True

    def test_no_repair_when_observed_but_not_applicable(self):
        from utilities.autopatcher.pipeline import should_auto_repair
        classified = self._classified()
        assert should_auto_repair(classified, [_observed(_BYPASS_TEXT)], False) is False

    def test_no_repair_when_no_raw_confirmed_defect(self):
        from utilities.autopatcher.pipeline import should_auto_repair
        classified = self._classified(_CHALLENGER_CLEAN)
        assert should_auto_repair(classified, [], True) is False

    def test_still_vulnerable_no_with_defect_shaped_wording_calibrated_hypothesis(self):
        """Real urllib3 CVE-2023-43804 regression shape: Challenger reports
        'Still vulnerable: No' yet phrases findings with defect-shaped
        wording ("could bypass", "does not address") that the raw regex
        classifier tags confirmed_defect. When Calibration labels those
        Hypothesis, repair must not fire."""
        from utilities.autopatcher.pipeline import should_auto_repair, _classify_challenger
        challenger = {
            "still_vulnerable": False,
            "edge_cases": [
                "Redirects handled at the Retry level rather than PoolManager could bypass the loop"
            ],
            "potential_issues": [
                "The patch does not address Cookie leakage via higher-level wrappers"
            ],
            "summary": "still_vulnerable: No, but heuristically defect-shaped wording present",
        }
        classified = _classify_challenger(challenger)
        assert classified["confirmed_defect_count"] > 0  # raw regex tags these confirmed_defect
        assert classified.get("still_vulnerable") is False
        defect_texts = [
            f["text"]
            for f in classified["classified_edge_cases"] + classified["classified_potential_issues"]
            if f["category"] == "confirmed_defect"
        ]
        calibration = [_hypothesis(t) for t in defect_texts]
        assert should_auto_repair(classified, calibration, True) is False

    def test_same_semantic_concern_different_wording_same_group_same_decision(self):
        """Two differently-worded confirmed_defect findings that calibrate
        to the SAME group must produce the SAME should_auto_repair decision."""
        from utilities.autopatcher.pipeline import should_auto_repair, _classify_challenger
        wordings = [
            "An attacker can bypass this check via path traversal",
            "A determined attacker could bypass this validation using a different encoding",
        ]
        decisions = set()
        for wording in wordings:
            classified = _classify_challenger({
                "still_vulnerable": False, "edge_cases": [wording],
                "potential_issues": [], "summary": "...",
            })
            assert classified["confirmed_defect_count"] == 1
            decisions.add(should_auto_repair(classified, [_hypothesis(wording)], True))
        assert decisions == {False}


class TestAcceptRepair:
    """Unit tests for accept_repair — the v2 acceptance gate. Symmetric with
    should_auto_repair but applied to v2's own finding state, and fails
    closed (rejects, preserving v1) under exactly the same uncertainty that
    should_auto_repair fails closed on (denying authorization) for v1."""

    def _classified(self, challenger):
        from utilities.autopatcher.pipeline import _classify_challenger
        return _classify_challenger(challenger)

    def test_accept_when_applicable_and_no_raw_confirmed_defect(self):
        from utilities.autopatcher.pipeline import accept_repair
        classified = self._classified(_CHALLENGER_CLEAN)
        assert accept_repair(classified, None, True) is True

    def test_reject_when_not_applicable(self):
        from utilities.autopatcher.pipeline import accept_repair
        classified = self._classified(_CHALLENGER_CLEAN)
        assert accept_repair(classified, None, False) is False

    def test_accept_when_confirmed_defect_calibrates_away_from_observed(self):
        """v2 applies and has no calibration-confirmed remaining defect."""
        from utilities.autopatcher.pipeline import accept_repair
        classified = self._classified(_BYPASS_CHALLENGER)
        assert accept_repair(classified, [_hypothesis(_BYPASS_TEXT)], True) is True

    def test_reject_when_confirmed_defect_calibrates_observed(self):
        """v2 retains (or introduces) a calibration-confirmed defect ->
        reject v2, preserve v1."""
        from utilities.autopatcher.pipeline import accept_repair
        classified = self._classified(_BYPASS_CHALLENGER)
        assert accept_repair(classified, [_observed(_BYPASS_TEXT)], True) is False

    def test_reject_when_calibration_v2_fails(self):
        """calibration v2 failure (None) with a raw confirmed_defect present
        -> cannot verify it was cleared -> reject v2, preserve v1."""
        from utilities.autopatcher.pipeline import accept_repair
        classified = self._classified(_BYPASS_CHALLENGER)
        assert accept_repair(classified, None, True) is False

    def test_reject_when_calibration_v2_omits_the_finding(self):
        from utilities.autopatcher.pipeline import accept_repair
        classified = self._classified(_BYPASS_CHALLENGER)
        other = _observed("a completely unrelated finding")
        assert accept_repair(classified, [other], True) is False


class TestRepairGateEndToEnd:
    """pipeline.run() coverage for the deterministic repair gate: same
    scenarios as TestShouldAutoRepair/TestAcceptRepair, exercised through
    the full pipeline with calibrate_findings mocked per-scenario."""

    @staticmethod
    def _calibrate_group(group):
        def _side_effect(vulnerability_text, patch, findings, llm, code_context=""):
            return [{"original": f, "group": group, "reworded": f} for f in findings]
        return _side_effect

    def test_no_repair_when_calibration_downgrades_to_hypothesis(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
            calibration_side_effect=self._calibrate_group("hypothesis"),
        )
        assert result.repair_attempted is False
        # No-repair path: neither a second generate_patch nor a second
        # challenge_patch call ever happens.
        assert mock_gen.call_count == 0
        assert mock_chall.call_count == 1

    def test_no_repair_when_calibration_downgrades_to_hardening(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
            calibration_side_effect=self._calibrate_group("hardening"),
        )
        assert result.repair_attempted is False
        assert mock_gen.call_count == 0

    def test_no_repair_when_calibration_raises(self, tmp_path):
        def _raise(*a, **kw):
            raise RuntimeError("calibration backend unavailable")
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
            calibration_side_effect=_raise,
        )
        assert result.repair_attempted is False
        assert mock_gen.call_count == 0

    def test_genuine_repair_authorization_fires_exactly_once(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
            calibration_side_effect=self._calibrate_group("observed"),
        )
        assert result.repair_attempted is True
        assert mock_gen.call_count == 1
        assert mock_chall.call_count == 2  # v1 + v2, never a third

    def test_v2_clean_is_accepted(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_CLEAN],
            calibration_side_effect=self._calibrate_group("observed"),
        )
        assert result.repair_succeeded is True
        assert "repaired" in result.patch

    def test_v2_retains_calibrated_defect_rejects_v2_preserves_v1(self, tmp_path):
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
            calibration_side_effect=self._calibrate_group("observed"),
        )
        assert result.repair_succeeded is False
        assert "repaired" not in result.patch
        # No v3: still exactly one repair-generation call despite rejection.
        assert mock_gen.call_count == 1

    def test_v2_introduces_new_calibrated_defect_rejects_v2_preserves_v1(self, tmp_path):
        """v2's own Challenger raises a brand-new (differently-worded)
        confirmed_defect that calibrates Observed -- must reject v2 and
        preserve v1, never generate a v3."""
        new_defect_challenger = {
            "still_vulnerable": False,
            "edge_cases": ["A separate attacker can bypass a completely different validation"],
            "potential_issues": [], "summary": "new defect introduced by v2",
        }
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, new_defect_challenger],
            calibration_side_effect=self._calibrate_group("observed"),
        )
        assert result.repair_succeeded is False
        assert "repaired" not in result.patch
        assert mock_gen.call_count == 1
        assert mock_chall.call_count == 2

    def test_v2_calibration_failure_rejects_v2_preserves_v1(self, tmp_path):
        """v1 calibration succeeds (authorizing repair), but v2's own
        calibration call fails outright -- v2 must be rejected (cannot
        verify it was cleared) and v1 preserved, never a v3."""
        calls = {"n": 0}

        def _side_effect(vulnerability_text, patch, findings, llm, code_context=""):
            calls["n"] += 1
            if calls["n"] == 1:
                return [{"original": f, "group": "observed", "reworded": f} for f in findings]
            raise RuntimeError("calibration v2 unavailable")

        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF, _REPAIR_DIFF],
            patches_app=[_APPLICABILITY_CLEAN, _APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT, _CHALLENGER_WITH_DEFECT],
            calibration_side_effect=_side_effect,
        )
        assert result.repair_succeeded is False
        assert "repaired" not in result.patch
        assert mock_gen.call_count == 1  # still exactly one repair attempt, no v3

    def test_calibrated_downgrade_not_counted_as_confirmed_defect_downstream(self, tmp_path):
        """A raw confirmed_defect finding that calibrates Hypothesis must
        not still read as a confirmed defect anywhere downstream: the raw
        classifier count is still reported as telemetry (unchanged), but
        the authoritative post-calibration finding state
        (_build_known_findings, which Trust Signals/Recommendation in
        _build_report now derive their defect_count from) must show zero
        remaining risks for it."""
        result, mock_gen, mock_chall = _capture_result(
            tmp_path,
            patches_gen=[_CLEAN_DIFF],
            patches_app=[_APPLICABILITY_CLEAN],
            patches_chall=[_CHALLENGER_WITH_DEFECT],
            calibration_side_effect=self._calibrate_group("hypothesis"),
        )
        # Raw pre-calibration telemetry is unchanged.
        assert result.original_challenger_defect_count == 1
        # The authoritative, calibration-aware representation must not
        # still show it as a confirmed defect.
        from utilities.autopatcher.pipeline import _build_known_findings, _classify_challenger
        classified = _classify_challenger(result.challenger)
        known = _build_known_findings(classified, result.finding_calibration)
        assert known["potential_remaining_risks"] == []
        assert any("bypass" in h for h in known["validation_hypotheses"])


class TestNoUnnecessaryCalibrationCall:
    """When there is no raw confirmed_defect finding to gate on, the repair
    block must not add an extra calibrate_findings() call -- calibration
    still runs at most once, at its original position and cost."""

    def test_no_calibration_call_at_all_when_challenger_fully_clean(self, tmp_path):
        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=_CLEAN_DIFF),
            mock.patch("utilities.autopatcher.pipeline.generate_patch") as mock_gen,
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value=_APPLICABILITY_CLEAN),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value=_CHALLENGER_CLEAN),
            mock.patch("utilities.autopatcher.pipeline.calibrate_findings",
                       side_effect=_calibrate_all_observed) as mock_calibrate,
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        ):
            mock_llm_cls.return_value = mock.MagicMock()
            from utilities.autopatcher.pipeline import run
            run("test vuln", api_key="", repo_root=str(tmp_path))
            mock_calibrate.assert_not_called()
            mock_gen.assert_not_called()

    def test_single_calibration_call_when_raw_defect_present_but_downgraded(self, tmp_path):
        """A raw confirmed_defect finding exists (so the early, widened
        calibration call DOES run -- it's the only one that can gate the
        repair decision), but the old, later plausible_risk/generic-only
        call must not ALSO run afterward -- exactly one calibration call
        total, not two."""
        with (
            mock.patch("utilities.autopatcher.pipeline.LLMClient") as mock_llm_cls,
            mock.patch("utilities.autopatcher.pipeline.generate_patch_raw", return_value=_CLEAN_DIFF),
            mock.patch("utilities.autopatcher.pipeline.generate_patch") as mock_gen,
            mock.patch("utilities.autopatcher.patch_applicability.check_applicability",
                       return_value=_APPLICABILITY_CLEAN),
            mock.patch("utilities.autopatcher.pipeline.review_patch", return_value="ok"),
            mock.patch("utilities.autopatcher.pipeline.challenge_patch", return_value=_CHALLENGER_WITH_DEFECT),
            mock.patch(
                "utilities.autopatcher.pipeline.calibrate_findings",
                side_effect=TestRepairGateEndToEnd._calibrate_group("hypothesis"),
            ) as mock_calibrate,
            mock.patch("utilities.autopatcher.pipeline.score_confidence", return_value="Confidence score: 0.8"),
            mock.patch("utilities.autopatcher.pipeline.LightweightImpactAnalyzer"),
            mock.patch("utilities.autopatcher.patch_hygiene.check_patch", return_value=[]),
        ):
            mock_llm_cls.return_value = mock.MagicMock()
            from utilities.autopatcher.pipeline import run
            run("test vuln", api_key="", repo_root=str(tmp_path))
            assert mock_calibrate.call_count == 1
            mock_gen.assert_not_called()
