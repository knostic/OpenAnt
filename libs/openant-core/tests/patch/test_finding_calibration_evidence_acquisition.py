"""Tests for the bounded post-Finding-Calibration evidence-acquisition loop
(pipeline._calibrate_findings_with_evidence_acquisition).

Context: Finding Calibration can identify (via `remediation_impact:
proof_required` + an optional structured "Evidence request:" field) that a
decision-relevant uncertainty could be resolved by one concrete repository
file/symbol, but previously had no mechanism to acquire it before the
uncertainty was carried, unresolved, into reconciliation. This wrapper
mirrors the bounded question -> identify -> acquire -> rerun -> decide
shape Planning/Strategy already use, reusing their own deterministic
resolution/dedup primitives -- but as a ONE-SHOT rerun (calibration #1 +
at most one evidence-informed rerun, never a loop).

All tests are repository-neutral -- no CVE-specific or urllib3-specific
fixtures. `calibrate_findings` itself is mocked throughout (no real LLM
call, no network); repository resolution uses real, disposable files under
`tmp_path`.
"""

from __future__ import annotations

from unittest import mock

import pytest

from utilities.autopatcher.pipeline import (
    _calibrate_findings_with_evidence_acquisition,
    MAX_CALIBRATION_ACQUISITION_ATTEMPTS,
    MAX_CALIBRATION_EVIDENCE_REQUESTS,
)


def _entry(remediation_impact="validation_only", evidence_request=None, original="finding text", **overrides):
    # A real, contract-consistent calibration entry: `evidence_acquirability`
    # defaults to "actionable" whenever an `evidence_request` is supplied
    # (the only combination finding_calibration.py's own consistency gate
    # ever produces alongside a non-None request) and to None otherwise --
    # callers that need a specific "not_expressible"/"conceptual_scope"/
    # "unclear" declaration pass `evidence_acquirability=...` explicitly via
    # **overrides.
    base = {
        "original": original, "group": "hypothesis", "reworded": original,
        "unresolved_dependencies": (["gap"] if remediation_impact == "proof_required" else []),
        "group_before_consistency_check": "hypothesis",
        "remediation_impact": remediation_impact,
        "evidence_acquirability": ("actionable" if evidence_request else None),
        "evidence_request": evidence_request,
    }
    base.update(overrides)
    return base


class TestNoProofRequired:
    def test_no_proof_required_findings_means_no_acquisition(self):
        calibration_1 = [_entry(), _entry()]
        with mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=calibration_1) as mock_cal:
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1", "f2"], mock.MagicMock(), code_context="ctx",
                repo_root="/tmp/whatever", investigation_context=object(),
            )
        assert mock_cal.call_count == 1
        assert result["attempted"] is True
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "no_actionable_evidence_request"
        assert result["final_calibration"] == calibration_1


class TestActionableRequestTriggersResolution:
    def test_actionable_proof_required_triggers_resolution_attempt(self, tmp_path):
        target = tmp_path / "a.py"
        target.write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        calibration_2 = [_entry(remediation_impact="validation_only")]
        with mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=[calibration_1, calibration_2],
        ) as mock_cal:
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        assert len(result["evidence_requests"]) == 1
        assert len(result["resolutions"]) == 1
        assert result["resolutions"][0]["resolved"] is True
        assert result["resolutions"][0]["resolved_file"] == "a.py"
        assert mock_cal.call_count == 2


class TestExactlyOneRerun:
    def test_resolved_and_included_evidence_triggers_exactly_one_rerun(self, tmp_path):
        target = tmp_path / "a.py"
        target.write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        calibration_2 = [_entry(remediation_impact="validation_only")]
        with mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=[calibration_1, calibration_2],
        ) as mock_cal:
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        assert mock_cal.call_count == 2
        assert result["rerun_performed"] is True
        second_call_kwargs = mock_cal.call_args_list[1].kwargs
        assert "x = 1" in second_call_kwargs["code_context"]
        assert "ctx" in second_call_kwargs["code_context"]

    def test_rerun_uses_the_same_complete_findings_list(self, tmp_path):
        """Never a subset -- the SAME findings list both calls."""
        target = tmp_path / "a.py"
        target.write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [
            _entry(remediation_impact="proof_required", evidence_request=evidence_request, original="f1"),
            _entry(remediation_impact="validation_only", original="f2"),
        ]
        calibration_2 = [_entry(original="f1"), _entry(original="f2")]
        with mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=[calibration_1, calibration_2],
        ) as mock_cal:
            _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1", "f2"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        first_findings = mock_cal.call_args_list[0].args[2]
        second_findings = mock_cal.call_args_list[1].args[2]
        assert first_findings == second_findings == ["f1", "f2"]


class TestRerunOutcomes:
    def test_rerun_returns_validation_only_terminal_calibration_reflects_it(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        calibration_2 = [_entry(remediation_impact="validation_only")]
        with mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=[calibration_1, calibration_2],
        ):
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        assert result["final_calibration"][0]["remediation_impact"] == "validation_only"

    def test_rerun_remains_proof_required_stays_blocking(self, tmp_path):
        from utilities.autopatcher.pipeline import _finding_blocks_remediation_proof

        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request, original="f1")]
        calibration_2 = [_entry(remediation_impact="proof_required", original="f1")]
        with mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=[calibration_1, calibration_2],
        ):
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        final = result["final_calibration"][0]
        assert final["remediation_impact"] == "proof_required"
        # The exact, unmodified reconciliation gate a genuinely-still-
        # proof_required calibrated finding must still trip.
        assert _finding_blocks_remediation_proof(
            {"category": "plausible_risk", "text": "f1"},
            {"unresolved_dependencies": ["gap"], "remediation_impact": "proof_required"},
        ) is True


class TestEvidenceUnavailable:
    def test_unresolvable_file_means_no_rerun_original_stands(self, tmp_path):
        evidence_request = {"request_type": "file_source", "file_hint": "does_not_exist.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        with mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=calibration_1) as mock_cal:
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        assert mock_cal.call_count == 1
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "no_evidence_resolved"
        assert result["resolutions"][0]["resolved"] is False
        assert result["resolutions"][0]["failure_reason"] == "unresolved_file"
        assert result["final_calibration"] == calibration_1


class TestMalformedRequest:
    def test_malformed_request_type_fails_closed_original_stands(self, tmp_path):
        evidence_request = {"request_type": "directory_listing", "file_hint": "src/", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        with mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=calibration_1) as mock_cal:
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        assert mock_cal.call_count == 1
        assert result["rerun_performed"] is False
        assert result["resolutions"][0]["resolved"] is False
        assert result["resolutions"][0]["failure_reason"] == "unsupported_request_type"


class TestDuplicateRequests:
    def test_duplicate_requests_across_findings_resolved_once(self, tmp_path):
        """The exact urllib3-regression shape: the same underlying concern
        raised twice (e.g. once as an edge case, once as a potential
        issue) must acquire its shared target at most once."""
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [
            _entry(remediation_impact="proof_required", evidence_request=dict(evidence_request), original="f1"),
            _entry(remediation_impact="proof_required", evidence_request=dict(evidence_request), original="f2"),
        ]
        calibration_2 = [_entry(original="f1"), _entry(original="f2")]
        import utilities.autopatcher.remediation_planner as rp
        with (
            mock.patch(
                "utilities.autopatcher.pipeline.calibrate_findings",
                side_effect=[calibration_1, calibration_2],
            ),
            mock.patch.object(
                rp, "_resolve_planning_evidence_request",
                wraps=rp._resolve_planning_evidence_request,
            ) as spy_resolve,
        ):
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1", "f2"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        assert len(result["evidence_requests"]) == 1
        assert spy_resolve.call_count == 1


class TestAlreadyPresentEvidence:
    def test_already_included_via_known_labels_skips_reacquisition(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        with mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=calibration_1) as mock_cal:
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
                known_included_evidence_labels=frozenset({"a.py"}),
            )
        assert mock_cal.call_count == 1  # no rerun
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "no_new_evidence_present"
        assert result["resolutions"][0]["resolved"] is True
        assert result["resolutions"][0]["already_present"] is True
        assert result["resolutions"][0]["included"] is None


class TestMaxTwoCalibrationCalls:
    @pytest.mark.parametrize("scenario", ["no_request", "resolved", "unresolvable", "capacity_exhausted"])
    def test_never_more_than_two_calibration_calls(self, tmp_path, scenario):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        if scenario == "no_request":
            calibration_1 = [_entry()]
        elif scenario == "unresolvable":
            er = {"request_type": "file_source", "file_hint": "missing.py", "symbol": None}
            calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=er)]
        else:
            er = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
            calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=er)]
        calibration_2 = [_entry(remediation_impact="validation_only")]

        capacity_kwargs = {}
        if scenario == "capacity_exhausted":
            capacity_kwargs["patch_capacity"] = 0  # forces required_missing on the existing context

        with mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=[calibration_1, calibration_2, calibration_1, calibration_2],
        ) as mock_cal:
            if scenario == "capacity_exhausted":
                with mock.patch(
                    "utilities.autopatcher.finding_calibration.compute_finding_calibration_capacity",
                ) as mock_cap:
                    from utilities.autopatcher.technical_capacity import SourceCapacityResult
                    mock_cap.return_value = SourceCapacityResult(
                        source_capacity_chars=0, capacity_source="conservative_fallback",
                        context_window_tokens=60000, reserved_output_tokens=4096,
                        safety_margin_tokens=2000, chars_per_token_ratio=3.0,
                        known_overhead_chars=999_999_999, capacity_is_approximate=True,
                    )
                    _calibrate_findings_with_evidence_acquisition(
                        "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                        repo_root=str(tmp_path), investigation_context=object(),
                    )
            else:
                _calibrate_findings_with_evidence_acquisition(
                    "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                    repo_root=str(tmp_path), investigation_context=object(),
                )
        assert mock_cal.call_count <= MAX_CALIBRATION_ACQUISITION_ATTEMPTS


class TestTechnicalCapacityOmission:
    def test_resolved_evidence_omitted_by_capacity_means_no_rerun(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n" * 5000, encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        with (
            mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=calibration_1) as mock_cal,
            mock.patch(
                "utilities.autopatcher.finding_calibration.compute_finding_calibration_capacity",
            ) as mock_cap,
        ):
            from utilities.autopatcher.technical_capacity import SourceCapacityResult
            # Enough room for the existing (tiny) code_context but not for
            # the large new file.
            mock_cap.return_value = SourceCapacityResult(
                source_capacity_chars=len("ctx") + 5, capacity_source="conservative_fallback",
                context_window_tokens=60000, reserved_output_tokens=4096,
                safety_margin_tokens=2000, chars_per_token_ratio=3.0,
                known_overhead_chars=0, capacity_is_approximate=True,
            )
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        assert mock_cal.call_count == 1
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "technical_capacity_exhausted"
        assert result["resolutions"][0]["resolved"] is True
        assert result["resolutions"][0]["included"] is False
        assert result["resolutions"][0]["omission_reason"] == "technical_capacity"


class TestProvenance:
    def test_provenance_distinguishes_all_four_states(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        calibration_2 = [_entry(remediation_impact="validation_only")]
        with mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=[calibration_1, calibration_2],
        ):
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        r = result["resolutions"][0]
        # requested
        assert result["evidence_requests"] == [evidence_request]
        # resolved
        assert r["resolved"] is True
        # included
        assert r["included"] is True
        # still-unresolved (terminal state) is readable from final_calibration
        assert result["final_calibration"][0]["remediation_impact"] == "validation_only"


class TestReconciliationSeesOnlyTerminalState:
    def test_run_patch_repair_and_calibration_returns_terminal_finding_calibration(self, tmp_path):
        """Integration point: Stage 6's OWN return value (`finding_
        calibration`) must already be the acquisition loop's terminal
        result -- reconciliation, which runs later in _build_report, must
        never see an intermediate calibration."""
        from utilities.autopatcher.pipeline import _run_patch_repair_and_calibration

        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request, original="A confirmed_defect-free finding.")]
        calibration_2 = [_entry(remediation_impact="validation_only", original="A confirmed_defect-free finding.")]

        challenger = {
            "edge_cases": ["A confirmed_defect-free finding."],
            "potential_issues": [],
        }
        with mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=[calibration_1, calibration_2],
        ):
            s6 = _run_patch_repair_and_calibration(
                vulnerability_text="v", llm=mock.MagicMock(), repo_root=str(tmp_path),
                code_context="ctx", challenger_context="ctx",
                patch="```diff\n--- a\n+++ b\n```", challenger=challenger,
                applicability_result={"applicable": True}, hygiene_findings=[],
                _final_repair_meta=None, _post_patch_observations=None,
                _investigated_patch="```diff\n--- a\n+++ b\n```",
                _investigation_context=object(),
            )
        assert s6["finding_calibration"] == calibration_2


class TestGenuineProofRequiredStillDowngrades:
    def test_reconciliation_unchanged_still_downgrades_verified_fixed(self):
        """No behavior change to _reconcile_verification_status_with_
        calibration itself -- a genuinely terminal proof_required finding
        must still downgrade VERIFIED_FIXED exactly as before this task."""
        from utilities.autopatcher.pipeline import _reconcile_verification_status_with_calibration

        classified_challenger = {
            "verification_status": "VERIFIED_FIXED", "still_vulnerable": False,
            "classified_edge_cases": [{"text": "residual concern", "category": "plausible_risk"}],
            "classified_potential_issues": [],
        }
        finding_calibration = [{
            "original": "residual concern", "unresolved_dependencies": ["gap"],
            "remediation_impact": "proof_required",
        }]
        result = _reconcile_verification_status_with_calibration(classified_challenger, finding_calibration)
        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"
        assert result["still_vulnerable"] is True


class TestBackwardCompatibility:
    def test_response_without_new_field_behaves_unchanged(self, tmp_path):
        """A calibration response with no 'Evidence request:' anywhere
        (every pre-existing response shape) must never trigger
        acquisition."""
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=None)]
        with mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=calibration_1) as mock_cal:
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        assert mock_cal.call_count == 1
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "no_actionable_evidence_request"


class TestReplayCompatibility:
    def test_missing_investigation_context_means_no_acquisition_even_with_real_repo_root(self, tmp_path):
        """Replay has a real repo_root but no real InvestigationContext for
        this stage -- both must be present for acquisition to be
        attempted, or a replay run could issue an LLM call its own
        original execution never made."""
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        with mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=calibration_1) as mock_cal:
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=None,
            )
        assert mock_cal.call_count == 1
        assert result["rerun_performed"] is False
        assert result["skip_reason"] == "no_repo_root"

    def test_missing_repo_root_means_no_acquisition(self):
        evidence_request = {"request_type": "file_source", "file_hint": "a.py", "symbol": None}
        calibration_1 = [_entry(remediation_impact="proof_required", evidence_request=evidence_request)]
        with mock.patch("utilities.autopatcher.pipeline.calibrate_findings", return_value=calibration_1) as mock_cal:
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", ["f1"], mock.MagicMock(), code_context="ctx",
                repo_root=None, investigation_context=object(),
            )
        assert mock_cal.call_count == 1
        assert result["skip_reason"] == "no_repo_root"


class TestEvidenceRequestCap:
    def test_more_than_max_deduplicated_requests_are_capped(self, tmp_path):
        for i in range(MAX_CALIBRATION_EVIDENCE_REQUESTS + 2):
            (tmp_path / f"f{i}.py").write_text("x = 1\n", encoding="utf-8")
        calibration_1 = [
            _entry(
                remediation_impact="proof_required",
                evidence_request={"request_type": "file_source", "file_hint": f"f{i}.py", "symbol": None},
                original=f"finding{i}",
            )
            for i in range(MAX_CALIBRATION_EVIDENCE_REQUESTS + 2)
        ]
        calibration_2 = list(calibration_1)
        with mock.patch(
            "utilities.autopatcher.pipeline.calibrate_findings",
            side_effect=[calibration_1, calibration_2],
        ):
            result = _calibrate_findings_with_evidence_acquisition(
                "vuln", "patch", [f"finding{i}" for i in range(MAX_CALIBRATION_EVIDENCE_REQUESTS + 2)],
                mock.MagicMock(), code_context="ctx",
                repo_root=str(tmp_path), investigation_context=object(),
            )
        assert len(result["evidence_requests"]) == MAX_CALIBRATION_EVIDENCE_REQUESTS


class TestAllThreeCallSitesUseTheWrapper:
    def test_all_three_calibrate_findings_call_sites_in_stage6_use_the_bounded_wrapper(self):
        """Source-shape guard: `_run_patch_repair_and_calibration`'s own
        body must never call the bare `calibrate_findings(...)` directly
        -- every one of its 3 call sites must go through
        `_calibrate_findings_with_evidence_acquisition` so the evidence
        opportunity is available consistently, not bypassed on one path."""
        import inspect
        from utilities.autopatcher.pipeline import _run_patch_repair_and_calibration

        source = inspect.getsource(_run_patch_repair_and_calibration)
        assert source.count("_calibrate_findings_with_evidence_acquisition(") == 3
        assert "= calibrate_findings(" not in source
