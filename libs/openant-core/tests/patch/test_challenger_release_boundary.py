"""Pre-regression release-boundary fixes (release audit D7, D2, D3).

D7 -- citation authority: a repository/diff citation in a structured
      Challenger response validates only against repository-derived
      evidence, never against model-authored narrative that is merely
      shown in the same context.
D2 -- `_classify_challenger` must not erase a structured (concerns-schema)
      RESIDUAL_VULNERABILITY using legacy lexical defect counts.
D3 -- the documented `- none` placeholder must not survive the
      concerns-schema path as a phantom finding.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest import mock

import pytest

from utilities.autopatcher.patch_challenger import challenge_patch


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_REPO_SECTION = (
    "#### Target definition: `m.py:process` (lines 1-6)\n"
    "```python\n"
    "def process(item, allow_external: bool = False):\n"
    "    if external(item) and not allow_external: raise AccessError()\n"
    "    perform_sensitive_operation(item)\n"
    "```\n"
)
# Model-authored narrative (e.g. a Planner/Strategy section) that quotes a
# code-looking line which does NOT exist in the repository section.
_NARRATIVE_SECTION = (
    "## Target Discovery Plan (exploratory)\n\n"
    "**Likely remediation mechanism:** the guard "
    "`if narrative_only_flag: raise AccessError()` already stops the operation.\n"
)
_NARRATIVE_QUOTING_REAL_GUARD = (
    "## Target Discovery Plan (exploratory)\n\n"
    "The guard `if external(item) and not allow_external: raise AccessError()` stops it.\n"
)


def _v2_block(*, role="primary", description="a concern", guard="present",
              guard_prov="if external(item) and not allow_external: raise AccessError()",
              default_state="condition_true_under_default",
              default_state_prov="def process(item, allow_external: bool = False):",
              effect="prevents_operation", effect_prov="raise AccessError()",
              override="false", num=1):
    return (
        f"{num}. Role: {role}\n"
        f"   Description: {description}\n"
        f"   Operation present in evidence: present\n"
        f"   Preceding guard: {guard}\n"
        f"   Guard provenance: {guard_prov}\n"
        f"   Function provenance: none\n"
        f"   Operation provenance: perform_sensitive_operation(item)\n"
        f"   Guard default state: {default_state}\n"
        f"   Guard default state provenance: {default_state_prov}\n"
        f"   Guard effect: {effect}\n"
        f"   Guard effect provenance: {effect_prov}\n"
        f"   Reentry state propagation: not_applicable\n"
        f"   Reentry provenance: none\n"
        f"   Requires explicit non-default action: {override}\n"
        f"   Override provenance: none\n"
        f"   Contract addresses override: not_applicable\n"
        f"   Scope provenance: none\n"
    )


def _v2_response(blocks, edge="- none", issues="- none"):
    return (
        "Verification status: VERIFIED_FIXED\n\n"
        f"Concerns:\n\n{blocks}\n"
        f"Edge cases:\n{edge}\n\n"
        f"Potential issues:\n{issues}\n\n"
        "Summary:\n- none\n"
    )


def _llm(response):
    llm = mock.MagicMock()
    llm.complete.return_value = response
    return llm


def _primary(result):
    return next(c for c in result["concerns"] if c["concern_role"] == "primary")


# ---------------------------------------------------------------------------
# D7 -- citation authority boundary (challenge_patch level)
# ---------------------------------------------------------------------------

class TestCitationAuthorityBoundary:
    def test_a_repository_source_citation_passes(self):
        result = challenge_patch(
            "vuln", "diff", _llm(_v2_response(_v2_block())),
            code_context=_REPO_SECTION + "\n" + _NARRATIVE_SECTION,
            provenance_context=_REPO_SECTION,
        )
        c = _primary(result)
        assert c["reachability_facts"]["preceding_guard"] == "present"
        assert c["default_execution_reachability"] == "blocked"
        assert c["consequence"] == "NON_BLOCKING"

    def test_b_citation_only_in_llm_narrative_fails(self):
        block = _v2_block(guard_prov="if narrative_only_flag: raise AccessError()")
        result = challenge_patch(
            "vuln", "diff", _llm(_v2_response(block)),
            code_context=_NARRATIVE_SECTION + "\n" + _REPO_SECTION,
            provenance_context=_REPO_SECTION,
        )
        c = _primary(result)
        assert c["reachability_facts"]["preceding_guard"] == "unresolved"
        assert c["default_execution_reachability"] == "unresolved"
        assert c["consequence"] == "UNRESOLVED"
        assert result["verification_status"] == "INSUFFICIENT_EVIDENCE"

    # Narrative that quotes the guard AND the operation together inside one
    # fenced snippet -- model-authored text can contain code fences. Guard/
    # operation ordering is block-local (patch_challenger._citation_
    # precedes_within_one_block), so a narrative-only guard quoted in prose
    # can no longer be ordered against an operation in a separate repository
    # block at all; this fixture keeps the control below about the citation
    # BOUNDARY itself, not about ordering.
    _NARRATIVE_WITH_FENCED_QUOTE = (
        "## Target Discovery Plan (exploratory)\n\n"
        "**Likely remediation mechanism:** the guard already stops the operation:\n\n"
        "```python\n"
        "if narrative_only_flag: raise AccessError()\n"
        "perform_sensitive_operation(item)\n"
        "```\n"
    )

    # The repository section WITHOUT the operation: with _REPO_SECTION the
    # repository's own occurrence of the operation (guarded by a different
    # guard than the narrative one) already fails the claim closed through
    # call-site identity (PR #763), so the control below could no longer
    # show what the boundary alone prevents.
    _REPO_SIGNATURE_ONLY = (
        "#### Target definition: `m.py:process` (lines 1-2)\n"
        "```python\n"
        "def process(item, allow_external: bool = False):\n"
        "    log(item)\n"
        "```\n"
    )

    def test_b_control_same_quote_was_accepted_without_the_boundary(self):
        """The defect being fixed: with no boundary (legacy default), the
        narrative-only quote validated and produced NON_BLOCKING."""
        block = _v2_block(guard_prov="if narrative_only_flag: raise AccessError()")
        result = challenge_patch(
            "vuln", "diff", _llm(_v2_response(block)),
            code_context=self._NARRATIVE_WITH_FENCED_QUOTE + "\n" + self._REPO_SIGNATURE_ONLY,
        )
        assert _primary(result)["consequence"] == "NON_BLOCKING"

    def test_b_control_narrative_quote_fails_with_the_boundary(self):
        block = _v2_block(guard_prov="if narrative_only_flag: raise AccessError()")
        result = challenge_patch(
            "vuln", "diff", _llm(_v2_response(block)),
            code_context=self._NARRATIVE_WITH_FENCED_QUOTE + "\n" + self._REPO_SIGNATURE_ONLY,
            provenance_context=self._REPO_SIGNATURE_ONLY,
        )
        assert _primary(result)["consequence"] == "UNRESOLVED"

    def test_b_narrative_quote_without_boundary_still_fails_against_the_repository_call_site(self):
        """Even without the boundary, the repository's own occurrence of the
        operation is preceded by a different guard than the cited one."""
        block = _v2_block(guard_prov="if narrative_only_flag: raise AccessError()")
        result = challenge_patch(
            "vuln", "diff", _llm(_v2_response(block)),
            code_context=self._NARRATIVE_WITH_FENCED_QUOTE + "\n" + _REPO_SECTION,
        )
        assert _primary(result)["consequence"] == "UNRESOLVED"

    def test_b_same_fenced_narrative_quote_fails_with_the_boundary(self):
        block = _v2_block(guard_prov="if narrative_only_flag: raise AccessError()")
        result = challenge_patch(
            "vuln", "diff", _llm(_v2_response(block)),
            code_context=self._NARRATIVE_WITH_FENCED_QUOTE + "\n" + _REPO_SECTION,
            provenance_context=_REPO_SECTION,
        )
        assert _primary(result)["reachability_facts"]["preceding_guard"] == "unresolved"
        assert _primary(result)["consequence"] == "UNRESOLVED"

    def test_c_text_in_both_narrative_and_repository_passes(self):
        result = challenge_patch(
            "vuln", "diff", _llm(_v2_response(_v2_block())),
            code_context=_REPO_SECTION + "\n" + _NARRATIVE_QUOTING_REAL_GUARD,
            provenance_context=_REPO_SECTION,
        )
        assert _primary(result)["reachability_facts"]["preceding_guard"] == "present"

    def test_g_existing_valid_citations_remain_valid_without_boundary(self):
        """`provenance_context=None` keeps the previous behavior exactly."""
        llm_a, llm_b = _llm(_v2_response(_v2_block())), _llm(_v2_response(_v2_block()))
        legacy = challenge_patch("vuln", "diff", llm_a, code_context=_REPO_SECTION)
        bounded = challenge_patch("vuln", "diff", llm_b, code_context=_REPO_SECTION,
                                  provenance_context=_REPO_SECTION)
        assert legacy["concerns"] == bounded["concerns"]
        assert legacy["verification_status"] == bounded["verification_status"] == "VERIFIED_FIXED"

    def test_model_still_sees_full_context(self):
        llm = _llm(_v2_response(_v2_block()))
        challenge_patch("vuln", "diff", llm, code_context=_REPO_SECTION + "\n" + _NARRATIVE_SECTION,
                        provenance_context=_REPO_SECTION)
        _system, user_message = llm.complete.call_args[0][:2]
        assert _NARRATIVE_SECTION in user_message

    def test_patch_remains_a_valid_citation_source(self):
        block = _v2_block(guard_prov="if blocked_by_patch: raise AccessError()")
        patch = "+    if blocked_by_patch: raise AccessError()\n+    perform_sensitive_operation(item)\n"
        result = challenge_patch(
            "vuln", patch, _llm(_v2_response(block)),
            code_context=_NARRATIVE_SECTION, provenance_context="",
        )
        assert _primary(result)["reachability_facts"]["preceding_guard"] == "present"

    def test_scope_citation_semantics_unchanged(self):
        """Scope provenance is validated against the vulnerability report,
        not the repository corpus -- unaffected by the boundary."""
        block = (
            _v2_block(override="true")
            .replace("   Override provenance: none\n",
                     "   Override provenance: def process(item, allow_external: bool = False):\n")
            .replace("   Contract addresses override: not_applicable\n",
                     "   Contract addresses override: explicitly_included\n")
            .replace("   Scope provenance: none\n", "   Scope provenance: overrides are in scope\n")
        )
        result = challenge_patch(
            "advisory text: overrides are in scope", "diff", _llm(_v2_response(block)),
            code_context=_REPO_SECTION, provenance_context=_REPO_SECTION,
        )
        c = _primary(result)
        assert c["contract_addresses_override"] == "explicitly_included"
        assert c["consequence"] == "BLOCKING"


class TestProvenanceCorpusConstruction:
    def test_labels_are_repository_derived_only(self):
        from utilities.autopatcher.patch_generator import PATCH_GENERATION_REQUIRED_LABEL
        from utilities.autopatcher.pipeline import _CHALLENGER_PROVENANCE_SECTION_LABELS
        assert _CHALLENGER_PROVENANCE_SECTION_LABELS == {
            "repository_grounding", "repository_understanding", "planner_evidence",
            PATCH_GENERATION_REQUIRED_LABEL,
        }
        for authored in ("phase_e_plan", "vulnerability_pattern_context", "remediation_plan",
                         "verified_authoritative_semantics", "remediation_strategy", "coverage_warning"):
            assert authored not in _CHALLENGER_PROVENANCE_SECTION_LABELS

    def test_only_shown_parts_are_included(self):
        from utilities.autopatcher.pipeline import _challenger_provenance_context
        shown = "A-section\n\nNARRATIVE\n\nB-section"
        corpus = _challenger_provenance_context(("A-section", "B-section", "omitted-section", ""), shown)
        assert corpus == "A-section\n\nB-section"
        assert "NARRATIVE" not in corpus

    def test_no_parts_fails_closed_to_empty(self):
        from utilities.autopatcher.pipeline import _challenger_provenance_context
        assert _challenger_provenance_context((), "anything") == ""
        assert _challenger_provenance_context(None, "anything") == ""


# ---------------------------------------------------------------------------
# D7 -- every production call path uses the boundary
# ---------------------------------------------------------------------------

def _load_repair_harness():
    path = Path(__file__).with_name("test_pipeline_repair.py")
    spec = importlib.util.spec_from_file_location("_release_boundary_repair_harness", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestProductionCallPathsUseBoundary:
    def _run(self, tmp_path):
        h = _load_repair_harness()
        _result, _gen, mock_chall = h._capture_result(
            tmp_path,
            patches_gen=[h._CLEAN_DIFF, h._REPAIR_DIFF],
            patches_app=[h._APPLICABILITY_CLEAN, h._APPLICABILITY_CLEAN],
            patches_chall=[h._CHALLENGER_WITH_DEFECT, h._CHALLENGER_CLEAN],
        )
        return mock_chall

    def test_d_main_challenger_call_passes_authoritative_corpus(self, tmp_path):
        mock_chall = self._run(tmp_path)
        _args, kwargs = mock_chall.call_args_list[0]
        shown = kwargs["code_context"]
        assert "provenance_context" in kwargs
        corpus = kwargs["provenance_context"]
        assert "## Target Discovery Plan" in shown  # precondition: narrative is shown
        assert "## Target Discovery Plan" not in corpus
        for part in corpus.split("\n\n") if corpus else []:
            assert part in shown

    def test_e_repair_rechallenge_passes_authoritative_corpus(self, tmp_path):
        mock_chall = self._run(tmp_path)
        assert mock_chall.call_count == 2
        _args, kwargs = mock_chall.call_args_list[1]
        assert "provenance_context" in kwargs
        assert "## Target Discovery Plan" in kwargs["code_context"]
        assert "## Target Discovery Plan" not in kwargs["provenance_context"]


class _Resolution:
    def __init__(self, path):
        self.artifact_path = path
        self.run_dir = path.parent


class TestReplayPathUsesBoundary:
    def _s4(self, tmp_path, **extra):
        artifact = {
            "vulnerability_text": "vuln",
            "patch": "diff",
            "code_context": _REPO_SECTION + "\n" + _NARRATIVE_SECTION,
            "challenger_context": _REPO_SECTION + "\n" + _NARRATIVE_SECTION,
            **extra,
        }
        p = tmp_path / "s4.json"
        p.write_text(json.dumps(artifact))
        return p

    def _replay(self, tmp_path, s4_path, response):
        from utilities.autopatcher import replay_engine
        from utilities.autopatcher.stage_registry import PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION
        out = tmp_path / "out"
        out.mkdir()
        result = replay_engine._run_replay_challenger(
            repo_root=None, llm=_llm(response), output_dir=out,
            resolved_dependencies={PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION: _Resolution(s4_path)},
        )
        return json.loads(Path(result.artifact_path).read_text())["challenger"]

    def test_f_replay_rejects_narrative_only_citation(self, tmp_path):
        s4 = self._s4(tmp_path, challenger_provenance_parts=[_REPO_SECTION], challenger_context=_NARRATIVE_SECTION + "\n" + _REPO_SECTION)
        block = _v2_block(guard_prov="if narrative_only_flag: raise AccessError()")
        challenger = self._replay(tmp_path, s4, _v2_response(block))
        assert _primary(challenger)["reachability_facts"]["preceding_guard"] == "unresolved"

    def test_f_replay_accepts_repository_citation(self, tmp_path):
        s4 = self._s4(tmp_path, challenger_provenance_parts=[_REPO_SECTION])
        challenger = self._replay(tmp_path, s4, _v2_response(_v2_block()))
        assert _primary(challenger)["reachability_facts"]["preceding_guard"] == "present"

    def test_f_legacy_artifact_without_parts_fails_closed(self, tmp_path):
        s4 = self._s4(tmp_path)  # predates challenger_provenance_parts
        challenger = self._replay(tmp_path, s4, _v2_response(_v2_block()))
        c = _primary(challenger)
        # empty corpus: even the operation citation cannot validate
        assert c["reachability_facts"]["operation_present_in_evidence"] == "unresolved"
        assert c["consequence"] == "UNRESOLVED"

    def test_f_repair_replay_forwards_recorded_parts(self, tmp_path):
        from utilities.autopatcher import replay_engine
        from utilities.autopatcher.stage_registry import (
            CHALLENGER, PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION,
        )
        s4 = self._s4(tmp_path, challenger_provenance_parts=[_REPO_SECTION])
        s5 = tmp_path / "s5.json"
        s5.write_text(json.dumps({"challenger": {}}))
        captured = {}

        def _capture(**kwargs):
            captured.update(kwargs)
            raise RuntimeError("stop after capture")

        with mock.patch.object(replay_engine, "_run_patch_repair_and_calibration", side_effect=_capture):
            with pytest.raises(RuntimeError, match="stop after capture"):
                replay_engine._run_replay_patch_repair_and_calibration(
                    repo_root=None, llm=None, output_dir=tmp_path,
                    resolved_dependencies={
                        PATCH_GENERATION_AND_POST_PATCH_INVESTIGATION: _Resolution(s4),
                        CHALLENGER: _Resolution(s5),
                    },
                )
        assert captured["_challenger_provenance_parts"] == [_REPO_SECTION]


# ---------------------------------------------------------------------------
# D2 -- structured RESIDUAL is not erased by legacy lexical counts
# ---------------------------------------------------------------------------

def _classified(response, *, code_context=_REPO_SECTION):
    from utilities.autopatcher.pipeline import _classify_challenger
    raw = challenge_patch("vuln", "diff", _llm(response), code_context=code_context,
                          provenance_context=code_context)
    return raw, _classify_challenger(raw)


class TestStructuredResidualSurvivesClassification:
    def test_a_v2_blocking_surfaces_residual(self):
        block = _v2_block(default_state="condition_false_under_default", effect="not_applicable",
                          effect_prov="none", override="not_applicable")
        raw, classified = _classified(_v2_response(block))
        assert raw["concerns"][0]["consequence"] == "BLOCKING"
        assert raw["verification_status"] == "RESIDUAL_VULNERABILITY"
        assert classified["confirmed_defect_count"] == 0  # the legacy count is still zero
        assert classified["verification_status"] == "RESIDUAL_VULNERABILITY"
        assert classified["still_vulnerable"] is True

    def test_b_v2_non_blocking_unchanged(self):
        raw, classified = _classified(_v2_response(_v2_block()))
        assert raw["concerns"][0]["consequence"] == "NON_BLOCKING"
        assert classified["verification_status"] == "VERIFIED_FIXED"
        assert classified["still_vulnerable"] is False

    def test_c_v2_unresolved_unchanged(self):
        block = _v2_block(guard="unresolved", guard_prov="none", default_state="not_applicable",
                          default_state_prov="none", effect="not_applicable", effect_prov="none",
                          override="not_applicable")
        raw, classified = _classified(_v2_response(block))
        assert raw["concerns"][0]["consequence"] == "UNRESOLVED"
        assert classified["verification_status"] == "INSUFFICIENT_EVIDENCE"

    def test_d_legacy_residual_downgrade_unchanged(self):
        from utilities.autopatcher.pipeline import _classify_challenger
        legacy = {
            "verification_status": "RESIDUAL_VULNERABILITY", "still_vulnerable": True,
            "edge_cases": ["Additional validation of header casing may be needed"],
            "potential_issues": [], "summary": "",
        }
        classified = _classify_challenger(legacy)
        assert classified["confirmed_defect_count"] == 0
        assert classified["verification_status"] == "INSUFFICIENT_EVIDENCE"

    def test_e_recommendation_policy_unchanged_for_structured_residual(self):
        """Same conservative decision as before (Manual Review); only the
        already-existing RESIDUAL wording becomes reachable."""
        from utilities.autopatcher.pipeline import _build_recommendation_v1, _compute_trust_signals
        block = _v2_block(default_state="condition_false_under_default", effect="not_applicable",
                          effect_prov="none", override="not_applicable")
        _raw, classified = _classified(_v2_response(block))
        signals = _compute_trust_signals([], {"applicable": True}, classified, "Good", "low")
        rec = _build_recommendation_v1(
            signals, still_vulnerable=True, defect_count=classified["confirmed_defect_count"],
            verification_status=classified["verification_status"],
        )
        assert rec["decision"] == "Manual Review Required"
        assert "affirmative evidence" in rec["why"]


# ---------------------------------------------------------------------------
# D3 -- placeholder `none` on the concerns-schema path
# ---------------------------------------------------------------------------

def _report_for(challenger, tmp_path):
    from utilities.autopatcher.pipeline import PipelineResult, _build_report
    result = PipelineResult(
        vulnerability_text="# Test vulnerability\n\nSome description.",
        patch="--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n def foo():\n-    return 1\n+    return 2\n",
        review="**Explanation:**\nok\n",
        score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
        challenger=challenger,
        impact={"impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": []},
        hygiene=[],
        applicability={"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""},
        repo_root=tmp_path,
        detected_language="python",
    )
    return _build_report(result)


class TestConcernsPathPlaceholders:
    def test_a_placeholder_none_is_not_a_finding(self):
        raw = challenge_patch("vuln", "diff", _llm(_v2_response(_v2_block())),
                              code_context=_REPO_SECTION)
        assert raw["edge_cases"] == []
        assert raw["potential_issues"] == []

    @pytest.mark.parametrize("placeholder", ["- none", "- None", "- n/a", "* none"])
    def test_a_established_placeholder_forms(self, placeholder):
        raw = challenge_patch("vuln", "diff",
                              _llm(_v2_response(_v2_block(), edge=placeholder, issues=placeholder)),
                              code_context=_REPO_SECTION)
        assert raw["edge_cases"] == [] and raw["potential_issues"] == []

    def test_b_no_verification_action_from_placeholder(self, tmp_path):
        raw = challenge_patch("vuln", "diff", _llm(_v2_response(_v2_block())),
                              code_context=_REPO_SECTION)
        report = _report_for(raw, tmp_path)
        assert "Verify none" not in report
        assert 'Based on finding: "none"' not in report

    def test_c_no_plausible_risk_count_from_placeholder(self):
        from utilities.autopatcher.pipeline import _classify_challenger
        raw = challenge_patch("vuln", "diff", _llm(_v2_response(_v2_block())),
                              code_context=_REPO_SECTION)
        classified = _classify_challenger(raw)
        assert classified["plausible_risk_count"] == 0
        assert classified["classified_edge_cases"] == []
        assert classified["classified_potential_issues"] == []

    def test_d_genuine_prose_is_kept_and_still_fails_closed(self):
        prose = "- The default set is never consulted by the direct pool path"
        raw = challenge_patch("vuln", "diff", _llm(_v2_response(_v2_block(), edge=prose)),
                              code_context=_REPO_SECTION)
        assert raw["edge_cases"] == ["The default set is never consulted by the direct pool path"]
        # substantive prose alongside Concerns: is still a structural violation
        assert raw["verification_status"] == "INSUFFICIENT_EVIDENCE"

    def test_e_legacy_response_keeps_placeholder_lines(self):
        legacy = "Verification status: VERIFIED_FIXED\n\nEdge cases:\n- none\n\nPotential issues:\n- none\n\nSummary:\n- ok\n"
        raw = challenge_patch("vuln", "diff", _llm(legacy), code_context=_REPO_SECTION)
        assert "concerns" not in raw
        assert raw["edge_cases"] == ["none"]
        assert raw["potential_issues"] == ["none"]
