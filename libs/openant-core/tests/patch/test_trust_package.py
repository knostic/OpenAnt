"""Unit tests for Trust Package V1 helpers.

Tests cover the four building blocks:
  _classify_finding        — categorises single challenger finding strings
  _classify_challenger     — classifies all findings + produces summary counts
  _compute_trust_signals   — derives the six trust signals deterministically
  _build_recommendation_v1 — produces a V1 deployment decision from signals
  _extract_security_gain   — extracts the benefit sentence from reviewer text
  _build_known_findings    — groups classified findings into the Known
                             Findings section's epistemic categories

All tests use synthetic inputs; no LLM calls are made.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


from utilities.autopatcher.pipeline import (
    _classify_finding,
    _classify_challenger,
    _compute_trust_signals,
    _build_recommendation_v1,
    _extract_security_gain,
    _build_known_findings,
    _render_known_findings,
    _check_recommendation_consistency,
)


# ---------------------------------------------------------------------------
# _classify_finding
# ---------------------------------------------------------------------------

class TestClassifyFinding:
    def test_confirmed_defect_still_vulnerable(self):
        assert _classify_finding("The patch is still vulnerable to the original attack") == "confirmed_defect"

    def test_confirmed_defect_does_not_fix(self):
        assert _classify_finding("This does not fix the underlying issue") == "confirmed_defect"

    def test_confirmed_defect_bypass(self):
        assert _classify_finding("An attacker can bypass this check via the login endpoint") == "confirmed_defect"

    def test_confirmed_defect_attack_remains(self):
        assert _classify_finding("The attack vector remains exploitable through direct API access") == "confirmed_defect"

    def test_validation_gap_cannot_verify(self):
        assert _classify_finding("Cannot verify this without running the test suite") == "validation_gap"

    def test_validation_gap_without_testing(self):
        assert _classify_finding("The fix cannot be confirmed without testing the redirect scenario") == "validation_gap"

    def test_validation_gap_needs_test(self):
        assert _classify_finding("This requires testing to validate the fix") == "validation_gap"

    def test_validation_gap_untested(self):
        assert _classify_finding("This path is untested and should be verified") == "validation_gap"

    def test_generic_tests_should(self):
        assert _classify_finding("Tests should be added to cover this scenario") == "generic"

    def test_generic_consider_adding(self):
        assert _classify_finding("Consider adding logging for audit purposes") == "generic"

    def test_plausible_risk_default(self):
        assert _classify_finding("Case-insensitive matching may not handle all header variants") == "plausible_risk"

    def test_plausible_risk_specific_path(self):
        assert _classify_finding("Custom Retry configurations that override DEFAULT may not benefit") == "plausible_risk"

    def test_empty_string_returns_generic(self):
        assert _classify_finding("") == "generic"

    def test_case_insensitive_matching(self):
        assert _classify_finding("STILL VULNERABLE to injection") == "confirmed_defect"


# ---------------------------------------------------------------------------
# Scope-marker exclusion for "does not fix/address/prevent/close"
# ---------------------------------------------------------------------------

class TestFindingClassificationScopeMarker:
    """Regression: scope-marker exclusion prevents false Confirmed Defects.

    Findings that say "does not fix/address/prevent/close" alongside a version
    reference or scope qualifier should be Plausible Risk (scope limitation).
    Those without any scope qualifier remain Confirmed Defect (primary failure).
    Explicit exploitability language overrides scope markers in both directions.
    """

    # --- Scope-limited findings → Plausible Risk ---

    def test_does_not_address_v1x_is_plausible_risk(self):
        assert _classify_finding(
            "does not address the urllib3 v1.x branch"
        ) == "plausible_risk"

    def test_does_not_prevent_users_who_override_is_plausible_risk(self):
        assert _classify_finding(
            "does not prevent users who override defaults"
        ) == "plausible_risk"

    def test_does_not_close_for_users_running_version_is_plausible_risk(self):
        assert _classify_finding(
            "does not close the attack vector for users running 1.26.x"
        ) == "plausible_risk"

    def test_does_not_fix_older_versions_is_plausible_risk(self):
        assert _classify_finding(
            "does not fix the issue for older versions of the library"
        ) == "plausible_risk"

    def test_does_not_prevent_when_configured_is_plausible_risk(self):
        assert _classify_finding(
            "does not prevent the attack when configured with custom retry settings"
        ) == "plausible_risk"

    def test_does_not_address_unless_is_plausible_risk(self):
        assert _classify_finding(
            "does not address this unless users explicitly opt in to the new behaviour"
        ) == "plausible_risk"

    def test_does_not_fix_separate_fix_needed_is_plausible_risk(self):
        assert _classify_finding(
            "does not fix the v1 branch; a separate fix would be required"
        ) == "plausible_risk"

    def test_does_not_close_legacy_branch_is_plausible_risk(self):
        assert _classify_finding(
            "does not close the vulnerability on the legacy branch"
        ) == "plausible_risk"

    def test_does_not_prevent_only_when_is_plausible_risk(self):
        assert _classify_finding(
            "does not prevent exploitation only when the application runs in debug mode"
        ) == "plausible_risk"

    # --- Primary-failure findings → Confirmed Defect ---

    def test_does_not_fix_sql_injection_is_confirmed_defect(self):
        assert _classify_finding(
            "does not fix the SQL injection vulnerability in execute_query()"
        ) == "confirmed_defect"

    def test_does_not_prevent_exploitation_is_confirmed_defect(self):
        assert _classify_finding(
            "does not prevent exploitation through the original endpoint"
        ) == "confirmed_defect"

    def test_does_not_address_attack_at_line_is_confirmed_defect(self):
        assert _classify_finding(
            "does not address the attack at line 47 in the vulnerable function"
        ) == "confirmed_defect"

    def test_does_not_close_path_traversal_is_confirmed_defect(self):
        assert _classify_finding(
            "does not close the path traversal vulnerability"
        ) == "confirmed_defect"

    def test_does_not_fix_underlying_issue_is_confirmed_defect(self):
        assert _classify_finding(
            "does not fix the underlying race condition"
        ) == "confirmed_defect"

    # --- Explicit exploitability overrides scope markers ---

    def test_still_vulnerable_with_version_still_confirmed_defect(self):
        assert _classify_finding(
            "still vulnerable in v1.x and v2.x contexts"
        ) == "confirmed_defect"

    def test_still_vulnerable_plain_confirmed_defect(self):
        assert _classify_finding("still vulnerable to the original attack") == "confirmed_defect"

    def test_validation_gap_unaffected_by_scope_markers(self):
        assert _classify_finding("cannot verify without testing") == "validation_gap"


# ---------------------------------------------------------------------------
# Narrowed bypass pattern: active exploit vs architectural observation
# ---------------------------------------------------------------------------

class TestBypassClassification:
    """Regression tests for the narrowed bypass pattern.

    Bare 'bypass' (architectural observation, speculation) → plausible_risk.
    'can bypass' / 'can be bypassed' / 'allows bypass' (active exploit) → confirmed_defect.
    """

    # Previously false positives — should now be Plausible Risk

    def test_architectural_bypass_is_plausible_risk(self):
        assert _classify_finding(
            "Cookies set via other mechanisms (e.g. adapters or poolmanagers) bypass this entirely"
        ) == "plausible_risk"

    def test_may_bypass_conditional_is_plausible_risk(self):
        assert _classify_finding(
            "headers like `cookie`, `COOKIE`, or `CookIe` may bypass the frozenset check "
            "if header comparison isn't case-insensitive"
        ) == "plausible_risk"

    def test_might_bypass_is_plausible_risk(self):
        assert _classify_finding(
            "URL-encoded variants might bypass the header comparison in some configurations"
        ) == "plausible_risk"

    def test_plain_bypass_verb_is_plausible_risk(self):
        assert _classify_finding(
            "Requests using connection-level cookies bypass this stripping logic"
        ) == "plausible_risk"

    # Active exploit framing — should remain Confirmed Defect

    def test_can_bypass_is_confirmed_defect(self):
        assert _classify_finding(
            "An attacker can bypass this check via the login endpoint"
        ) == "confirmed_defect"

    def test_can_be_bypassed_is_confirmed_defect(self):
        assert _classify_finding(
            "The vulnerability can be bypassed by sending a crafted request"
        ) == "confirmed_defect"

    def test_could_bypass_is_confirmed_defect(self):
        assert _classify_finding(
            "An attacker could bypass the authentication with a malformed token"
        ) == "confirmed_defect"

    def test_allows_bypass_is_confirmed_defect(self):
        assert _classify_finding(
            "This flaw allows bypass of the session validation"
        ) == "confirmed_defect"

    def test_allows_bypassing_is_confirmed_defect(self):
        assert _classify_finding(
            "The missing check allows bypassing the access control"
        ) == "confirmed_defect"

    # Other explicit defect patterns unaffected by this change

    def test_still_vulnerable_unaffected(self):
        assert _classify_finding(
            "The patch is still vulnerable to the original attack"
        ) == "confirmed_defect"

    def test_attack_vector_remains_unaffected(self):
        assert _classify_finding(
            "The attack vector remains open via the original endpoint"
        ) == "confirmed_defect"

    def test_remains_exploitable_unaffected(self):
        assert _classify_finding(
            "The injection point remains exploitable after this change"
        ) == "confirmed_defect"


# ---------------------------------------------------------------------------
# _classify_challenger
# ---------------------------------------------------------------------------

class TestClassifyChallenger:
    def _make(self, still_vulnerable=False, edge_cases=None, potential_issues=None):
        return {
            "still_vulnerable": still_vulnerable,
            "edge_cases": edge_cases or [],
            "potential_issues": potential_issues or [],
            "summary": "Test summary",
        }

    def test_empty_challenger_zero_counts(self):
        result = _classify_challenger(self._make())
        assert result["confirmed_defect_count"] == 0
        assert result["plausible_risk_count"] == 0
        assert result["validation_gap_count"] == 0

    def test_confirmed_defect_increments_count(self):
        result = _classify_challenger(self._make(
            edge_cases=["attack vector remains exploitable"]
        ))
        assert result["confirmed_defect_count"] == 1
        assert result["plausible_risk_count"] == 0

    def test_validation_gap_increments_count(self):
        result = _classify_challenger(self._make(
            potential_issues=["cannot verify without running tests"]
        ))
        assert result["validation_gap_count"] == 1
        assert result["confirmed_defect_count"] == 0

    def test_mixed_findings_counted_independently(self):
        result = _classify_challenger(self._make(
            edge_cases=["still vulnerable via header", "cannot verify without testing"],
            potential_issues=["case mismatch may occur"],
        ))
        assert result["confirmed_defect_count"] == 1
        assert result["validation_gap_count"] == 1
        assert result["plausible_risk_count"] == 1

    def test_original_fields_preserved(self):
        challenger = self._make(still_vulnerable=True)
        result = _classify_challenger(challenger)
        assert result["still_vulnerable"] is True
        assert result["summary"] == "Test summary"

    def test_classified_lists_have_text_and_category(self):
        result = _classify_challenger(self._make(
            edge_cases=["cannot verify without running tests"]
        ))
        items = result["classified_edge_cases"]
        assert len(items) == 1
        assert "text" in items[0] and "category" in items[0]
        assert items[0]["category"] == "validation_gap"

    def test_none_challenger_returns_empty_counts(self):
        result = _classify_challenger(None)
        assert result.get("confirmed_defect_count", 0) == 0


# ---------------------------------------------------------------------------
# _compute_trust_signals
# ---------------------------------------------------------------------------

def _clean_applicability():
    return {"applicable": True, "skipped": False, "skipped_reason": None, "error": None, "stderr": ""}

def _skip_applicability():
    return {"applicable": None, "skipped": True, "skipped_reason": "no .git directory", "error": None, "stderr": ""}

def _fail_applicability(stderr="error: patch does not apply"):
    return {"applicable": False, "skipped": False, "skipped_reason": None, "error": None, "stderr": stderr}

def _classified(still_vulnerable=False, defects=0, risks=0, gaps=0):
    c = {
        "still_vulnerable": still_vulnerable,
        "confirmed_defect_count": defects,
        "plausible_risk_count": risks,
        "validation_gap_count": gaps,
        "classified_edge_cases": [],
        "classified_potential_issues": [],
    }
    # Populate classified lists to match counts
    for _ in range(defects):
        c["classified_edge_cases"].append({"text": "still vulnerable", "category": "confirmed_defect"})
    for _ in range(risks):
        c["classified_edge_cases"].append({"text": "plausible edge case", "category": "plausible_risk"})
    for _ in range(gaps):
        c["classified_potential_issues"].append({"text": "cannot verify without tests", "category": "validation_gap"})
    return c


class TestComputeTrustSignals:

    # Patch Integrity
    def test_integrity_clean_when_no_issues(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "None", "low")
        assert s["patch_integrity"]["value"] == "Clean"

    def test_integrity_does_not_apply(self):
        s = _compute_trust_signals([], _fail_applicability(), _classified(), "None", "low")
        assert s["patch_integrity"]["value"] == "Does Not Apply"

    def test_integrity_not_verified_when_skipped(self):
        s = _compute_trust_signals([], _skip_applicability(), _classified(), "None", "low")
        assert s["patch_integrity"]["value"] == "Not Verified"

    def test_integrity_critical_when_high_hygiene(self):
        hygiene = [{"severity": "HIGH", "check": "empty_hunk", "detail": "Empty hunk"}]
        s = _compute_trust_signals(hygiene, _clean_applicability(), _classified(), "None", "low")
        assert s["patch_integrity"]["value"] == "Critical Issues"

    def test_integrity_minor_when_medium_hygiene_only(self):
        hygiene = [{"severity": "MEDIUM", "check": "unused_import", "detail": "Unused import"}]
        s = _compute_trust_signals(hygiene, _clean_applicability(), _classified(), "None", "low")
        assert s["patch_integrity"]["value"] == "Minor Issues"

    # Security Improvement
    def test_improvement_none_when_does_not_apply(self):
        s = _compute_trust_signals([], _fail_applicability(), _classified(), "None", "low")
        assert s["security_improvement"]["value"] == "None"

    def test_improvement_unknown_when_skipped(self):
        s = _compute_trust_signals([], _skip_applicability(), _classified(), "None", "low")
        assert s["security_improvement"]["value"] == "Unknown"

    def test_improvement_low_when_high_hygiene(self):
        hygiene = [{"severity": "HIGH", "check": "empty_hunk", "detail": "Empty hunk"}]
        s = _compute_trust_signals(hygiene, _clean_applicability(), _classified(), "None", "low")
        assert s["security_improvement"]["value"] == "Low"

    def test_improvement_low_when_confirmed_defect(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(still_vulnerable=True, defects=1), "None", "low")
        assert s["security_improvement"]["value"] == "Low"

    def test_improvement_high_when_not_still_vulnerable(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(still_vulnerable=False), "None", "low")
        assert s["security_improvement"]["value"] == "High"

    def test_improvement_high_when_only_validation_gaps(self):
        # still_vulnerable=True but only gaps (no confirmed defects, no plausible risks)
        s = _compute_trust_signals([], _clean_applicability(), _classified(still_vulnerable=True, gaps=2), "None", "low")
        assert s["security_improvement"]["value"] == "High"

    def test_improvement_medium_when_plausible_risks_present(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(still_vulnerable=True, risks=1), "None", "low")
        assert s["security_improvement"]["value"] == "Medium"

    # Remediation Alignment
    def test_alignment_misaligned_when_confirmed_defect(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(still_vulnerable=True, defects=1), "None", "low")
        assert s["remediation_alignment"]["value"] == "Misaligned"

    def test_alignment_aligned_when_not_still_vulnerable(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(still_vulnerable=False), "None", "low")
        assert s["remediation_alignment"]["value"] == "Aligned"

    def test_alignment_likely_aligned_when_only_gaps(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(still_vulnerable=True, gaps=2), "None", "low")
        assert s["remediation_alignment"]["value"] == "Likely Aligned"

    def test_alignment_partial_when_plausible_risks(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(still_vulnerable=True, risks=1), "None", "low")
        assert s["remediation_alignment"]["value"] == "Partial"

    # Coverage Confidence
    def test_coverage_high_when_no_findings(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "None", "low")
        assert s["coverage_confidence"]["value"] == "High"

    def test_coverage_medium_when_gaps(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(gaps=2), "None", "low")
        assert s["coverage_confidence"]["value"] == "Medium"

    def test_coverage_medium_when_plausible_risks(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(risks=1), "None", "low")
        assert s["coverage_confidence"]["value"] == "Medium"

    def test_coverage_low_when_confirmed_defect(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(defects=1), "None", "low")
        assert s["coverage_confidence"]["value"] == "Low"

    # Test Availability
    def test_test_availability_tests_available_for_good(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "Good", "low")
        assert s["test_availability"]["value"] == "Tests Available"

    def test_test_availability_tests_available_for_some(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "Some", "low")
        assert s["test_availability"]["value"] == "Tests Available"

    def test_test_availability_no_tests_for_none(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "None", "low")
        assert s["test_availability"]["value"] == "No Tests Found"

    # Deployment Safety
    def test_safety_low_risk_for_low_impact(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "None", "low")
        assert s["deployment_safety"]["value"] == "Low Risk"

    def test_safety_medium_risk_for_medium_impact(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "None", "medium")
        assert s["deployment_safety"]["value"] == "Medium Risk"

    def test_safety_high_risk_for_high_impact(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "None", "high")
        assert s["deployment_safety"]["value"] == "High Risk"

    def test_safety_high_risk_for_high_hygiene(self):
        hygiene = [{"severity": "HIGH", "check": "empty_hunk", "detail": "Empty hunk"}]
        s = _compute_trust_signals(hygiene, _clean_applicability(), _classified(), "None", "low")
        assert s["deployment_safety"]["value"] == "High Risk"

    # Composite: urllib3-representative inputs
    def test_urllib3_representative_signals(self):
        """All six signals for a well-grounded correct urllib3-style patch."""
        classified = _classified(still_vulnerable=True, risks=1, gaps=1)
        s = _compute_trust_signals([], _clean_applicability(), classified, "None", "low")
        assert s["patch_integrity"]["value"] == "Clean"
        assert s["security_improvement"]["value"] == "Medium"
        assert s["remediation_alignment"]["value"] == "Partial"
        assert s["coverage_confidence"]["value"] == "Medium"
        assert s["test_availability"]["value"] == "No Tests Found"
        assert s["deployment_safety"]["value"] == "Low Risk"

    # Labels contain icons
    def test_labels_contain_icon_for_clean(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "None", "low")
        assert "✓" in s["patch_integrity"]["label"]

    def test_labels_contain_icon_for_does_not_apply(self):
        s = _compute_trust_signals([], _fail_applicability(), _classified(), "None", "low")
        assert "✗" in s["patch_integrity"]["label"]

    # ---- Language guardrail: "Not Applicable" / "not_applicable" must not
    # collapse into the same reassuring labels as a genuine clean finding. ----

    def test_test_availability_not_applicable_is_not_verified_not_no_tests_found(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "Not Applicable", "low")
        assert s["test_availability"]["value"] == "Not Verified"
        assert s["test_availability"]["value"] != "No Tests Found"
        assert s["test_availability"]["value"] != "Tests Available"

    def test_deployment_safety_not_applicable_is_not_verified_not_low_risk(self):
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "None", "not_applicable")
        assert s["deployment_safety"]["value"] == "Not Verified"
        assert s["deployment_safety"]["value"] != "Low Risk"

    def test_non_python_repo_signals_never_read_as_clean(self):
        # Simulates the actual values a non-Python (e.g. curl/C) run produces:
        # testing_rating="Not Applicable" from score_test_support, and
        # impact_level="not_applicable" from LightweightImpactAnalyzer.
        s = _compute_trust_signals([], _clean_applicability(), _classified(), "Not Applicable", "not_applicable")
        assert s["test_availability"]["value"] not in ("Tests Available", "No Tests Found")
        assert s["deployment_safety"]["value"] not in ("Low Risk", "Medium Risk", "High Risk")
        assert s["test_availability"]["value"] == "Not Verified"
        assert s["deployment_safety"]["value"] == "Not Verified"


# ---------------------------------------------------------------------------
# _build_recommendation_v1
# ---------------------------------------------------------------------------

def _signals_for(integrity="Clean", improvement="High", alignment="Aligned", safety="Low Risk"):
    return {
        "patch_integrity":       {"value": integrity, "label": integrity, "notes": ""},
        "security_improvement":  {"value": improvement, "label": improvement, "notes": ""},
        "remediation_alignment": {"value": alignment, "label": alignment, "notes": ""},
        "coverage_confidence":   {"value": "High", "label": "High", "notes": ""},
        "test_availability":     {"value": "No Tests Found", "label": "No Tests Found", "notes": ""},
        "deployment_safety":     {"value": safety, "label": safety, "notes": ""},
    }


# ---------------------------------------------------------------------------
# Trust Signals v2 — question-style rendering (display only)
# ---------------------------------------------------------------------------

def _signals_full(**overrides):
    """All six keys with a neutral 'good' baseline, so tests only need to
    override the one signal they're checking."""
    base = {
        "patch_integrity":       {"value": "Clean", "label": "Clean", "notes": "Applies cleanly · no hygiene issues"},
        "security_improvement":  {"value": "High", "label": "High", "notes": "Adversarial review found no remaining exploit path"},
        "remediation_alignment": {"value": "Aligned", "label": "Aligned", "notes": "Adversarial review confirms fix approach"},
        "coverage_confidence":   {"value": "High", "label": "High", "notes": "No gaps identified by adversarial analysis"},
        "test_availability":     {"value": "Tests Available", "label": "Tests Available", "notes": "Good — test files cover this module"},
        "deployment_safety":     {"value": "Low Risk", "label": "Low Risk", "notes": "Localized change · low regression risk"},
    }
    base.update(overrides)
    return base


class TestTrustSignalsV2Table:
    """Rendering-only tests for the redesigned Trust Signals table. None of
    these touch _compute_trust_signals or _build_recommendation_v1."""

    def test_heading_unchanged(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full())
        assert "## Trust Signals\n" in table

    def test_question_rows_present(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full())
        for question in [
            "Does the patch apply?",
            "Does it address the vulnerability?",
            "Are there unresolved concerns?",
            "Do relevant tests already exist?",
            "Is deployment risk low?",
        ]:
            assert question in table

    def test_security_improvement_not_displayed_as_a_row(self):
        """Requirement 3: overlapping aggregate signals must not appear as
        peer rows. security_improvement must not surface anywhere in the
        rendered table, even though it's still computed and still read by
        _build_recommendation_v1 elsewhere."""
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full())
        assert "Security Improvement" not in table
        assert "security_improvement" not in table

    def test_old_icon_vocabulary_does_not_leak_through(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full())
        for old_icon in ["✓", "✗", "◑", "○"]:
            assert old_icon not in table

    def test_patch_integrity_status_mapping(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        expected = {
            "Clean": "✅ Good",
            "Minor Issues": "⚠️ Needs review",
            "Critical Issues": "❌ Blocked",
            "Does Not Apply": "❌ Blocked",
            "Not Verified": "? Not verified",
        }
        for value, status in expected.items():
            table = _render_trust_signals_table(_signals_full(
                patch_integrity={"value": value, "label": value, "notes": ""}
            ))
            row = [l for l in table.splitlines() if l.startswith("| Does the patch apply?")][0]
            assert status in row, f"{value} -> expected {status!r} in row: {row!r}"

    def test_remediation_alignment_status_mapping(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        expected = {
            "Aligned": "✅ Good",
            "Likely Aligned": "⚠️ Needs review",
            "Partial": "⚠️ Needs review",
            "Misaligned": "❌ Blocked",
        }
        for value, status in expected.items():
            table = _render_trust_signals_table(_signals_full(
                remediation_alignment={"value": value, "label": value, "notes": ""}
            ))
            row = [l for l in table.splitlines() if l.startswith("| Does it address")][0]
            assert status in row, f"{value} -> expected {status!r} in row: {row!r}"

    def test_coverage_confidence_status_mapping(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        expected = {"High": "✅ Good", "Medium": "⚠️ Needs review", "Low": "❌ Blocked"}
        for value, status in expected.items():
            table = _render_trust_signals_table(_signals_full(
                coverage_confidence={"value": value, "label": value, "notes": ""}
            ))
            row = [l for l in table.splitlines() if l.startswith("| Are there unresolved")][0]
            assert status in row, f"{value} -> expected {status!r} in row: {row!r}"

    def test_test_availability_status_mapping(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        expected = {
            "Tests Available": "✅ Good",
            "No Tests Found": "⚠️ Needs review",
            "Not Verified": "? Not verified",
        }
        for value, status in expected.items():
            table = _render_trust_signals_table(_signals_full(
                test_availability={"value": value, "label": value, "notes": ""}
            ))
            row = [l for l in table.splitlines() if l.startswith("| Do relevant tests already exist?")][0]
            assert status in row, f"{value} -> expected {status!r} in row: {row!r}"

    def test_deployment_safety_status_mapping(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        expected = {
            "Low Risk": "✅ Good",
            "Medium Risk": "⚠️ Needs review",
            "High Risk": "❌ Blocked",
            "Not Verified": "? Not verified",
        }
        for value, status in expected.items():
            table = _render_trust_signals_table(_signals_full(
                deployment_safety={"value": value, "label": value, "notes": ""}
            ))
            row = [l for l in table.splitlines() if l.startswith("| Is deployment risk low?")][0]
            assert status in row, f"{value} -> expected {status!r} in row: {row!r}"

    def test_coverage_medium_note_points_to_review_results_section(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full(
            coverage_confidence={
                "value": "Medium", "label": "Medium",
                "notes": "12 review finding(s) · no deterministic blocker identified",
            }
        ))
        assert "see Review Results section below" in table
        assert "see analysis below" not in table

    def test_notes_text_otherwise_preserved(self):
        """Requirement 5: the underlying computed notes text is not altered
        beyond the one dangling-reference substitution."""
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full())
        assert "Applies cleanly · no hygiene issues" in table
        assert "Adversarial review confirms fix approach" in table
        assert "No gaps identified by adversarial analysis" in table
        assert "Good — test files cover this module" in table
        assert "Localized change · low regression risk" in table

    def test_good_rows_get_no_forward_pointer(self):
        """A row that's already ✅ Good has nothing to send the reader to —
        except the testing row, which always carries its Existing-Test-
        Coverage-vs-Missing-Behavioral-Validation bridge regardless of
        status (see test_testing_row_bridge_present_regardless_of_status)."""
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full())
        rows = [l for l in table.splitlines() if l.startswith("| ") and "Do relevant tests" not in l]
        for row in rows:
            assert "see" not in row.lower(), f"Unexpected forward pointer in a good row: {row!r}"

    def test_testing_row_bridge_present_regardless_of_status(self):
        """The Existing Test Coverage vs Missing Behavioral Validation bridge
        must appear whether or not test coverage is good — a "✅ Good" status
        here must never look like it also answers whether the new behavior
        itself is validated."""
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full())
        row = [l for l in table.splitlines() if l.startswith("| Do relevant tests already exist?")][0]
        assert "Review Results" in row
        # Points at Review Results as a whole, not a specific subsection —
        # verified against a real challenger run that "no test validates X"
        # findings don't reliably classify as validation_gap (they can land
        # in Behavior Notes instead), so naming one subsection here would
        # risk pointing at an empty section.
        assert "Validation Gaps" not in row

    def test_non_good_patch_integrity_points_to_patch_applicability(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full(
            patch_integrity={"value": "Does Not Apply", "label": "Does Not Apply", "notes": "rejected by git apply"}
        ))
        assert "see Patch Applicability section below" in table

    def test_non_good_test_availability_points_to_test_support(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full(
            test_availability={"value": "No Tests Found", "label": "No Tests Found", "notes": "No test files cover this module"}
        ))
        assert "see Test Support section below" in table

    def test_non_good_deployment_safety_points_to_impact_surface(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(_signals_full(
            deployment_safety={"value": "High Risk", "label": "High Risk", "notes": "HIGH impact surface"}
        ))
        assert "see Impact Surface section below" in table

    def test_non_good_remediation_alignment_points_to_review_results_when_rendered(self):
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(
            _signals_full(remediation_alignment={"value": "Partial", "label": "Partial", "notes": "still_vulnerable flag set"}),
            known_findings_rendered=True,
        )
        assert "see Review Results section below" in table

    def test_remediation_alignment_pointer_suppressed_when_review_results_empty(self):
        """Edge case: remediation_alignment can be non-good ("Likely Aligned")
        while no relevant Review Results category is populated. The pointer
        must not be shown in that case — never reference a section that
        won't exist. (The testing row's own Review Results bridge is
        independent of this gate and is checked separately.)"""
        from utilities.autopatcher.pipeline import _render_trust_signals_table
        table = _render_trust_signals_table(
            _signals_full(remediation_alignment={
                "value": "Likely Aligned", "label": "Likely Aligned",
                "notes": "Correct mechanism · runtime verification pending",
            }),
            known_findings_rendered=False,
        )
        row = [l for l in table.splitlines() if l.startswith("| Does it address the vulnerability?")][0]
        assert "see Review Results" not in row


class TestRecommendationV1:
    def test_do_not_apply_for_does_not_apply_integrity(self):
        rec = _build_recommendation_v1(_signals_for(integrity="Does Not Apply"))
        assert rec["decision"] == "Do Not Apply"

    def test_do_not_apply_for_critical_issues(self):
        rec = _build_recommendation_v1(_signals_for(integrity="Critical Issues"))
        assert rec["decision"] == "Do Not Apply"

    def test_misaligned_alone_is_manual_review_not_do_not_apply(self):
        """Recommendation Policy v2: alignment=Misaligned is heuristic-only evidence
        (challenger-derived confirmed_defect_count) and must not hard-block by itself."""
        rec = _build_recommendation_v1(_signals_for(alignment="Misaligned"))
        assert rec["decision"] == "Manual Review Required"
        # Reason must not state the exploit as a confirmed fact.
        assert "confirmed exploit path" not in rec["reason"].lower()

    def test_deploy_after_validation_high_improvement_low_risk(self):
        rec = _build_recommendation_v1(_signals_for(improvement="High", safety="Low Risk"))
        assert rec["decision"] == "Deploy After Validation"

    def test_deploy_after_validation_medium_improvement_low_risk(self):
        rec = _build_recommendation_v1(_signals_for(improvement="Medium", safety="Low Risk"))
        assert rec["decision"] == "Deploy After Validation"

    def test_deploy_after_validation_medium_improvement_medium_risk(self):
        rec = _build_recommendation_v1(_signals_for(improvement="Medium", safety="Medium Risk"))
        assert rec["decision"] == "Deploy After Validation"

    def test_deploy_with_caution_low_improvement_low_risk(self):
        rec = _build_recommendation_v1(_signals_for(improvement="Low", safety="Low Risk"))
        assert rec["decision"] == "Deploy With Caution"

    def test_manual_review_required_high_risk(self):
        rec = _build_recommendation_v1(_signals_for(improvement="Low", safety="High Risk"))
        assert rec["decision"] == "Manual Review Required"

    def test_recommendation_has_reason(self):
        rec = _build_recommendation_v1(_signals_for())
        assert len(rec["reason"]) > 20

    def test_urllib3_representative_deploy_after_validation(self):
        """A well-grounded correct patch with medium coverage → Deploy After Validation."""
        classified = _classified(still_vulnerable=True, risks=1, gaps=1)
        signals = _compute_trust_signals([], _clean_applicability(), classified, "None", "low")
        rec = _build_recommendation_v1(signals)
        assert rec["decision"] == "Deploy After Validation"


# ---------------------------------------------------------------------------
# Evaluation case regressions — still_vulnerable guard
# ---------------------------------------------------------------------------

class TestRecommendationV1EvaluationCases:
    """Phase A regression suite for the still_vulnerable hard-block guard.

    Each test represents the definitive signal state observed in the evaluation
    run for that case and asserts the expected recommendation before and after
    the guard was introduced.  Tests named *_unchanged confirm no regression.
    """

    # --- GitPython: the bug case ---

    def test_still_vulnerable_no_defects_produces_manual_review(self):
        """still_vulnerable=True with no confirmed defects → Manual Review Required.

        Signals: integrity=Clean, improvement=Medium, alignment=Partial,
        safety=Low Risk, still_vulnerable=True, defect_count=0.
        The LLM binary verdict alone is insufficient for a hard-block;
        the escalation tier asks a human to review the plausible risks.
        """
        signals = _signals_for(
            integrity="Clean",
            improvement="Medium",
            alignment="Partial",
            safety="Low Risk",
        )
        rec = _build_recommendation_v1(signals, still_vulnerable=True, defect_count=0)
        assert rec["decision"] == "Manual Review Required"

    def test_gitpython_reason_names_challenger(self):
        """Escalation reason must mention the challenger, not applicability."""
        signals = _signals_for(integrity="Clean", improvement="Medium", alignment="Partial")
        rec = _build_recommendation_v1(signals, still_vulnerable=True, defect_count=0)
        assert "challenger" in rec["reason"].lower() or "review" in rec["reason"].lower()

    def test_gitpython_before_guard_would_have_passed(self):
        """Confirm the pre-fix path: same signals without still_vulnerable → Deploy After Validation."""
        signals = _signals_for(
            integrity="Clean",
            improvement="Medium",
            alignment="Partial",
            safety="Low Risk",
        )
        rec = _build_recommendation_v1(signals, still_vulnerable=False)
        assert rec["decision"] == "Deploy After Validation"

    # --- urllib3: must not regress ---

    def test_urllib3_unchanged(self):
        """urllib3: still_vulnerable=False, improvement=High → Deploy After Validation unchanged."""
        signals = _signals_for(
            integrity="Clean",
            improvement="High",
            alignment="Aligned",
            safety="Low Risk",
        )
        rec = _build_recommendation_v1(signals, still_vulnerable=False)
        assert rec["decision"] == "Deploy After Validation"

    # --- pip: must not regress ---

    def test_pip_unchanged(self):
        """pip: still_vulnerable=False, improvement=High → Deploy After Validation unchanged."""
        signals = _signals_for(
            integrity="Clean",
            improvement="High",
            alignment="Aligned",
            safety="Medium Risk",
        )
        rec = _build_recommendation_v1(signals, still_vulnerable=False)
        assert rec["decision"] == "Deploy After Validation"

    # --- minimist: must not regress ---

    def test_minimist_unchanged(self):
        """minimist v3: still_vulnerable=False, improvement=High → Deploy After Validation unchanged."""
        signals = _signals_for(
            integrity="Clean",
            improvement="High",
            alignment="Aligned",
            safety="Low Risk",
        )
        rec = _build_recommendation_v1(signals, still_vulnerable=False)
        assert rec["decision"] == "Deploy After Validation"

    # --- pygeoapi: integrity check takes priority over still_vulnerable ---

    def test_pygeoapi_integrity_fires_before_still_vulnerable(self):
        """pygeoapi: Does Not Apply integrity fires before still_vulnerable guard."""
        signals = _signals_for(
            integrity="Does Not Apply",
            improvement="None",
            alignment="Partial",
            safety="Low Risk",
        )
        rec = _build_recommendation_v1(signals, still_vulnerable=True)
        assert rec["decision"] == "Do Not Apply"
        assert "does not apply" in rec["reason"].lower() or "critical" in rec["reason"].lower()

    def test_pygeoapi_do_not_apply_without_still_vulnerable(self):
        """pygeoapi: Do Not Apply fires on integrity alone when still_vulnerable=False."""
        signals = _signals_for(integrity="Does Not Apply", improvement="None", alignment="Partial")
        rec = _build_recommendation_v1(signals, still_vulnerable=False)
        assert rec["decision"] == "Do Not Apply"

    # --- Guard ordering ---

    def test_still_vulnerable_does_not_fire_when_integrity_fails(self):
        """Reason text should reflect integrity failure, not still_vulnerable, when both are true."""
        signals = _signals_for(integrity="Does Not Apply", improvement="None", alignment="Partial")
        rec_integrity = _build_recommendation_v1(signals, still_vulnerable=False)
        rec_both = _build_recommendation_v1(signals, still_vulnerable=True)
        assert rec_integrity["decision"] == rec_both["decision"] == "Do Not Apply"
        assert rec_integrity["reason"] == rec_both["reason"]

    def test_still_vulnerable_no_defects_escalates_regardless_of_improvement(self):
        """still_vulnerable=True with defect_count=0 escalates even when other signals are clean."""
        signals = _signals_for(
            integrity="Clean",
            improvement="High",
            alignment="Aligned",
            safety="Low Risk",
        )
        rec = _build_recommendation_v1(signals, still_vulnerable=True, defect_count=0)
        assert rec["decision"] == "Manual Review Required"


# ---------------------------------------------------------------------------
# _extract_security_gain
# ---------------------------------------------------------------------------

class TestExtractSecurityGain:
    def test_extracts_sentence_with_fix_verb(self):
        explanation = "The vulnerability exists because the header is not stripped. The patch fixes this by adding Cookie to the removal list."
        gain = _extract_security_gain(explanation)
        assert "patch" in gain.lower() or "fix" in gain.lower()
        assert len(gain) >= 40

    def test_extracts_sentence_with_prevent_verb(self):
        explanation = "Sensitive tokens were logged. This patch prevents token values from appearing in log output."
        gain = _extract_security_gain(explanation)
        assert "prevent" in gain.lower()

    def test_extracts_sentence_with_add_verb(self):
        explanation = "Cookie was not stripped. The fix adds Cookie to DEFAULT_REMOVE_HEADERS_ON_REDIRECT alongside Authorization."
        gain = _extract_security_gain(explanation)
        assert "add" in gain.lower() or "Cookie" in gain

    def test_skips_short_sentences(self):
        # A sentence with a verb but too short should be skipped
        explanation = "Bug found. The patch fixes it. Here is why the fix adds significant protection against cross-origin leakage of credentials."
        gain = _extract_security_gain(explanation)
        assert len(gain) >= 40

    def test_fallback_to_first_paragraph(self):
        explanation = "This change modifies the retry behavior."
        gain = _extract_security_gain(explanation)
        assert len(gain) > 0

    def test_empty_explanation_returns_empty(self):
        assert _extract_security_gain("") == ""


# ---------------------------------------------------------------------------
# _build_known_findings / _render_known_findings
# ---------------------------------------------------------------------------

class TestBuildKnownFindings:
    """_build_known_findings regroups the same four classifier categories
    into epistemic-state labels — no new classification, no change to the
    counts _compute_trust_signals/_build_recommendation_v1 read.

    plausible_risk/generic findings are further split three ways by the
    (optional) finding_calibration stage output — evidence-quality pass —
    with a conservative fallback (plausible_risk -> Validation Hypotheses,
    generic -> Future Hardening Ideas) when no calibration entry exists for
    a given finding, so a calibration failure degrades gracefully instead of
    losing information."""

    def _classified_with(self, defects=(), risks=(), gaps=(), generic=()):
        classified_edge = []
        classified_issues = []
        for d in defects:
            classified_edge.append({"text": d, "category": "confirmed_defect"})
        for r in risks:
            classified_edge.append({"text": r, "category": "plausible_risk"})
        for g in gaps:
            classified_issues.append({"text": g, "category": "validation_gap"})
        for gen in generic:
            classified_issues.append({"text": gen, "category": "generic"})
        return {
            "classified_edge_cases": classified_edge,
            "classified_potential_issues": classified_issues,
            "confirmed_defect_count": len(defects),
            "plausible_risk_count": len(risks),
            "validation_gap_count": len(gaps),
        }

    def test_confirmed_defects_map_to_potential_remaining_risks(self):
        cc = self._classified_with(defects=["confirmed issue"])
        findings = _build_known_findings(cc)
        assert findings["potential_remaining_risks"] == ["confirmed issue"]

    def test_validation_gaps_map_to_validation_gaps(self):
        cc = self._classified_with(gaps=["gap1"])
        findings = _build_known_findings(cc)
        assert findings["validation_gaps"] == ["gap1"]

    def test_plausible_risk_without_calibration_falls_back_to_hypotheses(self):
        cc = self._classified_with(risks=["plausible risk"])
        findings = _build_known_findings(cc, finding_calibration=None)
        assert findings["validation_hypotheses"] == ["plausible risk"]
        assert findings["observed_implementation_notes"] == []
        assert findings["future_hardening_ideas"] == []

    def test_generic_without_calibration_falls_back_to_hardening(self):
        cc = self._classified_with(generic=["tests should be added"])
        findings = _build_known_findings(cc, finding_calibration=None)
        assert findings["future_hardening_ideas"] == ["tests should be added"]

    def test_calibration_routes_finding_to_its_assigned_group(self):
        cc = self._classified_with(risks=["case normalization detail"])
        calibration = [{
            "original": "case normalization detail",
            "group": "observed",
            "reworded": "The constructor normalizes header casing via h.lower().",
        }]
        findings = _build_known_findings(cc, finding_calibration=calibration)
        assert findings["observed_implementation_notes"] == [
            "The constructor normalizes header casing via h.lower()."
        ]
        assert findings["validation_hypotheses"] == []

    def test_calibration_can_move_a_finding_out_of_its_classifier_bucket(self):
        """A plausible_risk-classified finding can still land in Future
        Hardening Ideas if calibration judges it unrelated to the advisory —
        the classifier bucket only decides which findings are eligible for
        calibration, not the final presentation group."""
        cc = self._classified_with(risks=["Proxy-Authorization header not stripped"])
        calibration = [{
            "original": "Proxy-Authorization header not stripped",
            "group": "hardening",
            "reworded": "Proxy-Authorization is not covered by this advisory; a separate hardening improvement.",
        }]
        findings = _build_known_findings(cc, finding_calibration=calibration)
        assert findings["future_hardening_ideas"] == [
            "Proxy-Authorization is not covered by this advisory; a separate hardening improvement."
        ]
        assert findings["validation_hypotheses"] == []

    def test_missing_calibration_entry_for_one_finding_still_falls_back(self):
        """Calibration covering only some findings must not drop the rest —
        each uncovered finding still gets its conservative default."""
        cc = self._classified_with(risks=["covered finding", "uncovered finding"])
        calibration = [{
            "original": "covered finding", "group": "observed", "reworded": "Covered, reworded.",
        }]
        findings = _build_known_findings(cc, finding_calibration=calibration)
        assert findings["observed_implementation_notes"] == ["Covered, reworded."]
        assert findings["validation_hypotheses"] == ["uncovered finding"]

    def test_validation_gaps_capped_at_three(self):
        cc = self._classified_with(gaps=["g1", "g2", "g3", "g4", "g5"])
        findings = _build_known_findings(cc)
        assert len(findings["validation_gaps"]) <= 3

    def test_empty_classified_challenger_returns_all_empty(self):
        cc = self._classified_with()
        findings = _build_known_findings(cc)
        assert all(v == [] for v in findings.values())

    def test_signature_takes_optional_calibration(self):
        """Unlike the old _build_known_limitations(cc, coverage_value), this
        function takes classified_challenger plus an optional
        finding_calibration — gating on coverage is the renderer/caller's
        job, and calibration is optional so a calibration failure doesn't
        change this function's contract."""
        import inspect
        params = inspect.signature(_build_known_findings).parameters
        assert list(params) == ["classified_challenger", "finding_calibration"]
        assert params["finding_calibration"].default is None


class TestRenderKnownFindings:
    def _findings(self, risks=(), gaps=(), observed=(), hypotheses=(), hardening=()):
        return {
            "potential_remaining_risks": list(risks),
            "validation_gaps": list(gaps),
            "observed_implementation_notes": list(observed),
            "validation_hypotheses": list(hypotheses),
            "future_hardening_ideas": list(hardening),
        }

    def test_empty_findings_render_nothing(self):
        assert _render_known_findings(self._findings()) == ""

    def test_bullet_count_disclaimer_present_when_rendered(self):
        """Reviewer-experience fix: the number of bullets below this heading
        must not read as a count of confirmed defects — a standing
        disclaimer states this once, directly under the heading."""
        block = _render_known_findings(self._findings(risks=["r1"]))
        assert "not a count of confirmed defects" in block.lower()

    def test_bullet_count_disclaimer_absent_when_empty(self):
        assert "confirmed defects" not in _render_known_findings(self._findings()).lower()

    def test_heading_and_subheadings_present(self):
        block = _render_known_findings(self._findings(
            risks=["r1"], gaps=["g1"], observed=["o1"], hypotheses=["h1"], hardening=["f1"],
        ))
        assert "## Review Results" in block
        assert "### Potential Remaining Risks" in block
        assert "### Validation Gaps" in block
        assert "### Confirmed Observations" in block
        assert "### Validation Questions" in block
        assert "### Future Improvements" in block
        assert "r1" in block and "g1" in block and "o1" in block and "h1" in block and "f1" in block

    def test_potential_remaining_risks_labeled_as_heuristic_not_confirmed(self):
        """Correction: confirmed_defect findings must not be presented as
        confirmed facts — the challenger is heuristic LLM analysis."""
        block = _render_known_findings(self._findings(risks=["r1"]))
        assert "heuristic" in block.lower()
        assert "**Confirmed" not in block
        assert "confirmed gap" not in block.lower()

    def test_observed_implementation_notes_labeled_as_repository_backed(self):
        block = _render_known_findings(self._findings(observed=["h.lower() normalizes casing"]))
        assert "### Confirmed Observations" in block
        assert "repository evidence" in block.lower()

    def test_validation_hypotheses_labeled_as_unconfirmed(self):
        """Correction: hypotheses must read as conditional reasoning, not
        observed behavior."""
        block = _render_known_findings(self._findings(hypotheses=["same-origin redirects may also strip Cookie"]))
        assert "### Validation Questions" in block
        assert "not directly observed" in block.lower()
        assert "not confirmed outcomes" in block.lower()

    def test_hardening_ideas_do_not_reduce_confidence(self):
        block = _render_known_findings(self._findings(hardening=["Proxy-Authorization header"]))
        assert "### Future Improvements" in block
        assert "do not reduce confidence" in block.lower()

    def test_validation_gaps_bridge_to_test_coverage(self):
        """Correction: Validation Gaps must clarify it's independent of
        whether the repo already has pre-existing tests for this module."""
        block = _render_known_findings(self._findings(gaps=["no test validates the new behavior"]))
        assert "Trust Signals" in block

    def test_only_populated_subsections_render(self):
        block = _render_known_findings(self._findings(gaps=["g1"]))
        assert "### Validation Gaps" in block
        assert "### Potential Remaining Risks" not in block
        assert "### Confirmed Observations" not in block
        assert "### Validation Questions" not in block
        assert "### Future Improvements" not in block

    def test_future_hardening_ideas_render_alone(self):
        """The section must render even when only hardening ideas are
        present — this is the previously-fully-discarded generic bucket."""
        block = _render_known_findings(self._findings(hardening=["consider adding a comment"]))
        assert "## Review Results" in block
        assert "### Future Improvements" in block
        assert "consider adding a comment" in block


# ---------------------------------------------------------------------------
# _check_recommendation_consistency (Slice 1 — Decision Consistency)
# ---------------------------------------------------------------------------

class TestRecommendationConsistency:
    """Unit tests for the Slice 1 consistency check.

    Goal: a top-tier recommendation must acknowledge, in its own text, any
    already-displayed evidence (test availability, decision-relevant open
    findings) that runs against it. This function never changes the decision
    itself — these tests only assert on the caveat list it returns.

    The coverage-related caveat is deliberately NOT driven by
    coverage_confidence's own value/notes: Coverage Confidence answers "how
    thoroughly did we explore?" (Future Hardening Ideas count there,
    unchanged) while this caveat answers "should this recommendation be
    discounted?" (Future Hardening Ideas must not count here). It computes
    its own decision-relevant count from `known_findings` instead.
    """

    def _signals(self, test_availability="Tests Available"):
        return {
            "test_availability": {
                "value": test_availability, "label": test_availability,
                "notes": "No test files cover this module" if test_availability == "No Tests Found" else "some notes",
            },
            # coverage_confidence is realistic fixture data only — this
            # function no longer reads it at all.
            "coverage_confidence": {
                "value": "Medium", "label": "Medium",
                "notes": "11 review finding(s) · no deterministic blocker identified",
            },
        }

    def _known_findings(self, risks=0, gaps=0, observed=0, hypotheses=0, hardening=0):
        return {
            "potential_remaining_risks": [f"risk {i}" for i in range(risks)],
            "validation_gaps": [f"gap {i}" for i in range(gaps)],
            "observed_implementation_notes": [f"observed {i}" for i in range(observed)],
            "validation_hypotheses": [f"hypothesis {i}" for i in range(hypotheses)],
            "future_hardening_ideas": [f"hardening {i}" for i in range(hardening)],
        }

    # --- Decision gating: only top-tier decisions are checked at all ---

    def test_no_caveat_for_manual_review_required(self):
        signals = self._signals(test_availability="No Tests Found")
        findings = self._known_findings(hypotheses=2)
        assert _check_recommendation_consistency(signals, "Manual Review Required", findings) == []

    def test_no_caveat_for_do_not_apply(self):
        signals = self._signals(test_availability="No Tests Found")
        findings = self._known_findings(hypotheses=2)
        assert _check_recommendation_consistency(signals, "Do Not Apply", findings) == []

    # --- Test Availability condition ---

    def test_caveat_for_no_tests_found_at_top_tier(self):
        signals = self._signals(test_availability="No Tests Found")
        findings = self._known_findings()
        caveats = _check_recommendation_consistency(signals, "Deploy After Validation", findings)
        assert len(caveats) == 1
        assert "test coverage" in caveats[0].lower()

    def test_no_caveat_when_tests_available_at_top_tier(self):
        signals = self._signals(test_availability="Tests Available")
        findings = self._known_findings()
        assert _check_recommendation_consistency(signals, "Deploy After Validation", findings) == []

    def test_not_verified_is_not_treated_as_no_tests_found(self):
        """Language-guardrail 'Not Verified' means the check didn't run, not
        that tests are confirmed absent — must not trip the same caveat."""
        signals = self._signals(test_availability="Not Verified")
        findings = self._known_findings()
        assert _check_recommendation_consistency(signals, "Deploy After Validation", findings) == []

    # --- Decision-relevant findings condition ---

    def test_caveat_when_decision_relevant_findings_open(self):
        signals = self._signals(test_availability="Tests Available")
        findings = self._known_findings(hypotheses=1)
        caveats = _check_recommendation_consistency(signals, "Deploy After Validation", findings)
        assert len(caveats) == 1
        assert "adversarial coverage" in caveats[0].lower()

    def test_no_caveat_when_no_findings_at_all(self):
        signals = self._signals(test_availability="Tests Available")
        findings = self._known_findings()
        assert _check_recommendation_consistency(signals, "Deploy After Validation", findings) == []

    def test_hardening_only_findings_produce_no_caveat(self):
        """The core fix: Future Hardening Ideas are real findings (they still
        count toward Coverage Confidence and appear in Known Findings) but
        must not, on their own, make this caveat fire — they are not reasons
        to distrust this deployment recommendation."""
        signals = self._signals(test_availability="Tests Available")
        findings = self._known_findings(hardening=5)
        assert _check_recommendation_consistency(signals, "Deploy After Validation", findings) == []

    def test_hardening_findings_excluded_from_caveat_count(self):
        """Mixed case: decision-relevant findings trigger the caveat, but its
        wording counts only those — hardening findings present alongside
        must not inflate the number shown."""
        signals = self._signals(test_availability="Tests Available")
        findings = self._known_findings(hypotheses=2, hardening=7)
        caveats = _check_recommendation_consistency(signals, "Deploy After Validation", findings)
        assert len(caveats) == 1
        assert "2 decision-relevant finding(s)" in caveats[0]
        assert "7" not in caveats[0]

    def test_confirmed_risks_and_gaps_also_count_as_decision_relevant(self):
        signals = self._signals(test_availability="Tests Available")
        findings = self._known_findings(risks=1, gaps=1, observed=1)
        caveats = _check_recommendation_consistency(signals, "Deploy After Validation", findings)
        assert "3 decision-relevant finding(s)" in caveats[0]

    # --- Both conditions at once ---

    def test_both_caveats_when_both_weak_at_top_tier(self):
        signals = self._signals(test_availability="No Tests Found")
        findings = self._known_findings(hypotheses=1)
        caveats = _check_recommendation_consistency(signals, "Deploy After Validation", findings)
        assert len(caveats) == 2

    # --- Deploy With Caution is also top-tier ---

    def test_deploy_with_caution_is_also_checked(self):
        """Deploy With Caution is reachable through _build_recommendation_v1's
        API even though today's _compute_trust_signals output cannot produce
        it in practice (see benchmark notes) — the check must still cover it
        defensively rather than assume it will never be seen."""
        signals = self._signals(test_availability="No Tests Found")
        findings = self._known_findings()
        caveats = _check_recommendation_consistency(signals, "Deploy With Caution", findings)
        assert len(caveats) == 1

    # --- Wording reuses already-displayed evidence, not new judgment ---

    def test_caveat_reuses_displayed_notes_text(self):
        signals = self._signals(test_availability="No Tests Found")
        findings = self._known_findings()
        caveats = _check_recommendation_consistency(signals, "Deploy After Validation", findings)
        assert "No test files cover this module" in caveats[0]

    # --- Defensive: missing keys never raise ---

    def test_missing_signal_keys_do_not_raise(self):
        assert _check_recommendation_consistency({}, "Deploy After Validation", {}) == []


class TestDecisionRelevantFindingCount:
    """Unit tests for the small pure helper the consistency check now uses
    instead of reusing coverage_confidence's value."""

    def test_excludes_future_hardening_ideas(self):
        from utilities.autopatcher.pipeline import _decision_relevant_finding_count
        findings = {
            "potential_remaining_risks": [], "validation_gaps": [],
            "observed_implementation_notes": [], "validation_hypotheses": [],
            "future_hardening_ideas": ["a", "b", "c"],
        }
        assert _decision_relevant_finding_count(findings) == 0

    def test_counts_all_other_categories(self):
        from utilities.autopatcher.pipeline import _decision_relevant_finding_count
        findings = {
            "potential_remaining_risks": ["r"], "validation_gaps": ["g"],
            "observed_implementation_notes": ["o"], "validation_hypotheses": ["h1", "h2"],
            "future_hardening_ideas": ["ignored"],
        }
        assert _decision_relevant_finding_count(findings) == 5

    def test_missing_keys_default_to_empty(self):
        from utilities.autopatcher.pipeline import _decision_relevant_finding_count
        assert _decision_relevant_finding_count({}) == 0


# ---------------------------------------------------------------------------
# Hybrid blocking policy
# ---------------------------------------------------------------------------

class TestHybridBlockingPolicy:
    """Regression suite for the hybrid blocking policy (Recommendation Policy v2).

    Hard-block  → integrity failure only (deterministic evidence)
    Escalation  → still_vulnerable=True, confirmed_defect_count == 0
                  OR confirmed_defect_count > 0 (alignment=Misaligned) — both heuristic-only,
                  both land at Manual Review Required, never Do Not Apply
    Forward     → still_vulnerable=False, confirmed_defect_count == 0

    Benchmark expectations
    ----------------------
    urllib3   : still_vulnerable=True,  defect_count=0, risks=12  → Manual Review Required
    minimist  : still_vulnerable=False, defect_count=0             → Deploy After Validation
    pip       : still_vulnerable=False, defect_count=0             → Deploy After Validation
    pygeoapi  : integrity=Does Not Apply                           → Do Not Apply
    GitPython : still_vulnerable=True,  defect_count=1             → Manual Review Required (via alignment)
    """

    # --- urllib3: still_vulnerable=True, defect_count=0 → escalation ---

    def test_urllib3_still_vulnerable_no_defects_is_manual_review(self):
        """urllib3 regression: plausible risks with no confirmed defect → Manual Review Required."""
        signals = _signals_for(integrity="Clean", improvement="Medium", alignment="Partial", safety="Low Risk")
        rec = _build_recommendation_v1(signals, still_vulnerable=True, defect_count=0)
        assert rec["decision"] == "Manual Review Required"

    def test_urllib3_full_signals_manual_review(self):
        """End-to-end urllib3 signal path via _compute_trust_signals."""
        classified = _classified(still_vulnerable=True, risks=12)
        signals = _compute_trust_signals([], _clean_applicability(), classified, "Good", "high")
        rec = _build_recommendation_v1(
            signals,
            still_vulnerable=classified["still_vulnerable"],
            defect_count=classified["confirmed_defect_count"],
        )
        assert rec["decision"] == "Manual Review Required"

    def test_urllib3_escalation_reason_mentions_challenger(self):
        signals = _signals_for(integrity="Clean", improvement="Medium", alignment="Partial")
        rec = _build_recommendation_v1(signals, still_vulnerable=True, defect_count=0)
        assert "challenger" in rec["reason"].lower()

    # --- GitPython v2: defect_count=1 → alignment=Misaligned → hard-block ---

    def test_gitpython_confirmed_defect_is_manual_review_required(self):
        """GitPython v2: one confirmed defect drives alignment=Misaligned → Manual Review
        Required. Per Recommendation Policy v2, heuristic evidence (challenger-derived
        confirmed_defect_count) escalates to human review, it does not hard-block."""
        classified = _classified(still_vulnerable=True, defects=1, risks=13)
        signals = _compute_trust_signals([], _clean_applicability(), classified, "Some", "low")
        rec = _build_recommendation_v1(
            signals,
            still_vulnerable=classified["still_vulnerable"],
            defect_count=classified["confirmed_defect_count"],
        )
        assert rec["decision"] == "Manual Review Required"
        assert signals["remediation_alignment"]["value"] == "Misaligned"

    def test_gitpython_escalation_survives_still_vulnerable_false(self):
        """Contradictory case: LLM says No but a finding classifies as confirmed_defect.
        defect_count > 0 drives alignment=Misaligned and escalates to Manual Review
        Required regardless of still_vulnerable — still never Do Not Apply on its own."""
        classified = _classified(still_vulnerable=False, defects=1)
        signals = _compute_trust_signals([], _clean_applicability(), classified, "None", "low")
        rec = _build_recommendation_v1(
            signals,
            still_vulnerable=classified["still_vulnerable"],
            defect_count=classified["confirmed_defect_count"],
        )
        assert rec["decision"] == "Manual Review Required"

    # --- pygeoapi: integrity failure fires before any challenger signal ---

    def test_pygeoapi_integrity_hard_block(self):
        """pygeoapi: Does Not Apply integrity blocks regardless of challenger state."""
        signals = _signals_for(integrity="Does Not Apply", improvement="None", alignment="Misaligned")
        rec = _build_recommendation_v1(signals, still_vulnerable=True, defect_count=1)
        assert rec["decision"] == "Do Not Apply"
        assert "does not apply" in rec["reason"].lower() or "critical" in rec["reason"].lower()

    # --- minimist / pip: clean path ---

    def test_minimist_clean_path_deploy_after_validation(self):
        """minimist: still_vulnerable=False, defect_count=0 → Deploy After Validation."""
        signals = _signals_for(integrity="Clean", improvement="High", alignment="Aligned", safety="Low Risk")
        rec = _build_recommendation_v1(signals, still_vulnerable=False, defect_count=0)
        assert rec["decision"] == "Deploy After Validation"

    def test_pip_clean_path_deploy_after_validation(self):
        """pip: still_vulnerable=False, defect_count=0, medium risk → Deploy After Validation."""
        signals = _signals_for(integrity="Clean", improvement="High", alignment="Aligned", safety="Medium Risk")
        rec = _build_recommendation_v1(signals, still_vulnerable=False, defect_count=0)
        assert rec["decision"] == "Deploy After Validation"

    # --- Boundary: still_vulnerable=True with defect_count>0 also hard-blocks ---

    def test_both_still_vulnerable_and_defects_is_manual_review_required(self):
        """When still_vulnerable=True AND defect_count>0, alignment=Misaligned fires →
        Manual Review Required (heuristic evidence escalates, it does not hard-block)."""
        classified = _classified(still_vulnerable=True, defects=2, risks=5)
        signals = _compute_trust_signals([], _clean_applicability(), classified, "None", "low")
        rec = _build_recommendation_v1(
            signals,
            still_vulnerable=classified["still_vulnerable"],
            defect_count=classified["confirmed_defect_count"],
        )
        assert rec["decision"] == "Manual Review Required"

    # --- Boundary: still_vulnerable=True with only gaps (risk_count=0) ---

    def test_still_vulnerable_gaps_only_is_manual_review(self):
        """still_vulnerable=True with only validation gaps (no plausible risks, no defects)
        also hits the escalation branch."""
        classified = _classified(still_vulnerable=True, gaps=3)
        signals = _compute_trust_signals([], _clean_applicability(), classified, "None", "low")
        rec = _build_recommendation_v1(
            signals,
            still_vulnerable=classified["still_vulnerable"],
            defect_count=classified["confirmed_defect_count"],
        )
        assert rec["decision"] == "Manual Review Required"


# ---------------------------------------------------------------------------
# Recommendation Policy v2 — explicit policy statement as a regression test
# ---------------------------------------------------------------------------

class TestPureHeuristicEvidenceNeverBlocks:
    """Recommendation Policy v2: pure heuristic evidence must never produce Do Not Apply.

    Do Not Apply may only be produced by deterministic evidence — currently that
    means `patch_integrity` (git-apply / static hygiene). Every other input to
    `_build_recommendation_v1` (`security_improvement`, `remediation_alignment`,
    `still_vulnerable`, `defect_count`) is derived entirely from the adversarial
    challenger's free-text output and is therefore heuristic, not deterministic
    (see docs/recommendation-policy-v2.md). This test holds `patch_integrity` at
    its cleanest, non-blocking value and sweeps every value the heuristic
    signals can take — including the worst case on every axis at once — and
    asserts none of them, alone or combined, ever reach Do Not Apply.

    This expresses the policy itself, not one input combination: if a future
    change reintroduces a path from heuristic evidence to Do Not Apply, this
    test fails regardless of which heuristic signal caused it.
    """

    _ALIGNMENT_VALUES = ["Misaligned", "Partial", "Likely Aligned", "Aligned"]
    _IMPROVEMENT_VALUES = ["None", "Low", "Medium", "High"]
    _SAFETY_VALUES = ["Low Risk", "Medium Risk", "High Risk"]
    _DEFECT_COUNTS = (0, 1, 5)

    def test_pure_heuristic_evidence_never_produces_do_not_apply(self):
        for alignment in self._ALIGNMENT_VALUES:
            for improvement in self._IMPROVEMENT_VALUES:
                for safety in self._SAFETY_VALUES:
                    for still_vulnerable in (True, False):
                        for defect_count in self._DEFECT_COUNTS:
                            signals = _signals_for(
                                integrity="Clean",  # the one deterministic control variable
                                improvement=improvement,
                                alignment=alignment,
                                safety=safety,
                            )
                            rec = _build_recommendation_v1(
                                signals,
                                still_vulnerable=still_vulnerable,
                                defect_count=defect_count,
                            )
                            assert rec["decision"] != "Do Not Apply", (
                                "Pure heuristic evidence produced Do Not Apply with "
                                f"integrity=Clean, alignment={alignment!r}, "
                                f"improvement={improvement!r}, safety={safety!r}, "
                                f"still_vulnerable={still_vulnerable}, "
                                f"defect_count={defect_count}"
                            )

    def test_integrity_is_still_the_only_path_to_do_not_apply(self):
        """Sanity check the sweep isn't vacuous: deterministic integrity failure
        must still produce Do Not Apply even with every heuristic signal clean."""
        signals = _signals_for(
            integrity="Does Not Apply",
            improvement="High",
            alignment="Aligned",
            safety="Low Risk",
        )
        rec = _build_recommendation_v1(signals, still_vulnerable=False, defect_count=0)
        assert rec["decision"] == "Do Not Apply"
