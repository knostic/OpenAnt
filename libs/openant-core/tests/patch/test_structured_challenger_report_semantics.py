"""Report semantics for structured (`Concerns:` schema) Challenger output.

F1 -- "Are there unresolved concerns?" derives from per-concern consequences.
F2 -- structured RESIDUAL wording states only what the schema establishes.
F3 -- a "Challenger concerns" section renders, and every pointer resolves.

Display only: none of this may change a signal value read by the I1-I6
gates, a recommendation decision, or any Challenger classification.
"""
import copy
import itertools
import re

import pytest

from utilities.autopatcher.patch_challenger import _derive_status_from_concerns
from utilities.autopatcher.pipeline import (
    PipelineResult,
    _build_known_findings,
    _build_recommendation_v1,
    _build_report,
    _classify_challenger,
    _compute_trust_signals,
    _reconcile_verification_status_with_calibration,
    _render_challenger_concerns,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _concern(consequence, role="additional", description=None, malformed=False):
    return {
        "concern_role": None if malformed else role,
        "description": "" if malformed else (description or f"a {consequence.lower()} concern"),
        "default_execution_reachability": None,
        "requires_explicit_non_default_action": "not_applicable",
        "contract_addresses_override": "not_applicable",
        "malformed": malformed,
        "malformed_reason": "missing field" if malformed else None,
        "consequence": consequence,
    }


def _structured(*consequences, schema="concerns_v2", primary_index=0):
    """A raw structured Challenger result whose aggregate is computed by the
    production aggregation rule, never asserted by hand."""
    concerns = [
        _concern(c, role="primary" if i == primary_index else "additional")
        for i, c in enumerate(consequences)
    ]
    status, still = _derive_status_from_concerns(concerns, legacy_prose_present=False)
    return {
        "verification_status": status, "still_vulnerable": still,
        "edge_cases": [], "potential_issues": [], "summary": "",
        "concerns": concerns, "schema_version": schema,
    }


def _signals(raw):
    return _compute_trust_signals([], {"applicable": True}, _classify_challenger(raw), "Good", "low")


def _coverage(raw):
    return _signals(raw)["coverage_confidence"]


# Persisted canonical urllib3 CVE-2023-43804 Run #2 Challenger result
# (/tmp/urllib3-release-regression-run2/trace/executions/
# 006_patch_repair_and_calibration.json "challenger", identical to
# 005_challenger.json; no repair; finding_calibration None), copied verbatim.
CANONICAL_RUN2_CHALLENGER = {
    "verification_status": "RESIDUAL_VULNERABILITY",
    "still_vulnerable": True,
    "edge_cases": [],
    "potential_issues": [],
    "summary": (
        "Primary concern: Whether a user-supplied Cookie header is still forwarded on a "
        "cross-origin redirect under default execution. (UNRESOLVED). Additional concern: "
        "Direct HTTPConnectionPool.urlopen usage (without PoolManager) does not re-filter "
        "headers on redirect, so Cookie may be forwarded cross-origin on that path. "
        "(UNRESOLVED). Additional concern: A caller passing an explicit "
        "remove_headers_on_redirect that omits Cookie still forwards the Cookie header on "
        "cross-origin redirect. (BLOCKING)."
    ),
    "concerns": [
        {
            "concern_role": "primary",
            "description": (
                "Whether a user-supplied Cookie header is still forwarded on a cross-origin "
                "redirect under default execution."
            ),
            "default_execution_reachability": "unresolved",
            "requires_explicit_non_default_action": "not_applicable",
            "contract_addresses_override": "not_applicable",
            "malformed": False,
            "malformed_reason": None,
            "consequence": "UNRESOLVED",
            "reachability_facts": {
                "operation_present_in_evidence": "present", "preceding_guard": "unresolved",
                "guard_default_state": "not_applicable", "guard_effect": "not_applicable",
                "reentry_state_propagation": "not_applicable",
            },
            "hypothesized_outcome": None,
        },
        {
            "concern_role": "additional",
            "description": (
                "Direct HTTPConnectionPool.urlopen usage (without PoolManager) does not "
                "re-filter headers on redirect, so Cookie may be forwarded cross-origin on that "
                "path."
            ),
            "default_execution_reachability": "unresolved",
            "requires_explicit_non_default_action": "not_applicable",
            "contract_addresses_override": "not_applicable",
            "malformed": False,
            "malformed_reason": None,
            "consequence": "UNRESOLVED",
            "reachability_facts": {
                "operation_present_in_evidence": "present", "preceding_guard": "absent",
                "guard_default_state": "not_applicable", "guard_effect": "not_applicable",
                "reentry_state_propagation": "not_applicable",
            },
            "hypothesized_outcome": (
                "The advisory describes the leak in terms of redirects generally; "
                "HTTPConnectionPool.urlopen passes `headers` through unchanged on its own "
                "redirect recursion and performs no remove_headers_on_redirect filtering, so "
                "direct pool usage bypassing PoolManager is not covered by this edit. However, "
                "`urlopen` here is quoted from a `Discovered consumer` window, not a `Full "
                "file`/`Target definition` block, so `absent` cannot be firmly established — "
                "treat as a potential gap, not a confirmed residual."
            ),
        },
        {
            "concern_role": "additional",
            "description": (
                "A caller passing an explicit remove_headers_on_redirect that omits Cookie "
                "still forwards the Cookie header on cross-origin redirect."
            ),
            "default_execution_reachability": "reachable",
            "requires_explicit_non_default_action": "not_applicable",
            "contract_addresses_override": "not_applicable",
            "malformed": False,
            "malformed_reason": None,
            "consequence": "BLOCKING",
            "reachability_facts": {
                "operation_present_in_evidence": "present", "preceding_guard": "present",
                "guard_default_state": "condition_false_under_default",
                "guard_effect": "not_applicable", "reentry_state_propagation": "not_applicable",
            },
            "hypothesized_outcome": (
                "Under default, Cookie IS in the set so the guard fires per-header and removes "
                "it; only an explicit non-default remove_headers_on_redirect omitting Cookie "
                "reintroduces the leak, which the advisory does not address."
            ),
        },
    ],
    "schema_version": "concerns_v2",
}

# The exact pre-fix (legacy) strings. Legacy output must keep rendering them.
LEGACY_RESIDUAL_NOTES = (
    "Adversarial review identified a concrete residual vulnerability; not corroborated by a "
    "separately confirmed defect"
)
LEGACY_RESIDUAL_REASON = (
    "Adversarial review found affirmative evidence the vulnerability may remain exploitable "
    "(a concrete bypass or ineffective mechanism); see Review Results below before deploying."
)
LEGACY_RESIDUAL_WHY = "affirmative evidence indicates the vulnerability may still be present"
OVERCLAIMS = ("concrete bypass", "concrete residual vulnerability", "affirmative evidence")


def _report_for(challenger, tmp_path):
    result = PipelineResult(
        vulnerability_text="# Test vulnerability\n\nSome description.",
        patch="--- a/mod.py\n+++ b/mod.py\n@@ -1,3 +1,3 @@\n def foo():\n-    return 1\n+    return 2\n",
        review="**Explanation:**\nok\n",
        score_text="**Confidence score:** 0.80\n\n**Reasons:**\n- ok",
        challenger=challenger,
        impact={"impact_level": "low", "changed_files": [], "affected_files": [],
                "impact_summary": "", "recommendations": [], "usage_matches": []},
        hygiene=[],
        applicability={"applicable": True, "skipped": False, "skipped_reason": None,
                       "error": None, "stderr": ""},
        repo_root=tmp_path,
        detected_language="python",
    )
    return _build_report(result)


_POINTER_RE = re.compile(r"\b[Ss]ee ([A-Z][A-Za-z ]*?)(?: section)? below")


def _dangling_pointers(report):
    headings = {m.group(1).strip() for m in re.finditer(r"^##+ (.+)$", report, re.MULTILINE)}
    return sorted({t for t in _POINTER_RE.findall(report) if t not in headings})


def _trust_row(report, question):
    return next(line for line in report.splitlines() if line.startswith(f"| {question} |"))


# ---------------------------------------------------------------------------
# F1 -- structured coverage signal
# ---------------------------------------------------------------------------

class TestF1StructuredCoverageSignal:
    def test_blocking_needs_review_not_blocked(self):
        cov = _coverage(_structured("NON_BLOCKING", "BLOCKING"))
        assert cov["value"] == "Medium"  # renders ⚠️ Needs review, never ❌ Blocked
        assert "1 blocking · 0 unresolved · 1 non-blocking of 2" in cov["notes"]
        assert "No gaps identified" not in cov["notes"]

    def test_unresolved_needs_review(self):
        cov = _coverage(_structured("UNRESOLVED"))
        assert cov["value"] == "Medium"
        assert "0 blocking · 1 unresolved · 0 non-blocking of 1" in cov["notes"]

    def test_mixed_blocking_and_unresolved_counts_are_truthful(self):
        cov = _coverage(_structured("UNRESOLVED", "BLOCKING", "UNRESOLVED", "NON_BLOCKING"))
        assert cov["value"] == "Medium"
        assert cov["notes"].startswith(
            "1 blocking · 2 unresolved · 1 non-blocking of 4 structured Challenger concern(s)"
        )
        assert "not independent verification" in cov["notes"]

    def test_all_non_blocking_is_good(self):
        raw = _structured("NON_BLOCKING", "NON_BLOCKING")
        assert raw["verification_status"] == "VERIFIED_FIXED"
        cov = _coverage(raw)
        assert cov["value"] == "High"
        assert cov["notes"] == "All 2 structured Challenger concern(s) classified non-blocking"

    def test_malformed_concern_counts_as_unresolved(self):
        raw = _structured("NON_BLOCKING")
        raw["concerns"].append(_concern("UNRESOLVED", malformed=True))
        assert "0 blocking · 1 unresolved · 1 non-blocking of 2" in _coverage(raw)["notes"]

    def test_unrecognized_consequence_fails_closed_to_unresolved(self):
        raw = _structured("NON_BLOCKING")
        raw["concerns"][0]["consequence"] = "SOMETHING_ELSE"
        assert _coverage(raw)["value"] == "Medium"

    def test_all_non_blocking_but_structurally_failed_is_not_good(self):
        raw = _structured("NON_BLOCKING", "NON_BLOCKING", primary_index=99)  # no primary
        assert raw["verification_status"] == "INSUFFICIENT_EVIDENCE"
        cov = _coverage(raw)
        assert cov["value"] == "Medium"
        assert "failed closed" in cov["notes"]

    def test_no_concerns_is_not_good(self):
        raw = _structured()
        cov = _coverage(raw)
        assert cov["value"] == "Medium"
        assert "No structured Challenger concern was reported" in cov["notes"]

    @pytest.mark.parametrize("schema", ["concerns_v1", "concerns_v2"])
    def test_both_structured_schema_versions(self, schema):
        assert _coverage(_structured("BLOCKING", schema=schema))["value"] == "Medium"

    def test_legacy_no_findings_unchanged(self):
        legacy = {"confirmed_defect_count": 0, "plausible_risk_count": 0,
                  "validation_gap_count": 0, "still_vulnerable": False}
        cov = _compute_trust_signals([], {"applicable": True}, legacy, "Good", "low")["coverage_confidence"]
        assert cov == {"value": "High", "label": "✓ High",
                       "notes": "No gaps identified by adversarial analysis"}

    def test_legacy_lexical_counts_unchanged(self):
        legacy = {"confirmed_defect_count": 0, "plausible_risk_count": 2,
                  "validation_gap_count": 1, "still_vulnerable": True}
        cov = _compute_trust_signals([], {"applicable": True}, legacy, "Good", "low")["coverage_confidence"]
        assert cov["value"] == "Medium"
        assert cov["notes"].startswith("3 raw review concern(s) recorded before evidence calibration")

    def test_legacy_defect_count_unchanged(self):
        legacy = {"confirmed_defect_count": 2, "plausible_risk_count": 0,
                  "validation_gap_count": 0, "still_vulnerable": True}
        cov = _compute_trust_signals([], {"applicable": True}, legacy, "Good", "low")["coverage_confidence"]
        assert cov["value"] == "Low"

    def test_report_row_needs_review_with_counts(self, tmp_path):
        report = _report_for(_structured("UNRESOLVED", "BLOCKING"), tmp_path)
        row = _trust_row(report, "Are there unresolved concerns?")
        assert "⚠️ Needs review" in row
        assert "1 blocking · 1 unresolved · 0 non-blocking of 2" in row
        assert "No gaps identified" not in report
        assert "❌" not in row


# ---------------------------------------------------------------------------
# F2 -- structured RESIDUAL wording
# ---------------------------------------------------------------------------

class TestF2StructuredResidualWording:
    def _rec(self, raw, structured):
        classified = _classify_challenger(raw)
        signals = _compute_trust_signals([], {"applicable": True}, classified, "Good", "low")
        return signals, _build_recommendation_v1(
            signals, still_vulnerable=classified["still_vulnerable"],
            defect_count=classified["confirmed_defect_count"],
            verification_status=classified["verification_status"],
            structured_challenger=structured,
        )

    def test_structured_residual_wording_is_bounded(self):
        signals, rec = self._rec(_structured("UNRESOLVED", "BLOCKING"), structured=True)
        assert rec["decision"] == "Manual Review Required"
        for text in (rec["reason"], rec["why"], signals["remediation_alignment"]["notes"],
                     signals["security_improvement"]["notes"]):
            assert "deterministic blocking rule" in text
            assert "not" in text and "independently verified" in text
            for phrase in OVERCLAIMS:
                assert phrase not in text
        assert "model-reported" in rec["reason"]
        assert "See Challenger concerns below" in rec["reason"]
        assert "Review Results" not in rec["reason"]
        assert signals["remediation_alignment"]["notes"].startswith(
            "1 of 2 structured Challenger concern(s) met the deterministic blocking rule"
        )

    def test_legacy_residual_signal_notes_unchanged(self):
        legacy = {"confirmed_defect_count": 0, "plausible_risk_count": 0,
                  "validation_gap_count": 1, "still_vulnerable": True,
                  "verification_status": "RESIDUAL_VULNERABILITY"}
        signals = _compute_trust_signals([], {"applicable": True}, legacy, "Good", "low")
        assert signals["remediation_alignment"]["notes"] == LEGACY_RESIDUAL_NOTES
        assert signals["security_improvement"]["notes"] == LEGACY_RESIDUAL_NOTES

    def test_legacy_residual_recommendation_unchanged(self):
        legacy = {"confirmed_defect_count": 0, "plausible_risk_count": 0,
                  "validation_gap_count": 1, "still_vulnerable": True,
                  "verification_status": "RESIDUAL_VULNERABILITY"}
        signals = _compute_trust_signals([], {"applicable": True}, legacy, "Good", "low")
        default = _build_recommendation_v1(signals, still_vulnerable=True, defect_count=0,
                                           verification_status="RESIDUAL_VULNERABILITY")
        explicit = _build_recommendation_v1(signals, still_vulnerable=True, defect_count=0,
                                            verification_status="RESIDUAL_VULNERABILITY",
                                            structured_challenger=False)
        assert default == explicit
        assert default["reason"] == f"{LEGACY_RESIDUAL_REASON} Remediation alignment: {LEGACY_RESIDUAL_NOTES}."
        assert default["why"] == f"{LEGACY_RESIDUAL_WHY} ({LEGACY_RESIDUAL_NOTES})"

    @pytest.mark.parametrize("status", ["INSUFFICIENT_EVIDENCE", None])
    def test_legacy_non_residual_reasons_unchanged(self, status):
        signals = _compute_trust_signals(
            [], {"applicable": True},
            {"confirmed_defect_count": 0, "plausible_risk_count": 0,
             "validation_gap_count": 1, "still_vulnerable": True, "verification_status": status},
            "Good", "low",
        )
        rec = _build_recommendation_v1(signals, still_vulnerable=True, defect_count=0,
                                       verification_status=status)
        assert "Review Results below" in rec["reason"]
        assert "Challenger concerns" not in rec["reason"]

    def test_structured_insufficient_points_at_existing_section(self):
        _signals_, rec = self._rec(_structured("UNRESOLVED"), structured=True)
        assert rec["reason"].startswith(
            "The available evidence was insufficient to verify the fix is effective; "
            "see Challenger concerns below before deploying."
        )


# ---------------------------------------------------------------------------
# F3 -- Challenger concerns section and pointers
# ---------------------------------------------------------------------------

class TestF3ChallengerConcernsSection:
    def test_section_renders_role_consequence_and_framed_description(self):
        raw = _structured("UNRESOLVED", "BLOCKING")
        raw["concerns"][1]["description"] = "Explicit override | omits the header"
        block = _render_challenger_concerns(_classify_challenger(raw))
        assert "## Challenger concerns" in block
        assert "| # | Role | Consequence | Model-authored description |" in block
        assert "| 1 | Primary | UNRESOLVED | a unresolved concern |" in block
        assert "| 2 | Additional | BLOCKING | Explicit override \\| omits the header |" in block
        assert "Descriptions are model-authored" in block
        assert "not that a defect was independently verified" in block

    def test_malformed_and_empty(self):
        raw = _structured("NON_BLOCKING")
        raw["concerns"].append(_concern("UNRESOLVED", malformed=True))
        block = _render_challenger_concerns(_classify_challenger(raw))
        assert "| 2 | Malformed | UNRESOLVED | *(no description parsed)* |" in block
        assert "No structured concern was reported." in _render_challenger_concerns(
            _classify_challenger(_structured())
        )

    def test_legacy_renders_nothing(self):
        assert _render_challenger_concerns({"edge_cases": [], "potential_issues": []}) == ""
        assert _render_challenger_concerns({}) == ""

    @pytest.mark.parametrize("consequences", [
        ("UNRESOLVED", "BLOCKING"), ("UNRESOLVED",), ("NON_BLOCKING",), (),
    ])
    def test_structured_report_section_and_pointers(self, consequences, tmp_path):
        report = _report_for(_structured(*consequences), tmp_path)
        assert "## Challenger concerns" in report
        assert _dangling_pointers(report) == []

    def test_structured_report_section_precedes_nothing_it_is_pointed_from(self, tmp_path):
        report = _report_for(_structured("UNRESOLVED", "BLOCKING"), tmp_path)
        assert report.index("## Trust Signals") < report.index("## Challenger concerns")
        assert report.index("## Recommendation") < report.index("## Challenger concerns")
        for question in ("Does it address the vulnerability?", "Are there unresolved concerns?"):
            assert "see Challenger concerns section below" in _trust_row(report, question)

    def test_legacy_report_has_no_challenger_concerns_section(self, tmp_path):
        legacy = {"verification_status": "INSUFFICIENT_EVIDENCE", "still_vulnerable": True,
                  "edge_cases": ["Header casing may not be validated"],
                  "potential_issues": [], "summary": "s"}
        report = _report_for(legacy, tmp_path)
        assert "Challenger concerns" not in report


# ---------------------------------------------------------------------------
# Decision invariance
# ---------------------------------------------------------------------------

_POLICY_KEYS = ("patch_integrity", "security_improvement", "remediation_alignment", "deployment_safety")


class TestDecisionInvariance:
    @pytest.mark.parametrize("consequences", [
        ("BLOCKING",), ("UNRESOLVED",), ("NON_BLOCKING",), ("UNRESOLVED", "BLOCKING"),
        ("NON_BLOCKING", "NON_BLOCKING"), (),
    ])
    def test_policy_signal_values_identical_with_and_without_schema(self, consequences):
        classified = _classify_challenger(_structured(*consequences))
        as_legacy = {k: v for k, v in classified.items() if k not in ("schema_version", "concerns")}
        structured = _compute_trust_signals([], {"applicable": True}, classified, "Good", "low")
        legacy = _compute_trust_signals([], {"applicable": True}, as_legacy, "Good", "low")
        for key in _POLICY_KEYS + ("test_availability",):
            assert structured[key]["value"] == legacy[key]["value"], key

    @pytest.mark.parametrize("integrity,improvement,alignment,safety,still,defects,status", list(
        itertools.product(
            ["Clean", "Minor Issues", "Does Not Apply", "Not Verified"],
            ["High", "Low", "Unknown"],
            ["Aligned", "Likely Aligned", "Misaligned"],
            ["Low Risk", "High Risk", "Not Verified"],
            [True, False],
            [0, 1],
            ["RESIDUAL_VULNERABILITY", "INSUFFICIENT_EVIDENCE", "VERIFIED_FIXED", None],
        )
    ))
    def test_decision_identical_with_structured_flag(
        self, integrity, improvement, alignment, safety, still, defects, status,
    ):
        signals = {
            "patch_integrity": {"value": integrity, "notes": "n"},
            "security_improvement": {"value": improvement, "notes": "n"},
            "remediation_alignment": {"value": alignment, "notes": "n"},
            "coverage_confidence": {"value": "Medium", "notes": "n"},
            "test_availability": {"value": "Tests Available", "notes": "n"},
            "deployment_safety": {"value": safety, "notes": "n"},
        }
        kwargs = dict(still_vulnerable=still, defect_count=defects, verification_status=status)
        off = _build_recommendation_v1(copy.deepcopy(signals), **kwargs)
        on = _build_recommendation_v1(copy.deepcopy(signals), **kwargs, structured_challenger=True)
        assert on["decision"] == off["decision"]
        if not (still and defects == 0 and alignment != "Misaligned" and integrity != "Does Not Apply"):
            assert on == off  # the flag is read only inside the I5 still_vulnerable branch


# ---------------------------------------------------------------------------
# Canonical urllib3 CVE-2023-43804 Run #2
# ---------------------------------------------------------------------------

class TestCanonicalUrllib3Run2:
    def _evaluate(self):
        classified = _reconcile_verification_status_with_calibration(
            _classify_challenger(copy.deepcopy(CANONICAL_RUN2_CHALLENGER)), None,
        )
        known = _build_known_findings(classified, None)
        defects = len(known["potential_remaining_risks"])
        signals = _compute_trust_signals(
            [], {"applicable": True}, {**classified, "confirmed_defect_count": defects}, "Good", "low",
        )
        rec = _build_recommendation_v1(
            signals, still_vulnerable=classified["still_vulnerable"], defect_count=defects,
            verification_status=classified["verification_status"], structured_challenger=True,
        )
        return classified, signals, rec

    def test_classification_unchanged(self):
        classified, _signals_, _rec = self._evaluate()
        assert classified["verification_status"] == "RESIDUAL_VULNERABILITY"
        assert [c["consequence"] for c in classified["concerns"]] == ["UNRESOLVED", "UNRESOLVED", "BLOCKING"]
        assert (classified["confirmed_defect_count"], classified["plausible_risk_count"],
                classified["validation_gap_count"]) == (0, 0, 0)

    def test_trust_signal_needs_review_with_truthful_counts(self):
        _classified, signals, _rec = self._evaluate()
        cov = signals["coverage_confidence"]
        assert cov["value"] == "Medium"
        assert cov["notes"].startswith(
            "1 blocking · 2 unresolved · 0 non-blocking of 3 structured Challenger concern(s)"
        )

    def test_policy_inputs_and_decision_unchanged(self):
        _classified, signals, rec = self._evaluate()
        assert {k: signals[k]["value"] for k in _POLICY_KEYS} == {
            "patch_integrity": "Clean", "security_improvement": "High",
            "remediation_alignment": "Likely Aligned", "deployment_safety": "Low Risk",
        }
        assert rec["decision"] == "Manual Review Required"

    def test_residual_wording_bounded(self):
        _classified, signals, rec = self._evaluate()
        for text in (rec["reason"], rec["why"], signals["remediation_alignment"]["notes"]):
            for phrase in OVERCLAIMS:
                assert phrase not in text
            assert "independently verified" in text

    def test_full_report(self, tmp_path):
        report = _report_for(copy.deepcopy(CANONICAL_RUN2_CHALLENGER), tmp_path)
        assert "MANUAL REVIEW REQUIRED" in report
        assert "⚠️ Needs review" in _trust_row(report, "Are there unresolved concerns?")
        assert "No gaps identified" not in report
        for phrase in OVERCLAIMS:
            assert phrase not in report
        assert "## Challenger concerns" in report
        assert "| 3 | Additional | BLOCKING | A caller passing an explicit remove_headers_on_redirect" in report
        assert _dangling_pointers(report) == []
