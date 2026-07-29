"""Regression tests for BUGHUNT2 findings (fork PR code, 2026-07-29).

Each test fails on the pre-fix code and passes after. Kept together for traceability;
the fixes live in html_report.py, context/threat_model.py, core/analysis_core.py.
"""
import os
import tempfile

import pytest

import report.html_report as H
import context.threat_model as T
import core.analysis_core as A


# --- GO-1: verdict badge must be HTML-escaped (model-supplied finding text) ---
def test_go1_verdict_badge_is_escaped():
    exp = {"results": [{"route_key": "a.py:f",
                        "finding": "<img src=x onerror=alert(1)>"}]}
    out = os.path.join(tempfile.mkdtemp(), "r.html")
    H.generate_html_report(exp, {"units": []}, "", out)
    html = open(out).read()
    assert "<img src=x onerror=alert(1)>" not in html      # raw injection blocked
    assert "&lt;img src=x onerror=alert(1)&gt;" in html    # escaped form present


# --- GO-2: explicit null reasoning must not crash the report build ---
def test_go2_null_reasoning_no_crash():
    exp = {"results": [{"route_key": "a.py:f", "finding": "vulnerable", "reasoning": None}]}
    H.prepare_findings_summary(exp, {"units": []})          # was None[:300] TypeError
    out = os.path.join(tempfile.mkdtemp(), "r.html")
    H.generate_html_report(exp, {"units": []}, "", out)     # end-to-end


# --- GO-3: an 'error' (unanalyzed) unit must be surfaced, not invisible ---
def test_go3_error_verdict_surfaced():
    exp = {"results": [{"route_key": "a.py:f", "finding": "error"}]}
    out = os.path.join(tempfile.mkdtemp(), "r.html")
    H.generate_html_report(exp, {"units": []}, "", out)
    html = open(out).read()
    assert "Errored (unanalyzed)" in html          # stat card
    assert '"error"' in html                        # AND the charts (not just the card)


# --- TM-1: a capitalized "Trusted" must still trigger the self-whitelisting warning ---
@pytest.mark.parametrize("trust", ["trusted", "Trusted", "TRUSTED"])
def test_tm1_trust_warning_case_insensitive(trust):
    w = T.warn_permissive_threat_model(
        {"input_sources": {"web": {"trust": trust, "description": "d"}}})
    assert any("input source" in x for x in w), f"warning missed for trust={trust!r}"


# --- TM-2: a backtick in any string field must round-trip render -> parse ---
def test_tm2_backtick_field_round_trips():
    data = {"schema": "openant-threat-model", "schema_version": 1,
            "application_type": "custom:x",
            "purpose": "runs ```bash deploy``` on push", "impact_statement": "y"}
    back = T.parse_threat_model_md(T.render_threat_model_md(data))
    assert back.get("purpose") == data["purpose"]


# --- ML-1: a non-string `finding` must not crash parse_response ---
@pytest.mark.parametrize("literal", ["123", "null", '["x"]'])
def test_ml1_non_string_finding_no_crash(literal):
    r = A.parse_response('{"finding": %s}' % literal)       # was AttributeError
    assert "verdict" in r
