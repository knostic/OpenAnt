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
    html = open(out).read()
    # not just no-crash: the finding must actually render (else a refactor that skips
    # the row for a non-fix reason would keep the test green)
    assert "a.py:f" in html and "vulnerable" in html


# --- GO-3: an 'error' (unanalyzed) unit must be surfaced, not invisible ---
def test_go3_error_verdict_surfaced():
    exp = {"results": [{"route_key": "a.py:f", "finding": "error"}]}
    out = os.path.join(tempfile.mkdtemp(), "r.html")
    H.generate_html_report(exp, {"units": []}, "", out)
    html = open(out).read()
    assert "Errored (unanalyzed)" in html          # stat card
    assert '"error"' in html                        # AND the charts (not just the card)


def test_go3_chart_does_not_reintroduce_injection():
    """GO-3's chart inclusion must add ONLY the known 'error' sentinel, never an
    arbitrary model-supplied verdict — else it re-opens GO-1 via json.dumps labels."""
    exp = {"results": [
        {"route_key": "a.py:f", "finding": "error"},
        {"route_key": "b.py:g", "finding": "<svg onload=alert(1)>"},
    ]}
    out = os.path.join(tempfile.mkdtemp(), "r.html")
    H.generate_html_report(exp, {"units": []}, "", out)
    html = open(out).read()
    assert '"error"' in html                        # sentinel charted
    assert "<svg onload=alert(1)>" not in html      # arbitrary verdict NOT injected


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


# --- ML-1 / R2D-5: a non-string `finding` -> countable ERROR, not a garbage verdict ---
@pytest.mark.parametrize("literal", ["123", "null", '["x"]', "true"])
def test_ml1_non_string_finding_maps_to_error(literal):
    r = A.parse_response('{"finding": %s}' % literal)       # was AttributeError, then garbage
    assert r.get("verdict") == "ERROR"                      # not "['X']"/"123"/"NONE" etc.


def test_ml1_string_finding_still_maps():
    assert A.parse_response('{"finding": "vulnerable"}')["verdict"] == "VULNERABLE"


# --- R2B-2: a null short_name on a disclosure-eligible finding must not crash generate_all ---
def test_r2b2_null_short_name_disclosure_no_crash(tmp_path, monkeypatch):
    import json
    import report.generator as G
    monkeypatch.setattr(G, "generate_summary_report", lambda *a, **k: ("summary", {}))
    monkeypatch.setattr(G, "generate_disclosure", lambda *a, **k: ("disclosure body", {}))
    pipeline = {
        "repository": {"name": "acme/app"},
        "analysis_date": "2026-07-30", "application_type": "web_app",
        "pipeline_stats": {}, "results": [],
        "findings": [{
            "id": "F1", "name": "n", "short_name": None,      # null short_name (passes presence-only validation)
            "stage2_verdict": "confirmed",                     # disclosure-eligible
            "stage1_verdict": "vulnerable",
            "location": {"file": "a.py", "function": "f"},
            "cwe_id": 89, "cwe_name": "SQLi",
        }],
    }
    p = tmp_path / "pipeline_output.json"; p.write_text(json.dumps(pipeline))
    out = tmp_path / "out"; out.mkdir()

    class _StubRegistry:
        def get(self, key): return object()

    G.generate_all(str(p), str(out), registry=_StubRegistry())   # pre-fix: None.replace -> AttributeError
    discs = list((out / "disclosures").glob("*.md"))
    assert discs, "no disclosure written"
    assert "F1" in discs[0].name, "id fallback not used for null short_name"


# --- R2B-1: ParseResult.to_dict must include the derived `degraded` flag ---
def test_r2b1_parse_envelope_includes_degraded():
    from core.schemas import ParseResult
    assert ParseResult(dataset_path="x", parse_errors=["boom"]).to_dict()["degraded"] is True
    assert ParseResult(dataset_path="x", parse_errors=[]).to_dict()["degraded"] is False


# --- R3A-1: a CRLF / autocrlf threat-model file must still parse (MULTILINE $ vs \r) ---
def test_r3a1_crlf_threat_model_parses():
    data = {"schema": "openant-threat-model", "schema_version": 1,
            "application_type": "custom:x", "purpose": "p", "impact_statement": "y"}
    crlf = T.render_threat_model_md(data).replace("\n", "\r\n")
    assert T.parse_threat_model_md(crlf).get("purpose") == "p"


# --- R3B-1: dynamic-test evidence must survive a checkpoint resume round-trip ---
def test_r3b1_dynamic_test_evidence_survives_resume():
    from utilities.dynamic_tester.models import DynamicTestResult, TestEvidence
    r = DynamicTestResult(finding_id="f", status="CONFIRMED", details="d",
                          evidence=[TestEvidence("command_output", "uid=0(root)")])
    cp = r.to_dict()
    restored = [TestEvidence(type=e.get("type", ""), content=e.get("content", ""))
                for e in cp.get("evidence", []) if isinstance(e, dict)]
    assert len(restored) == 1 and restored[0].content == "uid=0(root)"


# --- R4B-1: a qualified 'untrusted (...)' boundary must NOT re-enable local-only suppression ---
def test_r4b1_qualified_untrusted_not_suppressed():
    from context.application_context import ApplicationContext as AC

    def mk(tb):
        return AC(application_type="library", purpose="x",
                  requires_remote_trigger=False, trust_boundaries=tb)
    assert mk({"n": "untrusted (attacker-controlled)"}).suppress_local_only() is False
    assert mk({"n": "Untrusted"}).suppress_local_only() is False
    assert mk({"n": "trusted"}).suppress_local_only() is True          # control unchanged


# --- R4B-3: a non-dict trust_boundaries (LLM hallucination) must not crash ---
def test_r4b3_non_dict_trust_boundaries_coerced():
    from context.application_context import ApplicationContext as AC
    ac = AC(application_type="library", purpose="x",
            requires_remote_trigger=False, trust_boundaries=["network: untrusted"])
    ac.suppress_local_only()                                            # must not raise
    assert isinstance(ac.trust_boundaries, dict)


# --- TM-2 / R2D-3: mixed-length fences (3-tick decoy + real 4-tick) must not desync ---
def test_tm2_mixed_length_fences_extract_real_block():
    data = {"schema": "openant-threat-model", "schema_version": 1,
            "application_type": "custom:x",
            "purpose": "runs ```bash``` deploy", "impact_statement": "y"}
    mixed = "```json\nDECOY not closed with 3 ticks\n\n" + T.render_threat_model_md(data)
    assert T.parse_threat_model_md(mixed).get("purpose") == data["purpose"]
