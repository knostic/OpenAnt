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


def test_parse_response_prose_and_code_braces_before_json():
    """A thinking-on model emits prose + a code snippet (with braces) before the
    final JSON verdict. The naive find('{')/rfind('}') span mis-decodes; the
    raw_decode scan must return the trailing assessment object, not ERROR."""
    from core.analysis_core import parse_response
    resp = (
        "## Analysis\n"
        "Here is the function:\n"
        "```rust\nfn f() { if x == 0 { return; } }\n```\n"
        "The `x == 0` case is guarded. Not exploitable.\n\n"
        '{"finding": "safe", "confidence": 0.82, "cwe_id": 0, "reasoning": "guarded"}'
    )
    out = parse_response(resp)
    assert out.get("verdict") == "SAFE", out


def test_parse_response_ignores_trailing_non_verdict_json_block():
    """A thinking-on model emits the verdict, THEN a remediation code block whose
    body is itself valid JSON. The scan must return the VERDICT object, not the
    trailing config dict. Keeping the last decodable dict unconditionally would
    return the config (no verdict, no error) -- silently dropping the unit and
    bypassing the parse_error retry tag. Requiring a verdict/finding key fixes it."""
    from core.analysis_core import parse_response
    resp = (
        "## Security Analysis\n"
        "The handler concatenates user input into the SQL string.\n\n"
        '{"finding": "vulnerable", "confidence": 0.9, "cwe_id": 89, "reasoning": "x"}\n\n'
        "### Recommended fix\n"
        "```json\n"
        '{"use_prepared_statements": true, "escape": "all"}\n'
        "```\n"
    )
    out = parse_response(resp)
    assert out.get("verdict") == "VULNERABLE", out


def test_parse_response_no_verdict_dict_still_tagged_for_retry():
    """When nothing decodable carries a verdict/finding key, parse_response must
    fall through to the ERROR return WITH the parse_error tag, so #236's in-run
    retry pass re-runs the unit instead of silently dropping it."""
    from core.analysis_core import parse_response
    resp = "Here is some config:\n```json\n{\"debug\": true, \"level\": 3}\n```\n"
    out = parse_response(resp)
    assert out.get("verdict") == "ERROR", out
    assert out.get("error", {}).get("type") == "parse_error", out


def test_parse_response_trailing_verdict_example_does_not_override_real_verdict():
    """False-negative guard: a real VULNERABLE verdict followed by a trailing
    'example: {SAFE}' block must NOT be silently downgraded to SAFE. Two
    verdict-bearing objects are ambiguous, so parse_response must refuse to guess
    and route to ERROR + retryable (never return SAFE)."""
    from core.analysis_core import parse_response
    from utilities.rate_limiter import is_retryable_error
    resp = (
        '{"verdict": "VULNERABLE", "confidence": 0.95, "cwe_id": 89}\n\n'
        "For reference, a safe reply would look like:\n"
        '{"verdict": "SAFE"}'
    )
    out = parse_response(resp)
    assert out.get("verdict") != "SAFE", out          # never a false negative
    assert out.get("verdict") == "ERROR", out
    assert is_retryable_error(out.get("error")) is True, out


def test_parse_response_malformed_outer_with_nested_example_is_not_false_negative():
    """REGRESSION (bug-hunt 2026-08-15): a malformed OUTER verdict object (e.g. a
    trailing comma — a very common LLM slip) that contains a nested example dict
    with a verdict/finding key must NOT have the nested example recovered as THE
    verdict. The real outer verdict is VULNERABLE; returning the nested SAFE is a
    silent false negative in a SAST tool. Master returns ERROR+parse_error here
    (→ JSONCorrector/#236 retry can recover the real verdict); PR-1 must not
    regress that to SAFE. All three inputs carry a real VULNERABLE outer."""
    from core.analysis_core import parse_response
    bad_inputs = [
        '{"verdict":"VULNERABLE", "note":{"finding":"safe"},}',              # trailing comma
        "{'verdict': 'VULNERABLE', 'ex': {\"finding\": \"safe\"}}",          # single-quoted outer
        '{"verdict":"VULNERABLE","cwe_id":89,"ex":{"finding":"safe"}, oops}',# junk tail
    ]
    for inp in bad_inputs:
        out = parse_response(inp)
        assert out.get("verdict") != "SAFE", f"FALSE NEGATIVE on {inp!r}: {out}"
        # must be ERROR so analyze_unit's JSONCorrector/#236 retry fires (verdict in ERROR/None)
        assert out.get("verdict") == "ERROR", f"expected ERROR (retryable) on {inp!r}: {out}"


def test_parse_response_depth0_scan_full_matrix():
    """PY-1 fix (depth-0 scan, sol-consulted): the full behavior matrix. Recover a
    verdict ONLY when exactly one DEPTH-0 verdict object decodes; a nested object
    inside a malformed outer must never be recovered (silent-FN guard)."""
    from core.analysis_core import parse_response as p
    # must-pass recoveries
    assert p('## Analysis\n```rust\nfn f() { if x==0 { return; } }\n```\nGuarded.\n\n{"finding":"safe","cwe_id":0}').get("verdict") == "SAFE"
    assert p('{"verdict":"SAFE","meta":{"x":1}}').get("verdict") == "SAFE"           # nested non-verdict not double-counted
    assert p('{"verdict":"VULNERABLE","reasoning":"has a { brace in string"}').get("verdict") == "VULNERABLE"  # brace in string value
    # ambiguous -> ERROR (both orders)
    assert p('Example: {"verdict":"SAFE"} ... Actual: {"verdict":"VULNERABLE"}').get("verdict") == "ERROR"
    assert p('Real: {"verdict":"VULNERABLE"} ... Example: {"verdict":"SAFE"}').get("verdict") == "ERROR"
    # malformed-outer + nested example -> ERROR, never the nested SAFE (the regression)
    for bad in ['{"verdict":"VULNERABLE", "note":{"finding":"safe"},}',
                "{'verdict': 'VULNERABLE', 'ex': {\"finding\": \"safe\"}}",
                '{"verdict":"VULNERABLE","cwe_id":89,"ex":{"finding":"safe"}, oops}']:
        assert p(bad).get("verdict") == "ERROR", bad
    # unbalanced brace in code before a real verdict -> safe-fail ERROR (depth never returns to 0)
    assert p('```\ndef f(): return {  # oops unbalanced\n```\n{"finding":"safe"}').get("verdict") == "ERROR"
    # truncated / no close -> ERROR
    assert p('{"verdict":"VULNERABLE"').get("verdict") == "ERROR"
    assert p('no json at all here').get("verdict") == "ERROR"


def test_parse_response_malformed_real_beside_valid_example_sibling():
    """PY-NEW-1 (round-2 bug hunt): a MALFORMED real verdict object sitting BESIDE
    a well-formed example sibling must NOT recover the example. Only the clean
    sibling decodes, but the malformed span still carries a verdict key -> ambiguous
    -> ERROR (retryable), never the sibling's SAFE. Distinct from the nested case."""
    from core.analysis_core import parse_response as p
    for bad in [
        'Actual analysis:\n{"verdict": "VULNERABLE", "confidence": 0.95,}\n\nFor reference the safe form:\n{"verdict": "SAFE"}',
        'Result: {"verdict": "VULNERABLE" "cwe_id": 79}\nExample clean unit: {"verdict": "SAFE"}',
    ]:
        out = p(bad)
        assert out.get("verdict") == "ERROR", (bad, out)


def test_parse_response_top_level_array_does_not_crash():
    """PY-2 (bug hunt): a top-level JSON ARRAY (array-of-findings) must not raise
    TypeError from _normalize_result. It routes through the depth-0 scanner, which
    recovers a lone verdict object inside the array."""
    from core.analysis_core import parse_response as p
    assert p('[{"verdict": "SAFE"}]').get("verdict") == "SAFE"
    assert p('```json\n[{"verdict":"VULNERABLE"}]\n```').get("verdict") == "VULNERABLE"
    # two verdicts in the array -> ambiguous -> ERROR, still no crash
    assert p('[{"verdict":"SAFE"},{"verdict":"VULNERABLE"}]').get("verdict") == "ERROR"
    # a non-object, non-recoverable top-level (scalar) -> ERROR, no crash
    assert p('42').get("verdict") == "ERROR"


def test_parse_response_verdict_shaped_preamble_prefers_retry_over_false_negative():
    """ACCEPTED trade-off (round-3 bug hunt): when the preamble echoes verdict-SHAPED
    broken JSON (e.g. analyzed code `{"verdict": v}`) beside a lone clean verdict, the
    parser routes to ERROR+retryable rather than recover — the safe direction. It is a
    recovery-rate cost (the in-run retry re-derives the verdict), NOT a wrong verdict,
    and it is what prevents the PY-NEW-1 false negative (malformed real verdict beside a
    clean example being returned as SAFE). Pinned so the trade-off is intentional."""
    from core.analysis_core import parse_response as p
    from utilities.rate_limiter import is_retryable_error
    out = p('The sink builds {"verdict": v} dynamically.\nFinal: {"verdict":"VULNERABLE"}')
    assert out.get("verdict") == "ERROR"                       # not a silently-wrong verdict
    assert is_retryable_error(out.get("error")) is True        # self-heals via the in-run retry
