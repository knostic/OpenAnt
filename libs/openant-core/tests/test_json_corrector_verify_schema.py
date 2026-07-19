"""Regression test for finding verifier-jscorrect-prompt-stage1-schema-mismatch.

The finding_verifier's Stage-2 (verify) response shape is
``{agree, correct_finding, explanation, exploit_path, security_weakness}``
(see VERIFICATION_TOOLS "finish" schema and ``_parse_finish_result``).

Before the fix, ``FindingVerifier._parse_json_from_text`` fell back to
``JSONCorrector.attempt_correction`` which ALWAYS used the Stage-1 (analyze)
extraction prompt/schema (``verdict``/``vulnerabilities``/``reasoning``) and
only accepted a ``verdict``/``finding`` key. A perfectly valid *verify*
response therefore:
  1. was asked for in the wrong schema, and
  2. was rejected as ``verdict == "ERROR"`` (no ``verdict``/``finding`` key),
so a real verification result was silently dropped (mis-corrected/rejected).
"""
import json

import pytest

from utilities.json_corrector import JSONCorrector


class _ToolAdapter:
    name = "anthropic"
    supports_tools = True

    def complete(self, **kwargs):  # pragma: no cover - never called
        raise AssertionError("adapter.complete must not be called in this test")

    def validate(self, model):  # pragma: no cover
        pass


def _tool_binding():
    from utilities.llm import PhaseBinding

    return PhaseBinding(
        phase="verify",
        adapter=_ToolAdapter(),
        model="claude-test",
        provider_name="anthropic",
    )


VERIFY_RESPONSE = {
    "agree": False,
    "correct_finding": "vulnerable",
    "explanation": "attacker input reaches the sink unchanged",
}


def test_finding_verifier_correction_preserves_verify_schema(monkeypatch):
    """End-to-end through the real anchor: a malformed verify text response
    must be corrected into the VERIFY shape (agree/correct_finding/explanation),
    not rejected, and the correction prompt must ask for the verify schema."""
    import utilities.json_corrector as jc
    from utilities.finding_verifier import FindingVerifier

    captured = {}

    def fake_simple_text(binding, prompt, **kwargs):
        captured["prompt"] = prompt
        return json.dumps(VERIFY_RESPONSE)

    monkeypatch.setattr(jc, "simple_text", fake_simple_text)

    fv = FindingVerifier(index=object(), binding=_tool_binding())

    # Prose with no JSON braces -> forces the LLM-correction fallback path.
    text = "Here is my verification analysis in plain prose with no json object at all"
    out = fv._parse_json_from_text(text)

    # (1) correction must NOT be rejected
    assert out is not None, "valid verify response was rejected by JSON correction"
    # (2) verify schema preserved for _parse_finish_result
    assert out.get("correct_finding") == "vulnerable"
    assert out.get("agree") is False
    # (3) the correction prompt must describe the VERIFY schema, not analyze-only
    assert "correct_finding" in captured["prompt"]
    assert "agree" in captured["prompt"]


def test_attempt_correction_accepts_verify_verdict(monkeypatch):
    """Unit level: attempt_correction must surface a verify-shaped dict
    (correct_finding present, no verdict field) instead of returning ERROR."""
    import utilities.json_corrector as jc

    monkeypatch.setattr(
        jc, "simple_text", lambda binding, prompt, **k: json.dumps(VERIFY_RESPONSE)
    )
    out = JSONCorrector(_tool_binding()).attempt_correction(
        "garbled prose then " + json.dumps(VERIFY_RESPONSE)
    )
    assert out.get("verdict") != "ERROR"
    assert out.get("correct_finding") == "vulnerable"
    assert out.get("agree") is False


def test_verify_extraction_prompt_describes_verify_schema():
    """The verify extraction prompt exists and asks for the verify fields."""
    from utilities.json_corrector import get_verify_extraction_prompt

    prompt = get_verify_extraction_prompt("some raw response")
    assert "agree" in prompt
    assert "correct_finding" in prompt
    assert "explanation" in prompt
