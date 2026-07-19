"""
Conformance test for jsoncorrect-schema-mismatch-enhance-review.

Bug: utilities/json_corrector.py hardcodes the security-analysis extraction
schema (verdict / vulnerabilities / reasoning) AND gates correction success on
the presence of a ``verdict`` field. But it is also invoked by the enhance and
review phases, whose valid output shapes have NO verdict:

  * context_enhancer -> {missing_dependencies, additional_callers, data_flow,
                         imports, reasoning, confidence}
  * context_reviewer -> {context_complete, missing_items, confidence, reasoning}

So a malformed-but-recoverable enhance/review response is (a) prompted with the
WRONG schema (the LLM is told to emit verdict/vulnerabilities, destroying the
enhance/review data) and (b) even a perfectly-extracted enhance/review dict is
REJECTED by the verdict-only success gate and replaced with the ERROR sentinel.
The enhancement/review is then silently dropped.

The fix makes the corrector schema-aware: callers pass the expected ``schema``
string (used to build the extraction prompt) and ``required_keys`` (used to
validate the corrected shape).

    RED  on pristine core: attempt_correction/get_json_extraction_prompt take no
         schema kwarg -> TypeError; a valid enhance dict is dropped for ERROR.
    GREEN on patched core: enhance-shaped extraction survives; prompt reflects
         the requested schema; the default vuln path is unchanged.

Select the core under test with OPENANT_CORE_ROOT (defaults to the worktree).
"""

import os
import sys

_CORE_ROOT = os.environ.get(
    "OPENANT_CORE_ROOT",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
)
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)


ENHANCE_SCHEMA = """{
    "missing_dependencies": [],
    "additional_callers": [],
    "data_flow": {"inputs": [], "outputs": [], "tainted_variables": [], "security_relevant_flows": []},
    "imports": [],
    "reasoning": "analysis summary",
    "confidence": 0.0
}"""


def test_json_corrector_schema_shape():
    import utilities.json_corrector as jc
    from utilities.json_corrector import JSONCorrector

    # (1) The extraction prompt must reflect the requested (enhance) schema and
    #     NOT force the vuln verdict schema onto an enhance/review response.
    prompt = jc.get_json_extraction_prompt("some raw enhance response", schema=ENHANCE_SCHEMA)
    assert "missing_dependencies" in prompt, "extraction prompt ignored the requested schema"

    # This test stubs the module-global ``extract_json_with_llm``; snapshot and
    # restore it so the stub does not leak into other test modules that patch
    # ``simple_text`` instead (e.g. test_json_corrector_verify_schema).
    _orig_extract = jc.extract_json_with_llm
    try:
        # (2) A perfectly-extracted enhance-shaped dict (no verdict) must SURVIVE the
        #     correction gate rather than being replaced by the ERROR sentinel.
        good_enhance = {
            "missing_dependencies": [{"name": "authStrategy"}],
            "additional_callers": [],
            "data_flow": {"inputs": [], "outputs": [], "tainted_variables": [], "security_relevant_flows": []},
            "imports": [],
            "reasoning": "recovered",
            "confidence": 0.8,
        }
        jc.extract_json_with_llm = lambda binding, raw, schema=None: dict(good_enhance)
        corrected = JSONCorrector(binding=None).attempt_correction(
            "{ malformed enhance", schema=ENHANCE_SCHEMA, required_keys=["missing_dependencies"]
        )
        assert corrected.get("verdict") != "ERROR", (
            f"valid enhance response wrongly rejected as ERROR: {corrected!r}"
        )
        assert corrected.get("missing_dependencies") == [{"name": "authStrategy"}], (
            f"enhance data lost by corrector: {corrected!r}"
        )

        # (3) Backward-compat: the default (vuln) path is unchanged.
        jc.extract_json_with_llm = lambda binding, raw, schema=None: {
            "verdict": "VULNERABLE", "confidence": 0.9, "vulnerabilities": [], "reasoning": "x",
        }
        vuln = JSONCorrector(binding=None).attempt_correction("{ malformed vuln")
        assert vuln.get("verdict") == "VULNERABLE", f"vuln path regressed: {vuln!r}"
    finally:
        jc.extract_json_with_llm = _orig_extract

    print("PASS: corrector is schema-aware; enhance/review shape survives; vuln path intact")


if __name__ == "__main__":
    test_json_corrector_schema_shape()
