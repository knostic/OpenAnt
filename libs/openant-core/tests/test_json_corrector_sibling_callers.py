"""
Sibling-caller conformance test for jsoncorrect-schema-mismatch-enhance-review.

The base fix threaded the expected JSON ``schema`` / ``required_keys`` from
context_enhancer and context_reviewer into JSONCorrector so a malformed-but-
recoverable NON-verdict response isn't (a) prompted with the wrong vuln schema
and (b) rejected by the verdict-only success gate.

But the SAME ``json_corrector-called-with-non-verdict-shape`` pattern lives at
two other call sites that the base fix did NOT thread:

  * utilities/finding_verifier.py     _parse_json_from_text
        shape: {agree, correct_finding, explanation, exploit_path, ...} -- no verdict
  * utilities/ground_truth_challenger.py  _parse_json_response
        shape: {arbitration_verdict, confidence, reasoning, recommendation} -- no verdict

At both sites ``attempt_correction`` was called with the DEFAULT (vuln) schema
and the DEFAULT required_keys=["verdict"]. A perfectly-extracted verifier /
arbitration dict has no ``verdict`` key, so the corrector's success gate fails,
returns the ERROR sentinel, the caller's ``verdict != "ERROR"`` check drops it,
and the whole verification / challenge is silently lost.

    RED  (un-threaded callers): a valid non-verdict dict extracted by the LLM
         corrector is dropped -> _parse_* returns None.
    GREEN (threaded callers): the non-verdict dict survives with json_corrected.

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


def test_finding_verifier_recovers_non_verdict_finish_shape():
    """finding_verifier._parse_json_from_text must recover a `finish`-shaped
    (agree/correct_finding/explanation) dict via the LLM corrector, not drop it
    because the default corrector required a `verdict`."""
    import utilities.json_corrector as jc
    from utilities.finding_verifier import FindingVerifier

    finish_shape = {
        "agree": False,
        "correct_finding": "vulnerable",
        "explanation": "recovered exploit path",
        "exploit_path": {"entry_point": "req.query.next", "sink_reached": True},
        "security_weakness": None,
    }
    # The corrector's LLM extraction succeeds and returns the verifier shape.
    # Snapshot/restore the module global so this stub does not leak into other
    # test modules that patch ``simple_text`` instead.
    _orig_extract = jc.extract_json_with_llm
    try:
        jc.extract_json_with_llm = lambda binding, raw, schema=None: dict(finish_shape)

        # Build a verifier without running __init__ (only .binding is used here).
        verifier = FindingVerifier.__new__(FindingVerifier)
        verifier.binding = object()  # non-None so the correction path is taken

        # Malformed text: has braces (so it reaches the corrector) but is not JSON.
        recovered = verifier._parse_json_from_text("{ agree: false, correct_finding: vulnerable BROKEN")
    finally:
        jc.extract_json_with_llm = _orig_extract

    assert recovered is not None, (
        "verifier finish shape was dropped by the corrector (needs schema threading)"
    )
    assert recovered.get("agree") is False and recovered.get("correct_finding") == "vulnerable", (
        f"verification data lost by corrector: {recovered!r}"
    )
    assert recovered.get("json_corrected") is True


def test_ground_truth_challenger_recovers_arbitration_shape():
    """ground_truth_challenger._parse_json_response must recover an arbitration-
    shaped (arbitration_verdict/...) dict via the LLM corrector."""
    import utilities.json_corrector as jc
    from utilities.ground_truth_challenger import _parse_json_response

    arbitration_shape = {
        "arbitration_verdict": "MODEL_CORRECT",
        "confidence": 0.9,
        "reasoning": "recovered arbitration",
        "recommendation": "VULNERABLE",
    }
    # Snapshot/restore the module global so this stub does not leak into other
    # test modules that patch ``simple_text`` instead.
    _orig_extract = jc.extract_json_with_llm
    try:
        jc.extract_json_with_llm = lambda binding, raw, schema=None: dict(arbitration_shape)

        recovered = _parse_json_response(
            "{ arbitration_verdict: MODEL_CORRECT confidence 0.9 BROKEN",
            binding=object(),  # non-None so the correction path is taken
        )
    finally:
        jc.extract_json_with_llm = _orig_extract

    assert recovered is not None, (
        "arbitration shape was dropped by the corrector (needs schema threading)"
    )
    assert recovered.get("arbitration_verdict") == "MODEL_CORRECT", (
        f"arbitration data lost by corrector: {recovered!r}"
    )
    assert recovered.get("json_corrected") is True


if __name__ == "__main__":
    test_finding_verifier_recovers_non_verdict_finish_shape()
    test_ground_truth_challenger_recovers_arbitration_shape()
    print("PASS: sibling non-verdict callers (finding_verifier, ground_truth_challenger) recover their shape")
