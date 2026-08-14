"""Regression tests: a parse-failure ERROR from parse_response must be retryable
in-run, so a malformed-but-recoverable model response is re-attempted instead of
permanently masking the unit's true verdict.

Wired seam under test mirrors core/analyzer.py: the detection retry pass computes
    retryable_indices = [i for i, r in enumerate(results)
                         if r and is_retryable_error(r.get("error"))]
where results[i] is the *inner* result dict returned by parse_response (via
analyze_unit / _run_detection). So the faithful unit-level check is:
    is_retryable_error(parse_response(<unparseable>).get("error"))
"""
from core.analysis_core import parse_response
from utilities.rate_limiter import is_retryable_error


# A response with no parseable JSON object at all (no braces) -> ERROR verdict.
NO_JSON = "I cannot produce JSON here. In prose: the code is SAFE."

# The realistic false-error shape: an example object then the real answer.
# Two top-level objects -> json.loads raises "Extra data" -> brace-grab span
# holds both -> also raises -> ERROR verdict, even though a good verdict existed.
EXAMPLE_THEN_REAL = (
    'Example format:\n{"verdict": "SAFE"}\n\n'
    'Actual analysis:\n{"verdict": "VULNERABLE", "confidence": 0.95}'
)

# A recoverable-parse response: prose prefix + exactly one valid object, no
# trailing brace. The brace-grab SUCCEEDS here -> verdict SAFE, NOT an error.
RECOVERABLE_PARSE = 'Here is my analysis.\n{"verdict": "SAFE", "confidence": 0.9}'


def test_no_json_parse_failure_is_retryable():
    result = parse_response(NO_JSON)
    assert result["verdict"] == "ERROR"
    # BUG (RED on pristine): the ERROR dict carries no top-level `error` key, so
    # is_retryable_error(None) is False and analyzer.py:534 never re-attempts it.
    assert is_retryable_error(result.get("error")) is True


def test_example_then_real_parse_failure_is_retryable():
    result = parse_response(EXAMPLE_THEN_REAL)
    assert result["verdict"] == "ERROR"
    assert is_retryable_error(result.get("error")) is True


def test_parse_error_dict_shape():
    result = parse_response(NO_JSON)
    err = result.get("error")
    assert isinstance(err, dict)
    assert err.get("type") == "parse_error"


def test_is_retryable_error_classifies_parse_error_type():
    # The classifier itself must treat a structured parse_error as retryable.
    assert is_retryable_error({"type": "parse_error"}) is True


def test_recoverable_parse_is_not_retryable():
    # Over-correction guard: a response the brace-grab correctly parses must keep
    # its verdict and must NOT be tagged retryable (no correct verdict re-run).
    result = parse_response(RECOVERABLE_PARSE)
    assert result["verdict"] == "SAFE"
    assert result.get("error") is None
    assert is_retryable_error(result.get("error")) is False
