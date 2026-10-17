"""#770: a Google 5xx keeps its HTTP status through the redaction and the
error_info dict, so analyze's dict-first retry arm agrees with the string arm.

The google-genai SDK's ``ServerError``/``APIError`` family carries the HTTP
code on ``.code`` (not ``.status_code`` — code-traced at the tested 2.21.0).
``redacted_cause_from`` copied only ``.status_code``/``.request_id`` and
``_build_error_info`` read only ``.status_code``, so a Google 5xx reached
``is_retryable_error(dict)`` as ``{'type': 'api_status'}`` with NO status —
defaulted to 0 -> never retried — while the same exception's redacted STRING
retried (``503`` matches the 5xx substring arm). PR #716 flipped analyze's
check to dict-first, so the auto-retry pass silently stopped retrying
transient Google 5xx units.

The fix (#770's suggested shape, validated, both branches): ``_http_status_from``
returns the first of ``.status_code``/``.code`` that VALIDATES as an HTTP status
(int, not bool, in 100-599) — a generic ``.code`` (an errno, an exit code,
OpenAI's string error codes) never synthesizes a bogus status, and a non-int
``.status_code`` never reaches the dict arm's ``>= 500`` compare as a
TypeError that aborts the retry pass; both the redaction
(``redacted_cause_from``) and the dict (``_build_error_info``) read through
it. NOT offered as a fix and locked against here: treating a missing status
on an ``api_status`` dict as retryable (it would also retry permanent Google
4xx the string arm never retried).
"""

from utilities.context_enhancer import _build_error_info
from utilities.rate_limiter import is_retryable_error
from utilities.llm.adapter import LLMResponseError
from utilities.llm._redact import RedactedCause, redacted_cause_from


class GoogleShapedSDKError(Exception):
    """The google-genai ServerError/APIError attribute shape (2.21.0):
    ``.code`` carries the HTTP status; there is no ``.status_code``."""


def _google_5xx(code=503):
    exc = GoogleShapedSDKError(f"{code} UNAVAILABLE; please retry")
    exc.code = code
    return exc


def _google_4xx(code=404):
    exc = GoogleShapedSDKError(f"{code} NOT_FOUND")
    exc.code = code
    return exc


# --------------------------------------------------------------------------
# WITNESSES at the #770 base: the five dict/redaction rows fail BY ASSERTION
# (the status never reaches them); the two helper rows fail by ABSENCE (the
# lazy import — the helper is new at base). test_a_missing_status_stays_
# non_retryable PASSES at base by design: the anti-fix LOCK (the issue's
# explicit not-offered trade), not a witness.

def test_the_status_helper_reads_the_google_code_shape():
    """``_http_status_from`` is the one status read: ``.status_code`` when
    IT validates as an HTTP status, else the validated ``.code``."""
    from utilities.llm._redact import _http_status_from
    assert _http_status_from(_google_5xx()) == 503, (
        "the google-genai .code shape carries the HTTP status (#770)")
    class AnthropicShaped(Exception):
        pass
    a = AnthropicShaped("overloaded_error")
    a.status_code = 529
    assert _http_status_from(a) == 529
    assert _http_status_from(GoogleShapedSDKError("no attributes")) is None
    a_str = AnthropicShaped("string status")
    a_str.status_code = "503"
    assert _http_status_from(a_str) is None, (
        "a non-int .status_code is rejected too — never passed to the "
        ">=500 compare as a TypeError that aborts the retry pass (#770)")
    both = AnthropicShaped("string status with a valid .code")
    both.status_code = "503"
    both.code = 503
    assert _http_status_from(both) == 503, (
        "an invalid .status_code falls through to the validated .code — "
        "the one new behavior the unified loop adds over the base's raw "
        "pass-through (which would have TypeErrored downstream) (#770)")
    prec = AnthropicShaped("valid status, out-of-range code")
    prec.status_code = 404
    prec.code = 13
    assert _http_status_from(prec) == 404, (
        "a VALID .status_code wins over .code — precedence pinned (#770)")


def test_the_status_helper_never_synthesizes_from_a_generic_code():
    """The validation gate: a generic ``.code`` never becomes a status."""
    from utilities.llm._redact import _http_status_from
    class OpenAIShaped(Exception):
        pass
    o = OpenAIShaped("server_error")
    o.code = "server_error"          # OpenAI's string error codes
    assert _http_status_from(o) is None, (
        "a string .code never synthesizes a status (#770)")
    class Errno(Exception):
        pass
    e = Errno("permissions")
    e.code = 13                      # an errno: int, below the HTTP range
    assert _http_status_from(e) is None, (
        "an out-of-range int .code never synthesizes a status (#770)")
    class Flag(Exception):
        pass
    f = Flag("flag")
    f.code = True                    # bools are ints; the bool gate matters
    assert _http_status_from(f) is None, (
        "a bool .code (an int subclass) never synthesizes a status (#770)")


def test_the_redaction_carries_the_google_status():
    """The redaction path: a Google 5xx redacted as ``__cause__`` keeps the
    status the retry verdict reads."""
    cause = redacted_cause_from(_google_5xx())
    assert isinstance(cause, RedactedCause)
    assert cause.status_code == 503, (
        "redacted_cause_from falls back to the validated .code — a redacted "
        "Google 5xx must keep the status its retry verdict reads (#770)")


def test_the_error_info_dict_carries_the_google_status_through_the_cause():
    """The #716 dict arm: a Google 5xx chained (redacted) on an
    ``LLMResponseError`` reaches ``is_retryable_error(dict)`` WITH the
    status — both arms retry the same transient."""
    sdk = _google_5xx()
    err = LLMResponseError(f"{sdk}")
    err.__cause__ = redacted_cause_from(sdk)
    info = _build_error_info(err)
    assert info["type"] == "api_status", (
        "an LLMResponseError builds an api_status dict (#770)")
    assert info.get("status_code") == 503, (
        "the redacted Google cause's validated .code reaches the dict (#770)")
    assert is_retryable_error(info) is True, (
        "a transient Google 5xx is retried on the dict arm — the #716 "
        "preference flip's silent regression (#770)")


def test_the_error_info_dict_carries_the_status_off_a_raw_sdk_cause():
    """The unredacted route: the raw SDK exception chained directly (an
    adapter path that has not gone through redaction) synthesizes the
    status through the same helper."""
    err = LLMResponseError("503 UNAVAILABLE; please retry")
    err.__cause__ = _google_5xx()
    info = _build_error_info(err)
    assert info.get("status_code") == 503, (
        "_build_error_info reads the validated status off a raw Google "
        "SDK __cause__ (#770)")
    assert is_retryable_error(info) is True, (
        "the raw-cause route retries the same transient (#770)")


def test_the_string_and_dict_arms_agree_on_the_google_5xx():
    """The #663 parity contract, the #770 instance: the SAME transient
    Google 5xx (the 503 the issue measured — the class Gemini emits:
    500/503/504) gets the SAME verdict through both shapes. The arms'
    5xx boundary classes differ by design (the string arm is an explicit
    allowlist, the dict arm ``>= 500`` — a pre-existing asymmetry every
    ``.status_code`` SDK already carries, not this fix's claim to reverse)."""
    sdk = _google_5xx()
    err = LLMResponseError(str(sdk))
    err.__cause__ = redacted_cause_from(sdk)
    assert is_retryable_error(str(sdk)) is True, (
        "the string arm retried the transient all along (#770)")
    assert is_retryable_error(_build_error_info(err)) is True, (
        "the dict arm agrees with the string arm (#770)")


def test_a_missing_status_stays_non_retryable():
    """The NOT-offered fix, locked against: a status-less ``api_status``
    dict is NOT retryable — treating it as such would also retry permanent
    Google 4xx the string arm never retried (the issue's explicit trade)."""
    err = LLMResponseError("no status anywhere")
    info = _build_error_info(err)
    assert info["type"] == "api_status"
    assert "status_code" not in info, (
        "no status to find — none is synthesized (#770)")
    assert is_retryable_error(info) is False, (
        "the status-less api_status dict stays non-retryable (#770)")


def test_a_google_4xx_synthesizes_but_stays_non_retryable():
    """The validation gate's other half: a 404 DOES synthesize the status
    (the shape is honest) and the 4xx class stays non-retryable — the
    string arm's behavior, preserved."""
    err = LLMResponseError("404 NOT_FOUND")
    err.__cause__ = _google_4xx()
    info = _build_error_info(err)
    assert info.get("status_code") == 404, (
        "the validated .code shape is provider-honest, 4xx included (#770)")
    assert is_retryable_error(info) is False, (
        "a permanent 4xx is not retried on either arm (#770)")
    assert is_retryable_error("404 NOT_FOUND") is False