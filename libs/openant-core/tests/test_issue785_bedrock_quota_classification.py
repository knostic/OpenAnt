"""Tests for issue #785 — the Bedrock adapter carries both halves of the
throttle/quota split (#663/#716).

The four sibling providers gate on ``kind`` (``if kind != "quota":
report_rate_limit``) and classify the quota surface by their provider's
markers. Bedrock was missed on both halves:

1. ``ServiceQuotaExceededException`` is an AWS **400** — it never reaches the
   rate-limit arms and lands in ``_classify_status_error``'s residual
   ``LLMResponseError`` ("a structural response problem") — the wrong label
   for an exhausted account quota, mislabelled to the kind-reading consumers.
2. Every Bedrock ``LLMRateLimitError`` is constructed without ``kind``, so it
   defaults to ``"throttle"`` — a quota-shaped 429 would arm the global
   all-worker pause AND be retried as transient: #716's exact bug.

The fix classifies by the **AWS error type** (the ``x-amzn-ErrorType``
header and the rest-json body's ``__type`` key — both normalized the
botocore way against the ``:URI``/``ns#Code`` wire suffixes; the message
prose is not a carrier).
"""
from __future__ import annotations

import pytest

import anthropic

from tests.test_llm_bedrock_adapter import _complete, _fake_http_resp, _stub_adapter
from utilities.llm import LLMResponseError, LLMRateLimitError
from utilities.rate_limiter import get_rate_limiter, reset_rate_limiter

QUOTA_TYPE = "ServiceQuotaExceededException"
THROTTLE_TYPE = "ThrottlingException"


def _http_resp(status, *, retry_after=None, error_type_header=None):
    resp = _fake_http_resp(status, retry_after=retry_after)
    if error_type_header is not None:
        resp.headers["x-amzn-ErrorType"] = error_type_header
    return resp


@pytest.fixture(autouse=True)
def _fresh_limiter():
    reset_rate_limiter()
    yield
    reset_rate_limiter()


def test_a_quota_400_is_classified_not_structural():
    """THE RED WITNESS (the issue's §1): the ServiceQuotaExceededException
    400 must surface as kind=quota — at base it falls to LLMResponseError
    ('a structural response problem'), mislabelled and invisible to the
    kind-reading consumers."""
    def respond(**kw):
        raise anthropic.APIStatusError(
            message="The model request exceeds the service quota for your account.",
            response=_http_resp(400, error_type_header=QUOTA_TYPE),
            body=None,
        )
    from utilities.llm.providers.bedrock import _rate_limit_kind
    probe = anthropic.APIStatusError(
        message="The model request exceeds the service quota for your account.",
        response=_http_resp(400, error_type_header=QUOTA_TYPE),
        body=None,
    )
    assert _rate_limit_kind(probe) == "quota", (
        "the classifier reads the AWS type from the header")
    adapter, _ = _stub_adapter(respond)
    with pytest.raises(LLMRateLimitError) as exc_info:
        _complete(adapter)
    assert exc_info.value.kind == "quota", (
        "an exhausted account quota must read as a rate limit of kind=quota — "
        "at base it is LLMResponseError, labelled 'a structural response "
        "problem' (#785)")


def test_a_quota_400_from_the_body_carries_the_same_kind():
    """The body carrier: the AWS rest-json ``__type`` key (the suffixed
    wire value), no header — classified the same."""
    def respond(**kw):
        raise anthropic.APIStatusError(
            message="ServiceQuotaExceededException: exceeds the service quota",
            response=_fake_http_resp(400),
            body={"__type": "com.amazonaws.bedrock#" + QUOTA_TYPE},
        )
    from utilities.llm.providers.bedrock import _rate_limit_kind
    probe = anthropic.APIStatusError(
        message="ServiceQuotaExceededException: exceeds the service quota",
        response=_fake_http_resp(400),
        body={"__type": "com.amazonaws.bedrock#" + QUOTA_TYPE},
    )
    assert _rate_limit_kind(probe) == "quota", (
        "the classifier reads the type from the body alone")
    adapter, _ = _stub_adapter(respond)
    with pytest.raises(LLMRateLimitError) as exc_info:
        _complete(adapter)
    assert exc_info.value.kind == "quota"


def test_a_quota_named_429_never_arms_the_global_pause():
    """THE RED WITNESS (the issue's §2 open question): a quota-shaped 429
    must NOT arm the global all-worker pause — at base both 429 arms report
    unconditionally and default kind=throttle (the two-sided #716 bug)."""
    def respond(**kw):
        raise anthropic.RateLimitError(
            message="throttled",
            response=_http_resp(429, retry_after="3", error_type_header=QUOTA_TYPE),
            body=None,
        )
    from utilities.llm.providers.bedrock import _rate_limit_kind
    probe = anthropic.RateLimitError(
        message="throttled",
        response=_http_resp(429, retry_after="3", error_type_header=QUOTA_TYPE),
        body=None,
    )
    assert _rate_limit_kind(probe) == "quota", (
        "the classifier reads the AWS type on the typed 429 arm's exception")
    adapter, _ = _stub_adapter(respond)
    with pytest.raises(LLMRateLimitError) as exc_info:
        _complete(adapter)
    assert exc_info.value.kind == "quota"
    assert not get_rate_limiter().is_in_backoff(), (
        "a hard limit must not stall all workers (#716's gate, the Bedrock arm)")


def test_an_ordinary_throttle_keeps_the_current_behavior():
    """A ThrottlingException 429: kind=throttle (explicit), the pause armed,
    retryable — the transient half preserved."""
    def respond(**kw):
        raise anthropic.RateLimitError(
            message="too many requests",
            response=_http_resp(429, retry_after="3", error_type_header=THROTTLE_TYPE),
            body=None,
        )
    adapter, _ = _stub_adapter(respond)
    with pytest.raises(LLMRateLimitError) as exc_info:
        _complete(adapter)
    assert exc_info.value.kind == "throttle"
    assert get_rate_limiter().is_in_backoff()


def test_an_unknown_429_retains_the_throttle_fallback():
    """No AWS type visible: kind=throttle (the default stays the default —
    the unknown stays transient)."""
    def respond(**kw):
        raise anthropic.RateLimitError(
            message="too many requests",
            response=_fake_http_resp(429, retry_after="3"),
            body=None,
        )
    adapter, _ = _stub_adapter(respond)
    with pytest.raises(LLMRateLimitError) as exc_info:
        _complete(adapter)
    assert exc_info.value.kind == "throttle"


def test_the_529_gateway_arm_propagates_the_kind():
    """The residual-classify 429/529 branch (the second arm): a quota-named
    529 from a compat gateway classifies quota and does not pause."""
    from utilities.llm.providers.bedrock import _rate_limit_kind
    probe = anthropic.APIStatusError(
        message="overloaded",
        response=_http_resp(529, retry_after="5", error_type_header=QUOTA_TYPE),
        body=None,
    )
    assert _rate_limit_kind(probe) == "quota", (
        "the classifier reads the AWS type on the residual arm's exception")
    def respond(**kw):
        raise anthropic.APIStatusError(
            message="overloaded",
            response=_http_resp(529, retry_after="5", error_type_header=QUOTA_TYPE),
            body=None,
        )
    adapter, _ = _stub_adapter(respond)
    with pytest.raises(LLMRateLimitError) as exc_info:
        _complete(adapter)
    assert exc_info.value.kind == "quota"
    assert not get_rate_limiter().is_in_backoff()


def test_the_retry_gate_honors_the_bedrock_quota():
    """The issue's check 5: a Bedrock-sourced kind=quota error is NOT
    transient at the retry gate (rate_limiter.py:247-252 — the gate exists
    at base; this LOCKs the plumbing end-to-end)."""
    from utilities.rate_limiter import is_retryable_error
    assert is_retryable_error({"type": "rate_limit", "kind": "quota"}) is False, (
        "the retry gate must refuse a Bedrock-sourced quota error")
    assert is_retryable_error({"type": "rate_limit", "kind": "throttle"}) is True, (
        "an ordinary throttle stays retryable at the same gate")


def test_the_other_400_stays_structural():
    """The LOCK: a plain 400 (no quota name, not the model-identifier arm)
    remains LLMResponseError — the classification narrows, never widens."""
    def respond(**kw):
        raise anthropic.APIStatusError(
            message="something malformed",
            response=_fake_http_resp(400),
            body=None,
        )
    adapter, _ = _stub_adapter(respond)
    with pytest.raises(LLMResponseError):
        _complete(adapter)
    assert not get_rate_limiter().is_in_backoff()


def test_validate_surfaces_the_kind_on_its_preflight_429():
    """The wiring witness (the C4 E1/E2 finding): validate()'s 429 arm —
    a one-shot preflight that deliberately never reports — must still
    SURFACE the kind, so a caller reading validate's error learns quota
    vs throttle (the preflight design unchanged; the classification added)."""
    from utilities.llm.providers.bedrock import BedrockAdapter
    from unittest.mock import MagicMock

    def respond(**kw):
        raise anthropic.RateLimitError(
            message="throttled",
            response=_http_resp(429, retry_after="3", error_type_header=QUOTA_TYPE),
            body=None,
        )
    client = MagicMock(spec=anthropic.AnthropicBedrock)
    client.messages = MagicMock()
    client.messages.create = MagicMock(side_effect=respond)
    adapter = BedrockAdapter(_client=client)
    with pytest.raises(LLMRateLimitError) as exc_info:
        adapter.validate(model="us.anthropic.claude-sonnet-4-6")
    err = exc_info.value
    assert isinstance(err, LLMRateLimitError)
    assert err.kind == "quota", (
        "validate's preflight 429 must carry the kind — the caller reads it "
        "without re-deriving the AWS type (#785, the wiring arm)")
    assert not get_rate_limiter().is_in_backoff(), (
        "validate never reports (the preflight design preserved)")


def test_the_suffixed_wire_header_forms_classify_quota():
    """T1 round-1 F1: the real AWS x-amzn-ErrorType carries a suffix —
    ``<Code>:<URI>`` or ``<ns>#<Code>`` (botocore's own normalization).
    The bare catalogue name is the one shape AWS does NOT send."""
    from utilities.llm.providers.bedrock import _rate_limit_kind
    for wire in (
        "ServiceQuotaExceededException:http://internal.amazon.com/coral",
        "com.amazonaws.bedrock#ServiceQuotaExceededException",
    ):
        probe = anthropic.APIStatusError(
            message="exceeds the service quota for your account.",
            response=_http_resp(400, error_type_header=wire),
            body=None,
        )
        assert _rate_limit_kind(probe) == "quota", (
            f"the suffixed wire form {wire!r} must normalize to quota "
            "(botocore's split/rsplit rule)")
    def respond(**kw):
        raise anthropic.APIStatusError(
            message="exceeds the service quota for your account.",
            response=_http_resp(400, error_type_header="com.amazonaws.bedrock#ServiceQuotaExceededException"),
            body=None,
        )
    adapter, _ = _stub_adapter(respond)
    with pytest.raises(LLMRateLimitError) as exc_info:
        _complete(adapter)
    assert exc_info.value.kind == "quota"


def test_a_throttle_whose_prose_mentions_quota_stays_throttle():
    """T1 round-1 F2: the message prose is NOT a carrier — a transient
    throttle whose body mentions the quota TYPE must not flip to quota
    (a false non-retryable inverts the over-seed safety rule)."""
    from utilities.llm.providers.bedrock import _rate_limit_kind
    probe = anthropic.RateLimitError(
        message="ThrottlingException: see ServiceQuotaExceededException docs",
        response=_http_resp(429, retry_after="3",
                            error_type_header="ThrottlingException:http://x/"),
        body=None,
    )
    assert _rate_limit_kind(probe) == "throttle", (
        "the prose mention must not classify quota — only the structured "
        "carriers (the header, the body type) count")
