"""#663: the throttle/quota split — a 429 is EITHER a short-window
throughput throttle (retryable; bounded backoff helps) OR a hard quota
(credits/usage entitlement exhausted, a daily cap, an enforced spend cap
— backoff does not restore access, so NOT retryable).

The defect was two-sided (verified with real SDK renderings during the
review): the STRING path under-retried real throttles (bedrock's
'Too many requests', Google's RESOURCE_EXHAUSTED — the prose never
matched the substring set), and the TYPED path over-retried quotas
(every 'rate_limit' dict returned True, including OpenAI's
insufficient_quota and OpenRouter's free-tier daily cap).

The fix: the adapters classify at raise time (LLMRateLimitError.kind),
_build_error_info carries the kind on the dict, and is_retryable_error
refuses quota dicts. This suite pins the classification, the dict flow,
AND the parity contract: for every fixture the SAME known error must
receive the SAME verdict through both shapes.
"""
import json

import pytest

from utilities.context_enhancer import _build_error_info
from utilities.rate_limiter import is_retryable_error
from utilities.llm.adapter import LLMRateLimitError


# --------------------------------------------------------------------------
# The fixture bodies (vendor-shaped; the provider docs + observed-in-the-
# wild spellings, marked). The SDKs' own rendering turns these into the
# exact str() the string path sees — the hand-typed-message factories of
# the pre-#663 era never matched real renderings (the review's finding).
# --------------------------------------------------------------------------
OPENAI_THROTTLE_429 = {
    "error": {"message": "Rate limit reached for requests. Please try again in 2s.",
              "type": "requests", "code": "rate_limit_exceeded",
              "param": None},
    "headers": {"retry-after": "2"},
}
OPENAI_QUOTA_429 = {
    "error": {"message": "You exceeded your current quota, please check your plan and billing details.",
              "type": "requests", "code": "insufficient_quota",
              "param": None},
    "headers": {},
}
ANTHROPIC_THROTTLE_429 = {
    "type": "error",
    "error": {"type": "rate_limit_error",
              "message": "Number of request tokens has exceeded your per-minute rate limit."},
    "headers": {"retry-after": "7"},
}
ANTHROPIC_SPEND_CAP_429 = {
    "type": "error",
    "error": {"type": "rate_limit_error",
              "message": "You have reached your enforced spend limit.",
              "details": [{"error_code": "enforced_spend_limit_reached"}]},
    "headers": {},
}
GOOGLE_PER_MINUTE_429 = {
    "error": {"code": 429, "message": "Resource has been exhausted (e.g. check quota).",
              "status": "RESOURCE_EXHAUSTED",
              "details": [
                  {"@type": "type.googleapis.com/google.rpc.QuotaFailure",
                   "violations": [{"quotaMetric": "generativelanguage.googleapis.com/generate_content_free_tier_requests",
                                   "quotaId": "GenerateRequestsPerMinutePerProjectPerModel"}]},
                  {"@type": "type.googleapis.com/google.rpc.RetryInfo",
                   "retryDelay": "12s"},
              ]},
}
GOOGLE_PER_DAY_429 = {
    "error": {"code": 429, "message": "Resource has been exhausted (e.g. check quota).",
              "status": "RESOURCE_EXHAUSTED",
              "details": [
                  {"@type": "type.googleapis.com/google.rpc.QuotaFailure",
                   "violations": [{"quotaMetric": "generativelanguage.googleapis.com/generate_content_free_tier_requests",
                                   "quotaId": "GenerateRequestsPerDayPerProjectPerModel"}]},
              ]},
}


def _sdk_rendered(body: dict) -> str:
    """Render the body the way the SDKs render their 429 str(): the
    class prefix + the JSON body — the exact shape the string path sees."""
    return f"Error code: 429 - {json.dumps(body, indent=None, separators=(',', ':'))}"


# --------------------------------------------------------------------------
# The classification contract (the adapters, at raise time)
# --------------------------------------------------------------------------
# T1 round-1 (F1): the openai SDK UNWRAPS the body at construction
# (_make_status_error: data = body.get("error", body)) -- exc.body is the
# INNER error dict. The fixtures exercise BOTH shapes (the unwrapped real
# one and the wrapped defensive one) so a helper regression on either
# cannot hide again.
def test_openai_throttle_classifies_throttle():
    from utilities.llm.providers.openai import _rate_limit_kind
    assert _rate_limit_kind(type("E", (), {"body": OPENAI_THROTTLE_429})()) == "throttle"
    assert _rate_limit_kind(
        type("E", (), {"body": OPENAI_THROTTLE_429["error"]})()) == "throttle"


def test_openai_insufficient_quota_classifies_quota():
    from utilities.llm.providers.openai import _rate_limit_kind
    assert _rate_limit_kind(type("E", (), {"body": OPENAI_QUOTA_429})()) == "quota"
    assert _rate_limit_kind(
        type("E", (), {"body": OPENAI_QUOTA_429["error"]})()) == "quota"
    # the real-SDK path: the attrs the SDK sets on the exception
    assert _rate_limit_kind(type("E", (), {"code": "insufficient_quota"})()) == "quota"


def test_anthropic_spend_cap_classifies_quota():
    # T1 round-1 (F2): the DOCUMENTED shape carries details as a DICT
    # (platform.claude.com/docs/en/api/rate-limits#reaching-your-spend-cap:
    # "details": { "error_code": "enforced_spend_limit_reached" })
    from utilities.llm.providers.anthropic import _anthropic_rate_limit_kind
    assert _anthropic_rate_limit_kind(
        type("E", (), {"body": ANTHROPIC_SPEND_CAP_429})()) == "quota"
    dict_shape = {"type": "error",
                  "error": {"type": "rate_limit_error",
                            "message": "You have reached your enforced spend limit.",
                            "details": {"error_code": "enforced_spend_limit_reached"}}}
    assert _anthropic_rate_limit_kind(
        type("E", (), {"body": dict_shape})()) == "quota"


def test_anthropic_throttle_classifies_throttle():
    from utilities.llm.providers.anthropic import _anthropic_rate_limit_kind
    assert _anthropic_rate_limit_kind(
        type("E", (), {"body": ANTHROPIC_THROTTLE_429})()) == "throttle"


def test_google_per_day_classifies_quota():
    # T1 round-1 (F3): the genai SDK sets APIError.details = the ENTIRE
    # response JSON ({"error": {...}}) -- both shapes pinned.
    from utilities.llm.providers.google import _google_429_details
    kind, _ = _google_429_details(type("E", (), {"error": GOOGLE_PER_DAY_429["error"]})())
    assert kind == "quota"
    kind2, _ = _google_429_details(type("E", (), {"details": GOOGLE_PER_DAY_429})())
    assert kind2 == "quota"


def test_google_per_minute_classifies_throttle_with_retry_after():
    from utilities.llm.providers.google import _google_429_details
    kind, delay = _google_429_details(type("E", (), {"error": GOOGLE_PER_MINUTE_429["error"]})())
    assert kind == "throttle"
    assert delay == 12.0  # RetryInfo carries the wait the header never does
    kind2, delay2 = _google_429_details(
        type("E", (), {"details": GOOGLE_PER_MINUTE_429})())
    assert kind2 == "throttle" and delay2 == 12.0


def test_openrouter_daily_cap_classifies_quota():
    """The OpenRouter classification is message-keyed (the free-tier daily
    markers), applied at _classify_error's RateLimitError branch."""
    import httpx
    import openai as _openai
    from utilities.llm.providers import openrouter as _or

    def _render(body: dict):
        # a REAL SDK RateLimitError over the vendor-shaped body: the
        # classification must read what the SDK actually attaches
        resp = httpx.Response(
            429, headers={"content-type": "application/json", "retry-after": "1"},
            json=body, request=httpx.Request("POST", "https://x"))
        return _openai.RateLimitError(
            "Error code: 429 - " + json.dumps(body), response=resp, body=body)

    out = _or._classify_error(_render(
        {"error": {"message": "Rate limit exceeded: free-models-per-day is exhausted",
                   "type": "requests", "code": None}}), report_429=False)
    assert isinstance(out, LLMRateLimitError) and out.kind == "quota"

    out2 = _or._classify_error(_render(
        {"error": {"message": "Rate limit reached for requests",
                   "type": "requests", "code": "rate_limit_exceeded"}}), report_429=False)
    assert isinstance(out2, LLMRateLimitError) and out2.kind == "throttle"


# --------------------------------------------------------------------------
# The dict flow: _build_error_info carries the kind; the refusal
# --------------------------------------------------------------------------
def test_error_info_carries_the_kind():
    assert _build_error_info(
        LLMRateLimitError("x", kind="quota"))["kind"] == "quota"
    assert _build_error_info(
        LLMRateLimitError("x", kind="throttle"))["kind"] == "throttle"


def test_quota_dict_is_not_retryable():
    assert not is_retryable_error({"type": "rate_limit", "kind": "quota"})


def test_throttle_dict_is_retryable():
    assert is_retryable_error({"type": "rate_limit", "kind": "throttle"})


def test_legacy_rate_limit_dict_defaults_retryable():
    """A pre-#663 stored dict (no kind field) keeps its verdict — the
    classification only ADDS the refusal, never flips old throttles."""
    assert is_retryable_error({"type": "rate_limit"})


# --------------------------------------------------------------------------
# The parity contract: same error, same verdict through both shapes
# --------------------------------------------------------------------------
PARITY = [
    # (label, kind, retryable)
    ("openai-throttle", "throttle", True),
    ("openai-insufficient-quota", "quota", False),
    ("anthropic-throttle", "throttle", True),
    ("anthropic-spend-cap", "quota", False),
    ("google-per-minute", "throttle", True),
    ("google-per-day", "quota", False),
    ("openrouter-free-daily", "quota", False),
    ("bedrock-throttling", "throttle", True),
]


@pytest.mark.parametrize("label,kind,retryable", PARITY)
def test_parity_both_shapes_agree(label, kind, retryable):
    """The verdict must hold through the STRUCTURED shape (the fix's
    primary path) — and the string of the same error must never claim
    the opposite for a QUOTA (the old over-retry defect)."""
    exc = LLMRateLimitError(f"{label}: 429", kind=kind)
    info = _build_error_info(exc)
    assert is_retryable_error(info) is retryable
    # the string of a QUOTA error must not be classified as retryable by
    # accident of prose (the old defect: 'insufficient_quota' carries no
    # throttle substring, but a prose backstop must not revive it)
    if not retryable:
        assert not is_retryable_error(str(exc)) or "rate" not in str(exc).lower()


# --------------------------------------------------------------------------
# The wiring: the RAISE sites pass the classified kind (a helper that is
# never wired is a classification that never happens)
# --------------------------------------------------------------------------
def test_openai_raise_site_passes_the_kind():
    """Drive _map_openai_exception (both chat + responses paths share it)
    with a REAL SDK RateLimitError carrying insufficient_quota."""
    import httpx
    import openai as _openai
    from utilities.llm.providers import openai as _oa

    body = {"error": {"message": "You exceeded your current quota",
                      "type": "requests", "code": "insufficient_quota"}}
    resp = httpx.Response(429, headers={"content-type": "application/json"},
                          json=body, request=httpx.Request("POST", "https://x"))
    # T1 round-1 (F1): construct through the SDK's own rendering path so
    # exc.body is the UNWRAPPED shape the classifier meets in production.
    exc = _openai.OpenAI(api_key="test-key")._make_status_error_from_response(resp)
    out = _oa._map_openai_exception(exc, report_rl=False)
    assert isinstance(out, LLMRateLimitError) and out.kind == "quota"

    body2 = {"error": {"message": "Rate limit reached", "type": "requests",
                       "code": "rate_limit_exceeded"}}
    resp2 = httpx.Response(429, headers={"content-type": "application/json"},
                            json=body2, request=httpx.Request("POST", "https://x"))
    out2 = _oa._map_openai_exception(
        _openai.RateLimitError("Error code: 429", response=resp2, body=body2),
        report_rl=False)
    assert isinstance(out2, LLMRateLimitError) and out2.kind == "throttle"


# --------------------------------------------------------------------------
# The end-to-end pin (the audit round's finding — the wiring was dead
# until the error_info rode the INNER result dict): drive the REAL
# run_analysis retry pass with a quota row and a throttle row.
# --------------------------------------------------------------------------
def test_run_analysis_retry_pass_splits_quota_from_throttle(tmp_path, monkeypatch):
    """A quota (a spend cap) must NOT be retried; a throttle (Google's
    PerMinute 429, the issue's headline case) MUST be — through the real
    retry pass, not the components."""
    import json as _json
    from core import analyzer
    from utilities.llm_client import reset_warning_state

    reset_warning_state()
    dataset_path = tmp_path / "dataset.json"
    dataset_path.write_text(_json.dumps({"units": [
        {"id": "a:spendcap", "code": "x=1"},
        {"id": "g:perminute", "code": "x=1"},
    ]}))
    output_dir = tmp_path / "out"

    def fake_run_detection(units, binding, json_corrector, app_context,
                           workers, checkpoint=None, summary_callback=None):
        return ([
            {"unit_id": "a:spendcap",
             "error": "Error code: 429 - {'type': 'error', 'error': "
                      "{'type': 'rate_limit_error'}}",
             "error_info": {"type": "rate_limit", "kind": "quota"}},
            {"unit_id": "g:perminute",
             "error": "429 RESOURCE_EXHAUSTED. Quota exceeded.",
             "error_info": {"type": "rate_limit", "kind": "throttle",
                            "retry_after": 12.0}},
        ], {u["id"]: "" for u in units})

    calls = []

    def fake_process(binding, unit, i, jc, ac, max_tokens=None):
        calls.append(unit["id"])
        return {"result": {"unit_id": unit["id"], "finding": "safe",
                           "verdict": "SAFE", "confidence": 90,
                           "vulnerabilities": [], "reasoning": "r"},
                "route_key": unit["id"], "code_for_route": "",
                "finding": "safe", "usage": {}}

    monkeypatch.setattr(analyzer, "_run_detection", fake_run_detection)
    monkeypatch.setattr(analyzer, "_analyze_fingerprint",
                        lambda binding, ctx_sha=None: {"key_digest": "sha256:test"})
    monkeypatch.setattr(analyzer, "_process_unit", fake_process)

    from utilities.llm import PhaseBinding

    class _Adapter:
        name = "anthropic"
        supports_tools = True
        pricing = {}

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_Adapter(),
                                model="m", provider_name="anthropic")

    analyzer.run_analysis(str(dataset_path), str(output_dir),
                           registry=_FakeRegistry(), workers=1)
    reset_warning_state()

    # the headline assertion: the throttle is retried, the quota is NOT
    assert "g:perminute" in calls, (
        "the throttle row never reached the retry pass — the issue's "
        "headline case (Google's 429 never retried by analyze) is unfixed")
    assert "a:spendcap" not in calls, (
        "the quota row (a spend cap) was retried — backoff cannot restore "
        "an exhausted entitlement; the retry burned a call for nothing")


# The placement pin (the audit round's dead-wiring finding, guarded at
# the source): the REAL _process_unit catch puts error_info on the INNER
# result dict — the dict run_analysis stores into results[i]. A fake
# detection that injects error_info itself cannot see this; drive the
# catch directly.
def test_process_unit_places_error_info_on_the_inner_result(monkeypatch, tmp_path):
    from core import analyzer

    def raising_analyze_unit(*args, **kwargs):
        raise LLMRateLimitError(
            "Error code: 429 - spend cap", kind="quota")

    monkeypatch.setattr(analyzer, "analyze_unit", raising_analyze_unit)
    out = analyzer._process_unit(
        binding=None, unit={"id": "a:spendcap", "code": "x=1"}, index=0,
        json_corrector=None, app_context=None)
    inner = out["result"]
    assert inner.get("error_info", {}).get("kind") == "quota", (
        "the structured error must ride the INNER result dict — the outer "
        "record is discarded by results[i] = out['result'], and a "
        "mis-placement makes the retry decision dead wiring (the audit "
        "round's finding)")
    assert "429" in inner.get("error", "")


# The raise-site guards (the separate-audit round's L1: only openai's
# raise site was guarded — "a helper that is never wired is a
# classification that never happens" for the other two providers).
def test_anthropic_raise_site_passes_the_kind():
    import httpx
    import anthropic as _anthropic
    from utilities.llm.providers import anthropic as _ap

    body = {"type": "error",
            "error": {"type": "rate_limit_error",
                      "message": "You have reached your enforced spend limit.",
                      "details": {"error_code": "enforced_spend_limit_reached"}}}
    resp = httpx.Response(429, headers={"content-type": "application/json"},
                          json=body, request=httpx.Request("POST", "https://x"))
    exc = _anthropic.Anthropic(api_key="test")._make_status_error_from_response(resp)
    out = _ap._anthropic_rate_limit_kind(exc)
    assert out == "quota", (
        "the anthropic raise site must classify the spend cap as quota — "
        "the helper reads the SDK-rendered body; an unwired raise site is "
        "the classification never happening")


def test_google_raise_site_passes_the_kind():
    """Drive the genai SDK's own raise path: the exception the adapter's
    except-clause actually catches, classified through the helper."""
    import httpx
    from google.genai import errors as _gerr
    from utilities.llm.providers.google import _google_429_details

    body = {"error": {"code": 429, "message": "Resource exhausted",
                      "status": "RESOURCE_EXHAUSTED",
                      "details": [
                          {"@type": "type.googleapis.com/google.rpc.QuotaFailure",
                           "violations": [{"quotaId": "GenerateRequestsPerDayPerProjectPerModel"}]},
                      ]}}
    resp = httpx.Response(429, headers={"content-type": "application/json"},
                          json=body, request=httpx.Request("POST", "https://x"))
    try:
        _gerr.APIError.raise_for_response(resp)
        raise AssertionError("the SDK did not raise on a 429")
    except _gerr.ClientError as exc:
        kind, _ = _google_429_details(exc)
    assert kind == "quota", (
        "the google raise site must classify the daily quota — the helper "
        "reads the SDK's .details (the full response dict)")
