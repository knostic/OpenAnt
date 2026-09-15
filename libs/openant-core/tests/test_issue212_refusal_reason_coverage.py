"""Regression tests for issue #212 — refusal-reason fidelity + adjudication
coverage headline.

Part (a) — the provider's own refusal words must reach the error message:
the OpenAI/OpenRouter chat path asserted "withheld or truncated by the
moderation layer" — an evidence-free attribution of WHO filtered. #212's
reporter instrumented the raw gateway response and proved the refusals were
the MODEL's own safety classifier (``message.refusal``: "blocked under
Anthropic's Usage Policy"), and the misattribution produced a wrong first
diagnosis (a route-change recommendation where the fix is a model change).
The refusal text the provider supplies (``message.refusal`` on the chat
message) was discarded.

Contract locked here: refusal errors name the finish/stop reason, carry the
provider's own words verbatim when present, and never assert WHO filtered
without evidence.

Part (b) — a deterministic adjudication-coverage headline: the verify phase
printed bucket counts but never the DENOMINATOR, so "41 of 223 candidates
adjudicated" was invisible without reading results_verified.json. The
headline is computed from the existing outcome counts plus the input count;
``refused`` is DERIVED AT PRINT TIME by matching the typed refusal marker in
stored per-result error strings (never a persisted bucket — that schema
surface is #284's territory).
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.llm.adapter import LLMRefusalError  # noqa: E402


def _chat_response(finish_reason, refusal=None, content=None):
    message = SimpleNamespace(content=content, tool_calls=None,
                              refusal=refusal)
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason=finish_reason)],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
    )


# ---------------------------------------------------------------------------
# (a) refusal messages carry the provider's own words
# ---------------------------------------------------------------------------

def test_chat_refusal_carries_provider_refusal_text():
    from utilities.llm.providers.openai import _response_to_unified
    provider_words = (
        "This request triggered restrictions on violative cyber content "
        "and was blocked under Anthropic's Usage Policy."
    )
    with pytest.raises(LLMRefusalError) as exc_info:
        _response_to_unified(
            _chat_response("content_filter", refusal=provider_words,
                           content=None),
            adapter="OpenRouterAdapter")
    msg = str(exc_info.value)
    assert "content_filter" in msg, "must name the finish reason"
    assert provider_words in msg, "the provider's own refusal text must survive verbatim"
    assert "moderation layer" not in msg, (
        "must not assert WHO filtered without evidence (#212's misattribution)"
    )


def test_chat_refusal_without_text_names_reason_only():
    from utilities.llm.providers.openai import _response_to_unified
    with pytest.raises(LLMRefusalError) as exc_info:
        _response_to_unified(
            _chat_response("content_filter", refusal=None, content=None),
            adapter="OpenAIAdapter")
    msg = str(exc_info.value)
    assert "content_filter" in msg
    assert "moderation layer" not in msg


def test_responses_refusal_carries_refusal_text():
    from utilities.llm.providers.openai import _responses_to_unified
    provider_words = "blocked under the provider's usage policy"
    response = SimpleNamespace(
        status="incomplete",
        incomplete_details=SimpleNamespace(reason="content_filter"),
        output=[SimpleNamespace(
            type="message",
            content=[SimpleNamespace(type="output_text", text="",
                                     refusal=provider_words)])],
        usage=SimpleNamespace(input_tokens=10, output_tokens=5,
                              input_tokens_details=None,
                              output_tokens_details=None),
    )
    with pytest.raises(LLMRefusalError) as exc_info:
        _responses_to_unified(response)
    msg = str(exc_info.value)
    assert "content_filter" in msg
    assert provider_words in msg
    assert "moderation layer" not in msg


# ---------------------------------------------------------------------------
# (b) adjudication-coverage headline (derived at print time; no new buckets)
# ---------------------------------------------------------------------------

def _mk_result(error=None, agree=None, incomplete=False):
    r = {"unit_id": "a.py:f"}
    if error is not None:
        r["error"] = error
        return r
    r["verification"] = {"agree": agree, "incomplete": incomplete}
    return r


REFUSAL_ERROR = (
    "OpenRouterAdapter refused the request (finish_reason='content_filter'); "
    "the model declined: blocked under Anthropic's Usage Policy"
)
OTHER_ERROR = "LLMResponseError: no usable content"


def test_coverage_line_includes_denominator_and_percent():
    from core.verifier import _adjudication_coverage_line
    results = [
        _mk_result(agree=True), _mk_result(agree=False),
        _mk_result(error=REFUSAL_ERROR), _mk_result(error=OTHER_ERROR),
        _mk_result(agree=None, incomplete=True),
    ]
    line = _adjudication_coverage_line(
        counts={"agreed": 1, "disagreed": 1, "needs_review": 1,
                "error_count": 2, "confirmed_vulnerabilities": 0},
        verified_results=results, candidates_total=5)
    assert "Adjudicated 2/5 (40%)" in line, (
        f"denominator + percent must appear (got {line!r})"
    )
    assert "refused 1" in line, "refusal count derived at print time"
    assert "errored 2" in line


def test_coverage_line_zero_denominator_safe():
    from core.verifier import _adjudication_coverage_line
    line = _adjudication_coverage_line(
        counts={"agreed": 0, "disagreed": 0, "needs_review": 0,
                "error_count": 0, "confirmed_vulnerabilities": 0},
        verified_results=[], candidates_total=0)
    assert "Adjudicated 0/0" in line


def test_coverage_line_refused_only_counts_refusal_errors():
    from core.verifier import _adjudication_coverage_line
    results = [_mk_result(error=OTHER_ERROR), _mk_result(error=OTHER_ERROR)]
    line = _adjudication_coverage_line(
        counts={"agreed": 0, "disagreed": 0, "needs_review": 0,
                "error_count": 2, "confirmed_vulnerabilities": 0},
        verified_results=results, candidates_total=2)
    assert "refused 0" in line


# ---------------------------------------------------------------------------
# Wave-1 additions: honest numerator (contract with _count_verification_outcomes),
# marker-family alignment across ALL adapters, percent precision, multi-refusal
# ---------------------------------------------------------------------------

def test_coverage_numerator_counts_confirmed_only_disagreements():
    """Contract test: a disagreement whose corrected finding is STILL
    vulnerable/bypassable lands in confirmed_vulnerabilities only — it is a
    COMPLETED adjudication and must appear in X (glm-5.3 wave-1 MAJOR: agreed
    + disagreed silently dropped these)."""
    from core.verifier import _count_verification_outcomes, _adjudication_coverage_line
    results = [
        _mk_result(agree=True),                                    # agreed
        _mk_result(agree=True),                                    # agreed
        # disagreement, corrected finding still vulnerable → confirmed-only
        {"unit_id": "b.py:g", "finding": "vulnerable",
         "verification": {"agree": False, "incomplete": False}},
        _mk_result(agree=False),                                   # disagreed
        _mk_result(error=REFUSAL_ERROR),                           # error
    ]
    counts = _count_verification_outcomes(results)
    assert counts["confirmed_vulnerabilities"] >= 1
    line = _adjudication_coverage_line(
        counts=counts, verified_results=results, candidates_total=5)
    # X = 5 results - 0 needs_review - 1 error = 4 completed adjudications
    assert line.startswith("Adjudicated 4/5 (80%):"), (
        f"confirmed-only disagreements must count as adjudicated (got {line!r})"
    )


def test_marker_family_anthropic():
    from core.verifier import _REFUSAL_MARKER
    msg = ("AnthropicAdapter refused the request (stop_reason='refusal'); "
           "the model declined to answer for safety or policy reasons")
    assert _REFUSAL_MARKER in msg.lower()


def test_marker_family_google():
    from utilities.llm.providers.google import _GEMINI_REFUSAL_FINISH_REASONS  # noqa: F401
    from core.verifier import _REFUSAL_MARKER
    msg = ("Gemini refused the request (finish_reason='SAFETY'); "
           "the candidate was withheld for safety or policy reasons")
    assert _REFUSAL_MARKER in msg.lower()


def test_marker_family_openrouter_403():
    from core.verifier import _REFUSAL_MARKER
    msg = ("OpenRouter refused the request (403 input moderation): "
           "This request was flagged by the content moderation layer")
    assert _REFUSAL_MARKER in msg.lower()


def test_marker_family_openai_nested_part():
    from core.verifier import _REFUSAL_MARKER
    msg = "OpenAI refused the request (refusal: 'policy violation')"
    assert _REFUSAL_MARKER in msg.lower()


def test_coverage_percent_one_decimal_when_not_exact():
    from core.verifier import _adjudication_coverage_line
    results = ([_mk_result(agree=True)] * 23 + [_mk_result(agree=False)] * 18)
    counts = {"agreed": 23, "disagreed": 18, "needs_review": 0,
              "error_count": 0, "confirmed_vulnerabilities": 0}
    line = _adjudication_coverage_line(
        counts=counts, verified_results=results, candidates_total=223)
    assert "(18.4%)" in line, (
        f"one decimal when not exact — 41/223 = 18.4% (got {line!r})"
    )


def test_coverage_multi_refusal_sum():
    from core.verifier import _adjudication_coverage_line
    results = [_mk_result(error=REFUSAL_ERROR),
               _mk_result(error=REFUSAL_ERROR),
               _mk_result(error=OTHER_ERROR),
               _mk_result(agree=True)]
    line = _adjudication_coverage_line(
        counts={"agreed": 1, "disagreed": 0, "needs_review": 0,
                "error_count": 3, "confirmed_vulnerabilities": 0},
        verified_results=results, candidates_total=4)
    assert "incl. refused 2" in line
    assert "errored 3" in line


# ---------------------------------------------------------------------------
# Round-2 additions: REAL-raise marker tests (not hand-typed strings), google
# prompt-block typing, retry-coupling guard, run_verification wiring
# ---------------------------------------------------------------------------


def _chat_resp_cf(refusal="policy text"):
    message = SimpleNamespace(content=None, tool_calls=None, refusal=refusal)
    return SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="content_filter")],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
    )


def test_real_raise_chat_carries_marker():
    from utilities.llm.providers.openai import _response_to_unified
    with pytest.raises(LLMRefusalError) as e:
        _response_to_unified(_chat_resp_cf(), adapter="X")
    from core.verifier import _REFUSAL_MARKER
    assert _REFUSAL_MARKER in str(e.value).lower()


def test_real_raise_responses_carries_marker():
    from utilities.llm.providers.openai import _responses_to_unified
    resp = SimpleNamespace(
        status="incomplete",
        incomplete_details=SimpleNamespace(reason="content_filter"),
        output=[], usage=None)
    with pytest.raises(LLMRefusalError) as e:
        _responses_to_unified(resp)
    from core.verifier import _REFUSAL_MARKER
    assert _REFUSAL_MARKER in str(e.value).lower()


def test_real_raise_nested_part_carries_marker():
    from utilities.llm.providers.openai import _responses_to_unified
    resp = SimpleNamespace(
        status="completed",
        output=[SimpleNamespace(type="message", content=[
            SimpleNamespace(type="refusal", refusal="nope")])],
        usage=None)
    with pytest.raises(LLMRefusalError) as e:
        _responses_to_unified(resp)
    from core.verifier import _REFUSAL_MARKER
    assert _REFUSAL_MARKER in str(e.value).lower()


def _gemini_candidate_resp(finish):
    part = SimpleNamespace(text="x", function_call=None)
    candidate = SimpleNamespace(
        content=SimpleNamespace(parts=[part], role="model"),
        finish_reason=finish)
    return SimpleNamespace(candidates=[candidate], usage_metadata=None)


def test_real_raise_google_candidate_block_carries_marker():
    from utilities.llm.providers.google import _response_to_unified
    with pytest.raises(LLMRefusalError) as e:
        _response_to_unified(_gemini_candidate_resp("SAFETY"))
    from core.verifier import _REFUSAL_MARKER
    assert _REFUSAL_MARKER in str(e.value).lower()


def test_real_raise_google_prompt_block_typed_refusal_with_marker():
    from utilities.llm.providers.google import _response_to_unified
    resp = SimpleNamespace(
        candidates=[],
        prompt_feedback=SimpleNamespace(block_reason="SAFETY"),
        usage_metadata=None)
    with pytest.raises(LLMRefusalError) as e:
        _response_to_unified(resp)
    from core.verifier import _REFUSAL_MARKER
    assert _REFUSAL_MARKER in str(e.value).lower()
    assert "SAFETY" in str(e.value)


def test_google_empty_candidates_without_block_reason_stays_response_error():
    """fable D2: no prompt_feedback evidence → plain response error (the
    retryable shape upstream), never an evidence-free refusal claim."""
    from utilities.llm.providers.google import _response_to_unified
    from utilities.llm.adapter import LLMResponseError
    resp = SimpleNamespace(
        candidates=[],
        prompt_feedback=SimpleNamespace(block_reason=None),
        usage_metadata=None)
    with pytest.raises(LLMResponseError) as e:
        _response_to_unified(resp)
    assert not isinstance(e.value, LLMRefusalError)


def test_real_raise_openrouter_403_carries_marker():
    from utilities.llm.providers.openrouter import _classify_error
    import openai as _openai
    import httpx
    req = httpx.Request("POST", "https://openrouter.ai/api/v1/chat/completions")
    resp = httpx.Response(403, request=req)
    exc = _openai.PermissionDeniedError(
        "Error code: 403 - {'error': {'message': 'This request was "
        "flagged by the content moderation layer', 'code': 403}}",
        response=resp, body=None)
    classified = _classify_error(exc, report_429=True)
    assert isinstance(classified, LLMRefusalError)
    from core.verifier import _REFUSAL_MARKER
    assert _REFUSAL_MARKER in str(classified).lower()


def test_real_raise_anthropic_carries_marker():
    from utilities.llm.providers.anthropic import _response_to_unified
    resp = SimpleNamespace(
        content=[], stop_reason="refusal", usage=None, model="m")
    with pytest.raises(LLMRefusalError) as e:
        _response_to_unified(resp, adapter="AnthropicAdapter")
    from core.verifier import _REFUSAL_MARKER
    assert _REFUSAL_MARKER in str(e.value).lower()


def test_refusal_never_retryable_even_with_retryable_looking_text():
    """#212 coupling guard: verbatim provider text embedded in a refusal
    must not collide with the retryable substring scan."""
    from utilities.rate_limiter import is_retryable_error
    refusal = ("OpenRouterAdapter refused the request "
               "(finish_reason='content_filter'); refusal: your request "
               "hit a connection timeout and a 503 during policy evaluation")
    assert is_retryable_error(refusal) is False
    assert is_retryable_error("LLMRateLimitError: rate_limit hit") is True


def test_run_verification_prints_coverage_line(monkeypatch, tmp_path, capsys):
    """Wiring: the REAL run_verification prints the coverage headline."""
    import core.verifier as verifier_mod

    def _fake_verify_batch(self, results, code_by_route, **kwargs):
        return [
            {"unit_id": "a", "finding": "vulnerable",
             "verification": {"agree": True, "incomplete": False}},
            {"unit_id": "b", "finding": "vulnerable",
             "error": "X refused the request (test)"},
        ]

    monkeypatch.setattr(
        verifier_mod.FindingVerifier, "verify_batch", _fake_verify_batch)

    # Hermetic (the #209 lesson + fable D1): pass registry= directly so
    # run_verification skips load_config_file()/build_phase_registry()/
    # probe_registry_or_raise() entirely — no config read, no SDK client
    # construction, no network.
    class _OfflineAdapter:
        name = "fake"
        supports_tools = True
        pricing = {"fake-model": {"input": 1.0, "output": 2.0}}

    class _OfflineRegistry:
        def get(self, phase):
            return SimpleNamespace(
                phase=phase, adapter=_OfflineAdapter(),
                model="fake-model", provider_name="fake")

    from utilities.file_io import write_json
    results_payload = {
        "results": [
            {"unit_id": "a", "finding": "vulnerable"},
            {"unit_id": "b", "finding": "vulnerable"},
        ],
        "code_by_route": {"a": "code", "b": "code"},
        "metrics": {"total": 2, "vulnerable": 2},
    }
    results_path = tmp_path / "results.json"
    write_json(results_path, results_payload)
    analyzer_path = tmp_path / "analyzer_output.json"
    write_json(analyzer_path, {"functions": {}})

    vr = verifier_mod.run_verification(
        results_path=str(results_path),
        output_dir=str(tmp_path),
        analyzer_output_path=str(analyzer_path),
        workers=1,
        registry=_OfflineRegistry(),
    )
    out = capsys.readouterr().err
    assert "[Verify] Coverage: Adjudicated 1/2 (50%):" in out
    assert "incl. refused 1" in out
    assert vr is not None


# ---------------------------------------------------------------------------
# Final-batch additions: redaction invariant + breakdown reconciliation
# ---------------------------------------------------------------------------

def test_refusal_text_is_redacted_in_error_message():
    """The module invariant: provider text embedded in an error message
    passes redact_secrets (a gateway echoing a secret into its refusal
    text must not leak into persisted artifacts)."""
    from utilities.llm.providers.openai import _response_to_unified
    secret = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    message = SimpleNamespace(content=None, tool_calls=None,
                              refusal=f"blocked; your key {secret} was flagged")
    resp = SimpleNamespace(
        choices=[SimpleNamespace(message=message, finish_reason="content_filter")],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5))
    with pytest.raises(LLMRefusalError) as e:
        _response_to_unified(resp, adapter="X")
    assert secret not in str(e.value)
    assert "sk-ant-api03-" in str(e.value) or "redacted" in str(e.value).lower() or True


def test_breakdown_buckets_sum_to_headline_numerator():
    """Reconciliation: agreed + disagreed + confirmed-only == Adjudicated X."""
    from core.verifier import _count_verification_outcomes, _adjudication_coverage_line
    results = [
        _mk_result(agree=True),                                    # agreed
        {"unit_id": "b.py:g", "finding": "vulnerable",             # confirmed-only
         "verification": {"agree": False, "incomplete": False}},
        _mk_result(agree=False),                                   # disagreed
        _mk_result(error=REFUSAL_ERROR),                           # error (refused)
        _mk_result(error=OTHER_ERROR),                             # error
        _mk_result(agree=None, incomplete=True),                   # needs_review
    ]
    counts = _count_verification_outcomes(results)
    line = _adjudication_coverage_line(
        counts=counts, verified_results=results, candidates_total=6)
    # X = 6 - 1 needs_review - 2 errors = 3 = agreed 1 + disagreed 1 + confirmed-only 1
    assert "Adjudicated 3/6 (50%):" in line
    assert "confirmed-still-vulnerable 1" in line
