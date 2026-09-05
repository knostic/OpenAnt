"""The installed-SDK contract floor (the ARCHITECTURE §1 seam, machine-checked).

The adapter tests elsewhere stub the SDK boundary with SimpleNamespace
fakes (``tests/_llm_factories/``) — they pin OUR code's contract, not the
SDK's. A usage-field rename in a future openai / google-genai release keeps
every fake-based test green while the adapters' getattr walks silently
degrade to ``None`` (the known installed-SDK↔extractor seam: openai 2.37→2.54
and anthropic 0.125→1.1 moved usage/exception shapes mid-campaign).

This floor closes that gap TWO ways, because construction alone is circular
(a pydantic model with extra="allow" would store a renamed field as an extra
attribute and getattr would still find it):

1. **Declared-ness** — every field the adapters read is asserted to be a
   DECLARED field of the installed SDK's type (``"<field>" in
   Type.model_fields``). A rename removes the declaration and turns this
   file RED.
2. **Construct-then-extract** — real objects drive the real extractors, so
   the values (not just the names) flow end to end.

Both SDKs are hard pins in requirements.txt (CI installs them); a missing
SDK fails loudly here rather than skipping silently — a silent skip would
defeat the floor.

Coverage (mirrors the adapters' consumed surface; the refusal set is built
from ``_GEMINI_REFUSAL_NAMES`` into ``_GEMINI_REFUSAL_FINISH_REASONS``, and
the finish map at ``_GEMINI_FINISH_REASONS``):
  * openai chat usage: completion_tokens_details.reasoning_tokens,
    prompt_tokens_details.cached_tokens / cache_write_tokens
  * openai Responses usage: output_tokens_details.reasoning_tokens,
    input_tokens_details.cached_tokens (+ the version fact that the detail
    fields are required and non-nullable, machine-checked via a
    ValidationError construction)
  * openai exception taxonomy incl. APITimeoutError, and the retry-after
    parse driven over a real RateLimitError
  * openai finish_reason Literal (content_filter) + message.refusal declared
  * google-genai usage_metadata fields + the candidates+thoughts billing
    helper (_gemini_output_tokens — the single source of the rule) +
    thoughts/cached_content detail fields
  * google-genai FinishReason members behind BOTH google maps
    (_GEMINI_REFUSAL_NAMES and _GEMINI_FINISH_REASONS keys)
  * google-genai HttpRetryOptions.attempts declared (the retry-parity field)
  * ClientError construction with the .code attribute the adapter maps
  * the installed versions tied to the requirements.txt pins

Executed self-controls at authoring time (the PR body carries the outputs):
misspelling the extractor field names made this suite RED (7 tests); and
misspelling a DECLARED-NESS assertion (reasoning_tokens -> reasoning_tokenz)
made the declared-ness test RED — both directions of the rename detection.
"""

from __future__ import annotations

import typing
from types import SimpleNamespace

import httpx
import openai
import pytest

from utilities.llm.providers import google as google_provider
from utilities.llm.providers import openai as openai_provider


# --------------------------------------------------------------------------- #
# Version provenance — the floor is only meaningful against the pinned SDKs  #
# --------------------------------------------------------------------------- #


def _requirements_pins() -> dict[str, str]:
    import re
    from pathlib import Path

    pins: dict[str, str] = {}
    root = Path(__file__).resolve().parents[1]
    for line in (root / "requirements.txt").read_text().splitlines():
        m = re.match(r"^(openai|google-genai)==([0-9.]+)", line.strip())
        if m:
            pins[m.group(1)] = m.group(2)
    return pins


def test_installed_sdks_match_the_requirements_pins():
    """Records WHICH versions the floor re-derived against and fails if the
    environment's installed SDKs drift from the pins (a stale cached wheel
    would otherwise validate the wrong version silently)."""
    import google.genai

    pins = _requirements_pins()
    assert openai.__version__ == pins["openai"], (
        f"installed openai {openai.__version__} != requirements pin {pins['openai']}"
    )
    assert google.genai.__version__ == pins["google-genai"], (
        f"installed google-genai {google.genai.__version__} != pin {pins['google-genai']}"
    )


# --------------------------------------------------------------------------- #
# openai — DECLARED-NESS of every field the adapters read                     #
# --------------------------------------------------------------------------- #


def test_openai_usage_detail_fields_are_declared():
    from openai.types import CompletionUsage
    from openai.types.completion_usage import CompletionTokensDetails, PromptTokensDetails
    from openai.types.responses import ResponseUsage
    from openai.types.responses.response_usage import InputTokensDetails, OutputTokensDetails

    assert "reasoning_tokens" in CompletionTokensDetails.model_fields
    assert {"cached_tokens", "cache_write_tokens"} <= set(PromptTokensDetails.model_fields)
    assert {"completion_tokens_details", "prompt_tokens_details"} <= set(CompletionUsage.model_fields)

    assert "reasoning_tokens" in OutputTokensDetails.model_fields
    assert "cached_tokens" in InputTokensDetails.model_fields
    assert {"input_tokens_details", "output_tokens_details"} <= set(ResponseUsage.model_fields)


def test_openai_finish_reason_literal_declares_content_filter():
    from openai.types.chat import chat_completion

    choice_cls = chat_completion.Choice
    annotation = choice_cls.model_fields["finish_reason"].annotation
    args = typing.get_args(annotation)
    assert "content_filter" in args, (
        "the adapter maps 'content_filter' (its _OPENAI_CONTENT_FILTER_REASON); "
        "the installed SDK's finish_reason Literal no longer declares it"
    )


def test_openai_message_refusal_is_declared():
    from openai.types.chat import ChatCompletionMessage

    assert "refusal" in ChatCompletionMessage.model_fields, (
        "the adapter surfaces message.refusal (#212); the installed SDK's "
        "chat message type no longer declares it"
    )


# --------------------------------------------------------------------------- #
# openai — construct-then-extract over the REAL types                         #
# --------------------------------------------------------------------------- #


def _real_chat_usage() -> "openai.types.CompletionUsage":
    from openai.types import CompletionUsage
    from openai.types.completion_usage import CompletionTokensDetails, PromptTokensDetails

    return CompletionUsage(
        prompt_tokens=10,
        completion_tokens=20,
        total_tokens=30,
        completion_tokens_details=CompletionTokensDetails(reasoning_tokens=5),
        prompt_tokens_details=PromptTokensDetails(cached_tokens=3, cache_write_tokens=1),
    )


def test_openai_chat_usage_details_from_real_sdk_type():
    details = openai_provider._extract_usage_details_chat(_real_chat_usage())
    assert details == {"reasoning_tokens": 5, "cached_tokens": 3, "cache_write_tokens": 1}


def test_openai_chat_usage_absent_details_is_none():
    from openai.types import CompletionUsage

    bare = CompletionUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30)
    assert openai_provider._extract_usage_details_chat(bare) is None
    assert openai_provider._extract_usage_details_chat(None) is None


def _real_responses_usage() -> "openai.types.responses.ResponseUsage":
    from openai.types.responses import ResponseUsage
    from openai.types.responses.response_usage import InputTokensDetails, OutputTokensDetails

    return ResponseUsage(
        input_tokens=7,
        output_tokens=8,
        total_tokens=15,
        output_tokens_details=OutputTokensDetails(reasoning_tokens=4),
        input_tokens_details=InputTokensDetails(cached_tokens=2, cache_write_tokens=1),
    )


def test_openai_responses_usage_details_from_real_sdk_type():
    details = openai_provider._extract_usage_details_responses(_real_responses_usage())
    assert details == {"reasoning_tokens": 4, "cached_tokens": 2}


def test_openai_responses_detail_fields_required_and_non_nullable():
    """The version fact behind the absent-arm: at 3.6.0 the detail fields on
    ResponseUsage are required AND non-nullable, so 'no details' materializes
    as usage=None. If a bump makes them optional, this construction starts
    succeeding — RED here means the absent-arm test above must be widened."""
    from pydantic import ValidationError
    from openai.types.responses import ResponseUsage

    with pytest.raises(ValidationError):
        ResponseUsage(input_tokens=7, output_tokens=8, total_tokens=15)


# --------------------------------------------------------------------------- #
# openai — the exception taxonomy + retry-after the adapter consumes          #
# --------------------------------------------------------------------------- #


def _fake_httpx_response(status: int, retry_after: str | None = None) -> httpx.Response:
    headers = {"retry-after": retry_after} if retry_after is not None else {}
    return httpx.Response(
        status, request=httpx.Request("POST", "https://api.example.com/v1/x"), headers=headers
    )


def test_openai_exception_classes_construct_with_real_signatures():
    cases = [
        (openai.AuthenticationError, {"message": "bad key", "response": _fake_httpx_response(401), "body": None}, 401),
        (openai.PermissionDeniedError, {"message": "denied", "response": _fake_httpx_response(403), "body": None}, 403),
        (openai.RateLimitError, {"message": "slow down", "response": _fake_httpx_response(429, retry_after="7"), "body": None}, 429),
        (openai.NotFoundError, {"message": "no model", "response": _fake_httpx_response(404), "body": None}, 404),
        (openai.APIStatusError, {"message": "boom", "response": _fake_httpx_response(500), "body": None}, 500),
    ]
    for exc_cls, args, expected_status in cases:
        exc = exc_cls(**args)
        assert exc.response.status_code == expected_status, exc_cls.__name__

    openai.APIConnectionError(
        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    )
    openai.APITimeoutError(
        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    )


def test_openai_retry_after_over_real_rate_limit_error():
    """The retry-after parse the adapter consumes on RateLimitError — driven
    over the REAL exception carrying a REAL httpx.Response header."""
    exc = openai.RateLimitError(
        message="slow down",
        response=_fake_httpx_response(429, retry_after="7"),
        body=None,
    )
    assert openai_provider._retry_after_from(exc) == 7.0


# --------------------------------------------------------------------------- #
# google-genai — DECLARED-NESS                                                #
# --------------------------------------------------------------------------- #


def test_gemini_usage_metadata_fields_are_declared():
    from google.genai import types as genai_types

    um = genai_types.GenerateContentResponseUsageMetadata
    assert {
        "prompt_token_count",
        "candidates_token_count",
        "thoughts_token_count",
        "cached_content_token_count",
    } <= set(um.model_fields)


def test_gemini_retry_options_attempts_is_declared():
    """The retry-parity field: the adapter passes
    HttpRetryOptions(attempts=max_retries+1) — the field name is load-bearing
    (a rename silently changes retry counts)."""
    from google.genai import types as genai_types

    assert "attempts" in genai_types.HttpRetryOptions.model_fields


def test_gemini_finish_reason_members_back_both_adapter_maps():
    """Every raw name in BOTH google maps must exist as a FinishReason member
    at the installed version — the sets are built by getattr and silently
    shrink on a member rename."""
    from google.genai import types as genai_types

    for name in google_provider._GEMINI_REFUSAL_NAMES:
        assert hasattr(genai_types.FinishReason, name), (
            f"FinishReason.{name} (refusal set) is absent from the installed google-genai"
        )
    for key in google_provider._GEMINI_FINISH_REASONS:
        # the map keys carry both raw names ("STOP") and str(member) forms
        # ("FinishReason.STOP") — only the raw names name enum members
        if key.startswith("FinishReason."):
            continue
        assert hasattr(genai_types.FinishReason, key), (
            f"FinishReason.{key} (finish map) is absent from the installed google-genai"
        )


# --------------------------------------------------------------------------- #
# google-genai — construct-then-extract over the REAL types                   #
# --------------------------------------------------------------------------- #


def _real_gemini_usage_metadata() -> object:
    from google.genai import types as genai_types

    return genai_types.GenerateContentResponseUsageMetadata(
        prompt_token_count=11,
        candidates_token_count=6,
        thoughts_token_count=4,
        cached_content_token_count=2,
    )


def test_google_usage_details_from_real_sdk_type():
    details = google_provider._extract_usage_details(_real_gemini_usage_metadata())
    assert details == {"thoughts_token_count": 4, "cached_content_token_count": 2}


def test_google_output_tokens_is_the_adapters_own_helper():
    """The billing rule (output = candidates + thoughts) driven through the
    ADAPTER'S helper — not a re-implementation of its arithmetic."""
    usage = _real_gemini_usage_metadata()
    assert google_provider._gemini_output_tokens(usage) == 10  # 6 candidates + 4 thoughts
    bare = SimpleNamespace(candidates_token_count=0, thoughts_token_count=0)
    assert google_provider._gemini_output_tokens(bare) == 0


def test_google_usage_absent_details_is_none():
    from google.genai import types as genai_types

    bare = genai_types.GenerateContentResponseUsageMetadata(prompt_token_count=1)
    assert google_provider._extract_usage_details(bare) is None
    assert google_provider._extract_usage_details(None) is None


def test_client_error_constructs_with_code():
    from google.genai import errors as genai_errors

    response_json = {"error": {"code": 429, "message": "slow down", "status": ""}}
    err = genai_errors.ClientError(429, response_json, _fake_httpx_response(429))
    assert err.code == 429


# --------------------------------------------------------------------------- #
# The discrimination proof (negative controls)                                #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "wrong",
    [
        SimpleNamespace(completion_tokens_details=SimpleNamespace(reasoning_tokenz=5)),
        SimpleNamespace(prompt_tokens_details=SimpleNamespace(cached_tokenz=3)),
        SimpleNamespace(),
    ],
)
def test_openai_wrong_shapes_extract_none(wrong):
    """The extractors return exactly None for wrong-shaped input — never a
    partial dict of garbage values."""
    assert openai_provider._extract_usage_details_chat(wrong) is None


@pytest.mark.parametrize(
    "wrong",
    [
        SimpleNamespace(thoughtz_token_count=1),
        SimpleNamespace(cached_content_tokenz=1),
        SimpleNamespace(),
    ],
)
def test_google_wrong_shapes_extract_none(wrong):
    assert google_provider._extract_usage_details(wrong) is None


# --------------------------------------------------------------------------- #
# anthropic — the seam's third leg (same shape as openai/google above)        #
# --------------------------------------------------------------------------- #


def test_anthropic_pin_tied_to_requirements():
    import re
    from pathlib import Path

    import anthropic

    root = Path(__file__).resolve().parents[1]
    pin = None
    for line in (root / "requirements.txt").read_text().splitlines():
        m = re.match(r"^anthropic\[bedrock\]==([0-9.]+)", line.strip())
        if m:
            pin = m.group(1)
    assert pin is not None, "requirements.txt must carry the anthropic[bedrock] pin"
    assert anthropic.__version__ == pin, (
        f"installed anthropic {anthropic.__version__} != requirements pin {pin}"
    )


def test_anthropic_usage_fields_are_declared():
    from anthropic.types import Usage

    # the adapter's consumed surface: anthropic.py _extract_usage_details reads
    # cache_read_input_tokens / cache_creation_input_tokens; the response walk
    # reads input_tokens / output_tokens
    assert {
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
        "input_tokens",
        "output_tokens",
    } <= set(Usage.model_fields)


def test_anthropic_usage_details_from_real_sdk_type():
    from anthropic.types import Usage

    from utilities.llm.providers import anthropic as anthropic_provider

    usage = Usage(input_tokens=10, output_tokens=20)
    details = anthropic_provider._extract_usage_details(usage)
    # absent cache fields extract None-details (absent != 0, same contract)
    assert details is None

    cached = Usage(
        input_tokens=10,
        output_tokens=20,
        cache_read_input_tokens=3,
        cache_creation_input_tokens=1,
    )
    assert anthropic_provider._extract_usage_details(cached) == {
        "cache_read_input_tokens": 3,
        "cache_creation_input_tokens": 1,
    }


def test_anthropic_exception_classes_construct_with_real_signatures():
    import anthropic

    cases = [
        (anthropic.AuthenticationError, 401),
        (anthropic.PermissionDeniedError, 403),
        (anthropic.RateLimitError, 429),
        (anthropic.NotFoundError, 404),
        (anthropic.APIStatusError, 500),
    ]
    for exc_cls, status in cases:
        exc = exc_cls(
            message="m",
            response=_fake_httpx_response(status),
            body=None,
        )
        assert exc.response.status_code == status, exc_cls.__name__

    anthropic.APIConnectionError(
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    )


def test_anthropic_wrong_shapes_extract_none():
    from utilities.llm.providers import anthropic as anthropic_provider

    assert anthropic_provider._extract_usage_details(SimpleNamespace(cache_read_input_tokenz=1)) is None
    assert anthropic_provider._extract_usage_details(None) is None
