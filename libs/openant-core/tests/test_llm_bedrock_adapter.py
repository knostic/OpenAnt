"""Bedrock-adapter-specific tests.

The shared contract harness (``test_llm_adapter_contract.py``) covers
behaviors every adapter must satisfy, and the request/response
translation layer is the Anthropic adapter's (reused, covered by
``test_llm_anthropic_adapter.py``). This file covers the bits that are
specific to Bedrock:

* constructor plumbing — ``base_url`` forwarded, ``api_key`` ignored
  with a one-time warning, no aws_* kwargs passed (region and
  credentials must resolve through the SDK's own AWS chain)
* inference-profile model IDs passed through verbatim
* AccessDenied (403) mapped to LLMAuthError with a "Model access" hint
* 400 "model identifier is invalid" mapped to LLMNotFoundError
* missing-credentials RuntimeError mapped to LLMAuthError
* Bedrock throttling (429) reports to the global rate limiter

These tests stub the SDK boundary so nothing hits the network.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import anthropic
import httpx
import pytest

from utilities.llm import (
    LLMAuthError,
    LLMNotFoundError,
    LLMRateLimitError,
    LLMResponseError,
    Message,
    TextBlock,
)
from utilities.llm.providers import bedrock as bedrock_module
from utilities.llm.providers.bedrock import BedrockAdapter
from utilities.rate_limiter import get_rate_limiter, reset_rate_limiter


def test_no_region_maps_to_typed_auth_error(monkeypatch):
    """anthropic>=1.0 removed the warned us-east-1 fallback: constructing
    AnthropicBedrock with no resolvable region raises the SDK's bare
    ValueError. The adapter must surface that as a typed, actionable
    LLMAuthError — not crash adapter construction. Constructs the REAL
    SDK class (no injected fake) so this path is exercised where the
    mocked-client contract suite is structurally blind."""
    for var in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"):
        monkeypatch.delenv(var, raising=False)
    # Point the AWS config file nowhere so a developer machine's own
    # ~/.aws/config cannot silently satisfy the region lookup. (Do NOT
    # set a bogus AWS_PROFILE: the SDK then raises botocore's
    # ProfileNotFound, a different failure mode.)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent-openant-test-aws-config")
    with pytest.raises(LLMAuthError, match="region"):
        BedrockAdapter()


@pytest.fixture(autouse=True)
def _reset_state():
    reset_rate_limiter()
    bedrock_module.reset_warnings()
    yield
    reset_rate_limiter()
    bedrock_module.reset_warnings()


def _ok_response(*, text="hi", input_tokens=1, output_tokens=1, stop_reason="end_turn"):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
        stop_reason=stop_reason,
    )


def _stub_adapter(side_effect):
    client = MagicMock(spec=anthropic.AnthropicBedrock)
    client.messages = MagicMock()
    client.messages.create = MagicMock(side_effect=side_effect)
    return BedrockAdapter(_client=client), client


def _fake_http_resp(status, *, retry_after=None):
    headers = {}
    if retry_after is not None:
        headers["retry-after"] = retry_after
    return httpx.Response(
        status_code=status,
        headers=headers,
        request=httpx.Request(
            "POST", "https://bedrock-runtime.us-east-1.amazonaws.com/model/test/invoke"
        ),
    )


def _complete(adapter, model="us.anthropic.claude-sonnet-4-6"):
    return adapter.complete(
        model=model,
        system=None,
        messages=[Message(role="user", content=[TextBlock("hi")])],
        max_tokens=8,
    )


# ---------------------------------------------------------------------------
# Constructor plumbing
# ---------------------------------------------------------------------------


class TestConstructor:
    def _patched(self, monkeypatch):
        captured = {}

        class FakeBedrock:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.messages = MagicMock()

        monkeypatch.setattr(
            "utilities.llm.providers.bedrock.anthropic.AnthropicBedrock", FakeBedrock
        )
        return captured

    def test_passes_base_url_to_sdk(self, monkeypatch):
        captured = self._patched(monkeypatch)
        BedrockAdapter(base_url="https://vpce-123.bedrock-runtime.us-east-1.vpce.amazonaws.com")
        assert captured["base_url"] == (
            "https://vpce-123.bedrock-runtime.us-east-1.vpce.amazonaws.com"
        )
        assert captured["max_retries"] == 5

    def test_no_aws_kwargs_passed(self, monkeypatch):
        """Region and credentials must resolve through the SDK's own AWS
        chain (AWS_REGION env, then ~/.aws via boto3) — the adapter
        passes no aws_* kwargs, so `openant` behaves exactly like the
        aws CLI on the same machine."""
        captured = self._patched(monkeypatch)
        BedrockAdapter()
        assert not any(key.startswith("aws_") for key in captured)
        assert "base_url" not in captured

    def test_api_key_is_ignored_not_forwarded(self, monkeypatch, capsys):
        """The registry constructs every adapter with api_key=...; Bedrock
        has no API-key auth in the pinned SDK, so the kwarg must be
        dropped (never forwarded) and warned about (never silent)."""
        captured = self._patched(monkeypatch)
        BedrockAdapter(api_key="sk-ant-should-be-ignored")
        assert "api_key" not in captured
        err = capsys.readouterr().err
        assert "ignores `api_key`" in err

    def test_api_key_warning_is_once_per_process(self, monkeypatch, capsys):
        self._patched(monkeypatch)
        BedrockAdapter(api_key="k1")
        BedrockAdapter(api_key="k2")
        err = capsys.readouterr().err
        assert err.count("ignores `api_key`") == 1

    def test_no_warning_without_api_key(self, monkeypatch, capsys):
        self._patched(monkeypatch)
        BedrockAdapter()
        assert "api_key" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Inference-profile model IDs
# ---------------------------------------------------------------------------


class TestInferenceProfileIds:
    def test_profile_id_passed_verbatim(self):
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        _complete(adapter, model="global.anthropic.claude-opus-4-8")
        assert client.messages.create.call_args.kwargs["model"] == (
            "global.anthropic.claude-opus-4-8"
        )

    def test_validate_probes_the_passed_profile(self):
        adapter, client = _stub_adapter(lambda **kw: _ok_response())
        adapter.validate(model="us.anthropic.claude-haiku-4-5-20251001-v1:0")
        kwargs = client.messages.create.call_args.kwargs
        assert kwargs["model"] == "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        assert kwargs["max_tokens"] == 1


# ---------------------------------------------------------------------------
# Bedrock-specific error mapping
# ---------------------------------------------------------------------------


class TestErrorMapping:
    def test_access_denied_maps_to_auth_error_with_model_access_hint(self):
        def respond(**kw):
            raise anthropic.PermissionDeniedError(
                message=(
                    "You don't have access to the model with the specified "
                    "model ID."
                ),
                response=_fake_http_resp(403),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMAuthError) as exc_info:
            _complete(adapter)
        assert "Model access" in str(exc_info.value)

    def test_validate_access_denied_carries_the_same_hint(self):
        def respond(**kw):
            raise anthropic.PermissionDeniedError(
                message="AccessDeniedException",
                response=_fake_http_resp(403),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMAuthError) as exc_info:
            adapter.validate(model="us.anthropic.claude-sonnet-4-6")
        assert "Model access" in str(exc_info.value)

    def test_invalid_model_identifier_400_maps_to_not_found(self):
        """Bedrock reports a malformed/unknown model ID as a 400
        ValidationException, not a 404 — it must still fail like a
        typo'd model so the registry's validate() catches it at init."""

        def respond(**kw):
            raise anthropic.BadRequestError(
                message="The provided model identifier is invalid.",
                response=_fake_http_resp(400),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMNotFoundError):
            _complete(adapter, model="us.anthropic.claude-typo-v1:0")

    def test_other_400_is_a_response_error(self):
        def respond(**kw):
            raise anthropic.BadRequestError(
                message="max_tokens must be positive",
                response=_fake_http_resp(400),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMResponseError):
            _complete(adapter)

    def test_missing_credentials_maps_to_auth_error(self):
        """The SDK's SigV4 signer raises a bare RuntimeError when the AWS
        chain resolves no credentials; it must surface typed, with a
        pointer at the env vars, not as an unhandled RuntimeError."""

        def respond(**kw):
            raise RuntimeError("could not resolve credentials from session")

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMAuthError) as exc_info:
            _complete(adapter)
        assert "AWS_ACCESS_KEY_ID" in str(exc_info.value)

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMAuthError):
            adapter.validate(model="us.anthropic.claude-sonnet-4-6")

    def test_unrelated_runtime_error_propagates(self):
        """Only the SDK's no-credentials RuntimeError is auth-shaped;
        anything else must not be swallowed into the taxonomy."""

        def respond(**kw):
            raise RuntimeError("something else entirely")

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(RuntimeError, match="something else"):
            _complete(adapter)


# ---------------------------------------------------------------------------
# Rate-limiter coordination
# ---------------------------------------------------------------------------


class TestRateLimiterCoordination:
    def test_throttling_429_reports_to_global_limiter(self):
        def respond(**kw):
            raise anthropic.RateLimitError(
                message="too many requests",
                response=_fake_http_resp(429, retry_after="3"),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMRateLimitError):
            _complete(adapter)
        assert get_rate_limiter().is_in_backoff()

    def test_529_from_a_compat_gateway_still_maps_to_rate_limit(self):
        """Bedrock itself never sends 529, but base_url may point at an
        Anthropic-compat gateway that does; the branch is kept and must
        keep behaving like the reference adapter."""

        def respond(**kw):
            raise anthropic.APIStatusError(
                message="overloaded",
                response=_fake_http_resp(529, retry_after="5"),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMRateLimitError) as exc_info:
            _complete(adapter)
        assert exc_info.value.retry_after == 5
        assert get_rate_limiter().is_in_backoff()

    def test_other_api_status_errors_do_not_trigger_backoff(self):
        def respond(**kw):
            raise anthropic.APIStatusError(
                message="internal error",
                response=_fake_http_resp(500),
                body=None,
            )

        adapter, _ = _stub_adapter(respond)
        with pytest.raises(LLMResponseError):
            _complete(adapter)
        assert not get_rate_limiter().is_in_backoff()
