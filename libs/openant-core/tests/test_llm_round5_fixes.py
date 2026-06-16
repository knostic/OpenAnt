"""Round-5 review fixes for the LLM provider adapters (PR #69).

This file holds the regression tests for the three round-5 findings.
Each finding has a RED test written first (per the project's TDD rule),
then the adapter / helper code is changed to make it pass.

Findings covered:

* F1 (HIGH) — :func:`redact_secrets` prefix patterns are anchored with
  ``\\b``, which does NOT match between two word chars. Verified
  slip-throughs ``key%3Dsk-ant-…`` (URL-encoded ``key=``) and
  ``xsk-ant-…`` (abutting word char) pass through UNREDACTED. The fix
  drops the leading ``\\b`` and also catches the ``%3D`` separator form,
  WITHOUT over-redacting ordinary hyphenated words (``disk-``, ``task-``,
  ``risk-free``). Folds in L2: the ``AIza`` tail length is made tolerant
  (``{30,}`` instead of exactly ``{35}``).
* F2 (HIGH) — adapters ``raise LLM*Error(redact_secrets(str(exc))) from
  exc``. The wrapped message is redacted but ``from exc`` keeps the raw
  SDK exception (key in its body) as ``__cause__``; ``step_context``'s
  ``__exit__`` calls ``traceback.print_exc()`` → the unredacted cause
  reaches stderr/logs. The fix raises from a lightweight *redacted* cause
  that still carries ``status_code`` / ``request_id`` so
  ``_build_error_info`` keeps surfacing those fields.
* F3 (MED) — Google ``HttpRetryOptions(attempts=max_retries)`` is
  off-by-one: the SDK's ``attempts`` counts the original request, so for
  parity with OpenAI/Anthropic ``max_retries`` (retries beyond the first)
  the adapter must forward ``attempts = max_retries + 1``.

Everything here stubs the SDK boundary; nothing hits the network.
"""

from __future__ import annotations

import traceback
from types import SimpleNamespace
from unittest.mock import MagicMock

import anthropic
import httpx
import openai
import pytest
from google import genai
from google.genai import errors as genai_errors

from utilities.context_enhancer import _build_error_info
from utilities.llm import (
    LLMResponseError,
    Message,
    TextBlock,
)
from utilities.llm._redact import redact_secrets
from utilities.llm.providers.anthropic import AnthropicAdapter
from utilities.llm.providers.google import GoogleAdapter
from utilities.llm.providers.openai import OpenAIAdapter
from utilities.llm_client import reset_warning_state
from utilities.rate_limiter import reset_rate_limiter


@pytest.fixture(autouse=True)
def _reset_state():
    # A leaked backoff would make later tests sleep; reset around each test.
    reset_rate_limiter()
    reset_warning_state()
    yield
    reset_rate_limiter()
    reset_warning_state()


def _hi():
    return [Message(role="user", content=[TextBlock("hi")])]


# ---------------------------------------------------------------------------
# Adapter stubs (mirror tests/test_llm_round4_fixes.py)
# ---------------------------------------------------------------------------


def _anthropic_stub(side_effect):
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages = MagicMock()
    client.messages.create = MagicMock(side_effect=side_effect)
    return AnthropicAdapter(_client=client), client


def _openai_stub(side_effect):
    client = MagicMock(spec=openai.OpenAI)
    client.chat = MagicMock()
    client.chat.completions = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=side_effect)
    return OpenAIAdapter(_client=client), client


def _google_stub(side_effect):
    client = MagicMock(spec=genai.Client)
    client.models = MagicMock()
    client.models.generate_content = MagicMock(side_effect=side_effect)
    return GoogleAdapter(_client=client), client


def _a_fake_http(status):
    return httpx.Response(
        status_code=status,
        request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
    )


def _openai_fake_http(status):
    return httpx.Response(
        status_code=status,
        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"),
    )


def _g_client_error(code, message):
    response_json = {"error": {"code": code, "message": message, "status": ""}}
    resp = httpx.Response(
        status_code=code,
        request=httpx.Request(
            "POST",
            "https://generativelanguage.googleapis.com/v1beta/models/x:generateContent",
        ),
    )
    return genai_errors.ClientError(code, response_json, resp)


# ===========================================================================
# F1 — redaction regex slip-through (HIGH) + L2 (AIza tail tolerance)
# ===========================================================================


class TestF1RedactionSlipThrough:
    def test_url_encoded_key_separator_is_redacted(self):
        """``key%3Dsk-ant-…`` — the URL-encoded ``key=`` form, common in
        an echoed query string. The ``\\b`` anchor before ``sk-`` fails
        because the char before ``sk-`` is ``D`` (a word char), so the
        Anthropic key slips through today."""
        secret = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF"
        out = redact_secrets(f"url?key%3D{secret}&x=1")
        assert secret not in out, out

    def test_abutting_word_char_before_key_is_redacted(self):
        """``xsk-ant-…`` — a key abutting a preceding word char. ``\\b``
        does not match between ``x`` and ``s`` (both word chars), so the
        key passes through unredacted today."""
        secret = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF"
        out = redact_secrets(f"prefixed:x{secret} bad")
        assert secret not in out, out

    def test_abutting_word_char_before_generic_sk_key(self):
        secret = "sk-proj-ABCDEFG1234567890hijklmnop"
        out = redact_secrets(f"junkX{secret} trailing")
        assert secret not in out, out

    def test_url_encoded_separator_before_aiza_key(self):
        secret = "AIzaSyA1234567890_abcDEFghIJklmNOpqrSTuvwx"
        out = redact_secrets(f"q?key%3D{secret}&z=2")
        assert secret not in out, out

    # --- L2: AIza tail length tolerance (30+ rather than exactly 35) -----

    def test_aiza_short_tail_is_redacted(self):
        """L2: an AIza key with a 30-char tail (shorter than today's
        39-char shape) should still be masked for future-proofing."""
        secret = "AIza" + "B" * 30  # 30-char tail
        out = redact_secrets(f"leaked {secret} here")
        assert secret not in out, out

    def test_aiza_long_tail_is_redacted(self):
        secret = "AIzaSyA1234567890_abcDEFghIJklmNOpqrSTuvwx"  # 38-char tail
        out = redact_secrets(f"leaked {secret} here")
        assert secret not in out, out

    # --- CRITICAL negative cases: do NOT over-redact ordinary prose -----

    def test_disk_drive_not_redacted(self):
        prose = "the disk-drive failed to mount"
        assert redact_secrets(prose) == prose

    def test_task_list_not_redacted(self):
        prose = "update the task-list before the standup"
        assert redact_secrets(prose) == prose

    def test_risk_free_not_redacted(self):
        prose = "a risk-free refactor of the disk-cache layer"
        assert redact_secrets(prose) == prose

    def test_normal_prose_unchanged(self):
        prose = "The model returned a 400 Bad Request: invalid 'messages' field."
        assert redact_secrets(prose) == prose

    def test_hyphenated_words_with_sk_substring_not_redacted(self):
        # "ask-", "risk-", "disk-", "task-" all contain an "sk-" run that
        # the de-anchored pattern must NOT treat as a key prefix.
        for word in ("ask-someone", "risk-averse", "disk-usage", "task-queue"):
            assert redact_secrets(word) == word, word

    # --- still-passing: the round-4 positive cases stay green -----------

    def test_plain_anthropic_key_still_redacted(self):
        secret = "sk-ant-api03-AbCdEf123456789ZyXwVu"
        out = redact_secrets(f"bad key: {secret} rejected")
        assert secret not in out
        assert "rejected" in out


# ===========================================================================
# F2 — raw key leaks via the chained __cause__ (HIGH)
# ===========================================================================


class TestF2CauseChainLeak:
    def test_anthropic_secret_absent_from_traceback(self):
        """The raised LLMError's full traceback (which is what
        ``step_context`` prints via ``traceback.print_exc``) must NOT
        contain the raw key carried in the SDK exception's message."""
        secret = "sk-ant-api03-LEAKED1234567890abcdefGHIJ"

        def boom(**kw):
            raise anthropic.APIStatusError(
                message=f"400 invalid_request: api key {secret} is bad",
                response=_a_fake_http(400),
                body=None,
            )

        adapter, _ = _anthropic_stub(boom)
        with pytest.raises(LLMResponseError) as exc_info:
            adapter.complete(model="claude-test", system=None, messages=_hi(), max_tokens=8)
        tb = "".join(traceback.format_exception(exc_info.value))
        assert secret not in tb, "raw key leaked through the cause chain"

    def test_openai_secret_absent_from_traceback(self):
        secret = "sk-proj-LEAKED1234567890abcdefGHIJKL"

        def boom(**kw):
            raise openai.BadRequestError(
                message=f"400: key {secret} rejected",
                response=_openai_fake_http(400),
                body=None,
            )

        adapter, _ = _openai_stub(boom)
        with pytest.raises(LLMResponseError) as exc_info:
            adapter.complete(model="gpt-4o", system=None, messages=_hi(), max_tokens=8)
        tb = "".join(traceback.format_exception(exc_info.value))
        assert secret not in tb

    def test_google_secret_absent_from_traceback(self):
        secret = "AIzaSyLEAKED1234567890_abcDEFghIJklmNOpqr"

        def boom(**kw):
            raise _g_client_error(400, f"bad request with key={secret}")

        adapter, _ = _google_stub(boom)
        with pytest.raises(LLMResponseError) as exc_info:
            adapter.complete(model="gemini-2.5-pro", system=None, messages=_hi(), max_tokens=8)
        tb = "".join(traceback.format_exception(exc_info.value))
        assert secret not in tb

    def test_validate_path_secret_absent_from_traceback(self):
        """The redaction must also hold on the ``validate()`` path, not
        just ``complete()`` — validate runs at scan startup."""
        secret = "sk-ant-api03-VALIDATELEAK1234567890abcd"

        def boom(**kw):
            raise anthropic.APIStatusError(
                message=f"400: key {secret} bad",
                response=_a_fake_http(400),
                body=None,
            )

        adapter, _ = _anthropic_stub(boom)
        with pytest.raises(LLMResponseError) as exc_info:
            adapter.validate(model="claude-test")
        tb = "".join(traceback.format_exception(exc_info.value))
        assert secret not in tb

    # --- no regression: status_code / request_id still reach the report -

    def test_status_code_and_request_id_reach_build_error_info(self):
        """``_build_error_info`` reads ``status_code`` / ``request_id``
        off ``__cause__`` today. After the F2 fix the cause is a redacted
        stand-in, but it MUST still carry those fields so the JSON report
        keeps populating them."""
        secret = "sk-ant-api03-LEAKED1234567890abcdefGHIJ"

        # The anthropic SDK populates ``request_id`` from the response's
        # ``request-id`` header in ``APIStatusError.__init__`` (and
        # ``status_code`` from the status). Drive both through a real
        # httpx.Response so we exercise the genuine SDK attribute surface
        # the adapter copies onto the redacted cause.
        response = httpx.Response(
            status_code=400,
            headers={"request-id": "req_abc123"},
            request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
        )

        def boom(**kw):
            raise anthropic.APIStatusError(
                message=f"400: key {secret} bad",
                response=response,
                body=None,
            )

        adapter, _ = _anthropic_stub(boom)
        with pytest.raises(LLMResponseError) as exc_info:
            adapter.complete(model="claude-test", system=None, messages=_hi(), max_tokens=8)

        info = _build_error_info(exc_info.value)
        assert info["type"] == "api_status"
        assert info.get("status_code") == 400
        assert info.get("request_id") == "req_abc123"
        # And the report message itself stays clean.
        assert secret not in info["message"]


# ===========================================================================
# F3 — Google retries off-by-one (MED)
# ===========================================================================


class TestF3GoogleRetryOffByOne:
    def test_attempts_is_max_retries_plus_one(self, monkeypatch):
        """SDK ``attempts`` counts the original request, so for parity
        with OpenAI/Anthropic ``max_retries`` (retries beyond the first)
        the adapter must forward ``attempts = max_retries + 1``."""
        captured = {}

        class FakeClient:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.models = MagicMock()

        monkeypatch.setattr(
            "utilities.llm.providers.google.genai.Client", FakeClient
        )
        GoogleAdapter(api_key="k", max_retries=5)
        retry = captured["http_options"].retry_options
        assert retry.attempts == 6, "max_retries=5 must map to attempts=6"

    def test_zero_retries_maps_to_one_attempt(self, monkeypatch):
        """``max_retries=0`` → ``attempts=1`` → no retries (sane edge)."""
        captured = {}

        class FakeClient:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.models = MagicMock()

        monkeypatch.setattr(
            "utilities.llm.providers.google.genai.Client", FakeClient
        )
        GoogleAdapter(api_key="k", max_retries=0)
        retry = captured["http_options"].retry_options
        assert retry.attempts == 1, "max_retries=0 must map to attempts=1 (no retries)"

    def test_offset_holds_with_base_url(self, monkeypatch):
        captured = {}

        class FakeClient:
            def __init__(self, **kwargs):
                captured.update(kwargs)
                self.models = MagicMock()

        monkeypatch.setattr(
            "utilities.llm.providers.google.genai.Client", FakeClient
        )
        GoogleAdapter(api_key="k", base_url="https://proxy.example/v1", max_retries=4)
        http_options = captured["http_options"]
        assert http_options.base_url == "https://proxy.example/v1"
        assert http_options.retry_options.attempts == 5
