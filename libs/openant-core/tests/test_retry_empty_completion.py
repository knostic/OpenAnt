"""F21/F23 — a transient empty-completion ERROR must be retried in-run.

The provider adapters RAISE on an empty completion (no usable content) instead of
returning a fake SAFE — anthropic.py / google.py / openai.py raise
``LLMResponseError`` with the message "no usable content (empty completion)".
That surfaces as a visible ERROR (good, no silent false-negative), but the error
string matches none of is_retryable_error's transient terms, so the detection
retry pass in core/analyzer.py never re-attempts it in-run (only a later
checkpoint-resume recovers it).

The empty-completion cause is predominantly TRANSIENT (a thinking-block
truncation or a malformed/overloaded response), because the DETERMINISTIC
content-filter / policy case is a distinct exception, ``LLMRefusalError``
("refused the request (stop_reason='refusal')"), raised earlier. So classifying
"empty completion" as retryable recovers the transient case (mirroring the
parse_error fix) WITHOUT retrying deterministic refusals, whose message does not
contain "empty completion".
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # libs/openant-core

from utilities.rate_limiter import is_retryable_error  # noqa: E402


# Verbatim adapter messages (str(e) of the raised exception is what reaches the
# retry filter via core.analyzer._process_unit's except-branch error=str(e)).
_EMPTY_ANTHROPIC = ("AnthropicAdapter returned no usable content (empty completion); "
                    "the request may have been filtered or the response was malformed")
_EMPTY_GEMINI = ("Gemini returned a candidate with no usable content (empty completion); "
                 "the response may have been truncated (a thinking block)")
# OpenAI Responses-API empty path (openai.py:730): says "no usable content" but
# NOT "empty completion" — the term must match the shared "no usable content"
# phrase so this sibling is covered too.
_EMPTY_OPENAI_RESPONSES = ("OpenAI Responses returned no usable content (status='incomplete'); "
                           "the request may have been truncated (reasoning consumed the budget) "
                           "or filtered")
# OpenAI Chat-Completions empty paths (openai.py:760, :816): say "empty
# completion" but NOT "no usable content" — so the term set must include the
# "empty completion" phrase too, or these (and OpenRouter, which reuses the
# translator) are silently not retried.
_EMPTY_OPENAI_CHAT_NOCHOICES = ("OpenAIAdapter returned no choices (empty completion); "
                                "the request may have been filtered or the response was malformed")
_EMPTY_OPENAI_CHAT_NOBLOCKS = ("OpenAIAdapter returned an empty completion (no text or tool "
                               "calls); the request may have been filtered or malformed")
_REFUSAL = ("AnthropicAdapter refused the request (stop_reason='refusal'); the model "
            "declined to answer for safety or policy reasons")


def test_empty_completion_is_retryable():
    assert is_retryable_error(_EMPTY_ANTHROPIC) is True
    assert is_retryable_error(_EMPTY_GEMINI) is True
    assert is_retryable_error(_EMPTY_OPENAI_RESPONSES) is True
    assert is_retryable_error(_EMPTY_OPENAI_CHAT_NOCHOICES) is True
    assert is_retryable_error(_EMPTY_OPENAI_CHAT_NOBLOCKS) is True


def test_refusal_is_not_retryable():
    # NEGATIVE CONTROL: a deterministic refusal must stay non-retryable — its
    # message lacks "empty completion", so the new term must not catch it.
    assert is_retryable_error(_REFUSAL) is False


def test_parse_error_still_retryable():
    # REGRESSION: the stacked-on parse_error classification (F22) is preserved.
    assert is_retryable_error({"type": "parse_error"}) is True


def test_unrelated_response_error_not_retryable():
    # A serialization/other LLMResponseError (different message) is not falsely
    # caught by the "empty completion" term.
    assert is_retryable_error("AnthropicAdapter: cannot serialise block of type Foo") is False


# ---------------------------------------------------------------------------
# #292 — the DICT shape: enhance passes a structured dict built by
# context_enhancer._build_error_info; before this fix the empty-completion
# case was classified api_status with no status_code (the raise carries none),
# so is_retryable_error returned False on the one path whose docstring
# documented the retry. All 48 errored verify/enhance records on the run that
# filed the issue carried exactly this exception.
# ---------------------------------------------------------------------------
from utilities.context_enhancer import _build_error_info  # noqa: E402
from utilities.llm.adapter import LLMResponseError  # noqa: E402


def _info(msg: str) -> dict:
    """The dict enhance builds from a bare LLMResponseError raise (no `from`,
    so no __cause__ / status_code — exactly as anthropic.py raises it)."""
    return _build_error_info(LLMResponseError(msg))


def test_empty_completion_dict_is_retryable():
    # the branch asymmetry: same exception, dict shape — was False
    assert is_retryable_error(_info(_EMPTY_ANTHROPIC)) is True
    assert is_retryable_error(_info(_EMPTY_GEMINI)) is True
    assert is_retryable_error(_info(_EMPTY_OPENAI_RESPONSES)) is True
    assert is_retryable_error(_info(_EMPTY_OPENAI_CHAT_NOCHOICES)) is True
    assert is_retryable_error(_info(_EMPTY_OPENAI_CHAT_NOBLOCKS)) is True


def test_build_error_info_classifies_empty_completion():
    info = _info(_EMPTY_ANTHROPIC)
    assert info["type"] == "empty_completion"


def test_refusal_dict_is_not_retryable():
    assert is_retryable_error(_info(_REFUSAL)) is False


def test_old_shape_dict_backstop():
    """Dicts built BEFORE the empty_completion classification (e.g. stored
    agent_context adopted on resume) carry type api_status with the
    empty-completion message — the message backstop must honour them."""
    old = {"type": "api_status", "exception_class": "LLMResponseError",
           "message": _EMPTY_ANTHROPIC}
    assert is_retryable_error(old) is True


def test_api_status_dict_unchanged():
    # a REAL server error still retries; a client error still does not
    assert is_retryable_error({"type": "api_status", "status_code": 529}) is True
    assert is_retryable_error({"type": "api_status", "status_code": 400}) is False


# ---------------------------------------------------------------------------
# #292 secondary — the string branch matched status codes as substrings over
# the whole message. Now they are PARSED bounded numbers tested against the
# SAME explicit allowlist (500,502,503,504,520,522,523,524,529 — 501 is a
# deterministic "not implemented", deliberately excluded; NOT a 5xx range).
# ---------------------------------------------------------------------------
def test_status_codes_parsed_not_substring():
    # substring-inside-longer-number false positives are gone
    assert is_retryable_error("byte offset 5000") is False
    assert is_retryable_error("read 15002 bytes") is False
    # real provider status formats still retry
    assert is_retryable_error(
        "Error code: 529 - {'type': 'overloaded_error'}") is True
    assert is_retryable_error("Error code: 500 - internal server error") is True
    # 501 is deliberately excluded (deterministic not-implemented)
    assert is_retryable_error("Error code: 501 - not implemented") is False


def test_status_code_residual_documented():
    """RESIDUAL (accepted by #292's corrected suggestion 3): a standalone
    '500' in non-status context ('token count 500', 'model gpt-500') still
    parses as the code 500 and retries — bounded to one extra attempt, and
    distinguishing it would need format-specific parsing the issue declined."""
    assert is_retryable_error("token count 500 exceeded") is True
