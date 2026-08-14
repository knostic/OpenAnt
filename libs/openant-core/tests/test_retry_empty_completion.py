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
