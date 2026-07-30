import os
import sys
import types

import pytest

# Ensure `src` is on path so imports like `from llm_client import ...`
# work when running tests directly.

import utilities.autopatcher.llm_client as llm_client
from utilities.autopatcher.llm_client import LLMClient, call_llm, _mock_response
from utilities.autopatcher.llm_config import DEFAULT_MAX_TOKENS


# ---------------------------------------------------------------------------
# LLMClient.is_mock — must reflect the active LLM_PROVIDER, not just OPENAI_API_KEY
# ---------------------------------------------------------------------------

def test_is_mock_false_when_anthropic_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client = LLMClient()
    assert not client.is_mock


def test_is_mock_false_when_openai_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    client = LLMClient(api_key="sk-fake")
    assert not client.is_mock


def test_is_mock_true_when_mock_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    client = LLMClient()
    assert client.is_mock


def test_is_mock_true_when_no_provider_no_key(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client = LLMClient()
    assert client.is_mock


def test_is_mock_false_when_cached_provider_anthropic(monkeypatch):
    # Simulates a session where the user already selected anthropic interactively.
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setattr(llm_client, "_cached_provider", "anthropic")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client = LLMClient()
    assert not client.is_mock


# ---------------------------------------------------------------------------


def test_mock_provider_returns_string(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    res = call_llm("test prompt for mock")
    assert isinstance(res, str)
    assert res


def test_anthropic_explicit_provider_raises_on_api_error(monkeypatch):
    """LLM_PROVIDER=anthropic + API failure must raise, not fall back to mock."""
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})

    class FakeAnthropic:
        def __init__(self, api_key=None):
            pass

        class messages:
            @staticmethod
            def create(model, max_tokens, messages):
                raise RuntimeError("simulated anthropic failure")

    fake_mod = types.SimpleNamespace(Anthropic=FakeAnthropic)
    monkeypatch.setitem(sys.modules, "anthropic", fake_mod)

    with pytest.raises(RuntimeError, match="Anthropic API call failed"):
        call_llm("prompt that triggers anthropic")


def test_openai_explicit_provider_raises_on_api_error(monkeypatch):
    """LLM_PROVIDER=openai + API failure must raise, not fall back to mock."""
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})

    class FakeOpenAI:
        def __init__(self, api_key=None):
            pass

        class chat:
            class completions:
                @staticmethod
                def create(model, messages, temperature, max_tokens):
                    raise RuntimeError("simulated openai failure")

    fake_mod = types.SimpleNamespace(OpenAI=FakeOpenAI)
    monkeypatch.setitem(sys.modules, "openai", fake_mod)

    with pytest.raises(RuntimeError, match="OpenAI API call failed"):
        call_llm("prompt that triggers openai")


def test_anthropic_explicit_provider_raises_on_missing_key(monkeypatch):
    """LLM_PROVIDER=anthropic with no key must raise, not fall back to mock."""
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")

    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY is not set"):
        call_llm("prompt with no anthropic key")


def test_openai_explicit_provider_raises_on_missing_key(monkeypatch):
    """LLM_PROVIDER=openai with no key must raise, not fall back to mock."""
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})
    monkeypatch.setattr("builtins.input", lambda *a, **k: "")

    with pytest.raises(RuntimeError, match="OPENAI_API_KEY is not set"):
        call_llm("prompt with no openai key")


class _FakeInteractiveStdin:
    def isatty(self):
        return True


def _fake_anthropic_ok(captured=None):
    class FakeContentBlock:
        text = "ok"

    class FakeResponse:
        content = [FakeContentBlock()]
        stop_reason = "end_turn"

    class FakeAnthropic:
        def __init__(self, api_key=None):
            if captured is not None:
                captured["api_key"] = api_key

        class messages:
            @staticmethod
            def create(model, max_tokens, messages):
                if captured is not None:
                    captured["model"] = model
                return FakeResponse()

    return types.SimpleNamespace(Anthropic=FakeAnthropic)


# ---------------------------------------------------------------------------
# Interactive prompt text must reach stderr, never stdout -- stdout is
# reserved for the JSON envelope openant/cli.py writes, and Go's
# python.Invoke parses it as pure JSON. The selected/typed value must still
# flow through correctly regardless of which channel displays the prompt.
# ---------------------------------------------------------------------------

def test_provider_menu_prompt_text_goes_to_stderr_not_stdout(monkeypatch, capsys):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda: "3")  # 3) Mock

    res = call_llm("prompt")

    assert res == _mock_response("prompt")
    captured = capsys.readouterr()
    assert "Choose (1/2/3): " in captured.err
    assert "Choose (1/2/3): " not in captured.out


def test_model_menu_prompt_text_goes_to_stderr_not_stdout(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_model", {})
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda: "1")  # first model in the menu

    captured_call: dict = {}
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic_ok(captured_call))

    call_llm("prompt")

    captured = capsys.readouterr()
    assert "Select Anthropic model:" in captured.err
    assert "Choose (1-" in captured.err
    assert "Select Anthropic model:" not in captured.out
    assert "Choose (1-" not in captured.out
    # the typed choice ("1") actually selected a real model, not a fallback default
    assert captured_call["model"]


def test_api_key_prompt_text_goes_to_stderr_not_stdout(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "_cached_provider", "anthropic")
    monkeypatch.setattr(llm_client, "_cached_model", {"anthropic": "claude-haiku-4-5-20251001"})
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda: "sk-typed-key")

    captured_call: dict = {}
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic_ok(captured_call))

    call_llm("prompt")

    captured = capsys.readouterr()
    assert "Enter ANTHROPIC_API_KEY: " in captured.err
    assert "Enter ANTHROPIC_API_KEY: " not in captured.out
    # the typed value actually reached the API client, not just the prompt
    assert captured_call["api_key"] == "sk-typed-key"


def test_non_interactive_defaults_to_mock(monkeypatch):
    # Ensure no provider env var
    monkeypatch.delenv("LLM_PROVIDER", raising=False)

    # Ensure input() would raise if called
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))

    # Simulate non-interactive stdin
    class FakeStdin:
        def isatty(self):
            return False

    monkeypatch.setattr("sys.stdin", FakeStdin())

    res = call_llm("no interactive")
    assert res == _mock_response("no interactive")


# ---------------------------------------------------------------------------
# Configurable max_tokens (LLM_MAX_TOKENS override + DEFAULT_MAX_TOKENS)
# ---------------------------------------------------------------------------

def _fake_anthropic_module(captured, stop_reason="end_turn", text="ok"):
    class FakeContentBlock:
        def __init__(self, text):
            self.text = text

    class FakeResponse:
        def __init__(self):
            self.content = [FakeContentBlock(text)]
            self.stop_reason = stop_reason

    class FakeAnthropic:
        def __init__(self, api_key=None):
            pass

        class messages:
            @staticmethod
            def create(model, max_tokens, messages):
                captured["max_tokens"] = max_tokens
                return FakeResponse()

    return types.SimpleNamespace(Anthropic=FakeAnthropic)


def _fake_openai_module(captured, finish_reason="stop", text="ok"):
    class FakeMessage:
        def __init__(self, content):
            self.content = content

    class FakeChoice:
        def __init__(self, content, finish_reason):
            self.message = FakeMessage(content)
            self.finish_reason = finish_reason

    class FakeResponse:
        def __init__(self):
            self.choices = [FakeChoice(text, finish_reason)]

    class FakeOpenAI:
        def __init__(self, api_key=None):
            pass

        class chat:
            class completions:
                @staticmethod
                def create(model, messages, temperature, max_tokens):
                    captured["max_tokens"] = max_tokens
                    return FakeResponse()

    return types.SimpleNamespace(OpenAI=FakeOpenAI)


def test_anthropic_uses_default_max_tokens_when_env_unset(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.delenv("LLM_MAX_TOKENS", raising=False)
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})

    captured: dict = {}
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic_module(captured))

    call_llm("prompt")
    assert captured["max_tokens"] == DEFAULT_MAX_TOKENS
    assert DEFAULT_MAX_TOKENS == 4096


def test_anthropic_honors_llm_max_tokens_override(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MAX_TOKENS", "8000")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})

    captured: dict = {}
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic_module(captured))

    call_llm("prompt")
    assert captured["max_tokens"] == 8000


def test_invalid_llm_max_tokens_falls_back_to_default(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MAX_TOKENS", "not-a-number")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})

    captured: dict = {}
    monkeypatch.setitem(sys.modules, "anthropic", _fake_anthropic_module(captured))

    call_llm("prompt")
    assert captured["max_tokens"] == DEFAULT_MAX_TOKENS
    # stderr, not stdout: progress/warning prints were redirected to stderr
    # during the merge into OpenAnt (stdout carries only the JSON envelope).
    assert "Invalid LLM_MAX_TOKENS" in capsys.readouterr().err


def test_openai_receives_explicit_max_tokens(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MAX_TOKENS", "2048")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})

    captured: dict = {}
    monkeypatch.setitem(sys.modules, "openai", _fake_openai_module(captured))

    call_llm("prompt")
    assert captured["max_tokens"] == 2048


# ---------------------------------------------------------------------------
# Per-stage call metadata (stop_reason / finish_reason capture)
# ---------------------------------------------------------------------------

def test_anthropic_call_metadata_captures_max_tokens_stop_reason(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})
    monkeypatch.setattr(llm_client, "_call_metadata", {})

    captured: dict = {}
    monkeypatch.setitem(
        sys.modules, "anthropic", _fake_anthropic_module(captured, stop_reason="max_tokens")
    )

    call_llm("prompt", stage="patch_generation")
    meta = llm_client.get_call_metadata()
    assert meta["patch_generation"]["stop_reason"] == "max_tokens"
    assert meta["patch_generation"]["provider"] == "anthropic"


def test_openai_call_metadata_captures_finish_reason(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})
    monkeypatch.setattr(llm_client, "_call_metadata", {})

    captured: dict = {}
    monkeypatch.setitem(
        sys.modules, "openai", _fake_openai_module(captured, finish_reason="length")
    )

    call_llm("prompt", stage="patch_review")
    meta = llm_client.get_call_metadata()
    assert meta["patch_review"]["stop_reason"] == "length"


def test_mock_call_populates_metadata_with_mock_stop_reason(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_call_metadata", {})

    call_llm("prompt", stage="confidence_scorer")
    meta = llm_client.get_call_metadata()
    assert meta["confidence_scorer"]["stop_reason"] == "mock"
    assert meta["confidence_scorer"]["max_tokens_configured"] is None


def test_complete_passes_stage_through_to_call_metadata(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_call_metadata", {})

    client = LLMClient(api_key="")
    client.complete("system prompt", "user message", stage="challenger")
    meta = llm_client.get_call_metadata()
    assert "challenger" in meta


def test_clear_call_metadata_empties_the_store(monkeypatch):
    monkeypatch.setattr(llm_client, "_call_metadata", {
        "patch_generation": {"provider": "anthropic", "model": "x", "max_tokens_configured": 1000, "stop_reason": "max_tokens"},
    })
    llm_client.clear_call_metadata()
    assert llm_client.get_call_metadata() == {}


def test_stale_metadata_does_not_leak_into_a_new_run(monkeypatch):
    # Simulates two sequential runs in the same process (e.g. a batch
    # runner) without the reset: a stage from run 1 must not survive into
    # run 2's metadata once clear_call_metadata() is called between them.
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_call_metadata", {})

    # "Run 1": patch_generation stage recorded.
    call_llm("prompt for run 1", stage="patch_generation")
    assert "patch_generation" in llm_client.get_call_metadata()

    # Reset, as main.py now does before each run.
    llm_client.clear_call_metadata()
    assert llm_client.get_call_metadata() == {}

    # "Run 2": only a different stage is called.
    call_llm("prompt for run 2", stage="challenger")
    meta = llm_client.get_call_metadata()
    assert "challenger" in meta
    assert "patch_generation" not in meta, "stale stage from a previous run leaked into the new run's metadata"


def test_complete_default_stage_is_unknown_and_does_not_break(monkeypatch):
    # Existing callers that don't pass `stage` must keep working unchanged.
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_call_metadata", {})

    client = LLMClient(api_key="")
    result = client.complete("system prompt", "user message")
    assert isinstance(result, str)
    meta = llm_client.get_call_metadata()
    assert "unknown" in meta
