import os
import sys

import pytest

import utilities.autopatcher.llm_client as llm_client
from utilities.autopatcher.llm_client import (
    LLMClient,
    ModelUnavailableError,
    call_llm,
    _mock_response,
)
from utilities.autopatcher.llm_config import DEFAULT_MAX_TOKENS
from utilities.llm import (
    PHASES,
    CompletionResult,
    ConfigFile,
    LLMConfig,
    LLMConnectionError,
    LLMNotFoundError,
    PhaseRef,
    ProviderConfig,
    TextBlock,
    empty_config,
)


# ---------------------------------------------------------------------------
# Isolation: every test in this module must be fully hermetic w.r.t. the
# real ~/.config/openant/config.json on the machine running the suite, and
# must start from a clean slate of Auto Patcher's session-cached choices.
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_shared_infra(monkeypatch):
    # Default: "no config.json" -- falls through to env-var / interactive
    # resolution, matching pre-migration test assumptions. Tests exercising
    # config.json-sourced credentials override this explicitly.
    monkeypatch.setattr(llm_client, "load_config_file", lambda: empty_config())
    # Fresh session state per test -- these are module-globals meant to
    # persist across an entire real run/process, not across unrelated tests.
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_api_keys", {})
    monkeypatch.setattr(llm_client, "_cached_model", {})
    monkeypatch.setattr(llm_client, "_cached_adapters", {})
    monkeypatch.setattr(llm_client, "_call_metadata", {})
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("LLM_MAX_TOKENS", raising=False)


class _FakeInteractiveStdin:
    def isatty(self):
        return True


class _FakeNonInteractiveStdin:
    def isatty(self):
        return False


def _make_full_llm_config(name, analyze_provider, analyze_model, filler_provider="anthropic", filler_model="claude-sonnet-4-6"):
    """Build a complete, schema-valid LLMConfig (all 7 canonical phases --
    LLMConfig.__post_init__ requires exactly these) with only the
    "analyze" phase set to the given provider/model. Auto Patcher inherits
    ONLY the analyze binding; the filler values on the other 6 phases are
    arbitrary and never consulted by anything under test here."""
    phases = {p: PhaseRef(provider=filler_provider, model=filler_model) for p in PHASES}
    phases["analyze"] = PhaseRef(provider=analyze_provider, model=analyze_model)
    return LLMConfig(name=name, phases=phases)


def _config_with_default_llm(name, analyze_provider, analyze_model, providers=None):
    """A ConfigFile whose default_llm points at a fully valid, explicitly
    user-authored llm-config (never the built-in "openant-default", which
    Auto Patcher deliberately never inherits from)."""
    return ConfigFile(
        default_llm=name,
        llm_configs={name: _make_full_llm_config(name, analyze_provider, analyze_model)},
        llm_providers=providers or {},
    )


def _completion_result(text="ok", stop_reason="end_turn", input_tokens=1, output_tokens=1):
    return CompletionResult(
        content=[TextBlock(text=text)],
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        stop_reason=stop_reason,
    )


class _FakeAdapter:
    """Records every complete() call; returns/raises canned outcomes in order.

    `outcomes`: a list where each item is either an Exception instance
    (raised) or a CompletionResult (returned). Consumed one per call; the
    last item repeats once the list is exhausted, so a single-outcome list
    behaves like "always this" for tests that only care about one call.
    """

    def __init__(self, outcomes):
        self.calls = []
        self._outcomes = list(outcomes)

    def complete(self, *, model, system, messages, max_tokens, tools=None):
        self.calls.append(
            {"model": model, "system": system, "messages": messages, "max_tokens": max_tokens}
        )
        outcome = self._outcomes.pop(0) if len(self._outcomes) > 1 else self._outcomes[0]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def validate(self, model):  # pragma: no cover - not exercised here
        pass


def _install_fake_adapter(monkeypatch, outcomes, captured_provider_config=None):
    """Monkeypatch build_adapter() to return a _FakeAdapter instead of
    constructing a real anthropic/openai SDK client. Optionally records the
    ProviderConfig build_adapter() was called with."""
    fake = _FakeAdapter(outcomes)

    def _fake_build_adapter(provider_config):
        if captured_provider_config is not None:
            captured_provider_config["value"] = provider_config
        return fake

    monkeypatch.setattr(llm_client, "build_adapter", _fake_build_adapter)
    return fake


# ---------------------------------------------------------------------------
# LLMClient.is_mock — must reflect the active LLM_PROVIDER, not just OPENAI_API_KEY
# ---------------------------------------------------------------------------

def test_is_mock_false_when_anthropic_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    client = LLMClient()
    assert not client.is_mock


def test_is_mock_false_when_openai_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    client = LLMClient(api_key="sk-fake")
    assert not client.is_mock


def test_is_mock_true_when_mock_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    client = LLMClient()
    assert client.is_mock


def test_is_mock_true_when_no_provider_no_key(monkeypatch):
    client = LLMClient()
    assert client.is_mock


def test_is_mock_false_when_cached_provider_anthropic(monkeypatch):
    # Simulates a session where the user already selected anthropic interactively.
    monkeypatch.setattr(llm_client, "_cached_provider", "anthropic")
    client = LLMClient()
    assert not client.is_mock


# ---------------------------------------------------------------------------
# Mock mode bypasses live config/provider resolution entirely
# ---------------------------------------------------------------------------


def test_mock_provider_returns_string(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    res = call_llm("test prompt for mock")
    assert isinstance(res, str)
    assert res


def test_mock_provider_never_touches_shared_config(monkeypatch):
    """Mock mode must bypass live config/provider resolution, not just
    avoid a real network call."""
    def _boom():
        raise AssertionError("mock mode must not read config.json")

    monkeypatch.setattr(llm_client, "load_config_file", _boom)
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    call_llm("prompt")  # must not raise


# ---------------------------------------------------------------------------
# Mock mode is permitted ONLY when explicitly selected as "mock". An unknown
# or mistyped live provider must fail clearly -- never silently produce a
# mock Trust Report indistinguishable from a real one.
# ---------------------------------------------------------------------------


def test_unknown_env_provider_never_falls_back_to_mock(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthorpic")  # typo

    with pytest.raises(RuntimeError, match="Unknown LLM provider 'anthorpic'"):
        call_llm("prompt")


def test_unknown_env_provider_error_lists_supported_providers(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthorpic")

    with pytest.raises(RuntimeError) as excinfo:
        call_llm("prompt")
    assert "anthropic, openai, mock" in str(excinfo.value)


def test_unknown_env_provider_never_calls_mock_response(monkeypatch):
    calls = []
    monkeypatch.setattr(llm_client, "_mock_response", lambda prompt: calls.append(prompt) or "SHOULD NOT HAPPEN")
    monkeypatch.setenv("LLM_PROVIDER", "google")  # a real other-scan-pipeline provider, unsupported here

    with pytest.raises(RuntimeError, match="Unknown LLM provider 'google'"):
        call_llm("prompt")

    assert calls == []


def test_unknown_env_provider_produces_no_mock_stderr_text(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "anthorpic")

    with pytest.raises(RuntimeError):
        call_llm("prompt")

    assert "Using mock LLM" not in capsys.readouterr().err


def test_interactive_invalid_menu_choice_never_falls_back_to_mock(monkeypatch):
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda: "9")  # not 1, 2, or 3
    calls = []
    monkeypatch.setattr(llm_client, "_mock_response", lambda prompt: calls.append(prompt) or "SHOULD NOT HAPPEN")

    with pytest.raises(RuntimeError, match="Invalid choice"):
        call_llm("prompt")

    assert calls == []


# ---------------------------------------------------------------------------
# Live errors propagate — never a silent fallback to mock or another
# provider/model. The shared adapter's typed error taxonomy is preserved
# in the message, wrapped in a RuntimeError for backward-compatible
# call-site behavior.
# ---------------------------------------------------------------------------


def test_anthropic_explicit_provider_raises_on_api_error(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[LLMConnectionError("simulated anthropic failure")])

    with pytest.raises(RuntimeError, match="Anthropic API call failed"):
        call_llm("prompt that triggers anthropic")


def test_openai_explicit_provider_raises_on_api_error(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-test-model")
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[LLMConnectionError("simulated openai failure")])

    with pytest.raises(RuntimeError, match="OpenAI API call failed"):
        call_llm("prompt that triggers openai")


def test_anthropic_explicit_provider_raises_on_missing_key(monkeypatch):
    """LLM_PROVIDER=anthropic with no key anywhere must raise, not fall
    back to mock. Non-interactive so the interactive prompt path can't
    silently supply one either. LLM_MODEL is set so model resolution
    succeeds and the credential check -- what this test is actually
    about -- is what's being exercised."""
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))

    with pytest.raises(RuntimeError, match="no Anthropic API key is available"):
        call_llm("prompt with no anthropic key")


def test_openai_explicit_provider_raises_on_missing_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-test-model")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))

    with pytest.raises(RuntimeError, match="no OpenAI API key is available"):
        call_llm("prompt with no openai key")


def test_missing_credentials_never_falls_back_to_mock(monkeypatch, capsys):
    """A missing-credentials failure must be an exception, never a mock
    response returned as if nothing were wrong."""
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())

    with pytest.raises(RuntimeError):
        call_llm("prompt")
    assert "mock" not in capsys.readouterr().err.lower()


# ---------------------------------------------------------------------------
# Interactive prompt text must reach stderr, never stdout -- stdout is
# reserved for the JSON envelope openant/cli.py writes, and Go's
# python.Invoke parses it as pure JSON. The selected/typed value must still
# flow through correctly regardless of which channel displays the prompt.
# ---------------------------------------------------------------------------

def test_provider_menu_prompt_text_goes_to_stderr_not_stdout(monkeypatch, capsys):
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
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda: "1")  # first model in the menu

    captured_cfg = {}
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    captured = capsys.readouterr()
    assert "Select Anthropic model:" in captured.err
    assert "Choose (1-" in captured.err
    assert "Select Anthropic model:" not in captured.out
    assert "Choose (1-" not in captured.out
    # the typed choice ("1") actually selected a real model, not a fallback default
    assert fake.calls[0]["model"]


def test_api_key_prompt_text_goes_to_stderr_not_stdout(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(llm_client, "_cached_model", {"anthropic": "claude-haiku-4-5-20251001"})
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda: "sk-typed-key")

    captured_cfg = {}
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    captured = capsys.readouterr()
    assert "Enter ANTHROPIC_API_KEY: " in captured.err
    assert "Enter ANTHROPIC_API_KEY: " not in captured.out
    # the typed value actually reached the adapter, not just the prompt
    assert captured_cfg["value"].api_key == "sk-typed-key"


def test_non_interactive_unset_provider_fails_clearly_never_mock(monkeypatch, capsys):
    """No LLM_PROVIDER, no config binding, non-interactive: must fail
    clearly. There is no more "unset -> mock" default -- mock is
    permitted ONLY when explicitly selected."""
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))

    with pytest.raises(RuntimeError, match="No LLM_PROVIDER is set"):
        call_llm("no interactive")
    assert "mock" not in capsys.readouterr().err.lower()


# ---------------------------------------------------------------------------
# Configurable max_tokens (LLM_MAX_TOKENS override + DEFAULT_MAX_TOKENS)
# ---------------------------------------------------------------------------

def test_anthropic_uses_default_max_tokens_when_env_unset(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")
    assert fake.calls[0]["max_tokens"] == DEFAULT_MAX_TOKENS
    assert DEFAULT_MAX_TOKENS == 4096


def test_anthropic_honors_llm_max_tokens_override(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MAX_TOKENS", "8000")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")
    assert fake.calls[0]["max_tokens"] == 8000


def test_invalid_llm_max_tokens_falls_back_to_default(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MAX_TOKENS", "not-a-number")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")
    assert fake.calls[0]["max_tokens"] == DEFAULT_MAX_TOKENS
    assert "Invalid LLM_MAX_TOKENS" in capsys.readouterr().err


def test_openai_receives_explicit_max_tokens(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-test-model")
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MAX_TOKENS", "2048")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")
    assert fake.calls[0]["max_tokens"] == 2048


# ---------------------------------------------------------------------------
# Per-stage call metadata (stop_reason capture) -- and it must always record
# the model that ACTUALLY executed.
# ---------------------------------------------------------------------------

def test_anthropic_call_metadata_captures_max_tokens_stop_reason(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result(stop_reason="max_tokens")])

    call_llm("prompt", stage="patch_generation")
    meta = llm_client.get_call_metadata()
    assert meta["patch_generation"]["stop_reason"] == "max_tokens"
    assert meta["patch_generation"]["provider"] == "anthropic"


def test_openai_call_metadata_captures_finish_reason(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-test-model")
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result(stop_reason="max_tokens")])

    call_llm("prompt", stage="patch_review")
    meta = llm_client.get_call_metadata()
    assert meta["patch_review"]["stop_reason"] == "max_tokens"


def test_mock_call_populates_metadata_with_mock_stop_reason(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")

    call_llm("prompt", stage="confidence_scorer")
    meta = llm_client.get_call_metadata()
    assert meta["confidence_scorer"]["stop_reason"] == "mock"
    assert meta["confidence_scorer"]["max_tokens_configured"] is None


def test_complete_passes_stage_through_to_call_metadata(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")

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
    monkeypatch.setenv("LLM_PROVIDER", "mock")

    call_llm("prompt for run 1", stage="patch_generation")
    assert "patch_generation" in llm_client.get_call_metadata()

    llm_client.clear_call_metadata()
    assert llm_client.get_call_metadata() == {}

    call_llm("prompt for run 2", stage="challenger")
    meta = llm_client.get_call_metadata()
    assert "challenger" in meta
    assert "patch_generation" not in meta, "stale stage from a previous run leaked into the new run's metadata"


def test_complete_default_stage_is_unknown_and_does_not_break(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")

    client = LLMClient(api_key="")
    result = client.complete("system prompt", "user message")
    assert isinstance(result, str)
    meta = llm_client.get_call_metadata()
    assert "unknown" in meta


# ---------------------------------------------------------------------------
# claude-opus-4-6 must reach the shared adapter exactly unchanged: not
# replaced, not normalized, not rejected by an Auto Patcher-local whitelist.
# ---------------------------------------------------------------------------

def test_opus_4_6_reaches_shared_adapter_unchanged(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MODEL", "claude-opus-4-6")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    assert fake.calls[0]["model"] == "claude-opus-4-6"


def test_opus_4_6_is_not_a_model_alias(monkeypatch):
    """MODEL_ALIASES only maps two legacy 3.x names -- claude-opus-4-6 must
    never be silently rewritten to a different id via that table."""
    from utilities.autopatcher.llm_config import MODEL_ALIASES

    assert "claude-opus-4-6" not in MODEL_ALIASES
    assert "claude-opus-4-6" not in MODEL_ALIASES.values()


def test_opus_4_6_metadata_records_actual_executed_model(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MODEL", "claude-opus-4-6")
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt", stage="patch_generation")

    meta = llm_client.get_call_metadata()
    assert meta["patch_generation"]["model"] == "claude-opus-4-6"


def test_opus_4_6_not_rejected_by_local_whitelist_even_if_unknown_status(monkeypatch):
    """config/models.json marks claude-opus-4-6 status="unknown" (liveness
    contested) -- that must never cause a local rejection or substitution."""
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MODEL", "claude-opus-4-6")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    assert len(fake.calls) == 1
    assert fake.calls[0]["model"] == "claude-opus-4-6"


# ---------------------------------------------------------------------------
# No silent fallback: an invalid/rejected model must never trigger a call
# with Haiku, or with any other model the caller didn't explicitly choose.
# ---------------------------------------------------------------------------

def test_invalid_model_non_interactive_never_calls_haiku(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MODEL", "claude-does-not-exist")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    fake = _install_fake_adapter(
        monkeypatch, outcomes=[LLMNotFoundError("model: claude-does-not-exist")]
    )

    with pytest.raises(ModelUnavailableError):
        call_llm("prompt")

    assert len(fake.calls) == 1
    called_models = [c["model"] for c in fake.calls]
    assert "claude-haiku-4-5-20251001" not in called_models
    assert called_models == ["claude-does-not-exist"]


def test_provider_rejects_model_non_interactive_no_alternate_call(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MODEL", "claude-opus-4-6")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    fake = _install_fake_adapter(
        monkeypatch, outcomes=[LLMNotFoundError("model: claude-opus-4-6")]
    )

    with pytest.raises(ModelUnavailableError):
        call_llm("prompt")

    # Exactly the requested model was tried, once, and nothing else.
    assert len(fake.calls) == 1
    assert fake.calls[0]["model"] == "claude-opus-4-6"


# ---------------------------------------------------------------------------
# Interactive model failure UX
# ---------------------------------------------------------------------------


def _monkeypatch_known_models(monkeypatch, models):
    """Force _known_models_for()'s source deterministically for tests."""
    monkeypatch.setattr(
        llm_client,
        "_known_models_for",
        lambda provider: [m for m in models if True],
    )


def test_known_models_for_uses_the_real_shared_model_registry():
    """Exercises core.model_registry.load_models() for real -- no
    monkeypatching of _known_models_for() itself or of load_models() --
    proving the helper reuses OpenAnt's actual shipped config/models.json
    rather than an incorrect import/API name that would silently degrade
    to an empty (falsely "no alternatives available") list. No network
    involved: config/models.json is a local, static file."""
    anthropic_models = llm_client._known_models_for("anthropic")

    assert anthropic_models, "expected at least one locally known Anthropic model from config/models.json"
    ids = {m["id"] for m in anthropic_models}
    # Real entries shipped in config/models.json today -- see that file.
    assert "claude-opus-4-8" in ids
    assert "claude-sonnet-4-6" in ids
    assert "claude-opus-4-6" in ids
    for m in anthropic_models:
        assert m["status"] in {"current", "retired", "unknown"}

    openai_models = llm_client._known_models_for("openai")
    assert openai_models
    assert all(m["id"] for m in openai_models)

    # A provider with zero shared-registry entries returns [] cleanly,
    # not an exception.
    assert llm_client._known_models_for("not-a-real-provider") == []


def test_interactive_reselection_calls_selected_model_only_after_explicit_choice(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MODEL", "claude-opus-4-6")
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    _monkeypatch_known_models(
        monkeypatch,
        [{"id": "claude-opus-4-8", "status": "current"}, {"id": "claude-sonnet-4-6", "status": "current"}],
    )
    monkeypatch.setattr("builtins.input", lambda: "1")  # pick claude-opus-4-8

    fake = _install_fake_adapter(
        monkeypatch,
        outcomes=[LLMNotFoundError("model: claude-opus-4-6"), _completion_result()],
    )

    result = call_llm("prompt", stage="patch_generation")

    assert isinstance(result, str)
    assert len(fake.calls) == 2
    assert fake.calls[0]["model"] == "claude-opus-4-6"  # original request tried first
    assert fake.calls[1]["model"] == "claude-opus-4-8"  # only the explicit choice, never automatic

    meta = llm_client.get_call_metadata()
    assert meta["patch_generation"]["model"] == "claude-opus-4-8"

    err = capsys.readouterr().err
    assert "The requested model could not be used" in err
    assert "Provider: Anthropic" in err
    assert "Model: claude-opus-4-6" in err


def test_user_cancels_reselection_aborts_run_with_no_alternate_call(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MODEL", "claude-opus-4-6")
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    _monkeypatch_known_models(monkeypatch, [{"id": "claude-opus-4-8", "status": "current"}])
    monkeypatch.setattr("builtins.input", lambda: "")  # blank = decline/cancel

    fake = _install_fake_adapter(
        monkeypatch, outcomes=[LLMNotFoundError("model: claude-opus-4-6")]
    )

    with pytest.raises(ModelUnavailableError):
        call_llm("prompt")

    assert len(fake.calls) == 1  # no alternate call was ever made
    assert fake.calls[0]["model"] == "claude-opus-4-6"


def test_non_interactive_model_failure_never_prompts_never_falls_back(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MODEL", "claude-opus-4-6")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))
    _monkeypatch_known_models(
        monkeypatch,
        [{"id": "claude-opus-4-8", "status": "current"}, {"id": "claude-sonnet-4-6", "status": "current"}],
    )
    fake = _install_fake_adapter(
        monkeypatch, outcomes=[LLMNotFoundError("model: claude-opus-4-6")]
    )

    with pytest.raises(ModelUnavailableError) as excinfo:
        call_llm("prompt")

    message = str(excinfo.value)
    assert "claude-opus-4-6" in message
    assert "anthropic" in message
    assert "claude-opus-4-8" in message  # available alternatives listed
    assert "LLM_MODEL=" in message  # rerun instruction
    assert len(fake.calls) == 1  # never retried automatically


# ---------------------------------------------------------------------------
# Provider/API-key resolution precedence: config.json > env var > interactive.
# ---------------------------------------------------------------------------


def test_provider_api_key_from_config_json_is_used(monkeypatch):
    from utilities.llm import ConfigFile

    cf = ConfigFile(llm_providers={"anthropic": ProviderConfig(name="anthropic", type="anthropic", api_key="sk-from-config")})
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))

    captured_cfg = {}
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    assert captured_cfg["value"].api_key == "sk-from-config"


def test_config_json_key_takes_precedence_over_env_var(monkeypatch):
    from utilities.llm import ConfigFile

    cf = ConfigFile(llm_providers={"anthropic": ProviderConfig(name="anthropic", type="anthropic", api_key="sk-from-config")})
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")

    captured_cfg = {}
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    assert captured_cfg["value"].api_key == "sk-from-config"


def test_env_credential_fallback_still_supported_when_no_config_entry(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")

    captured_cfg = {}
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    assert captured_cfg["value"].api_key == "sk-from-env"


# ---------------------------------------------------------------------------
# Auto Patcher no longer directly constructs provider SDK clients.
# ---------------------------------------------------------------------------


def test_llm_client_module_does_not_construct_sdk_clients_directly():
    import inspect
    import utilities.autopatcher.llm_client as mod

    source = inspect.getsource(mod)
    assert "anthropic.Anthropic(" not in source
    assert "openai.OpenAI(" not in source
    assert "import anthropic" not in source
    assert "import openai" not in source
    assert "build_adapter" in source


def test_openai_live_calls_flow_through_shared_openai_adapter(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-test-model")
    monkeypatch.setenv("OPENAI_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result(text="hello")])

    result = call_llm("prompt")

    assert result == "hello"
    assert fake.calls[0]["system"] is None
    assert fake.calls[0]["messages"][0].role == "user"


def test_anthropic_live_calls_flow_through_shared_anthropic_adapter(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result(text="hello")])

    result = call_llm("prompt")

    assert result == "hello"
    assert fake.calls[0]["system"] is None
    assert fake.calls[0]["messages"][0].role == "user"


def test_adapter_is_built_once_and_reused_across_calls(monkeypatch):
    """Mirrors PhaseRegistry's eager-build-once-reuse adapter lifecycle."""
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    build_calls = []

    def _fake_build_adapter(provider_config):
        build_calls.append(provider_config)
        return _FakeAdapter(outcomes=[_completion_result()])

    monkeypatch.setattr(llm_client, "build_adapter", _fake_build_adapter)

    call_llm("prompt one", stage="patch_generation")
    call_llm("prompt two", stage="patch_review")

    assert len(build_calls) == 1


# ---------------------------------------------------------------------------
# Prompt semantics unchanged: system+user are still concatenated into a
# single user-role message with no system parameter, exactly as before the
# migration.
# ---------------------------------------------------------------------------


def test_complete_preserves_system_and_user_concatenation(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-test-model")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    client = LLMClient(model="claude-opus-4-6")
    client.complete("SYSTEM PROMPT TEXT", "USER MESSAGE TEXT", stage="patch_generation")

    assert fake.calls[0]["system"] is None
    sent_text = fake.calls[0]["messages"][0].content[0].text
    assert sent_text == "SYSTEM PROMPT TEXT" + "\n\n" + "USER MESSAGE TEXT"


# ---------------------------------------------------------------------------
# Config-only resolution: default_llm -> llm_configs[default_llm].analyze
# -> {provider, model} -> llm_providers[provider] -> shared adapter, with NO
# LLM_PROVIDER / LLM_MODEL / ANTHROPIC_API_KEY / OPENAI_API_KEY set at all.
# ---------------------------------------------------------------------------


def test_config_only_resolution_no_env_vars_at_all(monkeypatch):
    """Scenario 1: pure config-only resolution. Environment contains none
    of LLM_PROVIDER/LLM_MODEL/ANTHROPIC_API_KEY/OPENAI_API_KEY. Provider,
    model, AND credential all come from OpenAnt's shared config.json."""
    cf = _config_with_default_llm(
        "test-config", "anthropic", "claude-opus-4-6",
        providers={"anthropic": ProviderConfig(name="anthropic", type="anthropic", api_key="configured-test-key")},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))

    captured_cfg = {}
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt", stage="patch_generation")

    assert fake.calls[0]["model"] == "claude-opus-4-6"
    assert captured_cfg["value"].api_key == "configured-test-key"
    meta = llm_client.get_call_metadata()
    assert meta["patch_generation"]["provider"] == "anthropic"
    assert meta["patch_generation"]["model"] == "claude-opus-4-6"


def test_config_only_resolution_passes_exact_opus_string_unchanged(monkeypatch):
    """Scenario 2: config-only resolution must pass claude-opus-4-6
    unchanged to the adapter -- not normalized, not substituted."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())

    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    assert fake.calls[0]["model"] == "claude-opus-4-6"


def test_explicit_model_overrides_configured_analyze_model(monkeypatch):
    """Scenario 3: config says Anthropic/Opus-4-6; LLM_MODEL=Sonnet-4-6
    overrides just the model -- provider still comes from config."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_MODEL", "claude-sonnet-4-6")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())

    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt", stage="patch_generation")

    assert fake.calls[0]["model"] == "claude-sonnet-4-6"
    assert llm_client.get_call_metadata()["patch_generation"]["provider"] == "anthropic"


def test_explicit_provider_matching_configured_analyze_provider_uses_its_model(monkeypatch):
    """Scenario 4: explicit LLM_PROVIDER=anthropic, no LLM_MODEL, config
    analyze is also Anthropic/Opus-4-6 -- the configured model is used."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())

    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    assert fake.calls[0]["model"] == "claude-opus-4-6"


def test_explicit_provider_conflicting_with_configured_provider_never_combines_non_interactive(monkeypatch, capsys):
    """Scenario 5 (non-interactive): config analyze is OpenAI/model-X;
    LLM_PROVIDER=anthropic explicitly, no LLM_MODEL. Auto Patcher must NOT
    reuse "model-X" with Anthropic -- must fail requiring an explicit
    model."""
    cf = _config_with_default_llm("test-config", "openai", "model-X")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))

    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    with pytest.raises(RuntimeError, match="No LLM_MODEL is set"):
        call_llm("prompt")

    assert fake.calls == []  # "model-X" (or anything else) was never called
    err = capsys.readouterr().err
    assert "provider 'openai'" in err
    assert "not 'anthropic'" in err


def test_explicit_provider_conflicting_with_configured_provider_interactive_requires_explicit_choice(monkeypatch):
    """Scenario 5 (interactive): same mismatch, but interactive -- must
    fall to the explicit model-selection menu rather than reusing model-X,
    and only the user's typed choice is ever sent."""
    cf = _config_with_default_llm("test-config", "openai", "model-X")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda: "1")  # first Anthropic model in the menu

    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    assert fake.calls[0]["model"] != "model-X"
    assert fake.calls[0]["model"]  # a real, explicitly-chosen Anthropic model


def test_missing_default_llm_non_interactive_fails_clearly_never_mock(monkeypatch, capsys):
    """Scenario 6 (non-interactive): default_llm names a config that
    doesn't exist -- a broken/invalid reference, not "unset". Must fail
    clearly, never mock."""
    cf = ConfigFile(default_llm="does-not-exist")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))

    with pytest.raises(RuntimeError, match="No LLM_PROVIDER is set"):
        call_llm("prompt")
    assert "mock" not in capsys.readouterr().err.lower()


def test_missing_default_llm_interactive_falls_to_explicit_selection(monkeypatch):
    """Scenario 6 (interactive): same broken reference, interactive --
    falls to the existing explicit provider-selection menu."""
    cf = ConfigFile(default_llm="does-not-exist")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setattr("sys.stdin", _FakeInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda: "3")  # Mock, explicitly chosen

    res = call_llm("prompt")
    assert res == _mock_response("prompt")


def test_missing_analyze_binding_never_substitutes_another_phase(monkeypatch):
    """Scenario 7: default_llm resolves, but its "analyze" phase binding
    is unavailable (defensive guard -- LLMConfig's own schema normally
    guarantees all 7 phases are present, but Auto Patcher must never
    silently reach for a DIFFERENT phase's binding, e.g. "verify", if this
    ever happened). Same fail/select behavior as "no config at all"."""
    class _FakeLLMConfigMissingAnalyze:
        name = "test-config"
        phases = {}  # no "analyze" key

    cf = ConfigFile(default_llm="test-config")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setattr(llm_client, "resolve_llm_config", lambda c, name: _FakeLLMConfigMissingAnalyze())
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))

    with pytest.raises(RuntimeError, match="No LLM_PROVIDER is set"):
        call_llm("prompt")


def test_no_config_model_and_no_llm_model_never_uses_old_default(monkeypatch):
    """Scenario 8: no config model, no LLM_MODEL -- the old Auto Patcher
    default (Haiku for anthropic) must never be silently selected. The
    adapter must never even be called."""
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input called")))
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    with pytest.raises(RuntimeError, match="No LLM_MODEL is set"):
        call_llm("prompt")

    assert fake.calls == []
    assert "claude-haiku-4-5-20251001" not in str(fake.calls)


def test_full_explicit_env_override_wins_over_a_different_config_binding(monkeypatch):
    """Scenario 10: existing LLM_PROVIDER/LLM_MODEL/API-key env usage must
    keep working exactly as before, even when config.json has a
    DIFFERENT, unrelated binding -- explicit env always wins outright."""
    cf = _config_with_default_llm("test-config", "openai", "some-other-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LLM_MODEL", "claude-sonnet-4-6")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env-key")

    captured_cfg = {}
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    assert fake.calls[0]["model"] == "claude-sonnet-4-6"
    assert captured_cfg["value"].api_key == "sk-env-key"
