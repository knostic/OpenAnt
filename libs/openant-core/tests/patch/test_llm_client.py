import os
import sys

import pytest

import utilities.autopatcher.llm_client as llm_client
from utilities.autopatcher.llm_client import (
    DEFAULT_MAX_TOKENS,
    LLMClient,
    ModelUnavailableError,
    call_llm,
    _mock_response,
)
from utilities.llm import (
    PHASES,
    CompletionResult,
    ConfigError,
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
    # Default: "no config.json" -- resolves to the built-in openant-default
    # (see _resolve_canonical_binding), matching a fresh, never-configured
    # install. Tests exercising a user-authored llm-config override this
    # explicitly via _config_with_default_llm.
    monkeypatch.setattr(llm_client, "load_config_file", lambda: empty_config())
    # Fresh session state per test -- these are module-globals meant to
    # persist across an entire real run/process, not across unrelated tests.
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_model", {})
    monkeypatch.setattr(llm_client, "_cached_adapters", {})
    monkeypatch.setattr(llm_client, "_call_metadata", {})
    monkeypatch.setattr(llm_client, "_call_history", {})
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    monkeypatch.delenv("LLM_MAX_TOKENS", raising=False)
    # call_llm() now records every successful live completion into
    # utilities.llm_client's global TokenTracker singleton -- reset it
    # before AND after each test so execution order in this file (and
    # relative to other test files sharing the same process) can never
    # leak call counts/cost into an unrelated test.
    from utilities.llm_client import reset_global_tracker

    reset_global_tracker()
    yield
    reset_global_tracker()


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
    user-authored llm-config. Auto Patcher's canonical resolution
    (_resolve_canonical_binding) reads default_llm exactly like every
    other OpenAnt command -- there is no Auto-Patcher-specific exclusion
    of the built-in "openant-default" anymore (see
    test_openant_default_inherited_* below for that scenario)."""
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


def _monkeypatch_known_models(monkeypatch, models):
    """Force _known_models_for()'s source deterministically for tests."""
    monkeypatch.setattr(
        llm_client,
        "_known_models_for",
        lambda provider: [m for m in models if True],
    )


# ---------------------------------------------------------------------------
# LLMClient.is_mock — must reflect the active LLM_PROVIDER, not just OPENAI_API_KEY
#
# This is a display-only helper (core/patch.py uses it to label the Trust
# Report's "MOCK"/"LIVE" run mode) and is independent of real-provider
# resolution -- it never selects anything itself, so LLM_PROVIDER's new
# real-provider-selection restriction doesn't apply to it.
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
    # Simulates a session where the provider has already been resolved.
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


def test_llm_model_irrelevant_to_mock(monkeypatch):
    """LLM_MODEL must not matter for an explicit mock run -- mock never
    resolves a model at all."""
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setenv("LLM_MODEL", "whatever")
    res = call_llm("prompt")
    assert res == _mock_response("prompt")


# ---------------------------------------------------------------------------
# LLM_PROVIDER / LLM_MODEL are no longer a supported way to select a real
# provider or model. Any non-mock, non-empty value is a hard, clear
# failure -- never silently ignored, never silently different from what a
# caller asked for, and never a fallback to mock.
# ---------------------------------------------------------------------------


def test_llm_provider_real_value_fails_clearly(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")

    with pytest.raises(RuntimeError, match="LLM_PROVIDER"):
        call_llm("prompt")


def test_llm_provider_real_value_points_at_setup_llm(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")

    with pytest.raises(RuntimeError, match="openant setup llm"):
        call_llm("prompt")


def test_llm_provider_typo_value_fails_the_same_way_as_a_real_one(monkeypatch):
    """Any non-mock value fails identically -- there is no local whitelist
    left to distinguish a typo from a real provider name."""
    monkeypatch.setenv("LLM_PROVIDER", "anthorpic")  # typo

    with pytest.raises(RuntimeError, match="LLM_PROVIDER"):
        call_llm("prompt")


def test_llm_provider_google_value_also_fails(monkeypatch):
    """Google is a real, canonically-supported provider -- but LLM_PROVIDER
    is still not how you select it for Auto Patcher; only OpenAnt's
    canonical configuration does that (see test_google_* below)."""
    monkeypatch.setenv("LLM_PROVIDER", "google")

    with pytest.raises(RuntimeError, match="LLM_PROVIDER"):
        call_llm("prompt")


def test_llm_provider_real_value_never_calls_mock_response(monkeypatch):
    calls = []
    monkeypatch.setattr(llm_client, "_mock_response", lambda prompt: calls.append(prompt) or "SHOULD NOT HAPPEN")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")

    with pytest.raises(RuntimeError):
        call_llm("prompt")

    assert calls == []


def test_llm_provider_real_value_produces_no_mock_stderr_text(monkeypatch, capsys):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")

    with pytest.raises(RuntimeError):
        call_llm("prompt")

    assert "Using mock LLM" not in capsys.readouterr().err


def test_llm_provider_rejection_identical_interactive_and_non_interactive(monkeypatch):
    """Interactive and non-interactive production runs must use the SAME
    rule for LLM_PROVIDER -- there is no more menu/prompt to fall to."""
    for is_tty in (True, False):
        monkeypatch.setattr(llm_client, "_cached_provider", None)
        monkeypatch.setenv("LLM_PROVIDER", "openai")
        monkeypatch.setattr(
            "sys.stdin",
            _FakeInteractiveStdin() if is_tty else _FakeNonInteractiveStdin(),
        )
        monkeypatch.setattr(
            "builtins.input",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input must never be called")),
        )

        with pytest.raises(RuntimeError, match="LLM_PROVIDER"):
            call_llm("prompt")


def test_llm_model_real_value_fails_clearly(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_MODEL", "claude-sonnet-4-6")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

    with pytest.raises(RuntimeError, match="LLM_MODEL"):
        call_llm("prompt")


def test_llm_model_real_value_points_at_setup_llm(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_MODEL", "claude-sonnet-4-6")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

    with pytest.raises(RuntimeError, match="openant setup llm"):
        call_llm("prompt")


def test_llm_model_real_value_never_overrides_configured_model(monkeypatch):
    """The old override behavior must be gone, not just relabeled: the
    adapter must never even be called with either model."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_MODEL", "claude-sonnet-4-6")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    with pytest.raises(RuntimeError, match="LLM_MODEL"):
        call_llm("prompt")

    assert fake.calls == []


# ---------------------------------------------------------------------------
# Live errors propagate — never a silent fallback to mock or another
# provider/model. The shared adapter's typed error taxonomy is preserved
# in the message, wrapped in a RuntimeError for backward-compatible
# call-site behavior.
# ---------------------------------------------------------------------------


def test_anthropic_explicit_provider_raises_on_api_error(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[LLMConnectionError("simulated anthropic failure")])

    with pytest.raises(RuntimeError, match="Anthropic API call failed"):
        call_llm("prompt that triggers anthropic")


def test_openai_explicit_provider_raises_on_api_error(monkeypatch):
    cf = _config_with_default_llm(
        "test-config", "openai", "gpt-test-model",
        providers={"openai": ProviderConfig(name="openai", type="openai", api_key="fake-key")},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    _install_fake_adapter(monkeypatch, outcomes=[LLMConnectionError("simulated openai failure")])

    with pytest.raises(RuntimeError, match="OpenAI API call failed"):
        call_llm("prompt that triggers openai")


def test_anthropic_missing_credential_raises_clearly_never_mock(monkeypatch, capsys):
    """No credential anywhere for the canonically-resolved anthropic
    provider: must raise clearly, never fall back to mock. Exercises the
    REAL shared build_adapter()/SDK path (not a faked adapter) so this
    proves the actual missing-credential failure, not just a stand-in.

    Unlike OpenAI/Google, the Anthropic SDK constructs its client
    successfully even with no key at all (resolve_provider()'s own
    synthesis leaves api_key=None, matching canonical behavior exactly)
    and only rejects the request once a real completion is attempted --
    so this surfaces as call_llm()'s own generic-exception wrapper around
    adapter.complete(), not _get_or_build_adapter()'s construction-time
    check. Still a clear RuntimeError, never a raw SDK traceback, never
    mock."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)

    with pytest.raises(RuntimeError, match="Anthropic API call failed"):
        call_llm("prompt with no anthropic key")
    assert "mock" not in capsys.readouterr().err.lower()


def test_openai_missing_credential_raises_clearly_never_mock(monkeypatch, capsys):
    """OpenAI has no anthropic-style auto-synthesis fallback in the shared
    resolver -- with no llm_providers["openai"] entry at all, resolution
    fails before ever reaching the adapter/SDK. Must raise clearly, never
    fall back to mock."""
    cf = _config_with_default_llm("test-config", "openai", "gpt-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)

    with pytest.raises(RuntimeError, match="No usable credential for provider 'openai'"):
        call_llm("prompt with no openai key")
    assert "mock" not in capsys.readouterr().err.lower()


# ---------------------------------------------------------------------------
# Credential resolution: matches canonical OpenAnt EXACTLY, no
# Auto-Patcher-specific fallback tier layered above resolve_provider().
# ---------------------------------------------------------------------------


def test_provider_api_key_from_config_json_is_used(monkeypatch):
    cf = _config_with_default_llm(
        "test-config", "anthropic", "claude-test-model",
        providers={"anthropic": ProviderConfig(name="anthropic", type="anthropic", api_key="sk-from-config")},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)

    captured_cfg = {}
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    assert captured_cfg["value"].api_key == "sk-from-config"


def test_config_json_key_takes_precedence_over_env_var(monkeypatch):
    cf = _config_with_default_llm(
        "test-config", "anthropic", "claude-test-model",
        providers={"anthropic": ProviderConfig(name="anthropic", type="anthropic", api_key="sk-from-config")},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")

    captured_cfg = {}
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    assert captured_cfg["value"].api_key == "sk-from-config"


def test_anthropic_credential_resolution_succeeds_with_no_config_entry(monkeypatch):
    """Anthropic's shared, canonical resolve_provider() synthesizes a
    credential-less config (letting the SDK's own env lookup find
    ANTHROPIC_API_KEY) even with zero llm_providers entries -- the SAME
    behavior normal OpenAnt commands get, with no Auto-Patcher-specific
    credential code involved."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)

    captured_cfg = {}
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    assert captured_cfg["value"].api_key is None
    assert captured_cfg["value"].name == "anthropic"


def test_openai_credential_resolution_fails_with_no_config_entry_even_with_env_var(monkeypatch):
    """Unlike Anthropic, canonical resolve_provider() has no auto-synthesis
    fallback for OpenAI -- a bare OPENAI_API_KEY with zero llm_providers
    entries now fails with the SAME ConfigError-driven failure normal
    OpenAnt commands would raise for the same problem. This is a
    DELIBERATE, intentional narrowing: Auto Patcher previously had its own
    extra env-var fallback tier for exactly this case; that tier is now
    deleted so credential behavior matches canonical OpenAnt exactly, not
    a broader contract."""
    cf = _config_with_default_llm("test-config", "openai", "gpt-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env-alone")

    with pytest.raises(RuntimeError, match="No usable credential for provider 'openai'"):
        call_llm("prompt")


def test_openai_credential_resolution_succeeds_once_config_entry_exists(monkeypatch):
    """Once a (possibly key-less) llm_providers["openai"] entry exists,
    OpenAI's SDK-level env fallback becomes reachable -- same as any other
    OpenAnt command; still no Auto-Patcher-specific code involved."""
    cf = _config_with_default_llm(
        "test-config", "openai", "gpt-test-model",
        providers={"openai": ProviderConfig(name="openai", type="openai", api_key=None)},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)

    captured_cfg = {}
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt")

    assert captured_cfg["value"].api_key is None
    assert captured_cfg["value"].name == "openai"


# ---------------------------------------------------------------------------
# Interactive prompt text must reach stderr, never stdout -- stdout is
# reserved for the JSON envelope openant/cli.py writes, and Go's
# python.Invoke parses it as pure JSON.
# ---------------------------------------------------------------------------

def test_model_unavailable_prompt_text_goes_to_stderr_not_stdout(monkeypatch, capsys):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[LLMNotFoundError("model: claude-opus-4-6")])

    with pytest.raises(ModelUnavailableError):
        call_llm("prompt")

    captured = capsys.readouterr()
    assert "The requested model could not be used" in captured.err
    assert "The requested model could not be used" not in captured.out


def test_non_interactive_unset_provider_uses_openant_default(monkeypatch, capsys):
    """No config.json at all: falls back to the built-in openant-default,
    exactly like every other OpenAnt command -- there is no more "unset ->
    fail immediately" state for provider/model resolution itself. A run
    can still fail later, on the missing credential (see
    test_no_config_no_credential_fails_clearly_never_mock)."""
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    assert fake.calls  # provider/model resolved successfully via openant-default
    assert llm_client._cached_provider == "anthropic"


def test_no_config_no_credential_fails_clearly_never_mock(monkeypatch, capsys):
    """No config.json, no credential anywhere: openant-default still
    resolves a provider+model (matching normal OpenAnt), but the run fails
    clearly on the missing credential -- never mock. See
    test_anthropic_missing_credential_raises_clearly_never_mock for why
    this is Anthropic's "construction succeeds, request fails" shape
    rather than a construction-time ConfigError/LLMAuthError."""
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())

    with pytest.raises(RuntimeError, match="Anthropic API call failed"):
        call_llm("prompt")
    assert "mock" not in capsys.readouterr().err.lower()


# ---------------------------------------------------------------------------
# Configurable max_tokens (LLM_MAX_TOKENS override + DEFAULT_MAX_TOKENS)
# -- unaffected by the LLM_PROVIDER/LLM_MODEL removal; unrelated mechanism.
# ---------------------------------------------------------------------------

def test_anthropic_uses_default_max_tokens_when_env_unset(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")
    assert fake.calls[0]["max_tokens"] == DEFAULT_MAX_TOKENS
    assert DEFAULT_MAX_TOKENS == 4096


def test_anthropic_honors_llm_max_tokens_override(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MAX_TOKENS", "8000")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")
    assert fake.calls[0]["max_tokens"] == 8000


def test_invalid_llm_max_tokens_falls_back_to_default(monkeypatch, capsys):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setenv("LLM_MAX_TOKENS", "not-a-number")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")
    assert fake.calls[0]["max_tokens"] == DEFAULT_MAX_TOKENS
    assert "Invalid LLM_MAX_TOKENS" in capsys.readouterr().err


def test_openai_receives_explicit_max_tokens(monkeypatch):
    cf = _config_with_default_llm(
        "test-config", "openai", "gpt-test-model",
        providers={"openai": ProviderConfig(name="openai", type="openai", api_key="fake-key")},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("LLM_MAX_TOKENS", "2048")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")
    assert fake.calls[0]["max_tokens"] == 2048


# ---------------------------------------------------------------------------
# Per-stage call metadata (stop_reason capture) -- and it must always record
# the model that ACTUALLY executed.
# ---------------------------------------------------------------------------

def test_anthropic_call_metadata_captures_max_tokens_stop_reason(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result(stop_reason="max_tokens")])

    call_llm("prompt", stage="patch_generation")
    meta = llm_client.get_call_metadata()
    assert meta["patch_generation"]["stop_reason"] == "max_tokens"
    assert meta["patch_generation"]["provider"] == "anthropic"


def test_openai_call_metadata_captures_finish_reason(monkeypatch):
    cf = _config_with_default_llm(
        "test-config", "openai", "gpt-test-model",
        providers={"openai": ProviderConfig(name="openai", type="openai", api_key="fake-key")},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
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
# Ordered call HISTORY (Auto Patcher stage-replay foundation, Batch A):
# get_call_metadata() only ever kept the LATEST call per stage tag -- a
# stage that legitimately makes more than one call under the same tag
# (e.g. Finding Calibration's v1/v2 passes) silently lost the earlier
# call's metadata. get_call_history() must never lose a call.
# ---------------------------------------------------------------------------

def test_repeated_same_tag_calls_are_all_recorded_in_history(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")

    call_llm("first prompt", stage="finding_calibration")
    call_llm("second prompt", stage="finding_calibration")

    history = llm_client.get_call_history()
    assert len(history["finding_calibration"]) == 2


def test_call_history_preserves_call_order(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[
        _completion_result(stop_reason="max_tokens"),
        _completion_result(stop_reason="end_turn"),
    ])

    call_llm("first", stage="finding_calibration")
    call_llm("second", stage="finding_calibration")

    history = llm_client.get_call_history()["finding_calibration"]
    assert [c["stop_reason"] for c in history] == ["max_tokens", "end_turn"]


def test_call_history_does_not_lose_metadata_that_get_call_metadata_overwrites(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")

    call_llm("v1 prompt", stage="finding_calibration")
    call_llm("v2 prompt", stage="finding_calibration")

    # get_call_metadata() -- unchanged, backward-compatible behavior --
    # only shows the LAST call.
    latest = llm_client.get_call_metadata()
    assert len(latest) == 1  # one stage key, "finding_calibration"

    # get_call_history() shows BOTH.
    history = llm_client.get_call_history()
    assert len(history["finding_calibration"]) == 2


def test_call_history_keeps_different_stages_separate(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")

    call_llm("prompt", stage="challenger")
    call_llm("prompt", stage="patch_repair_regeneration")

    history = llm_client.get_call_history()
    assert list(history.keys()) == ["challenger", "patch_repair_regeneration"]
    assert len(history["challenger"]) == 1
    assert len(history["patch_repair_regeneration"]) == 1


def test_clear_call_metadata_also_clears_call_history(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")

    call_llm("prompt", stage="patch_generation")
    assert llm_client.get_call_history()

    llm_client.clear_call_metadata()

    assert llm_client.get_call_history() == {}
    assert llm_client.get_call_metadata() == {}


def test_call_history_returns_independent_copies(monkeypatch):
    """Mutating the returned dict/list must never affect internal state."""
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    call_llm("prompt", stage="patch_review")

    history = llm_client.get_call_history()
    history["patch_review"].append({"fabricated": True})
    history["patch_review"][0]["provider"] = "tampered"

    fresh = llm_client.get_call_history()
    assert len(fresh["patch_review"]) == 1
    assert fresh["patch_review"][0]["provider"] != "tampered"


# ---------------------------------------------------------------------------
# claude-opus-4-6 must reach the shared adapter exactly unchanged: not
# replaced, not normalized, not rejected by any local check.
# ---------------------------------------------------------------------------

def test_opus_4_6_reaches_shared_adapter_unchanged(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    assert fake.calls[0]["model"] == "claude-opus-4-6"


def test_opus_4_6_metadata_records_actual_executed_model(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt", stage="patch_generation")

    meta = llm_client.get_call_metadata()
    assert meta["patch_generation"]["model"] == "claude-opus-4-6"


def test_opus_4_6_not_rejected_even_if_unknown_status(monkeypatch):
    """config/models.json marks claude-opus-4-6 status="unknown" (liveness
    contested) -- that must never cause a rejection or substitution. There
    is no local model whitelist left to reject it in the first place."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    assert len(fake.calls) == 1
    assert fake.calls[0]["model"] == "claude-opus-4-6"


# ---------------------------------------------------------------------------
# No silent fallback: an invalid/rejected model must never trigger a call
# with a different model than the one canonically configured, and never
# offers an interactive reselection -- interactive and non-interactive
# behave identically.
# ---------------------------------------------------------------------------

def test_invalid_model_never_calls_a_different_model(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-does-not-exist")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
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


def test_provider_rejects_model_no_alternate_call(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
    fake = _install_fake_adapter(
        monkeypatch, outcomes=[LLMNotFoundError("model: claude-opus-4-6")]
    )

    with pytest.raises(ModelUnavailableError):
        call_llm("prompt")

    # Exactly the configured model was tried, once, and nothing else.
    assert len(fake.calls) == 1
    assert fake.calls[0]["model"] == "claude-opus-4-6"


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


def test_model_unavailable_fails_clearly_directs_to_setup_llm(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())
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
    assert "claude-opus-4-8" in message  # available alternatives listed as reference
    assert "openant setup llm" in message
    assert "LLM_MODEL" not in message  # never directs the user back to the removed override
    assert len(fake.calls) == 1  # never retried automatically


def test_model_unavailable_behavior_identical_interactive_and_non_interactive(monkeypatch):
    """Model-unavailable behavior must not depend on TTY -- no more
    interactive-vs-non-interactive branching, and no prompt is ever issued
    either way."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    _monkeypatch_known_models(monkeypatch, [{"id": "claude-opus-4-8", "status": "current"}])

    for is_tty in (True, False):
        monkeypatch.setattr(llm_client, "_cached_provider", None)
        monkeypatch.setattr(llm_client, "_cached_model", {})
        monkeypatch.setattr(llm_client, "_cached_adapters", {})
        monkeypatch.setattr(
            "sys.stdin",
            _FakeInteractiveStdin() if is_tty else _FakeNonInteractiveStdin(),
        )
        monkeypatch.setattr(
            "builtins.input",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("input must never be called")),
        )
        _install_fake_adapter(monkeypatch, outcomes=[LLMNotFoundError("model: claude-opus-4-6")])

        with pytest.raises(ModelUnavailableError) as excinfo:
            call_llm("prompt")
        assert "claude-opus-4-6" in str(excinfo.value)


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
    cf = _config_with_default_llm(
        "test-config", "openai", "gpt-test-model",
        providers={"openai": ProviderConfig(name="openai", type="openai", api_key="fake-key")},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result(text="hello")])

    result = call_llm("prompt")

    assert result == "hello"
    assert fake.calls[0]["system"] is None
    assert fake.calls[0]["messages"][0].role == "user"


def test_anthropic_live_calls_flow_through_shared_anthropic_adapter(monkeypatch):
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result(text="hello")])

    result = call_llm("prompt")

    assert result == "hello"
    assert fake.calls[0]["system"] is None
    assert fake.calls[0]["messages"][0].role == "user"


def test_adapter_is_built_once_and_reused_across_calls(monkeypatch):
    """Mirrors PhaseRegistry's eager-build-once-reuse adapter lifecycle."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
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
    cf = _config_with_default_llm("test-config", "anthropic", "claude-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
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
# LLM_PROVIDER / LLM_MODEL set at all. This is the ONLY real-provider
# resolution path now -- not one scenario among several.
# ---------------------------------------------------------------------------


def test_config_only_resolution_no_env_vars_at_all(monkeypatch):
    """Pure config-only resolution. Environment contains none of
    LLM_PROVIDER/LLM_MODEL/ANTHROPIC_API_KEY/OPENAI_API_KEY. Provider,
    model, AND credential all come from OpenAnt's shared config.json."""
    cf = _config_with_default_llm(
        "test-config", "anthropic", "claude-opus-4-6",
        providers={"anthropic": ProviderConfig(name="anthropic", type="anthropic", api_key="configured-test-key")},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())

    captured_cfg = {}
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()], captured_provider_config=captured_cfg)

    call_llm("prompt", stage="patch_generation")

    assert fake.calls[0]["model"] == "claude-opus-4-6"
    assert captured_cfg["value"].api_key == "configured-test-key"
    meta = llm_client.get_call_metadata()
    assert meta["patch_generation"]["provider"] == "anthropic"
    assert meta["patch_generation"]["model"] == "claude-opus-4-6"


def test_config_only_resolution_passes_exact_opus_string_unchanged(monkeypatch):
    """Config-only resolution must pass claude-opus-4-6 unchanged to the
    adapter -- not normalized, not substituted."""
    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())

    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    assert fake.calls[0]["model"] == "claude-opus-4-6"


def test_missing_default_llm_fails_clearly_never_mock(monkeypatch, capsys):
    """default_llm names a config that doesn't exist -- a broken/invalid
    reference, not "unset". Raises the SAME ConfigError canonical OpenAnt
    commands raise for the identical problem; never mock."""
    cf = ConfigFile(default_llm="does-not-exist")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setattr("sys.stdin", _FakeNonInteractiveStdin())

    with pytest.raises(ConfigError, match="does-not-exist"):
        call_llm("prompt")
    assert "mock" not in capsys.readouterr().err.lower()


def test_missing_analyze_binding_never_substitutes_another_phase(monkeypatch):
    """default_llm resolves, but its "analyze" phase binding is
    unavailable (defensive guard -- LLMConfig's own schema normally
    guarantees all 7 phases are present, but Auto Patcher must never
    silently reach for a DIFFERENT phase's binding, e.g. "verify", if this
    ever happened)."""
    class _FakeLLMConfigMissingAnalyze:
        name = "test-config"
        phases = {}  # no "analyze" key

    cf = ConfigFile(default_llm="test-config")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setattr(llm_client, "resolve_llm_config", lambda c, name: _FakeLLMConfigMissingAnalyze())

    with pytest.raises(RuntimeError, match="no usable 'analyze' phase binding"):
        call_llm("prompt")


# ---------------------------------------------------------------------------
# openant-default is inherited exactly like every other OpenAnt command --
# no Auto-Patcher-specific exclusion of it anymore.
# ---------------------------------------------------------------------------


def test_openant_default_inherited_when_credential_available(monkeypatch):
    """No explicit default_llm configured (falls back to the built-in
    openant-default), but a real ANTHROPIC_API_KEY is present -- Auto
    Patcher must inherit openant-default's analyze binding and run,
    exactly like every other OpenAnt command, with zero prompting. This is
    exactly the experience a user who has only ever run
    `openant set-api-key` (never `openant setup llm`) gets from `openant
    scan` too."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt", stage="patch_generation")

    assert fake.calls  # a real call was made -- provider/model resolved successfully
    meta = llm_client.get_call_metadata()
    assert meta["patch_generation"]["provider"] == "anthropic"


def test_openant_default_analyze_model_reaches_adapter_unchanged(monkeypatch):
    """The built-in openant-default's analyze model string reaches the
    adapter exactly as OPENANT_DEFAULT defines it -- not normalized, not
    substituted, not defaulted to some Auto-Patcher-specific model."""
    from utilities.llm import get_builtin_default

    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result()])

    call_llm("prompt")

    expected_model = get_builtin_default().phases["analyze"].model
    assert fake.calls[0]["model"] == expected_model


# ---------------------------------------------------------------------------
# Usage/cost propagation into OpenAnt's shared global TokenTracker
# ---------------------------------------------------------------------------
#
# call_llm() forwards every successful live CompletionResult's real
# input_tokens/output_tokens (plus the adapter's own pricing table) to
# utilities.llm_client.get_global_tracker().record_call() -- the same
# mechanism the seven-phase scan pipeline uses -- so a live Auto Patcher
# run's cost shows up via core.tracking.get_usage() / core.step_report's
# cost delta instead of always reading $0. See _isolate_shared_infra above
# for the tracker reset that keeps these tests hermetic against each other.


def test_live_completion_records_usage_in_global_tracker(monkeypatch):
    from utilities.llm_client import get_global_tracker

    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-8")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(
        monkeypatch, outcomes=[_completion_result(input_tokens=1000, output_tokens=500)]
    )
    fake.pricing = {"claude-opus-4-8": {"input": 15.0, "output": 75.0}}

    call_llm("prompt", stage="patch_generation")

    totals = get_global_tracker().get_totals()
    assert totals["total_calls"] == 1
    call_record = get_global_tracker().get_summary()["calls"][-1]
    assert call_record["model"] == "claude-opus-4-8"
    assert call_record["input_tokens"] == 1000
    assert call_record["output_tokens"] == 500
    expected_cost = (1000 / 1_000_000) * 15.0 + (500 / 1_000_000) * 75.0
    assert call_record["cost_usd"] == pytest.approx(expected_cost)
    assert call_record["cost_usd"] > 0


def test_live_completion_records_exactly_once(monkeypatch):
    """A single successful call_llm() invocation must increment the
    tracker's call count by exactly one -- not zero (dropped), not two
    (double-counted across the two live adapter.complete() call sites)."""
    from utilities.llm_client import get_global_tracker

    cf = _config_with_default_llm("test-config", "anthropic", "claude-sonnet-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    _install_fake_adapter(monkeypatch, outcomes=[_completion_result(input_tokens=10, output_tokens=5)])

    call_llm("prompt", stage="stage_a")
    assert get_global_tracker().get_totals()["total_calls"] == 1

    call_llm("prompt", stage="stage_b")
    assert get_global_tracker().get_totals()["total_calls"] == 2


def test_mock_mode_never_records_paid_usage(monkeypatch):
    from utilities.llm_client import get_global_tracker

    monkeypatch.setenv("LLM_PROVIDER", "mock")

    call_llm("prompt", stage="patch_generation")

    assert get_global_tracker().get_totals()["total_calls"] == 0


def test_unpriced_model_still_records_tokens_with_zero_cost(monkeypatch, capsys):
    """Preserve the existing shared-infra behavior for a model with no
    pricing data (e.g. today's claude-opus-4-6, status "unknown"/price
    null in config/models.json): token counts are still recorded, cost
    is 0, and the existing one-time warning still fires -- never a
    fabricated price."""
    from utilities.llm_client import get_global_tracker

    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-6")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(
        monkeypatch, outcomes=[_completion_result(input_tokens=1000, output_tokens=500)]
    )
    # No fake.pricing set -- adapter reports no pricing for this model,
    # and it's genuinely unpriced (null) in the real config/models.json too.

    call_llm("prompt", stage="patch_generation")

    call_record = get_global_tracker().get_summary()["calls"][-1]
    assert call_record["model"] == "claude-opus-4-6"
    assert call_record["input_tokens"] == 1000
    assert call_record["output_tokens"] == 500
    assert call_record["cost_usd"] == 0.0
    assert "no pricing for model 'claude-opus-4-6'" in capsys.readouterr().err


def test_step_report_cost_delta_reflects_fake_live_auto_patcher_call(monkeypatch, tmp_path):
    """End-to-end (still fully fake/hermetic): a fake live Auto Patcher LLM
    call recorded into the global tracker must be visible through
    core.step_report's cost-delta mechanism, which is what ultimately
    produces the CLI's printed "(...s, $X)" line and patch.report.json's
    cost_usd field."""
    from core.step_report import step_context

    cf = _config_with_default_llm("test-config", "anthropic", "claude-opus-4-8")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    fake = _install_fake_adapter(
        monkeypatch, outcomes=[_completion_result(input_tokens=1000, output_tokens=500)]
    )
    fake.pricing = {"claude-opus-4-8": {"input": 15.0, "output": 75.0}}

    with step_context("patch", str(tmp_path)) as ctx:
        call_llm("prompt", stage="patch_generation")
        ctx.summary = {}
        ctx.outputs = {}

    report_path = tmp_path / "patch.report.json"
    assert report_path.exists()
    written = __import__("json").loads(report_path.read_text())
    assert written["cost_usd"] > 0
    expected_cost = round((1000 / 1_000_000) * 15.0 + (500 / 1_000_000) * 75.0, 6)
    assert written["cost_usd"] == pytest.approx(expected_cost)
    assert written["token_usage"]["input_tokens"] == 1000
    assert written["token_usage"]["output_tokens"] == 500


# ---------------------------------------------------------------------------
# Google works through canonical OpenAnt configuration + the shared Google
# adapter -- no Auto-Patcher-specific Google implementation anywhere.
# ---------------------------------------------------------------------------


def test_google_resolves_through_canonical_config_and_shared_adapter(monkeypatch):
    cf = _config_with_default_llm(
        "test-config", "google", "gemini-test-model",
        providers={"google": ProviderConfig(name="google", type="google", api_key="fake-google-key")},
    )
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)

    captured_cfg = {}
    fake = _install_fake_adapter(monkeypatch, outcomes=[_completion_result(text="hi from gemini")], captured_provider_config=captured_cfg)

    result = call_llm("prompt")

    assert result == "hi from gemini"
    assert fake.calls[0]["model"] == "gemini-test-model"
    assert captured_cfg["value"].name == "google"
    assert captured_cfg["value"].api_key == "fake-google-key"
    meta = llm_client.get_call_metadata()
    assert meta["unknown"]["provider"] == "google"


def test_google_credential_resolution_matches_openai_shape_not_anthropic(monkeypatch):
    """Google has no anthropic-style auto-synthesis fallback either --
    same shape as OpenAI, proving Auto Patcher applies no Google-specific
    special-casing of its own."""
    cf = _config_with_default_llm("test-config", "google", "gemini-test-model")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: cf)
    monkeypatch.setenv("GOOGLE_API_KEY", "sk-from-env-alone")

    with pytest.raises(RuntimeError, match="No usable credential for provider 'google'"):
        call_llm("prompt")


def test_google_is_not_reachable_via_llm_provider_env(monkeypatch):
    """Google is a real canonical provider, but Auto Patcher never adds it
    (or any real provider) to a patch-specific selection mechanism --
    LLM_PROVIDER=google still fails exactly like any other real-provider
    value."""
    monkeypatch.setenv("LLM_PROVIDER", "google")

    with pytest.raises(RuntimeError, match="LLM_PROVIDER"):
        call_llm("prompt")
