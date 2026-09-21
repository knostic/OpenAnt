"""#625 follow-up: the phase binding must report the EFFECTIVE policy —
an adapter that does not consume the knob (its class does not declare the
``thinking`` kwarg; ``build_adapter`` warns once and threads nothing) must
not have the requested policy recorded as effective, or every fingerprint/
step-input reader is told a policy the requests never carried."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import utilities.llm.registry as registry_mod  # noqa: E402
from utilities.llm.config import (  # noqa: E402
    ConfigFile,
    LLMConfig,
    PhaseRef,
    ProviderConfig,
)

_ALL_PHASES = ("analyze", "enhance", "verify", "report", "dynamic_test",
               "llm_reach", "app_context")


def _registry_for(provider_type: str, thinking=None):
    cf = ConfigFile(llm_providers={
        "p": ProviderConfig(name="p", type=provider_type,
                            api_key="dummy-key")})
    phases = {p: PhaseRef(provider="p", model="m") for p in _ALL_PHASES}
    phases["analyze"] = PhaseRef(provider="p", model="m", thinking=thinking)
    return registry_mod.build_phase_registry(
        cf, LLMConfig(name="c", phases=phases))


def test_nonconsuming_binding_records_no_effective_policy():
    """google's adapter does not declare the kwarg (the 625b warning row);
    the binding is the fingerprint/step-input source of truth — recording
    the requested dict there lies to every reader downstream."""
    r = _registry_for("google", {"type": "adaptive"})
    assert r.get("analyze").thinking is None, (
        "a non-consuming adapter must not report an effective policy")


def test_consuming_binding_records_the_policy():
    """The anthropic adapter declares the kwarg — the policy IS effective."""
    r = _registry_for("anthropic", {"type": "adaptive"})
    assert r.get("analyze").thinking == {"type": "adaptive"}


def test_default_binding_stays_none():
    r = _registry_for("google", None)
    assert r.get("analyze").thinking is None
