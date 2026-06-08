"""Resolve a config.json + llm-config name into ready-to-use adapters.

The registry is the bridge between :mod:`utilities.llm.config`
(parsed config types) and :mod:`utilities.llm.providers` (adapter
implementations).

Lifecycle at scan / step-verb time:

1. ``load_config_file()`` reads ``~/.config/openant/config.json``
   (or falls back to an empty file).
2. ``resolve_llm_config(cf, name)`` picks the active llm-config by
   name; falls through ``--llm-config`` flag → ``project.json``
   override → file ``default_llm`` → built-in ``openant-default``.
3. ``build_phase_registry(cf, llm_config)`` eagerly instantiates one
   adapter per unique provider used by the config. Returns a
   :class:`PhaseRegistry` the pipeline queries by phase name.
4. ``probe_registry_or_raise(registry)`` calls
   ``registry.validate()`` to probe every unique ``(provider,
   model)`` pair with a 1-token request, wrapping any
   :class:`LLMError` with a friendly stderr preamble. Called at the
   start of ``scan_repository`` AND at the head of every standalone
   step verb (analyze, enhance, verify, dynamic_test, report,
   llm_reach) when they build their own registry — scanner-driven
   step calls reuse the scanner's already-probed registry.
5. ``registry.get(phase)`` returns ``(adapter, model)`` for that
   phase. O(1) dict access.

This module deliberately does NOT cache PhaseRegistry instances. The
caller (the scan-time bootstrap, or a Go-CLI shim) owns the
lifecycle. If a user edits config.json mid-scan, an in-flight
PhaseRegistry keeps its original resolution — which is the right
behavior for a single ``scan`` invocation.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .adapter import LLMAdapter
from .builtins import get_builtin_default
from .config import (
    ConfigError,
    ConfigFile,
    LLMConfig,
    PhaseRef,
    PHASES,
    ProviderConfig,
    empty_config,
    parse_config,
)
from .providers import get_adapter_class


# ---------------------------------------------------------------------------
# Config-file IO
# ---------------------------------------------------------------------------


def default_config_path() -> Path:
    """Resolve the canonical config.json path.

    Mirrors the Go CLI: ``$XDG_CONFIG_HOME/openant/config.json``
    when set, ``~/.config/openant/config.json`` otherwise. The Python
    pipeline doesn't run on Windows for these code paths (the Go CLI
    handles platform-specific paths and passes the file path in via
    env), but we keep the Linux/macOS branch consistent.
    """
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if xdg:
        return Path(xdg) / "openant" / "config.json"
    return Path.home() / ".config" / "openant" / "config.json"


def load_config_file(path: Optional[Path] = None) -> ConfigFile:
    """Read and parse config.json.

    Missing file is not an error — returns an empty ConfigFile so
    the caller can still resolve ``openant-default``.
    """
    target = path or default_config_path()
    if not target.exists():
        return empty_config()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config.json at {target}: invalid JSON ({exc})") from exc
    return parse_config(raw)


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------


def resolve_llm_config(cf: ConfigFile, name: Optional[str]) -> LLMConfig:
    """Pick the active llm-config.

    Precedence (highest first):

    1. Explicit ``name`` argument (typically from ``--llm-config`` or
       ``project.json:llm_config``).
    2. ``cf.default_llm``.
    3. Built-in ``openant-default``.

    Raises:
        ConfigError: when an explicitly-named config doesn't exist.
    """
    builtin = get_builtin_default()

    chosen_name = name or cf.default_llm

    if chosen_name == "openant-default":
        return builtin
    if chosen_name in cf.llm_configs:
        return cf.llm_configs[chosen_name]

    # Explicit name that doesn't exist is always an error. Falling
    # silently back to openant-default would mask typos.
    available = ["openant-default"] + sorted(cf.llm_configs)
    raise ConfigError(
        f"llm-config {chosen_name!r} not found. "
        f"Available: {', '.join(available)}."
    )


# ---------------------------------------------------------------------------
# Provider resolution
# ---------------------------------------------------------------------------


def resolve_provider(cf: ConfigFile, name: str) -> ProviderConfig:
    """Look up a provider by name, with a fallback for ``"anthropic"``.

    The fallback exists for upgrade-from-v1 users who have
    ``ANTHROPIC_API_KEY`` in their environment but no ``llm_providers``
    entry in config.json. In that case the openant-default config
    references provider ``"anthropic"`` but the file knows nothing
    about it; this function synthesises a credential-less
    ProviderConfig and lets the SDK's own env lookup find the key.

    Raises:
        ConfigError: when no provider exists by that name and the
            fallback synthesis doesn't apply.
    """
    if name in cf.llm_providers:
        return cf.llm_providers[name]
    if name == "anthropic":
        # SDK reads ANTHROPIC_API_KEY from env when api_key is None.
        return ProviderConfig(name="anthropic", type="anthropic")
    raise ConfigError(
        f"Provider {name!r} is referenced by an llm-config but not defined "
        f"in llm_providers. Defined: {sorted(cf.llm_providers) or 'none'}."
    )


# ---------------------------------------------------------------------------
# Adapter instantiation
# ---------------------------------------------------------------------------


def build_adapter(provider: ProviderConfig) -> LLMAdapter:
    """Construct an adapter instance from a ProviderConfig.

    Adapter constructors typically raise provider-native exceptions
    when they can't even find a credential (e.g. ``anthropic.Anthropic()``
    with no ``api_key`` arg AND no ``ANTHROPIC_API_KEY`` env var
    raises ``ValueError``). Catch those here and re-raise as
    :class:`LLMAuthError` so the user sees OpenAnt's message
    naming the problematic provider rather than the SDK's generic one.
    """
    from .adapter import LLMAuthError

    adapter_cls = get_adapter_class(provider.type)
    try:
        return adapter_cls(
            api_key=provider.api_key,
            base_url=provider.base_url,
        )
    except Exception as exc:  # noqa: BLE001 — re-raise as typed
        raise LLMAuthError(
            f"Failed to construct adapter for provider {provider.name!r} "
            f"(type {provider.type!r}): {type(exc).__name__}: {exc}. "
            f"For the anthropic adapter, ensure either "
            f"`llm_providers[{provider.name!r}].api_key` is set in "
            f"config.json or `ANTHROPIC_API_KEY` is exported in the "
            f"environment."
        ) from exc


# ---------------------------------------------------------------------------
# The phase registry — what the pipeline holds during a scan
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PhaseBinding:
    """One row in a PhaseRegistry: a phase → (adapter, model) link."""

    phase: str
    adapter: LLMAdapter
    model: str
    provider_name: str


class PhaseRegistry:
    """Eagerly-instantiated registry the pipeline queries during a scan.

    Adapters are constructed once at registry-build time and reused
    across phases that share a provider. Lookups are O(1) and
    thread-safe (adapters are stateless dispatchers).
    """

    def __init__(self, bindings: dict[str, PhaseBinding], config_name: str):
        self._bindings = bindings
        self._config_name = config_name

    @property
    def config_name(self) -> str:
        """Name of the llm-config this registry was built from."""
        return self._config_name

    def get(self, phase: str) -> PhaseBinding:
        """Return the binding for ``phase``.

        Raises:
            KeyError: with a helpful message if the caller asks for a
                phase that isn't in the canonical set. This indicates
                a bug in pipeline code, not a user-config issue.
        """
        if phase not in self._bindings:
            raise KeyError(
                f"Unknown pipeline phase: {phase!r}. "
                f"Known phases: {', '.join(PHASES)}."
            )
        return self._bindings[phase]

    def unique_probe_targets(self) -> list[tuple[str, str]]:
        """All distinct ``(provider_name, model)`` pairs across phases.

        Used by :meth:`validate` to probe each pair exactly once.
        Two phases sharing the same provider+model don't double-probe.
        """
        seen: set[tuple[str, str]] = set()
        for binding in self._bindings.values():
            seen.add((binding.provider_name, binding.model))
        return sorted(seen)

    def validate(self) -> None:
        """Probe every unique ``(provider, model)`` pair.

        Called at scan startup by ``scan_repository`` and at the head
        of every standalone step verb (analyze, enhance, verify,
        dynamic_test, report, llm_reach) via
        :func:`probe_registry_or_raise`. Raises on the FIRST failure
        — no point probing the rest of a broken config. The exception
        type is the adapter's :class:`LLMError` subclass; callers
        catch :class:`LLMError` and surface a user-friendly message.
        """
        # Group probes by provider name so the error message can name
        # the offending provider, not just the model.
        adapters_by_provider: dict[str, LLMAdapter] = {}
        for binding in self._bindings.values():
            adapters_by_provider[binding.provider_name] = binding.adapter
        for provider_name, model in self.unique_probe_targets():
            adapters_by_provider[provider_name].validate(model)


def probe_registry_or_raise(registry: PhaseRegistry) -> None:
    """Run ``registry.validate()`` with a friendly stderr preamble.

    Every pipeline entry point that builds its own registry should
    call this immediately after ``build_phase_registry()``. The point
    is uniform UX: a bad key, a typo'd model ID, or an unreachable
    endpoint produces the same "llm-config {name!r} failed
    validation: ..." line whether the user ran ``openant scan`` or
    ``openant analyze`` standalone.

    The original :class:`LLMError` is re-raised — callers higher up
    decide whether to swallow it (envelope-out for the CLI) or let
    it propagate.
    """
    from .adapter import LLMError

    try:
        registry.validate()
    except LLMError as exc:
        print(
            f"llm-config {registry.config_name!r} failed validation: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        raise


def build_phase_registry(
    cf: ConfigFile, llm_config: LLMConfig
) -> PhaseRegistry:
    """Eagerly instantiate every adapter the llm-config needs.

    One adapter per unique provider name (not per phase). Phases that
    share a provider reuse the same adapter instance — which is
    correct because adapters are stateless dispatchers and the SDK
    clients underneath are thread-safe.
    """
    # First pass: pick out the unique provider names referenced.
    unique_providers: dict[str, ProviderConfig] = {}
    for ref in llm_config.phases.values():
        if ref.provider not in unique_providers:
            unique_providers[ref.provider] = resolve_provider(cf, ref.provider)

    # Second pass: instantiate one adapter per provider.
    adapters: dict[str, LLMAdapter] = {
        name: build_adapter(provider)
        for name, provider in unique_providers.items()
    }

    # Third pass: build phase bindings reusing the per-provider adapters.
    bindings: dict[str, PhaseBinding] = {}
    for phase, ref in llm_config.phases.items():
        bindings[phase] = PhaseBinding(
            phase=phase,
            adapter=adapters[ref.provider],
            model=ref.model,
            provider_name=ref.provider,
        )

    # Tool-support gating (plan §5): enhance + verify require an
    # adapter with supports_tools=True. Catch this here rather than
    # at the first call site, so init can fail loudly.
    _check_tool_support(bindings)

    return PhaseRegistry(bindings=bindings, config_name=llm_config.name)


_TOOL_PHASES = ("enhance", "verify")


def _check_tool_support(bindings: dict[str, PhaseBinding]) -> None:
    for phase in _TOOL_PHASES:
        binding = bindings[phase]
        if not binding.adapter.supports_tools:
            raise ConfigError(
                f"Phase {phase!r} requires tool calling, but provider "
                f"{binding.provider_name!r} (adapter type "
                f"{binding.adapter.name!r}) does not support it in this release. "
                f"Either point {phase!r} at a provider whose adapter supports "
                f"tools, or wait for that adapter to gain tool support."
            )
