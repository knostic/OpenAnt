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
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .adapter import LLMAdapter
from .builtins import get_builtin_default
from .config import (
    ConfigError,
    ConfigFile,
    LLMConfig,
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

# #604: one-time-PER-TYPE warning when a config sets request_timeout on a
# provider type whose adapter does not consume it. Silent-ignoring config a
# user explicitly wrote would violate the no-silent-drops rule (the bedrock
# api_key warning is the in-tree precedent). Keyed by TYPE (not a global
# flag): a config setting the knob on two unconsuming types names both.
_unconsumed_timeout_warned: set[str] = set()
_unconsumed_timeout_warned_lock = threading.Lock()


_warned_unconsumed_thinking: set[tuple[str, str]] = set()
_thinking_warn_lock = threading.Lock()


def _warn_unconsumed_thinking(provider_name: str, adapter_type: str) -> None:
    """#625: one-time-per-(provider, type) stderr warning when a phase
    sets a thinking policy but the adapter class does not consume the
    kwarg — the request would silently carry no thinking key. Duplicated
    (not generalized) from the #604 warn-set: generalizing touches the
    #604 pins and llm_client's reset tuple atomically — a deliberate,
    # separate refactor."""
    key = (provider_name, adapter_type)
    should_warn = False
    with _thinking_warn_lock:
        if key not in _warned_unconsumed_thinking:
            _warned_unconsumed_thinking.add(key)
            should_warn = True
    if should_warn:
        sys.stderr.write(
            f"warning: a phase sets a thinking policy for provider "
            f"{provider_name!r} (type {adapter_type!r}), but that adapter "
            f"does not consume it — the requests will carry no thinking "
            f"key.\n"
        )


def reset_unconsumed_thinking_warning() -> None:
    """Test hook: re-arm the one-time #625 warning."""
    with _thinking_warn_lock:
        _warned_unconsumed_thinking.clear()


def _warn_unconsumed_timeout(provider_name: str, provider_type: str) -> None:
    with _unconsumed_timeout_warned_lock:
        if provider_type in _unconsumed_timeout_warned:
            return
        _unconsumed_timeout_warned.add(provider_type)
    # #604 review: BOTH the entry name and the type — with two same-type
    # providers the type alone cannot tell the user WHICH entry to fix.
    sys.stderr.write(
        "warning: request_timeout is not consumed by provider entry "
        f"{provider_name!r} (type {provider_type!r}) — that type declares "
        "no `request_timeout` constructor kwarg. An adapter adopts the "
        "knob by declaring the kwarg. Remove `request_timeout` from "
        "that provider entry to silence this.\n"
    )


def reset_unconsumed_timeout_warning() -> None:
    """Test hook: re-arm the per-type one-time warnings (wired into
    ``llm_client.reset_warning_state`` so the suite's autouse fixtures
    reset it with every other one-time warning)."""
    with _unconsumed_timeout_warned_lock:
        _unconsumed_timeout_warned.clear()


def _declares_thinking_kwarg(adapter_cls) -> bool:
    """#625: the single source of truth for whether an adapter class
    consumes the thinking knob — ``build_adapter`` threads the policy iff
    this holds, and the phase binding records an EFFECTIVE policy iff it
    holds (a non-consuming adapter must never report a policy its
    requests never carried; the one-time build warning stays the only
    surface for the unconsumed knob)."""
    import inspect

    return "thinking" in inspect.signature(
        adapter_cls.__init__).parameters


def build_adapter(provider: ProviderConfig,
                  thinking: Optional[dict] = None) -> LLMAdapter:
    """Construct an adapter instance from a ProviderConfig.

    Adapter constructors typically raise provider-native exceptions
    when they can't even find a credential (e.g. ``anthropic.Anthropic()``
    with no ``api_key`` arg AND no ``ANTHROPIC_API_KEY`` env var
    raises ``ValueError``). Catch those here and re-raise as
    :class:`LLMAuthError` so the user sees OpenAnt's message
    naming the problematic provider rather than the SDK's generic one.

    #604: ``request_timeout`` (seconds) is threaded CAPABILITY-
    conditionally — passed iff the adapter class declares the kwarg
    (``inspect.signature``), else the one-time warning above. The
    membership check cannot drift from the constructor (a declared
    attribute could), and a ``**kwargs`` constructor does NOT list the
    kwarg, so an undeclared consumer still warns (fail-visible).
    """
    import inspect

    from .adapter import LLMAuthError

    adapter_cls = get_adapter_class(provider.type)
    kwargs: dict = {
        "api_key": provider.api_key,
        "base_url": provider.base_url,
    }
    if provider.request_timeout is not None:
        if "request_timeout" in inspect.signature(
                adapter_cls.__init__).parameters:
            kwargs["request_timeout"] = provider.request_timeout
        else:
            _warn_unconsumed_timeout(provider.name, provider.type)
    # #625: the per-phase thinking policy threads the same capability-
    # conditional way — an adapter that declares ``thinking`` consumes it;
    # any other type (bedrock's duplicated request-build, openai, google)
    # warns ONCE per type (fail-visible, never a silent ignore). Bedrock
    # deliberately does not adopt it in this change (its own complete());
    # its reuse of _response_to_unified means the dropped-block count
    # DOES reach it.
    if thinking is not None:
        if _declares_thinking_kwarg(adapter_cls):
            kwargs["thinking"] = thinking
        else:
            _warn_unconsumed_thinking(provider.name, provider.type)
    try:
        return adapter_cls(**kwargs)
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
    # The provider's configured base_url (gateway/proxy endpoint), carried so the
    # I2 backend-identity fingerprint can discriminate two configs that share a
    # model+provider but route to different upstreams. ``None`` for default-config
    # users (SDK default endpoint) → fingerprint unchanged, zero re-pay. Sanitized
    # (userinfo/query/fragment stripped) before it ever enters the KEY / sidecar.
    base_url: Optional[str] = None
    # #625: the phase's EFFECTIVE request-side thinking policy (the
    # per-phase config, post-gate). None = the request carries no thinking
    # key (the byte-identical default) AND the fingerprint extra stays
    # absent (zero re-pay for default users, exactly like base_url). The
    # fingerprint fold rides extra_key only-when-set — the #242 exclusion
    # rationale was CONDITIONAL (truncation records as ERROR, never
    # adopted); a thinking policy changes ORDINARY SUCCESSES, so a resumed
    # scan must not adopt cross-policy verdicts.
    thinking: Optional[dict] = None


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


TOOL_PHASES = ("enhance", "verify")


def _canonical_thinking(thinking: Optional[dict]) -> Optional[str]:
    """#625: the hashable canonical form of a thinking policy for the
    adapter-tuple key (None stays None — the default tuple)."""
    return json.dumps(thinking, sort_keys=True) if thinking else None


def build_phase_registry(
    cf: ConfigFile, llm_config: LLMConfig
) -> PhaseRegistry:
    """Eagerly instantiate every adapter the llm-config needs.

    One adapter per unique (provider, thinking) tuple (not per phase):
    phases that share a provider AND policy reuse the same adapter
    instance — correct because adapters are stateless dispatchers and
    the SDK clients underneath are thread-safe. #625: a thinking-
    configured phase and a default phase behind the same provider get
    DISTINCT adapters (their request dicts differ).
    """
    # #625 (the panel round): the tool-phase gate fires BEFORE any adapter
    # is built — a thinking-configured tool phase on a non-consuming
    # provider must see the ConfigError, not a spurious unconsumed-knob
    # warning first.
    for phase, ref in llm_config.phases.items():
        if (ref.thinking is not None
                and ref.thinking.get("type") != "disabled"
                and phase in TOOL_PHASES):
            raise ConfigError(
                f"llm-config {llm_config.name!r}: phase {phase!r} sets a "
                f"thinking policy, but {phase} is a tool-calling phase — "
                "the platform requires thinking blocks echoed back with "
                "tool results, which this pipeline does not yet support "
                "(the loops carry text and tool-use only). Configure "
                "thinking on a single-turn phase (analyze, report, "
                "llm_reach, dynamic_test) or remove the key.")

    # First pass: pick out the unique provider names referenced.
    unique_providers: dict[str, ProviderConfig] = {}
    for ref in llm_config.phases.values():
        if ref.provider not in unique_providers:
            unique_providers[ref.provider] = resolve_provider(cf, ref.provider)

    # #625 Second pass: one adapter per (provider, thinking) tuple — a
    # thinking-configured phase and a default phase behind the SAME
    # provider need DIFFERENT request dicts, and adapters are stateless
    # dispatchers, so the tuple key preserves the one-adapter-per-shape
    # economy while honoring both policies.
    adapters: dict[tuple, LLMAdapter] = {}
    for ref in llm_config.phases.values():
        provider = unique_providers[ref.provider]
        key = (ref.provider, _canonical_thinking(ref.thinking))
        if key not in adapters:
            adapters[key] = build_adapter(
                provider, thinking=ref.thinking)

    # #625 Third pass: build phase bindings (the tool-phase GATE fired in
    # the pre-build pass above; the ADAPTER-level tool backstop in
    # anthropic.complete is the exhaustive half — the gate is the
    # early-UX half for the phases that ALWAYS tool-call).
    bindings: dict[str, PhaseBinding] = {}
    for phase, ref in llm_config.phases.items():
        adapter = adapters[(ref.provider, _canonical_thinking(ref.thinking))]
        bindings[phase] = PhaseBinding(
            phase=phase,
            adapter=adapter,
            model=ref.model,
            provider_name=ref.provider,
            base_url=unique_providers[ref.provider].base_url,
            # #625 follow-up: EFFECTIVE, not requested — an adapter whose
            # class does not declare the kwarg never sends the policy, so
            # the binding (the fingerprint-extra and step-input source of
            # truth) must not report one; the build warning is the only
            # surface for the unconsumed knob, and default users are
            # unaffected (absent → absent).
            thinking=ref.thinking
            if _declares_thinking_kwarg(type(adapter)) else None,
        )

    # Tool-support gating (plan §5): enhance + verify require an
    # adapter with supports_tools=True. Catch this here rather than
    # at the first call site, so init can fail loudly.
    _check_tool_support(bindings)

    return PhaseRegistry(bindings=bindings, config_name=llm_config.name)


def _check_tool_support(bindings: dict[str, PhaseBinding]) -> None:
    for phase in TOOL_PHASES:
        binding = bindings[phase]
        if not binding.adapter.supports_tools:
            raise ConfigError(
                f"Phase {phase!r} requires tool calling, but provider "
                f"{binding.provider_name!r} (adapter type "
                f"{binding.adapter.name!r}) does not support it in this release. "
                f"Either point {phase!r} at a provider whose adapter supports "
                f"tools, or wait for that adapter to gain tool support."
            )
