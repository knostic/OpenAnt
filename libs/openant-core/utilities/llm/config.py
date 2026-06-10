"""Config-file types and v1 -> v2 migration.

This module knows nothing about adapters. It deals purely in parsed
JSON shapes and validation. The registry (``registry.py``) consumes
these types to instantiate adapters.

Schema v2 lives at ``~/.config/openant/config.json``::

    {
      "$schema_version": 2,
      "default_llm": "openant-default",
      "active_project": "org/repo",
      "llm_providers": {
        "<name>": {
          "type": "anthropic",
          "api_key": "sk-...",
          "base_url": null
        }
      },
      "llm_configs": {
        "<name>": {
          "analyze":      {"provider": "<provider-name>", "model": "claude-..."},
          "enhance":      {"provider": "<provider-name>", "model": "claude-..."},
          "verify":       {"provider": "<provider-name>", "model": "claude-..."},
          "report":       {"provider": "<provider-name>", "model": "claude-..."},
          "dynamic_test": {"provider": "<provider-name>", "model": "claude-..."},
          "llm_reach":    {"provider": "<provider-name>", "model": "claude-..."},
          "app_context":  {"provider": "<provider-name>", "model": "claude-..."}
        }
      }
    }

User-authored configs MUST list every phase explicitly — there's no
``_default`` fallback. The error message points at
``openant llm-config show openant-default`` so users can see the
template they need to mirror.

Schema v1 fields (``api_key``, ``default_model`` at the top level)
are read by the migrator and projected into a synthesised
``llm_providers["anthropic"]`` entry. The legacy fields stay in
config.json until the next save — kept for one release as a
downgrade safety net per the plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Mapping, Optional

from .adapter import LLMError


# The closed set of phase names. User configs and openant-default both
# list exactly these keys. Adding a phase here is a coordinated change
# across the Python pipeline, the Go CLI, and the docs.
PHASES: tuple[str, ...] = (
    "analyze",
    "enhance",
    "verify",
    "report",
    "dynamic_test",
    "llm_reach",
    "app_context",
)


CURRENT_SCHEMA_VERSION = 2


# ---------------------------------------------------------------------------
# Typed schema
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProviderConfig:
    """One entry in ``llm_providers``."""

    # Lookup key in the parent dict. Carried inside the dataclass so
    # error messages can name the offending provider without callers
    # threading the name separately.
    name: str
    type: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None


@dataclass(frozen=True)
class PhaseRef:
    """One ``{provider, model}`` pair inside an LLM config."""

    provider: str
    model: str


@dataclass(frozen=True)
class LLMConfig:
    """One entry in ``llm_configs`` (or the built-in ``openant-default``).

    ``phases`` is stored as a :class:`types.MappingProxyType` so the
    dataclass's ``frozen=True`` is honored at every level — a
    ``cfg.phases["analyze"] = something`` mutation raises
    ``TypeError`` instead of silently editing a config that's
    supposed to be immutable. Callers pass a regular dict at
    construction and it's normalised in ``__post_init__``.
    """

    name: str
    phases: Mapping[str, PhaseRef]

    def __post_init__(self) -> None:
        missing = [p for p in PHASES if p not in self.phases]
        extras = [p for p in self.phases if p not in PHASES]
        if missing or extras:
            problems = []
            if missing:
                problems.append(f"missing phases: {', '.join(missing)}")
            if extras:
                problems.append(f"unknown phases: {', '.join(extras)}")
            raise ConfigError(
                f"llm-config {self.name!r}: {'; '.join(problems)}. "
                f"Run `openant llm-config show openant-default` to see the "
                f"full required phase set."
            )
        # Normalise to MappingProxyType so frozen=True holds at the
        # nested-dict level too. Skip if already a MappingProxyType
        # (e.g. constructed from another LLMConfig via dataclasses.replace).
        if not isinstance(self.phases, MappingProxyType):
            object.__setattr__(self, "phases", MappingProxyType(dict(self.phases)))


@dataclass(frozen=True)
class ConfigFile:
    """The whole config.json, post-migration to v2."""

    schema_version: int = CURRENT_SCHEMA_VERSION
    default_llm: str = "openant-default"
    active_project: Optional[str] = None
    llm_providers: dict[str, ProviderConfig] = field(default_factory=dict)
    llm_configs: dict[str, LLMConfig] = field(default_factory=dict)

    # Legacy v1 fields. Read on migration, written back unchanged on
    # save during the deprecation window so a downgraded binary can
    # still pick up the key. The pipeline NEVER reads these directly
    # post-migration — everything goes through ``llm_providers``.
    legacy_api_key: Optional[str] = None
    legacy_default_model: Optional[str] = None


class ConfigError(LLMError):
    """Raised on structurally invalid config.json contents.

    Subclasses :class:`LLMError` so the scanner's single ``except
    LLMError`` clause catches both "bad config" and "bad
    credentials" with one handler — the two failure modes look
    different to the user but are surfaced through the same path.
    """


# ---------------------------------------------------------------------------
# Parsing + migration
# ---------------------------------------------------------------------------


def parse_config(raw: dict) -> ConfigFile:
    """Turn a JSON-loaded dict into a typed :class:`ConfigFile`.

    Runs v1 -> v2 migration in memory. Does NOT write anything back to
    disk — the Go CLI is responsible for persisting migrated state.
    Pipeline code only needs the in-memory shape.

    Raises:
        ConfigError: when the file is structurally invalid in a way
            we can't auto-fix (e.g. an llm-config that omits a
            required phase, or a phase referencing an unknown
            provider).
    """
    if not isinstance(raw, dict):
        raise ConfigError("config.json root must be a JSON object")

    # Surface a malformed ``$schema_version`` as ConfigError (caught
    # by the scanner's ``except LLMError`` handler) rather than a
    # bare ValueError from ``int()``.
    raw_version = raw.get("$schema_version", 1)
    try:
        schema_version = int(raw_version)
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"config.json: '$schema_version' must be an integer, got "
            f"{raw_version!r}"
        ) from exc

    # Coerce + validate like the v2 fields: a non-string here (e.g.
    # ``"api_key": 12345``) is a config error, not a silently-kept value.
    legacy_api_key = _optional_str(raw.get("api_key"))
    legacy_default_model = _optional_str(raw.get("default_model"))

    providers = _parse_providers(raw.get("llm_providers") or {})
    configs = _parse_configs(raw.get("llm_configs") or {})

    if schema_version < CURRENT_SCHEMA_VERSION:
        # v1 had a top-level api_key + default_model. Project the key
        # into an "anthropic" provider entry if one isn't already
        # defined; leave it alone otherwise (the user may have
        # already migrated by hand).
        if legacy_api_key and "anthropic" not in providers:
            providers["anthropic"] = ProviderConfig(
                name="anthropic",
                type="anthropic",
                api_key=legacy_api_key,
                base_url=None,
            )

    default_llm = raw.get("default_llm") or "openant-default"
    if not isinstance(default_llm, str) or not default_llm:
        raise ConfigError(
            "config.json: 'default_llm' must be a non-empty string"
        )

    active_project = raw.get("active_project") or None
    if active_project is not None and not isinstance(active_project, str):
        raise ConfigError("config.json: 'active_project' must be a string")

    cf = ConfigFile(
        schema_version=CURRENT_SCHEMA_VERSION,
        default_llm=default_llm,
        active_project=active_project,
        llm_providers=providers,
        llm_configs=configs,
        legacy_api_key=legacy_api_key,
        legacy_default_model=legacy_default_model,
    )

    # Cross-reference check: every phase reference in every config
    # must point at a provider defined here OR at "anthropic" (which
    # gets auto-synthesised from the env when missing — see
    # ``registry.resolve_provider``, called during
    # ``registry.build_phase_registry``).
    _validate_phase_references(cf)

    return cf


def _parse_providers(raw: dict) -> dict[str, ProviderConfig]:
    if not isinstance(raw, dict):
        raise ConfigError("config.json: 'llm_providers' must be a JSON object")
    out: dict[str, ProviderConfig] = {}
    for name, entry in raw.items():
        if not isinstance(name, str) or not name:
            raise ConfigError(
                f"config.json: provider name must be a non-empty string, got {name!r}"
            )
        if not isinstance(entry, dict):
            raise ConfigError(
                f"config.json: provider {name!r} must be a JSON object"
            )
        ptype = entry.get("type")
        if not isinstance(ptype, str) or not ptype:
            raise ConfigError(
                f"config.json: provider {name!r}: 'type' is required and must be a non-empty string"
            )
        out[name] = ProviderConfig(
            name=name,
            type=ptype,
            api_key=_optional_str(entry.get("api_key")),
            base_url=_optional_str(entry.get("base_url")),
        )
    return out


def _parse_configs(raw: dict) -> dict[str, LLMConfig]:
    if not isinstance(raw, dict):
        raise ConfigError("config.json: 'llm_configs' must be a JSON object")
    out: dict[str, LLMConfig] = {}
    for name, entry in raw.items():
        if not isinstance(name, str) or not name:
            raise ConfigError(
                f"config.json: llm-config name must be a non-empty string, got {name!r}"
            )
        if name == "openant-default":
            raise ConfigError(
                "config.json: 'openant-default' is a built-in name and cannot be "
                "redefined in llm_configs. Copy it under a different name: "
                "`openant llm-config copy openant-default my-config`."
            )
        if not isinstance(entry, dict):
            raise ConfigError(
                f"config.json: llm-config {name!r} must be a JSON object"
            )
        phases: dict[str, PhaseRef] = {}
        for phase_key, phase_entry in entry.items():
            phases[phase_key] = _parse_phase_ref(name, phase_key, phase_entry)
        # LLMConfig.__post_init__ raises if PHASES coverage is wrong.
        out[name] = LLMConfig(name=name, phases=phases)
    return out


def _parse_phase_ref(config_name: str, phase: str, entry) -> PhaseRef:
    if not isinstance(entry, dict):
        raise ConfigError(
            f"config.json: llm-config {config_name!r} phase {phase!r}: "
            f"expected {{provider, model}} object, got {type(entry).__name__}"
        )
    provider = entry.get("provider")
    model = entry.get("model")
    if not isinstance(provider, str) or not provider:
        raise ConfigError(
            f"config.json: llm-config {config_name!r} phase {phase!r}: "
            f"'provider' must be a non-empty string"
        )
    if not isinstance(model, str) or not model:
        raise ConfigError(
            f"config.json: llm-config {config_name!r} phase {phase!r}: "
            f"'model' must be a non-empty string"
        )
    return PhaseRef(provider=provider, model=model)


def _validate_phase_references(cf: ConfigFile) -> None:
    """Validate provider references in user-authored llm-configs.

    Only the configs in ``cf.llm_configs`` (i.e. those parsed from
    config.json) flow through here — the ``openant-default`` builtin is
    constructed by the registry and never passes through this function.

    Every referenced provider must be defined in ``llm_providers``,
    EXCEPT ``anthropic``: that name is allowed to go undefined because
    ``registry.resolve_provider`` synthesises a credential-less
    ProviderConfig for it and lets the SDK read ``ANTHROPIC_API_KEY``
    from the env. This keeps the v1 -> v2 upgrade path working for users
    who have the env key but no ``llm_providers`` entry yet.
    """
    for config in cf.llm_configs.values():
        for phase, ref in config.phases.items():
            if ref.provider not in cf.llm_providers and ref.provider != "anthropic":
                raise ConfigError(
                    f"llm-config {config.name!r} phase {phase!r} references "
                    f"unknown provider {ref.provider!r}. Defined providers: "
                    f"{sorted(cf.llm_providers) or 'none'}."
                )


def _optional_str(value) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(
            f"config.json: expected a string or null, got "
            f"{type(value).__name__} ({value!r})"
        )
    stripped = value.strip()
    return stripped or None


# ---------------------------------------------------------------------------
# Serialisation back to dict (for the Go CLI / file save)
# ---------------------------------------------------------------------------


def serialise_config(cf: ConfigFile) -> dict:
    """Inverse of :func:`parse_config`.

    Always emits schema v2. Legacy fields are written through
    unchanged for one release so a downgraded binary still finds
    the key — the registry never reads them.
    """
    out: dict = {
        "$schema_version": CURRENT_SCHEMA_VERSION,
        "default_llm": cf.default_llm,
        "llm_providers": {
            name: _serialise_provider(p) for name, p in cf.llm_providers.items()
        },
        "llm_configs": {
            name: _serialise_config(c) for name, c in cf.llm_configs.items()
        },
    }
    if cf.active_project:
        out["active_project"] = cf.active_project
    if cf.legacy_api_key:
        out["api_key"] = cf.legacy_api_key
    if cf.legacy_default_model:
        out["default_model"] = cf.legacy_default_model
    return out


def _serialise_provider(p: ProviderConfig) -> dict:
    entry: dict = {"type": p.type}
    if p.api_key is not None:
        entry["api_key"] = p.api_key
    if p.base_url is not None:
        entry["base_url"] = p.base_url
    return entry


def _serialise_config(c: LLMConfig) -> dict:
    return {
        phase: {"provider": ref.provider, "model": ref.model}
        for phase, ref in c.phases.items()
    }


# ---------------------------------------------------------------------------
# Convenience constructors
# ---------------------------------------------------------------------------


def empty_config() -> ConfigFile:
    """Return a fresh ConfigFile representing 'no config.json at all'."""
    return ConfigFile()


def with_provider(cf: ConfigFile, provider: ProviderConfig) -> ConfigFile:
    """Return a copy of ``cf`` with ``provider`` added/updated."""
    new_providers = dict(cf.llm_providers)
    new_providers[provider.name] = provider
    return replace(cf, llm_providers=new_providers)


def with_llm_config(cf: ConfigFile, llm_config: LLMConfig) -> ConfigFile:
    """Return a copy of ``cf`` with ``llm_config`` added/updated."""
    new_configs = dict(cf.llm_configs)
    new_configs[llm_config.name] = llm_config
    return replace(cf, llm_configs=new_configs)
