"""Pluggable LLM provider layer.

OpenAnt's vulnerability pipeline talks to LLMs through this package
rather than calling provider SDKs directly. Each phase (analyze,
enhance, verify, report, dynamic_test, llm_reach, app_context)
resolves to an adapter instance via the registry, and adapters
implement a unified ``LLMAdapter`` protocol so swapping providers is
"drop a file in ``providers/`` and register it" — no core changes.

Public surface:

* :class:`LLMAdapter` — protocol every provider implements.
* Content / message / tool dataclasses — the unified call shape.
* Error taxonomy — ``LLMError`` and subclasses, mapped from each
  provider's native exceptions.

See ``docs/features/llm-providers/plan.done.md`` for the design and
``docs/features/llm-providers/HOW_TO_ADD_AN_ADAPTER.md`` for the
contributor recipe.
"""

from .adapter import (
    CompletionResult,
    ContentBlock,
    LLMAdapter,
    LLMAuthError,
    LLMConnectionError,
    LLMError,
    LLMNotFoundError,
    LLMRateLimitError,
    LLMRefusalError,
    LLMResponseError,
    Message,
    StopReason,
    TextBlock,
    ToolDef,
    ToolResultBlock,
    ToolUseBlock,
)
from .builtins import OPENANT_DEFAULT, get_builtin_default
from .config import (
    PHASES,
    ConfigError,
    ConfigFile,
    LLMConfig,
    PhaseRef,
    ProviderConfig,
    empty_config,
    parse_config,
    serialise_config,
    with_llm_config,
    with_provider,
)
from .registry import (
    PhaseBinding,
    PhaseRegistry,
    binding_policy_summary,
    build_adapter,
    build_phase_registry,
    default_config_path,
    load_config_file,
    probe_registry_or_raise,
    resolve_llm_config,
    resolve_provider,
)
from .helpers import DEFAULT_MAX_TOKENS, lookup_pricing, simple_completion, simple_text

class LLMConfigError(LLMError):
    """A configuration/policy the provider refuses up front (#696).

    The designed-abort discriminator: unlike LLMResponseError (a per-unit
    recoverable response defect), a config error is a property of the RUN —
    it recurs on every unit (a rejected thinking policy, a thinking budget
    that leaves no room for the response), so the analyze stage re-raises
    it to abort the phase (the llm_reachability LLMAuthError parity anchor)
    instead of burying it as per-unit ERROR rows while the run reads green.
    """


__all__ = [
    # adapter
    "CompletionResult",
    "ContentBlock",
    "LLMAdapter",
    "LLMAuthError",
    "LLMConnectionError",
    "LLMError",
    "LLMNotFoundError",
    "LLMRateLimitError",
    "LLMRefusalError",
    "LLMConfigError",
    "LLMResponseError",
    "Message",
    "StopReason",
    "TextBlock",
    "ToolDef",
    "ToolResultBlock",
    "ToolUseBlock",
    # builtins
    "OPENANT_DEFAULT",
    "get_builtin_default",
    # config
    "PHASES",
    "ConfigError",
    "ConfigFile",
    "LLMConfig",
    "PhaseRef",
    "ProviderConfig",
    "empty_config",
    "parse_config",
    "serialise_config",
    "with_llm_config",
    "with_provider",
    # registry
    "PhaseBinding",
    "PhaseRegistry",
    "binding_policy_summary",
    "build_adapter",
    "build_phase_registry",
    "default_config_path",
    "load_config_file",
    "probe_registry_or_raise",
    "resolve_llm_config",
    "resolve_provider",
    # helpers
    "lookup_pricing",
    "DEFAULT_MAX_TOKENS",
    "simple_completion",
    "simple_text",
]
