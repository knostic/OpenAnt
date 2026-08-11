"""
Abstract LLM client.

Live calls (LLM_PROVIDER=anthropic/openai) go through OpenAnt's shared
provider infrastructure (``utilities.llm``) -- the same adapter registry
the seven-phase scan pipeline uses -- instead of constructing SDK clients
directly. This is a thin, Auto Patcher-specific layer BELOW that registry:
Auto Patcher is not one of the seven scan phases and does not go through
``PhaseRegistry`` / the ``llm_configs`` schema. See ``_resolve_provider_config``
and ``_get_or_build_adapter`` below.

When no explicit LLM_PROVIDER/LLM_MODEL env var is set, provider and model
resolution fall back to OpenAnt's shared config.json:
``default_llm -> llm_configs[default_llm].analyze -> {provider, model}``.
Auto Patcher does NOT get its own scan phase for this -- it reuses the
existing "analyze" phase's binding as the closest semantic fit (the
architectural decision recorded against this migration). Only an
EXPLICITLY user-authored llm-config counts: the built-in "openant-default"
(what ``default_llm`` resolves to on an install where the user has never
run ``openant setup llm``) is deliberately excluded from this inheritance,
so a never-configured install keeps today's interactive-menu-or-fail
behavior instead of being silently funneled into Anthropic-only credential
prompting with no provider choice. See ``_resolve_analyze_binding``.

Falls back to deterministic mock responses ONLY when LLM_PROVIDER=mock is
selected explicitly (env var, or the interactive menu's "Mock" choice) --
never implicitly. Mock mode is Auto-Patcher-specific and bypasses the
shared infrastructure entirely.

Model identity is never silently substituted. If a caller-requested model
(via LLM_MODEL, the interactive menu, or the inherited config binding) is
rejected by the provider, this module never falls back to a different
model on its own -- see ``ModelUnavailableError`` and
``_handle_model_unavailable``. Nor does it ever combine an explicitly
resolved provider with a *different* provider's configured model -- see
``_resolve_model``.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Optional

from ..model_config import GPT_4O_MINI
from ..llm import (
    ConfigError,
    LLMAuthError,
    LLMError,
    LLMNotFoundError,
    Message,
    ProviderConfig,
    TextBlock,
    build_adapter,
    load_config_file,
    resolve_llm_config,
    resolve_provider,
)
from .llm_config import LLM_CONFIG, MODEL_ALIASES, DEFAULT_MAX_TOKENS

# In-memory cached choices for the running session so we don't prompt
# repeatedly. Lifetime is the whole process/session (mirrors PhaseRegistry's
# "build once, reuse across calls" adapter lifecycle) -- NOT reset by
# clear_call_metadata(), which only clears per-run stage metadata.
_cached_provider: Optional[str] = None
_cached_api_keys: dict = {}
_cached_model: dict = {}
_cached_adapters: dict = {}

# Per-stage call metadata for the current run, keyed by stage name (e.g.
# "patch_generation", "patch_review", "challenger", "confidence_scorer").
# Populated as a side effect of call_llm(), mirroring _cached_provider /
# _cached_model above; read by main.py after the pipeline run completes.
#
# `model` here is ALWAYS the model that actually executed -- if a requested
# model was rejected and the user explicitly picked an alternative
# interactively, this records the alternative, never the original request.
_call_metadata: dict = {}

# Display names for user-facing messages. Internal `provider` strings stay
# lowercase ("anthropic", "openai") to match LLM_PROVIDER's convention.
_DISPLAY_NAME = {"anthropic": "Anthropic", "openai": "OpenAI"}

# Env var Auto Patcher reads the API key from per provider, when no
# config.json llm_providers entry supplies one -- unchanged from before
# the migration, preserved for backward compatibility / CI / headless use.
_ENV_KEY_NAME = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}

# Safety bound on the interactive model-reselection loop so a user who keeps
# picking models the provider also rejects doesn't spin forever.
_MAX_RESELECTION_ATTEMPTS = 5


class ModelUnavailableError(RuntimeError):
    """The requested model cannot be used and no live call may proceed.

    Raised in exactly three situations -- callers deciding what to do next
    can handle all of them with one except clause, because in every case
    the invariant is the same: no LLM call happens with a model other than
    one the user (or config) explicitly asked for.

    * Non-interactive execution and the provider rejected the requested
      model (no prompting is possible; fail closed).
    * Interactive execution and the user explicitly declined/cancelled
      model reselection.
    * Interactive execution and every reselection attempt was itself
      rejected by the provider, up to ``_MAX_RESELECTION_ATTEMPTS``.

    Never raised for "the user picked a working alternative" -- that case
    returns a normal string result to the original caller, with
    ``_call_metadata``/``_cached_model`` updated to the model that actually
    ran.
    """


def get_call_metadata() -> dict:
    """Return a copy of the per-stage LLM call metadata collected so far."""
    return dict(_call_metadata)


def clear_call_metadata() -> None:
    """Clear per-stage LLM call metadata.

    Call this once at the start of a run — _call_metadata is module-level
    state and otherwise persists across multiple run() invocations in the
    same process (e.g. a batch runner, or a test suite), letting a stale
    stage entry from a previous run leak into a new run's report.
    """
    _call_metadata.clear()


def _resolve_max_tokens() -> int:
    """Resolve the max output tokens for LLM completions.

    Override via the LLM_MAX_TOKENS environment variable; falls back to
    DEFAULT_MAX_TOKENS on an unset or invalid value.
    """
    raw = os.environ.get("LLM_MAX_TOKENS", "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            print(f"Invalid LLM_MAX_TOKENS={raw!r}; falling back to default {DEFAULT_MAX_TOKENS}", file=sys.stderr)
    return DEFAULT_MAX_TOKENS


# ---------------------------------------------------------------------------
# Mock responses – keyed by the first few words of the system prompt so each
# pipeline stage gets a realistic-looking placeholder.
#
# Mock mode is Auto-Patcher-specific and deliberately does NOT go through
# utilities.llm (the shared registry has no mock provider, by design -- see
# migration notes). It bypasses live config/provider resolution entirely.
# ---------------------------------------------------------------------------

_MOCK_PATCH = """\
```diff
--- a/app/auth.py
+++ b/app/auth.py
@@ -42,4 +42,5 @@
 def authenticate(username: str, password: str) -> bool:
-    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
+    query = "SELECT * FROM users WHERE username=? AND password=?"
     cursor = db.execute(query)
+    # Use parameterized queries to prevent SQL injection
     return cursor.fetchone() is not None
```
"""

_MOCK_REVIEW = """\
**Explanation:**
The original code constructs a SQL query using f-string interpolation, which
allows an attacker to inject arbitrary SQL by manipulating the `username` or
`password` parameters (e.g. `' OR '1'='1`).

The patch replaces string interpolation with a parameterized query (`?`
placeholders). The database driver escapes values automatically, eliminating
the injection vector.

**Affected areas:**
- `app/auth.py` – `authenticate()` function
- Any caller that passes user-supplied input to `authenticate()`
- Authentication flow and session management downstream

**Validation notes:**
- Verify the database driver in use supports `?` placeholders (SQLite, MySQL
  via `mysql-connector-python`). Use `%s` for `psycopg2` (PostgreSQL).
- Add unit tests with payloads such as `' OR '1'='1` to confirm they are
  rejected.
- Review all other query construction sites in the codebase for the same
  pattern.
"""

_MOCK_SCORE = """\
**Confidence score:** 0.82

**Reasons:**
- The vulnerability (SQL injection via string interpolation) is
  well-understood and the fix (parameterized queries) is the industry-standard
  remediation — high baseline confidence.
- The exact placeholder syntax (`?` vs `%s`) depends on the database driver,
  which is not visible in the provided context — minor uncertainty.
- No tests were supplied to confirm the patch does not break existing
  authentication flows — slight reduction.
- The patch is minimal and surgical; it changes only the query construction
  line, reducing the risk of unintended side-effects.
"""

_MOCK_CHALLENGE = """\
Still vulnerable: No

Edge cases:
- Database drivers that use `%s` placeholders (driver mismatch)
- Unicode and binary username encodings

Potential issues:
- Missing unit tests for edge-case payloads
- Assumes `db.execute` accepts parameterized args as shown

Summary:
- The patch removes direct interpolation but requires driver-specific
    placeholder verification and targeted tests for edge cases.
"""

# Mock calibration output must cover an arbitrary number of input findings —
# real callers pass however many plausible_risk/generic findings the mock
# challenger produced. Rather than a fixed block count, this is built
# dynamically in _mock_response() from the actual finding count in the
# prompt, cycling through a small set of representative group/wording pairs.
_MOCK_CALIBRATION_GROUPS = ["Observed", "Hypothesis", "Hardening"]


_FINDING_LINE_RE = re.compile(r"^\d+\.\s+.+$", re.MULTILINE)


def _mock_calibration_response(prompt_hint: str) -> str:
    """Build a mock finding-calibration response sized to the actual number
    of input findings in the prompt (the real count varies per run — the
    mock challenger's own finding count, whatever it is), cycling through
    Observed/Hypothesis/Hardening so every group is exercised in mock mode.
    """
    section = prompt_hint.split("## Findings to calibrate", 1)
    finding_lines = _FINDING_LINE_RE.findall(section[1]) if len(section) > 1 else []
    count = len(finding_lines) or 1
    blocks = []
    for i in range(1, count + 1):
        group = _MOCK_CALIBRATION_GROUPS[(i - 1) % len(_MOCK_CALIBRATION_GROUPS)]
        blocks.append(f"{i}. Group: {group}\n   Reworded: (mock calibration) finding {i} reworded as {group.lower()}.")
    return "\n\n".join(blocks)


def _mock_response(prompt_hint: str) -> str:
    """
    Return a mock LLM response based on which stage is calling.

    Routing is determined by the first non-empty line of the system prompt
    (the Markdown heading), e.g. "# Patch Generator Prompt", so that words
    appearing later in the prompt body cannot confuse the dispatch.
    """
    first_line = ""
    for line in prompt_hint.splitlines():
        stripped = line.strip().lstrip("#").strip().lower()
        if stripped:
            first_line = stripped
            break

    if "calibrat" in first_line:
        return _mock_calibration_response(prompt_hint)
    if "confidence" in first_line or "scorer" in first_line:
        return _MOCK_SCORE
    if "reviewer" in first_line or ("review" in first_line and "generator" not in first_line):
        return _MOCK_REVIEW
    if "challeng" in first_line or "adversarial" in first_line or "challenger" in first_line:
        return _MOCK_CHALLENGE
    if "generator" in first_line or "patch" in first_line:
        return _MOCK_PATCH
    return "(mock response)"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class LLMClient:
    """
    Thin wrapper around an LLM provider.

    Parameters
    ----------
    api_key:
        OpenAI API key. When *None* (or an empty string) the client
        operates in mock mode and returns canned responses.
    model:
        OpenAI model name (default ``gpt-4o-mini`` for cost efficiency).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = GPT_4O_MINI,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model
        self._mock = not bool(self.api_key)

    @property
    def is_mock(self) -> bool:
        # Check the resolved provider first — LLM_PROVIDER=anthropic/openai means
        # call_llm() will use a real provider even when OPENAI_API_KEY is absent.
        provider = _cached_provider or os.environ.get("LLM_PROVIDER", "")
        if provider and provider != "mock":
            return False
        if provider == "mock":
            return True
        return self._mock

    def complete(self, system_prompt: str, user_message: str, stage: str = "unknown") -> str:
        """
        Send a chat completion request and return the assistant's text.

        Falls back to a mock response when no API key is configured.

        `stage` labels which pipeline stage is calling (e.g.
        "patch_generation", "challenger") purely for observability — it does
        not affect the request or the returned text. Defaults to "unknown"
        so existing callers are unaffected if they don't pass it.

        System prompt and user message are concatenated into a single
        prompt string exactly as before the migration onto OpenAnt's shared
        adapter layer -- this preserves Auto Patcher's existing effective
        prompt semantics unchanged (see call_llm()'s Message construction).
        """
        # Delegate to the convenience function so both interfaces behave the
        # same way (and so tests/code can call the simple `call_llm`).
        combined = system_prompt + "\n\n" + user_message
        return call_llm(combined, model=self.model, stage=stage)


# ---------------------------------------------------------------------------
# Provider selection (unchanged from before the migration)
# ---------------------------------------------------------------------------


_SUPPORTED_PROVIDERS = ("anthropic", "openai", "mock")


def _resolve_analyze_binding() -> "Optional[tuple[str, str]]":
    """Return ``(provider, model)`` inherited from OpenAnt's shared
    ``default_llm -> llm_configs[default_llm].analyze`` binding, or
    ``None`` when unavailable.

    Auto Patcher does not get its own scan phase for this (see this
    module's docstring for the architectural decision) -- it reuses the
    existing "analyze" phase's binding as the closest semantic fit.

    Only an EXPLICITLY user-authored llm-config counts: the built-in
    "openant-default" -- what ``default_llm`` resolves to on an install
    where the user has never run ``openant setup llm`` -- is deliberately
    excluded. Without this exclusion, a never-configured install would be
    silently funneled into Anthropic-only credential prompting with no
    provider choice, and (more subtly) local development/test machines
    that HAVE run the scan-pipeline wizard would have that config
    unexpectedly govern Auto Patcher too.

    Returns ``None`` on any resolution problem (missing/invalid
    ``default_llm``, or -- structurally near-impossible via real parsing,
    but guarded defensively -- a resolved config missing the "analyze"
    phase) rather than raising: callers treat "no binding" the same as "no
    config at all" and fall through to interactive selection or a clear
    failure, never a partial/guessed binding.
    """
    try:
        cf = load_config_file()
    except Exception:
        return None
    if not cf.default_llm or cf.default_llm == "openant-default":
        return None
    try:
        llm_config = resolve_llm_config(cf, cf.default_llm)
    except ConfigError:
        return None
    ref = llm_config.phases.get("analyze")
    if ref is None or not ref.provider or not ref.model:
        return None
    return (ref.provider, ref.model)


def _resolve_active_provider() -> str:
    """Resolve which provider this session uses: "anthropic" | "openai" | "mock".

    Precedence:
    1. Cached choice for this session.
    2. LLM_PROVIDER env var, if set.
    3. OpenAnt's configured ``default_llm.analyze.provider`` (see
       `_resolve_analyze_binding`), if available.
    4. Interactive prompt (tty only).
    5. Non-interactive with nothing resolved: fail clearly. There is no
       "unset -> mock" default anymore -- mock mode is permitted ONLY when
       explicitly selected as "mock" (env var or interactive menu choice).

    An explicitly-requested provider that isn't one Auto Patcher supports
    is a hard failure, never a silent mock fallback: a live-provider
    request must either use that exact provider or fail clearly; it must
    never quietly produce a mock Trust Report the user could mistake for a
    real one.
    """
    global _cached_provider

    provider = _cached_provider or os.environ.get("LLM_PROVIDER")
    if not provider:
        analyze_binding = _resolve_analyze_binding()
        if analyze_binding is not None:
            provider = analyze_binding[0]
            _cached_provider = provider
        elif not sys.stdin.isatty():
            raise RuntimeError(
                "No LLM_PROVIDER is set, and OpenAnt's config.json has no "
                "explicitly configured default_llm with an 'analyze' binding "
                "to inherit. Set LLM_PROVIDER=anthropic|openai|mock, or "
                "configure a default via `openant setup llm`."
            )
        else:
            print("Select LLM provider:", file=sys.stderr)
            print("1) OpenAI", file=sys.stderr)
            print("2) Anthropic", file=sys.stderr)
            print("3) Mock", file=sys.stderr)
            print("Choose (1/2/3): ", file=sys.stderr, end="", flush=True)
            choice = input().strip()
            mapping = {"1": "openai", "2": "anthropic", "3": "mock"}
            if choice not in mapping:
                raise RuntimeError(f"Invalid choice {choice!r}; expected 1, 2, or 3.")
            provider = mapping[choice]
            _cached_provider = provider

    # An explicitly-requested provider (env var, config binding, or --
    # above -- a session already carrying one from a prior explicit
    # request) must be one Auto Patcher actually supports. No
    # warning-then-mock: fail closed.
    if isinstance(LLM_CONFIG, dict) and provider not in LLM_CONFIG:
        raise RuntimeError(
            f"Unknown LLM provider {provider!r}. Supported Auto Patcher providers: "
            f"{', '.join(_SUPPORTED_PROVIDERS)}."
        )

    return provider


def ensure_provider_configured() -> None:
    """Fail fast, before any pipeline work, if no LLM provider can be
    resolved -- WITHOUT duplicating any part of that resolution.

    This is a thin public entry point for external callers (e.g.
    ``core.patch``) that want the same early, fail-closed guarantee
    ``call_llm()`` already provides on its first real invocation, but
    before paying for setup work (file I/O, an NVD fetch, investigation
    directory creation, ...) the pipeline would otherwise do first. It is
    a pure delegation to `_resolve_active_provider` -- the ONE
    authoritative resolver -- not a second, independent check: env
    selection, OpenAnt's configured ``default_llm.analyze`` binding, and
    interactive selection are all honored exactly as `call_llm` honors
    them, because this calls the identical function.

    Side effects mirror `_resolve_active_provider`: the resolved choice is
    cached for the rest of the session (so calling this and then later
    making a real call never re-prompts or re-raises), and an interactive
    terminal may prompt here rather than at the first actual LLM call.

    Raises:
        RuntimeError: non-interactive execution with no explicit provider
            and no valid OpenAnt config binding, or an explicitly
            requested provider Auto Patcher doesn't support. Never
            degrades to mock -- mock is only ever returned when
            explicitly selected.
    """
    _resolve_active_provider()


# ---------------------------------------------------------------------------
# Model selection
#
# IMPORTANT: there is no local whitelist here. config/models.json's
# "status" field (current/retired/unknown) and LLM_CONFIG's "models" dict
# are informational only -- an explicitly requested model (LLM_MODEL, an
# interactive menu choice, or the inherited config binding) is NEVER
# rejected or silently substituted here. The provider is the sole
# authority on whether a model can actually be used; see call_llm()'s
# handling of LLMNotFoundError / ModelUnavailableError for what happens
# when it says no.
# ---------------------------------------------------------------------------


def _resolve_model(provider: str, fallback_model: str) -> str:
    """Resolve which model string to request for the already-resolved
    `provider`.

    Precedence:
    1. Already resolved earlier this session (`_cached_model[provider]`) --
       checked FIRST so that once a model has been confirmed to work (or
       explicitly reselected after a failure), every later stage call in
       the same run reuses that exact model rather than re-deriving the
       original (possibly rejected) request from LLM_MODEL on every call.
       Model identity is part of experiment reproducibility: a run should
       use one confirmed model throughout, not re-litigate the choice once
       per stage.
    2. LLM_MODEL environment variable, if set -- passed through verbatim
       (after a small legacy-alias mapping; see MODEL_ALIASES), with no
       whitelist check.
    3. OpenAnt's configured ``default_llm.analyze.model``, but ONLY when
       its provider matches `provider` exactly. An explicit/resolved
       provider is never combined with a *different* provider's
       configured model -- if they don't match, this falls straight
       through to step 4/5 exactly as if no binding existed at all.
    4. Interactive: a numbered menu built from LLM_CONFIG (informational
       display only -- the choice is never validated against it).
    5. Non-interactive with nothing resolved: fail clearly. There is no
       silent default model anymore (not the old Auto Patcher default, not
       Haiku, not anything chosen from the registry).

    `fallback_model` (the legacy `model=` argument threaded through from
    `LLMClient`/`call_llm`) is intentionally never consulted as a silent
    default -- kept only for call-site signature compatibility.
    """
    if provider in _cached_model:
        return _cached_model[provider]

    env_model = os.environ.get("LLM_MODEL", "").strip()
    if env_model:
        mapped = MODEL_ALIASES.get(env_model, env_model) if isinstance(MODEL_ALIASES, dict) else env_model
        if mapped != env_model:
            print(f"Mapping model name to latest version: {mapped}", file=sys.stderr)
        _cached_model[provider] = mapped
        return mapped

    analyze_binding = _resolve_analyze_binding()
    if analyze_binding is not None:
        binding_provider, binding_model = analyze_binding
        if binding_provider == provider:
            _cached_model[provider] = binding_model
            return binding_model
        print(
            f"Note: OpenAnt's configured default model ({binding_model!r}) is for "
            f"provider {binding_provider!r}, not {provider!r} -- an explicit model "
            f"is required.",
            file=sys.stderr,
        )

    if not sys.stdin.isatty():
        raise RuntimeError(
            f"No LLM_MODEL is set and no compatible model is configured for "
            f"provider {provider!r} in OpenAnt's config.json. Set "
            f"LLM_MODEL=<model> explicitly."
        )

    # Interactive menu -- built from LLM_CONFIG purely for discoverability.
    # The selection is never rejected locally; only the provider (via the
    # actual API call in call_llm()) can reject it.
    provider_cfg = LLM_CONFIG.get(provider, {}) if isinstance(LLM_CONFIG, dict) else {}
    models_dict = provider_cfg.get("models", {})
    items = list(models_dict.items())
    print(f"Select {provider.capitalize()} model:", file=sys.stderr)
    for idx, (mname, meta) in enumerate(items, start=1):
        label = meta.get("label") if isinstance(meta, dict) else ""
        print(f"{idx}) {mname} ({label})", file=sys.stderr)
    print(f"Choose (1-{len(items)}): ", file=sys.stderr, end="", flush=True)
    choice = input().strip()
    try:
        sel = int(choice) - 1
        if sel < 0:
            raise ValueError
        chosen = items[sel][0]
    except Exception:
        raise RuntimeError(f"Invalid choice {choice!r}; expected 1-{len(items)}.")

    if isinstance(MODEL_ALIASES, dict) and chosen in MODEL_ALIASES:
        mapped = MODEL_ALIASES[chosen]
        print(f"Mapping model name to latest version: {mapped}", file=sys.stderr)
        chosen = mapped

    _cached_model[provider] = chosen
    return chosen


def _known_models_for(provider: str) -> list:
    """Locally known models for `provider`, sourced from OpenAnt's existing
    shared model registry (config/models.json via core.model_registry).

    These are LOCALLY KNOWN, not provider-confirmed available -- status
    ("current"/"retired"/"unknown") is OpenAnt's own shipped claim, not a
    live check. Reuses the existing registry rather than maintaining a
    second Auto Patcher-specific model list.
    """
    try:
        from core.model_registry import load_models
    except ImportError:
        return []
    try:
        records = load_models()
    except Exception:
        return []
    return [
        {"id": rec.get("id"), "status": rec.get("status", "unknown")}
        for rec in records
        if rec.get("provider") == provider and rec.get("id")
    ]


# ---------------------------------------------------------------------------
# Provider credential / adapter resolution via OpenAnt's shared infrastructure
# ---------------------------------------------------------------------------


def _resolve_provider_config(provider: str) -> ProviderConfig:
    """Resolve credentials for `provider` using OpenAnt's shared config.

    Precedence (highest first):
    1. config.json's ``llm_providers[provider].api_key`` -- the same
       ``~/.config/openant/config.json`` the seven-phase scan pipeline
       reads, via ``utilities.llm.load_config_file`` /
       ``utilities.llm.resolve_provider``. Reused as-is; no duplicate
       parsing.
    2. The provider's environment variable (``ANTHROPIC_API_KEY`` /
       ``OPENAI_API_KEY``) -- preserved for backward compatibility with
       existing headless/CI usage.
    3. An interactive prompt (once per process, cached), when a TTY is
       attached -- preserves the pre-migration UX.

    Returns a ``ProviderConfig`` whose ``api_key`` is ``None`` if none of
    the above produced one; callers must check for that and fail loudly
    rather than attempting to build an adapter with no credential.
    """
    base_url = None
    api_key = None
    try:
        cfg = resolve_provider(load_config_file(), provider)
        api_key = cfg.api_key
        base_url = cfg.base_url
    except ConfigError:
        # No llm_providers[provider] entry in config.json (and provider is
        # not "anthropic", the one name resolve_provider() auto-synthesizes
        # credential-free). Fall through to env / interactive prompt below.
        pass

    if api_key:
        _cached_api_keys[provider] = api_key
    else:
        env_name = _ENV_KEY_NAME.get(provider)
        api_key = _get_api_key_for(provider, env_name) if env_name else None

    return ProviderConfig(name=provider, type=provider, api_key=api_key or None, base_url=base_url)


def _get_api_key_for(p: str, env_name: str) -> Optional[str]:
    """Env var / interactive-prompt fallback, cached per session.

    Only consulted when config.json has no ``llm_providers[p].api_key`` --
    see ``_resolve_provider_config``.
    """
    if p in _cached_api_keys:
        return _cached_api_keys[p]
    key = os.environ.get(env_name, "")
    if not key:
        try:
            print(f"Enter {env_name}: ", file=sys.stderr, end="", flush=True)
            key = input().strip()
        except Exception:
            key = ""
    if key:
        _cached_api_keys[p] = key
    return key


def _missing_key_message(provider: str) -> str:
    env_name = _ENV_KEY_NAME.get(provider, "")
    return (
        f"LLM_PROVIDER={provider} is configured but no {_DISPLAY_NAME.get(provider, provider)} "
        f"API key is available. Checked: config.json's llm_providers[{provider!r}].api_key, "
        f"the {env_name} environment variable, and an interactive prompt. "
        f"Set one of those, or set LLM_PROVIDER=mock to use mock mode."
    )


def _get_or_build_adapter(provider: str):
    """Build (once per process) or reuse the shared adapter for `provider`.

    Mirrors PhaseRegistry's "one adapter per provider, built once, reused
    across every call" lifecycle -- Auto Patcher's LLMClient is a single
    shared client across all 8 stages, so one adapter instance per provider
    per run is correct and avoids re-reading config.json / reconstructing
    the SDK client on every stage call.
    """
    if provider in _cached_adapters:
        return _cached_adapters[provider]

    provider_config = _resolve_provider_config(provider)
    if not provider_config.api_key:
        raise RuntimeError(_missing_key_message(provider))

    try:
        adapter = build_adapter(provider_config)
    except LLMAuthError as exc:
        raise RuntimeError(f"{_DISPLAY_NAME.get(provider, provider)} API call failed: {exc}") from exc

    _cached_adapters[provider] = adapter
    return adapter


# ---------------------------------------------------------------------------
# Model-failure handling — the non-negotiable "never silently substitute" path
# ---------------------------------------------------------------------------


def _print_model_failure(provider: str, model: str, reason: str) -> None:
    print("", file=sys.stderr)
    print("The requested model could not be used:", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"Provider: {_DISPLAY_NAME.get(provider, provider)}", file=sys.stderr)
    print(f"Model: {model}", file=sys.stderr)
    print(f"Reason: {reason}", file=sys.stderr)
    print("", file=sys.stderr)


def _handle_model_unavailable(provider: str, model: str, reason: str, adapter, max_tokens: int, messages: list):
    """`model` was rejected by `provider` (LLMNotFoundError). Never silently
    substitutes another model -- either the user explicitly picks a working
    alternative (interactive) or this raises ModelUnavailableError so the
    caller aborts.

    Returns:
        (CompletionResult, actual_model) if an explicitly user-selected
        alternative succeeded.

    Raises:
        ModelUnavailableError: non-interactive execution, or the user
            declined/cancelled, or every reselection attempt also failed.
    """
    _print_model_failure(provider, model, reason)

    alternatives = [m for m in _known_models_for(provider) if m["id"] != model]

    if not sys.stdin.isatty():
        lines = [
            f"Requested model {model!r} is unavailable for provider {provider!r}.",
            f"Reason: {reason}",
            "",
        ]
        if alternatives:
            lines.append(
                "Locally known models for this provider (from OpenAnt's model "
                "registry -- NOT a live provider-confirmed availability check):"
            )
            lines += [f"  - {m['id']} ({m['status']})" for m in alternatives]
            lines.append("")
        lines.append(f"Rerun with: LLM_MODEL=<model> ... openant patch ...")
        raise ModelUnavailableError("\n".join(lines))

    # Interactive: only ever proceed with a model the user explicitly typed
    # a selection for. Looping lets a second bad pick be corrected without
    # re-running the whole command, but is bounded so a user who keeps
    # picking rejected models doesn't spin forever.
    current_model, current_reason = model, reason
    for _attempt in range(_MAX_RESELECTION_ATTEMPTS):
        if alternatives:
            print(
                "Locally known models for this provider (from OpenAnt's model "
                "registry -- NOT a live provider-confirmed availability check):",
                file=sys.stderr,
            )
            for idx, m in enumerate(alternatives, start=1):
                print(f"{idx}) {m['id']} ({m['status']})", file=sys.stderr)
        else:
            print("No other locally known models for this provider.", file=sys.stderr)
        print("Choose a number, or press Enter to abort: ", file=sys.stderr, end="", flush=True)
        choice = input().strip()
        if not choice:
            raise ModelUnavailableError(
                f"User declined to select an alternative model for provider "
                f"{provider!r}; aborting the Auto Patcher run."
            )
        try:
            selected = alternatives[int(choice) - 1]["id"]
        except (ValueError, IndexError):
            print("Invalid selection.", file=sys.stderr)
            continue

        print(f"Retrying with explicitly selected model: {selected}", file=sys.stderr)
        try:
            result = adapter.complete(model=selected, system=None, messages=messages, max_tokens=max_tokens)
            _cached_model[provider] = selected
            return result, selected
        except LLMNotFoundError as exc:
            current_model, current_reason = selected, str(exc)
            _print_model_failure(provider, current_model, current_reason)
            alternatives = [m for m in alternatives if m["id"] != selected]
            continue

    raise ModelUnavailableError(
        f"Gave up after {_MAX_RESELECTION_ATTEMPTS} rejected model selections for "
        f"provider {provider!r}; aborting the Auto Patcher run. Last attempted "
        f"model: {current_model!r} ({current_reason})."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def call_llm(prompt: str, model: str = GPT_4O_MINI, stage: str = "unknown") -> str:
    """Call an LLM and return a single text response.

    Live calls (provider != "mock") go through OpenAnt's shared adapter
    layer (utilities.llm) -- see _resolve_provider_config /
    _get_or_build_adapter. Mock mode bypasses that layer entirely.

    Model identity is never silently substituted: if the resolved model is
    rejected by the provider (LLMNotFoundError), this raises
    ModelUnavailableError unless the caller is interactive and explicitly
    picks a working alternative -- see _handle_model_unavailable. No other
    live failure (auth, rate limit, connection, malformed response) ever
    causes a fallback to mock or to a different provider/model; it is
    raised so the caller aborts.
    """
    global _cached_model

    provider = _resolve_active_provider()

    if provider == "mock":
        print("Using mock LLM", file=sys.stderr)
        _call_metadata[stage] = {
            "provider": "mock",
            "model": "mock",
            "max_tokens_configured": None,
            "stop_reason": "mock",
        }
        return _mock_response(prompt)

    model_to_use = _resolve_model(provider, model)
    adapter = _get_or_build_adapter(provider)
    resolved_max_tokens = _resolve_max_tokens()

    print(f"Using {_DISPLAY_NAME.get(provider, provider)} (model: {model_to_use})", file=sys.stderr)

    # Preserve Auto Patcher's existing effective prompt exactly: LLMClient.
    # complete() already concatenated system_prompt + user_message into one
    # string before calling here, so this is a single user turn with no
    # system parameter -- matching pre-migration behavior byte-for-byte.
    messages = [Message(role="user", content=[TextBlock(text=prompt)])]

    try:
        result = adapter.complete(model=model_to_use, system=None, messages=messages, max_tokens=resolved_max_tokens)
    except LLMNotFoundError as exc:
        result, model_to_use = _handle_model_unavailable(
            provider, model_to_use, str(exc), adapter, resolved_max_tokens, messages
        )
    except LLMError as exc:
        raise RuntimeError(f"{_DISPLAY_NAME.get(provider, provider)} API call failed: {exc}") from exc

    # _cached_model always reflects the model that ACTUALLY executed --
    # core/patch.py's RunMetadata reads this for the Trust Report, so a
    # reselection is truthfully recorded for every subsequent stage too.
    _cached_model[provider] = model_to_use

    _call_metadata[stage] = {
        "provider": provider,
        "model": model_to_use,
        "max_tokens_configured": resolved_max_tokens,
        "stop_reason": result.stop_reason,
    }

    return "\n".join(block.text for block in result.content if isinstance(block, TextBlock))
