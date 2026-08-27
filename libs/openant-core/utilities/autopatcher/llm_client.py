"""
Abstract LLM client.

Auto Patcher is a consumer of OpenAnt's LLM platform, not a second
configuration system. For REAL providers (anthropic/openai/google/...),
provider and model selection come ONLY from OpenAnt's canonical LLM
configuration -- the same ``default_llm`` -> ``llm_configs[default_llm]``
-> ``{provider, model}`` resolution every scan-pipeline phase uses. Auto
Patcher reuses the existing "analyze" phase binding as the closest
semantic fit (it is not one of the seven scan phases and does not go
through ``PhaseRegistry``), and inherits the built-in ``openant-default``
config exactly like every other OpenAnt command -- there is no
Auto-Patcher-specific exclusion of it anymore.

``LLM_PROVIDER`` / ``LLM_MODEL`` are NOT a supported way to select a real
provider or model here (normal OpenAnt has no such mechanism either).
Setting either to select a real provider/model is a hard, clear failure --
never a silent no-op -- so an existing script asking for one provider/model
never silently runs against a different one. See ``_resolve_active_provider``
/ ``_resolve_model``.

``LLM_PROVIDER=mock`` is the one narrow, intentional exception: an explicit
Auto-Patcher-specific test/research escape hatch that bypasses live
resolution and the shared adapter layer entirely. It is never an implicit
fallback -- there is no "unset -> mock" default.

Live calls (any real provider) go through OpenAnt's shared provider
infrastructure (``utilities.llm``) -- the same ``resolve_provider()`` /
``build_adapter()`` the seven-phase scan pipeline uses -- with no
Auto-Patcher-specific credential resolution layered in front. Credential
behavior therefore matches canonical OpenAnt exactly: config.json's
``llm_providers[<name>].api_key`` first, then whatever environment-variable
fallback the shared resolver / provider SDK itself already provides (e.g.
``resolve_provider``'s anthropic-only credential-less synthesis, letting
the Anthropic SDK read ``ANTHROPIC_API_KEY``). Auto Patcher does not expand
that contract for any provider.

Model identity is never silently substituted. If a configured model is
rejected by the provider, this module never falls back to a different
model and never offers an interactive reselection -- it fails clearly and
points at ``openant setup llm``. See ``ModelUnavailableError`` and
``_handle_model_unavailable``.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Optional

from ..model_config import GPT_4O_MINI
from ..llm_client import get_global_tracker
from ..llm import (
    LLMError,
    LLMNotFoundError,
    Message,
    TextBlock,
    build_adapter,
    load_config_file,
    resolve_llm_config,
    resolve_provider,
)

# Default max output tokens for LLM completions. Override per-run via the
# LLM_MAX_TOKENS environment variable (see _resolve_max_tokens).
DEFAULT_MAX_TOKENS = 4096

# In-memory cached choices for the running session so we don't re-resolve
# repeatedly. Lifetime is the whole process/session (mirrors PhaseRegistry's
# "build once, reuse across calls" adapter lifecycle) -- NOT reset by
# clear_call_metadata(), which only clears per-run stage metadata.
_cached_provider: Optional[str] = None
_cached_model: dict = {}
_cached_adapters: dict = {}

# Per-stage call metadata for the current run, keyed by stage name (e.g.
# "patch_generation", "patch_review", "challenger", "confidence_scorer").
# Populated as a side effect of call_llm(); read by main.py after the
# pipeline run completes.
#
# `model` here is ALWAYS the model that actually executed.
#
# NOTE: this dict holds only the MOST RECENT call for a given stage tag --
# a stage that legitimately makes more than one call under the same tag
# (e.g. Finding Calibration's v1 and v2 passes both tagged
# "finding_calibration") silently overwrites the earlier entry here. This
# is preserved, unchanged, for backward compatibility with every existing
# consumer of get_call_metadata() (core/patch.py's RunMetadata, tests).
# See _call_history / get_call_history() below for the ordered, complete
# record -- added for the Auto Patcher stage-replay foundation, which needs
# to prove "this stage made exactly N calls" per stage, not just "a call
# with this tag happened at some point."
_call_metadata: dict = {}

# Ordered, complete history of every call, keyed by stage name -> list of
# per-call metadata dicts in call order. Never overwrites -- every call
# appends. Same lifetime/reset semantics as _call_metadata (cleared by
# clear_call_metadata()).
_call_history: dict = {}

# Display names for user-facing messages. Internal `provider` strings stay
# lowercase ("anthropic", "openai") to match canonical config's convention.
_DISPLAY_NAME = {"anthropic": "Anthropic", "openai": "OpenAI", "google": "Google"}


class ModelUnavailableError(RuntimeError):
    """The requested model cannot be used and no live call may proceed.

    Raised whenever a resolved model is rejected by the provider
    (``LLMNotFoundError``) -- Auto Patcher never falls back to a different
    model or offers an interactive reselection; the caller is directed to
    update OpenAnt's canonical LLM configuration instead. Interactive and
    non-interactive execution behave identically here.
    """


def get_call_metadata() -> dict:
    """Return a copy of the per-stage LLM call metadata collected so far.

    One entry per stage tag -- the MOST RECENT call under that tag. Use
    get_call_history() instead when a stage may legitimately make more
    than one call under the same tag and every call's metadata (not just
    the last) is needed.
    """
    return dict(_call_metadata)


def get_call_history() -> dict:
    """Return a copy of the complete, ordered per-stage call history:
    ``{stage: [call_metadata, ...]}``, one list entry per call to that
    stage tag, in call order. Unlike get_call_metadata(), no call is ever
    lost to a same-tag overwrite -- a stage that legitimately makes
    several calls under one tag (e.g. two "finding_calibration" passes)
    has all of them here, in order.
    """
    return {stage: [dict(call) for call in calls] for stage, calls in _call_history.items()}


def clear_call_metadata() -> None:
    """Clear per-stage LLM call metadata (both the latest-call view and
    the ordered call history).

    Call this once at the start of a run — _call_metadata/_call_history
    are module-level state and otherwise persist across multiple run()
    invocations in the same process (e.g. a batch runner, or a test
    suite), letting a stale stage entry from a previous run leak into a
    new run's report.
    """
    _call_metadata.clear()
    _call_history.clear()


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
# utilities.llm (the shared registry has no mock provider, by design). It
# bypasses live config/provider resolution entirely.
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
        # Check the resolved provider first — a resolved real provider
        # means call_llm() will use it regardless of OPENAI_API_KEY.
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
# Provider + model selection
#
# Real providers: ONLY OpenAnt's canonical configuration. No local
# whitelist, no Auto-Patcher-specific provider/model override.
# Mock: the one explicit, narrow exception -- see the module docstring.
# ---------------------------------------------------------------------------


def _resolve_canonical_binding() -> "tuple[str, str]":
    """Resolve ``(provider, model)`` from OpenAnt's canonical LLM
    configuration -- ``default_llm`` -> ``llm_configs[default_llm].analyze``
    -> ``{provider, model}``, falling back to the built-in
    ``openant-default`` exactly like every other OpenAnt command (scan,
    analyze, verify, ...). This is Auto Patcher's ONLY real-provider
    configuration mechanism now -- there is no Auto-Patcher-specific
    override above it, and no exclusion of ``openant-default``.

    Raises:
        ConfigError (a ``utilities.llm.LLMError`` subclass): config.json is
            malformed, or ``default_llm`` names a config that doesn't
            exist -- the identical failure canonical OpenAnt commands raise
            for the same problem.
        RuntimeError: the resolved llm-config has no usable "analyze" phase
            binding. Structurally near-impossible via real parsing --
            ``LLMConfig.__post_init__`` requires all seven phases -- but
            guarded defensively rather than assumed.
    """
    cf = load_config_file()
    llm_config = resolve_llm_config(cf, cf.default_llm)
    ref = llm_config.phases.get("analyze")
    if ref is None or not ref.provider or not ref.model:
        raise RuntimeError(
            f"llm-config {llm_config.name!r} has no usable 'analyze' phase "
            f"binding. Run `openant setup llm` to reconfigure."
        )
    return (ref.provider, ref.model)


def _resolve_active_provider() -> str:
    """Resolve which provider this session uses: "mock", or whatever
    OpenAnt's canonical configuration resolves for the "analyze" phase.

    Precedence:
    1. Cached choice for this session.
    2. LLM_PROVIDER=mock -- the ONLY recognized value; an explicit,
       Auto-Patcher-specific test/research escape hatch (see module
       docstring). Never an implicit fallback.
    3. Any OTHER non-empty LLM_PROVIDER value -- hard, clear failure.
       Real-provider selection is not a supported Auto Patcher interface
       through this variable (normal OpenAnt has none either); it is never
       silently ignored, so an existing script asking for one provider can
       never end up silently running against a different one.
    4. OpenAnt's canonical default_llm/analyze binding (see
       _resolve_canonical_binding) -- always resolves for any valid
       config.json, exactly like every other OpenAnt command, including a
       never-configured install (via the built-in openant-default).
    """
    global _cached_provider

    if _cached_provider:
        return _cached_provider

    env_provider = os.environ.get("LLM_PROVIDER", "").strip()
    if env_provider == "mock":
        _cached_provider = "mock"
        return _cached_provider
    if env_provider:
        raise RuntimeError(
            f"LLM_PROVIDER={env_provider!r} is no longer used to select a "
            "real provider for Auto Patcher. Configure a provider and model "
            "via `openant setup llm`. Set LLM_PROVIDER=mock to use Auto "
            "Patcher's test/research mock mode."
        )

    provider, model = _resolve_canonical_binding()
    _cached_provider = provider
    _cached_model[provider] = model
    return provider


def ensure_provider_configured() -> None:
    """Fail fast, before any pipeline work, if no LLM provider can be
    resolved -- WITHOUT duplicating any part of that resolution.

    This is a thin public entry point for external callers (e.g.
    ``core.patch``) that want the same early, fail-closed guarantee
    ``call_llm()`` already provides on its first real invocation, but
    before paying for setup work (file I/O, an NVD fetch, investigation
    directory creation, ...) the pipeline would otherwise do first.

    For a real provider, this also eagerly builds (and caches, for reuse
    by the first real `call_llm()`) the shared adapter via
    `_get_or_build_adapter` -- catching an undefined provider in
    config.json (`ConfigError`) or an adapter-construction-time credential
    failure early. This is NOT a full credential guarantee for every
    provider: some SDKs (Anthropic's, as of this writing) construct their
    client successfully with no key at all and only reject the request
    when a real completion is attempted -- that specific failure mode
    surfaces later, at the first real `call_llm()`, not here. Auto Patcher
    deliberately does not add a live 1-token probe call (like canonical
    OpenAnt's `probe_registry_or_raise`) to close that gap -- that would be
    new, heavier behavior no caller asked for, not a smallest-change
    alignment with existing behavior.

    Since OpenAnt's canonical `openant-default` is now always inheritable,
    provider/model RESOLUTION itself (as opposed to the credential) always
    succeeds for any valid config.json, exactly like every other OpenAnt
    command -- there is no more "unconfigured install" state for
    resolution to fail fast on; only a broken config.json reference, or a
    disallowed env var, does.

    Raises:
        ConfigError: OpenAnt's config.json is malformed, or `default_llm`
            names a config that doesn't exist -- the identical failure
            canonical OpenAnt commands raise for the same problem.
        RuntimeError: a non-mock LLM_PROVIDER/LLM_MODEL value was set
            (real-provider selection is not supported through them), or a
            credential failure was caught at adapter-construction time.
            Never degrades to mock -- mock is only ever returned when
            explicitly selected.
    """
    provider = _resolve_active_provider()
    if provider != "mock":
        _get_or_build_adapter(provider)


def _resolve_model(provider: str, fallback_model: str) -> str:
    """Resolve which model string to request for the already-resolved
    `provider`.

    `provider == "mock"`: always "mock" -- LLM_MODEL is irrelevant to mock.

    Otherwise: the model was already resolved atomically alongside the
    provider, from OpenAnt's canonical configuration (see
    `_resolve_active_provider` / `_resolve_canonical_binding`) -- there is
    no separate real-provider model-selection step anymore. LLM_MODEL is
    recognized only to fail clearly if set, for the same reason
    LLM_PROVIDER is: silently ignoring it could let a real provider run
    with a different model than a caller explicitly asked for.

    `fallback_model` (the legacy `model=` argument threaded through from
    `LLMClient`/`call_llm`) is intentionally never consulted -- kept only
    for call-site signature compatibility.
    """
    if provider == "mock":
        return "mock"

    env_model = os.environ.get("LLM_MODEL", "").strip()
    if env_model:
        raise RuntimeError(
            f"LLM_MODEL={env_model!r} is no longer used to select a model "
            "for Auto Patcher. Configure a model via `openant setup llm`."
        )

    return _cached_model[provider]


def _known_models_for(provider: str) -> list:
    """Locally known models for `provider`, sourced from OpenAnt's existing
    shared model registry (config/models.json via core.model_registry).

    These are LOCALLY KNOWN, not provider-confirmed available -- status
    ("current"/"retired"/"unknown") is OpenAnt's own shipped claim, not a
    live check. Reuses the existing registry rather than maintaining a
    second Auto Patcher-specific model list. Shown only as reference text
    in a model-unavailable failure message -- never used to drive an
    automatic or interactive substitution.
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
# Adapter construction -- delegates entirely to OpenAnt's shared registry
# ---------------------------------------------------------------------------


def _get_or_build_adapter(provider: str):
    """Build (once per process) or reuse the shared adapter for `provider`.

    Delegates entirely to the shared `resolve_provider()` / `build_adapter()`
    -- the SAME functions the seven-phase scan pipeline uses -- with no
    Auto-Patcher-specific credential resolution layered in front. Auto
    Patcher's LLMClient is a single shared client across all pipeline
    stages, so one adapter instance per provider per run is correct and
    avoids re-reading config.json / reconstructing the SDK client on every
    stage call.

    Any resolution failure (an undefined provider in config.json, or a
    credential the provider's SDK still can't find) surfaces as a single
    clear RuntimeError pointing at `openant setup llm` -- the identical
    class of failure canonical OpenAnt commands raise for the same problem,
    just re-worded for this call site.
    """
    if provider in _cached_adapters:
        return _cached_adapters[provider]

    try:
        provider_config = resolve_provider(load_config_file(), provider)
        adapter = build_adapter(provider_config)
    except LLMError as exc:
        raise RuntimeError(
            f"No usable credential for provider {provider!r} (resolved via "
            f"your OpenAnt LLM configuration). Run `openant setup llm` to "
            f"configure one, or set that provider's standard credential "
            f"environment variable if its SDK supports it directly. ({exc})"
        ) from exc

    _cached_adapters[provider] = adapter
    return adapter


# ---------------------------------------------------------------------------
# Model-failure handling — the non-negotiable "never silently substitute" path
# ---------------------------------------------------------------------------


def _handle_model_unavailable(provider: str, model: str, reason: str) -> None:
    """`model` was rejected by `provider` (LLMNotFoundError). Never
    substitutes another model and never offers an interactive reselection
    -- fails clearly, with the locally-known-models list shown as reference
    only, and points at `openant setup llm` to reconfigure. Identical
    behavior whether the run is interactive or not.

    Raises:
        ModelUnavailableError: always.
    """
    print("", file=sys.stderr)
    print("The requested model could not be used:", file=sys.stderr)
    print("", file=sys.stderr)
    print(f"Provider: {_DISPLAY_NAME.get(provider, provider)}", file=sys.stderr)
    print(f"Model: {model}", file=sys.stderr)
    print(f"Reason: {reason}", file=sys.stderr)
    print("", file=sys.stderr)

    alternatives = [m for m in _known_models_for(provider) if m["id"] != model]

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
    lines.append(
        "Update your OpenAnt LLM configuration (`openant setup llm`) to use "
        "a different model."
    )
    raise ModelUnavailableError("\n".join(lines))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def call_llm(prompt: str, model: str = GPT_4O_MINI, stage: str = "unknown") -> str:
    """Call an LLM and return a single text response.

    Live calls (provider != "mock") go through OpenAnt's shared adapter
    layer (utilities.llm) -- see _get_or_build_adapter. Mock mode bypasses
    that layer entirely.

    Model identity is never silently substituted: if the resolved model is
    rejected by the provider (LLMNotFoundError), this raises
    ModelUnavailableError -- see _handle_model_unavailable. No other live
    failure (auth, rate limit, connection, malformed response) ever causes
    a fallback to mock or to a different provider/model; it is raised so
    the caller aborts.
    """
    provider = _resolve_active_provider()

    if provider == "mock":
        print("Using mock LLM", file=sys.stderr)
        record = {
            "provider": "mock",
            "model": "mock",
            "max_tokens_configured": None,
            "stop_reason": "mock",
        }
        _call_metadata[stage] = record
        _call_history.setdefault(stage, []).append(dict(record))
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
        _handle_model_unavailable(provider, model_to_use, str(exc))  # always raises
    except LLMError as exc:
        raise RuntimeError(f"{_DISPLAY_NAME.get(provider, provider)} API call failed: {exc}") from exc
    except Exception as exc:
        # Not every provider SDK raises a typed LLMError for a missing
        # credential -- e.g. the Anthropic SDK constructs its client
        # successfully with no key at all and only rejects the request
        # (with a raw, un-typed exception) once a real completion is
        # attempted. Wrap ANY other unexpected failure the same way, so a
        # credential problem this deep still fails clearly instead of a
        # raw SDK traceback -- never a fallback to mock or another model.
        raise RuntimeError(
            f"{_DISPLAY_NAME.get(provider, provider)} API call failed: "
            f"{type(exc).__name__}: {exc}. If this is a missing-credential "
            f"error, run `openant setup llm` to configure one, or set that "
            f"provider's standard credential environment variable."
        ) from exc

    # Record real usage/cost against OpenAnt's shared global tracker -- the
    # same TokenTracker.record_call() the seven-phase scan pipeline uses --
    # so a live run's cost shows up via core.tracking.get_usage() / step
    # reports instead of always reading $0.
    get_global_tracker().record_call(
        model=model_to_use,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        pricing=getattr(adapter, "pricing", {}).get(model_to_use),
    )

    record = {
        "provider": provider,
        "model": model_to_use,
        "max_tokens_configured": resolved_max_tokens,
        "stop_reason": result.stop_reason,
    }
    _call_metadata[stage] = record
    _call_history.setdefault(stage, []).append(dict(record))

    return "\n".join(block.text for block in result.content if isinstance(block, TextBlock))
