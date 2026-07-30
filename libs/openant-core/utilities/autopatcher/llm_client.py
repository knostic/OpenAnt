"""
Abstract LLM client.

Uses the OpenAI API when OPENAI_API_KEY is set in the environment.
Falls back to deterministic mock responses when the key is absent,
so the pipeline always runs end-to-end even without a real API key.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Optional

from ..model_config import GPT_4O_MINI
from .llm_config import LLM_CONFIG, MODEL_ALIASES, DEFAULT_MAX_TOKENS

# In-memory cached choices for the running session so we don't prompt
# repeatedly.
_cached_provider: Optional[str] = None
_cached_api_keys: dict = {}
_cached_model: dict = {}

# Per-stage call metadata for the current run, keyed by stage name (e.g.
# "patch_generation", "patch_review", "challenger", "confidence_scorer").
# Populated as a side effect of call_llm(), mirroring _cached_provider /
# _cached_model above; read by main.py after the pipeline run completes.
_call_metadata: dict = {}


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
        OpenAI API key.  When *None* (or an empty string) the client
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
        """
        # Delegate to the convenience function so both interfaces behave the
        # same way (and so tests/code can call the simple `call_llm`).
        combined = system_prompt + "\n\n" + user_message
        return call_llm(combined, model=self.model, stage=stage)


def call_llm(prompt: str, model: str = GPT_4O_MINI, stage: str = "unknown") -> str:
    """Call an LLM and return a single text response.

    Provider resolution order:
    - `LLM_PROVIDER` env var if set
    - otherwise prompt the user to choose (OpenAI / Anthropic / Mock)

    API keys are read from environment vars (`OPENAI_API_KEY`,
    `ANTHROPIC_API_KEY`) or prompted interactively once per run and cached
    in-memory for the session.

    This function keeps behavior simple: no streaming, no retries, and a
    straightforward fallback to mock responses on any error.
    """

    global _cached_provider, _cached_api_keys, _cached_model

    # Resolve provider (cached)
    provider = _cached_provider or os.environ.get("LLM_PROVIDER")
    if not provider:
        # If running non-interactively (tests/CI), default to mock to avoid
        # blocking on stdin. Otherwise prompt the user once.
        if not sys.stdin.isatty():
            provider = "mock"
            _cached_provider = provider
        else:
            print("Select LLM provider:", file=sys.stderr)
            print("1) OpenAI", file=sys.stderr)
            print("2) Anthropic", file=sys.stderr)
            print("3) Mock", file=sys.stderr)
            choice = input("Choose (1/2/3): ").strip()
            provider = {"1": "openai", "2": "anthropic", "3": "mock"}.get(choice, "mock")
            _cached_provider = provider

    # Validate provider against configured providers to avoid unexpected
    # values (and to fail open to `mock` for safety).
    if isinstance(LLM_CONFIG, dict) and provider not in LLM_CONFIG:
        print(f"Unknown provider '{provider}' not configured. Falling back to mock", file=sys.stderr)
        provider = "mock"
        _cached_provider = provider

    # Resolve model (per-provider) using centralized config when available.
    env_model = os.environ.get("LLM_MODEL", "").strip()
    chosen_model = None

    # Helper to get provider config safely
    provider_cfg = LLM_CONFIG.get(provider, {}) if isinstance(LLM_CONFIG, dict) else {}
    available_models = list(provider_cfg.get("models", {}).keys())
    default_model = provider_cfg.get("default_model") if provider_cfg else None

    # If provider is mock, model selection is irrelevant
    if provider == "mock":
        model_to_use = None
    else:
        # 1) env override
        if env_model:
            # map aliases first
            mapped = MODEL_ALIASES.get(env_model, env_model) if isinstance(MODEL_ALIASES, dict) else env_model
            if available_models and mapped not in available_models:
                print(f"Invalid model '{env_model}' for {provider}. Falling back to default.", file=sys.stderr)
                chosen_model = default_model or model
            else:
                if mapped != env_model:
                    print(f"Mapping model name to latest version: {mapped}", file=sys.stderr)
                chosen_model = mapped
            _cached_model[provider] = chosen_model

        # 2) cached choice
        elif provider in _cached_model:
            chosen_model = _cached_model[provider]

        # 3) interactive menu or non-interactive default
        else:
            if not sys.stdin.isatty():
                chosen_model = default_model or model
                _cached_model[provider] = chosen_model
            else:
                # Build dynamic menu from config
                models_dict = provider_cfg.get("models", {})
                items = list(models_dict.items())
                print(f"Select {provider.capitalize()} model:", file=sys.stderr)
                for idx, (mname, meta) in enumerate(items, start=1):
                    label = meta.get("label") if isinstance(meta, dict) else ""
                    print(f"{idx}) {mname} ({label})", file=sys.stderr)
                choice = input(f"Choose (1-{len(items)}): ").strip()
                try:
                    sel = int(choice) - 1
                    chosen_model = items[sel][0]
                except Exception:
                    chosen_model = default_model or model
                _cached_model[provider] = chosen_model

        # Validate chosen model
        if chosen_model:
            # map legacy aliases
            if isinstance(MODEL_ALIASES, dict) and chosen_model in MODEL_ALIASES:
                mapped = MODEL_ALIASES[chosen_model]
                print(f"Mapping model name to latest version: {mapped}", file=sys.stderr)
                chosen_model = mapped
                _cached_model[provider] = chosen_model

            if available_models and chosen_model not in available_models:
                print(f"Invalid model for {provider}. Falling back to default.", file=sys.stderr)
                chosen_model = default_model or model
                _cached_model[provider] = chosen_model

        model_to_use = chosen_model or default_model or model

    # Helper to get API key either from env, cache, or prompt once
    def _get_api_key_for(p: str, env_name: str) -> Optional[str]:
        if p in _cached_api_keys:
            return _cached_api_keys[p]
        key = os.environ.get(env_name, "")
        if not key:
            try:
                key = input(f"Enter {env_name}: ").strip()
            except Exception:
                key = ""
        if key:
            _cached_api_keys[p] = key
        return key

    # Mock provider
    if provider == "mock":
        print("Using mock LLM", file=sys.stderr)
        _call_metadata[stage] = {
            "provider": "mock",
            "model": "mock",
            "max_tokens_configured": None,
            "stop_reason": "mock",
        }
        return _mock_response(prompt)

    resolved_max_tokens = _resolve_max_tokens()

    # OpenAI provider
    if provider == "openai":
        print(f"Using OpenAI (model: {model_to_use})", file=sys.stderr)
        api_key = _get_api_key_for("openai", "OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError(
                "LLM_PROVIDER=openai is configured but OPENAI_API_KEY is not set. "
                "Export the key or set LLM_PROVIDER=mock to use mock mode."
            )

        try:
            try:
                import openai  # type: ignore
            except ImportError as exc:
                print("OpenAI client library not installed:", exc, file=sys.stderr)
                raise

            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=model_to_use,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=resolved_max_tokens,
            )

            finish_reason = None
            try:
                finish_reason = getattr(response.choices[0], "finish_reason", None)
            except Exception:
                finish_reason = None
            _call_metadata[stage] = {
                "provider": "openai",
                "model": model_to_use,
                "max_tokens_configured": resolved_max_tokens,
                "stop_reason": finish_reason,
            }

            try:
                return response.choices[0].message.content or ""
            except Exception:
                return getattr(response.choices[0], "text", "") or ""

        except Exception as exc:
            raise RuntimeError(f"OpenAI API call failed: {exc}") from exc

    # Anthropic provider
    if provider == "anthropic":
        print(f"Using Anthropic (model: {model_to_use})", file=sys.stderr)
        api_key = _get_api_key_for("anthropic", "ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError(
                "LLM_PROVIDER=anthropic is configured but ANTHROPIC_API_KEY is not set. "
                "Export the key or set LLM_PROVIDER=mock to use mock mode."
            )

        try:
            try:
                from anthropic import Anthropic  # type: ignore
            except Exception as exc:
                print("Anthropic client library not installed:", exc, file=sys.stderr)
                raise

            client = Anthropic(api_key=api_key)
            response = client.messages.create(
                model=model_to_use or default_model,
                max_tokens=resolved_max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )

            stop_reason = None
            try:
                stop_reason = getattr(response, "stop_reason", None)
            except Exception:
                stop_reason = None
            _call_metadata[stage] = {
                "provider": "anthropic",
                "model": model_to_use or default_model,
                "max_tokens_configured": resolved_max_tokens,
                "stop_reason": stop_reason,
            }

            # Safely extract text from the Messages API response structure.
            text_out = ""
            try:
                if hasattr(response, "content") and response.content:
                    first = response.content[0]
                    text_out = getattr(first, "text", None) or getattr(first, "content", None) or ""
            except Exception:
                text_out = ""

            if not text_out:
                text_out = getattr(response, "completion", None) or getattr(response, "text", None) or ""

            return text_out or ""

        except Exception as exc:
            raise RuntimeError(f"Anthropic API call failed: {exc}") from exc

    # Unknown provider: fallback
    print(f"Unknown provider '{provider}' — falling back to mock", file=sys.stderr)
    print("Using mock LLM", file=sys.stderr)
    return _mock_response(prompt)
