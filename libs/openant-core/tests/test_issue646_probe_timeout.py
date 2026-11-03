"""#646 — the registry's startup probes carry no per-request timeout: with
#604's 600 s adapter default and max_retries=5, a black-holed
``registry.validate()`` probe (run at every scan start and at the head of
every standalone LLM verb, once per (provider, model) pair) fails after
~61 minutes worst case, not 600 s — the probe is a cheap 1-token
liveness check, not a full request, and the Go wizard's probe already
anchors the right number at 15 s (``llm_probe_google.go``:
``http.Client{Timeout: 15 * time.Second}``).

THE RULING (the issue's direction — a tighter per-request timeout on the
probe path ONLY, never the adapter's request-level default): each of the
six adapters' ``validate()`` gains a ``PROBE_TIMEOUT_SECONDS = 15`` class
constant, applied per-request — anthropic/bedrock
``messages.create(timeout=...)``, openai/openrouter/ollama
``chat.completions.create / responses.create (timeout=...)``, google's
``GenerateContentConfig(http_options=HttpOptions(timeout=15_000))`` (the
per-request field-wise is-not-None merge with the client's — the opus-r1
wire probe: PROBE 15.0 s vs REQUEST 600.0 s) — so a black-holed probe
fails in ~104 s worst case (the client's 6-attempt retry, the wire
measurement; google ~124 s — the SDK retries TimeoutException too)
instead of tens of minutes, and the request path's 600 s default is
untouched. The /responses probe's output budget is 16 tokens (the
opus-r1 catch: a healthy gpt-5 reasoning response must not outlive the
15 s read deadline — 16 is OpenAI's own documented floor for the
parameter). Ollama's probe IS a remote chat.completions POST (the
constructor performs no network I/O — the opus-r1 wire measurement: the
unbounded shape was ~30 min; the Go wizard bounds it too:
llm_probe_openai.go: probeClientTimeout = 15 s).

Nodes (every witness drives the REAL adapter validate() with a stubbed
SDK client):
  S1 -- anthropic: the probe call carries timeout=15 (base: no timeout
        kwarg — the ~61-minute shape).
  S2 -- openai (chat): the probe call carries timeout=15.
  S3 -- openai (responses): the probe call carries timeout=15.
  S4 -- google: the probe call carries GenerateContentConfig(http_options
        with timeout=15_000 MILLISECONDS).
  S5 -- openrouter: the probe call carries timeout=15.
  S6 -- bedrock: the probe call carries timeout=15.
  C1 -- the request path unchanged: complete() carries NO timeout kwarg
        (the 600 s client default rules; base-green).
  C2 -- the Go anchor parity: the probe timeout constant is 15 (the
        llm_probe_google.go anchor; base-green).
  S7 -- the ollama probe wired (the opus-r1 catch: it IS a remote
        POST, the Go wizard bounds it too).
  S8 -- the /responses probe budget 16, not 1000 (the opus-r1 catch:
        a healthy reasoning response must not outlive the probe).
  C2 -- the Go anchor parity (base-green).
"""

import sys
from pathlib import Path

CORE = Path(__file__).resolve().parents[1]
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))


def test_anthropic_probe_carries_timeout():
    """S1: the anthropic validate() probe names timeout=15 in its
    messages.create call (base: no timeout kwarg — the probe rides the
    600 s client default x 5 retries)."""
    from utilities.llm.providers.anthropic import PROBE_TIMEOUT_SECONDS as _pt  # the witness screen
    assert _pt == 15

    from utilities.llm.providers import anthropic as anth
    assert anth.PROBE_TIMEOUT_SECONDS == 15
    calls = {}
    class _Msgs:
        def create(self, **kwargs):
            calls.update(kwargs)
            class _R: pass
            return _R()
    class _Client:
        messages = _Msgs()
    a = anth.AnthropicAdapter.__new__(anth.AnthropicAdapter)
    a._client = _Client()
    a.validate("claude-sonnet-5")
    assert calls.get("timeout") == 15, (
        f"the anthropic probe's timeout kwarg: {calls!r}")


def test_openai_chat_probe_carries_timeout():
    """S2: the openai validate() chat-completions probe names
    timeout=15."""
    from utilities.llm.providers.openai import PROBE_TIMEOUT_SECONDS as _pt  # the witness screen
    assert _pt == 15

    from utilities.llm.providers import openai as oai
    assert oai.PROBE_TIMEOUT_SECONDS == 15
    calls = {}
    class _Chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                calls.update(kwargs)
                class _R: pass
                return _R()
    class _Client:
        chat = _Chat()
    a = oai.OpenAIAdapter.__new__(oai.OpenAIAdapter)
    a._client = _Client()
    a._use_responses_api_override = None
    a._reasoning_effort = "low"
    a.validate("gpt-4o")
    assert calls.get("timeout") == 15, (
        f"the openai chat probe's timeout kwarg: {calls!r}")


def test_openai_responses_probe_carries_timeout():
    """S3: the openai validate() /responses probe names timeout=15 (the
    gpt-5-class endpoint)."""
    from utilities.llm.providers.openai import PROBE_TIMEOUT_SECONDS as _pt  # the witness screen
    assert _pt == 15

    from utilities.llm.providers import openai as oai
    calls = {}
    class _Responses:
        @staticmethod
        def create(**kwargs):
            calls.update(kwargs)
            class _R: pass
            return _R()
    class _Client:
        responses = _Responses()
    a = oai.OpenAIAdapter.__new__(oai.OpenAIAdapter)
    a._client = _Client()
    a._use_responses_api_override = True
    a._reasoning_effort = "low"
    a.validate("gpt-5")
    assert calls.get("timeout") == 15, (
        f"the openai responses probe's timeout kwarg: {calls!r}")


def test_google_probe_carries_per_request_timeout():
    """S4: the google validate() probe carries the per-request
    GenerateContentConfig(http_options=HttpOptions(timeout=15_000))
    — the per-request field-wise is-not-None merge with the client's
    handling; base: no http_options in the probe's config."""
    from utilities.llm.providers.google import PROBE_TIMEOUT_SECONDS as _pt  # the witness screen
    assert _pt == 15

    from utilities.llm.providers import google as goog
    assert goog.PROBE_TIMEOUT_SECONDS == 15
    calls = {}
    class _Models:
        @staticmethod
        def generate_content(**kwargs):
            calls.update(kwargs)
            class _R: pass
            return _R()
    class _Client:
        models = _Models()
    a = goog.GoogleAdapter.__new__(goog.GoogleAdapter)
    a._client = _Client()
    a.validate("gemini-2.5-pro")
    cfg = calls.get("config")
    assert cfg is not None, f"no config in the probe call: {calls!r}"
    ho = getattr(cfg, "http_options", None)
    assert ho is not None and getattr(ho, "timeout", None) == 15_000, (
        f"the google probe's http_options.timeout (ms): {ho!r}")


def test_openrouter_probe_carries_timeout():
    """S5: the openrouter validate() probe names timeout=15."""
    from utilities.llm.providers.openrouter import PROBE_TIMEOUT_SECONDS as _pt  # the witness screen
    assert _pt == 15

    from utilities.llm.providers import openrouter as orr
    assert orr.PROBE_TIMEOUT_SECONDS == 15
    calls = {}
    class _Chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                calls.update(kwargs)
                class _R: pass
                return _R()
    class _Client:
        chat = _Chat()
    a = orr.OpenRouterAdapter.__new__(orr.OpenRouterAdapter)
    a._client = _Client()
    a.validate("anthropic/claude-sonnet-5")
    assert calls.get("timeout") == 15, (
        f"the openrouter probe's timeout kwarg: {calls!r}")


def test_bedrock_probe_carries_timeout():
    """S6: the bedrock validate() probe names timeout=15 (the shared
    Anthropic SDK shape)."""
    from utilities.llm.providers.bedrock import PROBE_TIMEOUT_SECONDS as _pt  # the witness screen
    assert _pt == 15

    from utilities.llm.providers import bedrock as bd
    assert bd.PROBE_TIMEOUT_SECONDS == 15
    calls = {}
    class _Msgs:
        def create(self, **kwargs):
            calls.update(kwargs)
            class _R: pass
            return _R()
    class _Client:
        messages = _Msgs()
    a = bd.BedrockAdapter.__new__(bd.BedrockAdapter)
    a._client = _Client()
    a.validate("us.anthropic.claude-sonnet-4-6")
    assert calls.get("timeout") == 15, (
        f"the bedrock probe's timeout kwarg: {calls!r}")


def test_request_path_untouched():
    """C1: the request path carries NO per-request timeout — the 600 s
    client default rules the complete() calls (base-green; the probe knob
    must not leak into the request path)."""
    import inspect
    from utilities.llm.providers import anthropic as anth
    src = inspect.getsource(anth.AnthropicAdapter.complete)
    assert "timeout=" not in src, (
        "the request path gained a per-request timeout — the probe knob "
        "leaked")


def test_probe_timeout_is_the_go_anchor():
    """C2: the anchor parity — the Go wizard's probe uses 15 s
    (llm_probe_google.go: http.Client{Timeout: 15 * time.Second}); the
    Python adapters' PROBE_TIMEOUT_SECONDS matches (base-green)."""
    import re
    from pathlib import Path
    go_src = (Path(__file__).resolve().parents[3]
              / "apps" / "openant-cli" / "cmd" / "llm_probe_google.go")
    if not go_src.exists():
        import pytest
        pytest.skip("the Go source not present in this checkout")
    text = go_src.read_text()
    m = re.search(r"Timeout:\s*(\d+)\s*\*\s*time\.Second", text)
    assert m and int(m.group(1)) == 15, (
        f"the Go anchor moved: {text[:200]!r}")
    from utilities.llm.providers import anthropic as anth
    assert anth.PROBE_TIMEOUT_SECONDS == int(m.group(1))


def test_ollama_probe_carries_timeout():
    """S7 (the opus-r1 catch): the ollama validate() IS a remote
    chat.completions.create POST (the constructor does no network I/O) —
    its probe carries timeout=15 like every other adapter. At base the
    probe rides the 600 s client default x the SDK's 2 retries ≈ 30 min
    (the opus wire measurement); the Go wizard DOES bound the Ollama
    probe (llm_probe_openai.go: probeClientTimeout = 15 s)."""
    # the prod-hunk symbol LOADED IN THE BODY (the witness screen)
    from utilities.llm.providers.ollama import PROBE_TIMEOUT_SECONDS as _olpt
    assert _olpt == 15
    from utilities.llm.providers import ollama as ol
    assert ol.PROBE_TIMEOUT_SECONDS == 15
    calls = {}
    class _Chat:
        class completions:
            @staticmethod
            def create(**kwargs):
                calls.update(kwargs)
                class _C: pass
                c = _C()
                class _M: content = "ok"
                class _Msg: message = _M()
                class _Ch: message = _Msg()
                c.choices = [_Ch()]
                return c
    class _Client:
        chat = _Chat()
    a = ol.OllamaAdapter.__new__(ol.OllamaAdapter)
    a._client = _Client()
    a.base_url = "http://localhost:11434/v1"
    a.validate("qwen3.8:27b")
    assert calls.get("timeout") == 15, (
        f"the ollama probe's timeout kwarg: {calls!r}")


def test_responses_probe_budget_matches_its_description():
    """S8 (the opus-r1 catch): the /responses probe's output budget is 16
    tokens, not 1000 — the pre-#646 1000-token budget let hidden reasoning
    burn the whole budget; under the 15 s probe deadline a HEALTHY gpt-5
    reasoning response would outlive the read timeout and the probe would
    convert a hang into a startup FAILURE on working providers. 16
    tokens: the effort kwarg is still sent (a rejected effort must fail
    fast), but the budget cannot consume a 15 s window."""
    import inspect
    # the prod-hunk CLASS loaded in the body (the witness screen; it
    # EXISTS at base so the import succeeds — the witness is
    # ASSERTION-RED at base via the behavior assert, never a KeyError)
    from utilities.llm.providers.openai import OpenAIAdapter
    src = inspect.getsource(OpenAIAdapter.validate)
    assert "max_output_tokens=16" in src, (
        "the /responses probe's budget must be 16 (the liveness-check "
        "description), not the 1000-token reasoning budget")
    assert "reasoning={" in src, (
        "the effort kwarg must still be sent (a rejected effort fails fast)")
    assert "timeout=PROBE_TIMEOUT_SECONDS" in src, (
        "the probe must carry the tight deadline")
