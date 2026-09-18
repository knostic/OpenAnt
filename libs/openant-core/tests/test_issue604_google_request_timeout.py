"""Regression tests for issue #604 — the Google adapter's requests carry
no I/O deadline (genai's default is explicitly ``timeout=None``), while the
five other adapters inherit their SDK's finite default (anthropic's
``Timeout(600, connect=5)`` family).

Contract locked here:
- the Google adapter gains a ``request_timeout`` knob (SECONDS), default 600
  — parity with the five SDK-finite adapters; ``None`` is the explicit
  unbounded opt-out (the SDK default, the pre-#604 behavior); ``<= 0`` is
  rejected unconditionally (a ``0`` would be SILENT-unbounded in genai:
  ``get_timeout_in_seconds`` is truthiness-guarded, and no
  X-Server-Timeout header is sent);
- the knob is threaded from config (``llm_providers[name].request_timeout``,
  SECONDS) via a capability check in ``build_adapter``: an adapter type that
  does not declare the kwarg gets a LOUD one-time warning, never a silent
  ignore;
- the config field round-trips (parse -> serialise -> reparse) and rejects
  non-int, boolean, and non-positive values loudly, naming the provider;
- a REAL transport read timeout fires when configured: an accept-and-HOLD
  listener (the #576 listener shapes, holding instead of closing) plus
  ``request_timeout=1`` must surface ``LLMConnectionError`` whose redacted
  message carries the timeout text — the timeout-vs-connect-REFUSED
  discrimination is message-based BY DESIGN (``redacted_cause_from`` never
  chains the raw SDK exception; the F2 redaction contract outranks test
  convenience; the connect leg to a listening loopback socket completes
  in-kernel, so a ConnectTimeout is unreachable in this shape).

Semantics documented alongside (see the adapter docstring): the value maps
to ``HttpOptions.timeout`` (MILLISECONDS) and bounds each transport
OPERATION (httpx connect/read/write/pool) — each read resets the read
timer, so a slow-drip response can outlast it; a fully-stalled request
times out at the configured value per attempt, with the SDK's own retry
layer (tenacity; httpx.TimeoutException is transient there) and the
pipeline's retry passes multiplying on top. genai also couples the client
timeout to an ``X-Server-Timeout: ceil(seconds)`` header — a server-directed
hint genai is alone in sending (the stainless SDKs disclose their client
timeouts in their own headers too — this one is an instruction to the
server, which is what the fingerprint surface grows by).
"""

from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.rate_limiter import reset_rate_limiter  # noqa: E402
from utilities.llm_client import reset_warning_state  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_state():
    reset_rate_limiter()
    reset_warning_state()
    yield
    reset_rate_limiter()
    reset_warning_state()


def _captured_client(monkeypatch):
    """Patch genai.Client to capture constructor kwargs (the round-5
    FakeClient precedent; the ``_client`` injection path returns BEFORE
    HttpOptions is built, so injection cannot observe it)."""
    from unittest.mock import MagicMock

    import utilities.llm.providers.google as gmod

    captured = {}

    class FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.models = MagicMock()

    monkeypatch.setattr(gmod.genai, "Client", FakeClient)
    return captured


def _adapter_cls():
    from utilities.llm.providers.google import GoogleAdapter
    return GoogleAdapter


def test_default_timeout_is_parity_600s(monkeypatch):
    """value-RED: no request_timeout -> HttpOptions.timeout == 600_000
    (master leaves the field None — the unbounded asymmetry this fixes)."""
    captured = _captured_client(monkeypatch)
    _adapter_cls()(api_key="k", max_retries=5)
    assert captured["http_options"].timeout == 600_000, (
        "the Google default must match the five SDK-finite adapters "
        "(600 s), not genai's unbounded None")


def test_explicit_none_keeps_sdk_unbounded(monkeypatch):
    """signature-RED on master (the new kwarg raises TypeError before any
    behavior); the HEAD pin: the explicit opt-out builds no timeout — the
    SDK default (unbounded) preserved."""
    captured = _captured_client(monkeypatch)
    _adapter_cls()(api_key="k", request_timeout=None)
    http_options = captured.get("http_options")
    assert not (http_options is not None and getattr(http_options, "timeout", None)), (
        "request_timeout=None must not set HttpOptions.timeout")


def test_constructor_rejects_nonpositive_even_with_injected_client():
    """signature-RED on master; a HEAD placement pin: the constructor's
    UNCONDITIONAL contract rejects ``<= 0``, bools, and non-ints — BEFORE
    the ``_client`` injection early-return (an injected caller passing 0
    must not slip the silent-unbounded trap; a ``True`` would silently
    become 1000 ms)."""
    from unittest.mock import MagicMock

    with pytest.raises(ValueError):
        _adapter_cls()(_client=MagicMock(), request_timeout=0)
    with pytest.raises(ValueError):
        _adapter_cls()(api_key="k", request_timeout=-5)
    # the full unconditional contract: bools and non-ints too (a ``True``
    # would silently become 1000 ms; a float defers to pydantic)
    with pytest.raises(ValueError):
        _adapter_cls()(api_key="k", request_timeout=True)
    with pytest.raises(ValueError):
        _adapter_cls()(api_key="k", request_timeout=1.5)
    with pytest.raises(ValueError):
        _adapter_cls()(api_key="k", request_timeout="600")


def test_config_threading_reaches_the_adapter(monkeypatch, capsys):
    """signature-RED on master (the field/kwarg do not exist); must-trip on
    HEAD: a google ProviderConfig(request_timeout=7) -> build_adapter ->
    HttpOptions.timeout == 7000 (seconds -> ms), AND the consuming path is
    SILENT (an implementation that both threads and warns must fail)."""
    from utilities.llm.config import ProviderConfig
    from utilities.llm.registry import build_adapter

    captured = _captured_client(monkeypatch)
    build_adapter(ProviderConfig(name="g", type="google",
                                  api_key="k", request_timeout=7))
    assert captured["http_options"].timeout == 7000, (
        "config SECONDS must convert to HttpOptions MILLISECONDS")
    assert capsys.readouterr().err == "", (
        "the consuming type + knob set must not warn")


def test_common_path_emits_no_warning(capsys, monkeypatch):
    """GUARD (green on master — master-existing surface only): the COMMON
    path (no knob set) is silent — the capability check's quiet leg (an
    over-eager warning implementation must fail here)."""
    from utilities.llm.config import ProviderConfig
    from utilities.llm.registry import build_adapter

    _captured_client(monkeypatch)
    build_adapter(ProviderConfig(name="g", type="google", api_key="k"))
    assert capsys.readouterr().err == "", (
        "no request_timeout configured — the capability check must be silent")


def test_unconsumed_knob_warns_once(capsys):
    """feature-RED: a provider type that does not declare the kwarg gets a
    LOUD one-time warning naming the type — never a silent ignore; and the
    FIRST emission is observable (not merely absence of duplicates)."""
    from utilities.llm.config import ProviderConfig
    from utilities.llm.registry import build_adapter

    build_adapter(ProviderConfig(name="a", type="anthropic",
                                 api_key="k", request_timeout=7))
    out1 = capsys.readouterr().err
    assert "request_timeout" in out1 and "anthropic" in out1, (
        "the unconsumed knob must warn loudly, naming the provider type")
    # one-time PER TYPE: the second build of the SAME type emits nothing
    build_adapter(ProviderConfig(name="a2", type="anthropic",
                                 api_key="k", request_timeout=9))
    out2 = capsys.readouterr().err
    assert out2 == "", "the warning is one-time per type, not per-build"
    # a DIFFERENT unconsuming type still warns (the per-type keying)
    build_adapter(ProviderConfig(name="o", type="openai",
                                 api_key="k", request_timeout=7))
    out3 = capsys.readouterr().err
    assert "openai" in out3, (
        "a second unconsuming type must warn (per-type keying, not a "
        "global flag)")
    # and reset_warning_state re-arms the warning (the autouse fixtures
    # depend on this wiring)
    reset_warning_state()
    build_adapter(ProviderConfig(name="a3", type="anthropic",
                                 api_key="k", request_timeout=7))
    out4 = capsys.readouterr().err
    assert "anthropic" in out4, "reset_warning_state must re-arm the warning"


def test_config_parses_serialises_and_reparses(tmp_path):
    """value-RED: master's parser reads only type/api_key/base_url (a set
    request_timeout is SILENTLY ignored); the field must survive the full
    parse -> serialise -> reparse cycle with explicit per-leg asserts."""
    from utilities.llm.config import parse_config

    from utilities.llm.registry import PHASES
    raw = {
        "$schema_version": 2,
        "llm_providers": {"g": {"type": "google", "api_key": "k",
                                 "request_timeout": 7}},
        "llm_configs": {"c": {
            p: {"provider": "g", "model": "m"} for p in PHASES}},
    }
    cfg = parse_config(json.loads(json.dumps(raw)))
    assert cfg.llm_providers["g"].request_timeout == 7
    from utilities.llm.config import serialise_config
    entry = serialise_config(cfg)["llm_providers"]["g"]
    assert entry["request_timeout"] == 7, (
        "_serialise_provider must emit the knob (no silent drops)")
    reparsed = parse_config(json.loads(json.dumps(serialise_config(cfg))))
    assert reparsed.llm_providers["g"].request_timeout == 7


@pytest.mark.parametrize("bad", [True, 7.5, 0, -1, "7"])
def test_config_rejects_invalid_values(bad):
    """value-RED: master silently ignores the key entirely; the load must
    reject non-int/boolean/non-positive values LOUDLY, naming the provider
    AND the knob (a JSON ``true`` would pass isinstance(x, int) — bools
    are rejected explicitly; the message must name request_timeout so an
    unrelated ConfigError cannot vacuously satisfy the expectation)."""
    from utilities.llm.config import ConfigError, parse_config

    from utilities.llm.registry import PHASES
    raw = {
        "$schema_version": 2,
        "llm_providers": {"my-google-1": {"type": "google", "api_key": "k",
                                 "request_timeout": bad}},
        "llm_configs": {"c": {
            p: {"provider": "my-google-1", "model": "m"} for p in PHASES}},
    }
    with pytest.raises(ConfigError) as excinfo:
        parse_config(json.loads(json.dumps(raw)))
    msg = str(excinfo.value)
    assert "request_timeout" in msg, (
        "the error must name the knob (a generic ConfigError is a vacuous "
        f"pass): {msg}")
    assert "my-google-1" in msg, "the error must name the provider"


def test_real_transport_read_timeout_fires():
    """signature-RED on master (the kwarg raises TypeError before any
    transport); the HEAD must-trip receipt: a REAL held connection (accept,
    never respond) with request_timeout=1, max_retries=0 surfaces
    LLMConnectionError whose REDACTED message carries the timeout text —
    the read-vs-connect discrimination is message-based (the raw httpx
    cause is never chained: redacted_cause_from is the F2 contract and
    outranks test convenience). Bounded: a join() wall-clock guard + a
    finally teardown — CI never hangs, master never blocks."""
    from utilities.llm import Message, TextBlock

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    held = []

    def accept_and_hold():
        # accept the connection, never respond — the READ times out
        # (a refused/closed conn would be a connect/protocol failure
        # instead, which is the discrimination this test pins)
        try:
            conn, _ = listener.accept()
            held.append(conn)
        except OSError:
            return

    t = threading.Thread(target=accept_and_hold, daemon=True)
    t.start()
    outcome = {}

    def drive():
        try:
            adapter = _adapter_cls()(api_key="test-key",
                                     base_url=f"http://127.0.0.1:{port}",
                                     max_retries=0, request_timeout=1)
            adapter.complete(model="m", system=None, max_tokens=8,
                             messages=[Message(role="user",
                                              content=[TextBlock("hi")])])
            outcome["result"] = "no-exception"
        except Exception as exc:  # the adapter's own typed raise
            outcome["exc"] = exc

    try:
        worker = threading.Thread(target=drive, daemon=True)
        worker.start()
        worker.join(10)
        assert not worker.is_alive(), (
            "the request never completed — no read deadline fired")
        assert "exc" in outcome, f"expected a typed error, got {outcome}"
        exc = outcome["exc"]
        from utilities.llm.adapter import LLMConnectionError
        from utilities.llm._redact import RedactedCause
        assert isinstance(exc, LLMConnectionError), (
            f"a transport timeout must map to LLMConnectionError, got {exc!r}")
        assert "timed out" in str(exc).lower(), (
            "the redacted message must carry the read-timeout text "
            f"(discrimination vs connect-refused), got: {exc}")
            # NOTE (#604 review): the substring is CPython's socket error
            # text surfaced via httpcore → httpx → the redacted message —
            # an implementation-detail dependency the F2 redaction contract
            # forces (the raw exception is never chained); a runner whose
            # httpcore words differ breaks HERE, not silently.
        assert isinstance(exc.__cause__, RedactedCause), (
            "the transport clause must keep redacted_cause_from (the F2 "
            "contract) — the raw httpx exception is never chained")
    finally:
        for conn in held:
            try:
                conn.close()
            except OSError:
                pass
        listener.close()
