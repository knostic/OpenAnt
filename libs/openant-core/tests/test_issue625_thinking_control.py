"""Regression tests for issue #625 — request-side thinking control, the
effective-policy record, and the dropped-block diagnostic.

#625 (an enhancement; no defect claimed in the default policy):
- ``utilities/llm/providers/anthropic.py`` exposed no ``thinking`` parameter
  although the SDK accepts one;
- the block translation dropped unsupported block kinds (thinking, refusal)
  from the delivered content while forwarding their usage — the delivered
  and billed content could differ by an invisible amount;
- the effective policy was invisible to comparisons and checkpoint
  decisions.

Contract pinned here (the instrument-change rule, #242: the DEFAULT is
unchanged — no thinking key in the request unless configured):
- config: ``llm_providers[name].thinking`` parses verbatim into
  ``ProviderConfig.thinking``; absent → ``None``;
- registry: ``build_adapter`` passes ``thinking`` to adapters that declare
  the kwarg, warns once per type for those that don't;
- AnthropicAdapter / BedrockAdapter: a configured policy lands in the
  request as ``thinking``; no policy → NO thinking key (byte-identical
  request to today's);
- the response translation counts dropped blocks per kind on
  ``CompletionResult.dropped_block_kinds`` (a COUNT, never a token split —
  usage cannot split thinking);
- ``fingerprint_for_binding`` folds a non-None thinking policy into the
  checkpoint KEY (a resumed run under a different policy must not adopt
  stale checkpoints), while a ``None`` policy leaves the digest unchanged
  (existing checkpoints survive the upgrade);
- ``binding_policy_summary`` exposes the effective policy for step reports
  ({"provider", "model", "thinking"}).
"""

from __future__ import annotations

import sys

import pytest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import anthropic  # noqa: E402

from utilities.llm import LLMResponseError, ToolDef  # noqa: E402
from utilities.llm.config import parse_config, ProviderConfig  # noqa: E402
from utilities.llm.providers.anthropic import (  # noqa: E402
    AnthropicAdapter,
    _response_to_unified,
)
from utilities.llm.providers.bedrock import BedrockAdapter  # noqa: E402


_THINKING = {"type": "enabled", "budget_tokens": 2048}


def _ok_response():
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text="hi")],
        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
        stop_reason="end_turn",
    )


def _thinking_response():
    return SimpleNamespace(
        content=[
            SimpleNamespace(type="thinking", thinking="…"),
            SimpleNamespace(type="thinking", thinking="…"),
            SimpleNamespace(type="redacted_thinking", data=b"xx"),
            SimpleNamespace(type="text", text="hi"),
        ],
        usage=SimpleNamespace(input_tokens=1, output_tokens=9),
        stop_reason="end_turn",
    )


def _stub_anthropic(**adapter_kwargs):
    client = MagicMock(spec=anthropic.Anthropic)
    client.messages = MagicMock()
    client.messages.create = MagicMock(side_effect=lambda **kw: _ok_response())
    return AnthropicAdapter(_client=client, **adapter_kwargs), client


def _stub_bedrock(**adapter_kwargs):
    client = MagicMock(spec=anthropic.AnthropicBedrock)
    client.messages = MagicMock()
    client.messages.create = MagicMock(side_effect=lambda **kw: _ok_response())
    return BedrockAdapter(_client=client, **adapter_kwargs), client


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------


def test_config_parses_thinking_verbatim():
    cfg = parse_config({"$schema_version": 2, "llm_providers": {
        "ant": {"type": "anthropic", "thinking": _THINKING}}})
    assert cfg.llm_providers["ant"].thinking == _THINKING


def test_config_thinking_absent_is_none():
    cfg = parse_config({"$schema_version": 2, "llm_providers": {
        "ant": {"type": "anthropic"}}})
    assert cfg.llm_providers["ant"].thinking is None


# ---------------------------------------------------------------------------
# Request-side control (the instrument rule: default unchanged)
# ---------------------------------------------------------------------------


def test_anthropic_configured_thinking_lands_in_request():
    adapter, client = _stub_anthropic(thinking=_THINKING)
    adapter.complete(model="claude-test", system=None,
                     messages=[], max_tokens=10)
    assert client.messages.create.call_args.kwargs["thinking"] == _THINKING


def test_anthropic_default_request_has_no_thinking_key():
    adapter, client = _stub_anthropic()
    adapter.complete(model="claude-test", system=None,
                     messages=[], max_tokens=10)
    assert "thinking" not in client.messages.create.call_args.kwargs


def test_bedrock_configured_thinking_lands_in_request():
    adapter, client = _stub_bedrock(thinking=_THINKING)
    adapter.complete(model="claude-test", system=None,
                     messages=[], max_tokens=10)
    assert client.messages.create.call_args.kwargs["thinking"] == _THINKING


def test_bedrock_default_request_has_no_thinking_key():
    adapter, client = _stub_bedrock()
    adapter.complete(model="claude-test", system=None,
                     messages=[], max_tokens=10)
    assert "thinking" not in client.messages.create.call_args.kwargs


# ---------------------------------------------------------------------------
# Registry threading + the unconsumed knob warning
# ---------------------------------------------------------------------------


def test_build_adapter_threads_thinking_to_declaring_adapter():
    from utilities.llm.registry import build_adapter
    provider = ProviderConfig(name="ant", type="anthropic", thinking=_THINKING)
    adapter = build_adapter(provider)
    assert adapter.thinking == _THINKING


def test_build_adapter_warns_on_non_consuming_type(capsys):
    from utilities.llm import registry as reg
    reg._unconsumed_thinking_warned.clear()
    # ollama constructs credential-free and declares no thinking kwarg
    provider = ProviderConfig(name="loc", type="ollama", thinking=_THINKING)
    adapter = reg.build_adapter(provider)
    err = capsys.readouterr().err
    assert "thinking" in err and "ollama" in err
    assert not getattr(adapter, "thinking", None)


# ---------------------------------------------------------------------------
# Dropped-block diagnostic (a count, not a token split)
# ---------------------------------------------------------------------------


def test_dropped_block_kinds_counted():
    result = _response_to_unified(_thinking_response())
    assert result.dropped_block_kinds == {"thinking": 2, "redacted_thinking": 1}
    assert result.input_tokens == 1 and result.output_tokens == 9


def test_no_drops_no_diagnostic():
    result = _response_to_unified(_ok_response())
    assert result.dropped_block_kinds is None


# ---------------------------------------------------------------------------
# Checkpoint identity + step-report policy summary
# ---------------------------------------------------------------------------


def test_fingerprint_folds_configured_thinking():
    from core.backend_identity import fingerprint_for_binding

    def binding(thinking):
        adapter = _stub_anthropic(thinking=thinking)[0]
        return SimpleNamespace(adapter=adapter, model="claude-test",
                               provider_name="ant", base_url=None,
                               phase="enhance")

    off = fingerprint_for_binding(binding(None), [])
    on = fingerprint_for_binding(binding(_THINKING), [])
    assert on["extra"]["thinking_policy"] == _THINKING
    assert off["key_digest"] != on["key_digest"]


def test_fingerprint_digest_unchanged_without_policy():
    from core.backend_identity import fingerprint_for_binding
    from utilities.llm.registry import build_adapter

    bare = ProviderConfig(name="ant", type="anthropic")
    binding = SimpleNamespace(adapter=build_adapter(bare), model="claude-test",
                              provider_name="ant", base_url=None,
                              phase="enhance")
    fp = fingerprint_for_binding(binding, [])
    # no extra at all when nothing folds — the KEY matches the pre-#625
    # shape (existing checkpoints survive the upgrade)
    assert "extra" not in fp


def test_binding_policy_summary_exposes_effective_policy():
    from utilities.llm.registry import build_phase_registry, binding_policy_summary
    from utilities.llm.config import parse_config

    cfg = parse_config({
        "$schema_version": 2,
        "llm_providers": {"ant": {"type": "anthropic", "thinking": _THINKING}},
        "llm_configs": {"c1": {p: {"provider": "ant", "model": "claude-test"}
                               for p in ("analyze", "enhance", "verify",
                                         "report", "dynamic_test",
                                         "llm_reach", "app_context")}},
    })
    registry = build_phase_registry(cfg, cfg.llm_configs["c1"])
    summary = binding_policy_summary(registry, "enhance")
    assert summary == {"provider": "ant", "model": "claude-test",
                       "thinking": _THINKING}


# ---------------------------------------------------------------------------
# T1 retro guard (2026-09-21): thinking + tools must fail loudly at build
# time — the loop echo filters thinking blocks from the echoed assistant
# turn, so a paid iteration-1 would be followed by an iteration-2 400.
# ---------------------------------------------------------------------------


def test_thinking_with_tools_refuses_loudly_before_the_paid_call():
    adapter, client = _stub_anthropic(thinking=_THINKING)
    with pytest.raises(LLMResponseError, match="thinking\\+tools"):
        adapter.complete(model="claude-test", system=None, messages=[],
                         max_tokens=10, tools=[ToolDef(
                             name="t", description="d", input_schema={})])
    client.messages.create.assert_not_called()


def test_disabled_thinking_with_tools_is_allowed():
    adapter, client = _stub_anthropic(thinking={"type": "disabled"})
    adapter.complete(model="claude-test", system=None, messages=[],
                     max_tokens=10, tools=[ToolDef(
                         name="t", description="d", input_schema={})])
    assert "thinking" in client.messages.create.call_args.kwargs


def test_thinking_without_tools_is_allowed():
    adapter, client = _stub_anthropic(thinking=_THINKING)
    adapter.complete(model="claude-test", system=None, messages=[],
                     max_tokens=10)
    assert client.messages.create.call_args.kwargs["thinking"] == _THINKING
