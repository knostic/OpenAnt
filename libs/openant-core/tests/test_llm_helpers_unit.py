"""Unit tests for the small helpers around the adapter layer.

Covers:

* :func:`utilities.llm.lookup_pricing` — the indirection that lets
  adapter-owned pricing replace the legacy global ``MODEL_PRICING``
  table (issue #65 §9). The contract: an adapter without a pricing
  attribute returns ``None``; an adapter with pricing but no entry
  for the requested model returns ``None``; an adapter with a hit
  returns the entry. ``None`` is what callers translate into the
  "unknown model, cost reported as $0" warning.

* :func:`utilities.llm.probe_registry_or_raise` — the stderr-preamble
  wrapper around ``PhaseRegistry.validate``. Two contracts: re-raise
  the underlying :class:`LLMError` unchanged so callers higher up
  decide handling, and emit a deterministic preamble naming the
  llm-config and exception type so the user knows *which* config
  failed and *why*.

* Regression test for the H2 finding from the issue #65 PR review:
  ``core.reporter._record_usage_in_tracker`` must record against the
  report-phase binding's model and the adapter's pricing — NOT the
  pre-refactor hardcoded ``"claude-opus-4-6"`` with no pricing
  override. A regression here would lie about cost on every
  non-Anthropic / non-opus report configuration.
"""

from __future__ import annotations

from typing import Optional

import pytest

from utilities.llm import (
    CompletionResult,
    LLMAuthError,
    LLMConnectionError,
    LLMError,
    LLMNotFoundError,
    PhaseBinding,
    PhaseRegistry,
    TextBlock,
    lookup_pricing,
    probe_registry_or_raise,
)
from utilities.llm_client import TokenTracker


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _AdapterWithPricing:
    name = "anthropic"
    supports_tools = True
    pricing = {
        "claude-opus-4-6": {"input": 15.00, "output": 75.00},
        "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    }

    def complete(self, *, model, system, messages, max_tokens, tools=None):  # pragma: no cover - unused
        raise NotImplementedError

    def validate(self, model):
        pass


class _AdapterWithoutPricing:
    """Conformant adapter that simply omits the optional pricing attr.

    Per issue #65, ``pricing`` is NOT Protocol-enforced — a provider
    plugin is allowed to ship without rates and report $0 instead of
    guessing them. ``lookup_pricing`` must handle the missing-attr case
    cleanly.
    """

    name = "byo-provider"
    supports_tools = False

    def complete(self, *, model, system, messages, max_tokens, tools=None):  # pragma: no cover - unused
        raise NotImplementedError

    def validate(self, model):
        pass


def _binding(adapter, *, model: str = "claude-opus-4-6", phase: str = "report"):
    return PhaseBinding(
        phase=phase,
        adapter=adapter,
        model=model,
        provider_name="anthropic",
    )


# ---------------------------------------------------------------------------
# lookup_pricing
# ---------------------------------------------------------------------------


class TestLookupPricing:
    def test_known_model_returns_pricing_dict(self):
        out = lookup_pricing(_binding(_AdapterWithPricing(), model="claude-opus-4-6"))
        assert out == {"input": 15.00, "output": 75.00}

    def test_unknown_model_on_pricing_adapter_returns_none(self):
        out = lookup_pricing(_binding(_AdapterWithPricing(), model="claude-future-7"))
        assert out is None

    def test_adapter_without_pricing_attr_returns_none(self):
        # Issue #65 §9: omitting `pricing` is conformant. ``getattr``
        # must default cleanly to ``{}`` so the lookup falls through
        # to ``None`` rather than raising ``AttributeError`` and
        # taking the whole call site down.
        out = lookup_pricing(_binding(_AdapterWithoutPricing(), model="anything"))
        assert out is None

    def test_works_for_any_phase_value(self):
        # PhaseBinding.phase is metadata only — lookup keys on
        # adapter+model, not on which phase asked.
        for phase in ("analyze", "verify", "report", "app_context"):
            out = lookup_pricing(
                _binding(_AdapterWithPricing(), model="claude-opus-4-6", phase=phase)
            )
            assert out == {"input": 15.00, "output": 75.00}, (
                f"lookup_pricing should be phase-agnostic; failed for {phase!r}"
            )


# ---------------------------------------------------------------------------
# probe_registry_or_raise
# ---------------------------------------------------------------------------


class _ScriptedValidateAdapter:
    """Adapter whose ``validate()`` raises a scripted exception."""

    name = "anthropic"
    supports_tools = True

    def __init__(self, exc: Optional[Exception] = None):
        self._exc = exc
        self.validate_calls: list[str] = []

    def complete(self, *, model, system, messages, max_tokens, tools=None):  # pragma: no cover - unused
        raise NotImplementedError

    def validate(self, model):
        self.validate_calls.append(model)
        if self._exc is not None:
            raise self._exc


def _registry_with(adapter, *, config_name: str = "my-config") -> PhaseRegistry:
    """One-binding PhaseRegistry that puts every phase on ``adapter``.

    ``probe_registry_or_raise`` only inspects ``registry.config_name``
    and calls ``registry.validate()`` — a single binding is enough to
    exercise the wrapper.
    """
    binding = PhaseBinding(
        phase="analyze",
        adapter=adapter,
        model="claude-opus-4-6",
        provider_name="anthropic",
    )
    return PhaseRegistry(bindings={"analyze": binding}, config_name=config_name)


class TestProbeRegistryOrRaise:
    def test_success_prints_nothing(self, capsys):
        registry = _registry_with(_ScriptedValidateAdapter(exc=None))

        probe_registry_or_raise(registry)

        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_reraises_llm_error_unchanged(self, capsys):
        original = LLMAuthError("bad key")
        registry = _registry_with(_ScriptedValidateAdapter(exc=original))

        with pytest.raises(LLMAuthError) as exc_info:
            probe_registry_or_raise(registry)

        # The SAME exception instance must be re-raised — higher-up
        # handlers may inspect type, args, or attributes (e.g.
        # ``retry_after`` on rate-limit errors).
        assert exc_info.value is original

    def test_preamble_names_config_and_exception_type(self, capsys):
        registry = _registry_with(
            _ScriptedValidateAdapter(exc=LLMConnectionError("DNS lookup failed")),
            config_name="my-team-config",
        )

        with pytest.raises(LLMConnectionError):
            probe_registry_or_raise(registry)

        err = capsys.readouterr().err
        assert "my-team-config" in err, (
            "preamble must name the failing llm-config so the user "
            "knows which one to inspect"
        )
        assert "LLMConnectionError" in err, (
            "preamble must name the exception class so the user can "
            "tell auth from network from 404 without reading code"
        )
        assert "DNS lookup failed" in err, (
            "preamble must include the underlying message"
        )

    def test_preamble_starts_with_validation_marker(self, capsys):
        # The exact prefix is part of the user-facing contract — a
        # CHANGELOG-worthy change. Pinning it here so a future refactor
        # that re-words the message has to think twice.
        registry = _registry_with(
            _ScriptedValidateAdapter(exc=LLMNotFoundError("no such model")),
            config_name="some-config",
        )
        with pytest.raises(LLMNotFoundError):
            probe_registry_or_raise(registry)
        err = capsys.readouterr().err
        assert err.startswith("llm-config 'some-config' failed validation:")

    def test_non_llm_error_propagates_without_preamble(self, capsys):
        # ``probe_registry_or_raise`` only owns the LLMError envelope.
        # An unexpected ``RuntimeError`` (programmer bug) must surface
        # as-is with no friendly preamble, because the preamble would
        # mis-attribute the bug to the user's config.
        registry = _registry_with(
            _ScriptedValidateAdapter(exc=RuntimeError("oops"))
        )
        with pytest.raises(RuntimeError):
            probe_registry_or_raise(registry)
        assert "failed validation" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# H2 regression — reporter._record_usage_in_tracker uses binding, not opus
# ---------------------------------------------------------------------------


class TestReporterUsageRecording:
    """Regression test for the PR-review HIGH finding H2.

    ``core/reporter.py:_record_usage_in_tracker`` previously hardcoded
    ``model="claude-opus-4-6"`` and never passed pricing through. The
    result: every non-opus report-phase configuration produced wrong
    cost numbers in the scan footer AND the step report JSON. The fix
    threads the report binding through; this test pins it.
    """

    def test_records_against_binding_model_not_hardcoded_opus(self):
        from utilities.llm_client import reset_global_tracker, get_global_tracker
        from core.reporter import _record_usage_in_tracker

        reset_global_tracker()

        adapter = _AdapterWithPricing()
        binding = PhaseBinding(
            phase="report",
            adapter=adapter,
            model="claude-sonnet-4-20250514",
            provider_name="anthropic",
        )
        usage = {"input_tokens": 1000, "output_tokens": 500, "total_tokens": 1500}

        _record_usage_in_tracker(usage, binding)

        tracker = get_global_tracker()
        summary = tracker.get_summary()
        assert len(summary["calls"]) == 1
        recorded = summary["calls"][0]
        # The recorded model is the binding's, NOT the pre-refactor
        # hardcoded "claude-opus-4-6".
        assert recorded["model"] == "claude-sonnet-4-20250514"
        # And the recorded cost reflects Sonnet rates, not Opus —
        # which is the user-facing impact of getting this wrong.
        expected_cost = (1000 / 1_000_000) * 3.0 + (500 / 1_000_000) * 15.0
        assert recorded["cost_usd"] == pytest.approx(expected_cost, rel=1e-9)

        reset_global_tracker()

    def test_skips_recording_when_no_tokens(self):
        from utilities.llm_client import reset_global_tracker, get_global_tracker
        from core.reporter import _record_usage_in_tracker

        reset_global_tracker()

        adapter = _AdapterWithPricing()
        binding = PhaseBinding(
            phase="report",
            adapter=adapter,
            model="claude-opus-4-6",
            provider_name="anthropic",
        )
        # No tokens: function early-returns without touching the tracker.
        _record_usage_in_tracker(
            {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            binding,
        )

        tracker = get_global_tracker()
        assert tracker.get_summary()["calls"] == []

        reset_global_tracker()
