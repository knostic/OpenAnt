"""Tests for utilities.autopatcher.technical_capacity -- Fix B's per-call
source-evidence capacity equation:

    available_input_tokens = total_context_tokens - reserved_output_tokens - SAFETY_MARGIN_TOKENS
    available_input_chars  = available_input_tokens * CONSERVATIVE_CHARS_PER_TOKEN
    source_capacity_chars  = available_input_chars - known_overhead_chars

See technical_capacity.py's own module docstring for why this replaces the
arbitrary stage-local character constants, and why the token<->char ratio
is the ONE approximation in the whole computation.
"""

from __future__ import annotations

from unittest import mock

import pytest


def _capacity(**kwargs):
    from utilities.autopatcher.technical_capacity import compute_source_capacity
    defaults = dict(provider=None, model=None, reserved_output_tokens=0, known_overhead_chars=0)
    defaults.update(kwargs)
    return compute_source_capacity(
        defaults.pop("provider"), defaults.pop("model"), **defaults,
    )


class TestConservativeFallback:
    def test_no_provider_or_model_uses_conservative_fallback(self):
        from utilities.autopatcher.technical_capacity import (
            CAPACITY_SOURCE_CONSERVATIVE_FALLBACK, CONSERVATIVE_FALLBACK_CONTEXT_WINDOW_TOKENS,
        )
        result = _capacity(provider=None, model=None)
        assert result.capacity_source == CAPACITY_SOURCE_CONSERVATIVE_FALLBACK
        assert result.context_window_tokens == CONSERVATIVE_FALLBACK_CONTEXT_WINDOW_TOKENS

    def test_unknown_model_in_registry_also_falls_back(self):
        from utilities.autopatcher.technical_capacity import CAPACITY_SOURCE_CONSERVATIVE_FALLBACK
        result = _capacity(provider="anthropic", model="totally-made-up-model-xyz")
        assert result.capacity_source == CAPACITY_SOURCE_CONSERVATIVE_FALLBACK

    def test_fallback_is_the_same_constant_regardless_of_stage_or_provider(self):
        """A missing capacity fact must never silently produce a different
        guess in different places."""
        a = _capacity(provider=None, model=None, known_overhead_chars=100)
        b = _capacity(provider="openai", model="nonexistent", known_overhead_chars=100)
        assert a.context_window_tokens == b.context_window_tokens


class TestModelRegistrySource:
    def test_real_registry_value_is_used_when_present(self):
        from utilities.autopatcher.technical_capacity import CAPACITY_SOURCE_MODEL_REGISTRY
        with mock.patch(
            "utilities.autopatcher.technical_capacity._registry_context_window_tokens",
            return_value=200_000,
        ):
            result = _capacity(provider="anthropic", model="claude-sonnet-5")
        assert result.capacity_source == CAPACITY_SOURCE_MODEL_REGISTRY
        assert result.context_window_tokens == 200_000


class TestEquationArithmetic:
    def test_exact_arithmetic_matches_the_documented_equation(self):
        from utilities.autopatcher.technical_capacity import CONSERVATIVE_CHARS_PER_TOKEN, SAFETY_MARGIN_TOKENS
        with mock.patch(
            "utilities.autopatcher.technical_capacity._registry_context_window_tokens",
            return_value=100_000,
        ):
            result = _capacity(
                provider="anthropic", model="x", reserved_output_tokens=4_000, known_overhead_chars=1_000,
            )
        available_input_tokens = 100_000 - 4_000 - SAFETY_MARGIN_TOKENS
        expected = int(available_input_tokens * CONSERVATIVE_CHARS_PER_TOKEN) - 1_000
        assert result.source_capacity_chars == expected

    def test_reserved_output_tokens_reduces_available_capacity(self):
        with mock.patch(
            "utilities.autopatcher.technical_capacity._registry_context_window_tokens",
            return_value=100_000,
        ):
            small_reserve = _capacity(provider="p", model="m", reserved_output_tokens=1_000)
            large_reserve = _capacity(provider="p", model="m", reserved_output_tokens=50_000)
        assert large_reserve.source_capacity_chars < small_reserve.source_capacity_chars

    def test_known_overhead_chars_reduces_available_capacity(self):
        with mock.patch(
            "utilities.autopatcher.technical_capacity._registry_context_window_tokens",
            return_value=100_000,
        ):
            no_overhead = _capacity(provider="p", model="m", known_overhead_chars=0)
            with_overhead = _capacity(provider="p", model="m", known_overhead_chars=20_000)
        assert with_overhead.source_capacity_chars < no_overhead.source_capacity_chars
        assert no_overhead.source_capacity_chars - with_overhead.source_capacity_chars == 20_000

    def test_safety_margin_is_applied(self):
        from utilities.autopatcher.technical_capacity import SAFETY_MARGIN_TOKENS
        assert SAFETY_MARGIN_TOKENS > 0
        with mock.patch(
            "utilities.autopatcher.technical_capacity._registry_context_window_tokens",
            return_value=SAFETY_MARGIN_TOKENS,  # total capacity == exactly the safety margin
        ):
            result = _capacity(provider="p", model="m", reserved_output_tokens=0, known_overhead_chars=0)
        assert result.source_capacity_chars == 0  # every token consumed by the margin alone

    def test_ratio_is_applied_deterministically(self):
        from utilities.autopatcher.technical_capacity import CONSERVATIVE_CHARS_PER_TOKEN
        with mock.patch(
            "utilities.autopatcher.technical_capacity._registry_context_window_tokens",
            return_value=10_000,
        ):
            r1 = _capacity(provider="p", model="m", reserved_output_tokens=0, known_overhead_chars=0)
            r2 = _capacity(provider="p", model="m", reserved_output_tokens=0, known_overhead_chars=0)
        assert r1.source_capacity_chars == r2.source_capacity_chars  # deterministic
        assert r1.chars_per_token_ratio == CONSERVATIVE_CHARS_PER_TOKEN

    def test_ratio_is_conservative_not_generous(self):
        """The ratio must UNDER-state usable capacity, never over-state
        it -- a realistic English/code chars-per-token average is closer
        to ~3.5-4.5; using anything at or above 4 here would risk
        constructing a request that looks fine in characters but exceeds
        the real token ceiling."""
        from utilities.autopatcher.technical_capacity import CONSERVATIVE_CHARS_PER_TOKEN
        assert CONSERVATIVE_CHARS_PER_TOKEN < 4.0


class TestNeverNegative:
    def test_overhead_exceeding_total_capacity_clamps_to_zero(self):
        with mock.patch(
            "utilities.autopatcher.technical_capacity._registry_context_window_tokens",
            return_value=1_000,
        ):
            result = _capacity(
                provider="p", model="m", reserved_output_tokens=900, known_overhead_chars=10**9,
            )
        assert result.source_capacity_chars == 0

    def test_reserved_output_alone_exceeding_total_clamps_to_zero(self):
        with mock.patch(
            "utilities.autopatcher.technical_capacity._registry_context_window_tokens",
            return_value=1_000,
        ):
            result = _capacity(provider="p", model="m", reserved_output_tokens=10**9)
        assert result.source_capacity_chars == 0


class TestApproximationLabeling:
    def test_capacity_is_approximate_always_true(self):
        """Even a real registry-sourced figure still passes through the
        char<->token approximation -- there is no exact code path here."""
        with mock.patch(
            "utilities.autopatcher.technical_capacity._registry_context_window_tokens",
            return_value=200_000,
        ):
            result = _capacity(provider="anthropic", model="claude-sonnet-5")
        assert result.capacity_is_approximate is True

    def test_result_records_every_input_for_trace_provenance(self):
        result = _capacity(
            provider=None, model=None, reserved_output_tokens=4096, known_overhead_chars=500,
        )
        d = result.as_dict()
        for key in (
            "source_capacity_chars", "capacity_source", "context_window_tokens",
            "reserved_output_tokens", "safety_margin_tokens", "chars_per_token_ratio",
            "known_overhead_chars", "capacity_is_approximate",
        ):
            assert key in d
