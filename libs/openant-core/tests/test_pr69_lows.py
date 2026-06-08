"""Tests for the PR #69 low-severity fixes.

* config ``_optional_str`` now raises ``ConfigError`` on a non-string
  value (e.g. ``"api_key": 12345``) instead of silently returning None —
  on both the v2 provider path and the legacy top-level path.
* ``report.generator._extract_usage`` warns once on missing pricing
  (reusing record_call's warning set) instead of silently reporting $0.
"""

from __future__ import annotations

import pytest

from report.generator import _extract_usage
from utilities.llm.config import ConfigError, _optional_str, parse_config
from utilities.llm_client import reset_warning_state


@pytest.fixture(autouse=True)
def _reset_warnings():
    reset_warning_state()
    yield
    reset_warning_state()


# --- _optional_str / config validation -------------------------------------


def test_optional_str_passes_through_strings_and_none():
    assert _optional_str(None) is None
    assert _optional_str("  sk-ant-xyz  ") == "sk-ant-xyz"
    assert _optional_str("   ") is None  # whitespace-only → None


def test_optional_str_rejects_non_string():
    with pytest.raises(ConfigError):
        _optional_str(12345)


def test_legacy_non_string_api_key_rejected():
    # v1 top-level api_key that isn't a string is a config error now,
    # not a silently-kept int.
    with pytest.raises(ConfigError):
        parse_config({"api_key": 12345})


def test_v2_provider_non_string_api_key_rejected():
    with pytest.raises(ConfigError):
        parse_config({
            "$schema_version": 2,
            "llm_providers": {"x": {"type": "anthropic", "api_key": 12345}},
        })


# --- generator unknown-pricing warning -------------------------------------


def test_extract_usage_warns_once_on_unknown_pricing(capsys):
    usage = _extract_usage(input_tokens=1_000_000, output_tokens=0, model="ghost-model-xyz")
    assert usage["cost_usd"] == 0.0
    assert "ghost-model-xyz" in capsys.readouterr().err, "must warn on unknown pricing"

    # Same model again → no second warning (shared one-time set).
    _extract_usage(input_tokens=1, output_tokens=1, model="ghost-model-xyz")
    assert capsys.readouterr().err == ""
