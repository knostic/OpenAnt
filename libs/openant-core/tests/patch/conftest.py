"""Shared fixtures for Auto Patcher tests.

Auto Patcher's live-provider resolution (utilities.autopatcher.llm_client)
never silently falls back to mock: for a real provider, it always resolves
OpenAnt's canonical default_llm/analyze binding (falling back to the
built-in "openant-default" exactly like every other OpenAnt command), and
LLM_PROVIDER is recognized only as the literal value "mock" -- any other
non-empty value is a hard failure, not a selector.

Without this fixture, EVERY test in this directory that constructs a real
LLMClient()/calls .complete() without an explicit LLM_PROVIDER=mock would
depend on whatever is actually configured on the machine running the
suite: raising an error (nothing configured) or -- on a machine that has
run `openant setup llm` / `openant set-api-key` -- attempting a REAL,
BILLED API call, instead of the deterministic mock response the test
actually wants.

This fixture makes mock the test suite's explicit, deterministic default
and isolates every test from the real config.json on disk. Individual
tests that want to exercise a real (adapter-mocked) provider or a specific
config.json shape override both via their own monkeypatch calls inside the
test body, which run after this fixture's setup and therefore win.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _default_to_mock_and_isolated_config(monkeypatch):
    import utilities.autopatcher.llm_client as llm_client
    from utilities.llm import empty_config

    monkeypatch.setenv("LLM_PROVIDER", "mock")
    monkeypatch.setattr(llm_client, "load_config_file", lambda: empty_config())
    monkeypatch.setattr(llm_client, "_cached_provider", None)
    monkeypatch.setattr(llm_client, "_cached_model", {})
    monkeypatch.setattr(llm_client, "_cached_adapters", {})
    monkeypatch.setattr(llm_client, "_call_metadata", {})
