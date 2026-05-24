"""Scenario factories for adapter contract tests.

Each module here exposes ``make_adapter(scenario: str) -> LLMAdapter``
returning an adapter wired to a fake SDK scripted for the given
scenario. Kept under ``tests/`` so production code isn't polluted
with test fixtures.

See ``tests/test_llm_adapter_contract.py`` for the scenario catalogue.
"""
