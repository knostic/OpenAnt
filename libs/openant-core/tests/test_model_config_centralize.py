"""RED->GREEN test for fix #42 — centralize model IDs into utilities/model_config.py.

Asserts the three properties the fix must satisfy:

(a) No hard-coded model-ID *literal* remains in product source outside
    ``utilities/model_config.py`` (grep-based scan over every product .py).
(b) The new module imports resolve, and every consumer imports its IDs from it —
    pricing now comes from the config/models.json registry (core.model_registry),
    NOT from model_config — with no circular import.
(c) The values match what was hard-coded before the refactor (behavior-preserving)
    for CURRENT models; retired/unknown ids are omitted from pricing now (null in
    the registry) so they can never price at $0. Cross-checked against each live
    consumer.

Run against the refactored tree (GREEN):
    OPENANT_CORE_ROOT=/path/to/openant-core \
        python -m pytest \
        model-config-centralize.test.py -q

Run against the pristine tree (RED — literals still inline, module absent):
    OPENANT_CORE_ROOT=/path/to/pristine/openant-core ... (same command)

With no OPENANT_CORE_ROOT, it defaults to the repo's libs/openant-core.
"""

from __future__ import annotations

import importlib
import os
import re
import sys
from pathlib import Path

import pytest


# --- locate the openant-core package under test ----------------------
def _default_root() -> Path:
    # This file lives in new-bugs-2/fixes/; core lives in
    # new-bugs-2/OpenAnt/libs/openant-core.
    return Path(__file__).resolve().parent.parent


ROOT = Path(os.environ.get("OPENANT_CORE_ROOT", str(_default_root()))).resolve()
MODEL_CONFIG_REL = "utilities/model_config.py"


@pytest.fixture(autouse=True)
def _core_on_syspath():
    """Put the core package root first on sys.path for the duration of a test."""
    root = str(ROOT)
    inserted = root not in sys.path
    if inserted:
        sys.path.insert(0, root)
    # Drop any cached target modules so a fresh ROOT is honored.
    for name in list(sys.modules):
        if name == "utilities" or name.startswith("utilities."):
            del sys.modules[name]
    try:
        yield
    finally:
        if inserted and root in sys.path:
            sys.path.remove(root)


# --- (a) grep-based: no model-ID literal outside model_config.py ------
# Quoted token that starts like a provider model family. Post-filtered to
# require an embedded digit so prose placeholders such as "claude-..." and
# fake ids such as "gemini_test" do not count.
_CANDIDATE = re.compile(r"""["'](?:claude|gpt|gemini|o[0-9])[A-Za-z0-9.\-]*["']""")


def _looks_like_real_model_id(token: str) -> bool:
    inner = token[1:-1]
    return bool(re.search(r"\d", inner)) and "..." not in inner


_SKIP_DIRS = {"tests", "__pycache__", "site-packages", "node_modules"}


def _product_py_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*.py"):
        parts = path.relative_to(ROOT).parts
        # Skip test trees, caches, and any bundled virtualenv / vendored
        # third-party code (e.g. .venv-*/…/site-packages, hidden dirs).
        if any(p in _SKIP_DIRS or p.startswith(".") for p in parts):
            continue
        if path.name.startswith("test_"):
            continue
        if path.as_posix().endswith(MODEL_CONFIG_REL):
            continue
        files.append(path)
    return files


def test_a_no_hardcoded_model_id_literal_outside_model_config():
    offenders: list[str] = []
    for path in _product_py_files():
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for tok in _CANDIDATE.findall(line):
                if _looks_like_real_model_id(tok):
                    rel = path.relative_to(ROOT).as_posix()
                    offenders.append(f"{rel}:{lineno}: {tok}")
    assert not offenders, (
        "Hard-coded model-ID literals must live only in "
        f"{MODEL_CONFIG_REL}; found:\n" + "\n".join(offenders)
    )


# --- (b) imports resolve --------------------------------------------
def test_b_model_config_module_imports():
    mc = importlib.import_module("utilities.model_config")
    for const in ("CLAUDE_OPUS", "CLAUDE_SONNET", "CLAUDE_HAIKU"):
        assert isinstance(getattr(mc, const), str)
    # Pricing moved OUT of model_config to the config/models.json registry
    # (read by core.model_registry). Lock that removal so a stray dict cannot
    # silently reintroduce a second, driftable source of truth.
    for table in ("ANTHROPIC_PRICING", "OPENAI_PRICING", "GOOGLE_PRICING"):
        assert not hasattr(mc, table), (
            f"{table} must no longer live in model_config; pricing is registry-owned"
        )


def test_b_consumers_import_without_cycle():
    # llm_client is imported transitively by the utilities.llm package
    # (helpers -> llm_client); importing both proves no circular import.
    for mod in (
        "utilities.llm_client",
        "utilities.context_enhancer",
        "utilities.llm.builtins",
        "utilities.llm.providers.anthropic",
        "utilities.llm.providers.google",
        "utilities.llm.providers.openai",
    ):
        importlib.import_module(mod)


# --- (c) values are behavior-preserving ------------------------------
# Snapshot of the exact literals present BEFORE the refactor.
# Post-cutover, pricing_map("anthropic") OMITS retired/unknown ids (null-priced
# in config/models.json), so the adapter table and MODEL_PRICING expose only the
# CURRENT models. The retired ids were priced in the old dict but must never
# price now (they resolve to warn + $0).
_EXPECTED_ANTHROPIC_CURRENT = {
    "claude-opus-4-8": {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 1.00, "output": 5.00},
}
_RETIRED_OR_UNKNOWN_ANTHROPIC = {
    "claude-opus-4-20250514",
    "claude-opus-4-6",
    "claude-sonnet-4-20250514",
}
_EXPECTED_OPENAI = {
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4.1": {"input": 2.00, "output": 8.00},
    "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
    "gpt-4.1-nano": {"input": 0.10, "output": 0.40},
    "o1": {"input": 15.00, "output": 60.00},
    "o3": {"input": 2.00, "output": 8.00},
    "o3-mini": {"input": 1.10, "output": 4.40},
    "o4-mini": {"input": 1.10, "output": 4.40},
}
_EXPECTED_GOOGLE = {
    "gemini-2.5-pro": {"input": 1.25, "output": 10.00},
    "gemini-2.5-flash": {"input": 0.30, "output": 2.50},
    "gemini-2.5-flash-lite": {"input": 0.10, "output": 0.40},
    "gemini-2.0-flash": {"input": 0.10, "output": 0.40},
    "gemini-2.0-flash-lite": {"input": 0.075, "output": 0.30},
    "gemini-1.5-pro": {"input": 1.25, "output": 5.00},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
}
_EXPECTED_PHASE_MODELS = {
    "analyze": "claude-opus-4-8",
    "enhance": "claude-sonnet-4-6",
    "verify": "claude-opus-4-8",
    "report": "claude-opus-4-8",
    "dynamic_test": "claude-sonnet-4-6",
    "llm_reach": "claude-opus-4-8",
    "app_context": "claude-sonnet-4-6",
}
_EXPECTED_LEGACY_ENHANCE = "claude-sonnet-4-20250514"


def test_c_pricing_maps_match_pre_refactor_snapshot():
    # Values are now sourced from config/models.json via core.model_registry.
    # Behavior-preserving for CURRENT models; retired/unknown ids are omitted.
    from core.model_registry import pricing_map

    anthropic = pricing_map("anthropic")
    assert anthropic == _EXPECTED_ANTHROPIC_CURRENT
    for retired in _RETIRED_OR_UNKNOWN_ANTHROPIC:
        assert retired not in anthropic, f"{retired} must be omitted, not priced"
    assert pricing_map("openai") == _EXPECTED_OPENAI
    assert pricing_map("google") == _EXPECTED_GOOGLE


def test_c_consumers_resolve_to_pre_refactor_values():
    from utilities.llm_client import MODEL_PRICING
    from utilities.llm.providers.anthropic import AnthropicAdapter
    from utilities.llm.providers.google import GoogleAdapter
    from utilities.llm.providers.openai import OpenAIAdapter
    from utilities.llm.builtins import OPENANT_DEFAULT
    from utilities.context_enhancer import CONTEXT_ENHANCEMENT_MODEL_LEGACY

    assert MODEL_PRICING == _EXPECTED_ANTHROPIC_CURRENT
    assert AnthropicAdapter.pricing == _EXPECTED_ANTHROPIC_CURRENT
    assert OpenAIAdapter.pricing == _EXPECTED_OPENAI
    assert GoogleAdapter.pricing == _EXPECTED_GOOGLE
    assert CONTEXT_ENHANCEMENT_MODEL_LEGACY == _EXPECTED_LEGACY_ENHANCE

    resolved = {p: OPENANT_DEFAULT.phases[p].model for p in _EXPECTED_PHASE_MODELS}
    assert resolved == _EXPECTED_PHASE_MODELS


def test_c_legacy_global_stays_pinned_to_adapter():
    # Pre-existing drift guard invariant must survive the refactor.
    from utilities.llm_client import MODEL_PRICING
    from utilities.llm.providers.anthropic import AnthropicAdapter

    assert MODEL_PRICING == AnthropicAdapter.pricing
