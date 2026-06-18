"""Guard against shipping dead/retired Claude model IDs in the default registry.

The scan path (analyzer/enhancer/verifier/reporter/scanner/llm_reachability) all
resolve models through ``build_phase_registry`` whose config-less default is
``OPENANT_DEFAULT`` in ``utilities/llm/builtins.py``. If that registry names a
retired model, every LLM phase 404s on a fresh install. These dead IDs were
shipped: ``claude-sonnet-4-20250514`` (retired) and ``claude-opus-4-6`` (stale).
"""

from __future__ import annotations

from utilities.llm.builtins import OPENANT_DEFAULT

# Models retired / not served by the Anthropic API.
DEAD_MODEL_IDS = {
    "claude-sonnet-4-20250514",
    "claude-opus-4-20250514",
    "claude-opus-4-5-20250514",
    "claude-opus-4-6",
}

# Current Anthropic model IDs the pipeline should use.
CURRENT_OPUS = "claude-opus-4-8"
CURRENT_SONNET = "claude-sonnet-4-6"


def test_no_dead_model_ids_in_default_registry():
    for phase, ref in OPENANT_DEFAULT.phases.items():
        assert ref.model not in DEAD_MODEL_IDS, (
            f"phase {phase!r} points at retired model {ref.model!r}"
        )


def test_default_registry_uses_current_ids():
    models = {ref.model for ref in OPENANT_DEFAULT.phases.values()}
    assert models <= {CURRENT_OPUS, CURRENT_SONNET}, (
        f"unexpected model ids in default registry: {models}"
    )
