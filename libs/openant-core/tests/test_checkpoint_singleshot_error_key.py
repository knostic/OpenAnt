"""Regression: StepCheckpoint.status() must count an errored single-shot unit.

Single-shot enhance persists its context under ``llm_context`` and records
``context_key: "llm_context"`` in the per-unit checkpoint file (see
``ContextEnhancer._save_unit_checkpoint``). ``core/checkpoint.StepCheckpoint.status``
historically hardcoded ``agent_context.error`` when classifying enhance-phase
checkpoints — so an errored *single-shot* unit (whose error lives under
``llm_context.error``) was mis-counted as ``completed`` instead of ``errored``,
hiding real enhancement failures from ``openant checkpoint-status``.

This test drives the REAL producer end to end: an injected LLM failure makes
``ContextEnhancer.enhance_unit`` store its real failed ``llm_context`` (which
carries a structured ``error`` key), that unit is persisted through the real
``_save_unit_checkpoint`` serializer, and then ``StepCheckpoint.status`` is
asserted to tally it as an error. RED without the checkpoint.py
``context_key``-aware change; GREEN with it.
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

from core.checkpoint import StepCheckpoint  # noqa: E402


class _FakeAdapter:
    name = "anthropic"
    supports_tools = True

    def complete(self, *, model, system, messages, max_tokens, tools=None):  # pragma: no cover
        raise AssertionError("adapter must not be called")

    def validate(self, model):  # pragma: no cover
        pass


def _make_enhancer():
    from utilities.context_enhancer import ContextEnhancer
    from utilities.llm import PhaseBinding

    binding = PhaseBinding(
        phase="enhance",
        adapter=_FakeAdapter(),
        model="claude-test",
        provider_name="anthropic",
    )
    return ContextEnhancer(binding=binding, tracker=None)


def _unit(uid="u_err"):
    return {"id": uid, "code": {"primary_code": "def f(): pass"}, "unit_type": "function"}


def _drive_real_singleshot_failure(monkeypatch, checkpoint_dir, uid="u_err"):
    """Run the real single-shot enhance failure path and persist its checkpoint.

    Returns the enhanced unit. The persisted checkpoint file mirrors exactly
    what ``enhance_dataset`` writes for a failed unit in single-shot mode.
    """
    import utilities.context_enhancer as ce

    monkeypatch.setattr(ce, "simple_text", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("provider exploded")))

    enh = _make_enhancer()
    unit = enh.enhance_unit(_unit(uid), {})
    # Precondition: fa2 producer must have stamped a structured error on the
    # real failed single-shot context. If this ever regresses, the test is moot.
    assert unit["llm_context"].get("error"), "producer must set llm_context.error on single-shot failure"
    # Persist through the REAL single-shot serializer (context_key='llm_context').
    enh._save_unit_checkpoint(unit, str(checkpoint_dir), context_key="llm_context")
    return unit


def test_status_counts_real_singleshot_failure(monkeypatch, tmp_path):
    cp_dir = tmp_path / "enhance"
    cp_dir.mkdir()
    _drive_real_singleshot_failure(monkeypatch, cp_dir)

    status = StepCheckpoint.status(str(cp_dir))

    assert status["errors"] == 1, f"errored single-shot unit must be counted as an error, got {status}"
    assert status["completed"] == 0, f"errored unit must NOT be counted completed, got {status}"
    # error_breakdown keys off the structured error 'type' from the real producer.
    assert sum(status["error_breakdown"].values()) == 1, status["error_breakdown"]


def test_status_counts_real_singleshot_success_as_completed(monkeypatch, tmp_path):
    """A successfully-enhanced single-shot unit stays counted as completed."""
    import utilities.context_enhancer as ce

    monkeypatch.setattr(
        ce, "simple_text",
        lambda *a, **k: '{"missing_dependencies": [], "additional_callers": [], '
                        '"data_flow": {}, "imports": [], "reasoning": "ok", "confidence": 0.5}',
    )
    cp_dir = tmp_path / "enhance"
    cp_dir.mkdir()
    enh = _make_enhancer()
    unit = enh.enhance_unit(_unit("u_ok"), {})
    assert not unit["llm_context"].get("error")
    enh._save_unit_checkpoint(unit, str(cp_dir), context_key="llm_context")

    status = StepCheckpoint.status(str(cp_dir))
    assert status["errors"] == 0, status
    assert status["completed"] == 1, status


def test_status_agentic_error_still_detected(tmp_path):
    """Legacy/agentic path (agent_context.error, no context_key) still works."""
    cp = StepCheckpoint("enhance", str(tmp_path))
    cp.save("a_err", {"id": "a_err", "agent_context": {"error": {"type": "Timeout"}, "confidence": 0.0}})
    status = StepCheckpoint.status(cp.dir)
    assert status["errors"] == 1, status
    assert status["error_breakdown"].get("Timeout") == 1, status["error_breakdown"]
