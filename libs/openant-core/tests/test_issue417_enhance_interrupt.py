"""Regression tests for issue #417 — SIGINT during enhance is silently
swallowed today: all four KeyboardInterrupt handlers in
utilities/context_enhancer.py catch, log, and ``return dataset``, so the
pipeline continues (analyze → verify → report) and the Go layer never sees
an interrupt (empty-stdout short-circuit never fires → no exit 130).

Issue #313/#411 fixed the ANALYZE stage's identical swallow by re-raising
after checkpoints; these tests lock the same contract for ENHANCE
(single-shot and agentic, sequential and parallel): after the interrupt is
observed and per-unit checkpoints are already on disk, the enhancer RAISES
KeyboardInterrupt so the caller (the scan pipeline) can surface it as an
interrupt — not complete the scan as if nothing happened.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import json

import pytest


def _analyzer_output(tmp_path, n: int = 6) -> str:
    """A minimal analyzer_output.json the agentic path can index."""
    p = tmp_path / "analyzer_output.json"
    p.write_text(json.dumps({
        "functions": {f"mod.py:unit_{i}": {"code": f"def unit_{i}(): return {i}\\n", "file_path": "mod.py", "name": f"unit_{i}"} for i in range(n)},
        "callGraph": {}, "reverseCallGraph": {},
    }))
    return str(p)


def _dataset(n: int = 6) -> dict:
    """A minimal dataset with n units — the loop processes dataset['units']."""
    return {
        "units": [
            {"id": f"mod.py:unit_{i}", "name": f"unit_{i}", "code": f"def unit_{i}(): return {i}\n"}
            for i in range(n)
        ]
    }


def _stub_binding():
    class B:
        phase = "enhance"
        provider_name = "test"
        model = "stub-model"
    return B()


def _tracker():
    from utilities.llm_client import TokenTracker
    return TokenTracker()


def test_agentic_sequential_interrupt_propagates(monkeypatch, tmp_path):
    """The agentic enhance loop's SEQUENTIAL path must RAISE KeyboardInterrupt
    after the interrupt — returning the dataset lets the scan continue as if
    the user never pressed Ctrl+C (issue #417's exact live-run repro)."""
    import utilities.context_enhancer as ce

    state = {"calls": 0}

    def fake_agent(unit, index, binding, tracker, verbose):
        state["calls"] += 1
        if state["calls"] == 2:
            raise KeyboardInterrupt
        unit.setdefault("agent_context", {})["security_classification"] = "neutral"

    monkeypatch.setattr(ce, "enhance_unit_with_agent", fake_agent)

    enhancer = ce.ContextEnhancer(_stub_binding(), tracker=_tracker())
    with pytest.raises(KeyboardInterrupt):
        enhancer.enhance_dataset_agentic(
            _dataset(), analyzer_output_path=_analyzer_output(tmp_path), workers=1)


def test_agentic_parallel_interrupt_propagates(monkeypatch, tmp_path):
    """The agentic PARALLEL path carries the same contract: the handler
    cancels pending futures, then re-raises (never returns the dataset)."""
    import utilities.context_enhancer as ce

    state = {"calls": 0}

    def fake_agent(unit, index, binding, tracker, verbose):
        state["calls"] += 1
        if state["calls"] == 2:
            raise KeyboardInterrupt
        unit.setdefault("agent_context", {})["security_classification"] = "neutral"

    monkeypatch.setattr(ce, "enhance_unit_with_agent", fake_agent)

    enhancer = ce.ContextEnhancer(_stub_binding(), tracker=_tracker())
    with pytest.raises(KeyboardInterrupt):
        enhancer.enhance_dataset_agentic(
            _dataset(), analyzer_output_path=_analyzer_output(tmp_path), workers=2)


def test_single_shot_parallel_interrupt_propagates(monkeypatch):
    """The single-shot PARALLEL path (the fourth handler) carries the same
    contract — after cancelling pending futures, it re-raises."""
    import utilities.context_enhancer as ce

    state = {"calls": 0}

    def fake_enhance_unit(self, unit, all_units):
        state["calls"] += 1
        if state["calls"] == 2:
            raise KeyboardInterrupt
        unit.setdefault("llm_context", {})["security_classification"] = "neutral"

    monkeypatch.setattr(ce.ContextEnhancer, "enhance_unit", fake_enhance_unit)

    enhancer = ce.ContextEnhancer(_stub_binding(), tracker=_tracker())
    with pytest.raises(KeyboardInterrupt):
        enhancer.enhance_dataset(_dataset(), workers=2)


def test_single_shot_interrupt_propagates(monkeypatch):
    """The single-shot enhance loop's sequential path carries the contract."""
    import utilities.context_enhancer as ce

    state = {"calls": 0}

    def fake_enhance_unit(self, unit, all_units):
        state["calls"] += 1
        if state["calls"] == 2:
            raise KeyboardInterrupt
        unit.setdefault("llm_context", {})["security_classification"] = "neutral"

    monkeypatch.setattr(ce.ContextEnhancer, "enhance_unit", fake_enhance_unit)

    enhancer = ce.ContextEnhancer(_stub_binding(), tracker=_tracker())
    with pytest.raises(KeyboardInterrupt):
        enhancer.enhance_dataset(_dataset(), workers=1)
