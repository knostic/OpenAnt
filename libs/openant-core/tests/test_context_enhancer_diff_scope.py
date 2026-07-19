"""Regression: single-shot enhance_dataset must keep the context-lookup dict
scoped to ALL units, not the diff-selected subset.

context_enhancer.enhance_dataset reassigns ``units`` to the diff-selected
subset, then builds ``units_by_id`` from that filtered list. But the code's own
comment promises ``units_by_id`` is kept over ALL units so that
``enhance_unit``'s same-file cross-unit context lookup still resolves callers/
callees that live outside the diff scope. The bug drops those non-diff units
from the lookup dict, so a changed unit loses same-file context from unchanged
siblings.

This test overrides ``enhance_unit`` to record the ``all_units`` dict it is
handed (no LLM call) and asserts an unchanged same-file sibling is still
reachable through it.
"""

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utilities.context_enhancer import ContextEnhancer  # noqa: E402


class _RecordingEnhancer(ContextEnhancer):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.seen_all_units = None

    def enhance_unit(self, unit, all_units):
        # Record the lookup dict handed to us; skip the real LLM call.
        self.seen_all_units = dict(all_units)
        unit["llm_context"] = {}
        return unit


def _unit(uid, file_path, diff_selected):
    return {
        "id": uid,
        "diff_selected": diff_selected,
        "unit_type": "function",
        "code": {"primary_origin": {"file_path": file_path, "function_name": uid}},
        "metadata": {"direct_calls": [], "direct_callers": []},
    }


def test_units_by_id_spans_all_units_not_diff_subset():
    dataset = {
        "units": [
            _unit("a.py:changed", "a.py", True),
            _unit("a.py:sibling", "a.py", False),  # unchanged same-file context
        ]
    }
    binding = SimpleNamespace(provider_name="test", model="test")
    enhancer = _RecordingEnhancer(binding)

    enhancer.enhance_dataset(dataset, workers=1)

    assert enhancer.seen_all_units is not None, "enhance_unit was never called"
    # The changed unit is processed; the unchanged sibling must remain in the
    # cross-unit lookup dict so same-file context resolution still works.
    assert "a.py:changed" in enhancer.seen_all_units
    assert "a.py:sibling" in enhancer.seen_all_units, (
        "non-diff sibling dropped from units_by_id — cross-unit context lost"
    )
