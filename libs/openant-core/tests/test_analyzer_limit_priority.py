"""Regression tests for priority-sorted ``--limit`` truncation.

`run_analysis(..., limit=N)` truncates the unit list with a raw head-slice
``units = units[:limit]`` (analyzer.py). The units arrive from the parser in
alphabetical-by-path order (repository_scanner.py: ``self.files.sort(key=lambda
f: f['path'])``), so a ``--limit`` run deterministically kept the first N
alphabetical units (e.g. ``Doc/`` before ``Lib/``) and dropped high-value code
with NO relevance/priority weighting.

The fix sorts by enhancement security_classification (exploitable >
vulnerable_internal > other) BEFORE the head-slice, stably (alphabetical order
preserved within a classification tier), and reads the classification
mode-agnostically (agentic writes agent_context, single-shot writes
llm_context). These tests drive the extracted ``_apply_limit`` helper directly.
"""
import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).parent.parent
if str(_CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CORE_ROOT))

from core.analyzer import _apply_limit  # noqa: E402


def _unit(uid, classification=None, mode="agentic"):
    u = {"id": uid}
    if classification is not None:
        ctx_key = "agent_context" if mode == "agentic" else "llm_context"
        u[ctx_key] = {"security_classification": classification}
    return u


def test_no_limit_returns_units_unchanged():
    units = [_unit("a"), _unit("b"), _unit("c")]
    assert _apply_limit(units, None) is units
    assert _apply_limit(units, 0) is units


def test_limit_keeps_exploitable_over_alphabetically_early_neutral():
    # Parser order: Doc/ neutral units come first alphabetically, the
    # exploitable Lib/ unit comes last. A raw head-slice with limit=2 would
    # keep the two Doc/ neutrals and DROP the exploitable unit.
    units = [
        _unit("Doc/a", "neutral"),
        _unit("Doc/b", "neutral"),
        _unit("Lib/danger", "exploitable"),
    ]
    kept = _apply_limit(units, 2)
    kept_ids = [u["id"] for u in kept]
    assert "Lib/danger" in kept_ids, (
        "exploitable unit must survive a --limit truncation over neutral units; "
        f"got {kept_ids}"
    )
    assert len(kept) == 2


def test_priority_order_exploitable_then_vulnerable_internal_then_other():
    units = [
        _unit("a", "neutral"),
        _unit("b", "vulnerable_internal"),
        _unit("c", "exploitable"),
        _unit("d", None),
    ]
    kept_ids = [u["id"] for u in _apply_limit(units, 4)]
    # exploitable first, then vulnerable_internal, then the rest (stable).
    assert kept_ids[0] == "c"
    assert kept_ids[1] == "b"
    assert set(kept_ids[2:]) == {"a", "d"}


def test_stable_within_same_classification_tier():
    # Equal-priority units retain their original (alphabetical) order.
    units = [
        _unit("Lib/a", "exploitable"),
        _unit("Lib/b", "exploitable"),
        _unit("Lib/c", "exploitable"),
    ]
    kept_ids = [u["id"] for u in _apply_limit(units, 2)]
    assert kept_ids == ["Lib/a", "Lib/b"]


def test_classification_read_mode_agnostically_single_shot():
    # Single-shot enhance writes llm_context, not agent_context.
    units = [
        _unit("Doc/a", "neutral", mode="single-shot"),
        _unit("Lib/danger", "exploitable", mode="single-shot"),
    ]
    kept_ids = [u["id"] for u in _apply_limit(units, 1)]
    assert kept_ids == ["Lib/danger"]


def test_limit_larger_than_list_returns_all_reprioritized():
    units = [_unit("a", "neutral"), _unit("b", "exploitable")]
    kept_ids = [u["id"] for u in _apply_limit(units, 10)]
    assert kept_ids == ["b", "a"]
