"""#680: the stage1_consistency grouping folds the legacy INSUFFICIENT_CONTEXT
spelling to INCONCLUSIVE — the #655 miss (the detector read, not the apply path).

The tests drive the REAL production helper (utilities.stage1_consistency.
_group_verdicts — the grouping extracted from run_stage1_consistency_check so
it is testable without the heavy binding/tracker deps). No inline copy.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utilities.stage1_consistency import _group_verdicts  # noqa: E402


def test_mixed_spellings_fold_to_one():
    """THE #680 SHAPE: legacy + canonical in the same group = unanimous."""
    s = _group_verdicts([{"verdict": "INSUFFICIENT_CONTEXT"},
                         {"verdict": "INCONCLUSIVE"}])
    assert s == {"INCONCLUSIVE"}, (
        f"a mixed legacy+canonical group must fold to one verdict, got {s} — "
        "the #655 miss (the detector read fires the paid resolver on a "
        "unanimous cluster)"
    )


def test_both_canonical_consistent():
    assert _group_verdicts([{"verdict": "INCONCLUSIVE"},
                            {"verdict": "INCONCLUSIVE"}]) == {"INCONCLUSIVE"}


def test_both_legacy_fold():
    assert _group_verdicts([{"verdict": "INSUFFICIENT_CONTEXT"},
                           {"verdict": "INSUFFICIENT_CONTEXT"}]) == {"INCONCLUSIVE"}


def test_the_real_equivalence_classes_unchanged():
    assert _group_verdicts([{"verdict": "VULNERABLE"},
                            {"verdict": "BYPASSABLE"}]) == {"VULNERABLE"}
    assert _group_verdicts([{"verdict": "SAFE"},
                            {"verdict": "PROTECTED"}]) == {"SAFE"}
    # a REAL inconsistency still fires
    assert len(_group_verdicts([{"verdict": "VULNERABLE"},
                                {"verdict": "SAFE"}])) == 2
    assert len(_group_verdicts([{"verdict": "VULNERABLE"},
                                {"verdict": "INSUFFICIENT_CONTEXT"}])) == 2


def test_the_type_guard():
    """A non-string verdict reads as "" (None, an int, a stray list)."""
    assert _group_verdicts([{"verdict": None}, {"verdict": 42}]) == {""}


def test_the_production_path_uses_the_helper():
    """F2 (the T1's review): the call-site pin — run_stage1_consistency_check
    must USE the grouping (re-inlining the old 13 lines would keep the helper
    tests green while the production path regresses). The spy replaces the
    paid resolver and records which groups fire (the #680 defect is a fired
    resolver on a unanimous legacy+canonical cluster)."""
    from unittest.mock import patch
    from utilities import stage1_consistency as mod

    def make_row(provider, verdict):
        route = f"libs/partners/{provider}/base.py:_check"
        return {"route_key": route, "verdict": verdict,
                "code": f"def _check(x): return {verdict!r}"}

    # the same signature pattern (*._check across providers) groups these;
    # the vuln/safe pair must share a DIFFERENT pattern to fire separately
    rows = [
        make_row("openai", "INSUFFICIENT_CONTEXT"),   # the legacy spelling
        make_row("anthropic", "INCONCLUSIVE"),        # the canonical
    ]
    # the same signature pattern: the same FILENAME + the same function
    # name in different directories (the cross-provider grouping shape)
    rows2 = [
        {"route_key": "libs/core/x/base.py:_run", "verdict": "VULNERABLE",
         "code": "def _run(x): return x"},
        {"route_key": "libs/core/y/base.py:_run", "verdict": "SAFE",
         "code": "def _run(x): return x"},
    ]
    fired = []
    all_rows = rows + rows2
    code = {r["route_key"]: r["code"] for r in all_rows}
    with patch.object(mod, "_resolve_stage1_inconsistency",
                      side_effect=lambda *a, **k: fired.append(a[1] if len(a) > 1 else k)):
        mod.run_stage1_consistency_check(all_rows, code, None, None)
    # the legacy+canonical pair must NOT fire (the #680 fix); the vuln/safe
    # pair MUST (a real inconsistency)
    fired_groups = [sorted(r["verdict"] for r in g) for g in fired]
    assert not any("INSUFFICIENT_CONTEXT" in g and "INCONCLUSIVE" in g
                   and len(g) == 2 for g in fired_groups), (
        f"a legacy+canonical group fired the resolver: {fired_groups} — the "
        "#680 defect (the paid call on a unanimous cluster)"
    )
    assert any("VULNERABLE" in g and "SAFE" in g for g in fired_groups), (
        f"the real inconsistency did not fire: {fired_groups}"
    )
