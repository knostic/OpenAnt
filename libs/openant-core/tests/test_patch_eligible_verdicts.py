"""Pins core.verdict_taxonomy.PATCH_ELIGIBLE, the eligibility filter used by
core/patch.py to decide whether a finding may be sent to the patch-trust
pipeline.

Deliberately a distinct set from DISCLOSURE_ELIGIBLE and DYNAMIC_TESTABLE --
see the constant's docstring in core/verdict_taxonomy.py for why.
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))

from core.verdict_taxonomy import PATCH_ELIGIBLE, DISCLOSURE_ELIGIBLE, DYNAMIC_TESTABLE


def test_patch_eligible_exact_membership():
    assert PATCH_ELIGIBLE == frozenset({"confirmed", "agreed", "vulnerable", "bypassable"})


def test_patch_eligible_excludes_non_vulnerability_verdicts():
    for verdict in ("unverified", "error", "rejected", "safe", "protected", "inconclusive"):
        assert verdict not in PATCH_ELIGIBLE


def test_patch_eligible_is_its_own_set_not_an_alias():
    """PATCH_ELIGIBLE must differ from both DISCLOSURE_ELIGIBLE (broader --
    includes unverified/error) and DYNAMIC_TESTABLE (narrower -- excludes
    bypassable). Guards against someone "simplifying" it into an alias."""
    assert PATCH_ELIGIBLE != DISCLOSURE_ELIGIBLE
    assert PATCH_ELIGIBLE != DYNAMIC_TESTABLE
    assert "bypassable" in PATCH_ELIGIBLE and "bypassable" not in DYNAMIC_TESTABLE
