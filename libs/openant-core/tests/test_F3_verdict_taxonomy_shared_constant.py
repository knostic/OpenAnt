"""F3 conformance test: shared verdict / disclosure taxonomy.

Enforces the ENTER => EXIT invariant for disclosure eligibility:

    every verdict the PRODUCER (core/reporter.py's stage2_verdict mapping) can
    emit must either be accepted by the disclosure filter (DISCLOSURE_ELIGIBLE)
    or be DELIBERATELY dropped (DISCLOSURE_DROPPED) -- never silently lost.

Formally:  enter-set  PRODUCER_VERDICTS
           exit-set   DISCLOSURE_ELIGIBLE
           dropped    DISCLOSURE_DROPPED
           assert  PRODUCER_VERDICTS <= DISCLOSURE_ELIGIBLE | DISCLOSURE_DROPPED
           assert  DISCLOSURE_ELIGIBLE & DISCLOSURE_DROPPED == set()  (partition)

RED on the ORIGINAL tree: core.verdict_taxonomy does not exist -> ImportError.
GREEN on the PATCHED tree: the module exists and the invariant holds, and the
behavior change (bypassable/error now disclosure-eligible) is asserted.

The target tree is chosen via the OPENANT_ROOT env var (defaults to this
repo's own openant-core). Run:

    OPENANT_ROOT=/path/to/patched/tree pytest F3-...test.py
"""

import importlib
from contextlib import contextmanager
import os
import re
import sys
from pathlib import Path

import pytest

# Default to THIS repo's core. The previous default was an absolute path into
# another machine-session's scratchpad; where that directory still happened to
# exist, the whole suite silently asserted against a stale, different tree
# (its core/ had no verdict_taxonomy at all, so the consumer check reported
# reporter.py as missing DISCLOSURE_ELIGIBLE when in fact it imports it).
_DEFAULT_ROOT = str(Path(__file__).resolve().parent.parent)
ROOT = Path(os.environ.get("OPENANT_ROOT", _DEFAULT_ROOT)).resolve()


@contextmanager
def _isolated_core_namespace():
    """Import ``core.*`` from ROOT without leaking the eviction into the session.

    The eviction itself is necessary: pointing OPENANT_ROOT at a different tree
    must re-import rather than reuse a cached copy. What was missing is putting
    ``sys.modules`` and ``sys.path`` BACK afterwards.

    Leaking them is not a tidiness issue. Any test collected after this one that
    bound ``import core.X as m`` at collection time and then monkeypatched
    ``m.attr`` was silently defeated: the code under test re-imported ``core.X``
    and got a DIFFERENT module object, so the patch applied to an orphan. That
    is what made ``test_enhance_limit`` bypass its stub and issue a live
    Anthropic API call during an offline test run.
    """
    saved_modules = {
        name: module
        for name, module in sys.modules.items()
        if name == "core" or name.startswith("core.")
    }
    saved_path = list(sys.path)
    try:
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        for name in list(sys.modules):
            if name == "core" or name.startswith("core."):
                del sys.modules[name]
        yield
    finally:
        for name in list(sys.modules):
            if name == "core" or name.startswith("core."):
                del sys.modules[name]
        sys.modules.update(saved_modules)
        sys.path[:] = saved_path


def _load_taxonomy():
    """Import core.verdict_taxonomy from the target tree in a clean namespace."""
    with _isolated_core_namespace():
        return importlib.import_module("core.verdict_taxonomy")


# ---------------------------------------------------------------------------
# Producer set derived independently from the test's own knowledge of the
# reporter mapping, so the taxonomy module cannot silently shrink the enter-set.
# core/reporter.py stage2_verdict can be:
#   WITH Stage 2    -> confirmed | agreed | unverified | rejected
#   WITHOUT Stage 2 -> a bare finding verdict: one of the 5 analyzer verdicts
#                      or the "error" sentinel.
EXPECTED_PRODUCER = {
    "confirmed", "agreed", "unverified", "rejected",   # stage-2
    "vulnerable", "bypassable", "inconclusive", "protected", "safe",  # stage-1
    "error",
}


def test_taxonomy_module_importable():
    """RED on original (no module) -> GREEN on patched."""
    tax = _load_taxonomy()
    for attr in (
        "PRODUCER_VERDICTS",
        "DISCLOSURE_ELIGIBLE",
        "DISCLOSURE_DROPPED",
        "DYNAMIC_TESTABLE",
        "FINDING_VERDICT_ORDER",
    ):
        assert hasattr(tax, attr), f"missing taxonomy constant: {attr}"


def test_producer_set_matches_reporter_mapping():
    tax = _load_taxonomy()
    assert set(tax.PRODUCER_VERDICTS) == EXPECTED_PRODUCER, (
        "PRODUCER_VERDICTS drifted from the reporter.py stage2_verdict mapping"
    )


def test_enter_subset_of_exit_union_dropped():
    """The core ENTER => EXIT invariant."""
    tax = _load_taxonomy()
    covered = set(tax.DISCLOSURE_ELIGIBLE) | set(tax.DISCLOSURE_DROPPED)
    missing = set(tax.PRODUCER_VERDICTS) - covered
    assert not missing, (
        f"producer verdicts silently dropped (neither eligible nor "
        f"deliberately-dropped): {sorted(missing)}"
    )


def test_eligible_and_dropped_are_disjoint():
    tax = _load_taxonomy()
    both = set(tax.DISCLOSURE_ELIGIBLE) & set(tax.DISCLOSURE_DROPPED)
    assert not both, f"verdict classified as BOTH eligible and dropped: {sorted(both)}"


def test_dropped_is_exactly_complement():
    """Every classified verdict is a real producer verdict (no phantom labels)."""
    tax = _load_taxonomy()
    covered = set(tax.DISCLOSURE_ELIGIBLE) | set(tax.DISCLOSURE_DROPPED)
    assert covered == set(tax.PRODUCER_VERDICTS)


def test_behavior_change_surfaces_bypassable_and_error():
    """The deliberate (sign-off-gated) behavior change: bypassable + error
    are now disclosure-eligible; they were previously silently dropped."""
    tax = _load_taxonomy()
    assert "bypassable" in tax.DISCLOSURE_ELIGIBLE
    assert "error" in tax.DISCLOSURE_ELIGIBLE


def test_previous_eligible_verdicts_still_eligible():
    """No regression: the pre-patch eligible set stays eligible."""
    tax = _load_taxonomy()
    for v in ("confirmed", "agreed", "unverified", "vulnerable"):
        assert v in tax.DISCLOSURE_ELIGIBLE


def test_rejected_and_safe_stay_dropped():
    tax = _load_taxonomy()
    for v in ("rejected", "safe", "protected", "inconclusive"):
        assert v in tax.DISCLOSURE_DROPPED
        assert v not in tax.DISCLOSURE_ELIGIBLE


def test_dynamic_testable_behavior_preserved():
    """dynamic_tester consolidation must NOT change its filter set."""
    tax = _load_taxonomy()
    assert set(tax.DYNAMIC_TESTABLE) == {"confirmed", "agreed", "vulnerable"}


def test_finding_verdict_order_preserved():
    """cli / generate_report consolidation must NOT change the ordered list."""
    tax = _load_taxonomy()
    assert list(tax.FINDING_VERDICT_ORDER) == [
        "vulnerable", "bypassable", "inconclusive", "protected", "safe",
    ]


def test_disclosure_consumers_reference_the_constant():
    """Each disclosure filter must actually use DISCLOSURE_ELIGIBLE (not an
    inlined tuple), so the shared taxonomy is authoritative."""
    for rel in ("core/reporter.py", "report/generator.py", "report/__main__.py"):
        src = (ROOT / rel).read_text()
        assert "DISCLOSURE_ELIGIBLE" in src, f"{rel} does not import/use DISCLOSURE_ELIGIBLE"
        # No lingering inlined disclosure tuple with the old membership.
        assert not re.search(
            r'stage2_verdict"?\)\s*(?:not\s+)?in\s*\(', src
        ), f"{rel} still uses an inlined stage2_verdict tuple filter"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


def test_loading_taxonomy_does_not_leak_module_eviction():
    """The eviction must not outlive the helper.

    Regression lock for a cross-test hazard: leaking it silently defeated
    monkeypatches in every test collected afterwards, which made
    test_enhance_limit bypass its stub and issue a live API call.
    """
    import core.parser_adapter as before

    _load_taxonomy()

    import core.parser_adapter as after
    assert after is before, (
        "core.parser_adapter was re-imported as a different object after "
        "_load_taxonomy() — the sys.modules eviction leaked"
    )
    assert "core.parser_adapter" in sys.modules
