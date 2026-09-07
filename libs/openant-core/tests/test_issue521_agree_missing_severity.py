"""#521 finding 2: an incomplete finish never authors a downgrade.

Agree-missing (`finish` without `agree`) marked the verification incomplete
but still honored the model-supplied ``correct_finding`` — so a supplied
``safe`` overwrote a Stage-1 vulnerable, the row left disclosure entirely
(core/verifier.py's confirmed_findings admits only vulnerable|bypassable),
while the metrics still counted it needs_review. The rule, shared with
FAM-REPORT-2's self-contradictory path: on ANY incomplete finish, the
surfacing verdict is the MORE-SEVERE of (Stage-1, supplied) per
FINDING_VERDICT_ORDER — upgrades honoured, downgrades withheld and recorded
(``withheld_correct_finding``).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.verdict_taxonomy import (  # noqa: E402
    DISCLOSURE_DROPPED,
    FINDING_VERDICT_ORDER,
    SEVERITY_FINDING_VERDICTS,
)
from utilities.finding_verifier import FindingVerifier  # noqa: E402


def _finish(supplied, original="vulnerable", agree_absent=True):
    # _parse_finish_result references no self.* — unbound-safe via __new__
    # (the famreport2 test file's own pattern)
    v = FindingVerifier.__new__(FindingVerifier)
    fr = {"correct_finding": supplied, "explanation": "model text"}
    if not agree_absent:
        fr["agree"] = False
    return v._parse_finish_result(fr, original, 2, 100)


# --- the core rule ---------------------------------------------------------

def test_agree_missing_supplied_safe_keeps_vulnerable():
    """RED on master: the vanish window — Stage-1 vulnerable, agree-missing
    finish supplying 'safe' — must keep 'vulnerable' + incomplete."""
    v = _finish("safe")
    assert v.correct_finding == "vulnerable", "the downgrade was authored"
    assert v.incomplete is True
    assert v.withheld_correct_finding == "safe"


def test_agree_missing_supplied_inconclusive_keeps_bypassable():
    v = _finish("inconclusive", original="bypassable")
    assert v.correct_finding == "bypassable"
    assert v.incomplete is True
    assert v.withheld_correct_finding == "inconclusive"


def test_agree_missing_upgrade_honoured_and_normalized():
    v = _finish("VULNERABLE", original="bypassable")
    assert v.correct_finding == "vulnerable"  # normalized, not uppercase
    assert v.withheld_correct_finding is None  # an upgrade is not withheld
    assert v.incomplete is True


def test_agree_missing_garbage_supplied_falls_back_to_original():
    v = _finish("MAYBE VULNERABLE")
    assert v.correct_finding == "vulnerable"
    assert v.withheld_correct_finding == "MAYBE VULNERABLE"


def test_agree_missing_null_supplied_falls_back_to_original():
    v = _finish(None)
    assert v.correct_finding == "vulnerable"
    assert v.withheld_correct_finding is None  # nothing withheld; it was absent


def test_agree_missing_error_supplied_does_not_error_checkpoint():
    """A supplied 'error' must not reach the checkpoint's error-retry read."""
    v = _finish("error")
    assert v.correct_finding == "vulnerable"
    assert v.withheld_correct_finding == "error"


# --- the complete paths stay untouched -------------------------------------

def test_complete_disagree_downgrade_still_honoured():
    """The legitimate downgrade channel: a COMPLETED disagree (agree=False
    PRESENT) keeps its supplied verdict — invariant 3's designed path."""
    v = _finish("safe", agree_absent=False)
    assert v.incomplete is False
    assert v.correct_finding == "safe"
    assert v.withheld_correct_finding is None


def test_fam_downgrade_withholds_and_records():
    """agree=True + supplied 'safe' over Stage-1 'vulnerable' (the FAM
    contradiction): the downgrade is withheld AND recorded — the audit
    record fires on BOTH incomplete-producing branches."""
    vv = FindingVerifier.__new__(FindingVerifier)
    fr = {"agree": True, "correct_finding": "safe", "explanation": "x"}
    v2 = vv._parse_finish_result(fr, "vulnerable", 1, 10)
    assert v2.incomplete is True
    assert v2.correct_finding == "vulnerable"
    assert v2.withheld_correct_finding == "safe"


def test_fam_report2_contradiction_unchanged():
    """The self-contradictory path (agree=True + diverging verdict) keeps
    FAM-REPORT-2's behavior: more-severe + incomplete."""
    vv = FindingVerifier.__new__(FindingVerifier)
    fr = {"agree": True, "correct_finding": "vulnerable", "explanation": "x"}
    v2 = vv._parse_finish_result(fr, "safe", 1, 10)
    assert v2.agree is False
    assert v2.incomplete is True
    assert v2.correct_finding == "vulnerable"
    assert v2.withheld_correct_finding is None  # the upgrade was honoured


# --- the authority's prefix property (the conformance pin) ----------------

def test_finding_verdict_order_prefix_is_the_eligible_set():
    """The _more_severe rule's correctness rests on this: the eligible
    finding verdicts are EXACTLY the order's two-element prefix, and the
    rest are all disclosure-dropped. A display-motivated reorder would
    silently re-open the vanish hole at both _more_severe call sites."""
    assert tuple(FINDING_VERDICT_ORDER[:2]) == tuple(SEVERITY_FINDING_VERDICTS), (
        "the eligible set is no longer the order's prefix — the severity "
        "rule and the disclosure boundary have diverged (the #521 guard)")
    assert set(FINDING_VERDICT_ORDER[2:]) <= DISCLOSURE_DROPPED, (
        "non-eligible verdicts outside DISCLOSURE_DROPPED — same divergence")


# --- end-to-end: the row stays in disclosure --------------------------------

def test_agree_missing_safe_row_survives_confirmed_findings():
    """The vanish, end-to-end through the REAL code: _parse_finish_result
    produces the verdict, the _verify_one incomplete write-back mirrors it
    onto result["finding"], and the disclosure-pipeline read (verifier's
    confirmed_findings filter — the {vulnerable, bypassable} admission)
    keeps the row. Pre-fix (supplied 'safe' honored verbatim): it vanishes."""
    vv = FindingVerifier.__new__(FindingVerifier)
    fr = {"correct_finding": "safe", "explanation": "model text"}
    v = vv._parse_finish_result(fr, "vulnerable", 2, 100)
    # _verify_one's incomplete write-back (finding_verifier:~:890) MIRRORED,
    # not hardcoded — the assertion reads the produced verdict, so this test
    # is RED on pristine master (the gate round's fix: the original form
    # hardcoded finding="vulnerable" and passed vacuously on both sides).
    row = {"route_key": "x.go:serveMsg.json", "finding": v.correct_finding,
           "verdict": "vulnerable",
           "verification": v.to_dict()}
    assert row["finding"] == "vulnerable"
    assert row["verification"]["incomplete"] is True
    # the disclosure-pipeline admission read (verifier.py's filter, verbatim)
    confirmed = [r for r in [row]
                 if str(r.get("finding") or r.get("verdict", "")).lower()
                 in ("vulnerable", "bypassable")]
    assert confirmed, "the agree-missing row vanished from the disclosure input"

    # pre-fix shape: the supplied 'safe' written verbatim -> vanished
    pre_row = dict(row, finding="safe", verification=dict(row["verification"], correct_finding="safe"))
    pre = [r for r in [pre_row]
           if str(r.get("finding") or r.get("verdict", "")).lower()
           in ("vulnerable", "bypassable")]
    assert not pre, "sanity: pre-fix shape must vanish (the reproduced defect)"


def test_withheld_verdict_serializes_for_the_triager():
    """The audit key rides the verification record so both withholdings
    (this rule's and #518's consistency block) are visible on one row."""
    v = _finish("safe")
    d = v.to_dict()
    assert d["withheld_correct_finding"] == "safe"
    assert d["incomplete"] is True
    assert d["correct_finding"] == "vulnerable"
    # and a non-withheld run serializes no key (absence stays absent)
    v2 = _finish("vulnerable")
    assert "withheld_correct_finding" not in v2.to_dict()
