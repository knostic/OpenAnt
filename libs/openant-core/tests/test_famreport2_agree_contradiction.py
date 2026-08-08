"""FAM-REPORT-2 (trace c938311d): a self-contradictory verifier finish must not
silently drop a vuln.

The `finish` tool schema declares `agree` and `correct_finding` as independent
fields (no cross-field constraint), so a model can emit `agree=True` (claims to
agree with Stage-1) while `correct_finding` diverges from the Stage-1 verdict.
Pre-fix, `_parse_finish_result` took `agree` verbatim and both write-back
consumers (`finding_verifier._verify_one`, `experiment.py`) only propagate
`correct_finding` on the disagree branch — so an UPGRADE contradiction
(stage1=safe, correct_finding=vulnerable) left `result["finding"]="safe"` and the
vuln was dropped by the reporter's disclosure filter (core/reporter.py:283).

Fix (chokepoint `_parse_finish_result`): on a contradiction — `agree=True` AND
`correct_finding != Stage-1` — treat it as a disagreement toward the MORE-SEVERE
verdict and flag `incomplete=True`, so the finding surfaces as "unverified"
(needs manual review) instead of a clean "agreed" that can be dropped. A single
fix at the shared producer covers both consumers.

Offline; no network. Pure `_parse_finish_result` translation + a verbatim copy of
the reporter's disclosure predicate for the end-to-end impact check.
"""
from __future__ import annotations

from utilities.finding_verifier import FindingVerifier


def _parse(finish_args: dict, stage1: str):
    # _parse_finish_result references no `self.*` — unbound-safe via __new__.
    v = FindingVerifier.__new__(FindingVerifier)
    return v._parse_finish_result(finish_args, stage1, 1, 10)


def _reporter_discloses(result: dict) -> bool:
    # Verbatim copy of core/reporter.py:283 disclosure predicate.
    return str(result.get("finding") or result.get("verdict", "")).lower() in ("vulnerable", "bypassable")


def _writeback(result: dict, vr) -> None:
    # Mirror of the consumer write-back branch (_verify_one:728-736 /
    # experiment.py:590-596): correct_finding propagates on the disagree branch.
    if vr.agree:
        pass
    else:
        result["finding"] = vr.correct_finding


# --- RED: the FN (upgrade contradiction, reachable via experiment.py --verify) ---

def test_upgrade_contradiction_is_flagged_not_clean_agreement():
    # agree=True but correct_finding upgrades safe -> vulnerable: a self-
    # contradiction, must NOT read as a clean completed agreement.
    vr = _parse({"agree": True, "correct_finding": "vulnerable", "explanation": "x"}, "safe")
    assert vr.incomplete is True          # surfaced as needs-review, not clean
    assert vr.agree is False              # so consumers propagate the verdict
    assert vr.correct_finding == "vulnerable"   # the more-severe reading is kept


def test_upgrade_contradiction_end_to_end_not_dropped():
    # Impact repro: after the consumer write-back + reporter filter, the vuln
    # carried only in correct_finding must reach disclosure (not be dropped).
    result = {"finding": "safe"}
    vr = _parse({"agree": True, "correct_finding": "vulnerable", "explanation": "x"}, "safe")
    _writeback(result, vr)
    assert _reporter_discloses(result) is True


# --- RED: downgrade contradiction (production relabel; more-severe preserved) ---

def test_downgrade_contradiction_preserves_severe_and_flags():
    # agree=True but correct_finding downgrades vulnerable -> safe: keep the
    # more-severe (vulnerable) reading and flag incomplete (needs review).
    vr = _parse({"agree": True, "correct_finding": "safe", "explanation": "x"}, "vulnerable")
    assert vr.incomplete is True
    assert vr.agree is False
    assert vr.correct_finding == "vulnerable"


def test_downgrade_contradiction_still_surfaced():
    result = {"finding": "vulnerable"}
    vr = _parse({"agree": True, "correct_finding": "safe", "explanation": "x"}, "vulnerable")
    _writeback(result, vr)
    assert _reporter_discloses(result) is True   # stays surfaced, not downgraded to safe


# --- edge: contradiction between two non-vuln verdicts must not fabricate a vuln ---

def test_nonvuln_contradiction_flags_but_no_vuln_fabricated():
    vr = _parse({"agree": True, "correct_finding": "protected", "explanation": "x"}, "safe")
    assert vr.incomplete is True
    assert vr.agree is False
    assert vr.correct_finding == "protected"     # more severe of {safe, protected}
    result = {"finding": "safe"}
    _writeback(result, vr)
    assert _reporter_discloses(result) is False  # neither side vulnerable -> not disclosed


# --- regression guards: normal (non-contradictory) paths must be UNCHANGED ---

def test_normal_agreement_unchanged():
    # agree=True and correct_finding matches Stage-1 -> a real, clean agreement.
    vr = _parse({"agree": True, "correct_finding": "vulnerable", "explanation": "x"}, "vulnerable")
    assert vr.agree is True
    assert vr.incomplete is False
    assert vr.correct_finding == "vulnerable"


def test_normal_disagreement_unchanged():
    vr = _parse({"agree": False, "correct_finding": "safe", "explanation": "x"}, "vulnerable")
    assert vr.agree is False
    assert vr.incomplete is False
    assert vr.correct_finding == "safe"


def test_missing_agree_still_incomplete():
    # The pre-existing F4/F5 degenerate path (absent `agree`) stays incomplete.
    vr = _parse({"correct_finding": "vulnerable", "explanation": "x"}, "safe")
    assert vr.agree is False
    assert vr.incomplete is True
