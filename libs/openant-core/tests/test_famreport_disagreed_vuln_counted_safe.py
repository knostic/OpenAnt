"""FAM-REPORT: a disagreement whose corrected verdict is still vulnerable must
not be folded into ``safe``.

Bug (core/verifier.py:_count_verification_outcomes): the ``else`` (agree=False)
branch bucketed EVERY disagreement as ``disagreed``, which the scanner folds
into ``safe`` (scanner.py: ``safe += verify_result.disagreed``). But
finding_verifier sets ``result["finding"] = correct_finding`` on disagree, and
``correct_finding`` may still be ``vulnerable``/``bypassable`` (e.g. Stage 1
"vulnerable" -> Stage 2 disagrees and says "bypassable"). Such a finding is a
confirmed vulnerability, yet it was counted as safe -> under-reports vulns.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.verifier import _count_verification_outcomes


def test_disagreed_but_still_vulnerable_is_confirmed_not_safe():
    verified_results = [
        {  # Stage 2 disagreed on classification but it is STILL a vuln
            "route_key": "a:1", "finding": "bypassable",
            "verification": {"agree": False, "correct_finding": "bypassable",
                             "incomplete": False},
        },
        {  # disagreed and re-classified vulnerable (still a vuln)
            "route_key": "a:2", "finding": "vulnerable",
            "verification": {"agree": False, "correct_finding": "vulnerable",
                             "incomplete": False},
        },
        {  # genuine downgrade to safe — the only true "disagreed" (folds to safe)
            "route_key": "c:3", "finding": "safe",
            "verification": {"agree": False, "correct_finding": "safe",
                             "incomplete": False},
        },
    ]
    counts = _count_verification_outcomes(verified_results)

    # The two still-vulnerable disagreements must be confirmed vulnerabilities.
    assert counts["confirmed_vulnerabilities"] == 2, (
        f"still-vulnerable disagreements must count as confirmed vulns, "
        f"got {counts['confirmed_vulnerabilities']}"
    )
    # Only the genuine downgrade-to-safe may fold into safe via ``disagreed``.
    assert counts["disagreed"] == 1, (
        f"only the downgrade-to-safe is 'disagreed'; a still-vulnerable "
        f"disagreement must NOT be (it folds into safe), got {counts['disagreed']}"
    )


def test_verdictonly_disagreed_still_vulnerable_is_confirmed():
    """fa2-alone defect: fa2's disagreed-branch read was ``r.get("finding","")
    .lower()`` — it OMITS the ``or r.get("verdict")`` fallback. So a verdict-only
    DISAGREED-still-vulnerable result {"verdict": "VULNERABLE", verification=
    {agree:False, correct_finding:"VULNERABLE"}} reads finding="" and is bucketed
    as ``disagreed`` (folds into safe) instead of ``confirmed_vulnerabilities``.
    RED on pristine (no disagreed-branch promotion at all) AND on fa2-alone;
    GREEN only on the canonical read.
    """
    verified_results = [
        {
            "route_key": "a:1", "verdict": "VULNERABLE",
            "verification": {"agree": False, "correct_finding": "VULNERABLE",
                             "incomplete": False},
        },
    ]
    counts = _count_verification_outcomes(verified_results)
    assert counts["confirmed_vulnerabilities"] == 1, (
        f"verdict-only disagreed-still-vulnerable must be a confirmed vuln, "
        f"got {counts['confirmed_vulnerabilities']}"
    )
    assert counts["disagreed"] == 0, (
        f"verdict-only disagreed-still-vulnerable must NOT fold into safe, "
        f"got disagreed={counts['disagreed']}"
    )
