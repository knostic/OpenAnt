"""
Conformance test for finding verifier-309-verdictonly-vuln-dropped.

Bug: the Stage-2 INPUT gate at core/verifier.py:99 admits a result on the
canonical read ``str(r.get("finding") or r.get("verdict", "")).lower()`` -- so
a verdict-only result ``{"verdict": "VULNERABLE"}`` (no ``finding`` key) passes.
But the downstream count/classify sites omit the ``or r.get("verdict")``
fallback:

  * :281 ``_count_verification_outcomes`` -> confirmed_vulnerabilities count
  * :309 ``_write_verified_results``       -> confirmed_findings list
  * :319 ``_write_verified_results``       -> metrics recount (does not lowercase
                                             a present finding)

so a verdict-only VULNERABLE result that the :99 filter admitted is silently
DROPPED from confirmed_findings / confirmed_vulnerabilities.

RED  on pristine core: verdict-only result absent from confirmed sets.
GREEN on patched core: verdict-only result counted / kept.
"""

import json
import os
import sys
import tempfile


_CORE_ROOT = os.environ.get(
    "OPENANT_CORE_ROOT",
    os.path.join(os.path.dirname(__file__), ".."),
)
_CORE_ROOT = os.path.abspath(_CORE_ROOT)
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)


def test_verdictonly_vulnerable_counted_as_confirmed():
    from core.verifier import _count_verification_outcomes

    # A verdict-only result the :99 input filter admits (agree=True Stage 2).
    verified = [
        {"verdict": "VULNERABLE", "verification": {"agree": True}},
    ]
    counts = _count_verification_outcomes(verified)
    assert counts["confirmed_vulnerabilities"] == 1, (
        f"verdict-only VULNERABLE dropped from confirmed_vulnerabilities: {counts}"
    )


def test_verdictonly_vulnerable_kept_in_confirmed_findings():
    from core.verifier import _write_verified_results

    verdict_only = {"verdict": "VULNERABLE", "verification": {"agree": True}}
    experiment = {"dataset": "d", "model": "m", "timestamp": "t"}
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "results_verified.json")
        _write_verified_results(path, experiment, [verdict_only], [verdict_only])
        with open(path) as fh:
            out = json.load(fh)
    confirmed = out["confirmed_findings"]
    assert len(confirmed) == 1, (
        f"verdict-only VULNERABLE dropped from confirmed_findings: {confirmed}"
    )
    # :319 metrics recount must also lowercase/classify the verdict.
    assert out["metrics"]["vulnerable"] == 1, (
        f"verdict-only VULNERABLE miscounted in metrics: {out['metrics']}"
    )


def test_present_uppercase_finding_counted_in_metrics():
    """Real :319 defect (the case fa11's own metrics assertion was false-green
    on): a PRESENT but UPPERCASE finding {"finding": "VULNERABLE"} with NO
    verdict. On pristine, :319's ``r.get("finding", r.get("verdict","error")
    .lower())`` takes the present-key branch and returns "VULNERABLE"
    UN-lowercased -> not in the counts dict -> dropped. Also RED on fa2-alone,
    which never touched :319. GREEN only on the canonical read that lowercases a
    present finding too.
    """
    from core.verifier import _write_verified_results

    present_upper = {"finding": "VULNERABLE", "verification": {"agree": True}}
    experiment = {"dataset": "d", "model": "m", "timestamp": "t"}
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "results_verified.json")
        _write_verified_results(path, experiment, [present_upper], [present_upper])
        with open(path) as fh:
            out = json.load(fh)
    assert out["metrics"]["vulnerable"] == 1, (
        f"present-uppercase VULNERABLE dropped from :319 metrics recount: "
        f"{out['metrics']}"
    )


if __name__ == "__main__":
    test_verdictonly_vulnerable_counted_as_confirmed()
    test_verdictonly_vulnerable_kept_in_confirmed_findings()
    test_present_uppercase_finding_counted_in_metrics()
    print("PASS")
