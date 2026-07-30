"""
Conformance test for the verifier-casing security false-negative.

Bug: a model may emit a Stage-1 result whose ``finding`` field is capitalized
(e.g. ``"Vulnerable"``). The Stage-2 verifier gate (core/verifier.py:99) and
the reporter confirmed-findings gate (core/reporter.py:256) compare that value
against the lowercase literals ``("vulnerable", "bypassable")``:

    r.get("finding", r.get("verdict", "").lower()) in ("vulnerable", "bypassable")

An un-normalized ``"Vulnerable"`` is NOT in that tuple, so a genuine vulnerable
finding is silently DROPPED before Stage-2 verification -- a security FN.

The ingestion-side fix normalizes the finding casing to lowercase where it is
first materialized:
  * core/analyzer.py  _process_unit  -- lowercase an existing finding (not only
    the verdict-fallback branch);
  * utilities/json_corrector.py  attempt_correction -- lowercase extracted
    ['finding'] instead of preserving it verbatim.
Both are RECOVER-ONLY: they lowercase an existing string and never manufacture
a vulnerable verdict.

This test drives the REAL ingestion path (_process_unit) with a stubbed
analyze_unit that returns a capitalized finding, then applies the exact
verifier.py:99 gate expression to the produced result.

    RED  on pristine core: finding stays "Vulnerable" -> gate drops it.
    GREEN on patched core: finding normalized to "vulnerable" -> gate keeps it.

Select the core under test with OPENANT_CORE_ROOT (defaults to pristine).
"""

import os
import sys
from pathlib import Path


_CORE_ROOT = os.environ.get(
    "OPENANT_CORE_ROOT",
    str(Path(__file__).resolve().parent.parent),
)
if _CORE_ROOT not in sys.path:
    sys.path.insert(0, _CORE_ROOT)


# The exact filter expression used at core/verifier.py:99 and (structurally)
# core/reporter.py:256 on the pristine tree. Replicated verbatim so the test
# measures what the real gate would decide about the produced result.
def _verifier_gate(r):
    return r.get("finding", r.get("verdict", "").lower()) in ("vulnerable", "bypassable")


def _run():
    import core.analyzer as analyzer

    # Stub analyze_unit to mimic a model that emitted a CAPITALIZED finding.
    def _fake_analyze_unit(binding, unit, **kwargs):
        return {"verdict": "VULNERABLE", "finding": "Vulnerable",
                "route_key": unit.get("id"), "vulnerabilities": []}

    original = analyzer.analyze_unit
    analyzer.analyze_unit = _fake_analyze_unit
    try:
        out = analyzer._process_unit(
            binding=None,
            unit={"id": "unit_0", "code": {"primary_code": "sink(user_input)"}},
            index=0,
            json_corrector=None,
            app_context=None,
        )
    finally:
        analyzer.analyze_unit = original

    result = out["result"]

    # 1) Ingestion must have normalized the finding casing.
    assert result.get("finding") == "vulnerable", (
        f"ingestion left finding un-normalized: {result.get('finding')!r} "
        f"(security FN -- verifier gate would drop it)"
    )

    # 2) The result must survive the real verifier.py:99 gate into Stage-2.
    assert _verifier_gate(result), (
        f"result dropped by verifier gate; finding={result.get('finding')!r}"
    )

    # 3) json_corrector must also lowercase an extracted capitalized finding.
    from utilities.json_corrector import JSONCorrector
    import utilities.json_corrector as jc

    jc.extract_json_with_llm = lambda binding, raw: {
        "finding": "Vulnerable", "confidence": 90, "vulnerabilities": [],
    }
    corrected = JSONCorrector(binding=None).attempt_correction("{ broken")
    assert corrected.get("finding") == "vulnerable", (
        f"json_corrector preserved capitalized finding: {corrected.get('finding')!r}"
    )
    assert _verifier_gate(corrected), "corrected result dropped by verifier gate"

    print("PASS: capitalized 'Vulnerable' finding survives ingestion + verifier gate")


if __name__ == "__main__":
    _run()
