"""#319: a failed dynamic test must not render as a verification.

``merge_dynamic_results`` attached a ``dynamic_testing`` block to a finding whenever a
dynamic-test result existed for its ID, **with no filter on the result's status** — and both
consumers of the block (the summary table's "Verified" column and the disclosure document's
"Verified via" line) key on its **existence**. A finding whose Docker test ERRORED or was
NOT_REPRODUCED therefore rendered as "Verified via dynamic testing" in the externally-facing
disclosure; the block's unconditional ``"tested": "Docker container, <Month Year>"`` asserted
a container run that never happened.

The fix (the issue's own suggestions, composing with #414's identity gate which still runs
first and unchanged):
- the full ``dynamic_testing`` block (with the ``tested`` Docker string) attaches ONLY for
  ``status == "CONFIRMED"``;
- every other status (ERROR, NOT_REPRODUCED, INCONCLUSIVE, BLOCKED, unknown) attaches a
  separate ``dynamic_testing_attempted`` block — the transparency without the verification
  claim, so a template cannot render a failed test as a verification by omission;
- both templates branch on the two blocks; the disclosure header stamps the dynamic dimension
  deterministically.
"""
import json
import sys
import tempfile
from pathlib import Path

import pytest

CORE = str(Path(__file__).resolve().parents[2])  # libs/openant-core
if CORE not in sys.path:
    sys.path.insert(0, CORE)

from report.generator import (  # noqa: E402
    merge_dynamic_results, _disclosure_verdict_header,
)


def _run_merge(pipeline_findings, results):
    """The real merge over a real temp scan dir (the results file must be
    named dynamic_test_results.json beside the pipeline output)."""
    with tempfile.TemporaryDirectory() as d:
        pp = Path(d) / "pipeline_output.json"
        pp.write_text(json.dumps({"findings": pipeline_findings}))
        (Path(d) / "dynamic_test_results.json").write_text(
            json.dumps({"results": results}))
        data = {"findings": [dict(f) for f in pipeline_findings]}
        merge_dynamic_results(data, str(pp))
        return data["findings"]


_FINDINGS = [
    {"id": "VULN-001", "identity_key": "a"},
    {"id": "VULN-002", "identity_key": "b"},
    {"id": "VULN-003", "identity_key": "c"},
]
_RESULTS = [
    {"finding_id": "VULN-001", "identity_key": "a", "status": "ERROR",
     "details": "generation failed"},
    {"finding_id": "VULN-002", "identity_key": "b", "status": "NOT_REPRODUCED",
     "details": "container ran, no repro"},
    {"finding_id": "VULN-003", "identity_key": "c", "status": "CONFIRMED",
     "details": "exploited", "evidence": ["step 1"]},
]


def test_only_confirmed_carries_the_verification_block():
    """The issue's executed fixture: ERROR / NOT_REPRODUCED / CONFIRMED —
    the verification block attaches ONLY for CONFIRMED."""
    out = _run_merge(_FINDINGS, _RESULTS)
    by_id = {f["id"]: f for f in out}
    assert "dynamic_testing" in by_id["VULN-003"]
    assert "dynamic_testing" not in by_id["VULN-001"]
    assert "dynamic_testing" not in by_id["VULN-002"]


def test_attempted_block_carries_the_transparency():
    """Every non-CONFIRMED status attaches dynamic_testing_attempted (the
    status visible), never the verification claim."""
    out = _run_merge(_FINDINGS, _RESULTS)
    by_id = {f["id"]: f for f in out}
    for fid, status in (("VULN-001", "ERROR"), ("VULN-002", "NOT_REPRODUCED")):
        att = by_id[fid].get("dynamic_testing_attempted")
        assert att, fid
        assert att["status"] == status
        assert "tested" not in att, fid          # no container claim
        assert att.get("attempted"), fid          # the date-stamped attempt


def test_tested_only_when_a_container_ran():
    """The unconditional "Docker container, <Month Year>" asserted a run that
    never happened — the string appears ONLY in the CONFIRMED block."""
    out = _run_merge(_FINDINGS, _RESULTS)
    by_id = {f["id"]: f for f in out}
    assert "Docker container" in by_id["VULN-003"]["dynamic_testing"]["tested"]
    for fid in ("VULN-001", "VULN-002"):
        blk = by_id[fid].get("dynamic_testing_attempted", {})
        assert "Docker container" not in str(blk), fid


def test_identity_gate_unchanged():
    """#414's gate still runs first: a refused (identity-mismatch) result
    attaches NOTHING (neither block); the legacy abstain path unchanged."""
    results = [
        {"finding_id": "VULN-001", "identity_key": "WRONG", "status": "CONFIRMED"},
        {"finding_id": "VULN-002", "status": "CONFIRMED"},          # no key: abstain
    ]
    out = _run_merge([_FINDINGS[0], _FINDINGS[1]], results)
    by_id = {f["id"]: f for f in out}
    assert "dynamic_testing" not in by_id["VULN-001"]
    assert "dynamic_testing_attempted" not in by_id["VULN-001"]
    assert "dynamic_testing" not in by_id["VULN-002"]


def test_disclosure_header_stamps_the_dynamic_dimension():
    """The deterministic banner: CONFIRMED-by-dynamic-testing stamps first;
    an attempted-but-failed stamps NOT-confirmed, before the Stage-2/static
    logic; a clean static finding keeps the existing wording."""
    confirmed = {"stage2_verdict": "confirmed",
                 "dynamic_testing": {"status": "CONFIRMED"},
                 "stage1_verdict": "vulnerable"}
    h = _disclosure_verdict_header(confirmed)
    assert "dynamic testing" in h.lower() and "CONFIRMED" in h

    failed = {"stage2_verdict": "confirmed",
             "dynamic_testing_attempted": {"status": "ERROR"},
             "stage1_verdict": "vulnerable"}
    h2 = _disclosure_verdict_header(failed)
    assert "NOT confirmed by dynamic testing" in h2, h2
    assert "ERROR" in h2

    static_only = {"stage2_verdict": "confirmed", "stage1_verdict": "vulnerable"}
    h3 = _disclosure_verdict_header(static_only)
    assert "dynamic" not in h3.lower(), h3


def test_templates_branch_on_the_two_blocks():
    """The summary's Verified column and the disclosure's Verified-via line
    must name the ATTEMPTED block's failed wording — never the verified
    wording for a failed test."""
    summary = (Path(__file__).resolve().parents[1] / "report" / "prompts"
               / "summary.txt").read_text()
    assert "dynamic_testing_attempted" in summary
    disclosure = (Path(__file__).resolve().parents[1] / "report" / "prompts"
                  / "disclosure.txt").read_text()
    assert "dynamic_testing_attempted" in disclosure


def test_schema_accepts_the_attempted_field():
    """Old artifacts (no attempted field) validate; new ones carry it."""
    from report.schema import Finding

    base = {"id": "VULN-001", "name": "v", "short_name": "V",
            "location": {"file": "a.py", "function": "f"},
            "cwe_id": 79, "cwe_name": "XSS",
            "stage1_verdict": "vulnerable", "stage2_verdict": "confirmed"}
    assert Finding.from_dict(base).dynamic_testing_attempted is None
    new = Finding.from_dict({**base,
                             "dynamic_testing_attempted": {"status": "ERROR"}})
    assert new.dynamic_testing_attempted == {"status": "ERROR"}


def test_attempted_block_reaches_the_summary_llm():
    """The e2e-caught gap: _compact_for_summary passed only dynamic_testing —
    the summary doc rendered the failed tests as "static" (safe, but the
    failure invisible). The attempted block must reach the LLM."""
    from report.generator import _compact_for_summary

    data = {"findings": [{
        "id": "VULN-001",
        "dynamic_testing_attempted": {"status": "ERROR", "attempted": "August 2026"},
    }]}
    compact = _compact_for_summary(data)
    assert compact["findings"][0]["dynamic_testing_attempted"]["status"] == "ERROR"


def test_skipped_attaches_nothing():
    """Wave r1: SKIPPED is "never executed" (models.py: distinct from ERROR)
    — attaching an attempted block would be the mirror of the defect this
    issue fixes (asserting a container action that never happened,
    inverted). SKIPPED attaches nothing."""
    results = [{"finding_id": "VULN-001", "identity_key": "a",
                "status": "SKIPPED", "details": "no harness for the language"}]
    out = _run_merge([_FINDINGS[0]], results)
    f = out[0]
    assert "dynamic_testing" not in f and "dynamic_testing_attempted" not in f


def test_null_status_normalised_both_surfaces_agree():
    """Wave r1: a model-supplied record with NO status must not render
    "failed (None)" in one surface while the header omits the dimension —
    normalised to UNKNOWN at the merge."""
    results = [{"finding_id": "VULN-001", "identity_key": "a",
                "details": "malformed: no status"}]
    out = _run_merge([_FINDINGS[0]], results)
    att = out[0].get("dynamic_testing_attempted")
    assert att and att["status"] == "UNKNOWN", att
    h = _disclosure_verdict_header({
        "stage2_verdict": "confirmed", "stage1_verdict": "vulnerable",
        "dynamic_testing_attempted": att})
    assert "UNKNOWN" in h  # the header agrees with the attempted block
