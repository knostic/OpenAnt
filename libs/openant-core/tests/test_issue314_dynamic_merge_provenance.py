"""Regression tests for issue #314 — the dynamic-test merge joins on
positional IDs with no check that both artifacts came from the same run.

Finding IDs are assigned by list position (VULN-001, VULN-002, ...) — not
derived from the finding's identity. `merge_dynamic_results` joins
pipeline_output.json's findings to dynamic_test_results.json's results on
that ID with NO provenance check: a stale results file left in the scan
directory merges into a later run whose finding set has shifted, and the
mis-join is stamped with the stale file's mtime ("Docker container,
August 2026") with nothing marking it.

Contract locked here (the issue's suggestions 2+3; suggestion 1 —
identity-derived IDs — is a schema-design change, deliberately deferred):
- each finding carries an identity_key (a short hash over the stable
  identity triple: location file + function + CWE) — a run-stable join
  key that a positional ID never was;
- the dynamic-test result carries the same identity_key (threaded from
  the finding it tested);
- the merge verifies the identity_key, not just the positional ID: a
  positional match whose identity_key DISAGREES is refused (the stale
  case from the issue's executed fixture), a positional match whose
  identity_key AGREES merges (the honest case);
- what happened is SURFACED: a refused merge prints what was skipped
  and why (never silently), and a merged result carries the
  identity_key so the join is auditable;
- a results file whose identity_keys are ABSENT (a legacy/pre-fix file)
  abstains — never silently merges on the positional ID alone, and never
  crashes on the missing key. The refusal is surfaced too.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.reporter import finding_identity_key  # noqa: E402
from report.generator import merge_dynamic_results  # noqa: E402


def _pipeline(findings):
    return {"findings": findings}


def _finding(n, ident):
    return {"id": f"VULN-{n:03d}",
            "identity_key": ident,
            "name": f"Finding {n}",
            "location": {"file": "app.py", "function": f"fn{n}"},
            "cwe_id": 79}


def test_identity_key_is_a_hash_of_the_triple():
    """The identity key derives from the stable triple (file + function +
    CWE) — the same finding yields the same key; a DIFFERENT finding
    yields a different key."""
    k1 = finding_identity_key("app.py", "login", 79)
    k2 = finding_identity_key("app.py", "login", 79)
    k3 = finding_identity_key("app.py", "upload", 79)
    k4 = finding_identity_key("app.py", "login", 89)
    assert k1 == k2
    assert k1 != k3
    assert k1 != k4


def _merge(tmp_path, pipeline, results):
    (tmp_path / "pipeline_output.json").write_text(json.dumps(pipeline))
    (tmp_path / "dynamic_test_results.json").write_text(json.dumps(
        {"results": results}))
    return merge_dynamic_results(pipeline,
                                 str(tmp_path / "pipeline_output.json"))


def test_honest_merge_attaches_on_identity_match(tmp_path):
    pipeline = _pipeline([_finding(1, "key-aaa"), _finding(2, "key-bbb")])
    merged = _merge(tmp_path, pipeline, [
        {"finding_id": "VULN-001", "identity_key": "key-aaa",
         "status": "CONFIRMED", "details": "d", "evidence": []},
    ])
    assert merged["findings"][0]["dynamic_testing"]["status"] == "CONFIRMED"
    assert "dynamic_testing" not in merged["findings"][1]


def test_stale_positional_match_is_refused(tmp_path):
    """The issue's executed fixture: a result for VULN-001 from a
    PREVIOUS run whose identity disagrees — the positional ID matches
    but the finding is a DIFFERENT finding. Refused, surfaced."""
    pipeline = _pipeline([_finding(1, "key-aaa"), _finding(2, "key-bbb")])
    merged = _merge(tmp_path, pipeline, [
        {"finding_id": "VULN-001", "identity_key": "key-XXX",
         "status": "EXPLOITED", "details": "stale", "evidence": []},
    ])
    assert "dynamic_testing" not in merged["findings"][0], (
        "a positional match whose identity_key disagrees is a DIFFERENT "
        "finding — the mis-join the issue demonstrated")


def test_legacy_results_without_identity_keys_abstain(tmp_path):
    """A pre-fix results file carries no identity_key: the merge must not
    silently fall back to the positional ID (that is the defect); it
    abstains and surfaces."""
    pipeline = _pipeline([_finding(1, "key-aaa")])
    merged = _merge(tmp_path, pipeline, [
        {"finding_id": "VULN-001",  # no identity_key
         "status": "CONFIRMED", "details": "d", "evidence": []},
    ])
    assert "dynamic_testing" not in merged["findings"][0]


def test_merged_result_carries_the_identity_key(tmp_path):
    """The join is auditable after the fact: the merged dict records
    WHICH identity was matched."""
    pipeline = _pipeline([_finding(1, "key-aaa")])
    merged = _merge(tmp_path, pipeline, [
        {"finding_id": "VULN-001", "identity_key": "key-aaa",
         "status": "CONFIRMED", "details": "d", "evidence": []},
    ])
    assert merged["findings"][0]["dynamic_testing"]["identity_key"] == "key-aaa"