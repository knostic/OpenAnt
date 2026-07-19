"""Regression: a non-dict element in a finding's ``vulnerabilities`` list
must not crash ``build_pipeline_output``.

``reporter.py`` did ``vuln = vulns[0] if vulns else {}`` and then called
``vuln.get(...)``. The truthiness guard only proves the list is non-empty —
it does NOT prove ``vulns[0]`` is a dict. A model that returns
``vulnerabilities: ["some string"]`` (schema violation) made the first
``vuln.get("description")`` raise ``AttributeError: 'str' object has no
attribute 'get'`` and killed report generation.

Same defensive-coercion class as ``test_reporter_coercion.py`` (issue #65
follow-up); this pins the list-element isinstance guard at :283-284.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.reporter import build_pipeline_output
from utilities.file_io import write_json


def _run_build(tmp_path: Path, finding: dict) -> dict:
    results = {
        "dataset": "test",
        "code_by_route": {"app.py:foo": "def foo(): pass"},
        "metrics": {},
        "confirmed_findings": [{
            "route_key": "app.py:foo",
            "unit_id": "app.py:foo",
            "verdict": "VULNERABLE",
            "finding": "vulnerable",
            **finding,
        }],
    }
    results_path = tmp_path / "results.json"
    write_json(results_path, results)
    out_path = tmp_path / "pipeline_output.json"
    build_pipeline_output(
        results_path=str(results_path),
        output_path=str(out_path),
        language="python",
        repo_name="test/repo",
    )
    return json.loads(out_path.read_text())


def test_non_dict_vulnerabilities_element_does_not_crash(tmp_path):
    # vulnerabilities is truthy (non-empty) but vulns[0] is a bare string.
    # Old code: vuln = "not-a-dict"; vuln.get(...) -> AttributeError.
    out = _run_build(tmp_path, finding={
        "vulnerabilities": ["not-a-dict"],
        "reasoning": "fallback reasoning",
    })
    assert len(out["findings"]) == 1
    # The non-dict vuln is ignored; downstream falls back to finding fields.
    assert out["findings"][0]["description"] == "fallback reasoning"


def test_dict_vulnerabilities_element_still_read(tmp_path):
    # Well-formed dict element must still be consumed (no regression).
    out = _run_build(tmp_path, finding={
        "vulnerabilities": [{"description": "real vuln desc", "impact": "RCE"}],
    })
    assert out["findings"][0]["description"] == "real vuln desc"
    assert out["findings"][0]["impact"] == "RCE"
