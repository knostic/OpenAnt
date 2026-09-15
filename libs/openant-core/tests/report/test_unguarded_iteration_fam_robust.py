"""FAM-ROBUST regression: unguarded iteration over model-supplied lists.

Distinct from the already-fixed *guarded-then-.get* class (a ``.get()`` on a
value returned with a default, e.g. ``finding.get("verification", {}).get(...)``).

This class is: ``core.reporter`` iterates a **model-supplied list**
(``results`` / ``confirmed_findings``) and calls ``.get()`` on **each element**
with no ``isinstance(el, dict)`` guard. A non-Anthropic model can emit a bare
string / number where a finding dict is expected (the same provider-fidelity
gap that motivated ``_coerce_to_str``). The first ``.get()`` then raises
``AttributeError: 'str' object has no attribute 'get'`` and report generation
crashes instead of skipping the malformed element.

Enumerated sites exercised here:
  * D — the manual ``confirmed`` filter over ``all_results``
        (``str(r.get("finding") ...)``), no-confirmed_findings path.
  * E — the top-level ``for finding in confirmed`` loop (``finding.get(...)``).
  * F — the ``full_result = next((r for r in all_results ...))`` lookup.
  * A/B/C — ``_dedup_caller_callee`` iterating ``confirmed`` / ``all_results``.
"""

from __future__ import annotations

import json
from pathlib import Path


from core.reporter import _dedup_caller_callee, build_pipeline_output
from utilities.file_io import write_json


def _write_results(tmp_path: Path, results: dict) -> Path:
    p = tmp_path / "results.json"
    write_json(p, results)
    return p


def test_bare_string_in_results_no_confirmed_findings(tmp_path: Path):
    """SITE D: manual confirmed-filter over ``results`` skips non-dict elements."""
    results = {
        "dataset": "fam-robust",
        "code_by_route": {},
        "metrics": {},
        # No confirmed_findings -> the manual filter iterates `results`.
        "results": [
            "a bare string a non-Anthropic model emitted",  # non-dict -> would crash r.get()
            {
                "route_key": "app.py:foo",
                "unit_id": "app.py:foo",
                "verdict": "vulnerable",
                "finding": "vulnerable",
            },
        ],
    }
    results_path = _write_results(tmp_path, results)
    out_path = tmp_path / "pipeline_output.json"

    out, count = build_pipeline_output(
        results_path=str(results_path),
        output_path=str(out_path),
        language="python",
        repo_name="test/repo",
    )
    data = json.loads(Path(out).read_text())
    # The one real dict finding survives; the bare string is skipped.
    assert count == 1
    assert len(data["findings"]) == 1


def test_bare_string_in_confirmed_findings(tmp_path: Path):
    """SITE E: the top-level ``for finding in confirmed`` loop skips non-dicts."""
    results = {
        "dataset": "fam-robust",
        "code_by_route": {"app.py:foo": "def foo(): pass"},
        "metrics": {},
        "results": [],
        "confirmed_findings": [
            12345,  # non-dict -> would crash finding.get()
            {
                "route_key": "app.py:foo",
                "unit_id": "app.py:foo",
                "verdict": "vulnerable",
                "finding": "vulnerable",
            },
        ],
    }
    results_path = _write_results(tmp_path, results)
    out_path = tmp_path / "pipeline_output.json"

    out, count = build_pipeline_output(
        results_path=str(results_path),
        output_path=str(out_path),
        language="python",
        repo_name="test/repo",
    )
    data = json.loads(Path(out).read_text())
    assert count == 1
    assert len(data["findings"]) == 1


def test_bare_string_in_results_during_full_result_lookup(tmp_path: Path):
    """SITE F: ``full_result = next((r for r in all_results ...))`` skips non-dicts."""
    results = {
        "dataset": "fam-robust",
        "code_by_route": {},
        "metrics": {},
        "results": [
            ["not", "a", "dict"],  # non-dict list element -> would crash r.get()
            {
                "route_key": "app.py:foo",
                "unit_id": "app.py:foo",
                "verdict": "vulnerable",
                "finding": "vulnerable",
                "cwe_id": 89,
            },
        ],
        # confirmed_findings present so the main loop's full_result lookup
        # iterates the (dirty) all_results list.
        "confirmed_findings": [
            {
                "route_key": "app.py:foo",
                "unit_id": "app.py:foo",
                "verdict": "vulnerable",
                "finding": "vulnerable",
            }
        ],
    }
    results_path = _write_results(tmp_path, results)
    out_path = tmp_path / "pipeline_output.json"

    out, count = build_pipeline_output(
        results_path=str(results_path),
        output_path=str(out_path),
        language="python",
        repo_name="test/repo",
    )
    data = json.loads(Path(out).read_text())
    assert count == 1
    assert data["findings"][0]["cwe_id"] == 89


def test_dedup_helper_standalone_with_non_dict_elements(tmp_path: Path):
    """SITES A/B/C: ``_dedup_caller_callee`` is self-defensive against non-dicts."""
    call_graph = {
        "reverse_call_graph": {
            "app.py:run_query": ["app.py:get_user"],
        }
    }
    cg_path = tmp_path / "call_graph.json"
    cg_path.write_text(json.dumps(call_graph))

    confirmed = [
        "bare string in confirmed",  # non-dict -> would crash f.get()
        {"route_key": "app.py:get_user", "unit_id": "app.py:get_user", "cwe_id": 89},
        {"route_key": "app.py:run_query", "unit_id": "app.py:run_query", "cwe_id": 89},
    ]
    all_results = [
        None,  # non-dict -> would crash r.get() in the cwe-lookup generator
        {"route_key": "app.py:get_user", "unit_id": "app.py:get_user", "cwe_id": 89},
        {"route_key": "app.py:run_query", "unit_id": "app.py:run_query", "cwe_id": 89},
    ]

    # Must not raise; the callee (run_query) is collapsed into its caller.
    deduped = _dedup_caller_callee(confirmed, all_results, str(cg_path))
    keys = {d.get("route_key") for d in deduped}
    assert "app.py:get_user" in keys
    assert "app.py:run_query" not in keys  # collapsed
