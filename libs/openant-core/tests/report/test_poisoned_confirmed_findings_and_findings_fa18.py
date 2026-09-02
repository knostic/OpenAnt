"""fa18 POISONED-SUBSTRATE: normalize `confirmed_findings` and `findings` at load.

fa17 normalized the model `results` array at 7 load boundaries. An adversarial
enumeration of EVERY model-JSON array-of-dict key iterated with `element.get()`
at a disk-load boundary found two more keys fa17 did NOT cover:

  * ``confirmed_findings`` -- reporter.build_pipeline_output reads it from the
    SAME results_verified.json trust boundary as ``results``. fa15 added a
    LIST-element guard (``[c for c in confirmed if isinstance(c, dict)]``), but
    that guard itself iterates ``confirmed``: a NON-LIST value (e.g. an int) a
    non-Anthropic model can emit raises ``TypeError`` at the guard. fa18
    normalizes the container at load so a non-list becomes ``[]``.
  * ``findings`` -- pipeline_output.json is our own generated output, but it is
    read back from disk (read_json) and iterated with ``finding.get(...)`` at
    every report/dynamic-test boundary (defense-in-depth boundary). A non-dict
    element raises ``AttributeError`` at the first ``.get()``.

RED (against the 63-set base, WITHOUT fa18):
  * reporter.build_pipeline_output(confirmed_findings=<int>) -> TypeError at the
    fa15 ``[c for c in confirmed]`` guard.
  * cli.cmd_report_data (dynamic path, poisoned pipeline_output findings) ->
    AttributeError at ``finding.get("id")`` -> rc == 2.
  * dynamic_tester.run_dynamic_tests(poisoned findings) -> AttributeError at the
    DYNAMIC_TESTABLE filter ``f.get("stage2_verdict")``.
  * reporter.generate_disclosure_docs(poisoned findings) -> AttributeError in
    merge_dynamic_results at ``finding.get("id")`` (runs before validation).
GREEN (with fa18): all pass -- non-dict elements dropped, non-list -> [].
"""

from __future__ import annotations

import json
import types
from pathlib import Path


from utilities.file_io import normalize_results, write_json


# ---------------------------------------------------------------------------
# 0. Helper-level: the existing normalize_results(obj, key) generalizes to the
#    two new keys (container-level filtering + non-list -> []).
# ---------------------------------------------------------------------------
def test_normalize_confirmed_findings_non_list_becomes_empty():
    obj = {"confirmed_findings": 12345}
    normalize_results(obj, "confirmed_findings")
    assert obj["confirmed_findings"] == []


def test_normalize_findings_filters_non_dicts():
    obj = {"findings": [{"id": "A"}, "bare string", 7, None, ["x"]]}
    normalize_results(obj, "findings")
    assert obj["findings"] == [{"id": "A"}]


# ---------------------------------------------------------------------------
# 1. confirmed_findings boundary: reporter.build_pipeline_output.
#    RED at base: confirmed_findings is a non-list int -> the fa15
#    `[c for c in confirmed]` guard raises TypeError.
# ---------------------------------------------------------------------------
def _experiment_with_confirmed(confirmed) -> dict:
    return {
        "dataset": "fa18",
        "code_by_route": {"app.py:foo": "def foo(): ..."},
        "metrics": {},
        "results": [],
        "confirmed_findings": confirmed,
    }


def test_build_pipeline_output_non_list_confirmed_findings(tmp_path: Path):
    from core.reporter import build_pipeline_output

    exp = tmp_path / "results.json"
    write_json(exp, _experiment_with_confirmed(12345))  # non-list -> TypeError at base
    out = tmp_path / "pipeline_output.json"

    out_path, count = build_pipeline_output(str(exp), str(out))
    # Poisoned container dropped to [] -> zero confirmed findings, no crash.
    assert count == 0
    data = json.loads(Path(out_path).read_text())
    assert data["findings"] == []


def test_build_pipeline_output_list_confirmed_findings_with_non_dicts(tmp_path: Path):
    """Defense-in-depth / no-regression: a LIST with non-dict elements (fa15's
    class) still yields exactly the valid dict."""
    from core.reporter import build_pipeline_output

    exp = tmp_path / "results.json"
    valid = {"route_key": "app.py:foo", "unit_id": "app.py:foo",
             "verdict": "vulnerable", "finding": "vulnerable"}
    write_json(exp, _experiment_with_confirmed([valid, "bare string", 99]))
    out = tmp_path / "pipeline_output.json"

    out_path, count = build_pipeline_output(str(exp), str(out))
    assert count == 1
    assert len(json.loads(Path(out_path).read_text())["findings"]) == 1


def test_build_pipeline_output_absent_confirmed_findings_uses_manual_filter(tmp_path: Path):
    """Regression guard for the presence-check: ABSENT confirmed_findings must
    keep falling through to the manual verdict filter over `results`."""
    from core.reporter import build_pipeline_output

    exp = tmp_path / "results.json"
    write_json(exp, {
        "dataset": "fa18",
        "code_by_route": {"app.py:foo": "def foo(): ..."},
        "metrics": {},
        "results": [{"route_key": "app.py:foo", "unit_id": "app.py:foo",
                     "verdict": "vulnerable", "finding": "vulnerable"}],
        # NO confirmed_findings key -> manual filter must run.
    })
    out = tmp_path / "pipeline_output.json"
    out_path, count = build_pipeline_output(str(exp), str(out))
    assert count == 1  # manual filter recovered the one vulnerable result


# ---------------------------------------------------------------------------
# 2. findings boundary: cli.cmd_report_data dynamic path (po_data findings).
#    RED at base: finding.get("id") on a bare string -> AttributeError -> rc 2.
# ---------------------------------------------------------------------------
_DATASET = {"units": [{"id": "app/api.py:handler",
                       "code": {"primary_code": "def handler(): ..."},
                       "llm_context": {"reasoning": "ctx"}}]}


def _safe_experiment() -> dict:
    return {
        "dataset": "fa18",
        "code_by_route": {"app/api.py:handler": "def handler(): ..."},
        "metrics": {},
        "results": [{"route_key": "app/api.py:handler", "unit_id": "app/api.py:handler",
                     "finding": "safe", "verdict": "safe",
                     "verification": {"correct_finding": "safe"}}],
    }


def test_cli_report_data_survives_poisoned_pipeline_findings(tmp_path: Path, capsys):
    from openant import cli

    exp = tmp_path / "results.json"
    ds = tmp_path / "dataset.json"
    exp.write_text(json.dumps(_safe_experiment()))
    ds.write_text(json.dumps(_DATASET))
    # Both files present -> cmd_report_data enters the dynamic branch.
    (tmp_path / "dynamic_test_results.json").write_text(
        json.dumps({"results": [{"finding_id": "VULN-001", "status": "CONFIRMED"}]}))
    (tmp_path / "pipeline_output.json").write_text(json.dumps({
        "repository": {"name": "poison/repo"},
        "findings": [
            "a bare string the model emitted",   # non-dict -> AttributeError at base
            {"id": "VULN-001", "location": {"function": "app/api.py:handler"}},
        ],
    }))

    args = types.SimpleNamespace(results=str(exp), dataset=str(ds))
    rc = cli.cmd_report_data(args)
    assert rc == 0  # RED at base: rc == 2 (AttributeError in the po_data findings loop)


# ---------------------------------------------------------------------------
# 3. findings boundary: utilities.dynamic_tester.run_dynamic_tests.
#    Driven hermetically with a dummy registry (skips probe/Docker). The one
#    valid dict is non-DYNAMIC_TESTABLE, so after filtering findings is empty
#    -> early return, no Docker. RED at base: f.get() on the bare string.
# ---------------------------------------------------------------------------
def test_run_dynamic_tests_survives_poisoned_findings(tmp_path: Path):
    from utilities.dynamic_tester import run_dynamic_tests

    pipeline = tmp_path / "pipeline_output.json"
    pipeline.write_text(json.dumps({
        "repository": {"name": "poison/repo", "language": "Python"},
        "application_type": "web_app",
        "findings": [
            "a bare string the model emitted",         # non-dict -> AttributeError at base
            {"id": "V1", "stage2_verdict": "safe"},    # dict, NOT dynamic-testable
        ],
    }))

    # Dict registry -> `registry.get("dynamic_test")` works, skips probe/Docker.
    out = run_dynamic_tests(str(pipeline), output_dir=str(tmp_path),
                            registry={"dynamic_test": None})
    assert out == []  # non-dict dropped; the safe dict filtered out -> early return


# ---------------------------------------------------------------------------
# 4. findings boundary: reporter.generate_disclosure_docs.
#    RED at base: merge_dynamic_results (runs BEFORE validation) does
#    finding.get("id") on the bare string -> AttributeError. GREEN: fa18
#    normalizes findings at load, before merge; the registry build is
#    monkeypatched so the no-eligible-findings path returns hermetically.
# ---------------------------------------------------------------------------
def test_generate_disclosure_docs_survives_poisoned_findings(tmp_path: Path, monkeypatch):
    import utilities.llm as _llm
    monkeypatch.setattr(_llm, "load_config_file", lambda *a, **k: {}, raising=False)
    monkeypatch.setattr(_llm, "resolve_llm_config", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(_llm, "build_phase_registry", lambda *a, **k: {"report": None}, raising=False)
    monkeypatch.setattr(_llm, "probe_registry_or_raise", lambda *a, **k: None, raising=False)

    from core.reporter import generate_disclosure_docs

    results_path = tmp_path / "pipeline_output.json"
    results_path.write_text(json.dumps({
        "repository": {"name": "poison/repo"},
        "analysis_date": "2026-01-01",
        "application_type": "web_app",
        "pipeline_stats": {},
        "results": {"vulnerable": 0, "safe": 1},
        "findings": [
            "a bare string the model emitted",   # non-dict -> AttributeError at base (in merge)
            {   # fully schema-valid but NOT disclosure-eligible ("safe")
                "id": "VULN-001", "name": "n", "short_name": "sn",
                "location": {"file": "app.py", "function": "app.py:foo"},
                "cwe_id": 0, "cwe_name": "unknown",
                "stage1_verdict": "safe", "stage2_verdict": "safe",
            },
        ],
    }))
    # Present so merge_dynamic_results iterates findings (results_by_id non-empty).
    (tmp_path / "dynamic_test_results.json").write_text(
        json.dumps({"results": [{"finding_id": "VULN-001", "status": "CONFIRMED",
                                 "details": "d", "evidence": []}]}))

    res = generate_disclosure_docs(str(results_path), str(tmp_path / "disclosures"))
    # No eligible ("safe") -> no disclosures generated, but NO crash.
    assert res.format == "disclosure"
