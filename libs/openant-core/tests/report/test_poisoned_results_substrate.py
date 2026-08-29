"""fa17 POISONED-SUBSTRATE E2E: normalize model-supplied `results` at TRUST BOUNDARIES.

OpenAnt reads model-produced JSON (experiment_results.json, dynamic_test_results.json)
and iterates the `results` array in ~20 places doing bare `r.get(...)`. A non-Anthropic
model can emit a NON-DICT element (bare string / number / None / nested list) — or a
non-list value for `results` itself — and the first `.get()` raises AttributeError,
aborting verify / report / CSV.

Per-loop `isinstance` guards (fa15 in reporter.py, fa16 in the 4 sibling emitters) did
NOT converge: they missed the upstream verifier (verify runs BEFORE report, so it
crashes first), the cli dynamic-test path, and report/generator's dynamic merge.

fa17's design: normalize ONCE at each load boundary via
`utilities.file_io.normalize_results(obj)`, mutating `obj["results"]` in place to a
list of dicts-only. Every downstream count AND iterator then sees the same filtered
list. This test drives EVERY public entry point that loads such JSON with a poisoned
substrate and asserts (a) no crash, (b) only valid dicts propagate, (c) counts match
the valid-dict count.

RED (against the 62-set base, without fa17):
  * core.verifier.run_verification    -> AttributeError at the vulnerable-filter (FIRST crash)
  * report.generator.merge_dynamic_results -> AttributeError at result.get("finding_id")
  * cli.cmd_report_data (dynamic path) -> AttributeError at dr.get("finding_id")
  * cli.cmd_report_data (experiment)   -> stats.total_units counts the RAW poisoned list
                                          (== 5) instead of the valid-dict count (== 1)
GREEN (with fa17): all pass.
"""

from __future__ import annotations

import ast
import json
import types
from pathlib import Path

import pytest

from utilities.file_io import normalize_results


# ---------------------------------------------------------------------------
# Poisoned substrates. One valid dict + the full non-dict zoo the task names:
# bare string, number, None, nested list.
# ---------------------------------------------------------------------------
def _valid_result(verdict: str) -> dict:
    return {
        "route_key": "app/api.py:handler",
        "unit_id": "app/api.py:handler",
        "finding": verdict,
        "verdict": verdict,
        "attack_vector": "prompt-injection",
        "reasoning": "r",
        "verification": {"correct_finding": verdict},
    }


def _poison_results(verdict: str) -> list:
    return [
        _valid_result(verdict),
        "a bare string a non-Anthropic model emitted",
        123,
        None,
        ["a", "nested", "list"],
    ]


def _experiment(verdict: str) -> dict:
    return {
        "dataset": "poison-substrate",
        "code_by_route": {"app/api.py:handler": "def handler(): ..."},
        "metrics": {},
        "results": _poison_results(verdict),
    }


DATASET = {
    "units": [
        {
            "id": "app/api.py:handler",
            "code": {"primary_code": "def handler(): ..."},
            "llm_context": {"reasoning": "context"},
        }
    ]
}

# Dynamic-test schema (separate schema, same `results` key + same poison).
DYNAMIC_POISON = {
    "results": [
        {
            "finding_id": "VULN-001",
            "identity_key": "k",
            "status": "CONFIRMED",
            "details": "reproduced",
            "evidence": ["step-1"],
        },
        "bare string in dynamic results",
        456,
        None,
        ["nested"],
    ]
}

PIPELINE_OUTPUT = {
    "repository": {"name": "poison/repo"},
    "findings": [
        # #314: identity_key is the verified join key (VULN-NNN is
        # positional); the fixture reflects the new artifact shape.
        {"id": "VULN-001", "identity_key": "k",
         "location": {"function": "app/api.py:handler"}}
    ],
}


# ---------------------------------------------------------------------------
# 0. The helper itself, incl. the malformed top-level (non-list) results.
# ---------------------------------------------------------------------------
def test_normalize_results_filters_non_dicts():
    obj = _experiment("vulnerable")
    normalize_results(obj)
    assert obj["results"] == [_valid_result("vulnerable")]
    assert all(isinstance(r, dict) for r in obj["results"])


def test_normalize_results_non_list_becomes_empty():
    obj = {"results": "not a list at all"}
    normalize_results(obj)
    assert obj["results"] == []


def test_normalize_results_missing_key_and_non_dict_obj():
    obj = {}
    normalize_results(obj)
    assert obj["results"] == []
    # A non-dict container is returned untouched (nothing to normalize).
    assert normalize_results("not even a dict") == "not even a dict"


# ---------------------------------------------------------------------------
# 1. EXPERIMENT boundary: core.verifier.run_verification (verify path).
#    The valid dict is `safe` so `findings_input == 0` and run_verification
#    early-returns BEFORE any LLM/registry/index work — hermetic.
#    RED at base: AttributeError at the vulnerable/bypassable filter.
# ---------------------------------------------------------------------------
def test_verifier_verify_path_survives_poison(tmp_path: Path):
    from core.verifier import run_verification

    exp = tmp_path / "results.json"
    exp.write_text(json.dumps(_experiment("safe")))
    out_dir = tmp_path / "verify_out"

    result = run_verification(
        results_path=str(exp),
        output_dir=str(out_dir),
        analyzer_output_path=str(tmp_path / "analyzer_output.json"),  # unused on early-return
    )
    assert result.findings_input == 0  # no vulnerable/bypassable -> hermetic early return

    written = json.loads((out_dir / "results_verified.json").read_text())
    assert all(isinstance(r, dict) for r in written["results"])
    assert len(written["results"]) == 1  # only the one valid dict survived


# ---------------------------------------------------------------------------
# 2. EXPERIMENT boundary: reporter.build_pipeline_output.
# ---------------------------------------------------------------------------
def test_reporter_build_pipeline_output_survives_poison(tmp_path: Path):
    from core.reporter import build_pipeline_output

    exp = tmp_path / "results.json"
    exp.write_text(json.dumps(_experiment("vulnerable")))
    out = tmp_path / "pipeline_output.json"

    out_path, findings_count = build_pipeline_output(str(exp), str(out))
    assert findings_count == 1  # exactly the one valid vulnerable dict
    data = json.loads(Path(out_path).read_text())
    assert len(data["findings"]) == 1


# ---------------------------------------------------------------------------
# 3. EXPERIMENT boundary: export_csv.export_csv.
# ---------------------------------------------------------------------------
def test_export_csv_survives_poison(tmp_path: Path):
    import report.csv_export as export_csv

    exp = tmp_path / "results.json"
    ds = tmp_path / "dataset.json"
    out = tmp_path / "out.csv"
    exp.write_text(json.dumps(_experiment("vulnerable")))
    ds.write_text(json.dumps(DATASET))

    export_csv.export_csv(str(exp), str(ds), str(out))
    lines = [ln for ln in out.read_text().splitlines() if ln.strip()]
    assert len(lines) == 2  # header + exactly one data row (4 poison elements dropped)


# ---------------------------------------------------------------------------
# 4. EXPERIMENT boundary: generate_report.main (drives load boundary at :824).
#    Remediation is the only LLM call -> monkeypatched so the test is hermetic.
# ---------------------------------------------------------------------------
def test_generate_report_main_survives_poison(tmp_path: Path, monkeypatch, capsys):
    import report.html_report as generate_report

    exp = tmp_path / "results.json"
    ds = tmp_path / "dataset.json"
    out = tmp_path / "report.html"
    exp.write_text(json.dumps(_experiment("vulnerable")))
    ds.write_text(json.dumps(DATASET))

    monkeypatch.setattr(generate_report, "generate_remediation_guidance", lambda findings: "")
    monkeypatch.setattr("sys.argv", ["generate_report", str(exp), str(ds), str(out)])

    generate_report.main()
    assert out.exists()

    # main() prints "Summary: {<verdict counts>}" — parse it and assert the
    # count reflects only the 1 valid dict, never the 5 raw elements.
    summary_line = next(
        ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("Summary:")
    )
    counts = ast.literal_eval(summary_line.split("Summary:", 1)[1].strip())
    assert counts == {"vulnerable": 1}


# ---------------------------------------------------------------------------
# 5. EXPERIMENT boundary + STAT FIX: cli.cmd_report_data.
#    Valid dict is `safe` -> non-actionable -> no LLM. RED at base: total_units
#    counts the raw poisoned list (5) instead of the valid-dict count (1).
# ---------------------------------------------------------------------------
def test_cli_report_data_stat_matches_valid_count(tmp_path: Path, capsys):
    from openant import cli

    exp = tmp_path / "results.json"
    ds = tmp_path / "dataset.json"
    exp.write_text(json.dumps(_experiment("safe")))
    ds.write_text(json.dumps(DATASET))

    args = types.SimpleNamespace(results=str(exp), dataset=str(ds))
    rc = cli.cmd_report_data(args)
    assert rc == 0

    payload = json.loads(capsys.readouterr().out.strip())
    stats = payload["data"]["stats"]
    findings = payload["data"]["findings"]
    assert stats["total_units"] == 1  # RED at base == 5 (counts poison)
    assert stats["total_units"] == len(findings)  # count invariant restored


# ---------------------------------------------------------------------------
# 6. DYNAMIC boundary: report.generator.merge_dynamic_results.
#    RED at base: AttributeError at result.get("finding_id") on the bare string.
# ---------------------------------------------------------------------------
def test_report_generator_dynamic_path_survives_poison(tmp_path: Path):
    from report.generator import merge_dynamic_results

    pipeline_path = tmp_path / "pipeline_output.json"
    pipeline_path.write_text(json.dumps(PIPELINE_OUTPUT))
    (tmp_path / "dynamic_test_results.json").write_text(json.dumps(DYNAMIC_POISON))

    merged = merge_dynamic_results(json.loads(json.dumps(PIPELINE_OUTPUT)), str(pipeline_path))
    finding = merged["findings"][0]
    assert finding["dynamic_testing"]["status"] == "CONFIRMED"  # only valid dynamic dict merged


# ---------------------------------------------------------------------------
# 7. DYNAMIC boundary: cli.cmd_report_data dynamic path (dt_data loop).
#    Both dynamic_test_results.json AND pipeline_output.json present triggers it.
#    RED at base: AttributeError at dr.get("finding_id") on the bare string.
# ---------------------------------------------------------------------------
def test_cli_report_data_dynamic_path_survives_poison(tmp_path: Path, capsys):
    from openant import cli

    exp = tmp_path / "results.json"
    ds = tmp_path / "dataset.json"
    exp.write_text(json.dumps(_experiment("safe")))
    ds.write_text(json.dumps(DATASET))
    (tmp_path / "dynamic_test_results.json").write_text(json.dumps(DYNAMIC_POISON))
    (tmp_path / "pipeline_output.json").write_text(json.dumps(PIPELINE_OUTPUT))

    args = types.SimpleNamespace(results=str(exp), dataset=str(ds))
    rc = cli.cmd_report_data(args)
    assert rc == 0  # RED at base: crashes in the dt_data loop -> rc == 2

    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["data"]["stats"]["total_units"] == 1
