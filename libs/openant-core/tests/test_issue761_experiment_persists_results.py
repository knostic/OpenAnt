"""#761 — ``experiment.py``'s ``main()`` must persist its results.

``run_experiment`` emits the analyze model under ``analyze_model``
(``experiment.py:734``, renamed there by PR #69) while ``print_summary``
subscripted ``experiment['model']`` (``experiment.py:755``) — a key no writer
in the repository emits. ``print_summary`` is called at ``:877`` and the run's
only ``write_json`` sits at ``:887``, so the unguarded read raised before the
results were ever written and a paid-for run was lost.

The LLM boundaries are stubbed, so these tests are offline and free; they drive
the real ``main()`` end to end and then assert on what was observed — the
exception that escaped and the ``write_json`` calls that happened — which is
the form the issue's own receipt takes. ``--no-challenge`` keeps the
arbitration reporter out of the seam: the subject here is the summary reporter
sequenced ahead of the single persistence call.
"""
import experiment


class _Binding:
    provider_name = "stub-provider"
    model = "stub-analyze-model"


class _Registry:
    def get(self, phase):
        return _Binding()


class _Config:
    name = "stub-llm-config"


ROUTE = "GET:/issue761"
DATASET = {
    "units": [
        {
            "id": "issue761-unit-0",
            "route": {"method": "GET", "path": "/issue761"},
            "code": {"primary_code": "print('safe')"},
        }
    ]
}
GROUND_TRUTH = {"categories": {"true_negatives": {"routes": [{"route_key": ROUTE}]}}}


def _stub_analyze_unit(binding, unit, **kwargs):
    return {
        "route_key": ROUTE,
        "verdict": "SAFE",
        "confidence": 0.9,
        "reasoning": "stubbed stage-1 reply",
        "elapsed_seconds": 0.0,
        "code_length": 14,
        "vulnerabilities": [],
    }


def _drive_main(mod, monkeypatch, tmp_path):
    """Drive ``mod.main()`` offline. Returns (write_json calls, path, raised)."""
    written = []

    monkeypatch.setattr(mod, "load_config_file", lambda *a, **k: {})
    monkeypatch.setattr(mod, "resolve_llm_config", lambda *a, **k: _Config())
    monkeypatch.setattr(mod, "build_phase_registry", lambda *a, **k: _Registry())
    monkeypatch.setattr(mod, "probe_registry_or_raise", lambda *a, **k: None)
    monkeypatch.setattr(mod, "load_dataset", lambda *a, **k: DATASET)
    monkeypatch.setattr(mod, "load_ground_truth", lambda *a, **k: GROUND_TRUTH)
    monkeypatch.setattr(mod, "analyze_unit", _stub_analyze_unit)
    # write_json is stubbed at the name experiment.py imported it under
    # (``:42``), which is the name ``:887`` calls — nothing reaches disk.
    monkeypatch.setattr(mod, "write_json", lambda path, obj: written.append((path, obj)))

    output_path = str(tmp_path / "issue761_experiment.json")
    monkeypatch.setattr(
        "sys.argv",
        ["experiment.py", "--dataset", "dvna", "--no-challenge", "--output", output_path],
    )

    raised = None
    try:
        mod.main()
    except Exception as exc:  # recorded, then asserted on below
        raised = exc
    return written, output_path, raised


def test_main_persists_the_experiment_result(monkeypatch, tmp_path):
    """The run reaches ``write_json`` — the reporters do not cost it its results."""
    written, output_path, raised = _drive_main(experiment, monkeypatch, tmp_path)

    assert raised is None, f"main() raised before persisting: {raised!r}"
    assert [path for path, _ in written] == [output_path]
    persisted = written[0][1]
    assert persisted["dataset"] == "dvna"
    assert persisted["metrics"]["total"] == 1
    assert persisted["results"][0]["route_key"] == ROUTE


def test_summary_reports_the_model_the_run_recorded(monkeypatch, tmp_path, capsys):
    """``print_summary`` reads the key ``run_experiment`` actually writes."""
    written, _, raised = _drive_main(experiment, monkeypatch, tmp_path)
    summary = capsys.readouterr().out.rsplit("EXPERIMENT SUMMARY", 1)[-1]

    assert raised is None, f"main() raised inside the summary reporter: {raised!r}"
    assert written[0][1]["analyze_model"] == _Binding.model
    assert f"Model: {_Binding.model}" in summary
