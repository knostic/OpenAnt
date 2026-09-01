"""#333: DYNAMIC_TEST_RESULTS.md's `**Total Cost:**` is the STEP's cost, not the run's.

The dynamic-test step shares the process-wide tracker with the earlier LLM phases
(deliberately — the comment at utilities/dynamic_tester/__init__.py:148-149: "so
step_context captures dynamic-test cost in dynamic-test.report.json"). The markdown
and structured-JSON writers read the RAW CUMULATIVE (`tracker.total_cost_usd`) at the
end of the step, so on a full `scan` they print the whole run's cost: the issue's real
run showed `**Total Cost:** $2062.3969` for a step whose own dynamic-test.report.json
recorded `cost_usd: 0.073281` — the same tracker, two readings, and the delta reading
(core/step_report.py:63) is the correct one. #280 fixed all four CONSOLE per-phase
lines via log_usage baselines; this markdown path never went through log_usage.

The fix snapshots the tracker at step entry (BEFORE the checkpoint prior-usage
injection — those injected costs are the step's OWN spend from earlier attempts, meant
to show "total cost across runs") and reports the delta, so both the markdown and
dynamic_test_results.json carry the step's cost like the JSON step-report already does.
"""
import json
import sys
from pathlib import Path

import pytest

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

import utilities.dynamic_tester as dt  # noqa: E402
from utilities.llm import PhaseBinding  # noqa: E402
from utilities.llm_client import get_global_tracker  # noqa: E402


class _NoopAdapter:
    name = "anthropic"
    supports_tools = True

    def complete(self, **kwargs):  # pragma: no cover - mocked away
        raise AssertionError("should not reach the adapter")

    def validate(self, model):
        pass


class _FakeRegistry:
    def get(self, phase):
        return PhaseBinding(phase=phase, adapter=_NoopAdapter(),
                            model="m", provider_name="anthropic")


def _write_pipeline(tmp_path):
    p = tmp_path / "pipeline_output.json"
    p.write_text(json.dumps({
        "repository": {"name": "t", "language": "python"},
        "application_type": "unknown",
        "findings": [{
            "id": "f1", "name": "X", "short_name": "x", "location": "a.py:1",
            "cwe_id": 79, "stage2_verdict": "confirmed",
            "vulnerable_code": "eval(x)", "attack_vector": "a",
            "steps_to_reproduce": "s", "impact": "i", "suggested_fix": "f",
        }],
    }))
    return str(p)


def _run(tmp_path, gen_fn):
    pipeline = _write_pipeline(tmp_path)
    out = tmp_path / "out"
    orig = dt.generate_test
    dt.generate_test = gen_fn
    try:
        dt.run_dynamic_tests(
            pipeline_output_path=pipeline,
            output_dir=str(out),
            checkpoint_path=str(tmp_path / "cp"),
            registry=_FakeRegistry(),
        )
    finally:
        dt.generate_test = orig
    md = (out / "DYNAMIC_TEST_RESULTS.md").read_text()
    js = json.loads((out / "dynamic_test_results.json").read_text())
    return md, js


def _md_total_cost(md):
    for line in md.splitlines():
        if "Total Cost:" in line:
            return float(line.split("$")[1])
    raise AssertionError(f"no Total Cost line in report:\n{md}")


def test_md_reports_step_delta_not_run_total(tmp_path):
    """Prior-phase spend on the shared tracker must NOT appear in the step's
    Total Cost (the issue's shape: $2062.3969 printed for a $0.0733 step)."""
    tracker = get_global_tracker()
    tracker.add_prior_usage(0, 0, 2062.3236)   # earlier phases of a full scan

    def gen(*a, **k):
        return None   # generation failure — no step spend
    md, js = _run(tmp_path, gen)

    total = _md_total_cost(md)
    assert total < 1.0, (
        f"DYNAMIC_TEST_RESULTS.md Total Cost = ${total:.4f} — the RAW cumulative "
        "run total, not the step's (the JSON step-report on the same run reads "
        "the delta; the markdown must match it)"
    )
    assert js["total_cost_usd"] < 1.0, (
        f"dynamic_test_results.json total_cost_usd = {js['total_cost_usd']} — "
        "the structured results file carries the same overstated cumulative"
    )


def test_delta_includes_step_own_spend(tmp_path):
    """The step's own spend during the loop IS the delta the report shows."""
    tracker = get_global_tracker()
    tracker.add_prior_usage(0, 0, 2062.3236)   # prior phases

    def gen(*a, **k):
        tracker.add_prior_usage(0, 0, 0.073281)  # the step's own spend
        return None
    md, js = _run(tmp_path, gen)

    total = _md_total_cost(md)
    assert abs(total - 0.0733) < 0.0005, (
        f"Total Cost = ${total:.4f}; want the step's own ~$0.0733 (not the "
        "cumulative ~$2062.3969)"
    )
    assert abs(js["total_cost_usd"] - 0.073281) < 1e-6


def test_standalone_run_reports_own_total(tmp_path):
    """No prior phases on the tracker: the delta equals the raw read — the
    standalone-run behaviour is unchanged by the fix."""
    def gen(*a, **k):
        get_global_tracker().add_prior_usage(0, 0, 0.05)
        return None
    md, js = _run(tmp_path, gen)
    assert abs(_md_total_cost(md) - 0.05) < 0.0005
    assert abs(js["total_cost_usd"] - 0.05) < 1e-6


def test_console_phase_line_excludes_the_restored_checkpoints(tmp_path, monkeypatch, capsys):
    """Wave r1 (opus): the dynamic-test CONSOLE line carried the #281 shape —
    the phase baseline snapshotted BEFORE the checkpoint injection, so a
    resumed run's `Dynamic Test:` line double-counted the restored spend
    (their original run's line already reported it). The baseline holder is
    refreshed AT the injection site: the line reports only the NEW retry
    spend."""
    import core.dynamic_tester as cd
    tracker = get_global_tracker()

    # 10 restored checkpoints' worth of prior spend, injected by the loop.
    pipeline = tmp_path / "pipeline_output.json"
    pipeline.write_text(json.dumps({
        "repository": {"name": "t", "language": "python"},
        "application_type": "unknown",
        "findings": [{
            "id": "f1", "name": "X", "short_name": "x", "location": "a.py:1",
            "cwe_id": 79, "stage2_verdict": "confirmed",
            "vulnerable_code": "eval(x)", "attack_vector": "a",
            "steps_to_reproduce": "s", "impact": "i", "suggested_fix": "f",
        }],
    }))
    # run_dynamic_tests derives its checkpoint dir from output_dir
    # (output_dir/dynamic_test_checkpoints) when no explicit path is given —
    # the step wrapper passes output_dir through.
    out = tmp_path / "out"
    out.mkdir()
    cp = out / "dynamic_test_checkpoints"
    cp.mkdir()
    # an ERRORED checkpoint carrying prior spend: its $0.60 is injected (the
    # loop injects ALL checkpoints) AND the finding is retried (the gen
    # monkeypatch spends $0.03 on the retry).
    import json as _json
    (cp / "f1.json").write_text(_json.dumps({
        "id": "f1", "status": "ERROR",
        "generation_cost_usd": 0.60,
        "generation_input_tokens": 1000, "generation_output_tokens": 500,
    }))
    (cp / "_summary.json").write_text(_json.dumps(
        {"total_units": 1, "completed": 0, "errors": 1}))

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_NoopAdapter(),
                                model="m", provider_name="anthropic")

    def gen(*a, **k):
        tracker.add_prior_usage(0, 0, 0.03)   # the retry's own spend
        return None

    import utilities.dynamic_tester as dt
    monkeypatch.setattr(dt, "generate_test", gen)
    err = capsys.readouterr().err
    out = tmp_path / "out"
    # the step wrapper (docker availability is mocked away; the loop's
    # finding is already restored so no container runs)
    monkeypatch.setattr(cd.shutil, "which", lambda n: "/usr/bin/docker" if n == "docker" else None)
    cd.run_tests(
        pipeline_output_path=str(pipeline), output_dir=str(out),
        registry=_FakeRegistry())
    err = capsys.readouterr().err
    line = next((l for l in err.splitlines() if "Dynamic Test:" in l), None)
    assert line is not None, err
    # ONLY the retry's $0.03 — the restored $0.60 stays in its original
    # run's line (double-counted before: the line read $0.63).
    assert "$0.0300" in line, f"the console phase line includes restored spend: {line}"
