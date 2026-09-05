"""#432: _summary.json's error_breakdown is derived from the unit files — self-sufficient for triage.

Live-observed on master: a content-filtered model produced 5 errors with
`error_breakdown: {}` — all four checkpoint.write_summary call sites in the
dynamic-tester pass a hardcoded `{}`, though core/checkpoint.py supports the
error_type -> count dict and the analyze pipeline populates one. The counts are
correct post-#311, but a post-mortem must open all 5 unit files to learn they were
all GENERATION failures (content filter) rather than Docker/execution failures.

The fix extends _summary_counts_from_checkpoints (#311's derivation — the same
source status() recomputes from) to also bucket ERROR unit files by category,
derived from the details prefixes the collector writes: `Test generation ...` ->
generation; `Docker build failed` -> build; `Container execution timed out` ->
timeout; the remaining execution shapes (`Docker execution was not attempted`,
`Container did not produce valid JSON output`) -> execution; anything else ->
other. Threaded through all four call sites in place of the hardcoded {}.
"""
import json
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

import utilities.dynamic_tester as dt  # noqa: E402
from utilities.llm import PhaseBinding  # noqa: E402
from utilities.dynamic_tester import _summary_counts_from_checkpoints  # noqa: E402


class _NoopAdapter:
    name = "anthropic"
    supports_tools = True

    def complete(self, **kwargs):  # pragma: no cover - mocked away
        raise AssertionError("should not reach the adapter")

    def validate(self, model):
        pass


def _run_generation_failures(tmp_path):
    """Drive the real loop with a failing generator: two units, both ERROR at
    the generation stage (the live-run class: a content-filtered model)."""
    pipeline = tmp_path / "pipeline_output.json"
    pipeline.write_text(json.dumps({
        "repository": {"name": "t", "language": "python"},
        "application_type": "unknown",
        "findings": [
            {"id": "f1", "name": "X", "short_name": "x", "location": "a.py:1",
             "cwe_id": 79, "stage2_verdict": "confirmed",
             "vulnerable_code": "eval(x)", "attack_vector": "a",
             "steps_to_reproduce": "s", "impact": "i", "suggested_fix": "f"},
            {"id": "f2", "name": "Y", "short_name": "y", "location": "b.py:1",
             "cwe_id": 79, "stage2_verdict": "confirmed",
             "vulnerable_code": "eval(y)", "attack_vector": "a",
             "steps_to_reproduce": "s", "impact": "i", "suggested_fix": "f"},
        ],
    }))

    class _FakeRegistry:
        def get(self, phase):
            return PhaseBinding(phase=phase, adapter=_NoopAdapter(),
                                model="m", provider_name="anthropic")

    orig = dt.generate_test
    dt.generate_test = lambda *a, **k: None
    try:
        dt.run_dynamic_tests(
            pipeline_output_path=str(pipeline),
            output_dir=str(tmp_path / "out"),
            checkpoint_path=str(tmp_path / "cp"),
            registry=_FakeRegistry(),
        )
    finally:
        dt.generate_test = orig
    return json.loads((tmp_path / "cp" / "_summary.json").read_text())


def test_summary_error_breakdown_buckets_generation_failures(tmp_path):
    """The live-run shape: all errors at the generation stage must be
    categorized — self-sufficient triage without opening unit files."""
    summary = _run_generation_failures(tmp_path)
    assert summary["errors"] == 2
    breakdown = summary.get("error_breakdown")
    assert breakdown == {"generation": 2}, (
        f"error_breakdown = {breakdown} (the hardcoded {{}} — a post-mortem "
        "must open every unit file to learn the stage)"
    )


def test_derivation_buckets_each_category():
    """The category derivation, from the details prefixes the collector
    writes (result_collector.py's vocabulary)."""
    cps = {
        "u1": {"status": "ERROR", "details": "Test generation failed — LLM did not return valid test code"},
        "u2": {"status": "ERROR", "details": "Test generation raised ValueError: bad"},
        "u3": {"status": "ERROR", "details": "Docker build failed: exit 1"},
        "u4": {"status": "ERROR", "details": "Container execution timed out"},
        "u5": {"status": "ERROR", "details": "Container did not produce valid JSON output. x"},
        "u6": {"status": "ERROR", "details": "Docker execution was not attempted"},
        "u7": {"status": "ERROR", "details": "something unprecedented"},
        "u8": {"status": "ERROR"},
        "ok": {"status": "CONFIRMED"},
    }
    counts = _summary_counts_from_checkpoints(cps)
    assert counts["completed"] == 1
    assert counts["errors"] == 8
    assert counts["error_breakdown"] == {
        "generation": 2, "build": 1, "timeout": 1,
        "execution": 2, "other": 2,
    }


def test_derivation_empty_states():
    counts = _summary_counts_from_checkpoints({})
    assert counts["error_breakdown"] == {}
    counts = _summary_counts_from_checkpoints(None)
    assert counts["error_breakdown"] == {}


def test_real_timeout_rows_reach_the_breakdown():
    """Wave r1 (sonnet): the collector writes "Container execution timed out"
    with status INCONCLUSIVE, never ERROR — the timeout bucket was DEAD CODE
    (the old test fabricated a status/details combo production never
    produces). A real timed-out row counts in the timeout bucket WITHOUT
    inflating `errors` (the #311 disjoint semantics hold)."""
    cps = {
        "u1": {"status": "INCONCLUSIVE", "details": "Container execution timed out"},
        "u2": {"status": "ERROR", "details": "Docker build failed: exit 1"},
    }
    counts = _summary_counts_from_checkpoints(cps)
    assert counts["completed"] == 1
    assert counts["errors"] == 1
    assert counts["error_breakdown"] == {"timeout": 1, "build": 1}


def test_status_uses_the_same_breakdown_vocabulary():
    """famD panel (opus): StepCheckpoint.status()'s dynamic-test arm buckets
    ERROR rows with the SAME #432 stage vocabulary as the summary derivation
    (generation/build/execution/other) — not a flat 'test_error' that
    reintroduces the #311 summary-vs-status drift."""
    import json as _json
    import tempfile, os
    from core.checkpoint import StepCheckpoint

    with tempfile.TemporaryDirectory() as d:
        for name, details in [
            ("V1", "Test generation raised: filtered"),
            ("V2", "Docker build failed: no manifest"),
            ("V3", "Container did not produce valid JSON output"),
            ("V4", "mystery"),
        ]:
            (Path(os.path.join(d, f"{name}.json"))).write_text(_json.dumps(
                {"id": name, "status": "ERROR", "details": details}),
                encoding="utf-8")
        st = StepCheckpoint.status(d)
        bd = st["error_breakdown"]
        assert bd.get("generation") == 1, bd
        assert bd.get("build") == 1, bd
        assert bd.get("execution") == 1, bd
        assert bd.get("other") == 1, bd
        assert "test_error" not in bd, bd
