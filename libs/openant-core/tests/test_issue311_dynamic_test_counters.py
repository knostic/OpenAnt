"""Regression tests for issue #311 — dynamic-test generation failures
bypass the loop counters, so `_summary.json` reports `errors: 0` for a run
that errored and its buckets do not sum to its own total.

The generation-failure branch records a result, saves a checkpoint, and
`continue`s — bypassing the only `_completed`/`_errors` increment site. On
`DetectFallback` (the path that reads `_summary.json` directly) an errored
run presents as clean. Two further defects on the same counters: the loop
counts errors as a SUBSET of completed while `StepCheckpoint.status()`
counts them as DISJOINT — so even with the increment added, the two
sources disagree; and the issue's observed shape (`completed: 0,
errors: 0` beside one unit file with `status: "ERROR"`) is internally
inconsistent regardless of any consumer.

Contract locked here (the issue's suggestion 1 — the structural fix):
- `write_summary`'s counts are DERIVED from the saved unit files (the
  same source `status()` recomputes from), not from loop-local
  accumulators — the two sources cannot drift;
- the disjoint semantics: an ERROR unit counts in `errors`, never in
  `completed`;
- a generation failure is counted (errors: 1, completed: 0) and its
  buckets sum to total_units;
- the retry behaviour is unchanged (ERROR checkpoints are still retried
  on resume — the defect was in the counters, not the retry).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utilities.dynamic_tester import _summary_counts_from_checkpoints  # noqa: E402


def _cp(status, **extra):
    d = {"status": status}
    d.update(extra)
    return d


def test_generation_failure_counts_as_error():
    """The issue's observed shape pinned: one ERROR unit file → errors: 1,
    completed: 0 (disjoint — not the loop's subset semantics)."""
    counts = _summary_counts_from_checkpoints({
        "f1": _cp("ERROR", details="Test generation failed — LLM did not return valid test code"),
    })
    # #432 added error_breakdown (derived in the same pass — the categories
    # are pinned in test_issue432_error_breakdown).
    assert counts == {"completed": 0, "errors": 1, "error_breakdown": {"generation": 1}}


def test_mixed_statuses_disjoint():
    counts = _summary_counts_from_checkpoints({
        "f1": _cp("CONFIRMED"),
        "f2": _cp("ERROR"),
        "f3": _cp("INCONCLUSIVE"),
    })
    assert counts["completed"] == 2 and counts["errors"] == 1


def test_empty_and_absent():
    counts = _summary_counts_from_checkpoints({})
    assert counts["completed"] == 0 and counts["errors"] == 0
    counts = _summary_counts_from_checkpoints(None)
    assert counts["completed"] == 0 and counts["errors"] == 0


def test_summary_json_consistent_with_unit_files(tmp_path, monkeypatch):
    """Drive the real loop with a failing generator: the written
    _summary.json reports the failure and its buckets sum to total."""
    import utilities.dynamic_tester as dt

    # a pipeline_output with one dynamic-testable finding
    findings_path = tmp_path / "pipeline_output.json"
    findings_path.write_text(json.dumps({
        "repository": {"name": "t", "language": "python"},
        "application_type": "unknown",
        "findings": [{
            "id": "f1", "name": "X", "short_name": "x", "location": "a.py:1",
            "cwe_id": 79, "stage2_verdict": "confirmed",
            "vulnerable_code": "eval(x)", "attack_vector": "a",
            "steps_to_reproduce": "s", "impact": "i", "suggested_fix": "f",
        }],
    }))
    cp_dir = tmp_path / "cp"

    # a fake registry so no LLM probe runs
    from utilities.llm import PhaseBinding

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

    # generation failure — the branch under test
    monkeypatch.setattr(dt, "generate_test", lambda *a, **k: None)
    monkeypatch.setattr(dt, "generate_report", lambda *a, **k: "# report")

    dt.run_dynamic_tests(
        pipeline_output_path=str(findings_path),
        output_dir=str(tmp_path / "out"),
        checkpoint_path=str(cp_dir),
        registry=_FakeRegistry(),
    )

    summary = json.loads((cp_dir / "_summary.json").read_text())
    assert summary["errors"] == 1, summary
    assert summary["completed"] == 0, summary
    assert summary["completed"] + summary["errors"] == summary["total_units"]
    # the unit file itself (the identification argument from the issue)
    unit_files = [f for f in cp_dir.glob("*.json") if f.name != "_summary.json"]
    assert len(unit_files) == 1
    unit = json.loads(unit_files[0].read_text())
    assert unit["status"] == "ERROR"
    assert "generation failed" in unit.get("details", "").lower()


def test_error_checkpoints_still_retried(tmp_path):
    """The retry contract is unchanged: an ERROR checkpoint is NOT
    'already done' — it lands in the retry set, not the restore set."""
    cp_dir = tmp_path / "cp"
    cp_dir.mkdir()
    (cp_dir / "f1.json").write_text(json.dumps(
        _cp("ERROR", details="Test generation failed")))
    (cp_dir / "f2.json").write_text(json.dumps(_cp("CONFIRMED")))

    # replicate the loop's restore classification (the lines under test)
    checkpointed = {fid: json.loads((cp_dir / f"{fid}.json").read_text())
                    for fid in ("f1", "f2")}
    successful_ids = {fid for fid, cp in checkpointed.items()
                      if cp.get("status") != "ERROR"}
    errored_ids = {fid for fid in checkpointed.keys()
                   if fid not in successful_ids}
    assert successful_ids == {"f2"}
    assert errored_ids == {"f1"}
