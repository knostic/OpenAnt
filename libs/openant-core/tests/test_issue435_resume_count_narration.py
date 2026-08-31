"""#435: the resume narration counts what actually runs — an errored row is not done.

Observed on master: an analyze resumed over a checkpoint dir with one intact completed
SAFE row and one #324-shaped error row (neither verdict nor finding). The unit is
correctly retried — but the narration counted the error row as done: "0 units to
process (2 already done)" and, after the retry, "Done: 3/2 units" — a counter past its
denominator. `_run_detection` computed remaining from the RAW restored count
(len(checkpointed)) while the retry queue is built from the ERROR-FILTERED count
(_cp_is_error), so an errored row was done-in-the-narration and retried-in-the-queue at
the same time; ProgressReporter was seeded with completed=len(checkpointed) too.

The fix derives done/remaining AND the ProgressReporter seed from the same predicate
the queue uses (_cp_is_error) — "units to process" equals what actually runs, and the
counter can never exceed its total.
"""
import io
import sys
from contextlib import redirect_stderr
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

import core.analyzer as az  # noqa: E402
from core.checkpoint import StepCheckpoint  # noqa: E402


def _fake_process_unit(calls):
    def f(binding, unit, index, json_corrector, app_context):
        calls["n"] += 1
        return {"index": index,
                "result": {"unit_id": unit["id"], "finding": "safe",
                           "verdict": "SAFE", "route_key": f"f.py:{unit['id']}"},
                "route_key": f"f.py:{unit['id']}", "code_for_route": "x",
                "finding": "safe", "elapsed": 0.1}
    return f


def _resume_two_rows(tmp_path, monkeypatch):
    """A checkpoint dir with one intact SAFE row + one error row (the #324
    shape: a result with neither verdict nor finding), then a resume run."""
    cp = StepCheckpoint("analyze", str(tmp_path))
    cp.ensure_dir()
    cp.save("u0", {"result": {"unit_id": "u0", "finding": "safe", "verdict": "SAFE",
                              "route_key": "f.py:u0"},
                   "route_key": "f.py:u0", "code_for_route": "x"})
    # the #324 error shape: a result with neither verdict nor finding
    cp.save("u1", {"result": {"unit_id": "u1"}, "route_key": "f.py:u1"})

    calls = {"n": 0}
    monkeypatch.setattr(az, "_process_unit", _fake_process_unit(calls))
    err = io.StringIO()
    with redirect_stderr(err):
        az._run_detection(
            [{"id": "u0", "code": "x=1"}, {"id": "u1", "code": "x=1"}],
            binding=object(), json_corrector=None, app_context=None,
            workers=1, checkpoint=cp)
    return err.getvalue(), calls


def test_resume_narration_counts_the_retry_queue(tmp_path, monkeypatch):
    """1 already done (the SAFE row), 1 to process (the error row RETRIES) —
    never "2 already done" with a retry running anyway."""
    out, calls = _resume_two_rows(tmp_path, monkeypatch)
    assert "1 units to process (1 already done)" in out, (
        f"the narration counted the error row as done while the queue "
        f"retried it: {out!r}"
    )
    assert calls["n"] == 1, "only the errored unit runs"


def test_final_counter_never_exceeds_total(tmp_path, monkeypatch):
    """Done: 2/2 — the seeded counter + the retry never passes the total."""
    out, _ = _resume_two_rows(tmp_path, monkeypatch)
    assert "3/2" not in out, f"the counter passed its denominator: {out!r}"
    assert "2/2" in out
