"""#420: an interrupted step's on-disk report says "interrupted", not "success".

When an interrupt propagates through a step (the #417/#418/#419 contract — the
handlers re-raise), `step_context`'s finally still writes the step report with the
DEFAULT status="success" and an empty summary — the on-disk artifact of an
interrupted run lies (stdout envelope unaffected: no envelope is emitted on the KI
path, so the Go exit-130 contract still works; this is the stderr/file channel only).

The fix: a propagating BaseException that is NOT an Exception (KeyboardInterrupt,
SystemExit, GeneratorExit — the ones `except Exception` cannot catch) maps the step's
status to "interrupted" before re-raising, and the partial-derivation in the finally
never downgrades it. The propagating-Exception path stays "error"; a normal step stays
"success"; the errors/error_count derivation stays "partial".
"""
import json
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[1]
if str(_CORE) not in sys.path:
    sys.path.insert(0, str(_CORE))

import pytest  # noqa: E402

from core.step_report import step_context  # noqa: E402


def _read(tmp_path, step="t_step"):
    return json.loads((tmp_path / f"{step}.report.json").read_text())


def test_propagating_ki_writes_interrupted_status(tmp_path):
    """The KI propagates (the #419 contract) AND the artifact says
    interrupted — on pristine the file was written status="success" with an
    empty summary: the on-disk artifact of an interrupted run lied."""
    with pytest.raises(KeyboardInterrupt):
        with step_context("t_step", str(tmp_path), inputs={"a": 1}):
            raise KeyboardInterrupt
    rep = _read(tmp_path)
    assert rep["status"] == "interrupted", (
        f"the interrupted step's report says {rep['status']!r} — the resume path "
        "and any artifact reader must see the run was cut short"
    )


def test_propagating_system_exit_writes_interrupted_status(tmp_path):
    with pytest.raises(SystemExit):
        with step_context("t_step", str(tmp_path)):
            raise SystemExit(2)
    assert _read(tmp_path)["status"] == "interrupted"


def test_propagating_exception_stays_error(tmp_path):
    """The Exception path is unchanged: status "error", the message recorded,
    the exception re-raised."""
    with pytest.raises(ValueError, match="boom"):
        with step_context("t_step", str(tmp_path)):
            raise ValueError("boom")
    rep = _read(tmp_path)
    assert rep["status"] == "error"
    assert any("boom" in e for e in rep["errors"])


def test_interrupted_with_errors_is_not_downgraded_to_partial(tmp_path):
    """A step that recorded errors AND was then interrupted: "interrupted" is
    the more specific, final answer — the partial-derivation must not
    overwrite it."""
    with pytest.raises(KeyboardInterrupt):
        with step_context("t_step", str(tmp_path)) as ctx:
            ctx.errors.append("unit 7 failed before the interrupt")
            raise KeyboardInterrupt
    assert _read(tmp_path)["status"] == "interrupted"


def test_normal_and_partial_derivations_unchanged(tmp_path):
    """The #209/#285 derivation is untouched: success stays success, an
    error_count in the summary derives partial, an explicit skipped stays."""
    with step_context("ok_step", str(tmp_path)) as ctx:
        ctx.summary = {"total_units": 3}
    assert _read(tmp_path, "ok_step")["status"] == "success"

    with step_context("p_step", str(tmp_path)) as ctx:
        ctx.summary = {"error_count": 2}
    assert _read(tmp_path, "p_step")["status"] == "partial"

    with step_context("s_step", str(tmp_path)) as ctx:
        ctx.status = "skipped"
        ctx.summary = {"reason": "no toolchain"}
    assert _read(tmp_path, "s_step")["status"] == "skipped"
