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


def test_propagating_system_exit_writes_error_with_the_code(tmp_path):
    """Wave r1 (opus): SystemExit is not an interrupt — it is how
    deterministic error exits are signalled. A non-zero code is ERROR with
    the cause recorded (mapping it to "interrupted" erased the validation
    error and contradicted the exit code: the Go contract reads
    "interrupted" as 130); a ZERO code is a deliberate early exit."""
    with pytest.raises(SystemExit):
        with step_context("t_step", str(tmp_path)):
            raise SystemExit(2)
    rep = _read(tmp_path)
    assert rep["status"] == "error", (
        "SystemExit(2) is an error exit, not an interrupt"
    )
    assert any("SystemExit: 2" in e for e in rep["errors"]), rep

    with pytest.raises(SystemExit):
        with step_context("t_step2", str(tmp_path)):
            raise SystemExit(0)
    assert _read(tmp_path, "t_step2")["status"] == "interrupted"


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
    # wave r1 (opus): the pre-interrupt errors SURVIVE into the artifact —
    # what distinguishes an interrupted-after-failures step from a bare one.
    assert any("unit 7 failed" in e for e in _read(tmp_path)["errors"])


def test_generator_exit_writes_interrupted_status(tmp_path):
    """The GeneratorExit case named in the comment, pinned (wave r1 opus)."""
    def _gen():
        with step_context("t_step", str(tmp_path)):
            yield
            raise AssertionError("unreachable")
    g = _gen()
    next(g)
    g.close()   # GeneratorExit fires INSIDE the body at the yield; close()
                # itself does not raise when the generator cooperates
    assert _read(tmp_path)["status"] == "interrupted"


def test_sarif_gate_treats_interrupted_as_failure_class():
    """Wave r1 (fable+opus): the SARIF executionSuccessful gate — the
    consumer-level pin lives in the Go suite
    (sarif_interrupted_test.go: TestSarifInterruptedStepIsFailure); this
    Python-side companion asserts the Go suite carries it and passes."""
    import re as _re
    import shutil as _sh
    import subprocess
    from pathlib import Path as _P
    if not _sh.which("go"):
        pytest.skip("Go toolchain not available")
    # the python-test CI runners carry a PATH `go` OLDER than the module's
    # directive (ubuntu: 1.21 vs go.mod's 1.25.8, GOTOOLCHAIN=local) — skip:
    # the Go CI jobs exercise the gate with a proper toolchain.
    _src = _P(__file__).resolve().parents[3] / "apps" / "openant-cli"
    _ver = subprocess.run(["go", "version"], capture_output=True,
                          text=True).stdout
    _vm = _re.search(r"go(\d+(?:\.\d+)+)", _ver)
    _want = _re.search(r"^go\s+(\d+(?:\.\d+)*)",
                       (_src / "go.mod").read_text(), _re.M)
    if _vm and _want:
        _vt = lambda v: tuple(int(x) for x in v.split("."))
        if _vt(_vm.group(1)) < _vt(_want.group(1)):
            pytest.skip(f"go {_vm.group(1)} older than the module's go {_want.group(1)}")
    out = subprocess.run(
        ["go", "test", "./internal/report/", "-run",
         "TestSarifInterruptedStepIsFailure", "-count=1", "-v"],
        capture_output=True, text=True,
        cwd=str(_P(__file__).resolve().parents[3] / "apps" / "openant-cli"),
        timeout=300)
    assert "PASS" in out.stdout, out.stdout + out.stderr


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
