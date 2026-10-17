"""Tests for issue #732 — the single-container timeout teardown gap.

``docker run`` is invoked ATTACHED with ``--rm`` and NO ``--name``/``--cidfile``,
and ``_run_command``'s subprocess timeout kills the docker CLI CLIENT only. On a
timeout the container keeps running: ``--rm`` is daemon-side (it fires only on
the container's own exit) and the outer cleanup (``_cleanup_docker``:
``docker rmi -f`` + ``docker network rm``) can neither stop nor remove a running
container. The fix names the container with the run's own UUID model
(``openant-ct-{run_id}-{safe_id}`` — the same run_id+safe_id the image tag, the
network name and the compose project name all carry, #315/#424) and tears it
down in ``_run_single``'s OWN finally — the discipline ``_run_compose`` already
holds (#536: down-in-finally on every exit path).

All witnesses drive ``run_single_container``'s REAL body (only ``_write_test_files``
and the ``_run_command`` subprocess are faked) so the orchestrator route — the
plumb from finding_id to the named, torn-down container — is what the tests
guard (the E1/E2 class: a plumb no test executes is a plumb nothing guards).
"""
from __future__ import annotations

import re

import pytest

import utilities.dynamic_tester.docker_executor as de


class _FakeDocker:
    """Records argv; the `docker run` call returns the scripted outcome."""

    def __init__(self, run_outcome):
        self.calls = []
        self._run_outcome = run_outcome  # (stdout, stderr, code, timed_out)

    def __call__(self, cmd, timeout=None, cwd=None):
        self.calls.append(list(cmd))
        if cmd[:2] == ["docker", "run"]:
            return self._run_outcome
        return ("", "", 0, False)


def _orchestrate(monkeypatch, tmp_path, run_outcome, runner):
    """Run a single-container dynamic test through the runner's real body
    (the production entry point, passed by the caller), faking only the file
    writes and the docker subprocess."""
    rec = _FakeDocker(run_outcome)
    monkeypatch.setattr(de, "_run_command", rec)
    monkeypatch.setattr(de, "_write_test_files", lambda *a, **k: None)
    monkeypatch.setattr(de, "tempfile", type(
        "T", (), {"mkdtemp": staticmethod(lambda *a, **k: str(tmp_path / "wd"))}))
    result = runner({"language": "python", "code": "print(1)"}, "VULN-001")
    return rec, result


def _run_argv(recorder):
    return [c for c in recorder.calls if c[:2] == ["docker", "run"]][0]


def _rm_calls(recorder):
    return [c for c in recorder.calls if c[:3] == ["docker", "rm", "-f"]]


def test_a_timed_out_run_kills_the_container_by_name(monkeypatch, tmp_path):
    """The RED witness: on a timeout a `docker rm -f <name>` must fire after
    the run — subprocess's timeout kills only the client, and `--rm` is
    daemon-side, so without an explicit teardown the container leaks."""
    rec, result = _orchestrate(
        monkeypatch, tmp_path, ("", "Command timed out", -1, True),
        runner=de.run_single_container)
    assert result.timed_out is True
    run_cmd = _run_argv(rec)
    assert "--name" in run_cmd, (
        "the container must be named at run time — a container nobody can "
        "address is a container nobody can tear down (#732)"
    )
    name = run_cmd[run_cmd.index("--name") + 1]
    assert name.startswith("openant-ct-"), "the run's own UUID naming model"
    rm = _rm_calls(rec)
    assert rm and rm[-1][3] == name, (
        "a timed-out run must `docker rm -f` the container it started "
        "(subprocess timeout kills only the client; --rm is daemon-side)"
    )
    assert rec.calls.index(rm[-1]) > rec.calls.index(run_cmd), (
        "the teardown must come after the run invocation"
    )


def test_the_name_reuses_the_run_naming_model(monkeypatch, tmp_path):
    """The container name carries the same run_id+safe_id as the image tag —
    the module's own UUID collision model (#315), not a new scheme."""
    rec, _ = _orchestrate(monkeypatch, tmp_path, ("", "", 0, False),
                          runner=de.run_single_container)
    run_cmd = _run_argv(rec)
    assert "--name" in run_cmd, "the container must be named at run time"
    name = run_cmd[run_cmd.index("--name") + 1]
    image = run_cmd[-1]
    m_name = re.fullmatch(r"openant-ct-([0-9a-f]{8})-(.+)", name)
    m_image = re.fullmatch(r"openant-test-([0-9a-f]{8})-(.+)", image)
    assert m_name and m_image, "both names follow the module's UUID model"
    assert m_name.group(2) == "vuln-001", "the safe_id derives from the finding"
    assert m_name.group(1) == m_image.group(1), "same run_id"
    assert m_name.group(2) == m_image.group(2), "same safe_id"


def test_a_normal_exit_still_tears_down_best_effort(monkeypatch, tmp_path):
    """The rm fires on every exit path (the compose path's down does too): on
    a normal exit `--rm` already removed the container and the rm is a
    harmless best-effort error, ignored like every cleanup call."""
    rec, result = _orchestrate(monkeypatch, tmp_path, ("", "", 0, False),
                               runner=de.run_single_container)
    assert result.timed_out is False
    assert "--name" in _run_argv(rec), "the container must be named at run time"
    assert _rm_calls(rec), "the teardown fires on every exit path"


def test_the_sandbox_flags_are_unchanged(monkeypatch, tmp_path):
    """The fix ADDS --name only: every F4/sandbox flag stays in the argv and
    --user stays out (the read-only-HOME breakage, per the reconstruct test)."""
    rec, _ = _orchestrate(monkeypatch, tmp_path, ("", "", 0, False),
                          runner=de.run_single_container)
    run_cmd = _run_argv(rec)
    assert "--name" in run_cmd, "the container must be named at run time"
    s = " ".join(run_cmd)
    for flag in ("--rm", "--network none", "--memory 512m", "--cpus 1",
                 "--pids-limit 256", "--cap-drop ALL", "--read-only",
                 "--security-opt no-new-privileges"):
        assert flag in s, f"the sandbox flag {flag} must be unchanged"
    assert "--user" not in run_cmd, "must NOT pin --user (read-only-HOME breakage)"


def test_the_teardown_survives_an_exception_from_the_run(monkeypatch, tmp_path):
    """The FINALLY discipline (fable round-1 F1): the rm must fire even when
    the `docker run` call RAISES (not merely times out — a crash between run
    and result must not leak the container either). A plain sequential
    teardown (no try/finally) must FAIL this test."""
    class _RaisingDocker(_FakeDocker):
        def __call__(self, cmd, timeout=None, cwd=None):
            self.calls.append(list(cmd))
            if cmd[:2] == ["docker", "run"]:
                raise RuntimeError("docker client crashed mid-run")
            return ("", "", 0, False)

    rec = _RaisingDocker(("", "", 0, False))
    monkeypatch.setattr(de, "_run_command", rec)
    monkeypatch.setattr(de, "_write_test_files", lambda *a, **k: None)
    monkeypatch.setattr(de, "tempfile", type(
        "T", (), {"mkdtemp": staticmethod(lambda *a, **k: str(tmp_path / "wd"))}))
    with pytest.raises(RuntimeError):
        de.run_single_container(
            {"language": "python", "code": "print(1)"}, "VULN-001")
    # the run raised; the finally must still have torn the container down
    assert _rm_calls(rec), (
        "an exception from the run must not skip the container teardown "
        "— the teardown lives in a finally, not in the happy path"
    )


def test_the_teardown_precedes_the_outer_image_cleanup(monkeypatch, tmp_path):
    """The ORDER discipline (fable round-1 F1): the container rm must run
    BEFORE the outer finally's `docker rmi -f` — an rm parked inside
    _cleanup_docker AFTER rmi/network (the wrong-site mutation) must FAIL
    this test."""
    rec, _ = _orchestrate(monkeypatch, tmp_path, ("", "", 0, False),
                          runner=de.run_single_container)
    calls = rec.calls
    rm_idx = [i for i, c in enumerate(calls) if c[:3] == ["docker", "rm", "-f"]]
    rmi_idx = [i for i, c in enumerate(calls) if c[:3] == ["docker", "rmi", "-f"]]
    assert rm_idx and rmi_idx, "both the container rm and the image rmi fire"
    assert rm_idx[0] < rmi_idx[0], (
        "the container teardown must precede the image cleanup — an "
        "in-use image is what makes rmi -f a dangle, not a removal"
    )


def test_the_required_name_has_no_fallback():
    """The param is required and derives nothing: the naming model has exactly
    one home (beside image_tag in run_single_container). A missing name is a
    programming error the orchestrator path can never paper over."""
    with pytest.raises(TypeError):
        de._run_single("/tmp/nowhere", "img:tag", "net", 10, 10)
