"""Tests for issue #536 — the compose build-failure teardown gap.

`_run_compose` returns early on a build failure (``code != 0 or timed_out``)
BEFORE the ``try/finally`` that runs ``compose down --volumes
--remove-orphans --rmi local`` — so a failed build leaks the images it
partially built (per-run UUID names accumulate forever). The outer cleanup
(``_cleanup_docker``) removes single-container names only
(``openant-test-<run>-<id>`` + the network), not the compose project's
``openant-<run>-<id>-<service>`` images.

Receipt (the monitored run): a compose build failed for VULN-001; the
post-run image ``openant-069b737a-vuln-001-attacker`` matched the compose
naming shape exactly (project + the attacker service) — name-shape
attribution (the docker event log carries no image names).
"""
from __future__ import annotations

from unittest.mock import patch

from utilities.dynamic_tester.docker_executor import _run_compose


class _Recorder:
    def __init__(self, results):
        self._results = list(results)
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout=None, cwd=None):
        self.calls.append(list(cmd))
        return self._results.pop(0)


def _seq(*outcomes):
    """Build the _run_command result sequence.

    outcomes: tuples (stdout, stderr, code, timed_out) in call order.
    """
    return [o for o in outcomes]


def test_build_failure_still_tears_down():
    """THE #536 regression: a failed build must still run compose down
    --rmi local (the images the partial build created must not leak)."""
    # build fails, then (post-fix) the teardown runs.
    rec = _Recorder([
        ("", "failed to solve: exit 1", 1, False),   # docker compose build
        ("", "", 0, False),                           # docker compose down (teardown)
        ("", "", 0, False),                           # docker compose logs (defensive)
    ])
    with patch(
        "utilities.dynamic_tester.docker_executor._run_command", rec
    ):
        result = _run_compose("/tmp/wd", "openant-abc12345-vuln-001", 60, 120)
    assert result.build_error  # the build failure is reported
    assert len(rec.calls) == 2, rec.calls  # build + teardown, nothing else
    downs = [c for c in rec.calls
             if "down" in c and "--rmi" in c and "local" in c]
    assert len(downs) == 1, (
        f"a failed build must tear down with --rmi local; calls: {rec.calls}")


def test_build_timeout_still_tears_down():
    rec = _Recorder([
        ("", "", -1, True),                            # build times out
        ("", "", 0, False),                           # teardown
    ])
    with patch(
        "utilities.dynamic_tester.docker_executor._run_command", rec
    ):
        result = _run_compose("/tmp/wd", "p", 60, 120)
    assert result.timed_out
    assert len(rec.calls) == 2, rec.calls
    downs = [c for c in rec.calls if "down" in c and "--rmi" in c]
    assert len(downs) == 1


def test_success_path_teardown_unchanged():
    """The happy path tears down exactly once (in the existing finally)."""
    rec = _Recorder([
        ("", "", 0, False),   # build
        ("", "", 0, False),   # up -d
        ("log", "", 0, False),  # logs -f test
        ("", "", 0, False),   # down (finally)
    ])
    with patch(
        "utilities.dynamic_tester.docker_executor._run_command", rec
    ):
        result = _run_compose("/tmp/wd", "p", 60, 120)
    assert result.exit_code == 0
    assert not result.build_error
    downs = [c for c in rec.calls if "down" in c and "--rmi" in c]
    assert len(downs) == 1  # exactly one teardown — no double-down
