"""Tests for utilities.docker_isolation.docker_preflight -- the ONE
canonical, cheap Docker readiness check used before Existing Test
Comparison spends an LLM call or does any Docker/workspace
work.

No real Docker daemon is ever invoked here -- docker_available/
run_docker_command are mocked at the docker_isolation module boundary.
"""

from __future__ import annotations

from unittest import mock

import utilities.docker_isolation as di


class TestDockerPreflightCliMissing:
    def test_cli_missing_is_not_ready_with_precise_status(self):
        with mock.patch.object(di, "docker_available", return_value=False), \
             mock.patch.object(di, "run_docker_command") as m_run:
            result = di.docker_preflight()
        assert result.ready is False
        assert result.status == "CLI_MISSING"
        assert "not installed" in result.reason
        m_run.assert_not_called()  # never even attempts `docker info` without the CLI


class TestDockerPreflightDaemonUnreachable:
    def test_nonzero_exit_is_daemon_unreachable(self):
        with mock.patch.object(di, "docker_available", return_value=True), \
             mock.patch.object(di, "run_docker_command") as m_run:
            m_run.return_value = (
                "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
                    "Is the docker daemon running?", 1, False,
            )
            result = di.docker_preflight()
        assert result.ready is False
        assert result.status == "DAEMON_UNREACHABLE"
        assert "Cannot connect to the Docker daemon" in result.reason
        assert "Start Docker" in result.reason

    def test_only_docker_info_is_invoked_never_build_or_pull(self):
        with mock.patch.object(di, "docker_available", return_value=True), \
             mock.patch.object(di, "run_docker_command") as m_run:
            m_run.return_value = ("{}", "", 0, False)
            di.docker_preflight()
        m_run.assert_called_once()
        cmd = m_run.call_args[0][0]
        assert cmd[:2] == ["docker", "info"]
        assert "build" not in cmd
        assert "pull" not in cmd
        assert "run" not in cmd


class TestDockerPreflightTimeout:
    def test_timeout_is_a_distinct_status(self):
        with mock.patch.object(di, "docker_available", return_value=True), \
             mock.patch.object(di, "run_docker_command") as m_run:
            m_run.return_value = ("", "Command timed out", -1, True)
            result = di.docker_preflight(timeout=5)
        assert result.ready is False
        assert result.status == "TIMEOUT"
        assert "timed out after 5s" in result.reason

    def test_preflight_uses_a_short_default_timeout(self):
        """Cheap and fast -- the readiness probe itself must not be
        allowed to run anywhere near as long as a real build/run."""
        assert di._PREFLIGHT_TIMEOUT_SECONDS <= 10


class TestDockerPreflightUnexpectedError:
    def test_exception_during_probe_is_a_distinct_status(self):
        with mock.patch.object(di, "docker_available", return_value=True), \
             mock.patch.object(di, "run_docker_command", side_effect=OSError("boom")):
            result = di.docker_preflight()
        assert result.ready is False
        assert result.status == "ERROR"
        assert "failed unexpectedly" in result.reason
        assert "boom" in result.reason


class TestDockerPreflightDaemonUnusable:
    def test_server_errors_reported_even_with_zero_exit_code(self):
        with mock.patch.object(di, "docker_available", return_value=True), \
             mock.patch.object(di, "run_docker_command") as m_run:
            m_run.return_value = ('{"ServerErrors": ["storage driver failure"]}', "", 0, False)
            result = di.docker_preflight()
        assert result.ready is False
        assert result.status == "DAEMON_UNUSABLE"
        assert "storage driver failure" in result.reason

    def test_malformed_json_does_not_crash_and_is_treated_as_ready(self):
        """docker info succeeding (exit 0) with output we can't parse as
        JSON degrades to "ready" rather than raising -- we only use the
        JSON to detect a KNOWN problem signal, never require it to be
        well-formed to trust a clean exit code."""
        with mock.patch.object(di, "docker_available", return_value=True), \
             mock.patch.object(di, "run_docker_command") as m_run:
            m_run.return_value = ("not json", "", 0, False)
            result = di.docker_preflight()
        assert result.ready is True
        assert result.status == "OK"


class TestDockerPreflightReady:
    def test_clean_response_is_ready(self):
        with mock.patch.object(di, "docker_available", return_value=True), \
             mock.patch.object(di, "run_docker_command") as m_run:
            m_run.return_value = ('{"ServerErrors": []}', "", 0, False)
            result = di.docker_preflight()
        assert result.ready is True
        assert result.status == "OK"
        assert result.reason is None


class TestDockerPreflightBoundedDetail:
    def test_long_stderr_is_bounded_in_the_reason(self):
        huge_stderr = "x" * 50_000
        with mock.patch.object(di, "docker_available", return_value=True), \
             mock.patch.object(di, "run_docker_command") as m_run:
            m_run.return_value = ("", huge_stderr, 1, False)
            result = di.docker_preflight()
        assert len(result.reason) < 1000  # bounded, never a giant dump


class TestDockerPreflightNeverPullsOrBuildsAnImage:
    def test_no_docker_build_or_docker_pull_invocation_anywhere(self):
        with mock.patch.object(di, "docker_available", return_value=True), \
             mock.patch.object(di, "run_docker_command") as m_run:
            m_run.return_value = ("{}", "", 0, False)
            di.docker_preflight()
        for call in m_run.call_args_list:
            cmd = call[0][0]
            assert "build" not in cmd
            assert "pull" not in cmd
