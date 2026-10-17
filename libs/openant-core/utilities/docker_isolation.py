"""Shared low-level Docker execution primitives.

These are the generic, non-exploit-specific pieces already validated by
``utilities.dynamic_tester.docker_executor`` — a "run a command with a
timeout" wrapper and best-effort image/network/container cleanup — factored
out here so a second caller (``utilities.autopatcher.test_executors``,
for Existing Test Comparison) can reuse them without importing
dynamic_tester's LLM-driven exploit-PoC-generation code path or its
custom exploit-verdict result model.

``utilities/dynamic_tester/docker_executor.py`` itself is left untouched —
it already has its own tested, working copies of this same logic; migrating
it to import from here is a separate, later refactor, not bundled with this
feature.

Nothing in this module decides *what* to run or *how* to isolate it beyond
this shared timeout/cleanup mechanic — Dockerfile content, resource limits,
network mode, and mount/tmpfs choices are the caller's responsibility.

Also home to ``docker_preflight()`` — the ONE canonical, cheap Docker
readiness check (CLI present, daemon reachable, daemon minimally usable)
callers should use before doing any real Docker work. It exists so a
caller like Existing Test Comparison can fail fast, before
spending an LLM call or building a workspace, rather than discovering
"Cannot connect to the Docker daemon" only after that cost is already
spent.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

from utilities.file_io import run_utf8

_PREFLIGHT_TIMEOUT_SECONDS = 5
_MAX_PREFLIGHT_DETAIL_CHARS = 300


def docker_available() -> bool:
    """True when a `docker` executable is on PATH. Never raises."""
    try:
        return shutil.which("docker") is not None
    except Exception:  # noqa: BLE001
        return False


@dataclass(frozen=True)
class DockerPreflightResult:
    """Verdict from ``docker_preflight()``. ``status`` is a closed,
    precise set of reasons (never collapsed into one generic "Docker
    unavailable") so a caller/report can say exactly what's wrong:
        OK                 -- ready to build/run
        CLI_MISSING        -- the `docker` executable isn't on PATH
        DAEMON_UNREACHABLE -- CLI present, daemon didn't respond (exit != 0)
        DAEMON_UNUSABLE    -- daemon responded but reported its own errors
        TIMEOUT            -- the readiness probe itself timed out
        ERROR              -- an unexpected exception during the probe
    """
    ready: bool
    status: str
    reason: "str | None"


def _bounded_detail(text: "str | None", limit: int = _MAX_PREFLIGHT_DETAIL_CHARS) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + " [... truncated]"


def _extract_server_errors(stdout: str) -> "str | None":
    """`docker info --format '{{json .}}'` includes a `ServerErrors` list
    when the daemon itself is in a broken state (e.g. storage driver
    failure) even though it responded (exit 0) -- this is what
    distinguishes DAEMON_UNUSABLE from a clean OK without any extra
    subprocess call."""
    try:
        data = json.loads(stdout)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    errors = data.get("ServerErrors")
    if errors:
        return "; ".join(str(e) for e in errors)
    return None


def docker_preflight(timeout: int = _PREFLIGHT_TIMEOUT_SECONDS) -> DockerPreflightResult:
    """Cheap, deterministic check that Docker is ready to build/run a
    container. Never pulls or builds anything -- the only subprocess this
    runs is one bounded ``docker info`` call, which proves CLI presence,
    daemon connectivity, and (via ``ServerErrors``) minimal daemon health,
    all in a single round trip. Never raises.
    """
    if not docker_available():
        return DockerPreflightResult(
            ready=False, status="CLI_MISSING",
            reason=(
                "docker is not installed (the `docker` command was not found on PATH). "
                "Install Docker and rerun with --compare-existing-tests."
            ),
        )

    try:
        stdout, stderr, code, timed_out = run_docker_command(
            ["docker", "info", "--format", "{{json .}}"], timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 -- preflight itself must never crash the caller
        return DockerPreflightResult(
            ready=False, status="ERROR",
            reason=f"the Docker readiness check failed unexpectedly ({type(exc).__name__}: {exc}).",
        )

    if timed_out:
        return DockerPreflightResult(
            ready=False, status="TIMEOUT",
            reason=(
                f"the Docker readiness check (`docker info`) timed out after {timeout}s. "
                "Check that Docker is responsive and rerun with --compare-existing-tests."
            ),
        )
    if code != 0:
        return DockerPreflightResult(
            ready=False, status="DAEMON_UNREACHABLE",
            reason=(
                f"the Docker daemon is not reachable ({_bounded_detail(stderr or stdout)}). "
                "Start Docker and rerun with --compare-existing-tests."
            ),
        )

    server_errors = _extract_server_errors(stdout)
    if server_errors:
        return DockerPreflightResult(
            ready=False, status="DAEMON_UNUSABLE",
            reason=(
                f"the Docker daemon is reachable but reported errors ({_bounded_detail(server_errors)}). "
                "Check your Docker installation and rerun with --compare-existing-tests."
            ),
        )

    return DockerPreflightResult(ready=True, status="OK", reason=None)


def run_docker_command(
    cmd: "list[str]", timeout: int, cwd: "str | None" = None
) -> "tuple[str, str, int, bool]":
    """Run a docker CLI command with a timeout.

    Returns ``(stdout, stderr, exit_code, timed_out)``. Never raises for a
    timeout or a missing executable — both degrade to a result tuple the
    caller can classify, mirroring
    ``utilities.dynamic_tester.docker_executor._run_command``.
    """
    try:
        result = run_utf8(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1, True
    except FileNotFoundError:
        return "", "docker executable not found", -1, False


def cleanup_docker_image(image_tag: str, timeout: int = 10) -> None:
    """Best-effort image removal. Never raises."""
    run_docker_command(["docker", "rmi", "-f", image_tag], timeout=timeout)


def cleanup_docker_network(network_name: str, timeout: int = 10) -> None:
    """Best-effort network removal. Never raises."""
    run_docker_command(["docker", "network", "rm", network_name], timeout=timeout)


def cleanup_docker_container(container_name: str, timeout: int = 10) -> None:
    """Best-effort forced container removal. Never raises.

    Needed even when the container was started with ``--rm``: if the run
    is killed by our own timeout (see callers), the container may still be
    running server-side and ``--rm`` never fires — an explicit `docker kill`
    followed by this removal is the caller's responsibility for that path.
    """
    run_docker_command(["docker", "rm", "-f", container_name], timeout=timeout)


def kill_docker_container(container_name: str, timeout: int = 10) -> None:
    """Best-effort forced stop of a still-running container. Never raises."""
    run_docker_command(["docker", "kill", container_name], timeout=timeout)
