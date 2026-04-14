"""Docker container execution for dynamic exploit tests.

Handles building images, running containers with timeouts,
and collecting stdout/stderr output. All execution is isolated
in Docker containers with no host volume mounts or privileged mode.
"""

import os
import re
import shutil
import subprocess
import tempfile
import time

# Timeouts
DEFAULT_CONTAINER_TIMEOUT = 120   # seconds per container
DEFAULT_BUILD_TIMEOUT = 300       # seconds for docker build

# Path to the bundled attacker server
_TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker_templates")
ATTACKER_SERVER_PATH = os.path.join(_TEMPLATES_DIR, "attacker_server.py")


class DockerExecutionResult:
    """Result from running a Docker container."""

    def __init__(self):
        self.stdout: str = ""
        self.stderr: str = ""
        self.exit_code: int = -1
        self.timed_out: bool = False
        self.build_error: str | None = None
        self.elapsed_seconds: float = 0.0

    @property
    def success(self) -> bool:
        return self.build_error is None and not self.timed_out


def _sanitize_compose(content: str) -> str:
    """Fix common LLM-generated docker-compose issues.

    - Removes obsolete `version:` key
    - Replaces remote attacker server images with local build
    """
    # Remove version: line (obsolete in modern docker compose)
    content = re.sub(r'^version:.*\n', '', content, flags=re.MULTILINE)

    # Replace any remote image references for attacker/capture services
    # with local build from ./attacker-server
    content = re.sub(
        r'image:\s*[^\n]*attacker[^\n]*',
        'build: ./attacker-server',
        content,
        flags=re.IGNORECASE,
    )

    return content


def _write_test_files(work_dir: str, generation: dict) -> None:
    """Write generated test files into the working directory."""
    # Write Dockerfile
    with open(os.path.join(work_dir, "Dockerfile"), "w") as f:
        f.write(generation["dockerfile"])

    # Write test script
    test_filename = generation.get("test_filename", "test_exploit.py")
    test_path = os.path.join(work_dir, test_filename)
    os.makedirs(os.path.dirname(test_path), exist_ok=True)
    with open(test_path, "w") as f:
        f.write(generation["test_script"])

    # Write requirements/dependencies file
    if generation.get("requirements"):
        req_filename = generation.get("requirements_filename", "requirements.txt")
        req_path = os.path.join(work_dir, req_filename)
        os.makedirs(os.path.dirname(req_path), exist_ok=True)
        with open(req_path, "w") as f:
            f.write(generation["requirements"])

    # Copy attacker server if needed (before docker-compose so it's available)
    if generation.get("needs_attacker_server"):
        attacker_dir = os.path.join(work_dir, "attacker-server")
        os.makedirs(attacker_dir, exist_ok=True)
        shutil.copy2(ATTACKER_SERVER_PATH, os.path.join(attacker_dir, "server.py"))
        # Write attacker Dockerfile
        with open(os.path.join(attacker_dir, "Dockerfile"), "w") as f:
            f.write("FROM python:3.11-slim\nWORKDIR /app\nCOPY server.py .\n"
                    "EXPOSE 9999\nCMD [\"python\", \"server.py\"]\n")

    # Write docker-compose if multi-service, with sanitization
    if generation.get("docker_compose"):
        compose_content = _sanitize_compose(generation["docker_compose"])
        with open(os.path.join(work_dir, "docker-compose.yml"), "w") as f:
            f.write(compose_content)


def _run_command(cmd: list[str], timeout: int, cwd: str = None) -> tuple[str, str, int, bool]:
    """Run a command with timeout. Returns (stdout, stderr, exit_code, timed_out)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired:
        return "", "Command timed out", -1, True


def run_single_container(
    generation: dict,
    finding_id: str,
    container_timeout: int = DEFAULT_CONTAINER_TIMEOUT,
    build_timeout: int = DEFAULT_BUILD_TIMEOUT,
) -> DockerExecutionResult:
    """Build and run a single Docker container for a test.

    Args:
        generation: Test generation output (dockerfile, test_script, etc.)
        finding_id: Finding ID for image naming
        container_timeout: Max seconds for container execution
        build_timeout: Max seconds for docker build

    Returns:
        DockerExecutionResult with stdout/stderr/exit_code
    """
    result = DockerExecutionResult()
    start_time = time.time()

    # Sanitize finding_id for use as Docker image tag.
    # Docker tags must match [a-z0-9][a-z0-9._-]*, so strip anything else.
    safe_id = re.sub(r"[^a-z0-9-]", "-", finding_id.lower()).strip("-_.")
    image_tag = f"openant-test-{safe_id}"
    network_name = f"openant-net-{safe_id}"

    # Use a deterministic, sanitized work_dir name so docker compose project
    # names (derived from the dir name) are always valid Docker references.
    # We still use mkdtemp for uniqueness but strip any non-alphanumeric chars.
    raw_work_dir = tempfile.mkdtemp(prefix=f"openant-test-{safe_id}-")
    parent = os.path.dirname(raw_work_dir)
    safe_basename = re.sub(r"[^a-z0-9-]", "", os.path.basename(raw_work_dir).lower()).strip("-")
    work_dir = os.path.join(parent, safe_basename)
    if work_dir != raw_work_dir:
        os.rename(raw_work_dir, work_dir)

    try:
        _write_test_files(work_dir, generation)

        if generation.get("docker_compose") and generation.get("needs_attacker_server"):
            # Multi-service: use docker compose with explicit project name
            result = _run_compose(work_dir, safe_id, container_timeout, build_timeout)
        else:
            # Single container: docker build + run
            result = _run_single(work_dir, image_tag, network_name,
                                 container_timeout, build_timeout)
    finally:
        result.elapsed_seconds = time.time() - start_time
        # Clean up work directory
        shutil.rmtree(work_dir, ignore_errors=True)
        # Clean up Docker resources (best effort)
        _cleanup_docker(image_tag, network_name)

    return result


def _run_single(
    work_dir: str,
    image_tag: str,
    network_name: str,
    container_timeout: int,
    build_timeout: int,
) -> DockerExecutionResult:
    """Build and run a single Docker container."""
    result = DockerExecutionResult()

    # Build
    stdout, stderr, code, timed_out = _run_command(
        ["docker", "build", "-t", image_tag, "."],
        timeout=build_timeout,
        cwd=work_dir,
    )
    if code != 0 or timed_out:
        result.build_error = stderr if not timed_out else "Build timed out"
        result.stderr = stderr
        result.timed_out = timed_out
        return result

    # Create isolated network
    _run_command(["docker", "network", "create", network_name], timeout=10)

    # Run with timeout, no host mounts, no privileged mode.
    # tmpfs for /tmp (writable workspace) and /root (for build caches like
    # ~/.cache/go-build that some test runners write to even at runtime).
    stdout, stderr, code, timed_out = _run_command(
        [
            "docker", "run",
            "--rm",
            "--network", network_name,
            "--memory", "512m",
            "--cpus", "1",
            "--read-only",
            "--tmpfs", "/tmp:size=256m",
            "--tmpfs", "/root:size=128m",
            "--security-opt", "no-new-privileges",
            image_tag,
        ],
        timeout=container_timeout,
        cwd=work_dir,
    )

    result.stdout = stdout
    result.stderr = stderr
    result.exit_code = code
    result.timed_out = timed_out

    return result


def _run_compose(
    work_dir: str,
    project_name: str,
    container_timeout: int,
    build_timeout: int,
) -> DockerExecutionResult:
    """Build and run multi-service test via docker compose.

    Uses an explicit project name to ensure image tags are always valid
    Docker references, independent of the temp dir name.
    """
    result = DockerExecutionResult()

    compose_base = ["docker", "compose", "-p", project_name]

    # Build all services
    stdout, stderr, code, timed_out = _run_command(
        compose_base + ["build"],
        timeout=build_timeout,
        cwd=work_dir,
    )
    if code != 0 or timed_out:
        result.build_error = stderr if not timed_out else "Compose build timed out"
        result.stderr = stderr
        result.timed_out = timed_out
        return result

    # Start services
    _run_command(
        compose_base + ["up", "-d"],
        timeout=60,
        cwd=work_dir,
    )

    try:
        # Wait for the test container to exit (it should be the main service)
        stdout, stderr, code, timed_out = _run_command(
            compose_base + ["logs", "--no-log-prefix", "-f", "test"],
            timeout=container_timeout,
            cwd=work_dir,
        )
        result.stdout = stdout
        result.stderr = stderr
        result.exit_code = code
        result.timed_out = timed_out
    finally:
        # Always tear down
        _run_command(
            compose_base + ["down", "--volumes", "--remove-orphans"],
            timeout=30,
            cwd=work_dir,
        )

    return result


def _cleanup_docker(image_tag: str, network_name: str) -> None:
    """Best-effort cleanup of Docker resources."""
    # Remove image
    _run_command(["docker", "rmi", "-f", image_tag], timeout=10)
    # Remove network
    _run_command(["docker", "network", "rm", network_name], timeout=10)
