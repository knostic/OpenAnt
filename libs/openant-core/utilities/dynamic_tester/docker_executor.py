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
import uuid
from utilities.file_io import open_utf8, run_utf8

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
    """Fix LLM-generated docker-compose issues AND enforce network isolation (F4).

    The compose file is UNTRUSTED LLM output and is built+run (executed). Force every
    network `internal: true` (no external egress) so an executing test cannot exfiltrate
    at RUNTIME, while intra-network service-to-service (the attacker capture server at
    `attacker:9999`, CWE-918 pattern) keeps working — an internal Docker network still
    resolves + routes service names, it only loses the external gateway.

    `internal: true` ALONE is bypassable, so this also, structurally (via PyYAML, not
    regex — a hostile file defeats textual patching):
      * strips every service `network_mode` (host/bridge would escape the internal net);
      * drops host `ports:` publishes (incompatible with an internal net anyway);
      * sets `internal: true` on every declared network AND injects an internal `default`
        so a service that omits `networks:` (implicit default) is still contained.
    Also removes obsolete `version:` and local-builds any remote attacker image.

    RESIDUAL (documented, NOT closed here): `docker build`/`compose build` run untrusted
    `RUN` steps with full egress, so build-time exfil/beaconing is still possible. The
    build context is minimal (generated test files + one pre-staged source file, no host
    secrets), and the exploit executes at RUNTIME where this policy applies — so runtime
    isolation is worth it, but this whole change is sandbox HARDENING, not a vuln fix.
    """
    try:
        import yaml
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("compose root is not a mapping")
    except Exception:
        # FAIL CLOSED. If PyYAML cannot parse+structure the compose we cannot prove
        # network isolation — and `docker compose` (compose-go, a DIFFERENT YAML impl)
        # might still parse+run the untrusted original with full egress. So we must NOT
        # return the untrusted content (nor a regex-patched copy, which cannot reliably
        # strip network_mode/external). Replace it with a refusing comment-only compose:
        # `docker compose build` then fails ("no services") -> build_error -> the finding
        # is recorded as ERROR and never executed. No egress. (We do not raise: the
        # orchestrator calls run_single_container unwrapped, so a raise would abort the
        # whole dynamic-test run instead of just this finding.)
        return ("# openant: docker-compose could not be safely parsed/sanitized; "
                "refusing to run it (fail-closed).\n")

    data.pop("version", None)

    networks = data.get("networks")
    if not isinstance(networks, dict):
        networks = {}
    for name, cfg in list(networks.items()):
        cfg = cfg if isinstance(cfg, dict) else {}
        # Drop `external`/`name`: an external network is one Compose does NOT create,
        # so it attaches services to a PRE-EXISTING network by name (e.g. `bridge`,
        # which has egress) and ignores our `internal: true`. Forcing Compose to
        # create the network fresh is what makes `internal` actually apply.
        cfg.pop("external", None)
        cfg.pop("name", None)
        cfg["internal"] = True
        networks[name] = cfg
    default = networks.get("default")
    default = default if isinstance(default, dict) else {}
    default.pop("external", None)
    default.pop("name", None)
    default["internal"] = True
    networks["default"] = default
    data["networks"] = networks

    services = data.get("services")
    if isinstance(services, dict):
        for svc in services.values():
            if not isinstance(svc, dict):
                continue
            svc.pop("network_mode", None)   # host/bridge escapes the internal network
            svc.pop("ports", None)          # host publish incompatible with internal
            img = svc.get("image")
            if isinstance(img, str) and "attacker" in img.lower():
                svc.pop("image", None)
                svc["build"] = "./attacker-server"

    return yaml.safe_dump(data, default_flow_style=False, sort_keys=False)


def _write_test_files(work_dir: str, generation: dict, source_file: str | None = None) -> None:
    """Write generated test files into the working directory.

    Args:
        work_dir: Temporary directory used as Docker build context.
        generation: LLM-generated test artifacts (dockerfile, test_script, …).
        source_file: Optional path to the vulnerable source file. When given,
            the file is copied into *work_dir* so the Dockerfile can COPY it
            without the LLM having to guess the path.
    """
    # Pre-stage the vulnerable source file so `COPY <basename> .` just works.
    if source_file and os.path.isfile(source_file):
        shutil.copy2(source_file, os.path.join(work_dir, os.path.basename(source_file)))

    # Write Dockerfile
    with open_utf8(os.path.join(work_dir, "Dockerfile"), "w") as f:
        f.write(generation["dockerfile"])

    # Write test script
    test_filename = generation.get("test_filename", "test_exploit.py")
    test_path = os.path.join(work_dir, test_filename)
    os.makedirs(os.path.dirname(test_path), exist_ok=True)
    with open_utf8(test_path, "w") as f:
        f.write(generation["test_script"])

    # Write requirements/dependencies file
    if generation.get("requirements"):
        req_filename = generation.get("requirements_filename", "requirements.txt")
        req_path = os.path.join(work_dir, req_filename)
        os.makedirs(os.path.dirname(req_path), exist_ok=True)
        with open_utf8(req_path, "w") as f:
            f.write(generation["requirements"])

    # Copy attacker server if needed (before docker-compose so it's available)
    if generation.get("needs_attacker_server"):
        attacker_dir = os.path.join(work_dir, "attacker-server")
        os.makedirs(attacker_dir, exist_ok=True)
        shutil.copy2(ATTACKER_SERVER_PATH, os.path.join(attacker_dir, "server.py"))
        # Write attacker Dockerfile
        with open_utf8(os.path.join(attacker_dir, "Dockerfile"), "w") as f:
            f.write("FROM python:3.11-slim\nWORKDIR /app\nCOPY server.py .\n"
                    "EXPOSE 9999\nCMD [\"python\", \"server.py\"]\n")

    # Write docker-compose if multi-service, with sanitization
    if generation.get("docker_compose"):
        compose_content = _sanitize_compose(generation["docker_compose"])
        with open_utf8(os.path.join(work_dir, "docker-compose.yml"), "w") as f:
            f.write(compose_content)


def _run_command(cmd: list[str], timeout: int, cwd: str = None) -> tuple[str, str, int, bool]:
    """Run a command with timeout. Returns (stdout, stderr, exit_code, timed_out)."""
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


def run_single_container(
    generation: dict,
    finding_id: str,
    container_timeout: int = DEFAULT_CONTAINER_TIMEOUT,
    build_timeout: int = DEFAULT_BUILD_TIMEOUT,
    source_file: str | None = None,
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
    # UUID prefix prevents collisions between parallel dynamic-test runs
    # (same finding IDs across scans).
    run_id = uuid.uuid4().hex[:8]
    safe_id = re.sub(r"[^a-z0-9-]", "-", finding_id.lower()).strip("-_.")
    image_tag = f"openant-test-{run_id}-{safe_id}"
    network_name = f"openant-net-{run_id}-{safe_id}"

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
        _write_test_files(work_dir, generation, source_file=source_file)

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

    # F4 hardening: a single-container test has NO sibling service, so it needs no
    # network at all. `--network none` (loopback only, no gateway/DNS) is strictly
    # stronger and simpler than an --internal network: an executing test derived from
    # untrusted findings cannot exfiltrate at runtime, and in-container client->server
    # tests still work over loopback. (No `docker network create` needed for this path.)
    # RESIDUAL: build-time RUN egress is still open — see _sanitize_compose. Hardening,
    # not a vuln fix. The multi-service path uses an internal compose network instead.
    stdout, stderr, code, timed_out = _run_command(
        [
            "docker", "run",
            "--rm",
            "--network", "none",
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
