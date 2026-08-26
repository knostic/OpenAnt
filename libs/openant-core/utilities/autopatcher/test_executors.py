"""Generic executors for a validated TestExecutionPlan.

DockerTestExecutor knows nothing about pytest, npm, go test, tox, or any
other specific tool -- it only knows how to safely build and run
``plan.setup_commands``/``plan.test_command`` inside a hardened,
disposable container, using an OpenAnt-owned base image chosen from
``plan.runtime_family`` (never an LLM-supplied image string). This is the
only concrete executor shipped this release; LocalTestExecutor is an
inert skeleton for a later release -- it must never silently run
repository code on the host.

Security model -- stated precisely, not as a blanket "fully isolated"
claim, because it is not one:

  - ``docker build`` (the setup phase, running ``plan.setup_commands``)
    MAY have network access -- it uses the Docker daemon's default
    network, because installing dependencies generally requires reaching
    a package registry. This is an accepted, documented trade-off, not
    an oversight.
  - Repository-controlled install/build hooks (e.g. a package's own
    ``setup.py``, npm pre/postinstall scripts, a Cargo ``build.rs``) MAY
    execute during the setup phase, as an inherent, unavoidable property
    of running that ecosystem's own standard tooling at all.
  - The repository's source is present in the Docker build context (it
    has to be, to run its own tests) -- so setup-phase network access
    is a REPOSITORY-CONTENT CONFIDENTIALITY consideration (that source
    is exposed to whatever the setup phase can reach), not merely a
    host-safety one. It is not a confidentiality risk to OpenAnt's own
    secrets -- see the next two points.
  - The test-run phase (``docker run``, executing ``plan.test_command``)
    uses ``--network none`` -- no network access at all once setup has
    completed.
  - The host filesystem is never mounted into the container at any
    phase (no ``-v``/``--mount``/``--volume``) -- only the disposable,
    already-isolated workspace copy is baked into the build context via
    ``COPY``.
  - Host/OpenAnt environment variables (including any LLM provider API
    key) are never forwarded into the container at any phase -- no
    ``-e``/``--env`` flag is ever passed to ``docker build``/``docker
    run``; the container's entire environment comes from this module's
    own fixed, hardcoded Dockerfile ``ENV`` line.

What this containment protects: the HOST machine and OpenAnt's own
secrets, always. What it does NOT claim to protect: the confidentiality
of the target repository's own source/dependency-fetch traffic against a
malicious setup-phase package during the network-enabled setup phase --
that risk is real and inherent to running arbitrary ecosystem tooling,
and containment does not eliminate it.

Preserved from the original pytest-specific Docker runner this was
refactored from: no host bind mounts, no privileged mode,
no-new-privileges, memory/CPU/pid limits, read-only rootfs with tmpfs for
the only paths that need to be writable, bounded build/run timeouts with
explicit kill-on-timeout, and guaranteed cleanup.
"""

from __future__ import annotations

import json
import shlex
import time
import uuid
from pathlib import Path
from typing import Protocol

import utilities.docker_isolation as docker_isolation
from utilities.docker_isolation import (
    cleanup_docker_container,
    cleanup_docker_image,
    kill_docker_container,
    run_docker_command,
)
from .test_execution_models import ExecutorPreflightResult, TestExecutionPlan, TestExecutionResult

DEFAULT_SETUP_TIMEOUT = 300  # seconds for `docker build` (dependency install)
DEFAULT_RUN_TIMEOUT = 300    # seconds for the test command itself

_RESULT_START_MARKER = "__OPENANT_RESULT_START__"
_RESULT_END_MARKER = "__OPENANT_RESULT_END__"

_MAX_CAPTURED_CHARS = 200_000
_MAX_RESULT_CHARS = 5_000_000

_DOCKERIGNORE_CONTENT = ".git\n.venv\nvenv\n__pycache__\n*.pyc\nnode_modules\n.tox\n.pytest_cache\n"

# OpenAnt-owned runtime policy: the ONLY images this release will ever
# pull and execute. plan.runtime_family selects a KEY into this map; the
# plan never supplies the image string itself, and there is no field in
# TestExecutionPlan's schema that could even hold one.
# runtime_version_hint is stored for provenance/reporting only and does
# not affect image selection this release -- one approved image per
# family, kept deliberately simple. All three are Debian-based so the
# same apt-based "common tools" install step (below) works for all of
# them.
APPROVED_IMAGES = {
    "python": "python:3.11-slim",
    "node": "node:20-slim",
    "go": "golang:1.22-bookworm",
}

# A small, fixed set of orchestration tools installed into EVERY approved
# image, so a plan whose test_command is e.g. ["make", "test"] can run
# regardless of runtime_family. This is OpenAnt-controlled runtime
# policy -- it does not inspect or care what "make" is being asked to do.
_COMMON_APT_PACKAGES = ("make",)

# Per-runtime-family cache-directory redirects, all pointed at the one
# tmpfs mount this executor provides (/tmp). This lets the container's
# rootfs stay read-only without this module needing to know about any
# specific framework's cache directory (e.g. pytest's .pytest_cache) --
# it only needs to know a handful of well-known ecosystem-level cache
# env vars, which is executor/runtime policy, not test-framework logic.
_CACHE_ENV_BY_FAMILY = {
    "python": {"PIP_CACHE_DIR": "/tmp/cache/pip", "PYTHONPYCACHEPREFIX": "/tmp/cache/pycache"},
    "node": {"npm_config_cache": "/tmp/cache/npm", "YARN_CACHE_FOLDER": "/tmp/cache/yarn"},
    "go": {"GOCACHE": "/tmp/cache/go-build", "GOPATH": "/tmp/cache/gopath",
           "GOMODCACHE": "/tmp/cache/gopath/pkg/mod"},
}


def is_runtime_supported(runtime_family: "str | None") -> bool:
    """Whether OpenAnt has an approved execution environment for
    ``runtime_family`` in THIS release -- distinct from, and checked
    separately from, plan well-formedness (test_plan_validation.py)."""
    return runtime_family in APPROVED_IMAGES


class TestExecutor(Protocol):
    __test__ = False  # not a pytest test class -- name collides with pytest's Test* discovery

    def preflight(self) -> ExecutorPreflightResult:
        """Cheap, deterministic readiness check -- callers MUST call this
        and check `.ready` before doing any evidence acquisition, LLM
        Test Plan Discovery call, or workspace/build/run work. Never
        raises; never pulls/builds a repository image."""
        ...

    def run(
        self, plan: TestExecutionPlan, workspace_root: Path,
        setup_timeout: int = DEFAULT_SETUP_TIMEOUT, run_timeout: int = DEFAULT_RUN_TIMEOUT,
    ) -> TestExecutionResult: ...


def _truncate(text: "str | None", limit: int = _MAX_CAPTURED_CHARS) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... {len(text) - limit} more char(s) truncated]"


def _json_exec_form(argv: "tuple[str, ...]") -> str:
    """Docker RUN instruction in JSON/exec array form -- never interpreted
    by a shell, regardless of what characters ended up in a token."""
    return json.dumps(list(argv))


def _generate_dockerfile(plan: TestExecutionPlan, image: str) -> str:
    lines = [f"FROM {image}"]

    cache_env = _CACHE_ENV_BY_FAMILY.get(plan.runtime_family, {})
    env_pairs = {"HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1", **cache_env}
    # Fixed, executor-authored key/value pairs only -- never derived from
    # this process's own environment. This is what guarantees no OpenAnt
    # secret (e.g. an LLM provider API key) is ever forwarded into the
    # container, regardless of what setup_commands/test_command do.
    lines.append("ENV " + " ".join(f'{k}="{v}"' for k, v in env_pairs.items()))

    if _COMMON_APT_PACKAGES:
        pkgs = " ".join(_COMMON_APT_PACKAGES)
        lines.append(
            f"RUN apt-get update && apt-get install -y --no-install-recommends {pkgs} "
            "&& rm -rf /var/lib/apt/lists/*"
        )

    lines.append("WORKDIR /repo")
    lines.append("COPY . .")
    for cmd in plan.setup_commands:
        lines.append("RUN " + _json_exec_form(cmd))

    lines.append("COPY .openant_run_test.sh /usr/local/bin/openant_run_test.sh")
    lines.append("RUN chmod +x /usr/local/bin/openant_run_test.sh")
    lines.append('ENTRYPOINT ["/usr/local/bin/openant_run_test.sh"]')
    lines.append("")
    return "\n".join(lines)


def _generate_entrypoint_script(plan: TestExecutionPlan) -> str:
    """A small, deterministically-generated shell wrapper -- never
    LLM-authored -- that runs the already-validated test_command, then
    echoes whatever's at result_output_path (if any) between fixed
    markers so the caller can recover it from stdout without `docker cp`
    (which would require dropping --rm). Each test_command token is
    individually shell-quoted so the resulting script is safe regardless
    of token content, on top of test_plan_validation.py already denying
    shell metacharacters in every token."""
    quoted_command = " ".join(shlex.quote(t) for t in plan.test_command)
    result_path = plan.result_output_path or ""
    return f"""#!/bin/sh
set -u
{quoted_command}
EXIT_CODE=$?
echo "{_RESULT_START_MARKER}"
if [ -n "{result_path}" ] && [ -f "{result_path}" ]; then
  cat "{result_path}"
fi
echo "{_RESULT_END_MARKER}"
exit $EXIT_CODE
"""


def _stage_build_context(workspace_root: Path, plan: TestExecutionPlan, image: str) -> None:
    """Write THIS executor's own deterministic Dockerfile/.dockerignore/
    entrypoint script into the (already disposable) workspace copy,
    OVERWRITING anything the target repository itself shipped under
    those names. OpenAnt controls the execution container; it never
    builds or runs a Dockerfile authored by the repository under test."""
    (workspace_root / ".dockerignore").write_text(_DOCKERIGNORE_CONTENT, encoding="utf-8")
    (workspace_root / "Dockerfile").write_text(_generate_dockerfile(plan, image), encoding="utf-8")
    (workspace_root / ".openant_run_test.sh").write_text(_generate_entrypoint_script(plan), encoding="utf-8")


def _extract_result(stdout: str) -> "str | None":
    try:
        start = stdout.index(_RESULT_START_MARKER)
        end = stdout.index(_RESULT_END_MARKER, start)
    except ValueError:
        return None
    text = stdout[start + len(_RESULT_START_MARKER):end].strip("\n")
    if not text:
        return None
    return text[:_MAX_RESULT_CHARS]


class DockerTestExecutor:
    """The only concrete executor shipped this release."""

    def preflight(self) -> ExecutorPreflightResult:
        """Delegates to the one canonical Docker readiness check
        (utilities.docker_isolation.docker_preflight) rather than
        composing an ad-hoc combination of checks here -- CLI presence,
        daemon reachability, and minimal daemon usability, in a single
        bounded `docker info` call. Never pulls/builds a repository
        image.

        Accessed as ``docker_isolation.docker_preflight()`` (module-
        qualified, looked up at call time) rather than via a name bound
        directly into this module's namespace at import time -- so that
        patching the canonical helper at its own source
        (``utilities.docker_isolation.docker_preflight``, the one
        documented mock target) reliably takes effect here, instead of a
        stale pre-import-time binding silently ignoring the patch."""
        result = docker_isolation.docker_preflight()
        return ExecutorPreflightResult(ready=result.ready, reason=result.reason, status=result.status)

    def run(
        self, plan: TestExecutionPlan, workspace_root: "Path | str",
        setup_timeout: int = DEFAULT_SETUP_TIMEOUT, run_timeout: int = DEFAULT_RUN_TIMEOUT,
    ) -> TestExecutionResult:
        image = APPROVED_IMAGES.get(plan.runtime_family)
        if image is None:
            return TestExecutionResult(
                ran=False, exit_code=None, timed_out=False, setup_failed=True,
                setup_error=f"runtime not supported: {plan.runtime_family!r}",
                stdout="", stderr="", result_output=None, duration_seconds=0.0, executor="docker",
            )

        workspace_root = Path(workspace_root)
        start = time.time()
        run_id = uuid.uuid4().hex[:10]
        image_tag = f"openant-regtest-{run_id}"
        container_name = f"openant-regtest-run-{run_id}"

        try:
            _stage_build_context(workspace_root, plan, image)
        except OSError as exc:
            return TestExecutionResult(
                ran=False, exit_code=None, timed_out=False, setup_failed=True,
                setup_error=f"failed to stage Docker build context: {exc}",
                stdout="", stderr="", result_output=None,
                duration_seconds=time.time() - start, executor="docker",
            )

        try:
            b_stdout, b_stderr, b_code, b_timed_out = run_docker_command(
                ["docker", "build", "-t", image_tag, "."],
                timeout=setup_timeout, cwd=str(workspace_root),
            )
            if b_timed_out or b_code != 0:
                return TestExecutionResult(
                    ran=False, exit_code=None, timed_out=b_timed_out, setup_failed=True,
                    setup_error=_truncate(b_stderr) if b_stderr else "docker build timed out",
                    stdout="", stderr=_truncate(b_stderr), result_output=None,
                    duration_seconds=time.time() - start, executor="docker",
                )

            # No host bind mounts, no privileged mode, no host env
            # forwarding (no -e/--env flags anywhere in this argv --
            # anything the container needs is baked into the Dockerfile's
            # own fixed ENV line above), --network none at run time
            # (setup already had whatever network access it needed at
            # build time, above; the actual test run does not).
            r_stdout, r_stderr, r_code, r_timed_out = run_docker_command(
                [
                    "docker", "run",
                    "--name", container_name,
                    "--rm",
                    "--network", "none",
                    "--memory", "512m",
                    "--cpus", "1",
                    "--pids-limit", "256",
                    "--read-only",
                    "--tmpfs", "/tmp:size=512m",
                    "--security-opt", "no-new-privileges",
                    image_tag,
                ],
                timeout=run_timeout, cwd=str(workspace_root),
            )
            if r_timed_out:
                # A client-side subprocess timeout does not by itself stop
                # a still-running container -- force it down explicitly
                # so cleanup below is meaningful.
                kill_docker_container(container_name)
                return TestExecutionResult(
                    ran=False, exit_code=None, timed_out=True, setup_failed=False, setup_error="",
                    stdout=_truncate(r_stdout), stderr=_truncate(r_stderr), result_output=None,
                    duration_seconds=time.time() - start, executor="docker",
                )

            return TestExecutionResult(
                ran=True, exit_code=r_code, timed_out=False, setup_failed=False, setup_error="",
                stdout=_truncate(r_stdout), stderr=_truncate(r_stderr),
                result_output=_extract_result(r_stdout),
                duration_seconds=time.time() - start, executor="docker",
            )
        finally:
            cleanup_docker_image(image_tag)
            cleanup_docker_container(container_name)


class LocalTestExecutor:
    """Inert skeleton. Local execution means running repository code
    directly on the host -- it must NEVER silently happen. This class
    exists only so the TestExecutor interface and select_executor() below
    are already shaped for a future, explicitly opt-in local mode; it is
    not wired into any code path that runs by default."""

    def preflight(self) -> ExecutorPreflightResult:
        """Reports not-ready rather than raising -- preflight must never
        crash a caller that merely asked "is this ready," even for an
        executor that isn't implemented yet."""
        return ExecutorPreflightResult(
            ready=False, status="NOT_IMPLEMENTED",
            reason="local execution is not implemented in this release.",
        )

    def run(
        self, plan: TestExecutionPlan, workspace_root: "Path | str",
        setup_timeout: int = DEFAULT_SETUP_TIMEOUT, run_timeout: int = DEFAULT_RUN_TIMEOUT,
    ) -> TestExecutionResult:
        raise NotImplementedError(
            "Local execution is not implemented in this release. "
            "Docker is the only supported executor for Existing Test Comparison."
        )


def select_executor(mode: str) -> "TestExecutor":
    """Pure factory -- resolves WHICH executor class to use for `mode`.
    Deliberately does NOT check readiness itself (no docker_available()
    call, no daemon probe): that would create a second, weaker notion of
    "ready" alongside `.preflight()`'s canonical one. Callers MUST call
    `.preflight()` on the returned executor and check `.ready` before
    doing any real work. Raises ValueError for an unrecognized mode --
    never silently substitutes a different executor.
    """
    if mode == "docker":
        return DockerTestExecutor()
    if mode == "local":
        return LocalTestExecutor()
    raise ValueError(f"unknown execution mode: {mode!r}")
