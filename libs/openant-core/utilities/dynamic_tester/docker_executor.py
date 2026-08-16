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


# Per-service compose keys we KEEP when reconstructing an untrusted compose. This is an
# ALLOWLIST, not a blocklist: every container-runtime attribute that could grant host
# access — privileged, cap_add, pid/ipc/uts/userns:host, security_opt, devices,
# device_cgroup_rules, cgroup_parent, volumes/host binds (incl /var/run/docker.sock),
# network_mode, ports, user, sysctls, group_add, extra_hosts, dns, env_file, extends,
# secrets, configs, … — is DROPPED by omission and replaced with the fixed hardening set
# in `_harden_service`. A blocklist is non-terminating (network_mode was one round's
# miss); an allowlist contains the NEXT unknown key by default.
# An ORDERED tuple (not a set): the reconstruction iterates it to build each service,
# so a set's hash-randomized order would make the emitted compose non-deterministic.
_SVC_ALLOWLIST = (
    "build", "image", "depends_on", "command", "entrypoint",
    "environment", "expose", "working_dir", "healthcheck", "networks",
)


def _refuse_compose(reason: str) -> str:
    """A services-less (comment-only) compose: `docker compose build`/`up` create ZERO
    containers (verified), so the untrusted definition never executes and the finding is
    recorded non-CONFIRMED (fail-closed, no egress). Note `docker compose build` on an
    empty compose exits 0 ("empty compose file") rather than erroring — safety comes from
    "no services => nothing runs", not from a build failure. We do not raise — the
    orchestrator calls run_single_container unwrapped, so a raise would
    abort the whole dynamic-test run instead of just this finding."""
    return f"# openant: {reason}; refusing to run it (fail-closed).\n"


def _safe_build(build):
    """Return a build spec confined to the work_dir, or raise if it escapes it.

    A compose `build.context` of `/`, `..`, or an absolute path would make
    `docker build` read HOST paths into the image. Only `.`/`./<sub>` (no `..`,
    not absolute) is allowed; `build.dockerfile` is confined the same way.
    """
    def _confined(p) -> bool:
        return (isinstance(p, str) and not p.startswith("/")
                and ".." not in p.replace("\\", "/").split("/"))

    if isinstance(build, str):
        if not _confined(build):
            raise ValueError(f"unsafe build context: {build!r}")
        return build
    if isinstance(build, dict):
        ctx = build.get("context", ".")
        if not _confined(ctx):
            raise ValueError(f"unsafe build context: {ctx!r}")
        out = {"context": ctx}
        df = build.get("dockerfile")
        if df is not None:
            if not _confined(df):
                raise ValueError(f"unsafe dockerfile path: {df!r}")
            out["dockerfile"] = df
        args = build.get("args")
        if isinstance(args, (dict, list)):
            out["args"] = args
        return out
    raise ValueError("service has no usable build spec")


def _safe_leaf(name, default: str) -> str:
    """Confine an LLM-supplied staging filename to a bare leaf inside work_dir.

    generation['test_filename'] / ['requirements_filename'] are LLM output
    influenced by the scanned repo. Used raw as `os.path.join(work_dir, name)`
    they let a `..`/absolute value escape work_dir and write to the HOST during
    pre-container staging (the compose `build.context` analogue that _safe_build
    already confines). The scaffold is flat by construction — the generation
    schema's examples are plain basenames, Dockerfiles `COPY <basename> .` at
    WORKDIR, and pip needs requirements.txt at the build-context root — so
    basename is strictly correct and strips any traversal.

    Fail-closed WITHOUT raising: an unwrapped raise here would abort the whole
    dynamic-test run (see _refuse_compose), so a hostile value degrades to a
    harmless leaf (COPY mismatch -> NOT_REPRODUCED) rather than a host write.
    A non-str value (JSON allows any type), a dot-segment ('.'/'..' -> a
    directory, not a file), and a name colliding with a fixed staging path
    (Dockerfile / docker-compose.yml / attacker-server) all degrade to `default`
    so nothing downstream raises IsADirectoryError / FileExistsError / TypeError.
    """
    if not isinstance(name, str):
        return default
    # A NUL (or other control char) is a str that survives basename and the
    # reserved check, but open()/os.path.join raise ValueError("embedded null
    # byte") — an unwrapped raise here would abort the whole run (the exact
    # fail-closed contract this helper exists to keep). Reject any name carrying a
    # control character (0x00-0x1f, 0x7f) and degrade to the default leaf.
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in name):
        return default
    leaf = os.path.basename(name)
    _RESERVED = {"", ".", "..", "Dockerfile", "docker-compose.yml", "attacker-server"}
    return default if leaf in _RESERVED else leaf


def _harden_service(name: str, svc: dict) -> dict:
    """Reconstruct ONE service from the allowlist + the fixed hardening set (C).

    Runtime-privilege keys are dropped by omission (allowlist). No `user`: the container
    runs as its image default (root) with a writable HOME via the /root tmpfs — dropping
    `user` avoids the read-only-`$HOME` breakage that flips HOME-cache-writing tests to
    ERROR, while cap_drop ALL + no-new-privileges + read_only + the internal-only network
    still prevent privilege escalation and host access.
    """
    out = {k: svc[k] for k in _SVC_ALLOWLIST if k in svc}

    # Attacker capture sidecar: a remote "attacker" image is replaced by the bundled,
    # OpenAnt-owned build context (preserves the prior behaviour).
    img = out.get("image")
    if isinstance(img, str) and "attacker" in img.lower():
        out.pop("image", None)
        out["build"] = "./attacker-server"

    if "build" in out:
        out["build"] = _safe_build(out["build"])
    if "build" not in out and "image" not in out:
        raise ValueError(f"service {name!r} declares neither a safe build nor an image")

    # Service network membership is preserved (from the allowlist) and every declared
    # network is forced `internal: true` at the doc level below, so service-name
    # resolution (test -> attacker:9999) keeps working with no external gateway.

    # (C) fixed per-service hardening — applied uniformly to EVERY service, attacker
    # sidecar included (it keeps captures in memory, so read_only is safe; :9999 > 1024
    # so cap_drop ALL does not break its bind).
    out["read_only"] = True
    out["cap_drop"] = ["ALL"]
    out["security_opt"] = ["no-new-privileges:true"]
    out["pids_limit"] = 256
    out["mem_limit"] = "512m"
    out["cpus"] = 1.0
    # Writable scratch + a writable HOME (=/root, image default user) on the RO rootfs.
    out["tmpfs"] = ["/tmp", "/root"]
    return out


def _sanitize_compose(content: str) -> str:
    """RECONSTRUCT an untrusted LLM/target-influenced docker-compose from an allowlist.

    The compose is UNTRUSTED and is built+run (executed). Rather than blocklist the
    dangerous keys (non-terminating — network_mode was one round's miss, then
    privileged/cap_add/volumes/pid/ipc/security_opt/devices), this DISCARDS the LLM's
    per-service runtime attributes entirely and rebuilds each declared service from a
    fixed allowlist (`_SVC_ALLOWLIST`) + a fixed hardening set (`_harden_service`): no
    privileged, no added caps (cap_drop ALL), no host mounts/volumes, no host namespaces,
    no devices, no host network, no `ports` publish, read-only rootfs, no-new-privileges,
    pids/mem/cpu caps — on an `internal: true` network with no external gateway.

    The SERVICE SET is preserved (test + attacker capture server + any extra service the
    generation legitimately needs, e.g. a DB for a SQLi test), so a multi-service test is
    not silently dropped; each service is reconstructed re-hardened.

    Fails CLOSED (returns a refusing comment-only compose) on unparseable YAML, a build
    context that escapes the work dir, or a service with neither a safe build nor an image.

    RESIDUAL (documented, NOT closed here): build-time `RUN` egress — `docker build`
    still runs the generated Dockerfile's RUN steps with network (an egress-allowlisting
    build proxy is deferred, an accepted residual). This change is RUNTIME sandbox
    hardening that makes the code enforce its stated "no host volume mounts or privileged
    mode" contract.
    """
    try:
        import yaml
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            raise ValueError("compose root is not a mapping")
    except Exception:
        return _refuse_compose("docker-compose could not be parsed")

    services_in = data.get("services")
    if not isinstance(services_in, dict) or not services_in:
        return _refuse_compose("docker-compose declares no services")

    services_out = {}
    try:
        for name, svc in services_in.items():
            if not isinstance(svc, dict):
                raise ValueError(f"service {name!r} is not a mapping")
            services_out[name] = _harden_service(name, svc)
    except Exception as exc:
        return _refuse_compose(f"docker-compose could not be safely reconstructed ({exc})")

    # Rebuild the networks: every DECLARED network is forced `internal: true` with
    # `external`/`name` stripped (an external net attaches services to a pre-existing,
    # egress-capable net by name and ignores `internal`), plus an injected internal
    # `default` so a service that omits `networks:` is still contained. Named top-level
    # `volumes:`/`secrets:`/`configs:`/`version:` are dropped by omission (services can
    # no longer reference them — host-bind `volumes:` were stripped per-service above).
    networks_in = data.get("networks")
    networks_out = {}
    if isinstance(networks_in, dict):
        for net_name, cfg in networks_in.items():
            cfg = cfg if isinstance(cfg, dict) else {}
            cfg = {k: v for k, v in cfg.items() if k not in ("external", "name")}
            cfg["internal"] = True
            networks_out[net_name] = cfg
    networks_out["default"] = {"internal": True}

    out = {"services": services_out, "networks": networks_out}
    return yaml.safe_dump(out, default_flow_style=False, sort_keys=False)


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

    # str() the content fields as a defense-in-depth belt: generate_test already
    # rejects a non-str content field (test_generator validation), but coercing here
    # too means a non-str value can never raise TypeError in f.write and abort the
    # whole run — it degrades to a garbage build that fails safe (NOT_REPRODUCED).
    # Write Dockerfile
    with open_utf8(os.path.join(work_dir, "Dockerfile"), "w") as f:
        f.write(str(generation["dockerfile"]))

    # Write test script (confine the LLM-supplied name to a leaf inside work_dir)
    test_filename = _safe_leaf(generation.get("test_filename"), "test_exploit.py")
    test_path = os.path.join(work_dir, test_filename)
    os.makedirs(os.path.dirname(test_path), exist_ok=True)
    with open_utf8(test_path, "w") as f:
        f.write(str(generation["test_script"]))

    # Write requirements/dependencies file
    if generation.get("requirements"):
        req_filename = _safe_leaf(generation.get("requirements_filename"), "requirements.txt")
        req_path = os.path.join(work_dir, req_filename)
        os.makedirs(os.path.dirname(req_path), exist_ok=True)
        with open_utf8(req_path, "w") as f:
            f.write(str(generation["requirements"]))

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


# The env the docker build/run subprocess is ALLOWED to see. `docker compose`
# interpolates a `${VAR}` in an untrusted, LLM-authored compose `build.args` from the
# subprocess env at BUILD time; the generated Dockerfile `RUN` then has open build-time
# network egress (an accepted GHSA-98g5 residual that assumed NO host secret was
# reachable at build time). An ALLOWLIST (not a deny-list) closes the exfil BY
# CONSTRUCTION: a provider secret with any name (ANTHROPIC_API_KEY, GH_PAT,
# AWS_ACCESS_KEY_ID, *_APIKEY, *_PASSPHRASE, *_AUTH, SLACK_WEBHOOK, …) is dropped by
# default because it is not on the list, so no new secret-name convention can leak.
# Docker's own needs are a bounded, well-known set. Tradeoff: a private base image
# pulled via a cloud credential-helper that reads secrets from ENV (e.g. AWS_* for
# ecr-login) will fail — use a prior `docker login` (writes config.json; DOCKER_CONFIG
# is allowed) instead. Public base images and pre-authenticated config.json are unaffected.
_ENV_ALLOW_EXACT = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "PWD", "TZ", "HOSTNAME",
    "TMPDIR", "TMP", "TEMP", "LANG", "LANGUAGE",
    "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO",
    "COLIMA_HOME", "SSH_AUTH_SOCK",  # ssh:// docker context needs the agent socket (a
                                     # unix-socket PATH, not a secret interpolable into a build-arg)
    # The BOUNDED set of real docker CLI knobs. NOT a `DOCKER_` prefix: that prefix
    # re-admits DOCKER_PASSWORD / DOCKER_AUTH_CONFIG (a GitLab-CI registry-cred var) /
    # DOCKER_TOKEN — the exact secret-by-name leak the allowlist exists to prevent.
    "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY", "DOCKER_API_VERSION", "DOCKER_BUILDKIT",
    "DOCKER_DEFAULT_PLATFORM", "DOCKER_CLI_EXPERIMENTAL", "DOCKER_CONTENT_TRUST",
    "BUILDKIT_HOST", "BUILDKIT_PROGRESS", "COMPOSE_PROJECT_NAME", "COMPOSE_FILE",
    "COMPOSE_PROFILES", "COMPOSE_DOCKER_CLI_BUILD",
    # Windows essentials so docker.exe resolves on CI runners.
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA",
    "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
})
# Only `LC_*` (locale) stays a prefix — it can never carry a provider secret. The
# docker/compose/buildkit knobs are enumerated exactly above precisely because their
# families ALSO contain credential-bearing names (DOCKER_PASSWORD/DOCKER_AUTH_CONFIG).
_ENV_ALLOW_PREFIXES = ("LC_",)
# Proxy vars may embed the user's OWN proxy credential — that is the user's network
# config (needed to reach the daemon/registry), not a provider API key, and dropping
# it would break builds behind a proxy.
_ENV_ALLOW_SUFFIXES = ("_PROXY", "_proxy")
_ENV_ALLOW_LOWER = frozenset({"no_proxy"})


def _scrubbed_subprocess_env() -> dict:
    """os.environ filtered to a docker-essentials ALLOWLIST for the build/run subprocess.

    Everything not explicitly allowed (every ``*_API_KEY`` / ``*_TOKEN`` / ``*_SECRET``
    / ``*_AUTH`` / ``*_PAT`` / arbitrary secret) is dropped, so no host secret can be
    interpolated into an untrusted compose build-arg and exfiltrated over build-time
    egress — regardless of the secret's name.
    """
    def _allowed(name: str) -> bool:
        up = name.upper()
        return (up in _ENV_ALLOW_EXACT
                or name in _ENV_ALLOW_LOWER
                or any(up.startswith(p) for p in _ENV_ALLOW_PREFIXES)
                or any(name.endswith(s) for s in _ENV_ALLOW_SUFFIXES))

    return {k: v for k, v in os.environ.items() if _allowed(k)}


def _run_command(cmd: list[str], timeout: int, cwd: str = None) -> tuple[str, str, int, bool]:
    """Run a command with timeout. Returns (stdout, stderr, exit_code, timed_out)."""
    try:
        result = run_utf8(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=_scrubbed_subprocess_env(),
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
            "--pids-limit", "256",
            "--cap-drop", "ALL",
            "--read-only",
            "--tmpfs", "/tmp:size=256m",
            "--tmpfs", "/root:size=128m",
            "--security-opt", "no-new-privileges",
            # No --user: the container runs as its image default (root) with a writable
            # HOME via the /root tmpfs above. cap_drop ALL + no-new-privileges + read_only
            # + --network none contain it; a non-root --user on a read-only rootfs would
            # instead move $HOME to an unwritable `/` and flip HOME-cache tests to ERROR.
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
