"""#710: the recorded ruling — build egress accepted by design, the state pinned.

#247 closed RUNTIME egress (``--network none`` / internal compose nets) and
named the build half as deferred. The falsifier (authored at filing): "a
dynamic-test build whose RUN steps resolve only allowlisted hosts (or a
recorded ruling that build egress is accepted by design)."

This suite pins the SECOND disjunct: the recorded ruling (the executed
evidence that killed the host-proxy alternative is named at the single-build
site in ``docker_executor.py``) + the DRIFT PINS — the accepted state (the
build invocations run with default networking, exactly as #247 left them;
the runtime argv closed; the env allowlist in force) cannot drift silently:
any flag added to a build (e.g. ``--network host``), any runtime flag
removed, any allowlist entry loosened, is a deliberate diff that fires these
pins.
"""

import sys
from pathlib import Path

_CORE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_CORE_ROOT))


def _executor():
    import utilities.dynamic_tester.docker_executor as de
    return de


def _capture(argvs):
    def run(cmd, timeout, cwd=None):
        argvs.append(cmd)
        return ("", "", 0, False)
    return run


# --- the drift pins: the accepted build state, exactly ---

def test_the_single_container_build_argv_is_exactly_the_accepted_state(monkeypatch):
    """The accepted build state pinned: `docker build -t <tag> .` — no
    network flag, no proxy routing, nothing added. A drift (e.g.
    --network host, a build-arg) is a deliberate diff this pin names."""
    de = _executor()
    argvs = []
    monkeypatch.setattr(de, "_run_command", _capture(argvs))
    de._run_single("/tmp/w", "img", "net", container_timeout=5,
                   build_timeout=5, container_name="c")
    builds = [a for a in argvs if a[:2] == ["docker", "build"]]
    assert builds, argvs
    assert builds[0] == ["docker", "build", "-t", "img", "."], builds[0]


def test_the_compose_build_argv_is_exactly_the_accepted_state(monkeypatch):
    """The compose twin: `docker compose -p <proj> build` — nothing added."""
    de = _executor()
    argvs = []
    monkeypatch.setattr(de, "_run_command", _capture(argvs))
    de._run_compose("/tmp/w", "proj", container_timeout=5, build_timeout=5)
    builds = [a for a in argvs if a[:2] == ["docker", "compose"] and a[4:5] == ["build"]]
    assert builds, argvs
    assert builds[0] == ["docker", "compose", "-p", "proj", "build"], builds[0]


def test_the_runtime_argv_stays_closed(monkeypatch):
    """The #247 runtime posture unchanged: --network none + the resource/
    capability caps. (Re-derived here: the ruling's 'the RUNTIME sandbox is
    the hard boundary' clause is pinned, not just stated.)"""
    de = _executor()
    argvs = []
    monkeypatch.setattr(de, "_run_command", _capture(argvs))
    de._run_single("/tmp/w", "img", "net", container_timeout=5,
                   build_timeout=5, container_name="c")
    runs = [a for a in argvs if a[:2] == ["docker", "run"]]
    assert runs, argvs
    r = runs[0]
    assert "--network" in r and r[r.index("--network") + 1] == "none", r
    for flag in ("--rm", "--read-only", "--cap-drop", "--pids-limit",
                 "--memory", "--cpus", "--security-opt", "--tmpfs"):
        assert flag in r, f"the runtime cap {flag} drifted: {r}"
    assert r.count("--tmpfs") == 2, r  # /tmp + /root (the writable mounts)
    assert r[r.index("--cap-drop") + 1] == "ALL", r
    assert r[r.index("--security-opt") + 1] == "no-new-privileges", r


def test_the_env_allowlist_still_scrubs(monkeypatch):
    """The #247 env allowlist (what the build subprocess SEES) is the
    accepted posture's other half — a loosened entry is a drift this pin
    names. (Pinned on the machinery's contract, re-derived here: a provider
    secret is dropped, the docker essentials kept.)"""
    de = _executor()
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "x")
    env = de._scrubbed_subprocess_env()
    assert "ANTHROPIC_API_KEY" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["PATH"] == "/usr/bin" and env["DOCKER_HOST"].startswith("unix://")


def test_the_compose_build_file_side_route_is_dropped():
    """The compose FILE-side route to a host-network build: the LLM-authored
    compose's `build.network: host` (or extra_hosts / entitlements) is
    dropped by _safe_build's allowlist (context/dockerfile/args only) — the
    r2-D3 catch: no pin held this drop, so a one-line drift in _safe_build
    would silently reopen the exact --network host posture the build-argv
    pin guards. Pinned now: the drop is a deliberate state."""
    de = _executor()
    out = de._safe_build({
        "context": ".", "dockerfile": "Dockerfile",
        "network": "host",
        "extra_hosts": ["pypi.org=169.254.0.1"],
        "entitlements": ["network.host"],
        "args": {"A": "b"},
    })
    assert "network" not in out, out
    assert "extra_hosts" not in out, out
    assert "entitlements" not in out, out
    assert out.get("context") == "." and out.get("args") == {"A": "b"}, out


# --- the ruling's presence (the recorded decision, named where it lives) ---

def test_the_recorded_ruling_names_the_executed_evidence():
    """The falsifier's second disjunct: the ruling is RECORDED — the
    single-build site in docker_executor.py carries the decision and the
    TWO executed findings that killed the host-proxy alternative
    (unreachable-from-RUN-steps; advisory-not-structural) plus the ONE
    design judgment (the netns alternative disproportionate), so a future
    reader finds the DECISION and its evidence honestly labelled, not a
    bare 'accepted residual'."""
    # the pinned executor is load-bearing: assert its #247 half exists
    # (the runtime sandbox + the env scrub — the ruling's premises)
    import utilities.dynamic_tester.docker_executor as de
    assert callable(de._scrubbed_subprocess_env)
    src = (_CORE_ROOT / "utilities" / "dynamic_tester"
           / "docker_executor.py").read_text()
    assert "THE RECORDED RULING (the falsifier's second disjunct)" in src
    assert "ACCEPTED BY DESIGN" in src
    # the two executed findings + the one design judgment are named
    # (honestly labelled — not a bare assertion)
    assert "TWO EXECUTED findings" in src and "ONE" in src
    assert "DESIGN JUDGMENT (not executed)" in src
    assert "UNREACHABLE from the RUN steps" in src
    assert "ADVISORY, not" in src
    assert "disproportionate" in src
    # the runtime-boundary clause (the ruling's load-bearing premise)
    assert "the RUNTIME sandbox is" in src


def test_no_proxy_routing_was_left_behind():
    """The killed alternative left no residue: no proxy build-args anywhere
    in the executor (the wiring is fully reverted, the module is gone)."""
    src = (_CORE_ROOT / "utilities" / "dynamic_tester"
           / "docker_executor.py").read_text()
    assert "build_arg" not in src.replace("--build-arg", "build_arg__X")
    assert "HTTP_PROXY" not in src
    assert not (_CORE_ROOT / "utilities" / "dynamic_tester"
                / "build_egress_proxy.py").exists()
