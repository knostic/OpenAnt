"""F4 (docker sandbox egress hardening): the dynamic tester builds+runs UNTRUSTED
LLM-generated code. Network isolation must prevent RUNTIME external egress while
keeping the intra-network attacker-capture server (CWE-918) reachable.

RED pre-fix: _sanitize_compose only fixed version:/attacker image: and set no
network isolation; _run_single ran with a plain egress-capable network. A hostile
compose could keep external egress via a plain network, `network_mode: host`, or an
omitted `networks:` (implicit default). These tests lock the structural hardening.

This is sandbox HARDENING (opt-in --dynamic-test, already sandboxed), not a vuln fix;
build-time RUN egress remains an accepted, documented residual (not tested here).
"""
import yaml

from utilities.dynamic_tester.docker_executor import _sanitize_compose


def _parse(compose_yaml):
    return yaml.safe_load(_sanitize_compose(compose_yaml))


def test_all_declared_networks_forced_internal():
    out = _parse("""
services:
  test:
    build: .
    networks: [testnet]
  attacker:
    image: myrepo/attacker:latest
    networks: [testnet]
networks:
  testnet: {}
""")
    assert out["networks"]["testnet"]["internal"] is True


def test_default_network_injected_internal_for_omitted_networks():
    # A service with NO `networks:` joins the implicit `default` network — which must
    # also be forced internal, else the whole isolation is bypassed by omission.
    out = _parse("""
services:
  test:
    build: .
""")
    assert out["networks"]["default"]["internal"] is True


def test_network_mode_host_is_stripped():
    # network_mode: host escapes ANY internal network -> full host-stack egress.
    out = _parse("""
services:
  test:
    build: .
    network_mode: host
""")
    assert "network_mode" not in out["services"]["test"]


def test_ports_publish_dropped():
    out = _parse("""
services:
  test:
    build: .
    ports: ["8080:8080"]
""")
    assert "ports" not in out["services"]["test"]


def test_attacker_capture_server_still_local_built_and_reachable():
    # The capture server must survive (intra-network) so SSRF/CWE-918 tests still work;
    # a remote attacker image is rewritten to the local build.
    out = _parse("""
services:
  test:
    build: .
    networks: [testnet]
  attacker:
    image: some/remote-attacker:1
    networks: [testnet]
networks:
  testnet: {}
""")
    atk = out["services"]["attacker"]
    assert atk.get("build") == "./attacker-server"
    assert "image" not in atk
    # attacker stays on the (now-internal) network -> test can reach attacker:9999
    assert out["networks"]["testnet"]["internal"] is True


def test_version_key_removed():
    out = _parse("version: '3.8'\nservices:\n  test:\n    build: .\n")
    assert "version" not in out


def test_malformed_yaml_fails_closed_to_a_refusing_compose():
    # FAIL CLOSED: an unparseable compose must NOT be returned (nor a regex-patched
    # copy) — compose-go might still run the untrusted original with egress. The
    # sanitizer must not raise (the orchestrator calls it unwrapped) and must emit a
    # refusing comment-only compose (no services) so `docker compose build` fails.
    bad = "services:\n  test:\n  - this: [is, not, valid\n"
    result = _sanitize_compose(bad)  # must not raise
    assert isinstance(result, str)
    assert "refusing" in result.lower()
    parsed = yaml.safe_load(result)  # our output is valid YAML
    assert not (parsed or {}).get("services"), "fail-closed output must define no services"


def test_external_network_is_forced_internal_not_attached_to_bridge():
    # An `external: true` network is one docker compose does NOT create — it attaches
    # to a pre-existing (egress-capable) network by name, ignoring `internal: true`.
    # The sanitizer must strip external/name so compose creates a fresh internal net.
    out = _parse("""
services:
  test:
    build: .
    networks: [evil]
networks:
  evil:
    external: true
    name: bridge
""")
    net = out["networks"]["evil"]
    assert net.get("internal") is True
    assert "external" not in net and "name" not in net


def test_single_container_run_uses_network_none():
    # Source-level guard: the single-container run path must use `--network none`
    # (no gateway) and must NOT create a plain egress-capable network.
    import inspect
    from utilities.dynamic_tester import docker_executor
    src = inspect.getsource(docker_executor._run_single)
    assert '"--network"' in src and '"none"' in src
    # No plain egress network CREATED for the single path. Match the actual command
    # list form ["docker", "network", "create", ...] (quoted tokens), which the prose
    # comment ("no `docker network create` needed") does not contain.
    assert '"docker", "network", "create"' not in src


# --- provider-secret exfil via compose build.args ${VAR} interpolation ---------

def test_scrubbed_env_removes_provider_secrets_keeps_docker_essentials():
    """The docker subprocess env must not carry provider API keys.

    A compose `build.args` value like `${ANTHROPIC_API_KEY}` is interpolated by
    docker compose from the host env at BUILD time and can be exfiltrated by the
    LLM-authored Dockerfile's `RUN` over the still-open build-time network. The
    build/run subprocess never needs any provider secret, so it runs with a
    scrubbed env — closing the exfil by construction regardless of build.args.
    """
    import os
    from utilities.dynamic_tester.docker_executor import _scrubbed_subprocess_env

    os.environ["ANTHROPIC_API_KEY"] = "sk-should-not-leak"
    os.environ["OPENAI_API_KEY"] = "sk-should-not-leak-2"
    os.environ["SOME_SECRET_TOKEN"] = "leak3"
    try:
        env = _scrubbed_subprocess_env()
        assert "ANTHROPIC_API_KEY" not in env
        assert "OPENAI_API_KEY" not in env
        assert "SOME_SECRET_TOKEN" not in env
        # docker still needs its essentials
        assert "PATH" in env
    finally:
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SOME_SECRET_TOKEN"):
            os.environ.pop(k, None)


def test_run_command_passes_scrubbed_env(monkeypatch):
    """_run_command must hand the scrubbed env to the subprocess (not inherit os.environ)."""
    import os
    from utilities.dynamic_tester import docker_executor

    os.environ["ANTHROPIC_API_KEY"] = "sk-should-not-leak"
    captured = {}

    def fake_run_utf8(cmd, **kwargs):
        captured["env"] = kwargs.get("env")
        class R:
            stdout, stderr, returncode = "", "", 0
        return R()

    monkeypatch.setattr(docker_executor, "run_utf8", fake_run_utf8)
    try:
        docker_executor._run_command(["docker", "version"], timeout=5)
    finally:
        os.environ.pop("ANTHROPIC_API_KEY", None)

    assert captured["env"] is not None, "_run_command must pass an explicit env= (scrubbed)"
    assert "ANTHROPIC_API_KEY" not in captured["env"]
    assert "PATH" in captured["env"]
