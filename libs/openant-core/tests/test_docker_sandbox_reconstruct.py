"""Tests for the untrusted-compose RECONSTRUCTION hardening (B)+(C).

The dynamic tester builds+runs an LLM/target-influenced docker-compose. Rather than
blocklist dangerous keys (non-terminating), `_sanitize_compose` rebuilds each declared
service from an allowlist + a fixed hardening set, dropping every container-runtime
attribute that could grant host access. These tests pin that behaviour.
"""

import yaml

from utilities.dynamic_tester.docker_executor import _sanitize_compose


HOSTILE = """
services:
  test:
    build: .
    privileged: true
    cap_add: [SYS_ADMIN]
    pid: host
    ipc: host
    security_opt: [seccomp=unconfined, apparmor=unconfined]
    devices: ["/dev/kmsg:/dev/kmsg"]
    network_mode: host
    user: root
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host:rw
    ports: ["8080:8080"]
  attacker:
    build: ./attacker-server
"""

DANGEROUS_KEYS = ("privileged", "cap_add", "pid", "ipc", "devices",
                  "network_mode", "user", "volumes", "ports", "sysctls",
                  "userns_mode", "cgroup_parent", "device_cgroup_rules",
                  "extra_hosts", "env_file", "extends")


def _load(out):
    doc = yaml.safe_load(out)
    assert isinstance(doc, dict), f"reconstructed compose is not a mapping: {out!r}"
    return doc


def test_hostile_runtime_attributes_are_gone():
    doc = _load(_sanitize_compose(HOSTILE))
    for name, svc in doc["services"].items():
        for bad in DANGEROUS_KEYS:
            assert bad not in svc, f"{bad!r} survived in service {name!r}"
    # and no host paths / docker socket anywhere in the serialized output
    out = _sanitize_compose(HOSTILE)
    for token in ("docker.sock", "/:/host", "network_mode", "privileged: true", "seccomp=unconfined"):
        assert token not in out, f"dangerous token survived: {token}"


def test_service_set_preserved_and_hardened():
    # test + attacker + db (SQLi-style) must ALL survive, each hardened — not dropped.
    compose = """
services:
  test:
    build: .
    depends_on: [db, attacker]
  attacker:
    build: ./attacker-server
  db:
    image: postgres:15
    environment: [POSTGRES_PASSWORD=x]
"""
    doc = _load(_sanitize_compose(compose))
    assert set(doc["services"]) == {"test", "attacker", "db"}, "a service was silently dropped"
    for name, svc in doc["services"].items():
        assert svc.get("read_only") is True, name
        assert svc.get("cap_drop") == ["ALL"], name
        assert svc.get("security_opt") == ["no-new-privileges:true"], name
        assert svc.get("pids_limit") == 256, name
        assert "user" not in svc, f"{name} must NOT set user (read-only-HOME breakage)"


def test_db_service_keeps_image_and_env():
    doc = _load(_sanitize_compose(
        "services:\n  db:\n    image: postgres:15\n    environment: [POSTGRES_PASSWORD=x]\n"))
    db = doc["services"]["db"]
    assert db.get("image") == "postgres:15"
    assert db.get("environment") == ["POSTGRES_PASSWORD=x"]


def test_network_is_internal():
    doc = _load(_sanitize_compose(HOSTILE))
    assert doc["networks"]["default"]["internal"] is True


def test_unsafe_build_context_fails_closed():
    for ctx in ("/", "../..", "/etc", "../../host"):
        out = _sanitize_compose(f"services:\n  test:\n    build:\n      context: {ctx}\n")
        assert "refusing to run" in out, f"context {ctx!r} should fail closed"
        assert yaml.safe_load(out).get("services") is None if isinstance(yaml.safe_load(out), dict) else True


def test_unparseable_fails_closed():
    out = _sanitize_compose("::: not : valid : yaml :::\n  - [")
    assert "refusing to run" in out


def test_attacker_remote_image_becomes_local_build():
    out = _sanitize_compose("services:\n  attacker:\n    image: evil/attacker:latest\n")
    svc = yaml.safe_load(out)["services"]["attacker"]
    assert "image" not in svc
    assert svc.get("build") == "./attacker-server"


def test_run_single_hardening_flags(monkeypatch):
    """_run_single's `docker run` must add cap_drop ALL + pids-limit, keep the F4 flags,
    and NOT set --user (which would break HOME on the read-only rootfs)."""
    from utilities.dynamic_tester import docker_executor as de
    calls = []

    def fake_run(cmd, timeout, cwd=None):
        calls.append(cmd)
        # first call = build (return success); second = run
        return ("", "", 0, False)

    monkeypatch.setattr(de, "_run_command", fake_run)
    de._run_single("/tmp/nowhere", "img:tag", "net", 10, 10)
    run_cmd = [c for c in calls if c[:2] == ["docker", "run"]][0]
    s = " ".join(run_cmd)
    assert "--cap-drop ALL" in s
    assert "--pids-limit 256" in s
    assert "--network none" in s
    assert "--read-only" in s
    assert "--security-opt no-new-privileges" in s
    assert "--user" not in run_cmd, "must NOT pin --user (read-only-HOME breakage)"


def test_allowlist_is_ordered_for_deterministic_output():
    """_SVC_ALLOWLIST must be an ORDERED sequence (not a set): the reconstruction
    iterates it to build each service, so a hash-randomized set would emit a
    non-deterministic compose file across processes."""
    from utilities.dynamic_tester.docker_executor import _SVC_ALLOWLIST
    assert isinstance(_SVC_ALLOWLIST, (tuple, list)), type(_SVC_ALLOWLIST)
    # reconstructed service keys follow the allowlist order, then the hardening keys
    doc = yaml.safe_load(_sanitize_compose(
        "services:\n  t:\n    environment: [A=1]\n    build: .\n    expose: [8080]\n"))
    keys = list(doc["services"]["t"])
    assert keys.index("build") < keys.index("environment") < keys.index("expose")
