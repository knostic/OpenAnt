"""Tests for the generic Docker/Local executors.

All Docker CLI invocations are mocked at
utilities.autopatcher.test_executors.run_docker_command -- these tests
never require a real Docker daemon and never invoke one.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

import utilities.autopatcher.test_executors as executors_mod
from utilities.autopatcher.test_execution_models import TestExecutionPlan


def _plan(**overrides) -> TestExecutionPlan:
    base = dict(
        setup_commands=(("python", "-m", "pip", "install", "-e", "."),),
        test_command=("python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"),
        result_strategy="junit",
        result_output_path="/tmp/openant-result.xml",
        runtime_family="python",
        runtime_version_hint="3.11",
        evidence=("pyproject.toml",),
        reasoning_summary="pyproject.toml declares pytest.",
        confidence="high",
        source="llm",
    )
    base.update(overrides)
    return TestExecutionPlan(**base)


_NODE_PLAN = _plan(
    setup_commands=(("npm", "ci"),), test_command=("npm", "test"),
    result_strategy="exit_code", result_output_path=None,
    runtime_family="node", runtime_version_hint="20", evidence=("package.json",),
)
_GO_PLAN = _plan(
    setup_commands=(("go", "mod", "download"),), test_command=("go", "test", "./..."),
    result_strategy="exit_code", result_output_path=None,
    runtime_family="go", runtime_version_hint="1.22", evidence=("go.mod",),
)
_MAKE_PLAN = _plan(
    setup_commands=(("make", "setup"),), test_command=("make", "test"),
    result_strategy="exit_code", result_output_path=None,
    runtime_family="python", evidence=("Makefile",),
)
_TAP_PLAN = _plan(
    setup_commands=(("npm", "ci"),), test_command=("npm", "test"),
    result_strategy="tap", result_output_path=None,
    runtime_family="node", runtime_version_hint="20", evidence=("package.json",),
)

_JUNIT_OK = (
    '<?xml version="1.0"?>'
    '<testsuites><testsuite name="pytest" tests="2" failures="0" errors="0" skipped="0">'
    '<testcase classname="tests.test_x" name="test_a" time="0.01"/>'
    '<testcase classname="tests.test_x" name="test_b" time="0.01"/>'
    "</testsuite></testsuites>"
)


def _wrapped_result_stdout(payload: str, other_output: str = "2 passed") -> str:
    return (
        f"{other_output}\n"
        f"{executors_mod._RESULT_START_MARKER}\n"
        f"{payload}\n"
        f"{executors_mod._RESULT_END_MARKER}\n"
    )


def _make_docker_command_stub(build_result, run_result):
    calls = []

    def _stub(cmd, timeout, cwd=None):
        calls.append(cmd)
        if cmd[:2] == ["docker", "build"]:
            assert build_result is not None, "docker build invoked unexpectedly"
            return build_result
        if cmd[:2] == ["docker", "run"]:
            assert run_result is not None, "docker run invoked unexpectedly"
            return run_result
        return ("", "", 0, False)

    return _stub, calls


class TestRuntimePolicy:
    def test_python_node_go_are_all_approved(self):
        assert executors_mod.is_runtime_supported("python")
        assert executors_mod.is_runtime_supported("node")
        assert executors_mod.is_runtime_supported("go")

    def test_rust_and_jvm_are_not_yet_approved(self):
        assert not executors_mod.is_runtime_supported("rust")
        assert not executors_mod.is_runtime_supported("jvm")

    def test_none_is_not_approved(self):
        assert not executors_mod.is_runtime_supported(None)

    def test_approved_images_are_fixed_openant_owned_strings(self):
        """No code path derives an image from plan content -- the map is
        a fixed literal, keyed only by the closed runtime_family enum."""
        assert executors_mod.APPROVED_IMAGES == {
            "python": "python:3.11-slim",
            "node": "node:20-slim",
            "go": "golang:1.22-bookworm",
        }

    def test_unsupported_runtime_never_touches_docker(self, tmp_path: Path):
        with mock.patch.object(executors_mod, "run_docker_command") as m_run:
            result = executors_mod.DockerTestExecutor().run(
                _plan(runtime_family="rust", test_command=("cargo", "test")), tmp_path,
            )
        assert result.setup_failed is True
        assert "not supported" in result.setup_error
        m_run.assert_not_called()


class TestGenericExecutorNoFrameworkBranching:
    """Three different plans (python/node/go) must flow through the exact
    same executor code path -- differing only in the DATA (image chosen,
    RUN lines emitted), never in control flow."""

    @pytest.mark.parametrize("plan,expected_image", [
        (_plan(), "python:3.11-slim"),
        (_NODE_PLAN, "node:20-slim"),
        (_GO_PLAN, "golang:1.22-bookworm"),
        (_TAP_PLAN, "node:20-slim"),
    ])
    def test_dockerfile_uses_the_approved_image_for_each_plan(self, tmp_path, plan, expected_image):
        image = executors_mod.APPROVED_IMAGES[plan.runtime_family]
        assert image == expected_image
        dockerfile = executors_mod._generate_dockerfile(plan, image)
        assert dockerfile.startswith(f"FROM {image}")

    @pytest.mark.parametrize("plan", [_plan(), _NODE_PLAN, _GO_PLAN, _MAKE_PLAN, _TAP_PLAN])
    def test_setup_commands_become_run_lines_regardless_of_content(self, plan):
        image = executors_mod.APPROVED_IMAGES[plan.runtime_family]
        dockerfile = executors_mod._generate_dockerfile(plan, image)
        for cmd in plan.setup_commands:
            import json
            assert f"RUN {json.dumps(list(cmd))}" in dockerfile

    @pytest.mark.parametrize("plan", [_plan(), _NODE_PLAN, _GO_PLAN, _MAKE_PLAN, _TAP_PLAN])
    def test_entrypoint_runs_the_exact_test_command(self, plan):
        script = executors_mod._generate_entrypoint_script(plan)
        for token in plan.test_command:
            assert token in script

    def test_make_available_for_all_approved_families(self, tmp_path):
        for family, image in executors_mod.APPROVED_IMAGES.items():
            dockerfile = executors_mod._generate_dockerfile(_plan(runtime_family=family), image)
            assert "make" in dockerfile

    def test_a_junit_plan_and_an_exit_code_plan_produce_structurally_identical_dockerfiles(self, tmp_path):
        """The executor must not branch on result_strategy at all -- a
        "junit" plan and an "exit_code" plan for the same setup_commands
        differ ONLY in the DATA carried by test_command, never in the
        Dockerfile shape the executor generates around it."""
        image = executors_mod.APPROVED_IMAGES["python"]
        junit_plan = _plan(
            result_strategy="junit", result_output_path="/tmp/openant-result.xml",
            test_command=("python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"),
        )
        exit_code_plan = _plan(
            result_strategy="exit_code", result_output_path=None,
            test_command=("python", "-m", "pytest"),
        )
        junit_dockerfile = executors_mod._generate_dockerfile(junit_plan, image)
        exit_code_dockerfile = executors_mod._generate_dockerfile(exit_code_plan, image)
        # Strip each plan's own test_command tokens out of its Dockerfile
        # before comparing -- what's left (image, setup RUN lines,
        # structure) must be byte-identical regardless of result_strategy.
        import json
        junit_shape = junit_dockerfile.replace(json.dumps(list(junit_plan.test_command)), "<CMD>")
        exit_code_shape = exit_code_dockerfile.replace(json.dumps(list(exit_code_plan.test_command)), "<CMD>")
        assert junit_shape == exit_code_shape

    def test_a_tap_plan_and_an_exit_code_plan_produce_identical_dockerfiles_and_entrypoints(self, tmp_path):
        """Same generic guarantee as the junit/exit_code test above,
        proving Problem 2 (TAP result-format support) added ZERO executor
        branching: a "tap" plan and an "exit_code" plan with the IDENTICAL
        setup_commands/test_command/runtime_family produce byte-identical
        Dockerfiles and entrypoint scripts -- the executor never even
        looks at result_strategy."""
        image = executors_mod.APPROVED_IMAGES["node"]
        exit_code_plan = _plan(
            setup_commands=_TAP_PLAN.setup_commands, test_command=_TAP_PLAN.test_command,
            result_strategy="exit_code", result_output_path=None,
            runtime_family="node", runtime_version_hint="20", evidence=("package.json",),
        )
        assert executors_mod._generate_dockerfile(_TAP_PLAN, image) == executors_mod._generate_dockerfile(
            exit_code_plan, image,
        )
        assert executors_mod._generate_entrypoint_script(_TAP_PLAN) == executors_mod._generate_entrypoint_script(
            exit_code_plan,
        )

    def test_tap_plan_entrypoint_never_cats_a_result_file(self):
        """result_output_path is null for "tap" (see
        test_plan_validation.TestTapResultStrategy) -- the generated
        entrypoint's `cat` guard is therefore never satisfied; the test
        command's own normal stdout, unmodified, IS the TAP source (see
        tap_parser.py)."""
        script = executors_mod._generate_entrypoint_script(_TAP_PLAN)
        # The `cat` line is templated in unconditionally (same generic
        # script shape for every plan -- see test above), but its guard
        # is `[ -n "" ] && [ -f "" ]`, which is always false for a null
        # result_output_path -- it can never actually execute.
        assert 'if [ -n "" ] && [ -f "" ]; then' in script

    def test_executor_module_source_contains_no_runner_specific_decision_logic(self):
        """Static guard against the executor ever growing framework-
        specific decision logic: no comparison/branch anywhere in the
        module may key off a runner-specific literal like "pytest" or
        "--junitxml" -- the executor only ever treats plan.test_command
        as opaque argv tokens supplied by the plan, never as something it
        recognizes and special-cases.

        Mentions in prose (module docstring, comments) and the one
        generic ignore-pattern entry (.pytest_cache, alongside .tox,
        node_modules, etc. -- a plain ignore list, not a decision) are
        expected and are not what this guards against."""
        import ast
        import inspect

        source = inspect.getsource(executors_mod)
        assert "--junitxml" not in source

        tree = ast.parse(source)
        offending_literals = {"pytest", "--junitxml", "junitxml", "tap", "result_strategy"}
        decision_node_types = (ast.Compare, ast.If, ast.IfExp)
        hits = []
        for node in ast.walk(tree):
            if isinstance(node, decision_node_types):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                        if sub.value.lower() in offending_literals:
                            hits.append((type(node).__name__, sub.value))
        assert hits == [], f"runner-specific literal used in a decision: {hits}"


class TestBuildContextStaging:
    def test_existing_repo_dockerfile_is_overwritten(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text("FROM evil-attacker-image\n", encoding="utf-8")
        executors_mod._stage_build_context(tmp_path, _plan(), "python:3.11-slim")
        dockerfile = (tmp_path / "Dockerfile").read_text(encoding="utf-8")
        assert "evil-attacker-image" not in dockerfile
        assert dockerfile.startswith("FROM python:3.11-slim")


class TestResultExtraction:
    def test_extracts_result_between_markers(self):
        stdout = _wrapped_result_stdout(_JUNIT_OK)
        assert executors_mod._extract_result(stdout) == _JUNIT_OK

    def test_no_markers_returns_none(self):
        assert executors_mod._extract_result("some output with no markers\n") is None

    def test_empty_between_markers_returns_none(self):
        stdout = f"{executors_mod._RESULT_START_MARKER}\n\n{executors_mod._RESULT_END_MARKER}\n"
        assert executors_mod._extract_result(stdout) is None


class TestDockerTestExecutorRun:
    def test_successful_build_and_run(self, tmp_path: Path):
        stub, calls = _make_docker_command_stub(
            build_result=("built", "", 0, False),
            run_result=(_wrapped_result_stdout(_JUNIT_OK), "", 0, False),
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            result = executors_mod.DockerTestExecutor().run(_plan(), tmp_path)
        assert result.ran is True
        assert result.setup_failed is False
        assert result.exit_code == 0
        assert result.result_output == _JUNIT_OK
        assert result.executor == "docker"

    def test_build_failure(self, tmp_path: Path):
        stub, calls = _make_docker_command_stub(
            build_result=("", "pip install failed", 1, False), run_result=None,
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            result = executors_mod.DockerTestExecutor().run(_plan(), tmp_path)
        assert result.setup_failed is True
        assert result.ran is False

    def test_build_timeout(self, tmp_path: Path):
        stub, calls = _make_docker_command_stub(
            build_result=("", "Command timed out", -1, True), run_result=None,
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            result = executors_mod.DockerTestExecutor().run(_plan(), tmp_path, setup_timeout=5)
        assert result.setup_failed is True
        assert result.timed_out is True

    def test_run_timeout_kills_container(self, tmp_path: Path):
        stub, calls = _make_docker_command_stub(
            build_result=("built", "", 0, False),
            run_result=("", "Command timed out", -1, True),
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            with mock.patch.object(executors_mod, "kill_docker_container") as m_kill:
                result = executors_mod.DockerTestExecutor().run(_plan(), tmp_path, run_timeout=5)
        assert result.timed_out is True
        assert result.ran is False
        m_kill.assert_called_once()

    def test_cleanup_always_runs(self, tmp_path: Path):
        stub, calls = _make_docker_command_stub(
            build_result=("built", "", 0, False),
            run_result=(_wrapped_result_stdout(_JUNIT_OK), "", 0, False),
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            with mock.patch.object(executors_mod, "cleanup_docker_image") as m_img, \
                 mock.patch.object(executors_mod, "cleanup_docker_container") as m_ctr:
                executors_mod.DockerTestExecutor().run(_plan(), tmp_path)
        m_img.assert_called_once()
        m_ctr.assert_called_once()

    def test_no_host_bind_mount_in_run_invocation(self, tmp_path: Path):
        stub, calls = _make_docker_command_stub(
            build_result=("built", "", 0, False),
            run_result=(_wrapped_result_stdout(_JUNIT_OK), "", 0, False),
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            executors_mod.DockerTestExecutor().run(_plan(), tmp_path)
        run_cmd = next(c for c in calls if c[:2] == ["docker", "run"])
        assert "-v" not in run_cmd
        assert "--mount" not in run_cmd
        assert "--volume" not in run_cmd

    def test_no_host_env_forwarded(self, tmp_path: Path):
        """Neither docker build nor docker run may ever pass -e/--env --
        the container's environment comes ONLY from the Dockerfile's own
        fixed ENV line, never from this process's os.environ."""
        stub, calls = _make_docker_command_stub(
            build_result=("built", "", 0, False),
            run_result=(_wrapped_result_stdout(_JUNIT_OK), "", 0, False),
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            executors_mod.DockerTestExecutor().run(_plan(), tmp_path)
        for cmd in calls:
            assert "-e" not in cmd
            assert "--env" not in cmd

    def test_generated_dockerfile_env_never_contains_host_secrets(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-super-secret-value")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-another-secret")
        dockerfile = executors_mod._generate_dockerfile(_plan(), "python:3.11-slim")
        assert "sk-super-secret-value" not in dockerfile
        assert "sk-another-secret" not in dockerfile
        assert "ANTHROPIC_API_KEY" not in dockerfile
        assert "OPENAI_API_KEY" not in dockerfile

    def test_security_flags_present_in_run_invocation(self, tmp_path: Path):
        stub, calls = _make_docker_command_stub(
            build_result=("built", "", 0, False),
            run_result=(_wrapped_result_stdout(_JUNIT_OK), "", 0, False),
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            executors_mod.DockerTestExecutor().run(_plan(), tmp_path)
        run_cmd = next(c for c in calls if c[:2] == ["docker", "run"])
        assert "--read-only" in run_cmd
        assert "no-new-privileges" in " ".join(run_cmd)
        assert "--pids-limit" in run_cmd
        assert "--memory" in run_cmd
        assert "--cpus" in run_cmd
        assert "none" in run_cmd  # --network none
        assert "--privileged" not in run_cmd

    def test_build_context_staged_before_build(self, tmp_path: Path):
        stub, calls = _make_docker_command_stub(
            build_result=("built", "", 0, False),
            run_result=(_wrapped_result_stdout(_JUNIT_OK), "", 0, False),
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            executors_mod.DockerTestExecutor().run(_plan(), tmp_path)
        assert (tmp_path / "Dockerfile").exists()
        assert (tmp_path / ".openant_run_test.sh").exists()

    def test_exit_code_only_plan_has_no_result_output(self, tmp_path: Path):
        stub, calls = _make_docker_command_stub(
            build_result=("built", "", 0, False),
            run_result=(_wrapped_result_stdout("", other_output="ok"), "", 0, False),
        )
        with mock.patch.object(executors_mod, "run_docker_command", side_effect=stub):
            result = executors_mod.DockerTestExecutor().run(_NODE_PLAN, tmp_path)
        assert result.result_output is None
        assert result.exit_code == 0


class TestLocalTestExecutorNeverSilentlyRuns:
    def test_local_executor_raises_not_implemented(self, tmp_path: Path):
        with pytest.raises(NotImplementedError):
            executors_mod.LocalTestExecutor().run(_plan(), tmp_path)


class TestSelectExecutor:
    """select_executor() is a PURE FACTORY -- it never checks readiness
    itself (no docker_available()/daemon probe). Readiness is
    exclusively the returned executor's own `.preflight()` -- see
    TestExecutorPreflight below. This is deliberate: a second, weaker
    notion of "ready" living inside select_executor would be exactly the
    ad-hoc-multiple-Docker-checks pattern this design avoids."""

    def test_docker_mode_always_returns_an_executor_instance(self):
        assert isinstance(executors_mod.select_executor("docker"), executors_mod.DockerTestExecutor)

    def test_docker_mode_returns_an_instance_even_when_docker_itself_is_unavailable(self):
        """Confirms select_executor does not probe Docker at all --
        constructing a DockerTestExecutor never fails merely because
        Docker isn't installed; only calling .preflight() on it reveals
        that."""
        with mock.patch("utilities.docker_isolation.docker_available", return_value=False):
            executor = executors_mod.select_executor("docker")
        assert isinstance(executor, executors_mod.DockerTestExecutor)

    def test_local_mode_returns_inert_executor_never_none(self):
        executor = executors_mod.select_executor("local")
        assert isinstance(executor, executors_mod.LocalTestExecutor)

    def test_unknown_mode_raises(self):
        with pytest.raises(ValueError):
            executors_mod.select_executor("magic")


class TestExecutorPreflight:
    """Covers the new .preflight() contract on both executors."""

    def test_docker_preflight_delegates_to_canonical_docker_isolation_check(self):
        fake = executors_mod.ExecutorPreflightResult(ready=True, reason=None, status="OK")
        with mock.patch.object(executors_mod.docker_isolation, "docker_preflight") as m_preflight:
            m_preflight.return_value = mock.MagicMock(ready=True, reason=None, status="OK")
            result = executors_mod.DockerTestExecutor().preflight()
        m_preflight.assert_called_once()
        assert result == fake

    def test_docker_preflight_not_ready_propagates_reason_and_status(self):
        with mock.patch.object(executors_mod.docker_isolation, "docker_preflight") as m_preflight:
            m_preflight.return_value = mock.MagicMock(
                ready=False, reason="the Docker daemon is not reachable (...).", status="DAEMON_UNREACHABLE",
            )
            result = executors_mod.DockerTestExecutor().preflight()
        assert result.ready is False
        assert result.status == "DAEMON_UNREACHABLE"
        assert "not reachable" in result.reason

    def test_docker_preflight_never_builds_or_pulls_an_image(self):
        with mock.patch.object(executors_mod, "run_docker_command") as m_run:
            executors_mod.DockerTestExecutor().preflight()
        m_run.assert_not_called()

    def test_patching_the_canonical_docker_isolation_preflight_is_observed_through_docker_test_executor(self):
        """Regression guard: test_executors.py used to bind
        docker_preflight directly at import time
        (``from utilities.docker_isolation import docker_preflight``),
        so patching ``utilities.docker_isolation.docker_preflight`` --
        the canonical, documented mock target -- silently failed to
        intercept it (the stale pre-import-time binding was called
        instead). preflight() now looks the helper up through the
        ``docker_isolation`` module object at call time, so patching it
        at its own source, exactly as production callers/tests are
        documented to, is what actually controls
        DockerTestExecutor.preflight()'s result. This is the same patch
        target used end-to-end by
        test_existing_test_regression.py::TestEnvironmentPreflight::
        test_preflight_uses_the_real_canonical_docker_check_end_to_end."""
        with mock.patch("utilities.docker_isolation.docker_preflight") as m_preflight:
            m_preflight.return_value = mock.MagicMock(
                ready=False, reason="the Docker daemon is not reachable (boom).", status="DAEMON_UNREACHABLE",
            )
            result = executors_mod.DockerTestExecutor().preflight()
        m_preflight.assert_called_once()
        assert result.ready is False
        assert result.status == "DAEMON_UNREACHABLE"
        assert "not reachable" in result.reason

    def test_local_preflight_reports_not_ready_without_raising(self):
        result = executors_mod.LocalTestExecutor().preflight()
        assert result.ready is False
        assert result.status == "NOT_IMPLEMENTED"
        assert result.reason is not None

    def test_preflight_result_is_the_generic_executor_preflight_type(self):
        result = executors_mod.DockerTestExecutor().preflight()
        assert isinstance(result, executors_mod.ExecutorPreflightResult)
        result2 = executors_mod.LocalTestExecutor().preflight()
        assert isinstance(result2, executors_mod.ExecutorPreflightResult)


class TestSecurityDocumentationPrecision:
    """The module docstring must state the real security model precisely
    -- setup-phase network access is a real, accepted trade-off, not
    something papered over with a blanket "fully isolated" claim."""

    def test_does_not_claim_full_network_isolation_as_a_positive_fact(self):
        """The docstring may (and does) explicitly DISCLAIM a blanket
        "fully isolated" characterization -- what it must never do is
        assert one as true. Checked by requiring the qualifying language
        that turns this into a precise, not a sweeping, claim."""
        doc = executors_mod.__doc__
        assert "not one" in doc or "is not" in doc
        assert "trade-off" in doc and "oversight" in doc

    def test_documents_setup_phase_network_access(self):
        doc = executors_mod.__doc__
        assert "MAY have network access" in doc

    def test_documents_repository_hooks_may_execute(self):
        doc = executors_mod.__doc__
        assert "install/build hooks" in doc or "MAY execute" in doc

    def test_documents_no_host_secret_forwarding(self):
        doc = executors_mod.__doc__
        assert "never forwarded" in doc

    def test_documents_test_run_network_none(self):
        doc = executors_mod.__doc__
        assert "--network none" in doc
